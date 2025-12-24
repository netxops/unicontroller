package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/utils"
	"go.uber.org/zap"
)

// ProcessManager 进程管理器接口
type ProcessManager interface {
	Start(ctx context.Context, service *domain.Service) error
	Stop(ctx context.Context, serviceID string) error
	Restart(ctx context.Context, service *domain.Service) error
	IsRunning(serviceID string) (bool, error)
	GetPID(serviceID string) (int, error)
}

// processManager 进程管理器实现
type processManager struct {
	processes map[string]*ProcessInfo // serviceID -> ProcessInfo
	mu        sync.RWMutex
	logger    *zap.Logger
	pidDir    string
	logDir    string
}

// ProcessInfo 进程信息
type ProcessInfo struct {
	ServiceID string
	PID       int
	Cmd       *exec.Cmd
	StartedAt time.Time
	LogFile   *os.File
}

// NewProcessManager 创建进程管理器
func NewProcessManager(logger *zap.Logger, pidDir, logDir string) ProcessManager {
	return &processManager{
		processes: make(map[string]*ProcessInfo),
		logger:    logger,
		pidDir:    pidDir,
		logDir:    logDir,
	}
}

// Start 启动进程
func (pm *processManager) Start(ctx context.Context, service *domain.Service) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 检查是否已经在运行
	if info, exists := pm.processes[service.ID]; exists {
		// 检查进程是否真的在运行
		if pm.isProcessRunning(info.PID) {
			return fmt.Errorf("service %s is already running with PID %d", service.ID, info.PID)
		}
		// 进程不存在，清理旧信息
		delete(pm.processes, service.ID)
	}

	// 构建命令
	cmd, err := pm.buildCommand(service)
	if err != nil {
		return fmt.Errorf("failed to build command: %w", err)
	}

	// 设置工作目录
	if service.Spec.Binary != nil && service.Spec.Binary.Path != "" {
		binaryDir := filepath.Dir(service.Spec.Binary.Path)
		if filepath.IsAbs(service.Spec.Binary.Path) {
			cmd.Dir = binaryDir
		} else {
			// 相对路径，从工作目录查找
			workspace := utils.GetDefaultWorkspace()
			cmd.Dir = filepath.Join(workspace, service.ID, binaryDir)
		}
	}

	// 设置环境变量
	cmd.Env = os.Environ()
	if service.Spec.Startup.Environment != nil {
		for k, v := range service.Spec.Startup.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// 设置用户和组（如果指定且是特权用户）
	if utils.IsPrivilegedUser() {
		if err := pm.setUserAndGroup(cmd, service); err != nil {
			return fmt.Errorf("failed to set user and group: %w", err)
		}
	}

	// 准备日志文件
	logFile, err := pm.prepareLogFile(service.ID)
	if err != nil {
		return fmt.Errorf("failed to prepare log file: %w", err)
	}

	// 重定向输出到日志文件
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// 启动进程
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("failed to start process: %w", err)
	}

	// 保存进程信息
	info := &ProcessInfo{
		ServiceID: service.ID,
		PID:       cmd.Process.Pid,
		Cmd:       cmd,
		StartedAt: time.Now(),
		LogFile:   logFile,
	}
	pm.processes[service.ID] = info

	// 写入 PID 文件
	if err := pm.writePIDFile(service.ID, cmd.Process.Pid); err != nil {
		pm.logger.Warn("Failed to write PID file",
			zap.String("service", service.ID),
			zap.Error(err))
	}

	// 启动 goroutine 监控进程
	go pm.monitorProcess(ctx, service.ID, cmd)

	pm.logger.Info("Process started",
		zap.String("service", service.ID),
		zap.Int("pid", cmd.Process.Pid))

	return nil
}

// Stop 停止进程
func (pm *processManager) Stop(ctx context.Context, serviceID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	info, exists := pm.processes[serviceID]
	if !exists {
		// 尝试从 PID 文件读取
		pid, err := pm.readPIDFile(serviceID)
		if err != nil {
			return fmt.Errorf("service %s is not running", serviceID)
		}
		info = &ProcessInfo{
			ServiceID: serviceID,
			PID:       pid,
		}
	}

	// 检查进程是否在运行
	if !pm.isProcessRunning(info.PID) {
		pm.cleanup(serviceID)
		return nil
	}

	// 发送 SIGTERM 信号
	process, err := os.FindProcess(info.PID)
	if err != nil {
		pm.cleanup(serviceID)
		return fmt.Errorf("failed to find process %d: %w", info.PID, err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		pm.logger.Warn("Failed to send SIGTERM, trying SIGKILL",
			zap.String("service", serviceID),
			zap.Int("pid", info.PID),
			zap.Error(err))
		// 尝试强制杀死
		process.Kill()
	}

	// 等待进程退出（最多等待 10 秒）
	done := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		done <- err
	}()

	select {
	case <-time.After(10 * time.Second):
		// 超时，强制杀死
		pm.logger.Warn("Process did not exit in time, killing",
			zap.String("service", serviceID),
			zap.Int("pid", info.PID))
		process.Kill()
		<-done // 等待 Wait 完成
	case err := <-done:
		if err != nil {
			pm.logger.Warn("Process wait error",
				zap.String("service", serviceID),
				zap.Error(err))
		}
	}

	pm.cleanup(serviceID)

	pm.logger.Info("Process stopped",
		zap.String("service", serviceID),
		zap.Int("pid", info.PID))

	return nil
}

// Restart 重启进程
func (pm *processManager) Restart(ctx context.Context, service *domain.Service) error {
	// 先停止
	if err := pm.Stop(ctx, service.ID); err != nil {
		pm.logger.Warn("Failed to stop service before restart",
			zap.String("service", service.ID),
			zap.Error(err))
		// 继续执行，尝试启动
	}

	// 等待一小段时间
	time.Sleep(500 * time.Millisecond)

	// 再启动
	return pm.Start(ctx, service)
}

// IsRunning 检查进程是否运行
func (pm *processManager) IsRunning(serviceID string) (bool, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	info, exists := pm.processes[serviceID]
	if exists {
		return pm.isProcessRunning(info.PID), nil
	}

	// 尝试从 PID 文件读取
	pid, err := pm.readPIDFile(serviceID)
	if err != nil {
		return false, nil
	}

	return pm.isProcessRunning(pid), nil
}

// GetPID 获取进程 PID
func (pm *processManager) GetPID(serviceID string) (int, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	info, exists := pm.processes[serviceID]
	if exists {
		return info.PID, nil
	}

	// 尝试从 PID 文件读取
	return pm.readPIDFile(serviceID)
}

// buildCommand 构建命令
func (pm *processManager) buildCommand(service *domain.Service) (*exec.Cmd, error) {
	if service.Spec.Binary == nil || service.Spec.Binary.Path == "" {
		return nil, fmt.Errorf("binary path is required for direct startup")
	}

	binaryPath := service.Spec.Binary.Path
	if !filepath.IsAbs(binaryPath) {
		// 相对路径，从工作目录查找
		workspace := utils.GetDefaultWorkspace()
		binaryPath = filepath.Join(workspace, service.ID, binaryPath)
	}

	// 检查二进制文件是否存在
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("binary file not found: %s", binaryPath)
	}

	args := service.Spec.Startup.Args
	if args == nil {
		args = []string{}
	}

	cmd := exec.Command(binaryPath, args...)
	return cmd, nil
}

// prepareLogFile 准备日志文件
func (pm *processManager) prepareLogFile(serviceID string) (*os.File, error) {
	// 确保日志目录存在
	if err := os.MkdirAll(pm.logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	logPath := filepath.Join(pm.logDir, fmt.Sprintf("%s.log", serviceID))
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return file, nil
}

// writePIDFile 写入 PID 文件
func (pm *processManager) writePIDFile(serviceID string, pid int) error {
	// 确保 PID 目录存在
	if err := os.MkdirAll(pm.pidDir, 0755); err != nil {
		return fmt.Errorf("failed to create pid directory: %w", err)
	}

	pidPath := filepath.Join(pm.pidDir, fmt.Sprintf("%s.pid", serviceID))
	return os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", pid)), 0644)
}

// readPIDFile 读取 PID 文件
func (pm *processManager) readPIDFile(serviceID string) (int, error) {
	pidPath := filepath.Join(pm.pidDir, fmt.Sprintf("%s.pid", serviceID))
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid PID file format: %w", err)
	}

	return pid, nil
}

// isProcessRunning 检查进程是否运行
func (pm *processManager) isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// 发送信号 0 来检查进程是否存在
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// monitorProcess 监控进程
func (pm *processManager) monitorProcess(ctx context.Context, serviceID string, cmd *exec.Cmd) {
	err := cmd.Wait()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	info, exists := pm.processes[serviceID]
	if exists {
		// 关闭日志文件
		if info.LogFile != nil {
			info.LogFile.Close()
		}
		delete(pm.processes, serviceID)
	}

	if err != nil {
		pm.logger.Error("Process exited with error",
			zap.String("service", serviceID),
			zap.Int("pid", cmd.Process.Pid),
			zap.Error(err))
	} else {
		pm.logger.Info("Process exited",
			zap.String("service", serviceID),
			zap.Int("pid", cmd.Process.Pid))
	}

	// 清理 PID 文件
	pidPath := filepath.Join(pm.pidDir, fmt.Sprintf("%s.pid", serviceID))
	os.Remove(pidPath)
}

// cleanup 清理资源
func (pm *processManager) cleanup(serviceID string) {
	info, exists := pm.processes[serviceID]
	if exists {
		if info.LogFile != nil {
			info.LogFile.Close()
		}
		delete(pm.processes, serviceID)
	}

	// 删除 PID 文件
	pidPath := filepath.Join(pm.pidDir, fmt.Sprintf("%s.pid", serviceID))
	os.Remove(pidPath)
}

// setUserAndGroup 设置进程的用户和组
func (pm *processManager) setUserAndGroup(cmd *exec.Cmd, service *domain.Service) error {
	// 如果没有指定用户，不需要切换
	if service.Spec.Startup.User == "" {
		return nil
	}

	// 查找用户信息
	usr, err := user.Lookup(service.Spec.Startup.User)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", service.Spec.Startup.User, err)
	}

	// 解析用户 ID
	uid, err := strconv.ParseUint(usr.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("failed to parse user ID %s: %w", usr.Uid, err)
	}

	// 确定组 ID
	var gid uint64
	if service.Spec.Startup.Group != "" {
		// 使用指定的组
		grp, err := user.LookupGroup(service.Spec.Startup.Group)
		if err != nil {
			return fmt.Errorf("failed to lookup group %s: %w", service.Spec.Startup.Group, err)
		}
		gid, err = strconv.ParseUint(grp.Gid, 10, 32)
		if err != nil {
			return fmt.Errorf("failed to parse group ID %s: %w", grp.Gid, err)
		}
	} else {
		// 使用用户的主组
		gid, err = strconv.ParseUint(usr.Gid, 10, 32)
		if err != nil {
			return fmt.Errorf("failed to parse group ID %s: %w", usr.Gid, err)
		}
	}

	// 设置 SysProcAttr
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}

	// 设置 NoSetGroups 为 false，允许设置补充组
	// 如果需要设置补充组，可以在这里添加
	// cmd.SysProcAttr.Credential.Groups = []uint32{...}

	pm.logger.Info("Set process user and group",
		zap.String("service", service.ID),
		zap.String("user", service.Spec.Startup.User),
		zap.Uint32("uid", uint32(uid)),
		zap.Uint32("gid", uint32(gid)),
		zap.String("group", service.Spec.Startup.Group))

	return nil
}
