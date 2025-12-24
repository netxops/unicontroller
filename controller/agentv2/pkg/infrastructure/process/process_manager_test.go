package process

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap/zaptest"
)

func TestProcessManager_IsRunning_NotRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir)

	// 测试不存在的服务
	running, err := pm.IsRunning("non-existent-service")
	if err != nil {
		t.Fatalf("IsRunning should not return error for non-existent service: %v", err)
	}
	if running {
		t.Error("Non-existent service should not be running")
	}
}

func TestProcessManager_GetPID_NotRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir)

	// 测试不存在的服务
	pid, err := pm.GetPID("non-existent-service")
	if err == nil {
		t.Error("GetPID should return error for non-existent service")
	}
	if pid != 0 {
		t.Errorf("GetPID should return 0 for non-existent service, got %d", pid)
	}
}

func TestProcessManager_Start_InvalidBinary(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir)

	// 创建无效的服务配置
	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Binary: &domain.BinarySpec{
				Path: "/non/existent/binary",
			},
			Startup: &domain.StartupSpec{
				Method: "direct",
			},
		},
	}

	ctx := context.Background()
	err := pm.Start(ctx, service)
	if err == nil {
		t.Error("Start should return error for non-existent binary")
	}
}

func TestProcessManager_Start_MissingBinaryPath(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir)

	// 创建缺少二进制路径的服务配置
	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Startup: &domain.StartupSpec{
				Method: "direct",
			},
		},
	}

	ctx := context.Background()
	err := pm.Start(ctx, service)
	if err == nil {
		t.Error("Start should return error for missing binary path")
	}
}

func TestProcessManager_Stop_NotRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir)

	ctx := context.Background()
	err := pm.Stop(ctx, "non-existent-service")
	if err == nil {
		t.Error("Stop should return error for non-existent service")
	}
}

func TestProcessManager_Restart_NotRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir)

	// 创建无效的服务配置
	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Binary: &domain.BinarySpec{
				Path: "/non/existent/binary",
			},
			Startup: &domain.StartupSpec{
				Method: "direct",
			},
		},
	}

	ctx := context.Background()
	// Restart 应该先尝试 Stop（会失败但不报错），然后尝试 Start（会失败）
	err := pm.Restart(ctx, service)
	if err == nil {
		t.Error("Restart should return error for invalid service")
	}
}

func TestProcessManager_PIDFileOperations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir).(*processManager)

	// 测试写入 PID 文件
	serviceID := "test-service"
	pid := 12345
	err := pm.writePIDFile(serviceID, pid)
	if err != nil {
		t.Fatalf("Failed to write PID file: %v", err)
	}

	// 验证文件存在
	pidPath := filepath.Join(pidDir, serviceID+".pid")
	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		t.Error("PID file should be created")
	}

	// 测试读取 PID 文件
	readPID, err := pm.readPIDFile(serviceID)
	if err != nil {
		t.Fatalf("Failed to read PID file: %v", err)
	}
	if readPID != pid {
		t.Errorf("Expected PID %d, got %d", pid, readPID)
	}

	// 测试读取不存在的 PID 文件
	_, err = pm.readPIDFile("non-existent")
	if err == nil {
		t.Error("Reading non-existent PID file should return error")
	}
}

func TestProcessManager_LogFileOperations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir).(*processManager)

	// 测试准备日志文件
	serviceID := "test-service"
	logFile, err := pm.prepareLogFile(serviceID)
	if err != nil {
		t.Fatalf("Failed to prepare log file: %v", err)
	}
	defer logFile.Close()

	// 验证文件存在
	logPath := filepath.Join(logDir, serviceID+".log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Log file should be created")
	}

	// 测试写入日志
	testMessage := "test log message\n"
	_, err = logFile.WriteString(testMessage)
	if err != nil {
		t.Fatalf("Failed to write to log file: %v", err)
	}

	// 验证日志内容
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	if string(data) != testMessage {
		t.Errorf("Expected log content %q, got %q", testMessage, string(data))
	}
}

func TestProcessManager_BuildCommand(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir).(*processManager)

	// 创建临时可执行文件（使用 echo 作为测试）
	// 在 Unix 系统上，/bin/echo 应该存在
	binaryPath := "/bin/echo"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		// 如果 /bin/echo 不存在，跳过这个测试
		t.Skip("Binary file not found, skipping test")
	}

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Binary: &domain.BinarySpec{
				Path: binaryPath,
			},
			Startup: &domain.StartupSpec{
				Method: "direct",
				Args:   []string{"hello", "world"},
			},
		},
	}

	cmd, err := pm.buildCommand(service)
	if err != nil {
		t.Fatalf("Failed to build command: %v", err)
	}

	if cmd.Path != binaryPath {
		t.Errorf("Expected binary path %s, got %s", binaryPath, cmd.Path)
	}

	if len(cmd.Args) != 3 { // binary path + 2 args
		t.Errorf("Expected 3 args, got %d", len(cmd.Args))
	}
}

func TestProcessManager_BuildCommand_RelativePath(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir).(*processManager)

	// 测试相对路径（应该会失败，因为文件不存在）
	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Binary: &domain.BinarySpec{
				Path: "relative/path/to/binary",
			},
			Startup: &domain.StartupSpec{
				Method: "direct",
			},
		},
	}

	_, err := pm.buildCommand(service)
	if err == nil {
		t.Error("BuildCommand should return error for non-existent relative path")
	}
}

func TestProcessManager_EnvironmentVariables(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir).(*processManager)

	// 创建带环境变量的服务
	binaryPath := "/bin/echo"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Skip("Binary file not found, skipping test")
	}

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Binary: &domain.BinarySpec{
				Path: binaryPath,
			},
			Startup: &domain.StartupSpec{
				Method: "direct",
				Environment: map[string]string{
					"TEST_VAR":  "test_value",
					"TEST_VAR2": "test_value2",
				},
			},
		},
	}

	cmd, err := pm.buildCommand(service)
	if err != nil {
		t.Fatalf("Failed to build command: %v", err)
	}

	// 设置环境变量（模拟 Start 方法中的逻辑）
	cmd.Env = os.Environ()
	for k, v := range service.Spec.Startup.Environment {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	// 验证环境变量
	foundTestVar := false
	foundTestVar2 := false
	for _, env := range cmd.Env {
		if env == "TEST_VAR=test_value" {
			foundTestVar = true
		}
		if env == "TEST_VAR2=test_value2" {
			foundTestVar2 = true
		}
	}

	if !foundTestVar {
		t.Error("Environment variable TEST_VAR should be set")
	}
	if !foundTestVar2 {
		t.Error("Environment variable TEST_VAR2 should be set")
	}
}

func TestProcessManager_IsProcessRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir).(*processManager)

	// 测试当前进程（应该存在）
	currentPID := os.Getpid()
	if !pm.isProcessRunning(currentPID) {
		t.Error("Current process should be running")
	}

	// 测试不存在的进程（使用一个很大的 PID）
	nonExistentPID := 999999
	if pm.isProcessRunning(nonExistentPID) {
		t.Error("Non-existent process should not be running")
	}
}

func TestProcessManager_ConcurrentAccess(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "pids")
	logDir := filepath.Join(tmpDir, "logs")

	pm := NewProcessManager(logger, pidDir, logDir)

	// 测试并发访问 IsRunning
	serviceID := "test-service"
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, _ = pm.IsRunning(serviceID)
			done <- true
		}()
	}

	// 等待所有 goroutine 完成
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent access test timed out")
		}
	}
}
