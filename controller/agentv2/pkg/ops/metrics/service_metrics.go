package metrics

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/shirou/gopsutil/v3/process"
)

// collectServiceMetrics 收集服务指标
func collectServiceMetrics(ctx context.Context, serviceID string, serviceSpec *domain.ServiceSpec) (*domain.ServiceMetrics, error) {
	metrics := &domain.ServiceMetrics{
		LastUpdated: time.Now(),
	}

	// 获取服务的 PID
	pid, err := getServicePID(serviceID, serviceSpec)
	if err != nil {
		// 如果无法获取 PID（服务可能未运行），返回空指标
		return metrics, nil
	}

	// 获取进程信息
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		// 进程不存在，返回空指标
		return metrics, nil
	}

	// 收集 CPU 使用率
	cpuPercent, err := proc.CPUPercentWithContext(ctx)
	if err == nil {
		metrics.CPUUsage = cpuPercent
	}

	// 收集内存使用情况
	memInfo, err := proc.MemoryInfoWithContext(ctx)
	if err == nil {
		metrics.MemoryBytes = int64(memInfo.RSS) // RSS: 实际物理内存使用
		// 计算内存使用百分比（需要系统总内存）
		if memInfo.RSS > 0 {
			// 这里可以获取系统总内存来计算百分比，暂时使用字节数
			metrics.MemoryUsage = float64(memInfo.RSS) / (1024 * 1024) // 转换为 MB
		}
	}

	// 收集进程的 goroutine 数量（如果是 Go 进程）
	// 这需要进程暴露运行时信息，暂时跳过

	return metrics, nil
}

// getServicePID 获取服务的 PID
func getServicePID(serviceID string, serviceSpec *domain.ServiceSpec) (int, error) {
	// 方法1: 通过 systemd 获取主进程 PID
	pid, err := getPIDFromSystemd(serviceID, serviceSpec)
	if err == nil {
		return pid, nil
	}

	// 方法2: 通过进程名查找（如果知道二进制名称）
	if serviceSpec != nil && serviceSpec.Binary != nil && serviceSpec.Binary.Name != "" {
		pid, err := getPIDFromProcessName(serviceSpec.Binary.Name)
		if err == nil {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("failed to get PID for service %s", serviceID)
}

// getPIDFromSystemd 从 systemd 获取服务的主进程 PID
func getPIDFromSystemd(serviceID string, serviceSpec *domain.ServiceSpec) (int, error) {
	// 确定服务名称
	serviceName := serviceID
	if serviceSpec != nil && serviceSpec.Startup != nil && serviceSpec.Startup.ServiceName != "" {
		serviceName = serviceSpec.Startup.ServiceName
	}

	// 使用 systemctl show 获取主进程 PID
	cmd := exec.Command("systemctl", "show", serviceName, "--property=MainPID", "--value")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to get PID from systemd: %w", err)
	}

	pidStr := strings.TrimSpace(string(output))
	if pidStr == "" || pidStr == "0" {
		return 0, fmt.Errorf("service is not running or has no main PID")
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID format: %s", pidStr)
	}

	return pid, nil
}

// getPIDFromProcessName 通过进程名查找 PID
func getPIDFromProcessName(processName string) (int, error) {
	// 使用 pgrep 查找进程
	cmd := exec.Command("pgrep", "-f", processName)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("process not found: %w", err)
	}

	pidStr := strings.TrimSpace(string(output))
	if pidStr == "" {
		return 0, fmt.Errorf("process not found")
	}

	// pgrep 可能返回多个 PID，取第一个
	lines := strings.Split(pidStr, "\n")
	if len(lines) > 0 {
		pidStr = lines[0]
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID format: %s", pidStr)
	}

	return pid, nil
}
