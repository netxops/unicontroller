package systemd

import (
	"fmt"
	"os/exec"
	"strings"
)

// SystemdAdapter systemd 适配器
type SystemdAdapter struct {
	isUserUnit bool
}

// NewSystemdAdapter 创建 systemd 适配器
func NewSystemdAdapter(isUserUnit bool) *SystemdAdapter {
	return &SystemdAdapter{
		isUserUnit: isUserUnit,
	}
}

// Start 启动服务
func (s *SystemdAdapter) Start(serviceName string) error {
	cmd := s.buildCommand("start", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start service %s: %v, output: %s", serviceName, err, string(output))
	}
	return nil
}

// Stop 停止服务
func (s *SystemdAdapter) Stop(serviceName string) error {
	cmd := s.buildCommand("stop", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop service %s: %v, output: %s", serviceName, err, string(output))
	}
	return nil
}

// Restart 重启服务
func (s *SystemdAdapter) Restart(serviceName string) error {
	cmd := s.buildCommand("restart", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart service %s: %v, output: %s", serviceName, err, string(output))
	}
	return nil
}

// Status 获取服务状态
func (s *SystemdAdapter) Status(serviceName string) (string, error) {
	cmd := s.buildCommand("is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get status for service %s: %v", serviceName, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// IsActive 检查服务是否激活
func (s *SystemdAdapter) IsActive(serviceName string) (bool, error) {
	status, err := s.Status(serviceName)
	if err != nil {
		return false, err
	}
	return status == "active", nil
}

// buildCommand 构建 systemctl 命令
func (s *SystemdAdapter) buildCommand(action, serviceName string) *exec.Cmd {
	if s.isUserUnit {
		return exec.Command("systemctl", "--user", action, serviceName)
	}
	return exec.Command("systemctl", action, serviceName)
}
