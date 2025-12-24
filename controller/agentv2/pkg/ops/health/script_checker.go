package health

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

// ScriptChecker 脚本健康检查器
type ScriptChecker struct {
	config *domain.HealthCheckConfig
}

// NewScriptChecker 创建脚本检查器
func NewScriptChecker(config *domain.HealthCheckConfig) *ScriptChecker {
	return &ScriptChecker{
		config: config,
	}
}

// Type 返回检查器类型
func (c *ScriptChecker) Type() string {
	return "script"
}

// Check 执行脚本健康检查
func (c *ScriptChecker) Check(ctx context.Context) (*domain.CheckResult, error) {
	start := time.Now()

	if c.config.ScriptPath == "" {
		return &domain.CheckResult{
			Healthy:      false,
			Message:      "script path not configured",
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
		}, nil
	}

	// 创建带超时的 context
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", c.config.ScriptPath)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return &domain.CheckResult{
			Healthy:      false,
			Message:      fmt.Sprintf("script execution failed: %v, output: %s", err, string(output)),
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
			Error:        err,
		}, nil
	}

	// 脚本退出码为 0 表示健康
	healthy := cmd.ProcessState.ExitCode() == 0
	message := "script check completed"
	if !healthy {
		message = fmt.Sprintf("script returned non-zero exit code: %d", cmd.ProcessState.ExitCode())
	}

	return &domain.CheckResult{
		Healthy:      healthy,
		Message:      message,
		ResponseTime: time.Since(start),
		Timestamp:    time.Now(),
	}, nil
}
