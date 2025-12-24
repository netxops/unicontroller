package health

import (
	"context"
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

// ProcessChecker 进程健康检查器
type ProcessChecker struct {
	config  *domain.HealthCheckConfig
	service *domain.Service
}

// NewProcessChecker 创建进程检查器
func NewProcessChecker(config *domain.HealthCheckConfig, service *domain.Service) *ProcessChecker {
	return &ProcessChecker{
		config:  config,
		service: service,
	}
}

// Type 返回检查器类型
func (c *ProcessChecker) Type() string {
	return "process"
}

// Check 执行进程健康检查
func (c *ProcessChecker) Check(ctx context.Context) (*domain.CheckResult, error) {
	start := time.Now()

	// 检查服务状态
	if c.service.Status == domain.ServiceStatusRunning {
		return &domain.CheckResult{
			Healthy:      true,
			Message:      "process is running",
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
		}, nil
	}

	return &domain.CheckResult{
		Healthy:      false,
		Message:      fmt.Sprintf("process is not running, status: %s", c.service.Status),
		ResponseTime: time.Since(start),
		Timestamp:    time.Now(),
	}, nil
}
