package health

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

// TCPChecker TCP 健康检查器
type TCPChecker struct {
	config *domain.HealthCheckConfig
}

// NewTCPChecker 创建 TCP 检查器
func NewTCPChecker(config *domain.HealthCheckConfig) *TCPChecker {
	return &TCPChecker{
		config: config,
	}
}

// Type 返回检查器类型
func (c *TCPChecker) Type() string {
	return "tcp"
}

// Check 执行 TCP 健康检查
func (c *TCPChecker) Check(ctx context.Context) (*domain.CheckResult, error) {
	start := time.Now()

	address := fmt.Sprintf(":%d", c.config.TCPPort)
	dialer := net.Dialer{
		Timeout: c.config.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return &domain.CheckResult{
			Healthy:      false,
			Message:      fmt.Sprintf("TCP connection failed: %v", err),
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
			Error:        err,
		}, nil
	}
	defer conn.Close()

	return &domain.CheckResult{
		Healthy:      true,
		Message:      "TCP connection successful",
		ResponseTime: time.Since(start),
		Timestamp:    time.Now(),
	}, nil
}
