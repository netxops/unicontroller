package health

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

// HTTPChecker HTTP 健康检查器
type HTTPChecker struct {
	config *domain.HealthCheckConfig
	client *http.Client
}

// NewHTTPChecker 创建 HTTP 检查器
func NewHTTPChecker(config *domain.HealthCheckConfig) *HTTPChecker {
	return &HTTPChecker{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// Type 返回检查器类型
func (c *HTTPChecker) Type() string {
	return "http"
}

// Check 执行 HTTP 健康检查
func (c *HTTPChecker) Check(ctx context.Context) (*domain.CheckResult, error) {
	start := time.Now()

	method := c.config.HTTPMethod
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, c.config.HTTPPath, nil)
	if err != nil {
		return &domain.CheckResult{
			Healthy:      false,
			Message:      fmt.Sprintf("failed to create request: %v", err),
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
			Error:        err,
		}, nil
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return &domain.CheckResult{
			Healthy:      false,
			Message:      fmt.Sprintf("health check request failed: %v", err),
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
			Error:        err,
		}, nil
	}
	defer resp.Body.Close()

	healthy := resp.StatusCode >= 200 && resp.StatusCode < 300
	message := fmt.Sprintf("HTTP %d", resp.StatusCode)

	return &domain.CheckResult{
		Healthy:      healthy,
		Message:      message,
		ResponseTime: time.Since(start),
		Timestamp:    time.Now(),
	}, nil
}
