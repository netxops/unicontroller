package health

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap"
)

// HealthNotifier 健康检查通知器接口
type HealthNotifier interface {
	Notify(service *domain.Service, oldStatus, newStatus domain.HealthStatus, result *domain.CheckResult) error
}

// LogNotifier 日志通知器（默认实现）
type LogNotifier struct {
	logger *zap.Logger
}

// NewLogNotifier 创建日志通知器
func NewLogNotifier(logger *zap.Logger) HealthNotifier {
	return &LogNotifier{
		logger: logger,
	}
}

// Notify 发送通知（记录日志）
func (n *LogNotifier) Notify(service *domain.Service, oldStatus, newStatus domain.HealthStatus, result *domain.CheckResult) error {
	level := zap.InfoLevel
	if newStatus == domain.HealthStatusUnhealthy {
		level = zap.WarnLevel
	}

	n.logger.Log(level, "Health status notification",
		zap.String("service", service.ID),
		zap.String("service_name", service.Name),
		zap.String("old_status", string(oldStatus)),
		zap.String("new_status", string(newStatus)),
		zap.String("message", result.Message),
		zap.Duration("response_time", result.ResponseTime),
		zap.Time("timestamp", result.Timestamp),
	)

	if result.Error != nil {
		n.logger.Log(level, "Health check error",
			zap.String("service", service.ID),
			zap.Error(result.Error),
		)
	}

	return nil
}

// WebhookNotifier Webhook 通知器
type WebhookNotifier struct {
	url    string
	logger *zap.Logger
	client *http.Client
}

// NewWebhookNotifier 创建 Webhook 通知器
func NewWebhookNotifier(url string, logger *zap.Logger) HealthNotifier {
	return &WebhookNotifier{
		url:    url,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Notify 发送 Webhook 通知
func (n *WebhookNotifier) Notify(service *domain.Service, oldStatus, newStatus domain.HealthStatus, result *domain.CheckResult) error {
	// 构建通知消息
	payload := map[string]interface{}{
		"service_id":       service.ID,
		"service_name":     service.Name,
		"old_status":       string(oldStatus),
		"new_status":       string(newStatus),
		"message":          result.Message,
		"timestamp":        result.Timestamp.Format(time.RFC3339),
		"response_time_ms": result.ResponseTime.Milliseconds(),
	}

	if result.Error != nil {
		payload["error"] = result.Error.Error()
	}

	// 发送 HTTP POST 请求
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal notification payload: %w", err)
	}

	req, err := http.NewRequest("POST", n.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	n.logger.Info("Health status notification sent",
		zap.String("service", service.ID),
		zap.String("url", n.url),
		zap.Int("status_code", resp.StatusCode))

	return nil
}
