package domain

import (
	"time"
)

// HealthStatus 健康状态
type HealthStatus string

const (
	HealthStatusUnknown   HealthStatus = "unknown"
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusDegraded  HealthStatus = "degraded"
)

// HealthStatusDetail 健康状态详情
type HealthStatusDetail struct {
	Status       HealthStatus
	Message      string
	LastCheck    time.Time
	CheckType    string
	ResponseTime time.Duration
	Error        error
}

// ServiceHealth 服务健康状态（用于 Service）
type ServiceHealth struct {
	Status    HealthStatus
	LastCheck time.Time
	Message   string
	Details   []HealthStatusDetail
}

// CheckResult 健康检查结果
type CheckResult struct {
	Healthy      bool
	Message      string
	ResponseTime time.Duration
	Error        error
	Timestamp    time.Time
}

// IsHealthy 检查是否健康
func (h *ServiceHealth) IsHealthy() bool {
	return h.Status == HealthStatusHealthy
}
