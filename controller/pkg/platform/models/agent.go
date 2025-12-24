package models

import (
	"time"
)

// AggregatedAgent 表示聚合后的 Agent 信息
type AggregatedAgent struct {
	ID            string    `json:"id"`             // Agent ID（通常等于 AgentCode）
	AgentCode     string    `json:"agent_code"`     // Agent 标识码（由运维平台生成，全局唯一）
	Area          string    `json:"area"`           // 所属区域
	ControllerID  string    `json:"controller_id"`  // 管理的 Controller ID
	DeviceID      string    `json:"device_id"`      // 关联的设备 ID
	Address       string    `json:"address"`        // Agent 地址
	Status        string    `json:"status"`         // Agent 状态
	HealthStatus  string    `json:"health_status"`  // 健康状态
	ServiceCount  int       `json:"service_count"`  // 管理的服务数量
	LastHeartbeat time.Time `json:"last_heartbeat"` // 最后心跳时间
	Version       string    `json:"version"`        // Agent 版本
	DeployedAt    time.Time `json:"deployed_at"`    // 部署时间
	CreatedAt     time.Time `json:"created_at"`     // 创建时间
	UpdatedAt     time.Time `json:"updated_at"`     // 更新时间
}

// AgentStatus Agent 状态常量
const (
	AgentStatusOnline  = "online"
	AgentStatusOffline = "offline"
)

// HealthStatus 健康状态常量
const (
	HealthStatusHealthy   = "healthy"
	HealthStatusUnhealthy = "unhealthy"
	HealthStatusUnknown   = "unknown"
)
