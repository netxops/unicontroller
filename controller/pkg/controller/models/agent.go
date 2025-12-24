package models

import "time"

type PackageStatus struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	IsRunning bool          `json:"is_running"`
	Duration  time.Duration `json:"duration"`
}

type Agent struct {
	ID              string            `json:"id"`
	AgentCode       string            `json:"agent_code"` // Agent标识码（由运维平台生成，全局唯一）
	AreaID          string            `json:"area_id"`
	Address         string            `json:"address"`
	Hostname        string            `json:"hostname"`
	Status          AgentStatus       `json:"status"`
	Labels          map[string]string `json:"labels"`
	Version         string            `json:"version"`
	LastHeartbeat   time.Time         `json:"last_heartbeat"`
	RegisterTime    time.Time         `json:"register_time"`
	Services        []PackageStatus   `json:"services"`
	HealthStatus    string            `json:"health_status,omitempty"`     // Agent 整体健康状态
	LastHealthCheck *time.Time        `json:"last_health_check,omitempty"` // 最后健康检查时间
}

const (
	AgentStatusUnknown = "unknown"
	AgentStatusOnline  = "online"
	AgentStatusOffline = "offline"
)

type AgentStatus string

type Server struct {
	ID   string `json:"id"`
	Host string `json:"host"`
}

type AgentsResponse struct {
	Agents   []Agent `json:"agents"`
	Total    int     `json:"total"`
	Page     int     `json:"page"`
	PageSize int     `json:"pageSize"`
}
