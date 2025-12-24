package models

import (
	"time"
)

// Controller 表示一个区域 Controller 的信息
type Controller struct {
	ID            string                 `json:"id"`             // Controller 唯一标识
	Area          string                 `json:"area"`           // 区域标识
	Address       string                 `json:"address"`        // Controller 地址（IP:Port）
	Status        string                 `json:"status"`         // 状态：online, offline
	Version       string                 `json:"version"`        // Controller 版本
	StartTime     time.Time              `json:"start_time"`     // 启动时间
	LastHeartbeat time.Time              `json:"last_heartbeat"` // 最后心跳时间
	AgentCount    int                    `json:"agent_count"`    // 管理的 Agent 数量
	Metadata      map[string]interface{} `json:"metadata"`       // 扩展元数据
	CreatedAt     time.Time              `json:"created_at"`     // 创建时间
	UpdatedAt     time.Time              `json:"updated_at"`     // 更新时间
}

// ControllerStatus Controller 状态常量
const (
	ControllerStatusOnline  = "online"
	ControllerStatusOffline = "offline"
)
