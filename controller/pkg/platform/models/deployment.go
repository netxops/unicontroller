package models

import (
	"time"
)

// AgentDeployment 表示 Agent 部署记录
type AgentDeployment struct {
	ID           string     `json:"id"`            // 部署记录 ID
	DeviceID     string     `json:"device_id"`     // 设备 ID
	AgentCode    string     `json:"agent_code"`    // Agent Code
	ControllerID string     `json:"controller_id"` // Controller ID
	Area         string     `json:"area"`          // 区域
	Status       string     `json:"status"`        // 部署状态
	AgentVersion string     `json:"agent_version"` // Agent 版本
	DeployedAt   time.Time  `json:"deployed_at"`   // 部署开始时间
	CompletedAt  *time.Time `json:"completed_at"`  // 部署完成时间
	ErrorMessage string     `json:"error_message"` // 错误信息
	Logs         []string   `json:"logs"`          // 部署日志
	CreatedAt    time.Time  `json:"created_at"`    // 创建时间
	UpdatedAt    time.Time  `json:"updated_at"`    // 更新时间
}

// DeploymentStatus 部署状态常量
const (
	DeploymentStatusDeploying = "deploying"
	DeploymentStatusCompleted = "completed"
	DeploymentStatusFailed    = "failed"
	DeploymentStatusCancelled = "cancelled"
)
