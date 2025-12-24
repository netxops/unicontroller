package models

import (
	"time"
)

// TaskStatus 监控任务状态
type TaskStatus string

const (
	TaskStatusActive  TaskStatus = "active"  // 激活状态
	TaskStatusPaused  TaskStatus = "paused"  // 暂停状态
	TaskStatusStopped TaskStatus = "stopped" // 停止状态
)

// MonitoringTarget 监控目标
type MonitoringTarget struct {
	Type     string            `json:"type"`               // ip, hostname, url 等
	Value    string            `json:"value"`              // 目标值
	Port     int               `json:"port,omitempty"`     // 端口（可选）
	Metadata map[string]string `json:"metadata,omitempty"` // 额外元数据
}

// ScheduleConfig 调度配置
type ScheduleConfig struct {
	Interval  string `json:"interval,omitempty"`   // 采集间隔，如 "10s", "1m"
	StartTime string `json:"start_time,omitempty"` // 开始时间（可选）
	EndTime   string `json:"end_time,omitempty"`   // 结束时间（可选）
	Timezone  string `json:"timezone,omitempty"`   // 时区
}

// MonitoringTask 监控任务
type MonitoringTask struct {
	ID          string                 `json:"id" bson:"_id"`
	Name        string                 `json:"name" bson:"name"`
	Description string                 `json:"description" bson:"description"`
	Status      TaskStatus             `json:"status" bson:"status"`
	Plugins     []PluginConfig         `json:"plugins" bson:"plugins"`
	Targets     []MonitoringTarget     `json:"targets" bson:"targets"`
	Schedule    *ScheduleConfig        `json:"schedule,omitempty" bson:"schedule,omitempty"`
	CreatedAt   time.Time              `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" bson:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// PluginConfig 插件配置
type PluginConfig struct {
	ID         string                 `json:"id" bson:"id"`
	Type       string                 `json:"type" bson:"type"`                                   // inputs.cpu, inputs.snmp 等
	Name       string                 `json:"name" bson:"name"`                                   // 插件实例名称
	TemplateID string                 `json:"template_id,omitempty" bson:"template_id,omitempty"` // 使用的模板ID
	Config     map[string]interface{} `json:"config" bson:"config"`                               // 插件配置（覆盖模板）
	Enabled    bool                   `json:"enabled" bson:"enabled"`
	Priority   int                    `json:"priority" bson:"priority"`                   // 配置合并优先级
	TaskID     string                 `json:"task_id,omitempty" bson:"task_id,omitempty"` // 所属任务ID（如果独立管理）
}

// TemplateParameter 模板参数
type TemplateParameter struct {
	Name        string      `json:"name" bson:"name"`
	Type        string      `json:"type" bson:"type"` // string, int, bool, array, object
	Required    bool        `json:"required" bson:"required"`
	Default     interface{} `json:"default,omitempty" bson:"default,omitempty"`
	Description string      `json:"description" bson:"description"`
	Validation  string      `json:"validation,omitempty" bson:"validation,omitempty"` // 验证规则（JSON Schema）
}

// PluginTemplate 插件模板
type PluginTemplate struct {
	ID          string                 `json:"id" bson:"_id"`
	Type        string                 `json:"type" bson:"type"` // 插件类型
	Name        string                 `json:"name" bson:"name"` // 模板名称
	Description string                 `json:"description" bson:"description"`
	Template    string                 `json:"template" bson:"template"`     // TOML 配置模板
	Parameters  []TemplateParameter    `json:"parameters" bson:"parameters"` // 模板参数定义
	Version     string                 `json:"version" bson:"version"`
	CreatedAt   time.Time              `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" bson:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// MonitoringStatus 监控平台状态
type MonitoringStatus struct {
	TelegrafStatus string                 `json:"telegraf_status"`
	ActiveTasks    int                    `json:"active_tasks"`
	TotalTasks     int                    `json:"total_tasks"`
	TotalPlugins   int                    `json:"total_plugins"`
	TotalTemplates int                    `json:"total_templates"`
	LastReloadTime *time.Time             `json:"last_reload_time,omitempty"`
	ConfigVersion  string                 `json:"config_version"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}
