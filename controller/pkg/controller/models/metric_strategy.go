package models

import (
	"time"
)

// MetricPriority 指标优先级
type MetricPriority string

const (
	PriorityCritical MetricPriority = "critical"
	PriorityHigh     MetricPriority = "high"
	PriorityMedium   MetricPriority = "medium"
	PriorityLow      MetricPriority = "low"
	PriorityDisabled MetricPriority = "disabled"
)

// MetricRule 指标规则
type MetricRule struct {
	Name     string         `json:"name" bson:"name"`         // 指标名称（支持通配符）
	Priority MetricPriority `json:"priority" bson:"priority"` // 优先级
	Interval *int           `json:"interval,omitempty" bson:"interval,omitempty"` // 采集间隔（秒，可选）
	Enabled  bool           `json:"enabled" bson:"enabled"`   // 是否启用
}

// GlobalMetricStrategy 全局指标策略
type GlobalMetricStrategy struct {
	ID             string      `json:"id" bson:"_id"`
	DefaultPriority MetricPriority `json:"default_priority" bson:"default_priority"` // 默认优先级
	DefaultInterval int        `json:"default_interval" bson:"default_interval"`      // 默认采集间隔（秒）
	MetricRules    []MetricRule `json:"metric_rules" bson:"metric_rules"`              // 指标规则列表
	CreatedAt      time.Time   `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at" bson:"updated_at"`
	Version        int64       `json:"version" bson:"version"` // 版本号（时间戳）
}

// InstanceMetricStrategy 实例指标策略
type InstanceMetricStrategy struct {
	ID            string       `json:"id" bson:"_id"`
	AgentCode     string       `json:"agent_code" bson:"agent_code"`         // Agent标识码
	MetricRules   []MetricRule `json:"metric_rules" bson:"metric_rules"`     // 实例规则列表
	InheritGlobal bool         `json:"inherit_global" bson:"inherit_global"`  // 是否继承全局配置
	CreatedAt     time.Time    `json:"created_at" bson:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at" bson:"updated_at"`
	Version       int64        `json:"version" bson:"version"` // 版本号（时间戳）
}

// ConfigStatus 配置生效状态
type ConfigStatus struct {
	Status      string    `json:"status"`       // active, pending, failed
	Version     string    `json:"version"`      // 配置版本号
	LastSync    time.Time `json:"last_sync"`    // 最后同步时间
	ErrorMessage string   `json:"error_message,omitempty"` // 错误信息（如果有）
}

// MetricRulePreview 规则预览结果
type MetricRulePreview struct {
	MatchedMetrics []string `json:"matched_metrics"` // 匹配的指标列表
	AgentCount     int      `json:"agent_count"`      // 影响的Agent数量
}

// AvailableMetricsResponse 可用指标列表响应
type AvailableMetricsResponse struct {
	Metrics []string `json:"metrics"`
}

// ApplicationTarget 应用指标采集目标
type ApplicationTarget struct {
	ServiceName string            `json:"service_name" bson:"service_name"`
	Protocol    string            `json:"protocol" bson:"protocol"` // prometheus/statsd/otel/json
	Endpoint    string            `json:"endpoint" bson:"endpoint"`
	Interval    int               `json:"interval" bson:"interval"` // 采集间隔（秒）
	Enabled     bool              `json:"enabled" bson:"enabled"`
	Labels      map[string]string `json:"labels,omitempty" bson:"labels,omitempty"`
}

// ApplicationMetricStrategy 应用指标策略
type ApplicationMetricStrategy struct {
	ID              string             `json:"id" bson:"_id"`
	DefaultInterval int                `json:"default_interval" bson:"default_interval"`
	Targets         []ApplicationTarget `json:"targets" bson:"targets"`
	Version         int64              `json:"version" bson:"version"`
	CreatedAt       time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at" bson:"updated_at"`
}

