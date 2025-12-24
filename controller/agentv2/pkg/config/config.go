package config

import (
	"time"
)

// Config Agent V2 配置
type Config struct {
	Agent        AgentConfig        `yaml:"agent"`
	Server       ServerConfig       `yaml:"server"`
	Registry     RegistryConfig     `yaml:"registry"`
	Discovery    DiscoveryConfig    `yaml:"discovery"`
	HealthCheck  HealthCheckConfig  `yaml:"health_check"`
	AutoRecovery AutoRecoveryConfig `yaml:"auto_recovery"`
	Metrics      MetricsConfig      `yaml:"metrics"`
	Logging      LoggingConfig      `yaml:"logging"`
}

// AgentConfig Agent 配置
type AgentConfig struct {
	Code      string `yaml:"code"`
	Workspace string `yaml:"workspace"`
	LogLevel  string `yaml:"log_level"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	GRPCPort  int    `yaml:"grpc_port"`
	HTTPPort  int    `yaml:"http_port"`
	UploadDir string `yaml:"upload_dir"` // 文件上传目录
}

// RegistryConfig 服务注册配置
type RegistryConfig struct {
	Enabled          bool          `yaml:"enabled"`
	EtcdEndpoints    []string      `yaml:"etcd_endpoints"`
	EtcdUsername     string        `yaml:"etcd_username"` // etcd 用户名（可选）
	EtcdPassword     string        `yaml:"etcd_password"` // etcd 密码（可选）
	EtcdPrefix       string        `yaml:"etcd_prefix"`
	RegisterInterval time.Duration `yaml:"register_interval"`
	TTL              time.Duration `yaml:"ttl"`
}

// DiscoveryConfig 服务发现配置
type DiscoveryConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	DefaultInterval time.Duration `yaml:"default_interval"`
	DefaultTimeout  time.Duration `yaml:"default_timeout"`
	DefaultRetries  int           `yaml:"default_retries"`
}

// AutoRecoveryConfig 自动恢复配置
type AutoRecoveryConfig struct {
	Enabled       bool          `yaml:"enabled"`
	MaxRestarts   int           `yaml:"max_restarts"`
	RestartDelay  time.Duration `yaml:"restart_delay"`
	BackoffFactor float64       `yaml:"backoff_factor"`
	MaxBackoff    time.Duration `yaml:"max_backoff"`
}

// MetricsConfig 指标收集配置
type MetricsConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Interval       time.Duration `yaml:"interval"`
	CollectSystem  bool          `yaml:"collect_system"`
	CollectService bool          `yaml:"collect_service"`
	// 增强型收集器配置
	EnhancedEnabled    bool     `yaml:"enhanced_enabled"`    // 是否启用增强型收集器（基于 Prometheus）
	EnhancedCollectors []string `yaml:"enhanced_collectors"` // 启用的collectors列表（空表示启用所有）
	EnhancedExclude    []string `yaml:"enhanced_exclude"`    // 排除的collectors列表
	EnhancedOnlyCore   bool     `yaml:"enhanced_only_core"`  // 是否只启用核心collectors
	// 历史缓存配置
	HistoryEnabled   bool `yaml:"history_enabled"`    // 是否启用历史缓存
	HistoryMaxPoints int  `yaml:"history_max_points"` // 历史数据点最大数量，默认 360
	// 指标上报配置
	ReportEnabled  bool          `yaml:"report_enabled"`  // 是否启用指标上报
	ControllerURL  string        `yaml:"controller_url"`  // Controller 地址（例如：http://controller:8080）
	ReportInterval time.Duration `yaml:"report_interval"` // 上报间隔
	RetryCount     int           `yaml:"retry_count"`     // 失败重试次数
	RetryDelay     time.Duration `yaml:"retry_delay"`     // 重试延迟
	// 应用指标配置
	ApplicationEnabled  bool   `yaml:"application_enabled"`  // 是否启用应用指标收集
	ApplicationEndpoint string `yaml:"application_endpoint"` // 应用指标接收端点（例如：:9091）
	// 应用指标拉取配置
	ApplicationPullEnabled  bool                `yaml:"application_pull_enabled"`  // 是否启用应用指标主动拉取
	ApplicationPullInterval time.Duration       `yaml:"application_pull_interval"`  // 默认拉取间隔
	ApplicationTargets     []ApplicationTarget `yaml:"application_targets"`       // 本地配置的采集目标（可选）
	// 指标策略配置
	StrategyEnabled      bool          `yaml:"strategy_enabled"`       // 是否启用策略
	StrategySource       string        `yaml:"strategy_source"`      // 策略来源（"config"或"api"）
	StrategyVersion      int64         `yaml:"strategy_version"`      // 策略版本号
	StrategyAPIURL       string        `yaml:"strategy_api_url"`      // 策略API地址（如果使用API源）
	StrategySyncInterval time.Duration `yaml:"strategy_sync_interval"` // 策略同步间隔
	// Telegraf Input 插件配置
	TelegrafInputs TelegrafInputsConfig `yaml:"telegraf_inputs"` // Telegraf input 插件配置
}

// TelegrafInputsConfig Telegraf Input 插件配置
type TelegrafInputsConfig struct {
	Enabled  []string               `yaml:"enabled"`  // 启用的插件列表
	Configs  map[string]interface{} `yaml:"configs"`  // 插件配置（每个插件的具体配置）
	Interval time.Duration          `yaml:"interval"` // 采集间隔
}

// ApplicationTarget 应用指标采集目标
type ApplicationTarget struct {
	ServiceName string            `yaml:"service_name"`
	Protocol    string            `yaml:"protocol"` // prometheus/statsd/otel/json
	Endpoint    string            `yaml:"endpoint"`
	Interval    int               `yaml:"interval"` // 采集间隔（秒）
	Enabled     bool              `yaml:"enabled"`
	Labels      map[string]string `yaml:"labels,omitempty"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Directory string `yaml:"directory"`
	MaxSize   string `yaml:"max_size"`
	MaxFiles  int    `yaml:"max_files"`
	Level     string `yaml:"level"`
}
