package config

import (
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/utils"
	"github.com/spf13/viper"
)

// Load 从文件加载配置
func Load(path string) (*Config, error) {
	// 重置 viper 实例（避免全局状态污染）
	viper.Reset()

	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	// 设置默认值（必须在 ReadInConfig 之前）
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 如果配置文件中没有设置端口，使用 viper 的默认值
	if cfg.Server.GRPCPort == 0 {
		cfg.Server.GRPCPort = viper.GetInt("server.grpc_port")
	}
	if cfg.Server.HTTPPort == 0 {
		cfg.Server.HTTPPort = viper.GetInt("server.http_port")
	}

	// 如果配置文件中没有设置 etcd_endpoints，使用 viper 的默认值
	if len(cfg.Registry.EtcdEndpoints) == 0 && viper.IsSet("registry.etcd_endpoints") {
		cfg.Registry.EtcdEndpoints = viper.GetStringSlice("registry.etcd_endpoints")
	}

	// 手动读取 etcd 认证信息（viper.Unmarshal 可能无法正确解析）
	if viper.IsSet("registry.etcd_username") {
		cfg.Registry.EtcdUsername = viper.GetString("registry.etcd_username")
	}
	if viper.IsSet("registry.etcd_password") {
		cfg.Registry.EtcdPassword = viper.GetString("registry.etcd_password")
	}
	if viper.IsSet("registry.etcd_prefix") {
		cfg.Registry.EtcdPrefix = viper.GetString("registry.etcd_prefix")
	}

	// 如果配置文件中没有设置 workspace，使用默认值
	if cfg.Agent.Workspace == "" {
		cfg.Agent.Workspace = utils.GetDefaultWorkspace()
	}

	// 如果配置文件中没有设置日志目录，使用默认值
	if cfg.Logging.Directory == "" {
		cfg.Logging.Directory = utils.GetDefaultLogDirectory()
	}

	// 手动解析时间字段（viper 不支持直接解析 time.Duration）
	if err := parseDurations(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse durations: %w", err)
	}

	// 显式读取 controller_url（确保从配置文件或环境变量中正确读取）
	// 直接读取值，不依赖 IsSet（因为 IsSet 可能在某些情况下返回 false）
	cfg.Metrics.ControllerURL = viper.GetString("metrics.controller_url")

	// 验证配置
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// setDefaults 设置默认值
func setDefaults() {
	// Agent 默认值（根据用户权限设置）
	viper.SetDefault("agent.code", "agent-001")
	viper.SetDefault("agent.workspace", utils.GetDefaultWorkspace())
	viper.SetDefault("agent.log_level", "info")

	// Server 默认值
	viper.SetDefault("server.grpc_port", 10380)
	viper.SetDefault("server.http_port", 8080)
	viper.SetDefault("server.upload_dir", "") // 留空使用默认值

	// Registry 默认值
	viper.SetDefault("registry.enabled", true)
	viper.SetDefault("registry.etcd_endpoints", []string{"127.0.0.1:2379"})
	viper.SetDefault("registry.etcd_prefix", "/agents")
	viper.SetDefault("registry.register_interval", "30s")
	viper.SetDefault("registry.ttl", "60s")

	// Discovery 默认值
	viper.SetDefault("discovery.enabled", true)
	viper.SetDefault("discovery.interval", "30s")

	// HealthCheck 默认值
	viper.SetDefault("health_check.default_interval", "30s")
	viper.SetDefault("health_check.default_timeout", "5s")
	viper.SetDefault("health_check.default_retries", 3)

	// AutoRecovery 默认值
	viper.SetDefault("auto_recovery.enabled", true)
	viper.SetDefault("auto_recovery.max_restarts", 5)
	viper.SetDefault("auto_recovery.restart_delay", "5s")
	viper.SetDefault("auto_recovery.backoff_factor", 2.0)
	viper.SetDefault("auto_recovery.max_backoff", "60s")

	// Metrics 默认值
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.interval", "10s")
	viper.SetDefault("metrics.collect_system", true)
	viper.SetDefault("metrics.collect_service", true)
	// 增强型收集器配置
	viper.SetDefault("metrics.enhanced_enabled", true)
	viper.SetDefault("metrics.enhanced_collectors", []string{}) // 空列表表示启用所有
	viper.SetDefault("metrics.enhanced_exclude", []string{})
	viper.SetDefault("metrics.enhanced_only_core", false)
	// 历史缓存配置
	viper.SetDefault("metrics.history_enabled", true)
	viper.SetDefault("metrics.history_max_points", 360)
	// 指标上报配置
	viper.SetDefault("metrics.report_enabled", false)
	viper.SetDefault("metrics.controller_url", "http://localhost:8080")
	viper.SetDefault("metrics.report_interval", "30s")
	viper.SetDefault("metrics.retry_count", 3)
	viper.SetDefault("metrics.retry_delay", "5s")
	// 应用指标配置
	viper.SetDefault("metrics.application_enabled", true)
	viper.SetDefault("metrics.application_endpoint", ":9091")
	// 指标策略配置
	viper.SetDefault("metrics.strategy_enabled", false)
	viper.SetDefault("metrics.strategy_source", "config")
	viper.SetDefault("metrics.strategy_version", int64(0))
	viper.SetDefault("metrics.strategy_api_url", "")
	viper.SetDefault("metrics.strategy_sync_interval", "5m")

	// Logging 默认值（根据用户权限设置）
	viper.SetDefault("logging.directory", utils.GetDefaultLogDirectory())
	viper.SetDefault("logging.max_size", "100MB")
	viper.SetDefault("logging.max_files", 10)
	viper.SetDefault("logging.level", "info")
}

// validate 验证配置
func validate(cfg *Config) error {
	if cfg.Agent.Code == "" {
		return fmt.Errorf("agent.code is required")
	}

	if cfg.Server.GRPCPort <= 0 || cfg.Server.GRPCPort > 65535 {
		return fmt.Errorf("server.grpc_port must be between 1 and 65535")
	}

	if cfg.Server.HTTPPort <= 0 || cfg.Server.HTTPPort > 65535 {
		return fmt.Errorf("server.http_port must be between 1 and 65535")
	}

	if cfg.Registry.Enabled && len(cfg.Registry.EtcdEndpoints) == 0 {
		return fmt.Errorf("registry.etcd_endpoints is required when registry is enabled")
	}

	// 如果启用了策略功能且使用 API 源，验证 controller_url 是否配置
	if cfg.Metrics.StrategyEnabled && cfg.Metrics.StrategySource == "api" {
		if cfg.Metrics.ControllerURL == "" && cfg.Metrics.StrategyAPIURL == "" {
			return fmt.Errorf("metrics.controller_url or metrics.strategy_api_url is required when strategy is enabled with API source")
		}
	}

	return nil
}

// parseDurations 解析配置中的时间字段
func parseDurations(cfg *Config) error {
	// 解析 Registry 时间字段
	if s := viper.GetString("registry.register_interval"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid registry.register_interval: %w", err)
		}
		cfg.Registry.RegisterInterval = d
	}
	if s := viper.GetString("registry.ttl"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid registry.ttl: %w", err)
		}
		cfg.Registry.TTL = d
	}

	// 解析 Discovery 时间字段
	if s := viper.GetString("discovery.interval"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid discovery.interval: %w", err)
		}
		cfg.Discovery.Interval = d
	}

	// 解析 HealthCheck 时间字段
	if s := viper.GetString("health_check.default_interval"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid health_check.default_interval: %w", err)
		}
		cfg.HealthCheck.DefaultInterval = d
	}
	if s := viper.GetString("health_check.default_timeout"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid health_check.default_timeout: %w", err)
		}
		cfg.HealthCheck.DefaultTimeout = d
	}

	// 解析 AutoRecovery 时间字段
	if s := viper.GetString("auto_recovery.restart_delay"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid auto_recovery.restart_delay: %w", err)
		}
		cfg.AutoRecovery.RestartDelay = d
	}
	if s := viper.GetString("auto_recovery.max_backoff"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid auto_recovery.max_backoff: %w", err)
		}
		cfg.AutoRecovery.MaxBackoff = d
	}

	// 解析 Metrics 时间字段
	if s := viper.GetString("metrics.interval"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid metrics.interval: %w", err)
		}
		cfg.Metrics.Interval = d
	}

	// 确保 EnhancedEnabled 正确读取（viper.Unmarshal 可能不会正确设置布尔值）
	// 直接读取值，不依赖 IsSet（因为 IsSet 可能在某些情况下返回 false）
	cfg.Metrics.EnhancedEnabled = viper.GetBool("metrics.enhanced_enabled")

	// 读取增强型收集器配置
	// 如果配置文件中没有设置，GetStringSlice 会返回空切片，GetBool 会返回默认值 false
	cfg.Metrics.EnhancedCollectors = viper.GetStringSlice("metrics.enhanced_collectors")
	cfg.Metrics.EnhancedExclude = viper.GetStringSlice("metrics.enhanced_exclude")
	cfg.Metrics.EnhancedOnlyCore = viper.GetBool("metrics.enhanced_only_core")

	// 读取策略配置
	cfg.Metrics.StrategyEnabled = viper.GetBool("metrics.strategy_enabled")
	cfg.Metrics.StrategySource = viper.GetString("metrics.strategy_source")
	cfg.Metrics.StrategyVersion = viper.GetInt64("metrics.strategy_version")
	cfg.Metrics.StrategyAPIURL = viper.GetString("metrics.strategy_api_url")
	if s := viper.GetString("metrics.strategy_sync_interval"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			cfg.Metrics.StrategySyncInterval = d
		}
	}

	return nil
}
