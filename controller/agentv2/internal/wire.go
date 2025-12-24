//go:build wireinject
// +build wireinject

package internal

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/wire"
	"github.com/influxdata/telegraf/controller/agentv2/internal/api"
	"github.com/influxdata/telegraf/controller/agentv2/internal/server"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/infrastructure/process"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/infrastructure/systemd"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/health"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/logs"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/metrics"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/recovery"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/registry"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/utils"
	"go.uber.org/zap"
)

// InitializeApp 初始化应用
func InitializeApp(cfg *config.Config, configPath string, logger *zap.Logger) (*App, error) {
	wire.Build(
		// 基础设施
		provideSystemdAdapter,
		provideProcessManager,

		// 服务层
		service.NewServiceManager,
		service.NewServiceRegistry,
		service.NewConfigManager,
		provideServiceDiscovery,

		// 运维模块
		provideLogManager,
		provideMetricsCollector,
		provideMetricsReporter,
		provideHealthChecker,
		provideAutoRecovery,
		provideHealthCoordinator,

		// API 层（核心服务）
		api.NewPackageService,
		api.NewCommandService,
		provideHealthService,
		provideApplicationTargetManager,
		provideApplicationMetricsCollector,
		provideMetricsService,
		provideFileService,
		provideFileGRPCService,

		// 注册器
		provideRegistry,
		provideRegistryManager,

		// 服务器配置（从 Config 提取）
		provideServerConfig,

		// 服务器（需要指标收集器）
		provideServerMetricsCollector,
		provideServer,

		// 配置重载器
		provideConfigReloader,

		// 策略管理
		provideStrategyManager,
		provideStrategySyncer,

		// 应用
		NewApp,
	)
	return nil, nil
}

// App 应用结构
type App struct {
	Server            *server.Server
	RegistryManager   *RegistryManager
	ServiceDiscovery  service.ServiceDiscovery
	HealthCoordinator *health.Coordinator
	MetricsCollector  metrics.MetricsCollector
	MetricsReporter   metrics.MetricsReporter
	ConfigReloader    config.ConfigReloader
	StrategySyncer    *StrategySyncer
}

// NewApp 创建应用
func NewApp(
	srv *server.Server,
	regMgr *RegistryManager,
	discovery service.ServiceDiscovery,
	healthCoord *health.Coordinator,
	metricsCollector metrics.MetricsCollector,
	metricsReporter metrics.MetricsReporter,
	configReloader config.ConfigReloader,
	strategySyncer *StrategySyncer,
) *App {
	return &App{
		Server:            srv,
		RegistryManager:   regMgr,
		ServiceDiscovery:  discovery,
		HealthCoordinator: healthCoord,
		MetricsCollector:  metricsCollector,
		MetricsReporter:   metricsReporter,
		ConfigReloader:    configReloader,
		StrategySyncer:    strategySyncer,
	}
}

// provideSystemdAdapter 提供 systemd 适配器
func provideSystemdAdapter(cfg *config.Config) *systemd.SystemdAdapter {
	// 根据用户权限决定使用 system 还是 user 模式
	// 特权用户使用 system 模式，普通用户使用 user 模式
	isUserUnit := !utils.IsPrivilegedUser()
	return systemd.NewSystemdAdapter(isUserUnit)
}

// provideProcessManager 提供进程管理器
func provideProcessManager(cfg *config.Config, logger *zap.Logger) process.ProcessManager {
	// PID 文件目录
	pidDir := filepath.Join(utils.GetHomeDir(), ".local", "run", "agentv2")
	if utils.IsPrivilegedUser() {
		pidDir = "/var/run/agentv2"
	}

	// 日志目录（使用配置的日志目录）
	logDir := cfg.Logging.Directory
	if logDir == "" {
		logDir = utils.GetDefaultLogDirectory()
	}

	return process.NewProcessManager(logger, pidDir, logDir)
}

// provideMetricsCollector 提供指标收集器
func provideMetricsCollector(cfg *config.Config, registry *service.ServiceRegistry, logger *zap.Logger) metrics.MetricsCollector {
	logger.Info("Providing metrics collector",
		zap.Bool("metrics_enabled", cfg.Metrics.Enabled),
		zap.Bool("enhanced_enabled", cfg.Metrics.EnhancedEnabled),
		zap.Bool("collect_system", cfg.Metrics.CollectSystem),
		zap.Bool("collect_service", cfg.Metrics.CollectService))

	if !cfg.Metrics.Enabled {
		// 如果指标收集未启用，返回一个空实现
		logger.Warn("Metrics collection is disabled")
		return metrics.NewMetricsCollector(logger, registry, metrics.CollectorConfig{
			Interval:        cfg.Metrics.Interval,
			CollectSystem:   false,
			CollectService:  false,
			EnhancedEnabled: false, // 明确设置为 false
		})
	}

	// 检查是否启用 Telegraf Inputs
	telegrafInputsEnabled := len(cfg.Metrics.TelegrafInputs.Enabled) > 0

	metricsConfig := metrics.CollectorConfig{
		Interval:              cfg.Metrics.Interval,
		CollectSystem:         cfg.Metrics.CollectSystem,
		CollectService:        cfg.Metrics.CollectService,
		EnhancedEnabled:       cfg.Metrics.EnhancedEnabled && !telegrafInputsEnabled, // 如果启用 Telegraf Inputs，禁用 Enhanced
		HistoryEnabled:        cfg.Metrics.HistoryEnabled,
		HistoryMaxPoints:      cfg.Metrics.HistoryMaxPoints,
		TelegrafInputsEnabled: telegrafInputsEnabled,
		TelegrafInputsList:    cfg.Metrics.TelegrafInputs.Enabled,
		TelegrafInputsConfigs: cfg.Metrics.TelegrafInputs.Configs,
		TelegrafInputsInterval: cfg.Metrics.TelegrafInputs.Interval,
	}

	// 构建增强型收集器配置（仅在未启用 Telegraf Inputs 时使用）
	var enhancedConfig metrics.EnhancedCollectorConfig
	if cfg.Metrics.EnhancedEnabled && !telegrafInputsEnabled {
		enhancedConfig = metrics.EnhancedCollectorConfig{
			EnabledCollectors: cfg.Metrics.EnhancedCollectors,
			ExcludeCollectors: cfg.Metrics.EnhancedExclude,
			OnlyCore:          cfg.Metrics.EnhancedOnlyCore,
		}
	}

	logger.Info("Creating metrics collector with config",
		zap.Bool("telegraf_inputs_enabled", telegrafInputsEnabled),
		zap.Int("telegraf_inputs_count", len(cfg.Metrics.TelegrafInputs.Enabled)),
		zap.Bool("enhanced_enabled", metricsConfig.EnhancedEnabled),
		zap.Bool("history_enabled", metricsConfig.HistoryEnabled),
		zap.Int("history_max_points", metricsConfig.HistoryMaxPoints),
		zap.Bool("enhanced_only_core", enhancedConfig.OnlyCore),
		zap.Int("enhanced_enabled_count", len(enhancedConfig.EnabledCollectors)),
		zap.Int("enhanced_exclude_count", len(enhancedConfig.ExcludeCollectors)))

	return metrics.NewMetricsCollectorWithEnhancedConfig(logger, registry, metricsConfig, enhancedConfig)
}

// provideRegistry 提供注册器
func provideRegistry(cfg *config.Config, logger *zap.Logger) (registry.Registry, error) {
	if !cfg.Registry.Enabled {
		// 如果注册未启用，返回一个空实现或错误
		logger.Info("Registry is disabled in config")
		return nil, nil
	}

	// 记录配置信息用于调试
	hasAuth := cfg.Registry.EtcdUsername != "" && cfg.Registry.EtcdPassword != ""
	logger.Info("Creating etcd registry from config",
		zap.Strings("endpoints", cfg.Registry.EtcdEndpoints),
		zap.String("prefix", cfg.Registry.EtcdPrefix),
		zap.Bool("has_auth", hasAuth),
		zap.String("username", cfg.Registry.EtcdUsername),
	)

	return registry.NewEtcdRegistryWithAuth(
		cfg.Registry.EtcdEndpoints,
		cfg.Registry.EtcdPrefix,
		cfg.Registry.EtcdUsername,
		cfg.Registry.EtcdPassword,
		logger,
	)
}

// provideServerConfig 从 Config 提供服务器配置
func provideServerConfig(cfg *config.Config) server.ServerConfig {
	return server.ServerConfig{
		ConfigPath: "", // 配置路径不再需要
		GRPCPort:   cfg.Server.GRPCPort,
		HTTPPort:   cfg.Server.HTTPPort,
	}
}

// provideLogManager 提供日志管理器
func provideLogManager(cfg *config.Config, logger *zap.Logger) logs.LogManager {
	// 解析 max_size（例如 "100MB"）
	maxSize := int64(100 * 1024 * 1024) // 默认 100MB
	if cfg.Logging.MaxSize != "" {
		// 简单解析，支持 MB/GB
		if strings.HasSuffix(cfg.Logging.MaxSize, "MB") {
			var mb int64
			fmt.Sscanf(cfg.Logging.MaxSize, "%dMB", &mb)
			maxSize = mb * 1024 * 1024
		} else if strings.HasSuffix(cfg.Logging.MaxSize, "GB") {
			var gb int64
			fmt.Sscanf(cfg.Logging.MaxSize, "%dGB", &gb)
			maxSize = gb * 1024 * 1024 * 1024
		}
	}

	return logs.NewLogManager(
		cfg.Logging.Directory,
		maxSize,
		cfg.Logging.MaxFiles,
		logger,
	)
}

// provideRegistryManager 提供注册管理器
func provideRegistryManager(
	cfg *config.Config,
	reg registry.Registry,
	serviceManager service.ServiceManager,
	logger *zap.Logger,
	serverConfig server.ServerConfig,
) *RegistryManager {
	if !cfg.Registry.Enabled {
		return nil
	}
	return NewRegistryManager(
		reg,
		serviceManager,
		logger,
		cfg.Agent.Code,
		serverConfig.GRPCPort,
		cfg.Registry.RegisterInterval,
	)
}

// provideServiceDiscovery 提供服务发现
func provideServiceDiscovery(
	cfg *config.Config,
	registry *service.ServiceRegistry,
	logger *zap.Logger,
) service.ServiceDiscovery {
	if !cfg.Discovery.Enabled {
		return nil
	}
	return service.NewServiceDiscovery(
		cfg.Agent.Workspace,
		cfg.Discovery.Interval,
		registry,
		logger,
	)
}

// provideHealthChecker 提供健康检查器
func provideHealthChecker() health.HealthChecker {
	return health.NewHealthChecker()
}

// provideAutoRecovery 提供自动恢复管理器
func provideAutoRecovery(serviceManager service.ServiceManager, logger *zap.Logger) *recovery.AutoRecovery {
	return recovery.NewAutoRecovery(serviceManager, logger)
}

// provideHealthCoordinator 提供健康检查和自动恢复协调器
func provideHealthCoordinator(
	healthChecker health.HealthChecker,
	autoRecovery *recovery.AutoRecovery,
	serviceManager service.ServiceManager,
	registry *service.ServiceRegistry,
	logger *zap.Logger,
) *health.Coordinator {
	return health.NewCoordinator(
		healthChecker,
		autoRecovery,
		serviceManager,
		registry,
		logger,
	)
}

// provideServerMetricsCollector 为 Server 提供指标收集器适配器
func provideServerMetricsCollector(metricsCollector metrics.MetricsCollector, logger *zap.Logger) server.MetricsCollector {
	adapter := &metricsCollectorAdapter{collector: metricsCollector}

	// 验证适配器是否能正确获取增强型收集器
	if enhanced := adapter.GetEnhancedCollector(); enhanced != nil {
		logger.Info("Server metrics collector adapter initialized with enhanced collector",
			zap.String("enhanced_type", fmt.Sprintf("%T", enhanced)))
	} else {
		logger.Warn("Server metrics collector adapter initialized but enhanced collector is nil",
			zap.String("collector_type", fmt.Sprintf("%T", metricsCollector)))
	}

	return adapter
}

// provideServer 提供服务器实例（带策略支持）
func provideServer(
	serverConfig server.ServerConfig,
	logger *zap.Logger,
	packageService *api.PackageService,
	commandService *api.CommandService,
	healthService *api.HealthService,
	metricsService *api.MetricsService,
	fileService *api.FileGRPCService,
	serverMetricsCollector server.MetricsCollector,
	strategySyncer *StrategySyncer,
	cfg *config.Config,
) (*server.Server, error) {
	return server.NewServerWithStrategy(
		serverConfig,
		logger,
		packageService,
		commandService,
		healthService,
		metricsService,
		fileService,
		serverMetricsCollector,
		strategySyncer,
		cfg,
	)
}

// provideHealthService 提供健康检查服务
func provideHealthService(
	healthChecker health.HealthChecker,
	healthCoordinator *health.Coordinator,
	serviceManager service.ServiceManager,
	logger *zap.Logger,
) *api.HealthService {
	return api.NewHealthService(healthChecker, healthCoordinator, serviceManager, logger)
}

// provideApplicationTargetManager 提供应用指标采集目标管理器
func provideApplicationTargetManager(
	cfg *config.Config,
	strategyManager *metrics.StrategyManager,
	logger *zap.Logger,
) *metrics.ApplicationTargetManager {
	if !cfg.Metrics.ApplicationPullEnabled {
		return nil
	}

	targetManager := metrics.NewApplicationTargetManager(cfg, logger, strategyManager)

	// 加载采集目标（异步，避免阻塞启动）
	go func() {
		ctx := context.Background()
		if err := targetManager.LoadTargets(ctx); err != nil {
			logger.Warn("Failed to load application targets", zap.Error(err))
		}
	}()

	return targetManager
}

// provideApplicationMetricsCollector 提供应用指标收集器
func provideApplicationMetricsCollector(
	cfg *config.Config,
	targetManager *metrics.ApplicationTargetManager,
	logger *zap.Logger,
) *metrics.ApplicationMetricsCollector {
	if !cfg.Metrics.ApplicationEnabled {
		return nil
	}

	endpoint := cfg.Metrics.ApplicationEndpoint
	if endpoint == "" {
		endpoint = ":9091" // 默认端点
	}

	collector, err := metrics.NewApplicationMetricsCollector(logger, endpoint)
	if err != nil {
		logger.Warn("Failed to create application metrics collector", zap.Error(err))
		return nil
	}

	// 如果启用了拉取模式，启用它
	if cfg.Metrics.ApplicationPullEnabled && targetManager != nil {
		collector.EnablePullMode(targetManager)
		logger.Info("Application metrics pull mode enabled")
	}

	return collector
}

// provideMetricsService 提供指标服务
func provideMetricsService(
	metricsCollector metrics.MetricsCollector,
	applicationCollector *metrics.ApplicationMetricsCollector,
	serviceManager service.ServiceManager,
	logger *zap.Logger,
) *api.MetricsService {
	return api.NewMetricsService(metricsCollector, applicationCollector, serviceManager, logger)
}

// provideFileService 提供文件服务
func provideFileService(cfg *config.Config, logger *zap.Logger) *api.FileService {
	uploadDir := cfg.Server.UploadDir
	if uploadDir == "" {
		uploadDir = "/tmp/agentv2/uploads"
	}
	return api.NewFileService(logger, uploadDir)
}

// provideFileGRPCService 提供文件 gRPC 服务
func provideFileGRPCService(fileService *api.FileService, logger *zap.Logger) *api.FileGRPCService {
	return api.NewFileGRPCService(fileService, logger)
}

// provideMetricsReporter 提供指标上报器
func provideMetricsReporter(
	cfg *config.Config,
	metricsCollector metrics.MetricsCollector,
	logger *zap.Logger,
) metrics.MetricsReporter {
	if !cfg.Metrics.ReportEnabled {
		// 如果指标上报未启用，返回 nil（调用者需要检查）
		return nil
	}

	return metrics.NewMetricsReporter(
		metricsCollector,
		cfg.Metrics.ControllerURL,
		cfg.Agent.Code,
		cfg.Metrics.ReportInterval,
		cfg.Metrics.RetryCount,
		cfg.Metrics.RetryDelay,
		logger,
	)
}

// metricsCollectorAdapter 适配器，将 metrics.MetricsCollector 适配为 server.MetricsCollector
type metricsCollectorAdapter struct {
	collector metrics.MetricsCollector
}

func (a *metricsCollectorAdapter) GetSystemMetrics() interface{} {
	// 使用反射或类型断言来访问私有方法
	// 由于 metricsCollector 是私有类型，我们需要通过接口扩展
	// 或者创建一个公开的访问器方法
	// 这里我们使用一个简单的解决方案：通过接口扩展

	// 尝试类型断言到有 GetSystemMetrics 方法的类型
	type systemMetricsGetter interface {
		GetSystemMetrics() *domain.SystemMetrics
	}

	if getter, ok := a.collector.(systemMetricsGetter); ok {
		return getter.GetSystemMetrics()
	}

	return nil
}

func (a *metricsCollectorAdapter) GetServiceMetrics(serviceID string) (interface{}, bool) {
	type serviceMetricsGetter interface {
		GetServiceMetrics(serviceID string) (*domain.ServiceMetrics, bool)
	}

	if getter, ok := a.collector.(serviceMetricsGetter); ok {
		return getter.GetServiceMetrics(serviceID)
	}

	return nil, false
}

func (a *metricsCollectorAdapter) GetAllServiceMetrics() map[string]interface{} {
	type allServiceMetricsGetter interface {
		GetAllServiceMetrics() map[string]*domain.ServiceMetrics
	}

	if getter, ok := a.collector.(allServiceMetricsGetter); ok {
		allMetrics := getter.GetAllServiceMetrics()
		if allMetrics == nil {
			return nil
		}
		// 转换为 map[string]interface{}
		result := make(map[string]interface{}, len(allMetrics))
		for serviceID, svcMetrics := range allMetrics {
			result[serviceID] = svcMetrics
		}
		return result
	}

	return nil
}

func (a *metricsCollectorAdapter) GetHistoryCache() interface{} {
	type historyCacheGetter interface {
		GetHistoryCache() interface{}
	}

	if getter, ok := a.collector.(historyCacheGetter); ok {
		return getter.GetHistoryCache()
	}

	return nil
}

func (a *metricsCollectorAdapter) GetEnhancedCollector() interface{} {
	// MetricsCollector 接口现在包含 GetEnhancedCollector() 方法
	// 直接调用接口方法
	if a.collector != nil {
		result := a.collector.GetEnhancedCollector()
		return result
	}
	return nil
}

// provideConfigReloader 提供配置重载器
func provideConfigReloader(
	cfg *config.Config,
	configPath string,
	registryManager *RegistryManager,
	serviceDiscovery service.ServiceDiscovery,
	metricsCollector metrics.MetricsCollector,
	metricsReporter metrics.MetricsReporter,
	logManager logs.LogManager,
	logger *zap.Logger,
) config.ConfigReloader {
	reloader, err := config.NewConfigReloader(configPath, logger)
	if err != nil {
		logger.Warn("Failed to create config reloader", zap.Error(err))
		return nil
	}

	// 创建配置变更处理器
	handler := NewConfigReloadHandler(
		registryManager,
		serviceDiscovery,
		metricsCollector,
		metricsReporter,
		logManager,
		logger,
	)

	// 注册配置变更回调
	reloader.OnReload(handler.HandleConfigChange)

	return reloader
}

// provideStrategyManager 提供策略管理器
func provideStrategyManager(cfg *config.Config, logger *zap.Logger) *metrics.StrategyManager {
	return metrics.NewStrategyManager(cfg, logger)
}

// provideStrategySyncer 提供策略同步器
func provideStrategySyncer(
	cfg *config.Config,
	strategyManager *metrics.StrategyManager,
	metricsCollector metrics.MetricsCollector,
	logger *zap.Logger,
) *StrategySyncer {
	return NewStrategySyncer(cfg, strategyManager, metricsCollector, logger)
}
