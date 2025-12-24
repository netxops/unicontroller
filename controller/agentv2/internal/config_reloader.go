package internal

import (
	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/logs"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/metrics"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"go.uber.org/zap"
)

// ConfigReloadHandler 配置重载处理器
type ConfigReloadHandler struct {
	registryManager  *RegistryManager
	serviceDiscovery service.ServiceDiscovery
	metricsCollector metrics.MetricsCollector
	metricsReporter  metrics.MetricsReporter
	logManager       logs.LogManager
	logger           *zap.Logger
}

// NewConfigReloadHandler 创建配置重载处理器
func NewConfigReloadHandler(
	registryManager *RegistryManager,
	serviceDiscovery service.ServiceDiscovery,
	metricsCollector metrics.MetricsCollector,
	metricsReporter metrics.MetricsReporter,
	logManager logs.LogManager,
	logger *zap.Logger,
) *ConfigReloadHandler {
	return &ConfigReloadHandler{
		registryManager:  registryManager,
		serviceDiscovery: serviceDiscovery,
		metricsCollector: metricsCollector,
		metricsReporter:  metricsReporter,
		logManager:       logManager,
		logger:           logger,
	}
}

// HandleConfigChange 处理配置变更
func (h *ConfigReloadHandler) HandleConfigChange(newConfig *config.Config) error {
	h.logger.Info("Handling config change")

	// 检查哪些配置发生了变化
	// 注意：某些配置（如端口号）不能热重载，需要重启服务
	// 这里只处理可以热重载的配置

	// 1. 更新服务发现间隔（如果可以动态调整）
	if h.serviceDiscovery != nil {
		// 注意：ServiceDiscovery 接口可能不支持动态更新间隔
		// 这里只是示例，实际实现可能需要扩展接口
		h.logger.Info("Config change: discovery interval",
			zap.Duration("new_interval", newConfig.Discovery.Interval))
	}

	// 2. 更新指标收集间隔
	if h.metricsCollector != nil {
		// 注意：MetricsCollector 接口可能不支持动态更新间隔
		// 这里只是示例，实际实现可能需要扩展接口
		h.logger.Info("Config change: metrics interval",
			zap.Duration("new_interval", newConfig.Metrics.Interval))
	}

	// 3. 更新指标上报配置
	if h.metricsReporter != nil {
		// 如果指标上报配置发生变化，需要重启上报器
		// 这里只是记录，实际重启需要更复杂的逻辑
		h.logger.Info("Config change: metrics reporter",
			zap.Bool("report_enabled", newConfig.Metrics.ReportEnabled),
			zap.String("controller_url", newConfig.Metrics.ControllerURL),
			zap.Duration("report_interval", newConfig.Metrics.ReportInterval))
	}

	// 4. 更新日志管理器配置
	if h.logManager != nil {
		// 日志目录等配置可能需要更新
		h.logger.Info("Config change: logging",
			zap.String("directory", newConfig.Logging.Directory),
			zap.String("max_size", newConfig.Logging.MaxSize),
			zap.Int("max_files", newConfig.Logging.MaxFiles))
	}

	// 5. 检查是否需要重启服务（端口号变化等）
	needsRestart := h.checkNeedsRestart(newConfig)
	if needsRestart {
		h.logger.Warn("Config change requires service restart",
			zap.String("reason", "server ports or other critical config changed"))
		// 注意：实际实现中，可能需要触发服务重启
		// 这里只是记录警告
	}

	return nil
}

// checkNeedsRestart 检查是否需要重启服务
func (h *ConfigReloadHandler) checkNeedsRestart(newConfig *config.Config) bool {
	// 端口号变化需要重启
	// 这里需要保存旧配置来比较
	// 暂时返回 false，实际实现需要更复杂的逻辑
	return false
}
