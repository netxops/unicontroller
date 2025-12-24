package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap"
)

// MetricsCollector 指标收集器接口
type MetricsCollector interface {
	CollectSystemMetrics(ctx context.Context) (*domain.SystemMetrics, error)
	CollectServiceMetrics(ctx context.Context, serviceID string) (*domain.ServiceMetrics, error)
	Start(ctx context.Context) error
	Stop() error
	GetSystemMetrics() *domain.SystemMetrics
	GetServiceMetrics(serviceID string) (*domain.ServiceMetrics, bool)
	GetAllServiceMetrics() map[string]*domain.ServiceMetrics
	GetEnhancedCollector() *EnhancedMetricsCollector           // 获取增强型收集器
	UpdateEnhancedConfig(config EnhancedCollectorConfig) error // 更新增强型收集器配置
}

// ServiceRegistry 服务注册表接口（避免循环依赖）
type ServiceRegistry interface {
	Get(serviceID string) (*domain.Service, bool)
	List() []*domain.Service
}

// metricsCollector 指标收集器实现
type metricsCollector struct {
	logger         *zap.Logger
	registry       ServiceRegistry
	systemMetrics  *domain.SystemMetrics
	serviceMetrics map[string]*domain.ServiceMetrics
	mu             sync.RWMutex
	interval       time.Duration
	collectSystem  bool
	collectService bool
	stopChan       chan struct{}

	// 增强型收集器（可选，已废弃）
	enhancedCollector *EnhancedMetricsCollector
	useEnhanced       bool

	// Telegraf Input 收集器（新）
	telegrafInputCollector *TelegrafInputCollector
	useTelegrafInputs      bool

	// 历史缓存（可选）
	historyCache *MetricsHistoryCache
	useHistory   bool
}

// NewMetricsCollector 创建指标收集器（兼容旧接口）
func NewMetricsCollector(logger *zap.Logger, registry ServiceRegistry, config CollectorConfig) MetricsCollector {
	return NewMetricsCollectorWithEnhancedConfig(logger, registry, config, EnhancedCollectorConfig{})
}

// NewMetricsCollectorWithEnhancedConfig 创建指标收集器（支持增强型收集器配置）
func NewMetricsCollectorWithEnhancedConfig(logger *zap.Logger, registry ServiceRegistry, config CollectorConfig, enhancedConfig EnhancedCollectorConfig) MetricsCollector {
	logger.Info("Creating metrics collector",
		zap.Bool("enabled", true),
		zap.Bool("enhanced_enabled", config.EnhancedEnabled),
		zap.Bool("collect_system", config.CollectSystem),
		zap.Bool("collect_service", config.CollectService),
		zap.Duration("interval", config.Interval))

	mc := &metricsCollector{
		logger:                logger,
		registry:              registry,
		systemMetrics:         &domain.SystemMetrics{},
		serviceMetrics:        make(map[string]*domain.ServiceMetrics),
		interval:              config.Interval,
		collectSystem:         config.CollectSystem,
		collectService:        config.CollectService,
		stopChan:              make(chan struct{}),
		useEnhanced:           false, // 初始化为 false，只有在成功初始化后才设为 true
		useTelegrafInputs:     false,
		useHistory:             config.HistoryEnabled,
		enhancedCollector:      nil, // 初始化为 nil
		telegrafInputCollector: nil,
	}

	// 优先使用 Telegraf Input 插件（新方式）
	if config.TelegrafInputsEnabled {
		logger.Info("Initializing Telegraf input collector",
			zap.Bool("telegraf_inputs_enabled", config.TelegrafInputsEnabled),
			zap.Int("input_count", len(config.TelegrafInputsList)))
		
		interval := config.TelegrafInputsInterval
		if interval <= 0 {
			interval = config.Interval
		}
		
		telegrafCollector, err := NewTelegrafInputCollector(
			logger,
			config.TelegrafInputsList,
			interval,
			config.TelegrafInputsConfigs,
		)
		if err != nil {
			logger.Error("Failed to create Telegraf input collector",
				zap.Error(err))
			// 降级到增强型收集器或基础收集器
		} else {
			mc.telegrafInputCollector = telegrafCollector
			mc.useTelegrafInputs = true
			logger.Info("Telegraf input collector enabled successfully",
				zap.Bool("use_telegraf_inputs", mc.useTelegrafInputs))
		}
	}

	// 初始化增强型收集器（已废弃，仅在 Telegraf Inputs 未启用时使用）
	if !config.TelegrafInputsEnabled && config.EnhancedEnabled {
		logger.Info("Initializing enhanced metrics collector",
			zap.Bool("enhanced_enabled", config.EnhancedEnabled))
		enhanced, err := NewEnhancedMetricsCollector(logger, enhancedConfig)
		if err != nil {
			logger.Error("Failed to create enhanced collector",
				zap.Error(err),
				zap.String("error_details", err.Error()))
			// 增强型收集器初始化失败，保持 useEnhanced = false 和 enhancedCollector = nil
			mc.useEnhanced = false
			mc.enhancedCollector = nil
			logger.Warn("Metrics collector created but enhanced collector is unavailable",
				zap.Bool("use_enhanced", mc.useEnhanced),
				zap.Bool("collector_is_nil", mc.enhancedCollector == nil))
		} else {
			if enhanced == nil {
				logger.Error("NewEnhancedMetricsCollector returned nil without error")
				mc.useEnhanced = false
				mc.enhancedCollector = nil
			} else {
				mc.enhancedCollector = enhanced
				mc.useEnhanced = true
				logger.Info("Enhanced metrics collector enabled successfully",
					zap.Bool("use_enhanced", mc.useEnhanced),
					zap.Bool("collector_is_nil", mc.enhancedCollector == nil),
					zap.String("collector_type", fmt.Sprintf("%T", mc.enhancedCollector)))
			}
		}
	} else {
		logger.Warn("Enhanced metrics collector is disabled. Metrics endpoint will not work properly.",
			zap.Bool("enhanced_enabled", config.EnhancedEnabled))
		mc.useEnhanced = false
		mc.enhancedCollector = nil
	}

	logger.Info("Metrics collector created",
		zap.Bool("use_enhanced", mc.useEnhanced),
		zap.Bool("enhanced_collector_is_nil", mc.enhancedCollector == nil))

	// 初始化历史缓存（如果启用）
	if config.HistoryEnabled {
		maxPoints := config.HistoryMaxPoints
		if maxPoints <= 0 {
			maxPoints = 360 // 默认 360 个点（1小时，10秒间隔）
		}
		mc.historyCache = NewMetricsHistoryCache(logger, maxPoints)
		logger.Info("Metrics history cache enabled",
			zap.Int("max_points", maxPoints))
	}

	return mc
}

// CollectSystemMetrics 收集系统指标
func (c *metricsCollector) CollectSystemMetrics(ctx context.Context) (*domain.SystemMetrics, error) {
	var metrics *domain.SystemMetrics
	var err error

	// 优先使用 Telegraf Input 收集器（新方式）
	if c.useTelegrafInputs && c.telegrafInputCollector != nil {
		metrics, err = c.telegrafInputCollector.CollectSystemMetrics(ctx)
		if err != nil {
			c.logger.Warn("Telegraf input collector failed, falling back",
				zap.Error(err))
			// 降级到增强型收集器或基础收集器
			if c.useEnhanced && c.enhancedCollector != nil {
				metrics, err = c.enhancedCollector.CollectSystemMetrics(ctx)
				if err != nil {
					metrics, err = collectSystemMetrics()
				}
			} else {
				metrics, err = collectSystemMetrics()
			}
		}
	} else if c.useEnhanced && c.enhancedCollector != nil {
		// 使用增强型收集器（已废弃）
		metrics, err = c.enhancedCollector.CollectSystemMetrics(ctx)
		if err != nil {
			c.logger.Warn("Enhanced collector failed, falling back to basic",
				zap.Error(err))
			// 降级到基础收集器
			metrics, err = collectSystemMetrics()
		}
	} else {
		// 使用基础收集器
		metrics, err = collectSystemMetrics()
	}

	if err != nil {
		return nil, err
	}

	// 更新缓存
	c.mu.Lock()
	c.systemMetrics = metrics
	c.mu.Unlock()

	// 添加到历史缓存（如果启用）
	if c.useHistory && c.historyCache != nil {
		c.historyCache.AddSystemMetrics(metrics)
	}

	return metrics, nil
}

// CollectServiceMetrics 收集服务指标
func (c *metricsCollector) CollectServiceMetrics(ctx context.Context, serviceID string) (*domain.ServiceMetrics, error) {
	// 获取服务信息
	service, exists := c.registry.Get(serviceID)
	if !exists {
		return nil, fmt.Errorf("service %s not found", serviceID)
	}

	// 如果服务未运行，返回空指标
	if !service.IsRunning() {
		metrics := &domain.ServiceMetrics{
			LastUpdated: time.Now(),
		}
		c.mu.Lock()
		c.serviceMetrics[serviceID] = metrics
		c.mu.Unlock()

		// 添加到历史缓存（如果启用）
		if c.useHistory && c.historyCache != nil {
			c.historyCache.AddServiceMetrics(serviceID, metrics)
		}

		return metrics, nil
	}

	// 收集服务指标
	metrics, err := collectServiceMetrics(ctx, serviceID, service.Spec)
	if err != nil {
		c.logger.Warn("Failed to collect service metrics",
			zap.String("service", serviceID),
			zap.Error(err))
		// 返回空指标而不是错误
		metrics = &domain.ServiceMetrics{
			LastUpdated: time.Now(),
		}
	}

	c.mu.Lock()
	c.serviceMetrics[serviceID] = metrics
	c.mu.Unlock()

	// 添加到历史缓存（如果启用）
	if c.useHistory && c.historyCache != nil {
		c.historyCache.AddServiceMetrics(serviceID, metrics)
	}

	return metrics, nil
}

// Start 启动指标收集
func (c *metricsCollector) Start(ctx context.Context) error {
	// 如果使用 Telegraf Input 收集器，启动它
	if c.useTelegrafInputs && c.telegrafInputCollector != nil {
		if err := c.telegrafInputCollector.Start(ctx); err != nil {
			c.logger.Error("Failed to start Telegraf input collector", zap.Error(err))
			// 继续使用传统方式
		} else {
			c.logger.Info("Telegraf input collector started")
			// Telegraf Input 收集器在后台运行，我们只需要定期收集服务指标
			ticker := time.NewTicker(c.interval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return nil
				case <-c.stopChan:
					return nil
				case <-ticker.C:
					if c.collectService {
						// 收集所有运行中服务的指标
						services := c.registry.List()
						for _, service := range services {
							if service.IsRunning() {
								if _, err := c.CollectServiceMetrics(ctx, service.ID); err != nil {
									c.logger.Warn("Failed to collect service metrics",
										zap.String("service", service.ID),
										zap.Error(err))
								}
							}
						}
					}
				}
			}
		}
	}

	// 传统方式：定期收集指标
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// 立即收集一次
	if c.collectSystem {
		if _, err := c.CollectSystemMetrics(ctx); err != nil {
			c.logger.Error("Failed to collect system metrics", zap.Error(err))
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopChan:
			return nil
		case <-ticker.C:
			if c.collectSystem {
				if _, err := c.CollectSystemMetrics(ctx); err != nil {
					c.logger.Error("Failed to collect system metrics", zap.Error(err))
				}
			}
			if c.collectService {
				// 收集所有运行中服务的指标
				services := c.registry.List()
				for _, service := range services {
					if service.IsRunning() {
						if _, err := c.CollectServiceMetrics(ctx, service.ID); err != nil {
							c.logger.Warn("Failed to collect service metrics",
								zap.String("service", service.ID),
								zap.Error(err))
						}
					}
				}
			}
		}
	}
}

// Stop 停止指标收集
func (c *metricsCollector) Stop() error {
	// 停止 Telegraf Input 收集器
	if c.useTelegrafInputs && c.telegrafInputCollector != nil {
		if err := c.telegrafInputCollector.Stop(); err != nil {
			c.logger.Warn("Failed to stop Telegraf input collector", zap.Error(err))
		}
	}
	close(c.stopChan)
	return nil
}

// GetSystemMetrics 获取系统指标
func (c *metricsCollector) GetSystemMetrics() *domain.SystemMetrics {
	// 优先从 Telegraf Input 收集器获取
	if c.useTelegrafInputs && c.telegrafInputCollector != nil {
		return c.telegrafInputCollector.GetSystemMetrics()
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.systemMetrics
}

// GetServiceMetrics 获取服务指标
func (c *metricsCollector) GetServiceMetrics(serviceID string) (*domain.ServiceMetrics, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	metrics, exists := c.serviceMetrics[serviceID]
	return metrics, exists
}

// GetAllServiceMetrics 获取所有服务指标
func (c *metricsCollector) GetAllServiceMetrics() map[string]*domain.ServiceMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 创建副本以避免外部修改
	result := make(map[string]*domain.ServiceMetrics, len(c.serviceMetrics))
	for serviceID, metrics := range c.serviceMetrics {
		result[serviceID] = metrics
	}
	return result
}

// GetHistoryCache 获取历史缓存（如果启用）
func (c *metricsCollector) GetHistoryCache() *MetricsHistoryCache {
	return c.historyCache
}

// GetEnhancedCollector 获取增强型收集器（如果启用）
// 如果使用 Telegraf Input 收集器，返回 nil（因为接口不兼容）
func (c *metricsCollector) GetEnhancedCollector() *EnhancedMetricsCollector {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 如果使用 Telegraf Input 收集器，返回 nil
	if c.useTelegrafInputs {
		c.logger.Debug("Using Telegraf input collector, enhanced collector is not available")
		return nil
	}

	if c.enhancedCollector == nil {
		c.logger.Debug("Enhanced collector is nil",
			zap.Bool("use_enhanced", c.useEnhanced))
	}

	return c.enhancedCollector
}

// UpdateEnhancedConfig 更新增强型收集器配置
func (c *metricsCollector) UpdateEnhancedConfig(config EnhancedCollectorConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logger.Info("Updating enhanced collector config",
		zap.Int("enabled_count", len(config.EnabledCollectors)),
		zap.Int("exclude_count", len(config.ExcludeCollectors)),
		zap.Bool("only_core", config.OnlyCore))

	// 如果增强型收集器未启用，记录警告并返回
	if !c.useEnhanced {
		c.logger.Warn("Enhanced collector is not enabled, cannot update config")
		return fmt.Errorf("enhanced collector is not enabled")
	}

	// 如果当前没有增强型收集器，创建一个新的
	if c.enhancedCollector == nil {
		c.logger.Info("Creating new enhanced collector with updated config")
		enhanced, err := NewEnhancedMetricsCollector(c.logger, config)
		if err != nil {
			c.logger.Error("Failed to create enhanced collector with new config",
				zap.Error(err))
			return fmt.Errorf("failed to create enhanced collector: %w", err)
		}
		c.enhancedCollector = enhanced
		c.logger.Info("Enhanced collector created successfully")
		return nil
	}

	// 由于 EnhancedMetricsCollector 不支持动态更新配置，
	// 我们需要重新创建它。但这可能会影响正在进行的指标收集。
	// 为了安全起见，我们记录日志并提示需要重启。
	// 在实际生产环境中，可以考虑实现更优雅的更新机制。
	c.logger.Warn("Enhanced collector does not support dynamic config update",
		zap.String("action", "recreating collector"))

	// 尝试重新创建收集器
	enhanced, err := NewEnhancedMetricsCollector(c.logger, config)
	if err != nil {
		c.logger.Error("Failed to recreate enhanced collector",
			zap.Error(err))
		return fmt.Errorf("failed to recreate enhanced collector: %w", err)
	}

	// 替换旧的收集器
	oldCollector := c.enhancedCollector
	c.enhancedCollector = enhanced
	c.logger.Info("Enhanced collector recreated successfully",
		zap.String("old_collector", fmt.Sprintf("%p", oldCollector)),
		zap.String("new_collector", fmt.Sprintf("%p", enhanced)))

	// 更新配置
	if enhanced != nil {
		enhanced.mu.Lock()
		enhanced.currentConfig = config
		enhanced.mu.Unlock()
	}

	return nil
}
