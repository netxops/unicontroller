package health

import (
	"context"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/recovery"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"go.uber.org/zap"
)

// ServiceRegistry 服务注册表接口（避免循环依赖）
type ServiceRegistry interface {
	Get(serviceID string) (*domain.Service, bool)
	List() []*domain.Service
}

// Coordinator 健康检查和自动恢复协调器
type Coordinator struct {
	healthChecker  HealthChecker
	autoRecovery   *recovery.AutoRecovery
	serviceManager service.ServiceManager
	registry       ServiceRegistry
	logger         *zap.Logger
	history        *HealthHistory
	notifier       HealthNotifier
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.RWMutex
	monitored      map[string]bool                // serviceID -> isMonitored
	lastStatus     map[string]domain.HealthStatus // serviceID -> last status
}

// NewCoordinator 创建协调器
func NewCoordinator(
	healthChecker HealthChecker,
	autoRecovery *recovery.AutoRecovery,
	serviceManager service.ServiceManager,
	registry ServiceRegistry,
	logger *zap.Logger,
) *Coordinator {
	ctx, cancel := context.WithCancel(context.Background())
	return &Coordinator{
		healthChecker:  healthChecker,
		autoRecovery:   autoRecovery,
		serviceManager: serviceManager,
		registry:       registry,
		logger:         logger,
		history:        NewHealthHistory(1000), // 每个服务保留 1000 条历史记录
		ctx:            ctx,
		cancel:         cancel,
		monitored:      make(map[string]bool),
		lastStatus:     make(map[string]domain.HealthStatus),
	}
}

// Start 启动协调器
func (c *Coordinator) Start() error {
	c.logger.Info("Starting health check and auto recovery coordinator")

	// 启动定期检查所有服务的健康状态
	c.wg.Add(1)
	go c.monitorServices()

	return nil
}

// Stop 停止协调器
func (c *Coordinator) Stop() error {
	c.logger.Info("Stopping health check and auto recovery coordinator")
	c.cancel()
	c.wg.Wait()
	return nil
}

// monitorServices 监控所有服务
func (c *Coordinator) monitorServices() {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second) // 每30秒检查一次
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkAllServices()
		}
	}
}

// checkAllServices 检查所有服务的健康状态
func (c *Coordinator) checkAllServices() {
	services := c.registry.List()

	for _, service := range services {
		// 只检查运行中的服务
		if !service.IsRunning() {
			// 如果服务停止，停止健康检查
			if c.isMonitored(service.ID) {
				c.stopMonitoring(service.ID)
			}
			continue
		}

		// 启动健康检查（如果还没有启动）
		if !c.isMonitored(service.ID) {
			c.startMonitoring(service)
		}

		// 执行健康检查
		result, err := c.healthChecker.Check(c.ctx, service)
		if err != nil {
			c.logger.Warn("Health check failed",
				zap.String("service", service.ID),
				zap.Error(err))
			continue
		}

		// 更新服务的健康状态
		c.updateServiceHealth(service, result)

		// 如果服务不健康，触发自动恢复
		if !result.Healthy {
			c.handleUnhealthyService(service, result)
		} else {
			// 服务恢复健康，重置恢复状态
			if c.autoRecovery != nil {
				c.autoRecovery.ResetRecoveryState(service.ID)
			}
		}
	}
}

// startMonitoring 开始监控服务
func (c *Coordinator) startMonitoring(service *domain.Service) {
	// 启动健康检查
	if err := c.healthChecker.Start(c.ctx, service); err != nil {
		c.logger.Warn("Failed to start health check",
			zap.String("service", service.ID),
			zap.Error(err))
		return
	}

	c.mu.Lock()
	c.monitored[service.ID] = true
	c.mu.Unlock()

	c.logger.Info("Started monitoring service",
		zap.String("service", service.ID))
}

// stopMonitoring 停止监控服务
func (c *Coordinator) stopMonitoring(serviceID string) {
	c.healthChecker.Stop(serviceID)

	c.mu.Lock()
	delete(c.monitored, serviceID)
	c.mu.Unlock()

	c.logger.Info("Stopped monitoring service",
		zap.String("service", serviceID))
}

// isMonitored 检查服务是否正在被监控
func (c *Coordinator) isMonitored(serviceID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.monitored[serviceID]
}

// updateServiceHealth 更新服务的健康状态
func (c *Coordinator) updateServiceHealth(service *domain.Service, result *domain.CheckResult) {
	if service.Health == nil {
		service.Health = &domain.ServiceHealth{}
	}

	oldStatus := service.Health.Status
	newStatus := domain.HealthStatusUnhealthy
	if result.Healthy {
		newStatus = domain.HealthStatusHealthy
	}

	service.Health.Status = newStatus
	service.Health.LastCheck = result.Timestamp
	service.Health.Message = result.Message

	// 更新健康状态详情
	if len(service.Health.Details) == 0 {
		service.Health.Details = []domain.HealthStatusDetail{}
	}

	// 添加或更新最新的检查结果
	detail := domain.HealthStatusDetail{
		Status:       service.Health.Status,
		Message:      result.Message,
		LastCheck:    result.Timestamp,
		ResponseTime: result.ResponseTime,
		Error:        result.Error,
	}

	// 只保留最新的详情
	service.Health.Details = []domain.HealthStatusDetail{detail}

	// 获取检查类型
	checkType := "unknown"
	if service.Spec != nil && service.Spec.Operations != nil && service.Spec.Operations.HealthCheck != nil {
		checkType = service.Spec.Operations.HealthCheck.Type
	}

	// 保存历史记录
	if c.history != nil {
		c.history.Add(service.ID, result, checkType)
	}

	// 检查状态变化并发送通知
	c.mu.Lock()
	lastStatus, exists := c.lastStatus[service.ID]
	c.lastStatus[service.ID] = newStatus
	c.mu.Unlock()

	if !exists || lastStatus != newStatus {
		// 状态发生变化，发送通知
		c.notifyStatusChange(service, oldStatus, newStatus, result)
	}
}

// notifyStatusChange 通知健康状态变化
func (c *Coordinator) notifyStatusChange(service *domain.Service, oldStatus, newStatus domain.HealthStatus, result *domain.CheckResult) {
	c.logger.Info("Health status changed",
		zap.String("service", service.ID),
		zap.String("old_status", string(oldStatus)),
		zap.String("new_status", string(newStatus)),
		zap.String("message", result.Message))

	// 如果配置了通知器，发送通知
	if c.notifier != nil {
		if err := c.notifier.Notify(service, oldStatus, newStatus, result); err != nil {
			c.logger.Error("Failed to send health status notification",
				zap.String("service", service.ID),
				zap.Error(err))
		}
	}
}

// GetHistory 获取健康检查历史记录
func (c *Coordinator) GetHistory(serviceID string, limit int) []*HealthHistoryEntry {
	if c.history == nil {
		return []*HealthHistoryEntry{}
	}
	return c.history.Get(serviceID, limit)
}

// SetNotifier 设置通知器
func (c *Coordinator) SetNotifier(notifier HealthNotifier) {
	c.notifier = notifier
}

// handleUnhealthyService 处理不健康的服务
func (c *Coordinator) handleUnhealthyService(service *domain.Service, result *domain.CheckResult) {
	c.logger.Warn("Service is unhealthy",
		zap.String("service", service.ID),
		zap.String("message", result.Message),
		zap.Bool("healthy", result.Healthy))

	// 触发自动恢复
	if c.autoRecovery != nil {
		if err := c.autoRecovery.HandleUnhealthy(c.ctx, service); err != nil {
			c.logger.Error("Auto recovery failed",
				zap.String("service", service.ID),
				zap.Error(err))
		}
	}
}
