package internal

import (
	"context"
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/registry"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"go.uber.org/zap"
)

// RegistryManager 注册管理器
type RegistryManager struct {
	registry       registry.Registry
	serviceManager service.ServiceManager
	logger         *zap.Logger
	agentCode      string
	grpcPort       int
	interval       time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewRegistryManager 创建注册管理器
func NewRegistryManager(
	reg registry.Registry,
	serviceManager service.ServiceManager,
	logger *zap.Logger,
	agentCode string,
	grpcPort int,
	interval time.Duration,
) *RegistryManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &RegistryManager{
		registry:       reg,
		serviceManager: serviceManager,
		logger:         logger,
		agentCode:      agentCode,
		grpcPort:       grpcPort,
		interval:       interval,
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start 启动注册管理器
func (rm *RegistryManager) Start() error {
	rm.logger.Info("Starting registry manager",
		zap.String("agent_code", rm.agentCode),
		zap.Int("grpc_port", rm.grpcPort),
		zap.Duration("interval", rm.interval))

	// 检查registry是否可用
	if rm.registry == nil {
		rm.logger.Error("Registry is not available (registry.enabled may be false)")
		return fmt.Errorf("registry is not available")
	}

	// 立即注册一次
	if err := rm.register(); err != nil {
		rm.logger.Error("Failed to register on start",
			zap.String("agent_code", rm.agentCode),
			zap.Error(err))
	} else {
		rm.logger.Info("Successfully registered on start",
			zap.String("agent_code", rm.agentCode))
	}

	// 启动定期注册
	go rm.periodicRegister()

	return nil
}

// Stop 停止注册管理器
func (rm *RegistryManager) Stop() error {
	rm.cancel()
	return rm.registry.Stop()
}

// periodicRegister 定期注册
func (rm *RegistryManager) periodicRegister() {
	ticker := time.NewTicker(rm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			if err := rm.register(); err != nil {
				rm.logger.Error("Failed to register service",
					zap.String("agent_code", rm.agentCode),
					zap.Int("grpc_port", rm.grpcPort),
					zap.Error(err))
			}
		}
	}
}

// register 注册服务
func (rm *RegistryManager) register() error {
	// 获取服务列表
	services, err := rm.serviceManager.ListServices(rm.ctx)
	if err != nil {
		return fmt.Errorf("failed to get services: %w", err)
	}

	// 构建服务列表（符合 Controller 的 PackageStatus 格式）
	// Controller 期望的格式: []models.PackageStatus
	// PackageStatus: { "name": string, "version": string, "is_running": bool, "duration": time.Duration }
	type PackageStatus struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		IsRunning bool   `json:"is_running"`
		Duration  int64  `json:"duration"` // 以秒为单位
	}

	serviceList := make([]PackageStatus, 0, len(services))
	for _, svc := range services {
		isRunning := svc.Status == domain.ServiceStatusRunning || svc.Status == domain.ServiceStatusStarting
		var duration int64
		// 如果服务有启动时间信息，计算运行时长
		if svc.StartedAt != nil {
			duration = int64(time.Since(*svc.StartedAt).Seconds())
		}
		serviceList = append(serviceList, PackageStatus{
			Name:      svc.Name,
			Version:   svc.Version,
			IsRunning: isRunning,
			Duration:  duration,
		})
	}

	// 检查 registry 是否可用
	if rm.registry == nil {
		return fmt.Errorf("registry is not available (registry.enabled may be false)")
	}

	// 构建服务信息
	// 注意：Address 使用 ":port" 格式，Register 方法会自动获取本机 IP
	info := &registry.ServiceInfo{
		Key:      rm.agentCode,
		Name:     "server-agent", // Controller 期望的服务名称
		Protocol: "grpc",
		Address:  fmt.Sprintf(":%d", rm.grpcPort), // 使用 ":port" 格式，Register 会获取本机 IP
		Meta: map[string]interface{}{
			"agent_code": rm.agentCode,
			"services":   serviceList, // []PackageStatus 类型，Register 会正确序列化
		},
	}

	// 注册到 etcd（使用配置的 TTL，如果没有配置则使用 60 秒）
	ttl := 60 * time.Second
	if rm.interval > 0 {
		// TTL 应该比 register_interval 长，确保在下次注册前不会过期
		ttl = rm.interval * 2
		if ttl < 60*time.Second {
			ttl = 60 * time.Second
		}
	}

	return rm.registry.Register(rm.ctx, info, ttl)
}
