package service

import (
	"context"
	"fmt"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/errors"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/infrastructure/process"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/infrastructure/systemd"
)

// ServiceManager 服务管理器接口
type ServiceManager interface {
	Start(ctx context.Context, serviceID string) error
	Stop(ctx context.Context, serviceID string) error
	Restart(ctx context.Context, serviceID string) error
	GetStatus(ctx context.Context, serviceID string) (*domain.Service, error)
	ListServices(ctx context.Context) ([]*domain.Service, error)
	RegisterService(service *domain.Service) error
	UnregisterService(serviceID string) error
}

// serviceManager 服务管理器实现
type serviceManager struct {
	registry       *ServiceRegistry
	systemd        *systemd.SystemdAdapter
	processManager process.ProcessManager
	dependencyMgr  *DependencyManager
}

// NewServiceManager 创建服务管理器
func NewServiceManager(
	registry *ServiceRegistry,
	systemd *systemd.SystemdAdapter,
	processManager process.ProcessManager,
) ServiceManager {
	return &serviceManager{
		registry:       registry,
		systemd:        systemd,
		processManager: processManager,
		dependencyMgr:  NewDependencyManager(registry),
	}
}

// Start 启动服务
func (m *serviceManager) Start(ctx context.Context, serviceID string) error {
	service, exists := m.registry.Get(serviceID)
	if !exists {
		return errors.NewError(errors.ErrCodeServiceNotFound, fmt.Sprintf("service %s not found", serviceID))
	}

	if service.IsRunning() {
		return errors.NewError(errors.ErrCodeServiceAlreadyRunning, fmt.Sprintf("service %s is already running", serviceID))
	}

	// 检查并启动依赖服务
	if err := m.startDependencies(ctx, service); err != nil {
		return errors.WrapError(errors.ErrCodeServiceStartFailed, fmt.Sprintf("failed to start dependencies for service %s", serviceID), err)
	}

	service.UpdateStatus(domain.ServiceStatusStarting)

	// 根据启动方式启动服务
	if service.Spec.Startup.Method == "systemd" {
		if err := m.systemd.Start(service.Spec.Startup.ServiceName); err != nil {
			service.UpdateStatus(domain.ServiceStatusFailed)
			service.LastError = err
			return errors.WrapError(errors.ErrCodeServiceStartFailed, fmt.Sprintf("failed to start service %s", serviceID), err)
		}
	} else if service.Spec.Startup.Method == "direct" {
		// 直接启动方式
		if m.processManager == nil {
			return errors.NewError(errors.ErrCodeInternal, "process manager not available")
		}
		if err := m.processManager.Start(ctx, service); err != nil {
			service.UpdateStatus(domain.ServiceStatusFailed)
			service.LastError = err
			return errors.WrapError(errors.ErrCodeServiceStartFailed, fmt.Sprintf("failed to start service %s", serviceID), err)
		}
	} else {
		return errors.NewError(errors.ErrCodeInvalidRequest, fmt.Sprintf("unsupported startup method: %s", service.Spec.Startup.Method))
	}

	service.UpdateStatus(domain.ServiceStatusRunning)
	return nil
}

// Stop 停止服务
func (m *serviceManager) Stop(ctx context.Context, serviceID string) error {
	service, exists := m.registry.Get(serviceID)
	if !exists {
		return errors.NewError(errors.ErrCodeServiceNotFound, fmt.Sprintf("service %s not found", serviceID))
	}

	if !service.IsRunning() {
		return errors.NewError(errors.ErrCodeServiceNotRunning, fmt.Sprintf("service %s is not running", serviceID))
	}

	// 检查是否有其他服务依赖此服务
	dependents := m.dependencyMgr.GetDependents(serviceID)
	runningDependents := make([]string, 0)
	for _, dep := range dependents {
		if dep.IsRunning() {
			runningDependents = append(runningDependents, dep.Name)
		}
	}
	if len(runningDependents) > 0 {
		return errors.NewError(
			errors.ErrCodeServiceStopFailed,
			fmt.Sprintf("cannot stop service %s: the following services depend on it and are still running: %v", serviceID, runningDependents),
		)
	}

	service.UpdateStatus(domain.ServiceStatusStopping)

	if service.Spec.Startup.Method == "systemd" {
		if err := m.systemd.Stop(service.Spec.Startup.ServiceName); err != nil {
			service.UpdateStatus(domain.ServiceStatusFailed)
			service.LastError = err
			return errors.WrapError(errors.ErrCodeServiceStopFailed, fmt.Sprintf("failed to stop service %s", serviceID), err)
		}
	} else if service.Spec.Startup.Method == "direct" {
		if m.processManager == nil {
			return errors.NewError(errors.ErrCodeInternal, "process manager not available")
		}
		if err := m.processManager.Stop(ctx, serviceID); err != nil {
			service.UpdateStatus(domain.ServiceStatusFailed)
			service.LastError = err
			return errors.WrapError(errors.ErrCodeServiceStopFailed, fmt.Sprintf("failed to stop service %s", serviceID), err)
		}
	}

	service.UpdateStatus(domain.ServiceStatusStopped)
	return nil
}

// Restart 重启服务
func (m *serviceManager) Restart(ctx context.Context, serviceID string) error {
	service, exists := m.registry.Get(serviceID)
	if !exists {
		return errors.NewError(errors.ErrCodeServiceNotFound, fmt.Sprintf("service %s not found", serviceID))
	}

	service.UpdateStatus(domain.ServiceStatusRestarting)

	if service.Spec.Startup.Method == "systemd" {
		if err := m.systemd.Restart(service.Spec.Startup.ServiceName); err != nil {
			service.UpdateStatus(domain.ServiceStatusFailed)
			service.LastError = err
			return errors.WrapError(errors.ErrCodeInternal, fmt.Sprintf("failed to restart service %s", serviceID), err)
		}
	} else if service.Spec.Startup.Method == "direct" {
		if m.processManager == nil {
			return errors.NewError(errors.ErrCodeInternal, "process manager not available")
		}
		if err := m.processManager.Restart(ctx, service); err != nil {
			service.UpdateStatus(domain.ServiceStatusFailed)
			service.LastError = err
			return errors.WrapError(errors.ErrCodeInternal, fmt.Sprintf("failed to restart service %s", serviceID), err)
		}
	}

	service.UpdateStatus(domain.ServiceStatusRunning)
	service.RestartCount++
	return nil
}

// GetStatus 获取服务状态
func (m *serviceManager) GetStatus(ctx context.Context, serviceID string) (*domain.Service, error) {
	service, exists := m.registry.Get(serviceID)
	if !exists {
		return nil, errors.NewError(errors.ErrCodeServiceNotFound, fmt.Sprintf("service %s not found", serviceID))
	}

	// 更新实际状态
	if service.Spec.Startup.Method == "systemd" {
		isActive, err := m.systemd.IsActive(service.Spec.Startup.ServiceName)
		if err == nil {
			if isActive && service.Status != domain.ServiceStatusRunning {
				service.UpdateStatus(domain.ServiceStatusRunning)
			} else if !isActive && service.Status == domain.ServiceStatusRunning {
				service.UpdateStatus(domain.ServiceStatusStopped)
			}
		}
	} else if service.Spec.Startup.Method == "direct" {
		if m.processManager != nil {
			isRunning, err := m.processManager.IsRunning(serviceID)
			if err == nil {
				if isRunning && service.Status != domain.ServiceStatusRunning {
					service.UpdateStatus(domain.ServiceStatusRunning)
				} else if !isRunning && service.Status == domain.ServiceStatusRunning {
					service.UpdateStatus(domain.ServiceStatusStopped)
				}
			}
		}
	}

	return service, nil
}

// ListServices 列出所有服务
func (m *serviceManager) ListServices(ctx context.Context) ([]*domain.Service, error) {
	return m.registry.List(), nil
}

// RegisterService 注册服务
func (m *serviceManager) RegisterService(service *domain.Service) error {
	m.registry.Register(service)
	return nil
}

// UnregisterService 注销服务
func (m *serviceManager) UnregisterService(serviceID string) error {
	m.registry.Unregister(serviceID)
	return nil
}

// startDependencies 启动服务的依赖
func (m *serviceManager) startDependencies(ctx context.Context, service *domain.Service) error {
	if service.Spec.Operations == nil || len(service.Spec.Operations.Dependencies) == 0 {
		return nil
	}

	// 获取依赖服务的 ID 列表
	depServiceIDs := make([]string, 0, len(service.Spec.Operations.Dependencies))
	for _, depName := range service.Spec.Operations.Dependencies {
		depService, exists := m.registry.GetByName(depName)
		if !exists {
			return errors.NewError(
				errors.ErrCodeServiceNotFound,
				fmt.Sprintf("dependency service %s not found for service %s", depName, service.Name),
			)
		}
		depServiceIDs = append(depServiceIDs, depService.ID)
	}

	// 解析依赖顺序（拓扑排序）
	sortedDeps, err := m.dependencyMgr.ResolveDependencies(depServiceIDs)
	if err != nil {
		return errors.WrapError(
			errors.ErrCodeInternal,
			fmt.Sprintf("failed to resolve dependencies for service %s", service.Name),
			err,
		)
	}

	// 按顺序启动依赖服务
	for _, depID := range sortedDeps {
		depService, exists := m.registry.Get(depID)
		if !exists {
			continue
		}

		// 如果依赖服务已经在运行，跳过
		if depService.IsRunning() {
			continue
		}

		// 递归启动依赖服务的依赖
		if err := m.startDependencies(ctx, depService); err != nil {
			return errors.WrapError(
				errors.ErrCodeServiceStartFailed,
				fmt.Sprintf("failed to start dependencies of %s", depService.Name),
				err,
			)
		}

		// 直接启动依赖服务（不通过 Start 方法，避免重复检查）
		depService.UpdateStatus(domain.ServiceStatusStarting)

		if depService.Spec.Startup.Method == "systemd" {
			if err := m.systemd.Start(depService.Spec.Startup.ServiceName); err != nil {
				depService.UpdateStatus(domain.ServiceStatusFailed)
				depService.LastError = err
				return errors.WrapError(
					errors.ErrCodeServiceStartFailed,
					fmt.Sprintf("failed to start dependency service %s for service %s", depService.Name, service.Name),
					err,
				)
			}
		} else if depService.Spec.Startup.Method == "direct" {
			if m.processManager == nil {
				return errors.NewError(errors.ErrCodeInternal, "process manager not available")
			}
			if err := m.processManager.Start(ctx, depService); err != nil {
				depService.UpdateStatus(domain.ServiceStatusFailed)
				depService.LastError = err
				return errors.WrapError(
					errors.ErrCodeServiceStartFailed,
					fmt.Sprintf("failed to start dependency service %s for service %s", depService.Name, service.Name),
					err,
				)
			}
		} else {
			return errors.NewError(
				errors.ErrCodeInvalidRequest,
				fmt.Sprintf("unsupported startup method: %s for dependency service %s", depService.Spec.Startup.Method, depService.Name),
			)
		}

		depService.UpdateStatus(domain.ServiceStatusRunning)
	}

	return nil
}
