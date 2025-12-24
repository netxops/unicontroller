package service

import (
	"sync"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

// ServiceRegistry 服务注册表
type ServiceRegistry struct {
	mu       sync.RWMutex
	services map[string]*domain.Service
}

// NewServiceRegistry 创建服务注册表
func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		services: make(map[string]*domain.Service),
	}
}

// Register 注册服务
func (r *ServiceRegistry) Register(service *domain.Service) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services[service.ID] = service
}

// Unregister 注销服务
func (r *ServiceRegistry) Unregister(serviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.services, serviceID)
}

// Get 获取服务
func (r *ServiceRegistry) Get(serviceID string) (*domain.Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	service, exists := r.services[serviceID]
	return service, exists
}

// GetByName 根据名称获取服务
func (r *ServiceRegistry) GetByName(name string) (*domain.Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, service := range r.services {
		if service.Name == name {
			return service, true
		}
	}
	return nil, false
}

// List 列出所有服务
func (r *ServiceRegistry) List() []*domain.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	services := make([]*domain.Service, 0, len(r.services))
	for _, service := range r.services {
		services = append(services, service)
	}
	return services
}

// Count 获取服务数量
func (r *ServiceRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.services)
}
