package health

import (
	"context"
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

// HealthChecker 健康检查器接口
type HealthChecker interface {
	Check(ctx context.Context, service *domain.Service) (*domain.CheckResult, error)
	Start(ctx context.Context, service *domain.Service) error
	Stop(serviceID string) error
}

// healthChecker 健康检查器实现
type healthChecker struct {
	checkers map[string]Checker // serviceID -> Checker
	results  map[string]*domain.CheckResult
}

// Checker 具体检查器接口
type Checker interface {
	Check(ctx context.Context) (*domain.CheckResult, error)
	Type() string
}

// NewHealthChecker 创建健康检查器
func NewHealthChecker() HealthChecker {
	return &healthChecker{
		checkers: make(map[string]Checker),
		results:  make(map[string]*domain.CheckResult),
	}
}

// Check 执行健康检查
func (h *healthChecker) Check(ctx context.Context, service *domain.Service) (*domain.CheckResult, error) {
	if service.Spec.Operations == nil || service.Spec.Operations.HealthCheck == nil {
		// 没有配置健康检查，返回默认健康状态
		return &domain.CheckResult{
			Healthy:   true,
			Message:   "no health check configured",
			Timestamp: time.Now(),
		}, nil
	}

	checker, exists := h.checkers[service.ID]
	if !exists {
		// 创建检查器
		var err error
		checker, err = h.createChecker(service)
		if err != nil {
			return nil, err
		}
		h.checkers[service.ID] = checker
	}

	result, err := checker.Check(ctx)
	if err != nil {
		result = &domain.CheckResult{
			Healthy:   false,
			Message:   err.Error(),
			Error:     err,
			Timestamp: time.Now(),
		}
	}

	h.results[service.ID] = result
	return result, nil
}

// Start 启动健康检查
func (h *healthChecker) Start(ctx context.Context, service *domain.Service) error {
	if service.Spec.Operations == nil || service.Spec.Operations.HealthCheck == nil {
		return nil // 没有配置健康检查，不需要启动
	}

	// 创建检查器
	checker, err := h.createChecker(service)
	if err != nil {
		return err
	}
	h.checkers[service.ID] = checker

	// 启动定期检查
	go h.runPeriodicCheck(ctx, service, checker)

	return nil
}

// Stop 停止健康检查
func (h *healthChecker) Stop(serviceID string) error {
	delete(h.checkers, serviceID)
	delete(h.results, serviceID)
	return nil
}

// createChecker 创建检查器
func (h *healthChecker) createChecker(service *domain.Service) (Checker, error) {
	config := service.Spec.Operations.HealthCheck

	switch config.Type {
	case "http":
		return NewHTTPChecker(config), nil
	case "tcp":
		return NewTCPChecker(config), nil
	case "process":
		return NewProcessChecker(config, service), nil
	case "script":
		return NewScriptChecker(config), nil
	default:
		return nil, fmt.Errorf("unsupported health check type: %s", config.Type)
	}
}

// runPeriodicCheck 运行定期检查
func (h *healthChecker) runPeriodicCheck(ctx context.Context, service *domain.Service, checker Checker) {
	config := service.Spec.Operations.HealthCheck
	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := checker.Check(ctx)
			if err != nil {
				result = &domain.CheckResult{
					Healthy:   false,
					Message:   err.Error(),
					Error:     err,
					Timestamp: time.Now(),
				}
			}
			h.results[service.ID] = result
		}
	}
}
