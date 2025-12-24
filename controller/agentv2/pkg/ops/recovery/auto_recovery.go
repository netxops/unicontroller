package recovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"go.uber.org/zap"
)

// AutoRecovery 自动恢复管理器
type AutoRecovery struct {
	serviceManager service.ServiceManager
	logger         *zap.Logger
	recoveryState  map[string]*RecoveryState
	mu             sync.RWMutex
}

// RecoveryState 恢复状态
type RecoveryState struct {
	ServiceID     string
	RestartCount  int
	LastRestart   time.Time
	NextRestart   time.Time
	BackoffDelay  time.Duration
	MaxRestarts   int
	BackoffFactor float64
	MaxBackoff    time.Duration
}

// NewAutoRecovery 创建自动恢复管理器
func NewAutoRecovery(serviceManager service.ServiceManager, logger *zap.Logger) *AutoRecovery {
	return &AutoRecovery{
		serviceManager: serviceManager,
		logger:         logger,
		recoveryState:  make(map[string]*RecoveryState),
	}
}

// HandleUnhealthy 处理不健康的服务
func (r *AutoRecovery) HandleUnhealthy(ctx context.Context, service *domain.Service) error {
	if service.Spec.Operations == nil || service.Spec.Operations.AutoRecovery == nil {
		return nil // 没有配置自动恢复
	}

	config := service.Spec.Operations.AutoRecovery
	if !config.Enabled {
		return nil // 自动恢复未启用
	}

	r.mu.Lock()
	state, exists := r.recoveryState[service.ID]
	if !exists {
		state = &RecoveryState{
			ServiceID:     service.ID,
			MaxRestarts:   config.MaxRestarts,
			BackoffFactor: config.BackoffFactor,
			MaxBackoff:    config.MaxBackoff,
			BackoffDelay:  config.RestartDelay,
		}
		r.recoveryState[service.ID] = state
	}
	r.mu.Unlock()

	// 检查是否超过最大重启次数
	if state.RestartCount >= state.MaxRestarts {
		r.logger.Error("Service exceeded max restart attempts",
			zap.String("service_id", service.ID),
			zap.String("service_name", service.Name),
			zap.Int("restart_count", state.RestartCount),
			zap.Int("max_restarts", state.MaxRestarts),
		)
		return fmt.Errorf("service %s exceeded max restart attempts (%d)", service.ID, state.MaxRestarts)
	}

	// 检查是否在退避期内
	now := time.Now()
	if now.Before(state.NextRestart) {
		r.logger.Debug("Service in backoff period, skipping restart",
			zap.String("service_id", service.ID),
			zap.Time("next_restart", state.NextRestart),
		)
		return nil
	}

	// 执行重启
	r.logger.Info("Attempting to restart unhealthy service",
		zap.String("service_id", service.ID),
		zap.String("service_name", service.Name),
		zap.Int("restart_count", state.RestartCount+1),
	)

	if err := r.serviceManager.Restart(ctx, service.ID); err != nil {
		r.logger.Error("Failed to restart service",
			zap.String("service_id", service.ID),
			zap.Error(err),
		)
		return err
	}

	// 更新恢复状态
	r.mu.Lock()
	state.RestartCount++
	state.LastRestart = now
	state.BackoffDelay = r.calculateBackoff(state.BackoffDelay, state.BackoffFactor, state.MaxBackoff)
	state.NextRestart = now.Add(state.BackoffDelay)
	r.mu.Unlock()

	r.logger.Info("Service restarted successfully",
		zap.String("service_id", service.ID),
		zap.Int("restart_count", state.RestartCount),
		zap.Duration("next_backoff", state.BackoffDelay),
	)

	return nil
}

// ResetRecoveryState 重置恢复状态（服务恢复健康时调用）
func (r *AutoRecovery) ResetRecoveryState(serviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if state, exists := r.recoveryState[serviceID]; exists {
		// 如果服务已经健康运行一段时间，重置计数
		if time.Since(state.LastRestart) > 5*time.Minute {
			delete(r.recoveryState, serviceID)
			r.logger.Info("Reset recovery state for service",
				zap.String("service_id", serviceID),
			)
		}
	}
}

// GetRecoveryState 获取恢复状态
func (r *AutoRecovery) GetRecoveryState(serviceID string) (*RecoveryState, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	state, exists := r.recoveryState[serviceID]
	return state, exists
}

// calculateBackoff 计算退避延迟（指数退避）
func (r *AutoRecovery) calculateBackoff(currentDelay time.Duration, factor float64, maxBackoff time.Duration) time.Duration {
	newDelay := time.Duration(float64(currentDelay) * factor)
	if newDelay > maxBackoff {
		return maxBackoff
	}
	return newDelay
}
