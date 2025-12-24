package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	"go.uber.org/zap"
)

// ApplicationTargetManager 应用指标采集目标管理器
type ApplicationTargetManager struct {
	cfg             *config.Config
	logger          *zap.Logger
	httpClient      *http.Client
	targets         map[string]*PullTarget
	mu              sync.RWMutex
	strategyManager StrategyManagerInterface
}

// PullTarget 拉取目标配置
type PullTarget struct {
	ServiceName string
	Protocol    string // prometheus/statsd/otel/json
	Endpoint    string // HTTP 端点或 UDP 地址
	Interval    int    // 采集间隔（秒）
	Enabled     bool
	Labels      map[string]string
	LastScrape  time.Time
	LastError   error
}

// ApplicationTargetStrategy 应用指标策略（从 API 获取）
type ApplicationTargetStrategy struct {
	ID              string       `json:"id"`
	DefaultInterval int          `json:"default_interval"`
	Targets         []PullTarget `json:"targets"`
	Version         int64        `json:"version"`
}

// NewApplicationTargetManager 创建应用指标采集目标管理器
func NewApplicationTargetManager(cfg *config.Config, logger *zap.Logger, strategyManager StrategyManagerInterface) *ApplicationTargetManager {
	return &ApplicationTargetManager{
		cfg:             cfg,
		logger:          logger,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		targets:         make(map[string]*PullTarget),
		strategyManager: strategyManager,
	}
}

// LoadTargets 加载采集目标（从策略管理器或本地配置）
func (m *ApplicationTargetManager) LoadTargets(ctx context.Context) error {
	if !m.cfg.Metrics.ApplicationPullEnabled {
		m.logger.Info("Application pull is disabled, skipping target load")
		return nil
	}

	// 优先从策略管理器获取（如果启用）
	if m.cfg.Metrics.StrategyEnabled && m.cfg.Metrics.StrategySource == "api" {
		if err := m.loadTargetsFromAPI(ctx); err != nil {
			m.logger.Warn("Failed to load targets from API, using local config",
				zap.Error(err))
			// 如果 API 加载失败，回退到本地配置
			return m.loadTargetsFromConfig()
		}
		return nil
	}

	// 从本地配置加载
	return m.loadTargetsFromConfig()
}

// loadTargetsFromAPI 从 API 加载采集目标
func (m *ApplicationTargetManager) loadTargetsFromAPI(ctx context.Context) error {
	agentCode := m.cfg.Agent.Code
	baseURL := m.cfg.Metrics.StrategyAPIURL
	if baseURL == "" {
		baseURL = m.cfg.Metrics.ControllerURL
	}
	if baseURL == "" {
		return fmt.Errorf("strategy API URL is not configured")
	}

	// 加载全局策略
	globalURL := fmt.Sprintf("%s/api/v1/platform/metrics/strategy/application/global", baseURL)
	global, err := m.fetchStrategy(ctx, globalURL)
	if err != nil {
		m.logger.Warn("Failed to load global application strategy, using default",
			zap.String("url", globalURL),
			zap.Error(err))
		global = &ApplicationTargetStrategy{
			ID:              "global",
			DefaultInterval: 60,
			Targets:         []PullTarget{},
			Version:         0,
		}
	}

	// 加载实例策略
	instanceURL := fmt.Sprintf("%s/api/v1/platform/metrics/strategy/application/instance/%s", baseURL, agentCode)
	instance, err := m.fetchStrategy(ctx, instanceURL)
	if err != nil {
		m.logger.Warn("Failed to load instance application strategy, using global",
			zap.String("url", instanceURL),
			zap.String("agent_code", agentCode),
			zap.Error(err))
		instance = &ApplicationTargetStrategy{
			ID:              agentCode,
			DefaultInterval: global.DefaultInterval,
			Targets:         []PullTarget{},
			Version:         0,
		}
	}

	// 合并策略（实例策略覆盖全局策略）
	m.mergeTargets(global, instance)

	m.logger.Info("Loaded application targets from API",
		zap.Int("global_targets", len(global.Targets)),
		zap.Int("instance_targets", len(instance.Targets)),
		zap.Int("total_targets", len(m.targets)))

	return nil
}

// loadTargetsFromConfig 从本地配置加载采集目标
func (m *ApplicationTargetManager) loadTargetsFromConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.targets = make(map[string]*PullTarget)

	for _, target := range m.cfg.Metrics.ApplicationTargets {
		if !target.Enabled {
			continue
		}

		pullTarget := &PullTarget{
			ServiceName: target.ServiceName,
			Protocol:    target.Protocol,
			Endpoint:    target.Endpoint,
			Interval:    target.Interval,
			Enabled:     target.Enabled,
			Labels:      target.Labels,
		}

		// 如果没有指定间隔，使用默认间隔
		if pullTarget.Interval <= 0 {
			if m.cfg.Metrics.ApplicationPullInterval > 0 {
				pullTarget.Interval = int(m.cfg.Metrics.ApplicationPullInterval.Seconds())
			} else {
				pullTarget.Interval = 60 // 默认 60 秒
			}
		}

		key := fmt.Sprintf("%s:%s", pullTarget.ServiceName, pullTarget.Endpoint)
		m.targets[key] = pullTarget
	}

	m.logger.Info("Loaded application targets from config",
		zap.Int("count", len(m.targets)))

	return nil
}

// fetchStrategy 获取策略
func (m *ApplicationTargetManager) fetchStrategy(ctx context.Context, url string) (*ApplicationTargetStrategy, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch strategy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var strategy ApplicationTargetStrategy
	if err := json.Unmarshal(body, &strategy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal strategy: %w", err)
	}

	return &strategy, nil
}

// mergeTargets 合并策略目标
func (m *ApplicationTargetManager) mergeTargets(global, instance *ApplicationTargetStrategy) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.targets = make(map[string]*PullTarget)

	// 先添加全局目标
	for _, target := range global.Targets {
		if !target.Enabled {
			continue
		}

		key := fmt.Sprintf("%s:%s", target.ServiceName, target.Endpoint)
		pullTarget := &PullTarget{
			ServiceName: target.ServiceName,
			Protocol:    target.Protocol,
			Endpoint:    target.Endpoint,
			Interval:    target.Interval,
			Enabled:     target.Enabled,
			Labels:      target.Labels,
		}

		if pullTarget.Interval <= 0 {
			pullTarget.Interval = global.DefaultInterval
		}

		m.targets[key] = pullTarget
	}

	// 实例目标覆盖全局目标
	for _, target := range instance.Targets {
		key := fmt.Sprintf("%s:%s", target.ServiceName, target.Endpoint)

		if !target.Enabled {
			// 如果实例策略禁用了某个目标，删除它
			delete(m.targets, key)
			continue
		}

		pullTarget := &PullTarget{
			ServiceName: target.ServiceName,
			Protocol:    target.Protocol,
			Endpoint:    target.Endpoint,
			Interval:    target.Interval,
			Enabled:     target.Enabled,
			Labels:      target.Labels,
		}

		if pullTarget.Interval <= 0 {
			pullTarget.Interval = instance.DefaultInterval
			if pullTarget.Interval <= 0 {
				pullTarget.Interval = global.DefaultInterval
			}
		}

		m.targets[key] = pullTarget
	}
}

// GetTargets 获取所有采集目标
func (m *ApplicationTargetManager) GetTargets() map[string]*PullTarget {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*PullTarget, len(m.targets))
	for k, v := range m.targets {
		result[k] = v
	}
	return result
}

// GetTarget 获取指定采集目标
func (m *ApplicationTargetManager) GetTarget(serviceName, endpoint string) (*PullTarget, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", serviceName, endpoint)
	target, exists := m.targets[key]
	return target, exists
}

// UpdateTarget 更新采集目标
func (m *ApplicationTargetManager) UpdateTarget(target *PullTarget) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%s", target.ServiceName, target.Endpoint)
	m.targets[key] = target
}

// RemoveTarget 移除采集目标
func (m *ApplicationTargetManager) RemoveTarget(serviceName, endpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%s", serviceName, endpoint)
	delete(m.targets, key)
}
