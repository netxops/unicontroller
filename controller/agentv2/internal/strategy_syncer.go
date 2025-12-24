package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/metrics"
	"go.uber.org/zap"
)

// StrategySyncer 策略同步器
type StrategySyncer struct {
	cfg              *config.Config
	logger           *zap.Logger
	strategyManager  *metrics.StrategyManager
	metricsCollector metrics.MetricsCollector
	httpClient       *http.Client
	stopChan         chan struct{}
	wg               sync.WaitGroup
	mu               sync.RWMutex
	lastSyncTime     time.Time
	lastVersion      int64
}

// NewStrategySyncer 创建策略同步器
func NewStrategySyncer(
	cfg *config.Config,
	strategyManager *metrics.StrategyManager,
	metricsCollector metrics.MetricsCollector,
	logger *zap.Logger,
) *StrategySyncer {
	return &StrategySyncer{
		cfg:              cfg,
		logger:           logger,
		strategyManager:  strategyManager,
		metricsCollector: metricsCollector,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
		stopChan:         make(chan struct{}),
	}
}

// Start 启动策略同步器
func (ss *StrategySyncer) Start(ctx context.Context) error {
	if !ss.cfg.Metrics.StrategyEnabled || ss.cfg.Metrics.StrategySource != "api" {
		ss.logger.Info("Strategy syncer disabled or not using API source")
		return nil
	}

	interval := ss.cfg.Metrics.StrategySyncInterval
	if interval == 0 {
		interval = 5 * time.Minute // 默认5分钟
	}

	ss.logger.Info("Starting strategy syncer",
		zap.Duration("interval", interval))

	// 立即同步一次
	if err := ss.sync(ctx); err != nil {
		ss.logger.Warn("Initial strategy sync failed", zap.Error(err))
	}

	ss.wg.Add(1)
	go ss.syncLoop(ctx, interval)

	return nil
}

// Stop 停止策略同步器
func (ss *StrategySyncer) Stop() {
	close(ss.stopChan)
	ss.wg.Wait()
	ss.logger.Info("Strategy syncer stopped")
}

// syncLoop 同步循环
func (ss *StrategySyncer) syncLoop(ctx context.Context, interval time.Duration) {
	defer ss.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ss.stopChan:
			return
		case <-ticker.C:
			if err := ss.sync(ctx); err != nil {
				ss.logger.Warn("Strategy sync failed", zap.Error(err))
			}
		}
	}
}

// sync 同步策略
func (ss *StrategySyncer) sync(ctx context.Context) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.logger.Debug("Syncing strategy from API")

	// 加载策略
	if err := ss.strategyManager.LoadStrategy(ctx); err != nil {
		return err
	}

	// 应用策略到收集器
	applyError := error(nil)
	if ss.metricsCollector != nil {
		enhancedConfig := ss.strategyManager.GetEnhancedCollectorConfig()
		if err := ss.metricsCollector.UpdateEnhancedConfig(enhancedConfig); err != nil {
			ss.logger.Warn("Failed to apply strategy to collector",
				zap.Error(err))
			applyError = err
			// 不返回错误，因为策略同步成功，只是应用失败
		} else {
			ss.logger.Info("Strategy applied to collector successfully",
				zap.Int("enabled_collectors", len(enhancedConfig.EnabledCollectors)),
				zap.Int("exclude_collectors", len(enhancedConfig.ExcludeCollectors)),
				zap.Bool("only_core", enhancedConfig.OnlyCore))

			// 设置策略管理器到增强型收集器（用于获取更新间隔）
			enhancedCollector := ss.metricsCollector.GetEnhancedCollector()
			if enhancedCollector != nil {
				enhancedCollector.SetStrategyManager(ss.strategyManager)
				ss.logger.Debug("Strategy manager set to enhanced collector")
			}
		}
	}

	// 获取策略版本
	var strategyVersion int64
	if ss.strategyManager != nil {
		// 从策略管理器获取当前版本（需要添加方法）
		// 暂时使用时间戳作为版本
		strategyVersion = time.Now().Unix()
	}

	// 上报配置状态
	ss.reportConfigStatus(ctx, strategyVersion, applyError)

	ss.lastSyncTime = time.Now()
	ss.lastVersion = strategyVersion
	ss.logger.Info("Strategy synced successfully",
		zap.Time("last_sync", ss.lastSyncTime),
		zap.Int64("version", strategyVersion))

	return nil
}

// reportConfigStatus 上报配置状态到 Controller
func (ss *StrategySyncer) reportConfigStatus(ctx context.Context, version int64, applyErr error) {
	if !ss.cfg.Metrics.StrategyEnabled {
		return
	}

	baseURL := ss.cfg.Metrics.StrategyAPIURL
	if baseURL == "" {
		baseURL = ss.cfg.Metrics.ControllerURL
	}
	if baseURL == "" {
		ss.logger.Debug("Controller URL not configured, skipping config status report")
		return
	}

	// 构建状态
	status := "active"
	errorMessage := ""
	if applyErr != nil {
		status = "failed"
		errorMessage = applyErr.Error()
	}

	statusData := map[string]interface{}{
		"status":        status,
		"version":       fmt.Sprintf("%d", version),
		"last_sync":     time.Now().Format(time.RFC3339),
		"error_message": errorMessage,
	}

	// 发送 POST 请求上报状态
	// 注意：如果 Controller 没有提供上报接口，这里会失败，但不影响策略同步
	url := fmt.Sprintf("%s/api/v1/platform/metrics/strategy/config-status/%s", baseURL, ss.cfg.Agent.Code)
	body, err := json.Marshal(statusData)
	if err != nil {
		ss.logger.Warn("Failed to marshal config status", zap.Error(err))
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		ss.logger.Debug("Failed to create config status report request", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ss.httpClient.Do(req)
	if err != nil {
		ss.logger.Debug("Failed to report config status", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent {
		ss.logger.Debug("Config status reported successfully",
			zap.String("status", status),
			zap.Int64("version", version))
	} else {
		ss.logger.Debug("Config status report returned non-success status",
			zap.Int("status_code", resp.StatusCode))
	}
}

// GetLastSyncTime 获取最后同步时间
func (ss *StrategySyncer) GetLastSyncTime() time.Time {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.lastSyncTime
}

// GetStrategyManager 获取策略管理器
func (ss *StrategySyncer) GetStrategyManager() *metrics.StrategyManager {
	return ss.strategyManager
}

// GetLastVersion 获取最后同步的版本号
func (ss *StrategySyncer) GetLastVersion() int64 {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.lastVersion
}
