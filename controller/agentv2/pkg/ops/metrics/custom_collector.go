package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CustomCollector 自定义采集器接口
type CustomCollector interface {
	// Name 返回采集器名称
	Name() string
	// Collect 收集指标
	Collect(ctx context.Context) (map[string]interface{}, error)
	// Enabled 是否启用
	Enabled() bool
}

// CustomCollectorRegistry 自定义采集器注册表
type CustomCollectorRegistry struct {
	logger    *zap.Logger
	collectors map[string]CustomCollector
	mu         sync.RWMutex
}

// NewCustomCollectorRegistry 创建自定义采集器注册表
func NewCustomCollectorRegistry(logger *zap.Logger) *CustomCollectorRegistry {
	return &CustomCollectorRegistry{
		logger:     logger,
		collectors: make(map[string]CustomCollector),
	}
}

// Register 注册采集器
func (r *CustomCollectorRegistry) Register(collector CustomCollector) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := collector.Name()
	if _, exists := r.collectors[name]; exists {
		return fmt.Errorf("collector %s already registered", name)
	}

	r.collectors[name] = collector
	r.logger.Info("Custom collector registered", zap.String("name", name))
	return nil
}

// Unregister 取消注册采集器
func (r *CustomCollectorRegistry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.collectors[name]; !exists {
		return fmt.Errorf("collector %s not found", name)
	}

	delete(r.collectors, name)
	r.logger.Info("Custom collector unregistered", zap.String("name", name))
	return nil
}

// Get 获取采集器
func (r *CustomCollectorRegistry) Get(name string) (CustomCollector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	collector, exists := r.collectors[name]
	return collector, exists
}

// List 列出所有采集器
func (r *CustomCollectorRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.collectors))
	for name := range r.collectors {
		names = append(names, name)
	}
	return names
}

// CollectAll 收集所有启用的采集器的指标
func (r *CustomCollectorRegistry) CollectAll(ctx context.Context) (map[string]map[string]interface{}, error) {
	r.mu.RLock()
	collectors := make(map[string]CustomCollector)
	for name, collector := range r.collectors {
		if collector.Enabled() {
			collectors[name] = collector
		}
	}
	r.mu.RUnlock()

	results := make(map[string]map[string]interface{})
	for name, collector := range collectors {
		metrics, err := collector.Collect(ctx)
		if err != nil {
			r.logger.Warn("Failed to collect metrics from custom collector",
				zap.String("collector", name),
				zap.Error(err))
			continue
		}
		results[name] = metrics
	}

	return results, nil
}

// ScriptCollector 脚本采集器
// 通过执行脚本采集指标，脚本输出 JSON 格式
type ScriptCollector struct {
	name      string
	scriptPath string
	interval   time.Duration
	enabled    bool
	logger     *zap.Logger
	lastResult map[string]interface{}
	mu         sync.RWMutex
}

// NewScriptCollector 创建脚本采集器
func NewScriptCollector(
	name string,
	scriptPath string,
	interval time.Duration,
	enabled bool,
	logger *zap.Logger,
) *ScriptCollector {
	return &ScriptCollector{
		name:       name,
		scriptPath: scriptPath,
		interval:   interval,
		enabled:    enabled,
		logger:     logger,
		lastResult: make(map[string]interface{}),
	}
}

// Name 返回采集器名称
func (sc *ScriptCollector) Name() string {
	return sc.name
}

// Enabled 是否启用
func (sc *ScriptCollector) Enabled() bool {
	return sc.enabled
}

// Collect 收集指标
func (sc *ScriptCollector) Collect(ctx context.Context) (map[string]interface{}, error) {
	// 执行脚本
	cmd := exec.CommandContext(ctx, "sh", "-c", sc.scriptPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute script: %w", err)
	}

	// 解析 JSON 输出
	var metrics map[string]interface{}
	if err := json.Unmarshal(output, &metrics); err != nil {
		return nil, fmt.Errorf("failed to parse script output as JSON: %w", err)
	}

	// 更新缓存
	sc.mu.Lock()
	sc.lastResult = metrics
	sc.mu.Unlock()

	return metrics, nil
}

// GetLastResult 获取上次采集结果
func (sc *ScriptCollector) GetLastResult() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	result := make(map[string]interface{})
	for k, v := range sc.lastResult {
		result[k] = v
	}
	return result
}

// HTTPCollector HTTP 采集器
// 通过 HTTP 请求采集指标
type HTTPCollector struct {
	name      string
	url       string
	interval  time.Duration
	enabled   bool
	logger    *zap.Logger
	lastResult map[string]interface{}
	mu        sync.RWMutex
}

// NewHTTPCollector 创建 HTTP 采集器
func NewHTTPCollector(
	name string,
	url string,
	interval time.Duration,
	enabled bool,
	logger *zap.Logger,
) *HTTPCollector {
	return &HTTPCollector{
		name:       name,
		url:        url,
		interval:   interval,
		enabled:    enabled,
		logger:     logger,
		lastResult: make(map[string]interface{}),
	}
}

// Name 返回采集器名称
func (hc *HTTPCollector) Name() string {
	return hc.name
}

// Enabled 是否启用
func (hc *HTTPCollector) Enabled() bool {
	return hc.enabled
}

// Collect 收集指标
func (hc *HTTPCollector) Collect(ctx context.Context) (map[string]interface{}, error) {
	// 创建 HTTP 请求
	req, err := http.NewRequestWithContext(ctx, "GET", hc.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 发送请求
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 解析响应
	var metrics map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// 更新缓存
	hc.mu.Lock()
	hc.lastResult = metrics
	hc.mu.Unlock()

	return metrics, nil
}

// GetLastResult 获取上次采集结果
func (hc *HTTPCollector) GetLastResult() map[string]interface{} {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	result := make(map[string]interface{})
	for k, v := range hc.lastResult {
		result[k] = v
	}
	return result
}

