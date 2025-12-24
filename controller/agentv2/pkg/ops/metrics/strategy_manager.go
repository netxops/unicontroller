package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	"go.uber.org/zap"
)

// MetricPriority 指标优先级
type MetricPriority string

const (
	PriorityCritical MetricPriority = "critical"
	PriorityHigh     MetricPriority = "high"
	PriorityMedium   MetricPriority = "medium"
	PriorityLow      MetricPriority = "low"
	PriorityDisabled MetricPriority = "disabled"
)

// MetricRule 指标规则
type MetricRule struct {
	Name     string         `json:"name"`
	Priority MetricPriority `json:"priority"`
	Interval *int           `json:"interval,omitempty"`
	Enabled  bool           `json:"enabled"`
}

// GlobalMetricStrategy 全局策略
type GlobalMetricStrategy struct {
	ID              string         `json:"id"`
	DefaultPriority MetricPriority `json:"default_priority"`
	DefaultInterval int            `json:"default_interval"`
	MetricRules     []MetricRule   `json:"metric_rules"`
	Version         int64          `json:"version"`
}

// InstanceMetricStrategy 实例策略
type InstanceMetricStrategy struct {
	ID            string       `json:"id"`
	AgentCode     string       `json:"agent_code"`
	MetricRules   []MetricRule `json:"metric_rules"`
	InheritGlobal bool         `json:"inherit_global"`
	Version       int64        `json:"version"`
}

// StrategyManager 策略管理器
type StrategyManager struct {
	cfg              *config.Config
	logger           *zap.Logger
	httpClient       *http.Client
	globalStrategy   *GlobalMetricStrategy
	instanceStrategy *InstanceMetricStrategy
	effectiveRules   []MetricRule
	mu               sync.RWMutex
	// 指标采集时间记录（用于支持不同间隔）
	metricCollectTimes map[string]time.Time
	collectTimesMu     sync.RWMutex
}

// NewStrategyManager 创建策略管理器
func NewStrategyManager(cfg *config.Config, logger *zap.Logger) *StrategyManager {
	return &StrategyManager{
		cfg:                cfg,
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		metricCollectTimes: make(map[string]time.Time),
	}
}

// LoadStrategy 加载策略
func (sm *StrategyManager) LoadStrategy(ctx context.Context) error {
	if !sm.cfg.Metrics.StrategyEnabled {
		sm.logger.Info("Strategy is disabled, skipping load")
		return nil
	}

	if sm.cfg.Metrics.StrategySource == "api" {
		return sm.loadStrategyFromAPI(ctx)
	}

	// 从配置文件加载（TODO: 实现配置文件策略加载）
	return nil
}

// loadStrategyFromAPI 从API加载策略
func (sm *StrategyManager) loadStrategyFromAPI(ctx context.Context) error {
	agentCode := sm.cfg.Agent.Code
	baseURL := sm.cfg.Metrics.StrategyAPIURL
	if baseURL == "" {
		baseURL = sm.cfg.Metrics.ControllerURL
	}
	if baseURL == "" {
		sm.logger.Error("Strategy API URL is not configured",
			zap.String("strategy_api_url", sm.cfg.Metrics.StrategyAPIURL),
			zap.String("controller_url", sm.cfg.Metrics.ControllerURL),
			zap.Bool("strategy_enabled", sm.cfg.Metrics.StrategyEnabled),
			zap.String("strategy_source", sm.cfg.Metrics.StrategySource))
		return fmt.Errorf("strategy API URL is not configured (strategy_api_url=%q, controller_url=%q)", sm.cfg.Metrics.StrategyAPIURL, sm.cfg.Metrics.ControllerURL)
	}

	sm.logger.Debug("Loading strategy from API",
		zap.String("base_url", baseURL),
		zap.String("agent_code", agentCode))

	// 加载全局策略
	globalURL := fmt.Sprintf("%s/api/v1/platform/metrics/strategy/global", baseURL)
	global, err := sm.fetchStrategy(ctx, globalURL, &GlobalMetricStrategy{})
	if err != nil {
		// 详细记录错误信息，帮助诊断问题
		sm.logger.Warn("Failed to load global strategy, using default",
			zap.String("url", globalURL),
			zap.String("base_url", baseURL),
			zap.String("error_type", fmt.Sprintf("%T", err)),
			zap.Error(err))

		// 如果是连接错误，提供更详细的诊断信息
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection") {
			sm.logger.Warn("Connection error detected, possible causes: Controller not running, network issue, or Controller crashed during request",
				zap.String("url", globalURL),
				zap.String("suggestion", "Check Controller logs and ensure it's running and accessible"))
		}

		global = sm.getDefaultGlobalStrategy()
		sm.logger.Info("Using default global strategy",
			zap.String("id", global.(*GlobalMetricStrategy).ID),
			zap.Int("rules_count", len(global.(*GlobalMetricStrategy).MetricRules)),
			zap.String("default_priority", string(global.(*GlobalMetricStrategy).DefaultPriority)),
			zap.Int("default_interval", global.(*GlobalMetricStrategy).DefaultInterval))
	} else {
		globalStrategy := global.(*GlobalMetricStrategy)
		sm.logger.Info("Loaded global strategy from API",
			zap.String("url", globalURL),
			zap.String("id", globalStrategy.ID),
			zap.Int("rules_count", len(globalStrategy.MetricRules)),
			zap.String("default_priority", string(globalStrategy.DefaultPriority)),
			zap.Int("default_interval", globalStrategy.DefaultInterval))

		sm.mu.Lock()
		sm.globalStrategy = globalStrategy
		sm.mu.Unlock()
	}

	// 加载实例策略
	instanceURL := fmt.Sprintf("%s/api/v1/platform/metrics/strategy/instance/%s", baseURL, agentCode)
	instance, err := sm.fetchStrategy(ctx, instanceURL, &InstanceMetricStrategy{})
	if err != nil {
		sm.logger.Warn("Failed to load instance strategy, using default",
			zap.String("url", instanceURL),
			zap.String("agent_code", agentCode),
			zap.Error(err))
		instance = &InstanceMetricStrategy{
			AgentCode:     agentCode,
			InheritGlobal: true,
			MetricRules:   []MetricRule{},
		}
		sm.logger.Info("Using default instance strategy",
			zap.String("agent_code", agentCode),
			zap.Int("rules_count", 0),
			zap.Bool("inherit_global", true))
	} else {
		instanceStrategy := instance.(*InstanceMetricStrategy)
		// 如果 Controller 没有返回 inherit_global 字段（默认为 false），但实例规则存在，
		// 则默认设置为 true（继承全局规则）
		if len(instanceStrategy.MetricRules) > 0 && !instanceStrategy.InheritGlobal {
			sm.logger.Info("Instance strategy has rules but inherit_global is false, defaulting to true",
				zap.Int("rules_count", len(instanceStrategy.MetricRules)),
				zap.String("agent_code", agentCode))
			instanceStrategy.InheritGlobal = true
		}

		sm.logger.Info("Loaded instance strategy from API",
			zap.String("url", instanceURL),
			zap.String("agent_code", agentCode),
			zap.Int("rules_count", len(instanceStrategy.MetricRules)),
			zap.Bool("inherit_global", instanceStrategy.InheritGlobal))

		sm.mu.Lock()
		sm.instanceStrategy = instanceStrategy
		sm.mu.Unlock()
	}

	// 合并策略
	sm.mergeStrategies()

	return nil
}

// fetchStrategy 获取策略
func (sm *StrategyManager) fetchStrategy(ctx context.Context, url string, target interface{}) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := sm.httpClient.Do(req)
	if err != nil {
		// 提供更详细的错误信息
		return nil, fmt.Errorf("failed to fetch strategy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 尝试读取响应体以获取更多错误信息
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, bodyStr)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 记录原始响应（用于调试）
	// 限制日志长度，避免日志过大
	bodyStr := string(body)
	if len(bodyStr) > 1000 {
		bodyStr = bodyStr[:1000] + "...(truncated)"
	}
	sm.logger.Info("Fetched strategy from API",
		zap.String("url", url),
		zap.String("response_preview", bodyStr),
		zap.Int("response_length", len(body)))

	if err := json.Unmarshal(body, target); err != nil {
		sm.logger.Error("Failed to unmarshal strategy",
			zap.String("url", url),
			zap.String("response_preview", bodyStr),
			zap.Int("response_length", len(body)),
			zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal strategy: %w", err)
	}

	// 记录解析后的策略信息
	if instanceStrategy, ok := target.(*InstanceMetricStrategy); ok {
		sm.logger.Info("Parsed instance strategy from JSON",
			zap.String("agent_code", instanceStrategy.AgentCode),
			zap.Int("rules_count", len(instanceStrategy.MetricRules)),
			zap.Bool("inherit_global", instanceStrategy.InheritGlobal))
	} else if globalStrategy, ok := target.(*GlobalMetricStrategy); ok {
		sm.logger.Info("Parsed global strategy from JSON",
			zap.String("id", globalStrategy.ID),
			zap.Int("rules_count", len(globalStrategy.MetricRules)),
			zap.String("default_priority", string(globalStrategy.DefaultPriority)),
			zap.Int("default_interval", globalStrategy.DefaultInterval))
	}

	return target, nil
}

// mergeStrategies 合并策略
func (sm *StrategyManager) mergeStrategies() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	effectiveRules := make([]MetricRule, 0)
	ruleMap := make(map[string]MetricRule)

	// 根据 InheritGlobal 标志决定合并策略
	if sm.instanceStrategy != nil && !sm.instanceStrategy.InheritGlobal {
		// InheritGlobal = false: 完全覆盖，只使用实例规则
		// 清空全局规则，只添加实例规则
		ruleMap = make(map[string]MetricRule)
		for _, rule := range sm.instanceStrategy.MetricRules {
			if rule.Enabled {
				ruleMap[rule.Name] = rule
			}
		}
	} else {
		// InheritGlobal = true 或没有实例策略: 继承全局规则，实例规则覆盖同名规则
		// 1. 先添加全局规则
		if sm.globalStrategy != nil {
			for _, rule := range sm.globalStrategy.MetricRules {
				if rule.Enabled {
					ruleMap[rule.Name] = rule
				}
			}
		}

		// 2. 然后添加实例规则（覆盖全局规则中同名的规则）
		if sm.instanceStrategy != nil {
			for _, rule := range sm.instanceStrategy.MetricRules {
				if rule.Enabled {
					ruleMap[rule.Name] = rule
				} else {
					// 如果实例规则禁用了某个规则，删除它（即使全局规则中有）
					delete(ruleMap, rule.Name)
				}
			}
		}
	}

	// 转换为列表并排序
	for _, rule := range ruleMap {
		effectiveRules = append(effectiveRules, rule)
	}

	// 按优先级排序
	sort.Slice(effectiveRules, func(i, j int) bool {
		priorityOrder := map[MetricPriority]int{
			PriorityCritical: 0,
			PriorityHigh:     1,
			PriorityMedium:   2,
			PriorityLow:      3,
			PriorityDisabled: 4,
		}
		return priorityOrder[effectiveRules[i].Priority] < priorityOrder[effectiveRules[j].Priority]
	})

	sm.effectiveRules = effectiveRules

	// 记录合并详情
	globalRulesCount := 0
	if sm.globalStrategy != nil {
		globalRulesCount = len(sm.globalStrategy.MetricRules)
	}
	instanceRulesCount := 0
	inheritGlobal := false
	if sm.instanceStrategy != nil {
		instanceRulesCount = len(sm.instanceStrategy.MetricRules)
		inheritGlobal = sm.instanceStrategy.InheritGlobal
	}

	sm.logger.Info("Strategies merged",
		zap.Int("global_rules_count", globalRulesCount),
		zap.Int("instance_rules_count", instanceRulesCount),
		zap.Bool("inherit_global", inheritGlobal),
		zap.Int("effective_rules_count", len(sm.effectiveRules)))
}

// GetEffectiveRules 获取生效的规则
func (sm *StrategyManager) GetEffectiveRules() []MetricRule {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	rules := make([]MetricRule, len(sm.effectiveRules))
	copy(rules, sm.effectiveRules)
	return rules
}

// GetGlobalStrategy 获取全局策略
func (sm *StrategyManager) GetGlobalStrategy() *GlobalMetricStrategy {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.globalStrategy
}

// GetInstanceStrategy 获取实例策略
func (sm *StrategyManager) GetInstanceStrategy() *InstanceMetricStrategy {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.instanceStrategy
}

// GetStrategyVersion 获取策略版本号（取全局和实例策略中的最大版本）
func (sm *StrategyManager) GetStrategyVersion() int64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	version := int64(0)
	if sm.globalStrategy != nil && sm.globalStrategy.Version > version {
		version = sm.globalStrategy.Version
	}
	if sm.instanceStrategy != nil && sm.instanceStrategy.Version > version {
		version = sm.instanceStrategy.Version
	}
	return version
}

// GetRulesByInterval 获取按间隔分组的规则
func (sm *StrategyManager) GetRulesByInterval() map[int][]MetricRule {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	rulesByInterval := make(map[int][]MetricRule)

	// 获取默认间隔
	defaultInterval := 60 // 默认60秒
	if sm.globalStrategy != nil {
		defaultInterval = sm.globalStrategy.DefaultInterval
	}

	// 按间隔分组规则
	for _, rule := range sm.effectiveRules {
		interval := defaultInterval
		if rule.Interval != nil {
			interval = *rule.Interval
		}
		rulesByInterval[interval] = append(rulesByInterval[interval], rule)
	}

	return rulesByInterval
}

// GetMinInterval 获取最小采集间隔（用于基础采集频率）
func (sm *StrategyManager) GetMinInterval() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	minInterval := 60 // 默认60秒
	if sm.globalStrategy != nil {
		minInterval = sm.globalStrategy.DefaultInterval
	}

	// 查找所有规则中的最小间隔
	for _, rule := range sm.effectiveRules {
		if rule.Interval != nil && *rule.Interval < minInterval {
			minInterval = *rule.Interval
		}
	}

	return minInterval
}

// ShouldCollectMetric 判断指标是否应该在此次采集时收集
// 注意：此方法只检查规则匹配和 enabled 状态，不进行时间间隔过滤
// 时间间隔应该用于控制 collector 的更新频率，而不是在 /metrics 端点层面过滤输出
// Prometheus 的 /metrics 端点应该始终返回所有启用的指标
func (sm *StrategyManager) ShouldCollectMetric(metricName string, currentTime time.Time) bool {
	sm.mu.RLock()
	effectiveRulesCount := len(sm.effectiveRules)
	// 匹配规则
	rule, matched := sm.matchMetricInternal(metricName)
	if !matched {
		// 没有匹配到规则，不采集
		sm.mu.RUnlock()
		if sm.logger != nil && effectiveRulesCount > 0 {
			sm.logger.Debug("Metric not matched by any rule, skipping",
				zap.String("metric", metricName),
				zap.Int("effective_rules_count", effectiveRulesCount))
		}
		return false
	}
	if rule == nil || !rule.Enabled {
		// 规则为 nil 或已禁用，不采集
		sm.mu.RUnlock()
		if sm.logger != nil {
			sm.logger.Debug("Metric rule is nil or disabled, skipping",
				zap.String("metric", metricName),
				zap.Bool("rule_is_nil", rule == nil),
				zap.Bool("rule_enabled", rule != nil && rule.Enabled))
		}
		return false
	}
	sm.mu.RUnlock()

	// 记录采集时间（用于统计和监控，但不用于过滤）
	sm.collectTimesMu.Lock()
	sm.metricCollectTimes[metricName] = currentTime
	sm.collectTimesMu.Unlock()

	// 如果规则匹配且启用，则返回 true
	// 注意：时间间隔不在这里检查，应该在 collector 层面控制更新频率
	return true
}

// RecordMetricCollectTime 记录指标的采集时间
func (sm *StrategyManager) RecordMetricCollectTime(metricName string, collectTime time.Time) {
	sm.collectTimesMu.Lock()
	defer sm.collectTimesMu.Unlock()
	sm.metricCollectTimes[metricName] = collectTime
}

// GetMetricInterval 获取指标的采集间隔（秒）
func (sm *StrategyManager) GetMetricInterval(metricName string) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// 匹配规则
	rule, matched := sm.matchMetricInternal(metricName)
	if !matched {
		// 使用默认间隔
		if sm.globalStrategy != nil {
			return sm.globalStrategy.DefaultInterval
		}
		return 60
	}

	// 获取规则的采集间隔
	if rule.Interval != nil {
		return *rule.Interval
	}
	if sm.globalStrategy != nil {
		return sm.globalStrategy.DefaultInterval
	}
	return 60
}

// matchMetricInternal 内部方法：匹配指标（不加锁，由调用者保证）
func (sm *StrategyManager) matchMetricInternal(metricName string) (*MetricRule, bool) {
	// 按优先级顺序匹配（第一个匹配的规则生效）
	for _, rule := range sm.effectiveRules {
		if sm.matchRule(rule, metricName) {
			return &rule, true
		}
	}

	// 如果有策略规则但没有匹配到，说明该指标不在策略中，不采集
	// 只有在没有任何策略规则时，才使用默认策略（采集所有指标）
	if len(sm.effectiveRules) > 0 {
		// 有策略规则但没有匹配，返回 nil 表示不采集
		return nil, false
	}

	// 没有任何策略规则，使用默认策略（允许采集所有指标）
	if sm.globalStrategy != nil {
		defaultRule := MetricRule{
			Name:     metricName,
			Priority: sm.globalStrategy.DefaultPriority,
			Interval: &sm.globalStrategy.DefaultInterval,
			Enabled:  true,
		}
		return &defaultRule, true
	}

	return nil, false
}

// MatchMetric 匹配指标
func (sm *StrategyManager) MatchMetric(metricName string) (*MetricRule, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// 按优先级顺序匹配（第一个匹配的规则生效）
	for _, rule := range sm.effectiveRules {
		if sm.matchRule(rule, metricName) {
			return &rule, true
		}
	}

	// 如果没有匹配的规则，使用默认策略
	if sm.globalStrategy != nil {
		defaultRule := MetricRule{
			Name:     metricName,
			Priority: sm.globalStrategy.DefaultPriority,
			Interval: &sm.globalStrategy.DefaultInterval,
			Enabled:  true,
		}
		return &defaultRule, true
	}

	return nil, false
}

// matchRule 匹配规则
func (sm *StrategyManager) matchRule(rule MetricRule, metricName string) bool {
	if !rule.Enabled {
		return false
	}

	pattern := rule.Name

	// 如果包含通配符，转换为正则表达式
	if strings.Contains(pattern, "*") {
		escaped := regexp.QuoteMeta(pattern)
		escaped = strings.ReplaceAll(escaped, "\\*", ".*")
		re, err := regexp.Compile("^" + escaped + "$")
		if err != nil {
			sm.logger.Warn("Failed to compile regex pattern",
				zap.String("pattern", pattern),
				zap.Error(err))
			return false
		}
		return re.MatchString(metricName)
	}

	// 精确匹配
	return metricName == pattern
}

// getDefaultGlobalStrategy 获取默认全局策略
func (sm *StrategyManager) getDefaultGlobalStrategy() *GlobalMetricStrategy {
	return &GlobalMetricStrategy{
		ID:              "global",
		DefaultPriority: PriorityMedium,
		DefaultInterval: 60,
		MetricRules:     []MetricRule{},
		Version:         0,
	}
}

// GetEnhancedCollectorConfig 根据策略规则生成增强型收集器配置
func (sm *StrategyManager) GetEnhancedCollectorConfig() EnhancedCollectorConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	config := EnhancedCollectorConfig{
		EnabledCollectors: []string{},
		ExcludeCollectors: []string{},
		OnlyCore:          false,
	}

	// 指标名称前缀到 collector 名称的映射
	metricToCollector := map[string]string{
		"node_cpu_":          "cpu",
		"node_memory_":       "meminfo",
		"node_load":          "loadavg",
		"node_filesystem_":   "filesystem",
		"node_diskstats_":    "diskstats",
		"node_network_":      "netdev",
		"node_netstat_":      "netstat",
		"node_sockstat_":     "sockstat",
		"node_textfile_":     "textfile",
		"node_time_":         "time",
		"node_uname_":        "uname",
		"node_os_":           "os",
		"node_hwmon_":        "hwmon",
		"node_edac_":         "edac",
		"node_interrupts_":   "interrupts",
		"node_ksmd_":         "ksmd",
		"node_logind_":       "logind",
		"node_mdstat_":       "mdadm",
		"node_meminfo_numa_": "numa",
		"node_nfs_":          "nfs",
		"node_nfsd_":         "nfsd",
		"node_ntp_":          "ntp",
		"node_perf_":         "perf",
		"node_powersupply_":  "powersupply",
		"node_pressure_":     "pressure",
		"node_rapl_":         "rapl",
		"node_runit_":        "runit",
		"node_schedstat_":    "schedstat",
		"node_selinux_":      "selinux",
		"node_softnet_":      "softnet",
		"node_stat_":         "stat",
		"node_supervisord_":  "supervisord",
		"node_systemd_":      "systemd",
		"node_tcpstat_":      "tcpstat",
		"node_timex_":        "timex",
		"node_udp_queues_":   "udp_queues",
		"node_unified_":      "unified",
		"node_vmstat_":       "vmstat",
		"node_wifi_":         "wifi",
		"node_xfs_":          "xfs",
		"node_zfs_":          "zfs",
		"node_zoneinfo_":     "zoneinfo",
	}

	// 收集所有涉及的 collectors
	collectorEnabled := make(map[string]bool) // collector 名称 -> 是否启用
	collectorSeen := make(map[string]bool)    // 记录哪些 collector 被规则覆盖

	// 遍历所有生效的规则
	for _, rule := range sm.effectiveRules {
		// 检查规则名称匹配哪些指标前缀
		rulePattern := rule.Name

		// 处理通配符规则（如 "node_cpu_*" 或 "node_*"）
		if strings.Contains(rulePattern, "*") {
			// 移除通配符，获取前缀
			prefix := strings.TrimSuffix(rulePattern, "*")
			prefix = strings.TrimSuffix(prefix, "_")

			// 检查每个指标前缀是否匹配规则
			for metricPrefix, collectorName := range metricToCollector {
				// 如果规则前缀匹配指标前缀，或者指标前缀以规则前缀开头
				if strings.HasPrefix(metricPrefix, prefix) || strings.HasPrefix(prefix, metricPrefix) {
					collectorSeen[collectorName] = true
					collectorEnabled[collectorName] = rule.Enabled
				}
			}
		} else {
			// 精确匹配：检查规则名称是否以某个指标前缀开头
			for metricPrefix, collectorName := range metricToCollector {
				if strings.HasPrefix(rulePattern, metricPrefix) {
					collectorSeen[collectorName] = true
					collectorEnabled[collectorName] = rule.Enabled
					break
				}
			}
		}
	}

	// 如果没有规则，使用默认配置（启用所有）
	if len(collectorSeen) == 0 {
		// 如果没有策略规则，保持 OnlyCore 为 false，启用所有 collectors
		return config
	}

	// 根据规则生成配置
	// 如果所有规则都是启用状态，且覆盖了大部分 collectors，则启用所有
	// 否则，只启用被规则明确启用的 collectors
	allEnabled := true
	for _, enabled := range collectorEnabled {
		if !enabled {
			allEnabled = false
			break
		}
	}

	if allEnabled && len(collectorSeen) > 10 {
		// 如果启用了大部分 collectors，则启用所有（清空列表表示启用所有）
		config.EnabledCollectors = []string{}
		config.ExcludeCollectors = []string{}
	} else {
		// 只启用被规则覆盖的 collectors
		for collectorName := range collectorSeen {
			if collectorEnabled[collectorName] {
				config.EnabledCollectors = append(config.EnabledCollectors, collectorName)
			} else {
				config.ExcludeCollectors = append(config.ExcludeCollectors, collectorName)
			}
		}
	}

	// 如果启用的 collectors 数量很少（<=10），可以考虑使用 OnlyCore
	// 但这里我们根据实际启用的 collectors 来判断
	coreCollectors := map[string]bool{
		"cpu":        true,
		"meminfo":    true,
		"loadavg":    true,
		"filesystem": true,
		"diskstats":  true,
		"netdev":     true,
		"stat":       true,
		"os":         true,
		"time":       true,
		"uname":      true,
	}

	if len(config.EnabledCollectors) > 0 {
		allCore := true
		for _, collector := range config.EnabledCollectors {
			if !coreCollectors[collector] {
				allCore = false
				break
			}
		}
		if allCore && len(config.EnabledCollectors) <= 10 {
			config.OnlyCore = true
		}
	}

	sm.logger.Info("Generated enhanced collector config from strategy",
		zap.Int("enabled_count", len(config.EnabledCollectors)),
		zap.Strings("enabled_collectors", config.EnabledCollectors),
		zap.Int("exclude_count", len(config.ExcludeCollectors)),
		zap.Strings("exclude_collectors", config.ExcludeCollectors),
		zap.Bool("only_core", config.OnlyCore))

	return config
}
