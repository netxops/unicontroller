package controller

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const (
	GlobalStrategyID = "global"
	CollectionName   = "metric_strategies"
)

// MetricsStrategyService 指标策略管理服务
// 注意：数据源是OneOps MySQL，Controller的MongoDB作为缓存/同步目标
// 策略数据流向：OneOps MySQL → Controller MongoDB → Agent
// 本服务主要用于Agent查询策略配置，实际的数据管理在OneOps后端完成
// MongoDB中的数据由OneOps后端同步更新
type MetricsStrategyService struct {
	mongoClient     *mongo.Client
	logger          *zap.Logger
	agentManager    *AgentManager
	registryManager *RegistryManager
	httpClient      *http.Client
}

// NewMetricsStrategyService 创建指标策略管理服务
func NewMetricsStrategyService(mongoClient *mongo.Client, agentManager *AgentManager, registryManager *RegistryManager, logger *zap.Logger) *MetricsStrategyService {
	return &MetricsStrategyService{
		mongoClient:     mongoClient,
		logger:          logger,
		agentManager:    agentManager,
		registryManager: registryManager,
		httpClient:      &http.Client{Timeout: 5 * time.Second},
	}
}

// GetGlobalStrategy 获取全局策略
func (s *MetricsStrategyService) GetGlobalStrategy(ctx context.Context) (*models.GlobalMetricStrategy, error) {
	log.Printf("DEBUG: GetGlobalStrategy called")

	// 检查 MongoDB 客户端是否已初始化
	if s.mongoClient == nil {
		log.Printf("WARN: MongoDB client is nil, returning default strategy")
		if s.logger != nil {
			s.logger.Error("MongoDB client is nil, returning default strategy")
		}
		return s.getDefaultGlobalStrategy(), nil
	}

	// 检查 MongoDB 连接
	if err := s.mongoClient.Ping(ctx, nil); err != nil {
		log.Printf("WARN: MongoDB connection failed: %v, returning default strategy", err)
		if s.logger != nil {
			s.logger.Warn("MongoDB connection failed, returning default strategy",
				zap.Error(err))
		}
		return s.getDefaultGlobalStrategy(), nil
	}

	log.Printf("DEBUG: MongoDB connection OK, querying collection")
	collection := s.mongoClient.Database("controller").Collection(CollectionName)

	var strategy models.GlobalMetricStrategy
	err := collection.FindOne(ctx, bson.M{"_id": GlobalStrategyID}).Decode(&strategy)
	if err == mongo.ErrNoDocuments {
		// 返回默认策略
		log.Printf("INFO: Global strategy not found in database, using default")
		if s.logger != nil {
			s.logger.Debug("Global strategy not found in database, using default")
		}
		return s.getDefaultGlobalStrategy(), nil
	}
	if err != nil {
		log.Printf("ERROR: Failed to query global strategy from MongoDB: %v", err)
		if s.logger != nil {
			s.logger.Error("Failed to query global strategy from MongoDB",
				zap.Error(err))
		}
		return nil, fmt.Errorf("failed to get global strategy: %w", err)
	}

	log.Printf("INFO: Global strategy found, ID: %s, rules count: %d", strategy.ID, len(strategy.MetricRules))
	return &strategy, nil
}

// UpdateGlobalStrategy 更新全局策略
func (s *MetricsStrategyService) UpdateGlobalStrategy(ctx context.Context, strategy *models.GlobalMetricStrategy) error {
	collection := s.mongoClient.Database("controller").Collection(CollectionName)

	strategy.ID = GlobalStrategyID
	strategy.UpdatedAt = time.Now()
	strategy.Version = time.Now().Unix()

	if strategy.CreatedAt.IsZero() {
		strategy.CreatedAt = time.Now()
	}

	opts := options.Update().SetUpsert(true)
	_, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": GlobalStrategyID},
		bson.M{"$set": strategy},
		opts,
	)
	if err != nil {
		return fmt.Errorf("failed to update global strategy: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Global strategy updated",
			zap.Int64("version", strategy.Version),
			zap.Int("rules_count", len(strategy.MetricRules)))
	}

	return nil
}

// GetInstanceStrategy 获取实例策略
func (s *MetricsStrategyService) GetInstanceStrategy(ctx context.Context, agentCode string) (*models.InstanceMetricStrategy, error) {
	collection := s.mongoClient.Database("controller").Collection(CollectionName)

	var strategy models.InstanceMetricStrategy
	err := collection.FindOne(ctx, bson.M{"agent_code": agentCode}).Decode(&strategy)
	if err == mongo.ErrNoDocuments {
		// 返回默认实例策略（继承全局）
		return &models.InstanceMetricStrategy{
			ID:            agentCode,
			AgentCode:     agentCode,
			MetricRules:   []models.MetricRule{},
			InheritGlobal: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Version:       0,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get instance strategy: %w", err)
	}

	return &strategy, nil
}

// UpdateInstanceStrategy 更新实例策略
func (s *MetricsStrategyService) UpdateInstanceStrategy(ctx context.Context, strategy *models.InstanceMetricStrategy) error {
	collection := s.mongoClient.Database("controller").Collection(CollectionName)

	strategy.UpdatedAt = time.Now()
	strategy.Version = time.Now().Unix()

	if strategy.CreatedAt.IsZero() {
		strategy.CreatedAt = time.Now()
	}

	opts := options.Update().SetUpsert(true)
	_, err := collection.UpdateOne(
		ctx,
		bson.M{"agent_code": strategy.AgentCode},
		bson.M{"$set": strategy},
		opts,
	)
	if err != nil {
		return fmt.Errorf("failed to update instance strategy: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Instance strategy updated",
			zap.String("agent_code", strategy.AgentCode),
			zap.Int64("version", strategy.Version),
			zap.Int("rules_count", len(strategy.MetricRules)))
	}

	return nil
}

// GetEffectiveStrategy 获取生效的策略（合并全局和实例）
func (s *MetricsStrategyService) GetEffectiveStrategy(ctx context.Context, agentCode string) (*models.GlobalMetricStrategy, []models.MetricRule, error) {
	global, err := s.GetGlobalStrategy(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get global strategy: %w", err)
	}

	instance, err := s.GetInstanceStrategy(ctx, agentCode)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get instance strategy: %w", err)
	}

	// 如果实例策略继承全局，只返回全局规则
	if instance.InheritGlobal {
		return global, []models.MetricRule{}, nil
	}

	// 否则返回全局策略和实例规则
	return global, instance.MetricRules, nil
}

// GetAvailableMetrics 获取可用指标列表
func (s *MetricsStrategyService) GetAvailableMetrics(ctx context.Context, agentCode string) ([]string, error) {
	if agentCode == "" {
		// 如果没有指定agentCode，返回所有Agent的指标（去重）
		return s.getAllAvailableMetrics(ctx)
	}

	// 从指定Agent获取指标
	return s.getAgentMetrics(ctx, agentCode)
}

// getAgentMetrics 从Agent获取指标列表
func (s *MetricsStrategyService) getAgentMetrics(ctx context.Context, agentCode string) ([]string, error) {
	// 通过HTTP请求Agent的/metrics端点
	agent, err := s.agentManager.GetAgent(ctx, agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent: %w", err)
	}

	// 构建Agent的HTTP地址（假设Agent HTTP端口为58080）
	// 从address中提取IP，默认端口58080
	address := agent.Address
	if !strings.Contains(address, ":") {
		address = address + ":58080"
	}
	metricsURL := fmt.Sprintf("http://%s/metrics", address)

	// 发送HTTP请求获取Prometheus格式的指标
	req, err := http.NewRequestWithContext(ctx, "GET", metricsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("Failed to fetch metrics from agent, using default metrics",
				zap.String("agent_code", agentCode),
				zap.String("url", metricsURL),
				zap.Error(err))
		}
		return s.getDefaultMetrics(), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if s.logger != nil {
			s.logger.Warn("Agent metrics endpoint returned non-200 status",
				zap.String("agent_code", agentCode),
				zap.Int("status", resp.StatusCode))
		}
		return s.getDefaultMetrics(), nil
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 解析Prometheus格式，提取指标名称
	metrics := s.parsePrometheusMetrics(string(body))
	if len(metrics) == 0 {
		// 如果解析失败，返回默认指标
		return s.getDefaultMetrics(), nil
	}

	return metrics, nil
}

// parsePrometheusMetrics 解析Prometheus格式的指标
func (s *MetricsStrategyService) parsePrometheusMetrics(content string) []string {
	var metrics []string
	seen := make(map[string]bool)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 跳过注释和空行
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// 提取指标名称（格式：metric_name{labels} value）
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		metricName := parts[0]
		// 移除标签部分（如果有）
		if idx := strings.Index(metricName, "{"); idx > 0 {
			metricName = metricName[:idx]
		}

		// 去重
		if !seen[metricName] {
			metrics = append(metrics, metricName)
			seen[metricName] = true
		}
	}

	return metrics
}

// getDefaultMetrics 获取默认指标列表
func (s *MetricsStrategyService) getDefaultMetrics() []string {
	return []string{
		"node_cpu_seconds_total",
		"node_memory_MemTotal_bytes",
		"node_memory_MemAvailable_bytes",
		"node_disk_io_now",
		"node_network_receive_bytes_total",
		"node_network_transmit_bytes_total",
		"node_load1",
		"node_load5",
		"node_load15",
	}
}

// getAllAvailableMetrics 获取所有Agent的指标（去重）
func (s *MetricsStrategyService) getAllAvailableMetrics(ctx context.Context) ([]string, error) {
	// 简化实现：返回常见指标列表
	// 实际应该查询所有Agent并合并指标
	return s.getDefaultMetrics(), nil
}

// PreviewRule 预览规则匹配的指标
func (s *MetricsStrategyService) PreviewRule(ctx context.Context, rule models.MetricRule) (*models.MetricRulePreview, error) {
	// 获取所有可用指标
	allMetrics, err := s.GetAvailableMetrics(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get available metrics: %w", err)
	}

	// 匹配规则
	matchedMetrics := s.matchRule(rule, allMetrics)

	// 计算影响的Agent数量（简化：返回所有在线Agent数量）
	agentCount, _ := s.agentManager.registryManager.GetAgentCount()
	if agentCount == 0 {
		agentCount = 1 // 至少返回1，避免显示0
	}

	return &models.MetricRulePreview{
		MatchedMetrics: matchedMetrics,
		AgentCount:     agentCount,
	}, nil
}

// matchRule 匹配规则
func (s *MetricsStrategyService) matchRule(rule models.MetricRule, metrics []string) []string {
	if !rule.Enabled {
		return []string{}
	}

	var matched []string
	pattern := rule.Name

	// 如果包含通配符，转换为正则表达式
	if strings.Contains(pattern, "*") {
		// 转义特殊字符，将*替换为.*
		escaped := regexp.QuoteMeta(pattern)
		escaped = strings.ReplaceAll(escaped, "\\*", ".*")
		re, err := regexp.Compile("^" + escaped + "$")
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("Failed to compile regex pattern",
					zap.String("pattern", pattern),
					zap.Error(err))
			}
			return []string{}
		}

		for _, metric := range metrics {
			if re.MatchString(metric) {
				matched = append(matched, metric)
			}
		}
	} else {
		// 精确匹配
		for _, metric := range metrics {
			if metric == pattern {
				matched = append(matched, metric)
				break
			}
		}
	}

	return matched
}

// GetConfigStatus 获取配置生效状态
func (s *MetricsStrategyService) GetConfigStatus(ctx context.Context, agentCode string) (*models.ConfigStatus, error) {
	// 获取实例策略
	instance, err := s.GetInstanceStrategy(ctx, agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get instance strategy: %w", err)
	}

	// 获取Agent的配置版本（需要通过Agent API查询）
	// 这里简化处理，假设Agent已应用配置
	status := &models.ConfigStatus{
		Status:   "active",
		Version:  fmt.Sprintf("%d", instance.Version),
		LastSync: instance.UpdatedAt,
	}

	// TODO: 实际应该从Agent查询当前应用的配置版本
	// 如果版本不匹配，状态为pending
	// 如果查询失败，状态为failed

	return status, nil
}

// getDefaultGlobalStrategy 获取默认全局策略
func (s *MetricsStrategyService) getDefaultGlobalStrategy() *models.GlobalMetricStrategy {
	return &models.GlobalMetricStrategy{
		ID:              GlobalStrategyID,
		DefaultPriority: models.PriorityMedium,
		DefaultInterval: 60,
		MetricRules:     []models.MetricRule{},
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Version:         0,
	}
}

// GetApplicationStrategy 获取应用指标策略（全局或实例）
func (s *MetricsStrategyService) GetApplicationStrategy(ctx context.Context, agentCode string) (*models.ApplicationMetricStrategy, error) {
	collection := s.mongoClient.Database("controller").Collection("application_metric_strategies")

	var strategy models.ApplicationMetricStrategy

	if agentCode == "" {
		// 获取全局策略
		err := collection.FindOne(ctx, bson.M{"_id": "global"}).Decode(&strategy)
		if err == mongo.ErrNoDocuments {
			return s.getDefaultApplicationStrategy("global"), nil
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get global application strategy: %w", err)
		}
	} else {
		// 获取实例策略
		err := collection.FindOne(ctx, bson.M{"agent_code": agentCode}).Decode(&strategy)
		if err == mongo.ErrNoDocuments {
			return s.getDefaultApplicationStrategy(agentCode), nil
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get instance application strategy: %w", err)
		}
	}

	return &strategy, nil
}

// UpdateApplicationStrategy 更新应用指标策略
func (s *MetricsStrategyService) UpdateApplicationStrategy(ctx context.Context, strategy *models.ApplicationMetricStrategy) error {
	collection := s.mongoClient.Database("controller").Collection("application_metric_strategies")

	strategy.UpdatedAt = time.Now()
	strategy.Version = time.Now().Unix()

	if strategy.CreatedAt.IsZero() {
		strategy.CreatedAt = time.Now()
	}

	opts := options.Update().SetUpsert(true)

	var filter bson.M
	if strategy.ID == "global" {
		filter = bson.M{"_id": "global"}
	} else {
		filter = bson.M{"agent_code": strategy.ID}
		// ID 和 agent_code 应该一致
	}

	_, err := collection.UpdateOne(
		ctx,
		filter,
		bson.M{"$set": strategy},
		opts,
	)
	if err != nil {
		return fmt.Errorf("failed to update application strategy: %w", err)
	}

	if s.logger != nil {
		s.logger.Info("Application strategy updated",
			zap.String("id", strategy.ID),
			zap.Int64("version", strategy.Version),
			zap.Int("targets_count", len(strategy.Targets)))
	}

	return nil
}

// getDefaultApplicationStrategy 获取默认应用指标策略
func (s *MetricsStrategyService) getDefaultApplicationStrategy(id string) *models.ApplicationMetricStrategy {
	return &models.ApplicationMetricStrategy{
		ID:              id,
		DefaultInterval: 60,
		Targets:         []models.ApplicationTarget{},
		Version:         0,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}
