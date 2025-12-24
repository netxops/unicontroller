package metrics

import (
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap"
)

// MetricHistoryPoint 指标历史数据点
type MetricHistoryPoint struct {
	Timestamp time.Time
	Metrics   *domain.SystemMetrics
}

// MetricsHistoryCache 指标历史缓存
type MetricsHistoryCache struct {
	logger      *zap.Logger
	maxPoints   int
	points      []MetricHistoryPoint
	mu          sync.RWMutex
	serviceData map[string][]ServiceMetricHistoryPoint
}

// ServiceMetricHistoryPoint 服务指标历史数据点
type ServiceMetricHistoryPoint struct {
	Timestamp time.Time
	Metrics   *domain.ServiceMetrics
}

// NewMetricsHistoryCache 创建指标历史缓存
func NewMetricsHistoryCache(logger *zap.Logger, maxPoints int) *MetricsHistoryCache {
	return &MetricsHistoryCache{
		logger:      logger,
		maxPoints:   maxPoints,
		points:      make([]MetricHistoryPoint, 0, maxPoints),
		serviceData: make(map[string][]ServiceMetricHistoryPoint),
	}
}

// AddSystemMetrics 添加系统指标到历史缓存
func (c *MetricsHistoryCache) AddSystemMetrics(metrics *domain.SystemMetrics) {
	c.mu.Lock()
	defer c.mu.Unlock()

	point := MetricHistoryPoint{
		Timestamp: time.Now(),
		Metrics:   metrics,
	}

	c.points = append(c.points, point)

	// 如果超过最大点数，删除最旧的数据
	if len(c.points) > c.maxPoints {
		c.points = c.points[1:]
	}
}

// AddServiceMetrics 添加服务指标到历史缓存
func (c *MetricsHistoryCache) AddServiceMetrics(serviceID string, metrics *domain.ServiceMetrics) {
	c.mu.Lock()
	defer c.mu.Unlock()

	point := ServiceMetricHistoryPoint{
		Timestamp: time.Now(),
		Metrics:   metrics,
	}

	if c.serviceData[serviceID] == nil {
		c.serviceData[serviceID] = make([]ServiceMetricHistoryPoint, 0, c.maxPoints)
	}

	c.serviceData[serviceID] = append(c.serviceData[serviceID], point)

	// 如果超过最大点数，删除最旧的数据
	if len(c.serviceData[serviceID]) > c.maxPoints {
		c.serviceData[serviceID] = c.serviceData[serviceID][1:]
	}
}

// GetSystemMetricsHistory 获取系统指标历史
func (c *MetricsHistoryCache) GetSystemMetricsHistory(startTime, endTime time.Time) []MetricHistoryPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []MetricHistoryPoint
	for _, point := range c.points {
		if (point.Timestamp.After(startTime) || point.Timestamp.Equal(startTime)) &&
			(point.Timestamp.Before(endTime) || point.Timestamp.Equal(endTime)) {
			result = append(result, point)
		}
	}

	return result
}

// GetServiceMetricsHistory 获取服务指标历史
func (c *MetricsHistoryCache) GetServiceMetricsHistory(serviceID string, startTime, endTime time.Time) []ServiceMetricHistoryPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()

	points, exists := c.serviceData[serviceID]
	if !exists {
		return nil
	}

	var result []ServiceMetricHistoryPoint
	for _, point := range points {
		if (point.Timestamp.After(startTime) || point.Timestamp.Equal(startTime)) &&
			(point.Timestamp.Before(endTime) || point.Timestamp.Equal(endTime)) {
			result = append(result, point)
		}
	}

	return result
}

// GetLatestSystemMetrics 获取最新的系统指标
func (c *MetricsHistoryCache) GetLatestSystemMetrics() *domain.SystemMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.points) == 0 {
		return nil
	}

	return c.points[len(c.points)-1].Metrics
}

// GetLatestServiceMetrics 获取最新的服务指标
func (c *MetricsHistoryCache) GetLatestServiceMetrics(serviceID string) *domain.ServiceMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	points, exists := c.serviceData[serviceID]
	if !exists || len(points) == 0 {
		return nil
	}

	return points[len(points)-1].Metrics
}

// Clear 清空历史缓存
func (c *MetricsHistoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.points = make([]MetricHistoryPoint, 0, c.maxPoints)
	c.serviceData = make(map[string][]ServiceMetricHistoryPoint)
}

// GetSystemMetricsCount 获取系统指标数据点数量
func (c *MetricsHistoryCache) GetSystemMetricsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.points)
}

// GetServiceMetricsCount 获取服务指标数据点数量
func (c *MetricsHistoryCache) GetServiceMetricsCount(serviceID string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	points, exists := c.serviceData[serviceID]
	if !exists {
		return 0
	}
	return len(points)
}
