package protocols

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// JSONScraper 自定义 JSON 格式采集器
type JSONScraper struct {
	logger *zap.Logger
	client *http.Client
}

// NewJSONScraper 创建 JSON 采集器
func NewJSONScraper(logger *zap.Logger) *JSONScraper {
	return &JSONScraper{
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Protocol 返回协议名称
func (s *JSONScraper) Protocol() string {
	return "json"
}

// Validate 验证端点配置
func (s *JSONScraper) Validate(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint cannot be empty")
	}
	
	// JSON 端点必须是 HTTP
	if endpoint[:4] != "http" {
		return fmt.Errorf("JSON endpoint must be HTTP")
	}
	
	return nil
}

// JSONMetricsResponse JSON 格式指标响应
type JSONMetricsResponse struct {
	ServiceName string                 `json:"service_name"`
	Timestamp   string                 `json:"timestamp"`
	Metrics     map[string]interface{} `json:"metrics"`
	Labels      map[string]string      `json:"labels,omitempty"`
}

// Scrape 从 JSON 端点采集指标
func (s *JSONScraper) Scrape(ctx context.Context, endpoint string) ([]*dto.MetricFamily, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Accept", "application/json")
	
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}
	
	var jsonResp JSONMetricsResponse
	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}
	
	// 转换为 Prometheus 格式
	metricFamilies := s.convertJSONToPrometheus(&jsonResp)
	
	s.logger.Debug("Scraped JSON metrics",
		zap.String("endpoint", endpoint),
		zap.String("service", jsonResp.ServiceName),
		zap.Int("count", len(metricFamilies)))
	
	return metricFamilies, nil
}

// convertJSONToPrometheus 将 JSON 格式转换为 Prometheus 格式
func (s *JSONScraper) convertJSONToPrometheus(jsonResp *JSONMetricsResponse) []*dto.MetricFamily {
	metricFamilies := make([]*dto.MetricFamily, 0)
	
	for metricName, value := range jsonResp.Metrics {
		family := &dto.MetricFamily{
			Name: &metricName,
			Type: dto.MetricType_GAUGE.Enum(),
		}
		
		metric := &dto.Metric{
			Label: make([]*dto.LabelPair, 0),
		}
		
		// 添加服务名称标签
		if jsonResp.ServiceName != "" {
			metric.Label = append(metric.Label, &dto.LabelPair{
				Name:  stringPtr("service"),
				Value: &jsonResp.ServiceName,
			})
		}
		
		// 添加自定义标签
		for k, v := range jsonResp.Labels {
			metric.Label = append(metric.Label, &dto.LabelPair{
				Name:  stringPtr(k),
				Value: stringPtr(v),
			})
		}
		
		// 转换指标值
		var floatValue float64
		switch v := value.(type) {
		case float64:
			floatValue = v
		case int:
			floatValue = float64(v)
		case int64:
			floatValue = float64(v)
		default:
			s.logger.Warn("Unsupported metric value type",
				zap.String("metric", metricName),
				zap.Any("value", value))
			continue
		}
		
		metric.Gauge = &dto.Gauge{
			Value: &floatValue,
		}
		
		family.Metric = []*dto.Metric{metric}
		metricFamilies = append(metricFamilies, family)
	}
	
	return metricFamilies
}

// stringPtr 返回字符串指针
func stringPtr(s string) *string {
	return &s
}

