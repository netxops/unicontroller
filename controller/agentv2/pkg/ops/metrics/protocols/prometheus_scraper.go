package protocols

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/prometheus/common/expfmt"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// PrometheusScraper Prometheus 协议采集器
type PrometheusScraper struct {
	logger   *zap.Logger
	client   *http.Client
}

// NewPrometheusScraper 创建 Prometheus 采集器
func NewPrometheusScraper(logger *zap.Logger) *PrometheusScraper {
	return &PrometheusScraper{
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Protocol 返回协议名称
func (s *PrometheusScraper) Protocol() string {
	return "prometheus"
}

// Validate 验证端点配置
func (s *PrometheusScraper) Validate(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint cannot be empty")
	}
	
	// 验证 URL 格式
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("endpoint must be HTTP or HTTPS")
	}
	
	return nil
}

// Scrape 从 Prometheus 端点采集指标
func (s *PrometheusScraper) Scrape(ctx context.Context, endpoint string) ([]*dto.MetricFamily, error) {
	// 确保端点以 /metrics 结尾（如果没有路径）
	if endpoint[len(endpoint)-1] != '/' && endpoint[len(endpoint)-7:] != "/metrics" {
		if endpoint[len(endpoint)-1] != '/' {
			endpoint = endpoint + "/metrics"
		} else {
			endpoint = endpoint + "metrics"
		}
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Accept", string(expfmt.FmtText))
	
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}
	
	// 解析 Prometheus 格式
	var parser expfmt.TextParser
	metricFamilies, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %w", err)
	}
	
	// 转换为 dto.MetricFamily 切片
	result := make([]*dto.MetricFamily, 0, len(metricFamilies))
	for _, family := range metricFamilies {
		result = append(result, family)
	}
	
	s.logger.Debug("Scraped Prometheus metrics",
		zap.String("endpoint", endpoint),
		zap.Int("count", len(result)))
	
	return result, nil
}

