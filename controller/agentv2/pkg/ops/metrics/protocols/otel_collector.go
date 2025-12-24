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

// OTelScraper OpenTelemetry 协议采集器
type OTelScraper struct {
	logger *zap.Logger
	client *http.Client
}

// NewOTelScraper 创建 OpenTelemetry 采集器
func NewOTelScraper(logger *zap.Logger) *OTelScraper {
	return &OTelScraper{
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Protocol 返回协议名称
func (s *OTelScraper) Protocol() string {
	return "otel"
}

// Validate 验证端点配置
func (s *OTelScraper) Validate(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint cannot be empty")
	}
	
	// OpenTelemetry 通常使用 HTTP/gRPC
	// 这里我们支持 HTTP 端点（OTel Collector 的 Prometheus 导出器）
	if endpoint[:4] != "http" {
		return fmt.Errorf("OpenTelemetry endpoint must be HTTP")
	}
	
	return nil
}

// Scrape 从 OpenTelemetry 端点采集指标
// 注意：OpenTelemetry 通常使用 gRPC，但 OTel Collector 可以导出为 Prometheus 格式
func (s *OTelScraper) Scrape(ctx context.Context, endpoint string) ([]*dto.MetricFamily, error) {
	// 如果 OTel Collector 配置了 Prometheus 导出器，可以从 HTTP 端点拉取
	// 默认路径通常是 /metrics
	if endpoint[len(endpoint)-1] != '/' && endpoint[len(endpoint)-7:] != "/metrics" {
		if endpoint[len(endpoint)-1] != '/' {
			endpoint = endpoint + "/metrics"
		} else {
			endpoint = endpoint + "metrics"
		}
	}
	
	// 使用 Prometheus scraper 的逻辑（OTel Collector 的 Prometheus 导出器提供 Prometheus 格式）
	promScraper := NewPrometheusScraper(s.logger)
	return promScraper.Scrape(ctx, endpoint)
}

// OTelMetricsResponse OpenTelemetry 指标响应（如果使用原生格式）
type OTelMetricsResponse struct {
	ResourceMetrics []OTelResourceMetrics `json:"resourceMetrics"`
}

type OTelResourceMetrics struct {
	Resource struct {
		Attributes []OTelAttribute `json:"attributes"`
	} `json:"resource"`
	ScopeMetrics []OTelScopeMetrics `json:"scopeMetrics"`
}

type OTelScopeMetrics struct {
	Scope struct {
		Name string `json:"name"`
	} `json:"scope"`
	Metrics []OTelMetric `json:"metrics"`
}

type OTelMetric struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Unit        string      `json:"unit"`
	Data        interface{} `json:"data"`
}

type OTelAttribute struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// scrapeOTelNative 从 OpenTelemetry 原生端点采集（如果支持）
func (s *OTelScraper) scrapeOTelNative(ctx context.Context, endpoint string) ([]*dto.MetricFamily, error) {
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
	
	var oTelResp OTelMetricsResponse
	if err := json.NewDecoder(resp.Body).Decode(&oTelResp); err != nil {
		return nil, fmt.Errorf("failed to decode OTel response: %w", err)
	}
	
	// 转换为 Prometheus 格式（简化实现）
	// 实际应用中需要完整的 OTel 到 Prometheus 转换逻辑
	metricFamilies := make([]*dto.MetricFamily, 0)
	
	s.logger.Debug("Scraped OpenTelemetry metrics",
		zap.String("endpoint", endpoint),
		zap.Int("count", len(metricFamilies)))
	
	return metricFamilies, nil
}

