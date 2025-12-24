package protocols

import (
	"context"
	"fmt"
	"net"

	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// StatsDScraper StatsD 协议采集器
// 注意：StatsD 通常是推送协议，但这里我们支持从 StatsD 导出端点拉取
type StatsDScraper struct {
	logger *zap.Logger
	client *net.UDPConn
}

// NewStatsDScraper 创建 StatsD 采集器
func NewStatsDScraper(logger *zap.Logger) *StatsDScraper {
	return &StatsDScraper{
		logger: logger,
	}
}

// Protocol 返回协议名称
func (s *StatsDScraper) Protocol() string {
	return "statsd"
}

// Validate 验证端点配置
func (s *StatsDScraper) Validate(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("endpoint cannot be empty")
	}
	
	// StatsD 通常使用 UDP，但也可以从 HTTP 端点拉取（如果 StatsD 导出器支持）
	// 这里我们支持两种格式：
	// 1. UDP: udp://host:port
	// 2. HTTP: http://host:port/metrics
	
	// 简化验证：检查是否为有效的网络地址
	_, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		// 如果不是 UDP 地址，尝试作为 HTTP 端点
		if endpoint[:4] != "http" {
			return fmt.Errorf("invalid StatsD endpoint format: %s", endpoint)
		}
	}
	
	return nil
}

// Scrape 从 StatsD 端点采集指标
// 注意：StatsD 本身是推送协议，这里假设有 StatsD 导出器提供 HTTP 端点
func (s *StatsDScraper) Scrape(ctx context.Context, endpoint string) ([]*dto.MetricFamily, error) {
	// 如果端点是 HTTP，使用 HTTP 客户端拉取
	if endpoint[:4] == "http" {
		// 使用 Prometheus scraper 的逻辑（StatsD 导出器通常提供 Prometheus 格式）
		promScraper := NewPrometheusScraper(s.logger)
		return promScraper.Scrape(ctx, endpoint)
	}
	
	// UDP 模式：StatsD 通常是推送的，这里返回空
	// 实际应用中，StatsD 指标应该通过推送方式接收
	s.logger.Warn("StatsD UDP endpoint is push-only, use HTTP exporter endpoint for pull mode",
		zap.String("endpoint", endpoint))
	
	return []*dto.MetricFamily{}, nil
}

