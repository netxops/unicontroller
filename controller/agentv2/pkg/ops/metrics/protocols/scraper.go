package protocols

import (
	"context"
	"time"

	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// Scraper 指标采集器接口
// 所有协议采集器都需要实现此接口
type Scraper interface {
	// Scrape 从指定端点采集指标
	Scrape(ctx context.Context, endpoint string) ([]*dto.MetricFamily, error)
	
	// Validate 验证端点配置是否有效
	Validate(endpoint string) error
	
	// Protocol 返回协议名称
	Protocol() string
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

// ScraperFactory 采集器工厂
type ScraperFactory struct {
	scrapers map[string]Scraper
	logger   *zap.Logger
}

// NewScraperFactory 创建采集器工厂
func NewScraperFactory(logger *zap.Logger) *ScraperFactory {
	factory := &ScraperFactory{
		scrapers: make(map[string]Scraper),
		logger:   logger,
	}
	
	// 注册所有支持的协议采集器
	factory.RegisterScraper(NewPrometheusScraper(logger))
	factory.RegisterScraper(NewStatsDScraper(logger))
	factory.RegisterScraper(NewOTelScraper(logger))
	factory.RegisterScraper(NewJSONScraper(logger))
	
	return factory
}

// RegisterScraper 注册采集器
func (f *ScraperFactory) RegisterScraper(scraper Scraper) {
	f.scrapers[scraper.Protocol()] = scraper
	f.logger.Info("Registered scraper",
		zap.String("protocol", scraper.Protocol()))
}

// GetScraper 获取指定协议的采集器
func (f *ScraperFactory) GetScraper(protocol string) (Scraper, bool) {
	scraper, exists := f.scrapers[protocol]
	return scraper, exists
}

// ListProtocols 列出所有支持的协议
func (f *ScraperFactory) ListProtocols() []string {
	protocols := make([]string, 0, len(f.scrapers))
	for protocol := range f.scrapers {
		protocols = append(protocols, protocol)
	}
	return protocols
}

