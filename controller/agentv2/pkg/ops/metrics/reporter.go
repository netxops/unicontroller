package metrics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/prometheus/prometheus/prompb"
	"go.uber.org/zap"
)

// MetricsReporter 指标上报器接口
type MetricsReporter interface {
	Start(ctx context.Context) error
	Stop() error
	Report(ctx context.Context) error
}

// metricsReporter 指标上报器实现
type metricsReporter struct {
	collector      MetricsCollector
	controllerURL  string
	agentCode      string
	reportInterval time.Duration
	retryCount     int
	retryDelay     time.Duration
	client         *http.Client
	logger         *zap.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.Mutex
}

// NewMetricsReporter 创建指标上报器
func NewMetricsReporter(
	collector MetricsCollector,
	controllerURL string,
	agentCode string,
	reportInterval time.Duration,
	retryCount int,
	retryDelay time.Duration,
	logger *zap.Logger,
) MetricsReporter {
	ctx, cancel := context.WithCancel(context.Background())
	return &metricsReporter{
		collector:      collector,
		controllerURL:  controllerURL,
		agentCode:      agentCode,
		reportInterval: reportInterval,
		retryCount:     retryCount,
		retryDelay:     retryDelay,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start 启动指标上报
func (r *metricsReporter) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 合并上下文
	r.ctx, r.cancel = context.WithCancel(ctx)

	r.wg.Add(1)
	go r.runPeriodicReport()

	r.logger.Info("Metrics reporter started",
		zap.String("controller_url", r.controllerURL),
		zap.Duration("interval", r.reportInterval))

	return nil
}

// Stop 停止指标上报
func (r *metricsReporter) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancel != nil {
		r.cancel()
	}

	r.wg.Wait()
	r.logger.Info("Metrics reporter stopped")
	return nil
}

// runPeriodicReport 定期上报指标
func (r *metricsReporter) runPeriodicReport() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.reportInterval)
	defer ticker.Stop()

	// 立即上报一次
	if err := r.Report(r.ctx); err != nil {
		r.logger.Warn("Failed to report metrics on startup", zap.Error(err))
	}

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			if err := r.Report(r.ctx); err != nil {
				r.logger.Warn("Failed to report metrics", zap.Error(err))
			}
		}
	}
}

// Report 上报指标
func (r *metricsReporter) Report(ctx context.Context) error {
	// 构建 Prometheus Remote Write 请求
	writeRequest, err := r.buildWriteRequest(ctx)
	if err != nil {
		return fmt.Errorf("failed to build write request: %w", err)
	}

	if len(writeRequest.Timeseries) == 0 {
		r.logger.Debug("No metrics to report")
		return nil
	}

	// 序列化并压缩
	data, err := r.serializeAndCompress(writeRequest)
	if err != nil {
		return fmt.Errorf("failed to serialize metrics: %w", err)
	}

	// 发送到 Controller（带重试）
	return r.sendWithRetry(ctx, data)
}

// buildWriteRequest 构建 Prometheus Remote Write 请求
func (r *metricsReporter) buildWriteRequest(ctx context.Context) (*prompb.WriteRequest, error) {
	writeRequest := &prompb.WriteRequest{
		Timeseries: make([]prompb.TimeSeries, 0),
	}

	// 添加系统指标
	systemMetrics := r.collector.GetSystemMetrics()
	if systemMetrics != nil {
		timeseries := r.convertSystemMetrics(systemMetrics)
		writeRequest.Timeseries = append(writeRequest.Timeseries, timeseries...)
	}

	// 添加服务指标
	allServiceMetrics := r.collector.GetAllServiceMetrics()
	if len(allServiceMetrics) > 0 {
		for serviceID, serviceMetrics := range allServiceMetrics {
			if serviceMetrics != nil {
				timeseries := r.convertServiceMetrics(serviceID, serviceMetrics)
				writeRequest.Timeseries = append(writeRequest.Timeseries, timeseries...)
			}
		}
	}

	return writeRequest, nil
}

// convertSystemMetrics 转换系统指标为 Prometheus TimeSeries
func (r *metricsReporter) convertSystemMetrics(metrics *domain.SystemMetrics) []prompb.TimeSeries {
	now := time.Now().UnixMilli()
	timeseries := make([]prompb.TimeSeries, 0)

	// 基础标签
	baseLabels := []prompb.Label{
		{Name: "__name__", Value: "agent_system"},
		{Name: "agent_code", Value: r.agentCode},
		{Name: "instance", Value: r.agentCode},
	}

	// CPU 使用率
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "cpu_usage"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.CPUUsage},
		},
	})

	// 内存使用率
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "memory_usage"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.MemoryUsage},
		},
	})

	// 内存总量（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "memory_total_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.MemoryTotal)},
		},
	})

	// 内存空闲（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "memory_free_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.MemoryFree)},
		},
	})

	// 磁盘使用率
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "disk_usage"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.DiskUsage},
		},
	})

	// 磁盘总量（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "disk_total_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.DiskTotal)},
		},
	})

	// 磁盘空闲（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "disk_free_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.DiskFree)},
		},
	})

	// 网络入流量（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "network_in_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.NetworkIn)},
		},
	})

	// 网络出流量（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "network_out_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.NetworkOut)},
		},
	})

	// 负载平均值
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "load_avg_1"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.LoadAvg1},
		},
	})

	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "load_avg_5"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.LoadAvg5},
		},
	})

	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "load_avg_15"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.LoadAvg15},
		},
	})

	return timeseries
}

// convertServiceMetrics 转换服务指标为 Prometheus TimeSeries
func (r *metricsReporter) convertServiceMetrics(serviceID string, metrics *domain.ServiceMetrics) []prompb.TimeSeries {
	now := time.Now().UnixMilli()
	timeseries := make([]prompb.TimeSeries, 0)

	// 基础标签
	baseLabels := []prompb.Label{
		{Name: "__name__", Value: "agent_service"},
		{Name: "agent_code", Value: r.agentCode},
		{Name: "service_id", Value: serviceID},
		{Name: "instance", Value: r.agentCode},
	}

	// CPU 使用率
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "cpu_usage"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.CPUUsage},
		},
	})

	// 内存使用率
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "memory_usage"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.MemoryUsage},
		},
	})

	// 内存使用量（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "memory_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.MemoryBytes)},
		},
	})

	// 磁盘使用率
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "disk_usage"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: metrics.DiskUsage},
		},
	})

	// 网络入流量（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "network_in_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.NetworkIn)},
		},
	})

	// 网络出流量（字节）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "network_out_bytes"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.NetworkOut)},
		},
	})

	// 请求数
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "request_count"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.RequestCount)},
		},
	})

	// 错误数
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "error_count"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.ErrorCount)},
		},
	})

	// 响应时间（毫秒）
	timeseries = append(timeseries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{Name: "metric", Value: "response_time_ms"}),
		Samples: []prompb.Sample{
			{Timestamp: now, Value: float64(metrics.ResponseTime.Milliseconds())},
		},
	})

	return timeseries
}

// serializeAndCompress 序列化并压缩数据
func (r *metricsReporter) serializeAndCompress(writeRequest *prompb.WriteRequest) ([]byte, error) {
	// 序列化
	uncompressed, err := proto.Marshal(writeRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal WriteRequest: %w", err)
	}

	// 压缩
	compressed := snappy.Encode(nil, uncompressed)
	return compressed, nil
}

// sendWithRetry 发送数据（带重试）
func (r *metricsReporter) sendWithRetry(ctx context.Context, data []byte) error {
	url := fmt.Sprintf("%s/api/v1/prometheus/write", r.controllerURL)

	for attempt := 0; attempt <= r.retryCount; attempt++ {
		if attempt > 0 {
			// 等待重试延迟
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(r.retryDelay):
			}
			r.logger.Debug("Retrying metrics report",
				zap.Int("attempt", attempt),
				zap.String("url", url))
		}

		err := r.send(ctx, url, data)
		if err == nil {
			if attempt > 0 {
				r.logger.Info("Metrics report succeeded after retry",
					zap.Int("attempt", attempt))
			}
			return nil
		}

		if attempt < r.retryCount {
			r.logger.Warn("Metrics report failed, will retry",
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", r.retryCount),
				zap.Error(err))
		} else {
			r.logger.Error("Metrics report failed after all retries",
				zap.Int("attempts", attempt+1),
				zap.Error(err))
		}
	}

	return fmt.Errorf("failed to send metrics after %d attempts", r.retryCount+1)
}

// send 发送数据
func (r *metricsReporter) send(ctx context.Context, url string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller returned error: status=%d, body=%s", resp.StatusCode, string(bodyBytes))
	}

	r.logger.Debug("Metrics reported successfully",
		zap.String("url", url),
		zap.Int("status_code", resp.StatusCode),
		zap.Int("data_size", len(data)))

	return nil
}
