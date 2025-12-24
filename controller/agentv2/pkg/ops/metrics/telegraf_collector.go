package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/agent"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// TelegrafInputCollector 使用 telegraf input 插件的指标收集器
type TelegrafInputCollector struct {
	logger    *zap.Logger
	registry  *prometheus.Registry
	inputs    map[string]telegraf.Input
	metricsCh chan telegraf.Metric
	mu        sync.RWMutex
	running   bool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	// 指标缓存
	systemMetrics *domain.SystemMetrics
	metricCache   map[string][]*dto.MetricFamily

	// 配置
	interval time.Duration
	configs  map[string]interface{}
}

// NewTelegrafInputCollector 创建新的 TelegrafInputCollector
func NewTelegrafInputCollector(
	logger *zap.Logger,
	enabledInputs []string,
	interval time.Duration,
	configs map[string]interface{},
) (*TelegrafInputCollector, error) {
	if interval <= 0 {
		interval = 10 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	collector := &TelegrafInputCollector{
		logger:        logger,
		registry:      prometheus.NewRegistry(),
		inputs:        make(map[string]telegraf.Input),
		metricsCh:     make(chan telegraf.Metric, 1000),
		ctx:           ctx,
		cancel:        cancel,
		systemMetrics: &domain.SystemMetrics{},
		metricCache:   make(map[string][]*dto.MetricFamily),
		interval:      interval,
		configs:       configs,
	}

	// 初始化启用的 input 插件
	if err := collector.initInputs(enabledInputs); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to init inputs: %w", err)
	}

	return collector, nil
}

// initInputs 初始化 input 插件
func (c *TelegrafInputCollector) initInputs(enabledInputs []string) error {
	if len(enabledInputs) == 0 {
		// 默认启用核心插件
		enabledInputs = []string{"cpu", "mem", "disk", "diskio", "net", "system"}
	}

	for _, name := range enabledInputs {
		creator, exists := inputs.Inputs[name]
		if !exists {
			c.logger.Warn("Input plugin not found, skipping",
				zap.String("name", name))
			continue
		}

		input := creator()
		if input == nil {
			c.logger.Warn("Failed to create input plugin",
				zap.String("name", name))
			continue
		}

		// 初始化插件
		if initializer, ok := input.(telegraf.Initializer); ok {
			if err := initializer.Init(); err != nil {
				c.logger.Error("Failed to init input plugin",
					zap.String("name", name),
					zap.Error(err))
				continue
			}
		}

		// 应用配置（如果提供）
		if config, ok := c.configs[name]; ok {
			if err := c.applyConfig(input, config); err != nil {
				c.logger.Warn("Failed to apply config to input plugin",
					zap.String("name", name),
					zap.Error(err))
			}
		}

		c.inputs[name] = input
		c.logger.Info("Input plugin initialized",
			zap.String("name", name))
	}

	if len(c.inputs) == 0 {
		return fmt.Errorf("no input plugins were successfully initialized")
	}

	return nil
}

// applyConfig 应用配置到 input 插件（使用反射或类型断言）
func (c *TelegrafInputCollector) applyConfig(input telegraf.Input, config interface{}) error {
	// 这里可以使用反射或类型断言来设置配置
	// 为了简化，我们暂时只记录日志
	// 实际配置应该通过 TOML 解析或结构体映射来完成
	c.logger.Debug("Applying config to input plugin",
		zap.Any("config", config))
	return nil
}

// Start 启动收集器
func (c *TelegrafInputCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("collector is already running")
	}
	c.running = true
	c.mu.Unlock()

	// 启动 ServiceInput 插件
	for name, input := range c.inputs {
		if serviceInput, ok := input.(telegraf.ServiceInput); ok {
			acc := c.createAccumulator(name)
			if err := serviceInput.Start(acc); err != nil {
				c.logger.Error("Failed to start service input",
					zap.String("name", name),
					zap.Error(err))
				continue
			}
			c.logger.Info("Service input started",
				zap.String("name", name))
		}
	}

	// 启动指标收集循环
	c.wg.Add(1)
	go c.collectLoop(ctx)

	// 启动指标处理循环
	c.wg.Add(1)
	go c.processMetrics(ctx)

	c.logger.Info("Telegraf input collector started",
		zap.Int("input_count", len(c.inputs)),
		zap.Duration("interval", c.interval))

	return nil
}

// Stop 停止收集器
func (c *TelegrafInputCollector) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	c.mu.Unlock()

	c.cancel()

	// 停止 ServiceInput 插件
	for name, input := range c.inputs {
		if serviceInput, ok := input.(telegraf.ServiceInput); ok {
			serviceInput.Stop()
			c.logger.Info("Service input stopped",
				zap.String("name", name))
		}
	}

	// 等待所有 goroutine 完成
	c.wg.Wait()

	close(c.metricsCh)

	c.logger.Info("Telegraf input collector stopped")
	return nil
}

// collectLoop 定期收集指标
func (c *TelegrafInputCollector) collectLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// 立即收集一次
	c.gatherMetrics()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.gatherMetrics()
		}
	}
}

// gatherMetrics 收集所有 input 插件的指标
func (c *TelegrafInputCollector) gatherMetrics() {
	c.mu.RLock()
	inputs := make(map[string]telegraf.Input, len(c.inputs))
	for k, v := range c.inputs {
		inputs[k] = v
	}
	c.mu.RUnlock()

	for name, input := range inputs {
		acc := c.createAccumulator(name)
		if err := input.Gather(acc); err != nil {
			c.logger.Warn("Failed to gather metrics from input",
				zap.String("name", name),
				zap.Error(err))
		}
	}
}

// createAccumulator 为 input 插件创建 Accumulator
func (c *TelegrafInputCollector) createAccumulator(inputName string) telegraf.Accumulator {
	maker := &inputMetricMaker{
		name:   inputName,
		logger: c.logger,
	}
	return agent.NewAccumulator(maker, c.metricsCh)
}

// processMetrics 处理收集到的指标
func (c *TelegrafInputCollector) processMetrics(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.ctx.Done():
			return
		case metric, ok := <-c.metricsCh:
			if !ok {
				return
			}
			c.handleMetric(metric)
		}
	}
}

// handleMetric 处理单个指标
func (c *TelegrafInputCollector) handleMetric(m telegraf.Metric) {
	// 转换为 Prometheus 格式
	metricFamilies := convertTelegrafMetricToPrometheus(m)

	// 更新缓存
	c.mu.Lock()
	for _, family := range metricFamilies {
		name := family.GetName()
		c.metricCache[name] = append(c.metricCache[name], family)
	}
	c.mu.Unlock()

	// 更新 SystemMetrics
	c.updateSystemMetrics(m)
}

// updateSystemMetrics 从 telegraf metric 更新 SystemMetrics
func (c *TelegrafInputCollector) updateSystemMetrics(m telegraf.Metric) {
	name := m.Name()
	fields := m.Fields()
	tags := m.Tags()

	c.mu.Lock()
	defer c.mu.Unlock()

	switch name {
	case "cpu":
		c.updateCPUMetrics(fields, tags)
	case "mem":
		c.updateMemoryMetrics(fields)
	case "disk":
		c.updateDiskMetrics(fields, tags)
	case "net":
		c.updateNetworkMetrics(fields, tags)
	case "system":
		c.updateSystemLoadMetrics(fields)
	}

	c.systemMetrics.LastUpdated = time.Now()
}

// updateCPUMetrics 更新 CPU 指标
func (c *TelegrafInputCollector) updateCPUMetrics(fields map[string]interface{}, tags map[string]string) {
	if usagePercent, ok := fields["usage_percent"].(float64); ok {
		c.systemMetrics.CPUUsage = usagePercent
	}
	if cpuTag, ok := tags["cpu"]; ok && cpuTag == "cpu-total" {
		// 处理总 CPU 使用率
	}
}

// updateMemoryMetrics 更新内存指标
func (c *TelegrafInputCollector) updateMemoryMetrics(fields map[string]interface{}) {
	if total, ok := fields["total"].(uint64); ok {
		c.systemMetrics.MemoryTotal = int64(total)
	}
	if available, ok := fields["available"].(uint64); ok {
		c.systemMetrics.MemoryFree = int64(available)
	}
	if usedPercent, ok := fields["used_percent"].(float64); ok {
		c.systemMetrics.MemoryUsage = usedPercent
	}
}

// updateDiskMetrics 更新磁盘指标
func (c *TelegrafInputCollector) updateDiskMetrics(fields map[string]interface{}, tags map[string]string) {
	// 只处理根分区
	if mountpoint, ok := tags["path"]; ok && mountpoint == "/" {
		if total, ok := fields["total"].(uint64); ok {
			c.systemMetrics.DiskTotal = int64(total)
		}
		if free, ok := fields["free"].(uint64); ok {
			c.systemMetrics.DiskFree = int64(free)
		}
		if usedPercent, ok := fields["used_percent"].(float64); ok {
			c.systemMetrics.DiskUsage = usedPercent
		}
	}
}

// updateNetworkMetrics 更新网络指标
func (c *TelegrafInputCollector) updateNetworkMetrics(fields map[string]interface{}, tags map[string]string) {
	interfaceName, ok := tags["interface"]
	if !ok {
		return
	}

	// 跳过回环接口
	if interfaceName == "lo" || interfaceName == "loopback" {
		return
	}

	var rxBytes, txBytes int64
	if bytesRecv, ok := fields["bytes_recv"].(uint64); ok {
		rxBytes = int64(bytesRecv)
	}
	if bytesSent, ok := fields["bytes_sent"].(uint64); ok {
		txBytes = int64(bytesSent)
	}

	// 查找或创建网络接口
	found := false
	for i := range c.systemMetrics.NetworkInterfaces {
		if c.systemMetrics.NetworkInterfaces[i].Name == interfaceName {
			c.systemMetrics.NetworkInterfaces[i].RxBytes = rxBytes
			c.systemMetrics.NetworkInterfaces[i].TxBytes = txBytes
			found = true
			break
		}
	}

	if !found {
		c.systemMetrics.NetworkInterfaces = append(c.systemMetrics.NetworkInterfaces, domain.NetworkInterface{
			Name:    interfaceName,
			RxBytes: rxBytes,
			TxBytes: txBytes,
		})
	}

	// 更新总计
	c.systemMetrics.NetworkIn += rxBytes
	c.systemMetrics.NetworkOut += txBytes
}

// updateSystemLoadMetrics 更新系统负载指标
func (c *TelegrafInputCollector) updateSystemLoadMetrics(fields map[string]interface{}) {
	if load1, ok := fields["load1"].(float64); ok {
		c.systemMetrics.LoadAvg1 = load1
	}
	if load5, ok := fields["load5"].(float64); ok {
		c.systemMetrics.LoadAvg5 = load5
	}
	if load15, ok := fields["load15"].(float64); ok {
		c.systemMetrics.LoadAvg15 = load15
	}
}

// CollectSystemMetrics 收集系统指标
func (c *TelegrafInputCollector) CollectSystemMetrics(ctx context.Context) (*domain.SystemMetrics, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 返回副本
	metrics := *c.systemMetrics
	return &metrics, nil
}

// GetSystemMetrics 获取系统指标
func (c *TelegrafInputCollector) GetSystemMetrics() *domain.SystemMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 返回副本
	metrics := *c.systemMetrics
	return &metrics
}

// GetPrometheusRegistry 获取 Prometheus Registry
func (c *TelegrafInputCollector) GetPrometheusRegistry() *prometheus.Registry {
	return c.registry
}

// UpdateMetrics 更新指标（从缓存转换为 Prometheus 格式）
func (c *TelegrafInputCollector) UpdateMetrics(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 将缓存的指标注册到 Prometheus registry
	// 这里需要将 metricCache 中的指标转换为 Prometheus Collector
	// 为了简化，我们暂时只更新 SystemMetrics

	return nil
}

// inputMetricMaker 实现 MetricMaker 接口
type inputMetricMaker struct {
	name   string
	logger *zap.Logger
}

func (m *inputMetricMaker) LogName() string {
	return m.name
}

func (m *inputMetricMaker) MakeMetric(metric telegraf.Metric) telegraf.Metric {
	// 直接返回，不做过滤
	return metric
}

func (m *inputMetricMaker) Log() telegraf.Logger {
	// 返回一个简单的 logger 实现
	return &simpleLogger{logger: m.logger}
}

// simpleLogger 简单的 logger 实现
type simpleLogger struct {
	logger *zap.Logger
}

func (l *simpleLogger) Level() telegraf.LogLevel {
	return telegraf.Debug
}

func (l *simpleLogger) AddAttribute(key string, value interface{}) {
	// 忽略属性添加
}

func (l *simpleLogger) Errorf(format string, args ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, args...))
}

func (l *simpleLogger) Error(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
}

func (l *simpleLogger) Warnf(format string, args ...interface{}) {
	l.logger.Warn(fmt.Sprintf(format, args...))
}

func (l *simpleLogger) Warn(args ...interface{}) {
	l.logger.Warn(fmt.Sprint(args...))
}

func (l *simpleLogger) Infof(format string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l *simpleLogger) Info(args ...interface{}) {
	l.logger.Info(fmt.Sprint(args...))
}

func (l *simpleLogger) Debugf(format string, args ...interface{}) {
	l.logger.Debug(fmt.Sprintf(format, args...))
}

func (l *simpleLogger) Debug(args ...interface{}) {
	l.logger.Debug(fmt.Sprint(args...))
}

func (l *simpleLogger) Tracef(format string, args ...interface{}) {
	l.logger.Debug(fmt.Sprintf(format, args...))
}

func (l *simpleLogger) Trace(args ...interface{}) {
	l.logger.Debug(fmt.Sprint(args...))
}
