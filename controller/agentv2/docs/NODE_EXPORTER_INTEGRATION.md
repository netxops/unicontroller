# Node Exporter 集成方案

## 一、方案概述

将 Node Exporter 的功能以代码形式嵌入到 agentv2 中，实现更丰富、更专业的系统指标采集。

### 1.1 当前状态

- **当前实现**: 使用 `gopsutil` 库进行基础指标采集
- **采集指标**: CPU、内存、磁盘、网络、负载等基础指标
- **局限性**: 指标类型有限，缺少详细的系统级指标（如文件系统、进程、硬件等）

### 1.2 集成目标

- **丰富指标**: 集成 Node Exporter 的丰富指标采集能力
- **标准化**: 使用 Prometheus 标准的指标格式
- **可扩展**: 支持按需启用/禁用不同的采集器
- **性能优化**: 最小化资源消耗，保持轻量级

## 二、技术方案

### 2.1 方案选择

#### 方案 A: 直接使用 Node Exporter 的 Collector 库（推荐）

**优点**:
- 直接复用 Node Exporter 的成熟代码
- 指标类型丰富且标准化
- 与 Prometheus 生态完全兼容
- 维护成本低（跟随 Node Exporter 更新）

**缺点**:
- 需要引入额外的依赖
- 可能增加二进制文件大小

**实现方式**:
```go
import (
    "github.com/prometheus/node_exporter/collector"
    "github.com/prometheus/client_golang/prometheus"
)
```

#### 方案 B: 基于 Prometheus Client 自行实现 Collector

**优点**:
- 完全可控，按需实现
- 依赖更少
- 可以定制化指标

**缺点**:
- 开发工作量大
- 需要维护更多代码
- 可能遗漏某些重要指标

### 2.2 推荐方案：混合方案

结合两种方案的优势：
- **核心指标**: 继续使用 gopsutil（轻量、快速）
- **扩展指标**: 集成 Node Exporter 的特定 Collector（按需启用）
- **统一接口**: 通过 Prometheus Registry 统一管理

## 三、架构设计

### 3.1 架构图

```
┌─────────────────────────────────────────────────┐
│              AgentV2 Metrics Layer              │
├─────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────┐  │
│  │     MetricsCollector Interface            │  │
│  └──────────────────────────────────────────┘  │
│                    │                            │
│        ┌───────────┴───────────┐                │
│        │                       │                │
│  ┌─────▼─────┐        ┌───────▼──────┐         │
│  │ Basic     │        │ Enhanced    │         │
│  │ Collector │        │ Collector   │         │
│  │ (gopsutil)│        │ (Node Exp)  │         │
│  └───────────┘        └─────────────┘         │
│        │                       │                │
│        └───────────┬───────────┘                │
│                    │                            │
│         ┌──────────▼──────────┐                 │
│         │ Prometheus Registry │                 │
│         └─────────────────────┘                 │
│                    │                            │
│         ┌──────────▼──────────┐                 │
│         │  Metrics Aggregator │                 │
│         └─────────────────────┘                 │
└─────────────────────────────────────────────────┘
```

### 3.2 核心组件

1. **EnhancedMetricsCollector**: 增强型指标收集器
   - 集成 Node Exporter 的 Collector
   - 管理多个子 Collector
   - 提供统一的指标接口

2. **CollectorManager**: Collector 管理器
   - 按需启用/禁用 Collector
   - 管理 Collector 生命周期
   - 处理 Collector 错误

3. **MetricsRegistry**: Prometheus Registry 封装
   - 统一注册所有指标
   - 提供指标查询接口
   - 支持指标导出

## 四、实现步骤

### 4.1 依赖管理

在 `go.mod` 中添加依赖：

```go
require (
    github.com/prometheus/node_exporter v1.6.1
    github.com/prometheus/client_golang v1.17.0
)
```

### 4.2 创建增强型 Collector

**文件**: `agent/agentv2/pkg/ops/metrics/enhanced_collector.go`

```go
package metrics

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/node_exporter/collector"
    "go.uber.org/zap"
)

// EnhancedMetricsCollector 增强型指标收集器
type EnhancedMetricsCollector struct {
    logger         *zap.Logger
    registry       *prometheus.Registry
    collectors     map[string]collector.Collector
    enabledCollectors []string
    mu             sync.RWMutex
    systemMetrics  *domain.SystemMetrics
}

// NewEnhancedMetricsCollector 创建增强型指标收集器
func NewEnhancedMetricsCollector(
    logger *zap.Logger,
    enabledCollectors []string,
) (*EnhancedMetricsCollector, error) {
    ec := &EnhancedMetricsCollector{
        logger:            logger,
        registry:          prometheus.NewRegistry(),
        collectors:        make(map[string]collector.Collector),
        enabledCollectors: enabledCollectors,
        systemMetrics:     &domain.SystemMetrics{},
    }

    // 初始化并注册 Collector
    if err := ec.initCollectors(); err != nil {
        return nil, fmt.Errorf("failed to init collectors: %w", err)
    }

    return ec, nil
}

// initCollectors 初始化 Collector
func (ec *EnhancedMetricsCollector) initCollectors() error {
    // 定义可用的 Collector
    availableCollectors := map[string]func() (collector.Collector, error){
        "cpu":        func() (collector.Collector, error) { return collector.NewCPUCollector() },
        "meminfo":    func() (collector.Collector, error) { return collector.NewMeminfoCollector() },
        "filesystem": func() (collector.Collector, error) { return collector.NewFilesystemCollector() },
        "diskstats":  func() (collector.Collector, error) { return collector.NewDiskstatsCollector() },
        "netdev":     func() (collector.Collector, error) { return collector.NewNetDevCollector() },
        "loadavg":    func() (collector.Collector, error) { return collector.NewLoadavgCollector() },
        "stat":       func() (collector.Collector, error) { return collector.NewStatCollector() },
        // 可以根据需要添加更多 Collector
    }

    // 启用指定的 Collector
    for _, name := range ec.enabledCollectors {
        if factory, ok := availableCollectors[name]; ok {
            coll, err := factory()
            if err != nil {
                ec.logger.Warn("Failed to create collector",
                    zap.String("name", name),
                    zap.Error(err))
                continue
            }
            ec.collectors[name] = coll
            ec.registry.MustRegister(coll)
            ec.logger.Info("Collector enabled", zap.String("name", name))
        } else {
            ec.logger.Warn("Unknown collector", zap.String("name", name))
        }
    }

    return nil
}

// CollectSystemMetrics 收集系统指标
func (ec *EnhancedMetricsCollector) CollectSystemMetrics(ctx context.Context) (*domain.SystemMetrics, error) {
    // 收集 Prometheus 指标
    metricFamilies, err := ec.registry.Gather()
    if err != nil {
        return nil, fmt.Errorf("failed to gather metrics: %w", err)
    }

    // 转换为 domain.SystemMetrics
    metrics := ec.convertPrometheusMetrics(metricFamilies)
    
    ec.mu.Lock()
    ec.systemMetrics = metrics
    ec.mu.Unlock()

    return metrics, nil
}

// convertPrometheusMetrics 将 Prometheus 指标转换为 domain.SystemMetrics
func (ec *EnhancedMetricsCollector) convertPrometheusMetrics(
    families []*prometheus.MetricFamily,
) *domain.SystemMetrics {
    metrics := &domain.SystemMetrics{
        LastUpdated: time.Now(),
    }

    for _, family := range families {
        switch family.GetName() {
        case "node_cpu_seconds_total":
            // 解析 CPU 指标
            metrics.CPUUsage = ec.parseCPUUsage(family)
        case "node_memory_MemTotal_bytes":
            // 解析内存总量
            if len(family.Metric) > 0 {
                metrics.MemoryTotal = int64(family.Metric[0].GetGauge().GetValue())
            }
        case "node_memory_MemAvailable_bytes":
            // 解析可用内存
            if len(family.Metric) > 0 {
                metrics.MemoryFree = int64(family.Metric[0].GetGauge().GetValue())
            }
        case "node_memory_MemTotal_bytes", "node_memory_MemAvailable_bytes":
            // 计算内存使用率
            if metrics.MemoryTotal > 0 {
                metrics.MemoryUsage = float64(metrics.MemoryTotal-metrics.MemoryFree) / 
                    float64(metrics.MemoryTotal) * 100
            }
        case "node_filesystem_size_bytes":
            // 解析磁盘总量
            metrics.DiskTotal = ec.parseDiskTotal(family)
        case "node_filesystem_avail_bytes":
            // 解析磁盘可用量
            metrics.DiskFree = ec.parseDiskFree(family)
        case "node_load1", "node_load5", "node_load15":
            // 解析负载平均值
            ec.parseLoadAvg(family, metrics)
        case "node_network_receive_bytes_total":
            // 解析网络接收
            metrics.NetworkIn = ec.parseNetworkIn(family)
        case "node_network_transmit_bytes_total":
            // 解析网络发送
            metrics.NetworkOut = ec.parseNetworkOut(family)
        }
    }

    return metrics
}

// GetSystemMetrics 获取系统指标
func (ec *EnhancedMetricsCollector) GetSystemMetrics() *domain.SystemMetrics {
    ec.mu.RLock()
    defer ec.mu.RUnlock()
    return ec.systemMetrics
}

// GetPrometheusRegistry 获取 Prometheus Registry（用于导出指标）
func (ec *EnhancedMetricsCollector) GetPrometheusRegistry() *prometheus.Registry {
    return ec.registry
}

// 辅助函数：解析各种指标
func (ec *EnhancedMetricsCollector) parseCPUUsage(family *prometheus.MetricFamily) float64 {
    // 实现 CPU 使用率计算逻辑
    // 需要计算 idle 和 total 的差值
    return 0.0 // 占位符
}

func (ec *EnhancedMetricsCollector) parseDiskTotal(family *prometheus.MetricFamily) int64 {
    // 实现磁盘总量解析
    return 0 // 占位符
}

func (ec *EnhancedMetricsCollector) parseDiskFree(family *prometheus.MetricFamily) int64 {
    // 实现磁盘可用量解析
    return 0 // 占位符
}

func (ec *EnhancedMetricsCollector) parseLoadAvg(
    family *prometheus.MetricFamily,
    metrics *domain.SystemMetrics,
) {
    // 实现负载平均值解析
}

func (ec *EnhancedMetricsCollector) parseNetworkIn(family *prometheus.MetricFamily) int64 {
    // 实现网络接收解析
    return 0 // 占位符
}

func (ec *EnhancedMetricsCollector) parseNetworkOut(family *prometheus.MetricFamily) int64 {
    // 实现网络发送解析
    return 0 // 占位符
}
```

### 4.3 配置管理

**文件**: `agent/agentv2/configs/agentv2.yaml`

```yaml
metrics:
  # 基础指标收集（使用 gopsutil）
  collect_system: true
  collect_service: true
  interval: 10s

  # 增强指标收集（使用 Node Exporter）
  enhanced:
    enabled: true
    collectors:
      - cpu        # CPU 详细指标
      - meminfo    # 内存详细信息
      - filesystem # 文件系统指标
      - diskstats  # 磁盘 I/O 统计
      - netdev     # 网络设备统计
      - loadavg    # 负载平均值
      - stat       # 系统统计信息
    # 可选：按需启用更多 Collector
    # - hwmon      # 硬件监控
    # - netstat    # 网络统计
    # - process    # 进程统计
```

### 4.4 集成到现有 Collector

修改 `agent/agentv2/pkg/ops/metrics/collector.go`：

```go
type metricsCollector struct {
    logger         *zap.Logger
    registry       ServiceRegistry
    systemMetrics  *domain.SystemMetrics
    serviceMetrics map[string]*domain.ServiceMetrics
    mu             sync.RWMutex
    interval       time.Duration
    collectSystem  bool
    collectService bool
    stopChan       chan struct{}
    
    // 新增：增强型收集器
    enhancedCollector *EnhancedMetricsCollector
    useEnhanced       bool
}

// CollectSystemMetrics 收集系统指标
func (c *metricsCollector) CollectSystemMetrics(ctx context.Context) (*domain.SystemMetrics, error) {
    var metrics *domain.SystemMetrics
    var err error

    // 如果启用了增强型收集器，优先使用
    if c.useEnhanced && c.enhancedCollector != nil {
        metrics, err = c.enhancedCollector.CollectSystemMetrics(ctx)
        if err != nil {
            c.logger.Warn("Enhanced collector failed, falling back to basic",
                zap.Error(err))
            // 降级到基础收集器
            metrics, err = collectSystemMetrics()
        }
    } else {
        // 使用基础收集器
        metrics, err = collectSystemMetrics()
    }

    if err != nil {
        return nil, err
    }

    c.mu.Lock()
    c.systemMetrics = metrics
    c.mu.Unlock()

    return metrics, nil
}
```

### 4.5 支持 Prometheus 格式导出

修改 `agent/agentv2/internal/server/server.go`：

```go
// metricsHandler 指标处理器（Prometheus 格式）
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain; version=0.0.4")

    if s.metricsCollector == nil {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("# Metrics collector not available\n"))
        return
    }

    // 如果使用增强型收集器，直接导出 Prometheus 格式
    if enhanced, ok := s.metricsCollector.(*EnhancedMetricsCollector); ok {
        registry := enhanced.GetPrometheusRegistry()
        promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
        return
    }

    // 否则使用原有的格式化方式
    var output []byte
    if sysMetrics := s.metricsCollector.GetSystemMetrics(); sysMetrics != nil {
        if metrics, ok := sysMetrics.(*domain.SystemMetrics); ok {
            output = append(output, s.formatSystemMetrics(metrics)...)
        }
    }
    w.WriteHeader(http.StatusOK)
    w.Write(output)
}
```

## 五、优势分析

### 5.1 功能优势

1. **丰富的指标类型**
   - CPU: 详细的 CPU 状态、频率、温度等
   - 内存: 详细的内存统计、缓存、交换等
   - 磁盘: I/O 统计、队列深度、延迟等
   - 网络: 详细的网络接口统计、错误率等
   - 系统: 进程数、文件描述符、中断等

2. **标准化**
   - 完全符合 Prometheus 指标规范
   - 与 Prometheus 生态无缝集成
   - 支持 Grafana 等可视化工具

3. **可扩展性**
   - 按需启用/禁用 Collector
   - 支持自定义 Collector
   - 易于添加新的指标类型

### 5.2 性能考虑

1. **资源消耗**
   - 按需启用 Collector，避免不必要的资源消耗
   - 可以配置采集间隔，平衡实时性和性能
   - 使用缓存机制，减少重复计算

2. **兼容性**
   - 保持与现有代码的兼容性
   - 支持降级到基础收集器
   - 不影响现有功能

## 六、实施建议

### 6.1 分阶段实施

**阶段 1: 基础集成（1-2周）**
- 添加 Node Exporter 依赖
- 实现 EnhancedMetricsCollector 基础框架
- 集成核心 Collector（CPU、内存、磁盘、网络）

**阶段 2: 功能完善（2-3周）**
- 完善指标转换逻辑
- 添加配置管理
- 实现降级机制

**阶段 3: 优化和测试（1-2周）**
- 性能优化
- 完整测试
- 文档完善

### 6.2 注意事项

1. **依赖管理**
   - Node Exporter 的版本选择
   - 确保与现有依赖兼容
   - 注意 Go 版本要求

2. **平台兼容性**
   - Linux、Windows、macOS 支持
   - 不同架构（amd64、arm64）的测试

3. **错误处理**
   - Collector 初始化失败的处理
   - 指标采集失败时的降级策略
   - 日志记录和监控

## 七、替代方案

如果直接集成 Node Exporter 遇到困难，可以考虑：

1. **使用 Prometheus Client 库自行实现**
   - 参考 Node Exporter 的实现
   - 按需实现关键指标
   - 更轻量级，但需要更多开发工作

2. **混合方案**
   - 核心指标使用 gopsutil（快速、轻量）
   - 扩展指标使用 Node Exporter（丰富、标准）
   - 通过配置选择使用哪种方式

## 八、总结

将 Node Exporter 嵌入 agentv2 是一个可行的方案，可以显著提升指标采集的丰富度和专业性。建议采用**混合方案**，在保持轻量级的同时，提供丰富的指标采集能力。

关键成功因素：
- 合理的架构设计
- 完善的错误处理
- 良好的性能优化
- 充分的测试验证

