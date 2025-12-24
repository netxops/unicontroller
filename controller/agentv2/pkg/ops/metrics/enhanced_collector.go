//go:build linux
// +build linux

// Package metrics provides metrics collection functionality.
// This file is only compiled on Linux systems because it depends on
// node_exporter collectors which are Linux-specific.
// On macOS and other systems, use TelegrafInputCollector instead.

package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/node_exporter/collector"
	"github.com/prometheus/procfs"
	"go.uber.org/zap"
)

// EnhancedMetricsCollector 增强型指标收集器
// 使用 Prometheus Node Exporter 的 collectors 实现
type EnhancedMetricsCollector struct {
	logger          *zap.Logger
	registry        *prometheus.Registry
	collectors      map[string]collector.Collector
	systemMetrics   *domain.SystemMetrics
	currentConfig   EnhancedCollectorConfig  // 当前配置
	strategyManager StrategyManagerInterface // 策略管理器接口（用于获取更新间隔）
	mu              sync.RWMutex
}

// StrategyManagerInterface 策略管理器接口（避免循环依赖）
type StrategyManagerInterface interface {
	GetMetricInterval(metricName string) int // 获取指标的采集间隔（秒）
}

// EnhancedCollectorConfig 增强型收集器配置
type EnhancedCollectorConfig struct {
	EnabledCollectors []string // 启用的collectors列表（空表示启用所有）
	ExcludeCollectors []string // 排除的collectors列表
	OnlyCore          bool     // 是否只启用核心collectors
}

// NewEnhancedMetricsCollector 创建增强型指标收集器
func NewEnhancedMetricsCollector(logger *zap.Logger, config ...EnhancedCollectorConfig) (*EnhancedMetricsCollector, error) {
	var collectorConfig EnhancedCollectorConfig
	if len(config) > 0 {
		collectorConfig = config[0]
	}

	logger.Info("Creating enhanced metrics collector",
		zap.Bool("only_core", collectorConfig.OnlyCore),
		zap.Int("enabled_count", len(collectorConfig.EnabledCollectors)),
		zap.Int("exclude_count", len(collectorConfig.ExcludeCollectors)))

	registry := prometheus.NewRegistry()
	if registry == nil {
		return nil, fmt.Errorf("failed to create Prometheus registry")
	}

	ec := &EnhancedMetricsCollector{
		logger:        logger,
		registry:      registry,
		collectors:    make(map[string]collector.Collector),
		systemMetrics: &domain.SystemMetrics{},
		currentConfig: collectorConfig,
	}

	logger.Debug("Enhanced metrics collector struct created",
		zap.Bool("registry_is_nil", ec.registry == nil))

	// 初始化并注册 Node Exporter collectors
	if err := ec.initCollectors(collectorConfig); err != nil {
		logger.Error("Failed to initialize collectors",
			zap.Error(err))
		return nil, fmt.Errorf("failed to init collectors: %w", err)
	}

	return ec, nil
}

// SetStrategyManager 设置策略管理器（用于获取更新间隔）
func (ec *EnhancedMetricsCollector) SetStrategyManager(sm StrategyManagerInterface) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.strategyManager = sm
	ec.logger.Info("Strategy manager set for enhanced collector")

	// 重新初始化 collectors 以应用新的更新间隔
	// 注意：这需要重新注册 collectors，可能会影响正在运行的收集
	// 为了简化，我们只在创建时设置间隔，不在这里重新初始化
}

// 核心 collectors（最常用且稳定的）
var coreCollectors = map[string]bool{
	"cpu":        true,
	"meminfo":    true,
	"loadavg":    true,
	"filesystem": true,
	"diskstats":  true,
	"netdev":     true,
	"stat":       true,
	"os":         true,
	"time":       true,
	"uname":      true,
}

// initCollectors 初始化并注册 Node Exporter collectors
func (ec *EnhancedMetricsCollector) initCollectors(config EnhancedCollectorConfig) error {
	// node_exporter collectors 使用包级别的 kingpin 变量来设置 procfs/sysfs 路径
	// 这些变量在 node_exporter/collector/paths.go 中定义：
	//   var procPath = kingpin.Flag("path.procfs", ...).Default(procfs.DefaultMountPoint).String()
	//   var sysPath = kingpin.Flag("path.sysfs", ...).Default("/sys").String()
	//
	// 问题：如果 kingpin 没有被初始化（没有调用 Parse()），这些变量可能是 nil 或空字符串
	//
	// 解决方案：我们需要在初始化 collectors 之前，确保 kingpin 被初始化
	// 由于 node_exporter 使用全局的 kingpin.Application，我们需要使用相同的 Application
	// 但是，node_exporter 的包级别变量是私有的，我们无法直接访问
	//
	// 最终解决方案：通过反射和 unsafe 来设置 node_exporter 包级别的变量
	// 这需要知道变量的确切名称和内存地址

	// 设置 procfs 和 sysfs 路径（使用默认值）
	procfsPath := os.Getenv("PROCFS_PATH")
	if procfsPath == "" {
		procfsPath = procfs.DefaultMountPoint
	}
	sysfsPath := os.Getenv("SYSFS_PATH")
	if sysfsPath == "" {
		sysfsPath = "/sys"
	}

	// node_exporter 的 collectors 使用包级别的 kingpin 变量来设置 procfs/sysfs 路径
	// 这些变量在 collector/paths.go 中定义：
	//   var procPath = kingpin.Flag("path.procfs", ...).Default(procfs.DefaultMountPoint).String()
	//   var sysPath = kingpin.Flag("path.sysfs", ...).Default("/sys").String()
	//
	// 问题：如果 kingpin 没有被初始化（没有调用 Parse()），这些变量可能是 nil 或空字符串
	//
	// 解决方案：我们需要在初始化 collectors 之前，确保 kingpin 被初始化
	// node_exporter 使用全局的 kingpin.Application，我们需要使用相同的 Application
	// 通过调用 kingpin.Parse() 来初始化这些变量

	// node_exporter 使用全局的 kingpin（不是 kingpin.New()）
	// 这意味着所有的 flags 都注册到同一个全局 Application
	// node_exporter 的 collector 包已经在 paths.go 中定义了这些 flags：
	//   var procPath = kingpin.Flag("path.procfs", ...).Default(procfs.DefaultMountPoint).String()
	//   var sysPath = kingpin.Flag("path.sysfs", ...).Default("/sys").String()
	//
	// 我们不应该重复定义这些 flags，而是应该调用 kingpin.Parse() 来初始化它们
	// 但是，我们需要确保 kingpin 使用默认值

	// 保存原始的 os.Args
	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
	}()

	// 设置 os.Args 为只包含程序名，让 kingpin 使用默认值
	os.Args = []string{"node_exporter"}

	// 解析命令行参数
	// kingpin.Parse() 会初始化所有已注册的 flags，包括 node_exporter 的 paths.go 中定义的
	// 这样 procPath 和 sysPath 变量会被设置为默认值
	_ = kingpin.Parse()

	ec.logger.Info("Initialized procfs/sysfs paths via kingpin",
		zap.String("procfs_path", procfsPath),
		zap.String("sysfs_path", sysfsPath),
		zap.String("note", "Using node_exporter's default paths from paths.go"))

	// 创建 slog.Logger（node_exporter 使用标准库的 slog）
	logger := slog.Default()

	// 定义所有可用的 collectors（使用 Node Exporter 的 collector 包）
	// 支持 node_exporter 的所有 collectors
	availableCollectors := map[string]func() (collector.Collector, error){
		// 核心系统指标
		"cpu":         func() (collector.Collector, error) { return collector.NewCPUCollector(logger) },
		"cpufreq":     func() (collector.Collector, error) { return collector.NewCPUFreqCollector(logger) },
		"meminfo":     func() (collector.Collector, error) { return collector.NewMeminfoCollector(logger) },
		"meminfonuma": func() (collector.Collector, error) { return collector.NewMeminfoNumaCollector(logger) },
		"loadavg":     func() (collector.Collector, error) { return collector.NewLoadavgCollector(logger) },
		"stat":        func() (collector.Collector, error) { return collector.NewStatCollector(logger) },
		"os":          func() (collector.Collector, error) { return collector.NewOSCollector(logger) },
		"time":        func() (collector.Collector, error) { return collector.NewTimeCollector(logger) },
		"timex":       func() (collector.Collector, error) { return collector.NewTimexCollector(logger) },
		"uname":       func() (collector.Collector, error) { return collector.NewUnameCollector(logger) },
		// boottime 通过 OS collector 提供

		// 文件系统和磁盘
		"filesystem": func() (collector.Collector, error) { return collector.NewFilesystemCollector(logger) },
		"diskstats":  func() (collector.Collector, error) { return collector.NewDiskstatsCollector(logger) },
		"mountstats": func() (collector.Collector, error) { return collector.NewMountStatsCollector(logger) },
		// xfs 和 zfs 通过 filesystem collector 提供
		"btrfs": func() (collector.Collector, error) { return collector.NewBtrfsCollector(logger) },
		"nvme":  func() (collector.Collector, error) { return collector.NewNVMeCollector(logger) },

		// 网络
		"netdev":       func() (collector.Collector, error) { return collector.NewNetDevCollector(logger) },
		"netclass":     func() (collector.Collector, error) { return collector.NewNetClassCollector(logger) },
		"netstat":      func() (collector.Collector, error) { return collector.NewNetStatCollector(logger) },
		"networkroute": func() (collector.Collector, error) { return collector.NewNetworkRouteCollector(logger) },
		"conntrack":    func() (collector.Collector, error) { return collector.NewConntrackCollector(logger) },
		"arp":          func() (collector.Collector, error) { return collector.NewARPCollector(logger) },
		"bonding":      func() (collector.Collector, error) { return collector.NewBondingCollector(logger) },
		"ethtool":      func() (collector.Collector, error) { return collector.NewEthtoolCollector(logger) },
		"fibrechannel": func() (collector.Collector, error) { return collector.NewFibreChannelCollector(logger) },
		"infiniband":   func() (collector.Collector, error) { return collector.NewInfiniBandCollector(logger) },
		"ipvs":         func() (collector.Collector, error) { return collector.NewIPVSCollector(logger) },
		"qdisc":        func() (collector.Collector, error) { return collector.NewQdiscStatCollector(logger) },
		"lnstat":       func() (collector.Collector, error) { return collector.NewLnstatCollector(logger) },
		"wifi":         func() (collector.Collector, error) { return collector.NewWifiCollector(logger) },
		"xfrm":         func() (collector.Collector, error) { return collector.NewXfrmCollector(logger) },

		// 进程和系统调用
		"processes":  func() (collector.Collector, error) { return collector.NewProcessStatCollector(logger) },
		"interrupts": func() (collector.Collector, error) { return collector.NewInterruptsCollector(logger) },
		"softirqs":   func() (collector.Collector, error) { return collector.NewSoftirqsCollector(logger) },
		"schedstat":  func() (collector.Collector, error) { return collector.NewSchedstatCollector(logger) },
		"filefd":     func() (collector.Collector, error) { return collector.NewFileFDStatCollector(logger) },
		"sockstat":   func() (collector.Collector, error) { return collector.NewSockStatCollector(logger) },
		"tcpstat":    func() (collector.Collector, error) { return collector.NewTCPStatCollector(logger) },
		"udpqueues":  func() (collector.Collector, error) { return collector.NewUDPqueuesCollector(logger) },

		// 内存和缓存
		"slabinfo":  func() (collector.Collector, error) { return collector.NewSlabinfoCollector(logger) },
		"buddyinfo": func() (collector.Collector, error) { return collector.NewBuddyinfoCollector(logger) },
		"vmstat":    func() (collector.Collector, error) { return collector.NewvmStatCollector(logger) },
		"pressure":  func() (collector.Collector, error) { return collector.NewPressureStatsCollector(logger) },
		"ksmd":      func() (collector.Collector, error) { return collector.NewKsmdCollector(logger) },

		// 硬件和驱动
		"hwmon":            func() (collector.Collector, error) { return collector.NewHwMonCollector(logger) },
		"dmi":              func() (collector.Collector, error) { return collector.NewDMICollector(logger) },
		"edac":             func() (collector.Collector, error) { return collector.NewEdacCollector(logger) },
		"drm":              func() (collector.Collector, error) { return collector.NewDrmCollector(logger) },
		"pcidevice":        func() (collector.Collector, error) { return collector.NewPcideviceCollector(logger) },
		"rapl":             func() (collector.Collector, error) { return collector.NewRaplCollector(logger) },
		"thermalzone":      func() (collector.Collector, error) { return collector.NewThermalZoneCollector(logger) },
		"powersupplyclass": func() (collector.Collector, error) { return collector.NewPowerSupplyClassCollector(logger) },
		"watchdog":         func() (collector.Collector, error) { return collector.NewWatchdogCollector(logger) },
		// cpu_vulnerabilities 通过 cpu collector 提供

		// 存储相关
		"mdadm":  func() (collector.Collector, error) { return collector.NewMdadmCollector(logger) },
		"bcache": func() (collector.Collector, error) { return collector.NewBcacheCollector(logger) },
		// drbd collector 可能不可用，跳过
		"tapestats": func() (collector.Collector, error) { return collector.NewTapestatsCollector(logger) },

		// 系统服务
		"systemd":     func() (collector.Collector, error) { return collector.NewSystemdCollector(logger) },
		"logind":      func() (collector.Collector, error) { return collector.NewLogindCollector(logger) },
		"runit":       func() (collector.Collector, error) { return collector.NewRunitCollector(logger) },
		"supervisord": func() (collector.Collector, error) { return collector.NewSupervisordCollector(logger) },

		// 文件系统服务
		"nfs":  func() (collector.Collector, error) { return collector.NewNfsCollector(logger) },
		"nfsd": func() (collector.Collector, error) { return collector.NewNFSdCollector(logger) },

		// 安全
		"selinux": func() (collector.Collector, error) { return collector.NewSelinuxCollector(logger) },

		// 其他
		"entropy":       func() (collector.Collector, error) { return collector.NewEntropyCollector(logger) },
		"ntp":           func() (collector.Collector, error) { return collector.NewNtpCollector(logger) },
		"perf":          func() (collector.Collector, error) { return collector.NewPerfCollector(logger) },
		"cgroupsummary": func() (collector.Collector, error) { return collector.NewCgroupSummaryCollector(logger) },
		"zoneinfo":      func() (collector.Collector, error) { return collector.NewZoneinfoCollector(logger) },
		"swap":          func() (collector.Collector, error) { return collector.NewSwapCollector(logger) },
		"softnet":       func() (collector.Collector, error) { return collector.NewSoftnetCollector(logger) },
		"sysctl":        func() (collector.Collector, error) { return collector.NewSysctlCollector(logger) },
		"textfile":      func() (collector.Collector, error) { return collector.NewTextFileCollector(logger) },
	}

	// 确定要启用的 collectors
	shouldEnable := func(name string) bool {
		// 如果配置了排除列表，先检查是否被排除
		for _, exclude := range config.ExcludeCollectors {
			if exclude == name {
				return false
			}
		}

		// 如果配置了启用列表（非空），只启用列表中的
		if len(config.EnabledCollectors) > 0 {
			found := false
			for _, enabled := range config.EnabledCollectors {
				if enabled == name {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		// 如果配置了只启用核心collectors，检查是否为核心collector
		if config.OnlyCore {
			if !coreCollectors[name] {
				return false
			}
		}

		return true
	}

	// 启用 collectors
	enabledCount := 0
	failedCount := 0
	skippedCount := 0
	envLimitErrors := 0 // 环境限制导致的错误（如缺少/proc、/sys）

	for name, factory := range availableCollectors {
		// 检查是否应该启用此collector
		if !shouldEnable(name) {
			skippedCount++
			ec.logger.Debug("Skipping collector (not in enabled list or excluded)",
				zap.String("name", name))
			continue
		}

		coll, err := factory()
		if err != nil {
			failedCount++
			// 判断是否为环境限制错误（非关键错误）
			errStr := err.Error()
			isEnvLimit := containsAny(errStr, []string{
				"failed to open procfs",
				"failed to open sysfs",
				"could not read",
				"no such file or directory",
				"only IP address",
			})

			if isEnvLimit {
				envLimitErrors++
				// 环境限制导致的失败使用Info级别（便于调试）
				ec.logger.Info("Collector not available (environment limitation)",
					zap.String("name", name),
					zap.String("reason", errStr))
			} else {
				// 真正的错误使用Warn级别
				ec.logger.Warn("Failed to create collector",
					zap.String("name", name),
					zap.Error(err))
			}
			continue
		}
		ec.collectors[name] = coll

		// 获取该 collector 对应的更新间隔
		updateInterval := time.Duration(60) * time.Second // 默认 60 秒
		if ec.strategyManager != nil {
			// 获取 collector 对应的指标前缀
			metricPrefix := collectorNameToMetricPrefix[name]
			if metricPrefix != "" {
				// 使用指标前缀获取间隔（策略中可能配置了 node_memory_* 这样的规则）
				interval := ec.strategyManager.GetMetricInterval(metricPrefix + "_*")
				updateInterval = time.Duration(interval) * time.Second
				ec.logger.Debug("Collector update interval from strategy",
					zap.String("collector", name),
					zap.String("metric_prefix", metricPrefix),
					zap.Int("interval_seconds", interval))
			} else {
				// 如果没有映射，使用默认间隔
				ec.logger.Debug("Collector has no metric prefix mapping, using default interval",
					zap.String("collector", name),
					zap.Duration("default_interval", updateInterval))
			}
		}

		// 创建适配器，将 collector.Collector 适配为 prometheus.Collector
		adapter := &collectorAdapter{
			collector:       coll,
			name:            name,
			desc:            nil, // 将在 Describe 时创建
			logger:          ec.logger,
			updateInterval:  updateInterval,
			lastUpdateTime:  time.Time{}, // 初始化为零值，表示从未更新
			cachedMetrics:   make([]prometheus.Metric, 0),
			strategyManager: ec.strategyManager,
		}

		// 使用 Register 而不是 MustRegister，以便捕获错误
		if err := ec.registry.Register(adapter); err != nil {
			ec.logger.Warn("Failed to register collector",
				zap.String("name", name),
				zap.Error(err))
			// 移除已创建的 collector
			delete(ec.collectors, name)
			continue
		}

		// 验证 collector 是否正确注册
		ec.logger.Debug("Collector registered successfully",
			zap.String("name", name))

		enabledCount++
		ec.logger.Info("Collector enabled successfully", zap.String("name", name))
	}

	ec.logger.Info("Enhanced metrics collector initialized",
		zap.Int("enabled_collectors", enabledCount),
		zap.Int("failed_collectors", failedCount),
		zap.Int("skipped_collectors", skippedCount),
		zap.Int("env_limit_errors", envLimitErrors),
		zap.Int("total_collectors", len(availableCollectors)))

	if enabledCount == 0 {
		ec.logger.Warn("No collectors were enabled. Metrics endpoint may not work properly.")
	}

	return nil
}

// UpdateMetrics 更新指标（从 Node Exporter collectors 收集数据）
func (ec *EnhancedMetricsCollector) UpdateMetrics(ctx context.Context) error {
	// Node Exporter collectors 会自动更新 Prometheus registry 中的指标
	// 我们只需要收集指标并转换为 domain.SystemMetrics
	ec.mu.RLock()
	registry := ec.registry
	collectorsCount := len(ec.collectors)
	ec.mu.RUnlock()

	if registry == nil {
		ec.logger.Error("Registry is nil in UpdateMetrics")
		return fmt.Errorf("registry is nil")
	}

	ec.logger.Info("Updating metrics from enhanced collector",
		zap.Int("collectors_count", collectorsCount),
		zap.Bool("registry_is_nil", registry == nil))

	metricFamilies, err := registry.Gather()
	if err != nil {
		ec.logger.Warn("Failed to gather metrics from registry",
			zap.Error(err))
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	ec.logger.Info("Gathered metrics from enhanced collector",
		zap.Int("metric_families_count", len(metricFamilies)),
		zap.Int("collectors_count", collectorsCount))

	// 转换为 domain.SystemMetrics
	metrics := ec.convertPrometheusMetrics(metricFamilies)

	ec.mu.Lock()
	ec.systemMetrics = metrics
	ec.mu.Unlock()

	return nil
}

// convertPrometheusMetrics 将 Prometheus 指标转换为 domain.SystemMetrics
func (ec *EnhancedMetricsCollector) convertPrometheusMetrics(
	families []*dto.MetricFamily,
) *domain.SystemMetrics {
	metrics := &domain.SystemMetrics{
		LastUpdated: time.Now(),
	}

	// 解析各种指标
	for _, family := range families {
		switch family.GetName() {
		case "node_cpu_seconds_total":
			metrics.CPUUsage = ec.parseCPUUsage(family)
		case "node_memory_MemTotal_bytes":
			if len(family.Metric) > 0 && family.Metric[0].Gauge != nil && family.Metric[0].Gauge.Value != nil {
				metrics.MemoryTotal = int64(*family.Metric[0].Gauge.Value)
			}
		case "node_memory_MemAvailable_bytes":
			if len(family.Metric) > 0 && family.Metric[0].Gauge != nil && family.Metric[0].Gauge.Value != nil {
				metrics.MemoryFree = int64(*family.Metric[0].Gauge.Value)
			}
		case "node_memory_MemFree_bytes":
			if len(family.Metric) > 0 && metrics.MemoryFree == 0 && family.Metric[0].Gauge != nil && family.Metric[0].Gauge.Value != nil {
				metrics.MemoryFree = int64(*family.Metric[0].Gauge.Value)
			}
		case "node_filesystem_size_bytes":
			// 获取根分区的磁盘大小
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.Name != nil && *label.Name == "mountpoint" && label.Value != nil && *label.Value == "/" {
						if metric.Gauge != nil && metric.Gauge.Value != nil {
							metrics.DiskTotal = int64(*metric.Gauge.Value)
						}
						break
					}
				}
			}
		case "node_filesystem_avail_bytes":
			// 获取根分区的可用空间
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.Name != nil && *label.Name == "mountpoint" && label.Value != nil && *label.Value == "/" {
						if metric.Gauge != nil && metric.Gauge.Value != nil {
							metrics.DiskFree = int64(*metric.Gauge.Value)
						}
						break
					}
				}
			}
		case "node_network_receive_bytes_total":
			// 累计所有网络接口的接收字节数
			for _, metric := range family.Metric {
				// 跳过回环接口
				isLoopback := false
				var devName string
				var rxBytes int64
				for _, label := range metric.Label {
					if label.Name != nil && *label.Name == "device" && label.Value != nil {
						devName = *label.Value
						if devName == "lo" || devName == "loopback" {
							isLoopback = true
							break
						}
					}
				}
				if metric.Counter != nil && metric.Counter.Value != nil {
					rxBytes = int64(*metric.Counter.Value)
				}
				if !isLoopback && devName != "" {
					// 记录每个接口的信息
					metrics.NetworkInterfaces = append(metrics.NetworkInterfaces, domain.NetworkInterface{
						Name:    devName,
						RxBytes: rxBytes,
					})
					metrics.NetworkIn += rxBytes
				}
			}
		case "node_network_transmit_bytes_total":
			// 累计所有网络接口的发送字节数
			for _, metric := range family.Metric {
				// 跳过回环接口
				isLoopback := false
				var devName string
				var txBytes int64
				for _, label := range metric.Label {
					if label.Name != nil && *label.Name == "device" && label.Value != nil {
						devName = *label.Value
						if devName == "lo" || devName == "loopback" {
							isLoopback = true
							break
						}
					}
				}
				if metric.Counter != nil && metric.Counter.Value != nil {
					txBytes = int64(*metric.Counter.Value)
				}
				if !isLoopback && devName != "" {
					// 更新对应接口的发送字节数
					found := false
					for i := range metrics.NetworkInterfaces {
						if metrics.NetworkInterfaces[i].Name == devName {
							metrics.NetworkInterfaces[i].TxBytes = txBytes
							found = true
							break
						}
					}
					if !found {
						metrics.NetworkInterfaces = append(metrics.NetworkInterfaces, domain.NetworkInterface{
							Name:    devName,
							TxBytes: txBytes,
						})
					}
					metrics.NetworkOut += txBytes
				}
			}
		case "node_load1":
			if len(family.Metric) > 0 && family.Metric[0].Gauge != nil && family.Metric[0].Gauge.Value != nil {
				metrics.LoadAvg1 = *family.Metric[0].Gauge.Value
			}
		case "node_load5":
			if len(family.Metric) > 0 && family.Metric[0].Gauge != nil && family.Metric[0].Gauge.Value != nil {
				metrics.LoadAvg5 = *family.Metric[0].Gauge.Value
			}
		case "node_load15":
			if len(family.Metric) > 0 && family.Metric[0].Gauge != nil && family.Metric[0].Gauge.Value != nil {
				metrics.LoadAvg15 = *family.Metric[0].Gauge.Value
			}
		}
	}

	// 计算派生指标
	if metrics.MemoryTotal > 0 {
		metrics.MemoryUsage = float64(metrics.MemoryTotal-metrics.MemoryFree) /
			float64(metrics.MemoryTotal) * 100
	}
	if metrics.DiskTotal > 0 {
		metrics.DiskUsage = float64(metrics.DiskTotal-metrics.DiskFree) /
			float64(metrics.DiskTotal) * 100
	}

	// 获取 CPU 核心数（从 node_cpu_seconds_total 的标签中获取）
	if len(metrics.NetworkInterfaces) == 0 {
		// 如果没有从网络指标中获取到接口信息，尝试从其他指标获取
		// 这里可以添加更多逻辑
	}

	return metrics
}

// parseCPUUsage 解析 CPU 使用率
// node_cpu_seconds_total 是一个 Counter，需要计算 idle 和 total 的差值
func (ec *EnhancedMetricsCollector) parseCPUUsage(family *dto.MetricFamily) float64 {
	var totalSeconds, idleSeconds float64

	for _, metric := range family.Metric {
		var mode string
		for _, label := range metric.Label {
			if label.Name != nil && *label.Name == "mode" {
				if label.Value != nil {
					mode = *label.Value
				}
			}
		}

		var value float64
		if metric.Counter != nil && metric.Counter.Value != nil {
			value = *metric.Counter.Value
		}
		totalSeconds += value

		if mode == "idle" {
			idleSeconds += value
		}
	}

	if totalSeconds == 0 {
		return 0.0
	}

	// CPU 使用率 = (总时间 - 空闲时间) / 总时间 * 100
	cpuUsage := (totalSeconds - idleSeconds) / totalSeconds * 100
	return cpuUsage
}

// CollectSystemMetrics 收集系统指标
func (ec *EnhancedMetricsCollector) CollectSystemMetrics(ctx context.Context) (*domain.SystemMetrics, error) {
	// 更新指标
	if err := ec.UpdateMetrics(ctx); err != nil {
		return nil, err
	}

	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.systemMetrics, nil
}

// GetSystemMetrics 获取系统指标
func (ec *EnhancedMetricsCollector) GetSystemMetrics() *domain.SystemMetrics {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.systemMetrics
}

// GetPrometheusRegistry 获取 Prometheus Registry（用于导出指标）
func (ec *EnhancedMetricsCollector) GetPrometheusRegistry() *prometheus.Registry {
	if ec == nil {
		return nil
	}
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.registry
}

// collectorAdapter 适配器，将 node_exporter 的 Collector 适配为 prometheus.Collector
type collectorAdapter struct {
	collector       collector.Collector
	name            string
	desc            *prometheus.Desc
	logger          *zap.Logger
	updateInterval  time.Duration            // 更新间隔
	lastUpdateTime  time.Time                // 上次更新时间
	cachedMetrics   []prometheus.Metric      // 缓存的指标
	cacheMu         sync.RWMutex             // 缓存锁
	strategyManager StrategyManagerInterface // 策略管理器（用于获取更新间隔）
}

// collectorNameToMetricPrefix collector 名称到指标前缀的映射
var collectorNameToMetricPrefix = map[string]string{
	"cpu":         "node_cpu",
	"meminfo":     "node_memory",
	"loadavg":     "node_load",
	"filesystem":  "node_filesystem",
	"netdev":      "node_network",
	"diskstats":   "node_disk",
	"stat":        "node_stat",
	"time":        "node_time",
	"uname":       "node_uname",
	"vmstat":      "node_vmstat",
	"textfile":    "node_textfile",
	"systemd":     "node_systemd",
	"interrupts":  "node_interrupts",
	"softirqs":    "node_softirqs",
	"pressure":    "node_pressure",
	"ksmd":        "node_ksmd",
	"entropy":     "node_entropy",
	"hwmon":       "node_hwmon",
	"thermalzone": "node_thermal",
	"swap":        "node_swap",
	"os":          "node_os",
	// 添加更多映射...
}

// Describe 实现 prometheus.Collector 接口
func (a *collectorAdapter) Describe(ch chan<- *prometheus.Desc) {
	// node_exporter collectors 不实现 Describe 方法
	// 根据 Prometheus 文档：
	// "Sending no descriptor at all marks the Collector as 'unchecked',
	//  i.e. no checks will be performed at registration time, and the
	//  Collector may yield any Metric it sees fit in its Collect method."
	//
	// 因此，我们不发送任何描述符，让 Prometheus 将 collector 标记为 "unchecked"
	// 这样 Prometheus 就会调用 Collect 方法，让 collector 自己发送实际的指标
	//
	// 这是 node_exporter collectors 的正确使用方式，因为它们不实现 Describe
}

// containsAny 检查字符串是否包含任何子字符串
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}

// Collect 实现 prometheus.Collector 接口
// 根据策略配置的更新间隔，决定是使用缓存数据还是更新数据
func (a *collectorAdapter) Collect(ch chan<- prometheus.Metric) {
	currentTime := time.Now()
	shouldUpdate := false

	// 检查是否需要更新
	a.cacheMu.RLock()
	hasCache := len(a.cachedMetrics) > 0
	lastUpdate := a.lastUpdateTime
	interval := a.updateInterval
	a.cacheMu.RUnlock()

	if !hasCache {
		// 没有缓存，需要更新
		shouldUpdate = true
		if a.logger != nil {
			a.logger.Debug("Collector has no cache, updating",
				zap.String("collector", a.name))
		}
	} else {
		// 检查是否到了更新间隔
		elapsed := currentTime.Sub(lastUpdate)
		if elapsed >= interval {
			shouldUpdate = true
			if a.logger != nil {
				a.logger.Debug("Collector update interval reached, updating",
					zap.String("collector", a.name),
					zap.Duration("elapsed", elapsed),
					zap.Duration("interval", interval))
			}
		} else {
			// 使用缓存数据
			if a.logger != nil {
				a.logger.Debug("Collector using cached data",
					zap.String("collector", a.name),
					zap.Duration("elapsed", elapsed),
					zap.Duration("interval", interval),
					zap.Int("cached_count", len(a.cachedMetrics)))
			}
		}
	}

	if shouldUpdate {
		// 需要更新，调用 collector 的 Update 方法
		metricChan := make(chan prometheus.Metric, 1000)
		done := make(chan error, 1)
		var newMetrics []prometheus.Metric

		// 在 goroutine 中调用 Update
		go func() {
			defer close(metricChan)
			err := a.collector.Update(metricChan)
			done <- err
		}()

		// 收集指标并转发到输出 channel
		for metric := range metricChan {
			// 注意：prometheus.Metric 接口的实现（如 prometheus.MustNewConstMetric）通常是不可变的
			// 可以安全地缓存。但为了确保安全，我们使用 dto.Metric 来存储数据
			newMetrics = append(newMetrics, metric)
			ch <- metric
		}

		// 等待 Update 完成
		if err := <-done; err != nil {
			if a.logger != nil {
				a.logger.Warn("Collector Update failed",
					zap.String("collector", a.name),
					zap.Error(err))
			}
			// 如果更新失败，尝试使用旧缓存
			if hasCache {
				a.cacheMu.RLock()
				for _, metric := range a.cachedMetrics {
					ch <- metric
				}
				a.cacheMu.RUnlock()
				if a.logger != nil {
					a.logger.Info("Using cached data after update failure",
						zap.String("collector", a.name))
				}
			}
		} else {
			// 更新成功，更新缓存
			// 注意：我们直接缓存 prometheus.Metric，因为标准实现（如 MustNewConstMetric）是不可变的
			a.cacheMu.Lock()
			a.cachedMetrics = make([]prometheus.Metric, len(newMetrics))
			copy(a.cachedMetrics, newMetrics)
			a.lastUpdateTime = currentTime
			a.cacheMu.Unlock()

			if a.logger != nil && len(newMetrics) > 0 {
				a.logger.Info("Collector collected metrics",
					zap.String("collector", a.name),
					zap.Int("count", len(newMetrics)),
					zap.Duration("interval", interval))
			} else if a.logger != nil && len(newMetrics) == 0 {
				a.logger.Warn("Collector produced no metrics",
					zap.String("collector", a.name))
			}
		}
	} else {
		// 使用缓存数据
		a.cacheMu.RLock()
		for _, metric := range a.cachedMetrics {
			ch <- metric
		}
		cachedCount := len(a.cachedMetrics)
		a.cacheMu.RUnlock()

		if a.logger != nil {
			a.logger.Debug("Collector returned cached metrics",
				zap.String("collector", a.name),
				zap.Int("count", cachedCount))
		}
	}
}

// GetConfig 获取当前配置
func (ec *EnhancedMetricsCollector) GetConfig() EnhancedCollectorConfig {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.currentConfig
}

// GetEnabledCollectors 获取当前启用的 collectors 列表
func (ec *EnhancedMetricsCollector) GetEnabledCollectors() []string {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	collectors := make([]string, 0, len(ec.collectors))
	for name := range ec.collectors {
		collectors = append(collectors, name)
	}
	// 排序以便于查看
	sort.Strings(collectors)
	return collectors
}
