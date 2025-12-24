package metrics

import (
	"strconv"
	"strings"

	"github.com/influxdata/telegraf"
	dto "github.com/prometheus/client_model/go"
)

// convertTelegrafMetricToPrometheus 将 telegraf.Metric 转换为 Prometheus MetricFamily
func convertTelegrafMetricToPrometheus(m telegraf.Metric) []*dto.MetricFamily {
	name := m.Name()
	fields := m.Fields()
	tags := m.Tags()
	timestamp := m.Time().Unix() // 转换为 Unix 时间戳（秒）

	metricFamilies := make([]*dto.MetricFamily, 0)

	// 根据不同的 measurement 名称进行转换
	switch name {
	case "cpu":
		metricFamilies = convertCPUMetric(fields, tags, timestamp)
	case "mem":
		metricFamilies = convertMemoryMetric(fields, tags, timestamp)
	case "disk":
		metricFamilies = convertDiskMetric(fields, tags, timestamp)
	case "diskio":
		metricFamilies = convertDiskIOMetric(fields, tags, timestamp)
	case "net":
		metricFamilies = convertNetworkMetric(fields, tags, timestamp)
	case "system":
		metricFamilies = convertSystemMetric(fields, tags, timestamp)
	case "processes":
		metricFamilies = convertProcessesMetric(fields, tags, timestamp)
	case "swap":
		metricFamilies = convertSwapMetric(fields, tags, timestamp)
	default:
		// 通用转换：将字段转换为 Prometheus 指标
		metricFamilies = convertGenericMetric(name, fields, tags, timestamp)
	}

	return metricFamilies
}

// convertCPUMetric 转换 CPU 指标
func convertCPUMetric(fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	cpuTag := tags["cpu"]
	if cpuTag == "" {
		cpuTag = "cpu-total"
	}

	// node_cpu_seconds_total
	if cpuTime, ok := fields["time_user"].(float64); ok {
		family := createMetricFamily("node_cpu_seconds_total", dto.MetricType_COUNTER)
		metric := createMetric(cpuTime, timestamp)
		addLabel(metric, "cpu", cpuTag)
		addLabel(metric, "mode", "user")
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// CPU 使用率百分比
	if usagePercent, ok := fields["usage_percent"].(float64); ok {
		family := createMetricFamily("node_cpu_usage_percent", dto.MetricType_GAUGE)
		metric := createMetric(usagePercent, timestamp)
		addLabel(metric, "cpu", cpuTag)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// convertMemoryMetric 转换内存指标
func convertMemoryMetric(fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	// node_memory_MemTotal_bytes
	if total, ok := getUint64Value(fields["total"]); ok {
		family := createMetricFamily("node_memory_MemTotal_bytes", dto.MetricType_GAUGE)
		metric := createMetric(float64(total), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_memory_MemAvailable_bytes
	if available, ok := getUint64Value(fields["available"]); ok {
		family := createMetricFamily("node_memory_MemAvailable_bytes", dto.MetricType_GAUGE)
		metric := createMetric(float64(available), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_memory_MemFree_bytes
	if free, ok := getUint64Value(fields["free"]); ok {
		family := createMetricFamily("node_memory_MemFree_bytes", dto.MetricType_GAUGE)
		metric := createMetric(float64(free), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_memory_MemUsed_bytes
	if used, ok := getUint64Value(fields["used"]); ok {
		family := createMetricFamily("node_memory_MemUsed_bytes", dto.MetricType_GAUGE)
		metric := createMetric(float64(used), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// convertDiskMetric 转换磁盘指标
func convertDiskMetric(fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	device := tags["device"]
	path := tags["path"]
	fstype := tags["fstype"]

	// node_filesystem_size_bytes
	if total, ok := getUint64Value(fields["total"]); ok {
		family := createMetricFamily("node_filesystem_size_bytes", dto.MetricType_GAUGE)
		metric := createMetric(float64(total), timestamp)
		addLabel(metric, "device", device)
		addLabel(metric, "fstype", fstype)
		addLabel(metric, "mountpoint", path)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_filesystem_avail_bytes
	if free, ok := getUint64Value(fields["free"]); ok {
		family := createMetricFamily("node_filesystem_avail_bytes", dto.MetricType_GAUGE)
		metric := createMetric(float64(free), timestamp)
		addLabel(metric, "device", device)
		addLabel(metric, "fstype", fstype)
		addLabel(metric, "mountpoint", path)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_filesystem_files
	if inodes, ok := getUint64Value(fields["inodes"]); ok {
		family := createMetricFamily("node_filesystem_files", dto.MetricType_GAUGE)
		metric := createMetric(float64(inodes), timestamp)
		addLabel(metric, "device", device)
		addLabel(metric, "fstype", fstype)
		addLabel(metric, "mountpoint", path)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// convertDiskIOMetric 转换磁盘 I/O 指标
func convertDiskIOMetric(fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	name := tags["name"]

	// node_disk_read_bytes_total
	if readBytes, ok := getUint64Value(fields["read_bytes"]); ok {
		family := createMetricFamily("node_disk_read_bytes_total", dto.MetricType_COUNTER)
		metric := createMetric(float64(readBytes), timestamp)
		addLabel(metric, "device", name)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_disk_written_bytes_total
	if writeBytes, ok := getUint64Value(fields["write_bytes"]); ok {
		family := createMetricFamily("node_disk_written_bytes_total", dto.MetricType_COUNTER)
		metric := createMetric(float64(writeBytes), timestamp)
		addLabel(metric, "device", name)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_disk_reads_completed_total
	if reads, ok := getUint64Value(fields["reads"]); ok {
		family := createMetricFamily("node_disk_reads_completed_total", dto.MetricType_COUNTER)
		metric := createMetric(float64(reads), timestamp)
		addLabel(metric, "device", name)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_disk_writes_completed_total
	if writes, ok := getUint64Value(fields["writes"]); ok {
		family := createMetricFamily("node_disk_writes_completed_total", dto.MetricType_COUNTER)
		metric := createMetric(float64(writes), timestamp)
		addLabel(metric, "device", name)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// convertNetworkMetric 转换网络指标
func convertNetworkMetric(fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	interfaceName := tags["interface"]
	if interfaceName == "" {
		return families
	}

	// node_network_receive_bytes_total
	if bytesRecv, ok := getUint64Value(fields["bytes_recv"]); ok {
		family := createMetricFamily("node_network_receive_bytes_total", dto.MetricType_COUNTER)
		metric := createMetric(float64(bytesRecv), timestamp)
		addLabel(metric, "device", interfaceName)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_network_transmit_bytes_total
	if bytesSent, ok := getUint64Value(fields["bytes_sent"]); ok {
		family := createMetricFamily("node_network_transmit_bytes_total", dto.MetricType_COUNTER)
		metric := createMetric(float64(bytesSent), timestamp)
		addLabel(metric, "device", interfaceName)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_network_receive_packets_total
	if packetsRecv, ok := getUint64Value(fields["packets_recv"]); ok {
		family := createMetricFamily("node_network_receive_packets_total", dto.MetricType_COUNTER)
		metric := createMetric(float64(packetsRecv), timestamp)
		addLabel(metric, "device", interfaceName)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_network_transmit_packets_total
	if packetsSent, ok := getUint64Value(fields["packets_sent"]); ok {
		family := createMetricFamily("node_network_transmit_packets_total", dto.MetricType_COUNTER)
		metric := createMetric(float64(packetsSent), timestamp)
		addLabel(metric, "device", interfaceName)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// convertSystemMetric 转换系统指标
func convertSystemMetric(fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	// node_load1
	if load1, ok := getFloat64Value(fields["load1"]); ok {
		family := createMetricFamily("node_load1", dto.MetricType_GAUGE)
		metric := createMetric(load1, timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_load5
	if load5, ok := getFloat64Value(fields["load5"]); ok {
		family := createMetricFamily("node_load5", dto.MetricType_GAUGE)
		metric := createMetric(load5, timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_load15
	if load15, ok := getFloat64Value(fields["load15"]); ok {
		family := createMetricFamily("node_load15", dto.MetricType_GAUGE)
		metric := createMetric(load15, timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_procs_running
	if procsRunning, ok := getUint64Value(fields["procs_running"]); ok {
		family := createMetricFamily("node_procs_running", dto.MetricType_GAUGE)
		metric := createMetric(float64(procsRunning), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_procs_blocked
	if procsBlocked, ok := getUint64Value(fields["procs_blocked"]); ok {
		family := createMetricFamily("node_procs_blocked", dto.MetricType_GAUGE)
		metric := createMetric(float64(procsBlocked), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// convertProcessesMetric 转换进程指标
func convertProcessesMetric(fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	// node_procs_total
	if total, ok := getUint64Value(fields["total"]); ok {
		family := createMetricFamily("node_procs_total", dto.MetricType_GAUGE)
		metric := createMetric(float64(total), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// convertSwapMetric 转换交换分区指标
func convertSwapMetric(fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	// node_memory_SwapTotal_bytes
	if total, ok := getUint64Value(fields["total"]); ok {
		family := createMetricFamily("node_memory_SwapTotal_bytes", dto.MetricType_GAUGE)
		metric := createMetric(float64(total), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	// node_memory_SwapFree_bytes
	if free, ok := getUint64Value(fields["free"]); ok {
		family := createMetricFamily("node_memory_SwapFree_bytes", dto.MetricType_GAUGE)
		metric := createMetric(float64(free), timestamp)
		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// convertGenericMetric 通用转换函数
func convertGenericMetric(measurement string, fields map[string]interface{}, tags map[string]string, timestamp int64) []*dto.MetricFamily {
	families := make([]*dto.MetricFamily, 0)

	// 将 measurement 名称转换为 Prometheus 格式
	promName := "node_" + strings.ReplaceAll(measurement, "_", "_")

	for fieldName, fieldValue := range fields {
		metricName := promName + "_" + strings.ReplaceAll(fieldName, "_", "_")

		var value float64
		var ok bool
		if value, ok = getFloat64Value(fieldValue); !ok {
			continue
		}

		family := createMetricFamily(metricName, dto.MetricType_GAUGE)
		metric := createMetric(value, timestamp)

		// 添加标签
		for k, v := range tags {
			addLabel(metric, k, v)
		}

		family.Metric = append(family.Metric, metric)
		families = append(families, family)
	}

	return families
}

// 辅助函数

func createMetricFamily(name string, metricType dto.MetricType) *dto.MetricFamily {
	return &dto.MetricFamily{
		Name: &name,
		Type: &metricType,
	}
}

func createMetric(value float64, timestamp int64) *dto.Metric {
	ts := timestamp * 1000 // 转换为毫秒
	return &dto.Metric{
		Gauge: &dto.Gauge{
			Value: &value,
		},
		TimestampMs: &ts,
	}
}

func addLabel(metric *dto.Metric, name, value string) {
	if metric.Label == nil {
		metric.Label = make([]*dto.LabelPair, 0)
	}
	metric.Label = append(metric.Label, &dto.LabelPair{
		Name:  &name,
		Value: &value,
	})
}

func getUint64Value(v interface{}) (uint64, bool) {
	switch val := v.(type) {
	case uint64:
		return val, true
	case int64:
		if val >= 0 {
			return uint64(val), true
		}
	case int:
		if val >= 0 {
			return uint64(val), true
		}
	case float64:
		if val >= 0 {
			return uint64(val), true
		}
	case string:
		if parsed, err := strconv.ParseUint(val, 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func getFloat64Value(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int64:
		return float64(val), true
	case int:
		return float64(val), true
	case uint64:
		return float64(val), true
	case string:
		if parsed, err := strconv.ParseFloat(val, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}
