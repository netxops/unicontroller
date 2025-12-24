package metrics

import (
	"fmt"
	"runtime"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// collectSystemMetrics 收集系统指标
func collectSystemMetrics() (*domain.SystemMetrics, error) {
	metrics := &domain.SystemMetrics{
		LastUpdated: time.Now(),
	}

	// CPU 使用率和核心数
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU usage: %w", err)
	}
	if len(cpuPercent) > 0 {
		metrics.CPUUsage = cpuPercent[0]
	}

	// 获取 CPU 核心数
	cpuCount, err := cpu.Counts(true) // true 表示逻辑核心数
	if err == nil {
		metrics.CPUCores = cpuCount
	} else {
		// 降级方案：使用 runtime
		metrics.CPUCores = runtime.NumCPU()
	}

	// 内存使用率
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}
	metrics.MemoryUsage = memInfo.UsedPercent
	metrics.MemoryTotal = int64(memInfo.Total)
	metrics.MemoryFree = int64(memInfo.Available)

	// 磁盘使用率
	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk info: %w", err)
	}
	metrics.DiskUsage = diskInfo.UsedPercent
	metrics.DiskTotal = int64(diskInfo.Total)
	metrics.DiskFree = int64(diskInfo.Free)

	// 网络流量（获取所有接口的详细信息）
	netIO, err := net.IOCounters(true) // true 表示获取每个接口的统计
	if err != nil {
		return nil, fmt.Errorf("failed to get network IO: %w", err)
	}

	// 转换网络接口信息
	metrics.NetworkInterfaces = make([]domain.NetworkInterface, 0, len(netIO))
	var totalRx, totalTx int64
	for _, io := range netIO {
		// 跳过回环接口
		if io.Name == "lo" || io.Name == "loopback" {
			continue
		}
		metrics.NetworkInterfaces = append(metrics.NetworkInterfaces, domain.NetworkInterface{
			Name:    io.Name,
			RxBytes: int64(io.BytesRecv),
			TxBytes: int64(io.BytesSent),
		})
		totalRx += int64(io.BytesRecv)
		totalTx += int64(io.BytesSent)
	}

	// 保持向后兼容
	if len(netIO) > 0 {
		metrics.NetworkIn = totalRx
		metrics.NetworkOut = totalTx
	}

	// 负载平均值
	loadAvg, err := load.Avg()
	if err == nil {
		metrics.LoadAvg1 = loadAvg.Load1
		metrics.LoadAvg5 = loadAvg.Load5
		metrics.LoadAvg15 = loadAvg.Load15
	}

	return metrics, nil
}

// GetGoRuntimeMetrics 获取 Go 运行时指标
func GetGoRuntimeMetrics() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"go_routines":       runtime.NumGoroutine(),
		"go_heap_alloc":     m.HeapAlloc,
		"go_heap_sys":       m.HeapSys,
		"go_heap_objects":   m.HeapObjects,
		"go_gc_runs":        m.NumGC,
		"go_gc_pause_total": m.PauseTotalNs,
	}
}
