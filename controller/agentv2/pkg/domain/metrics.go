package domain

import (
	"time"
)

// ServiceMetrics 服务指标
type ServiceMetrics struct {
	CPUUsage    float64
	MemoryUsage float64
	MemoryBytes int64
	DiskUsage   float64
	NetworkIn   int64
	NetworkOut  int64
	RequestCount int64
	ErrorCount   int64
	ResponseTime time.Duration
	LastUpdated  time.Time
}

// NetworkInterface 网络接口信息
type NetworkInterface struct {
	Name    string
	RxBytes int64
	TxBytes int64
}

// SystemMetrics 系统指标
type SystemMetrics struct {
	CPUUsage         float64
	CPUCores         int
	MemoryUsage      float64
	MemoryTotal      int64
	MemoryFree       int64
	DiskUsage        float64
	DiskTotal        int64
	DiskFree         int64
	NetworkIn        int64 // 已废弃，使用 NetworkInterfaces
	NetworkOut       int64 // 已废弃，使用 NetworkInterfaces
	NetworkInterfaces []NetworkInterface
	LoadAvg1         float64
	LoadAvg5         float64
	LoadAvg15        float64
	LastUpdated      time.Time
}

// Update 更新服务指标
func (m *ServiceMetrics) Update(cpu, memory float64, memoryBytes int64) {
	m.CPUUsage = cpu
	m.MemoryUsage = memory
	m.MemoryBytes = memoryBytes
	m.LastUpdated = time.Now()
}

// Reset 重置指标
func (m *ServiceMetrics) Reset() {
	m.CPUUsage = 0
	m.MemoryUsage = 0
	m.MemoryBytes = 0
	m.NetworkIn = 0
	m.NetworkOut = 0
	m.RequestCount = 0
	m.ErrorCount = 0
	m.ResponseTime = 0
	m.LastUpdated = time.Now()
}

// ApplicationMetrics 应用指标（业务指标）
type ApplicationMetrics struct {
	ServiceName string
	Metrics     map[string]float64 // 指标名称 -> 指标值
	Labels      map[string]string  // 指标标签
	Timestamp   time.Time
}

