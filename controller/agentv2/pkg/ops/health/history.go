package health

import (
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

// HealthHistory 健康检查历史记录
type HealthHistory struct {
	mu      sync.RWMutex
	entries map[string][]*HealthHistoryEntry // serviceID -> entries
	maxSize int                              // 每个服务保留的最大记录数
}

// HealthHistoryEntry 健康检查历史记录条目
type HealthHistoryEntry struct {
	Status       domain.HealthStatus
	Message      string
	Timestamp    time.Time
	CheckType    string
	ResponseTime time.Duration
	Error        error
}

// NewHealthHistory 创建健康检查历史记录管理器
func NewHealthHistory(maxSize int) *HealthHistory {
	if maxSize <= 0 {
		maxSize = 1000 // 默认保留 1000 条记录
	}
	return &HealthHistory{
		entries: make(map[string][]*HealthHistoryEntry),
		maxSize: maxSize,
	}
}

// Add 添加健康检查历史记录
func (h *HealthHistory) Add(serviceID string, result *domain.CheckResult, checkType string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	status := domain.HealthStatusUnhealthy
	if result.Healthy {
		status = domain.HealthStatusHealthy
	}

	entry := &HealthHistoryEntry{
		Status:       status,
		Message:      result.Message,
		Timestamp:    result.Timestamp,
		CheckType:    checkType,
		ResponseTime: result.ResponseTime,
		Error:        result.Error,
	}

	entries := h.entries[serviceID]
	entries = append(entries, entry)

	// 限制记录数量
	if len(entries) > h.maxSize {
		entries = entries[len(entries)-h.maxSize:]
	}

	h.entries[serviceID] = entries
}

// Get 获取健康检查历史记录
func (h *HealthHistory) Get(serviceID string, limit int) []*HealthHistoryEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()

	entries := h.entries[serviceID]
	if len(entries) == 0 {
		return []*HealthHistoryEntry{}
	}

	// 返回最新的记录
	start := len(entries) - limit
	if start < 0 {
		start = 0
	}

	result := make([]*HealthHistoryEntry, len(entries)-start)
	copy(result, entries[start:])

	// 反转顺序，最新的在前
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// Clear 清除指定服务的历史记录
func (h *HealthHistory) Clear(serviceID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.entries, serviceID)
}

// GetAll 获取所有服务的历史记录
func (h *HealthHistory) GetAll() map[string][]*HealthHistoryEntry {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make(map[string][]*HealthHistoryEntry)
	for serviceID, entries := range h.entries {
		result[serviceID] = entries
	}
	return result
}
