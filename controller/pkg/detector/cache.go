package detector

import (
	"sync"
	"time"
)

// DetectionCache 检测结果缓存
type DetectionCache struct {
	cache map[string]*CachedDetectionResult
	ttl   time.Duration
	mu    sync.RWMutex
}

// CachedDetectionResult 缓存的检测结果
type CachedDetectionResult struct {
	Result     *DetectionResult
	DetectedAt time.Time
	ExpiresAt  time.Time
}

// NewDetectionCache 创建检测缓存
func NewDetectionCache(ttl time.Duration) *DetectionCache {
	return &DetectionCache{
		cache: make(map[string]*CachedDetectionResult),
		ttl:   ttl,
	}
}

// Get 获取缓存的检测结果
func (dc *DetectionCache) Get(ip string) (*DetectionResult, bool) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	cached, exists := dc.cache[ip]
	if !exists {
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(cached.ExpiresAt) {
		// 异步删除过期项
		go func() {
			dc.mu.Lock()
			delete(dc.cache, ip)
			dc.mu.Unlock()
		}()
		return nil, false
	}

	return cached.Result, true
}

// Set 设置缓存的检测结果
func (dc *DetectionCache) Set(ip string, result *DetectionResult) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.cache[ip] = &CachedDetectionResult{
		Result:     result,
		DetectedAt: time.Now(),
		ExpiresAt:  time.Now().Add(dc.ttl),
	}
}

// Clear 清空缓存
func (dc *DetectionCache) Clear() {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.cache = make(map[string]*CachedDetectionResult)
}

// Remove 移除指定IP的缓存
func (dc *DetectionCache) Remove(ip string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	delete(dc.cache, ip)
}

// CleanExpired 清理过期的缓存项
func (dc *DetectionCache) CleanExpired() {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	now := time.Now()
	for ip, cached := range dc.cache {
		if now.After(cached.ExpiresAt) {
			delete(dc.cache, ip)
		}
	}
}

