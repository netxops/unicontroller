package metrics

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// ConfigStatus 配置状态
type ConfigStatus struct {
	Status       string    `json:"status"`        // active, pending, failed
	Version      string    `json:"version"`       // 配置版本号
	LastSync     time.Time `json:"last_sync"`    // 最后同步时间
	ErrorMessage string    `json:"error_message,omitempty"` // 错误信息
}

// ConfigStatusManager 配置状态管理器
type ConfigStatusManager struct {
	currentVersion int64
	lastApplied    time.Time
	status         string
	errorMessage   string
	mu             sync.RWMutex
	logger         *zap.Logger
}

// NewConfigStatusManager 创建配置状态管理器
func NewConfigStatusManager(logger *zap.Logger) *ConfigStatusManager {
	return &ConfigStatusManager{
		currentVersion: 0,
		lastApplied:     time.Now(),
		status:         "active",
		logger:          logger,
	}
}

// UpdateStatus 更新状态
func (csm *ConfigStatusManager) UpdateStatus(version int64, status string, err error) {
	csm.mu.Lock()
	defer csm.mu.Unlock()

	csm.currentVersion = version
	csm.lastApplied = time.Now()
	csm.status = status
	if err != nil {
		csm.errorMessage = err.Error()
	} else {
		csm.errorMessage = ""
	}

	csm.logger.Info("Config status updated",
		zap.Int64("version", version),
		zap.String("status", status),
		zap.Error(err))
}

// GetStatus 获取状态
func (csm *ConfigStatusManager) GetStatus() ConfigStatus {
	csm.mu.RLock()
	defer csm.mu.RUnlock()

	return ConfigStatus{
		Status:       csm.status,
		Version:      csm.getVersionString(),
		LastSync:     csm.lastApplied,
		ErrorMessage: csm.errorMessage,
	}
}

// getVersionString 获取版本字符串
func (csm *ConfigStatusManager) getVersionString() string {
	if csm.currentVersion == 0 {
		return "0"
	}
	return time.Unix(csm.currentVersion, 0).Format("20060102150405")
}

// GetCurrentVersion 获取当前版本
func (csm *ConfigStatusManager) GetCurrentVersion() int64 {
	csm.mu.RLock()
	defer csm.mu.RUnlock()
	return csm.currentVersion
}

