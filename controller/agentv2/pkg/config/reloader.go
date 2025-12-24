package config

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// ConfigReloader 配置热重载器接口
type ConfigReloader interface {
	Start(ctx context.Context) error
	Stop() error
	OnReload(callback func(*Config) error)
}

// ConfigChangeHandler 配置变更处理器
type ConfigChangeHandler interface {
	OnConfigChange(newConfig *Config) error
}

// configReloader 配置热重载器实现
type configReloader struct {
	configPath string
	logger     *zap.Logger
	watcher    *fsnotify.Watcher
	callbacks  []func(*Config) error
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	debounce   time.Duration // 防抖延迟，避免频繁触发
	lastReload time.Time
}

// NewConfigReloader 创建配置热重载器
func NewConfigReloader(configPath string, logger *zap.Logger) (ConfigReloader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &configReloader{
		configPath: configPath,
		logger:     logger,
		watcher:    watcher,
		callbacks:  make([]func(*Config) error, 0),
		ctx:        ctx,
		cancel:     cancel,
		debounce:   2 * time.Second, // 默认 2 秒防抖
	}, nil
}

// Start 启动配置热重载
func (r *configReloader) Start(ctx context.Context) error {
	// 合并上下文
	r.ctx, r.cancel = context.WithCancel(ctx)

	// 获取配置文件所在目录
	configDir := filepath.Dir(r.configPath)
	if !filepath.IsAbs(configDir) {
		absPath, err := filepath.Abs(configDir)
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %w", err)
		}
		configDir = absPath
	}

	// 监听配置文件目录
	if err := r.watcher.Add(configDir); err != nil {
		return fmt.Errorf("failed to watch config directory: %w", err)
	}

	r.logger.Info("Config reloader started",
		zap.String("config_path", r.configPath),
		zap.String("config_dir", configDir))

	r.wg.Add(1)
	go r.watchLoop()

	return nil
}

// Stop 停止配置热重载
func (r *configReloader) Stop() error {
	if r.cancel != nil {
		r.cancel()
	}

	if r.watcher != nil {
		if err := r.watcher.Close(); err != nil {
			r.logger.Error("Failed to close file watcher", zap.Error(err))
		}
	}

	r.wg.Wait()
	r.logger.Info("Config reloader stopped")
	return nil
}

// OnReload 注册配置重载回调
func (r *configReloader) OnReload(callback func(*Config) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callbacks = append(r.callbacks, callback)
}

// watchLoop 监听循环
func (r *configReloader) watchLoop() {
	defer r.wg.Done()

	for {
		select {
		case <-r.ctx.Done():
			return
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			r.handleEvent(event)
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			r.logger.Error("File watcher error", zap.Error(err))
		}
	}
}

// handleEvent 处理文件事件
func (r *configReloader) handleEvent(event fsnotify.Event) {
	// 只处理配置文件的变化
	if event.Name != r.configPath {
		return
	}

	// 只处理写入和创建事件
	if event.Op&fsnotify.Write == 0 && event.Op&fsnotify.Create == 0 {
		return
	}

	// 防抖：避免频繁触发
	now := time.Now()
	if now.Sub(r.lastReload) < r.debounce {
		r.logger.Debug("Config change event ignored (debounce)",
			zap.String("event", event.Op.String()),
			zap.Duration("since_last_reload", now.Sub(r.lastReload)))
		return
	}

	r.logger.Info("Config file changed, reloading",
		zap.String("config_path", r.configPath),
		zap.String("event", event.Op.String()))

	// 延迟一下，确保文件写入完成
	time.Sleep(500 * time.Millisecond)

	// 重新加载配置
	if err := r.reload(); err != nil {
		r.logger.Error("Failed to reload config",
			zap.String("config_path", r.configPath),
			zap.Error(err))
		return
	}

	r.lastReload = now
}

// reload 重新加载配置
func (r *configReloader) reload() error {
	// 重新加载配置文件
	newConfig, err := Load(r.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// 验证配置
	if err := validate(newConfig); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	r.logger.Info("Config reloaded successfully",
		zap.String("config_path", r.configPath))

	// 调用所有注册的回调
	r.mu.RLock()
	callbacks := make([]func(*Config) error, len(r.callbacks))
	copy(callbacks, r.callbacks)
	r.mu.RUnlock()

	for i, callback := range callbacks {
		if err := callback(newConfig); err != nil {
			r.logger.Error("Config reload callback failed",
				zap.Int("callback_index", i),
				zap.Error(err))
			// 继续执行其他回调，不因为一个失败而停止
		}
	}

	return nil
}
