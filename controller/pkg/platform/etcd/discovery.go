package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/platform/models"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// ControllerDiscovery Controller 发现服务
type ControllerDiscovery struct {
	client             *clientv3.Client
	watchPrefix        string
	controllers        map[string]*models.Controller // area/controller_id -> Controller
	mu                 sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
	onControllerUpdate func(*models.Controller) // Controller 更新回调
	onControllerDelete func(string)             // Controller 删除回调
}

// ControllerInfo Controller 在 etcd 中的注册信息结构
type ControllerInfo struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Area      string    `json:"area"`
	StartTime time.Time `json:"start_time"`
	Version   string    `json:"version"`
}

// NewControllerDiscovery 创建 Controller 发现服务
func NewControllerDiscovery(client *clientv3.Client, watchPrefix string) *ControllerDiscovery {
	ctx, cancel := context.WithCancel(context.Background())
	return &ControllerDiscovery{
		client:      client,
		watchPrefix: watchPrefix,
		controllers: make(map[string]*models.Controller),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// SetOnControllerUpdate 设置 Controller 更新回调
func (cd *ControllerDiscovery) SetOnControllerUpdate(fn func(*models.Controller)) {
	cd.onControllerUpdate = fn
}

// SetOnControllerDelete 设置 Controller 删除回调
func (cd *ControllerDiscovery) SetOnControllerDelete(fn func(string)) {
	cd.onControllerDelete = fn
}

// Start 启动 Controller 发现服务
func (cd *ControllerDiscovery) Start() error {
	// 先进行一次全量同步
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cd.SyncControllers(ctx); err != nil {
		xlog.Warn("Failed to initial sync controllers", xlog.FieldErr(err))
	}

	// 启动 Watch
	go cd.WatchControllers()

	// 启动定期同步
	go cd.PeriodicSync()

	return nil
}

// Stop 停止 Controller 发现服务
func (cd *ControllerDiscovery) Stop() {
	cd.cancel()
}

// SyncControllers 从 etcd 同步所有 Controller
func (cd *ControllerDiscovery) SyncControllers(ctx context.Context) error {
	resp, err := cd.client.Get(ctx, cd.watchPrefix, clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("failed to get controllers from etcd: %w", err)
	}

	cd.mu.Lock()
	defer cd.mu.Unlock()

	// 记录当前 etcd 中的 Controller
	currentKeys := make(map[string]bool)
	for _, kv := range resp.Kvs {
		key := string(kv.Key)
		currentKeys[key] = true

		controller, err := cd.parseControllerFromKeyValue(kv.Key, kv.Value)
		if err != nil {
			xlog.Warn("Failed to parse controller", xlog.String("key", key), xlog.FieldErr(err))
			continue
		}

		// 更新或添加 Controller
		controllerKey := cd.getControllerKey(controller.Area, controller.ID)
		oldController, exists := cd.controllers[controllerKey]
		if !exists || oldController.LastHeartbeat.Before(controller.LastHeartbeat) {
			controller.UpdatedAt = time.Now()
			cd.controllers[controllerKey] = controller
			if cd.onControllerUpdate != nil {
				cd.onControllerUpdate(controller)
			}
		}
	}

	// 删除 etcd 中不存在的 Controller
	for key, controller := range cd.controllers {
		if !currentKeys[cd.getEtcdKey(controller.Area, controller.ID)] {
			delete(cd.controllers, key)
			if cd.onControllerDelete != nil {
				cd.onControllerDelete(key)
			}
		}
	}

	return nil
}

// WatchControllers 监听 etcd 中的 Controller 变化
func (cd *ControllerDiscovery) WatchControllers() {
	watcher := cd.client.Watch(cd.ctx, cd.watchPrefix, clientv3.WithPrefix())

	for {
		select {
		case <-cd.ctx.Done():
			return
		case resp := <-watcher:
			if resp.Err() != nil {
				xlog.Error("Watch controllers error", xlog.FieldErr(resp.Err()))
				continue
			}

			for _, event := range resp.Events {
				cd.handleEvent(event)
			}
		}
	}
}

// handleEvent 处理 etcd 事件
func (cd *ControllerDiscovery) handleEvent(event *clientv3.Event) {
	key := string(event.Kv.Key)

	switch event.Type {
	case clientv3.EventTypePut:
		// Controller 注册或更新
		controller, err := cd.parseControllerFromKeyValue(event.Kv.Key, event.Kv.Value)
		if err != nil {
			xlog.Warn("Failed to parse controller from event", xlog.String("key", key), xlog.FieldErr(err))
			return
		}

		cd.mu.Lock()
		controllerKey := cd.getControllerKey(controller.Area, controller.ID)
		controller.UpdatedAt = time.Now()
		cd.controllers[controllerKey] = controller
		cd.mu.Unlock()

		if cd.onControllerUpdate != nil {
			cd.onControllerUpdate(controller)
		}

		xlog.Info("Controller registered/updated", xlog.String("area", controller.Area), xlog.String("id", controller.ID))

	case clientv3.EventTypeDelete:
		// Controller 删除
		area, id := cd.extractAreaAndIDFromKey(key)
		if area != "" && id != "" {
			cd.mu.Lock()
			controllerKey := cd.getControllerKey(area, id)
			delete(cd.controllers, controllerKey)
			cd.mu.Unlock()

			if cd.onControllerDelete != nil {
				cd.onControllerDelete(controllerKey)
			}

			xlog.Info("Controller deleted", xlog.String("area", area), xlog.String("id", id))
		}
	}
}

// PeriodicSync 定期同步 Controller 列表
func (cd *ControllerDiscovery) PeriodicSync() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-cd.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := cd.SyncControllers(ctx); err != nil {
				xlog.Warn("Periodic sync controllers failed", xlog.FieldErr(err))
			}
			cancel()
		}
	}
}

// GetController 获取指定区域的 Controller
func (cd *ControllerDiscovery) GetController(area, controllerID string) (*models.Controller, error) {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	key := cd.getControllerKey(area, controllerID)
	controller, exists := cd.controllers[key]
	if !exists {
		return nil, fmt.Errorf("controller not found: area=%s, id=%s", area, controllerID)
	}

	return controller, nil
}

// GetControllerByArea 获取指定区域的 Controller（返回第一个）
func (cd *ControllerDiscovery) GetControllerByArea(area string) (*models.Controller, error) {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	for _, controller := range cd.controllers {
		if controller.Area == area && controller.Status == models.ControllerStatusOnline {
			return controller, nil
		}
	}

	return nil, fmt.Errorf("no online controller found for area: %s", area)
}

// ListControllers 列出所有 Controller
func (cd *ControllerDiscovery) ListControllers() []*models.Controller {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	controllers := make([]*models.Controller, 0, len(cd.controllers))
	for _, controller := range cd.controllers {
		controllers = append(controllers, controller)
	}

	return controllers
}

// ListControllersByArea 列出指定区域的所有 Controller
func (cd *ControllerDiscovery) ListControllersByArea(area string) []*models.Controller {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	controllers := make([]*models.Controller, 0)
	for _, controller := range cd.controllers {
		if controller.Area == area {
			controllers = append(controllers, controller)
		}
	}

	return controllers
}

// parseControllerFromKeyValue 从 etcd key-value 解析 Controller 信息
func (cd *ControllerDiscovery) parseControllerFromKeyValue(key, value []byte) (*models.Controller, error) {
	var info ControllerInfo
	if err := json.Unmarshal(value, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal controller info: %w", err)
	}

	area, id := cd.extractAreaAndIDFromKey(string(key))
	if area == "" || id == "" {
		return nil, fmt.Errorf("invalid controller key format: %s", string(key))
	}

	// 检查 Controller 是否在线（基于最后心跳时间）
	status := models.ControllerStatusOnline
	lastHeartbeat := time.Now()
	// 如果超过 90 秒没有更新，认为离线
	if time.Since(lastHeartbeat) > 90*time.Second {
		status = models.ControllerStatusOffline
	}

	controller := &models.Controller{
		ID:            id,
		Area:          area,
		Address:       info.Address,
		Status:        status,
		Version:       info.Version,
		StartTime:     info.StartTime,
		LastHeartbeat: lastHeartbeat,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Metadata:      make(map[string]interface{}),
	}

	return controller, nil
}

// extractAreaAndIDFromKey 从 etcd key 中提取 area 和 controller ID
// key 格式: controllers/{area}/{controller_id}
func (cd *ControllerDiscovery) extractAreaAndIDFromKey(key string) (area, id string) {
	// 移除前缀
	key = strings.TrimPrefix(key, cd.watchPrefix)
	key = strings.Trim(key, "/")

	parts := strings.Split(key, "/")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}

	return "", ""
}

// getControllerKey 生成 Controller 的内部 key
func (cd *ControllerDiscovery) getControllerKey(area, id string) string {
	return fmt.Sprintf("%s/%s", area, id)
}

// getEtcdKey 生成 etcd key
func (cd *ControllerDiscovery) getEtcdKey(area, id string) string {
	return fmt.Sprintf("%s/%s/%s", cd.watchPrefix, area, id)
}
