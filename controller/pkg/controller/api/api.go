package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/nacos-group/nacos-sdk-go/v2/common/logger"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"

	"github.com/gorilla/mux"
	"github.com/influxdata/telegraf/controller/pkg/controller"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/influxdata/telegraf/controller/pkg/l3nodemap/model/meta"
	l3service "github.com/influxdata/telegraf/controller/pkg/l3nodemap/service"
	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"

	"github.com/influxdata/telegraf/controller/pkg/detector"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"
	agentStruct "github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/netlink/dispatch"
	"github.com/netxops/netlink/netdevice"
	ps "github.com/netxops/netlink/service"
	"github.com/netxops/netlink/structs"
	clitask "github.com/netxops/utils/task"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// TaskStatus 任务状态枚举
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"   // 等待执行
	TaskStatusRunning   TaskStatus = "running"   // 正在执行
	TaskStatusCompleted TaskStatus = "completed" // 执行成功
	TaskStatusFailed    TaskStatus = "failed"    // 执行失败
	TaskStatusTimeout   TaskStatus = "timeout"   // 执行超时
	TaskStatusCancelled TaskStatus = "cancelled" // 已取消
)

// ErrorType 错误类型枚举
type ErrorType string

const (
	ErrorTypeNone           ErrorType = "none"           // 无错误
	ErrorTypeNetwork        ErrorType = "network"        // 网络错误
	ErrorTypeAuthentication ErrorType = "authentication" // 认证错误
	ErrorTypeExecution      ErrorType = "execution"      // 执行错误
	ErrorTypeTimeout        ErrorType = "timeout"        // 超时错误
	ErrorTypeCancelled      ErrorType = "cancelled"      // 取消错误
	ErrorTypeUnknown        ErrorType = "unknown"        // 未知错误
)

// CommandResult 单个命令的执行结果
type CommandResult struct {
	Index      int       `json:"index"`               // 命令索引（从0开始）
	Command    string    `json:"command"`             // 执行的命令
	Stdout     string    `json:"stdout,omitempty"`    // 标准输出
	Stderr     string    `json:"stderr,omitempty"`    // 标准错误输出
	ExitCode   int       `json:"exit_code,omitempty"` // 退出码（如果可用）
	Success    bool      `json:"success"`             // 是否成功
	Error      string    `json:"error,omitempty"`     // 错误信息（如果有）
	Duration   int64     `json:"duration,omitempty"`  // 执行时长（毫秒）
	ExecutedAt time.Time `json:"executed_at"`         // 执行时间
}

// ExecutionResult 执行结果详情
type ExecutionResult struct {
	Stdout         string          `json:"stdout,omitempty"`          // 标准输出（合并后的输出，用于向后兼容）
	Stderr         string          `json:"stderr,omitempty"`          // 标准错误输出（合并后的输出，用于向后兼容）
	ExitCode       int             `json:"exit_code,omitempty"`       // 退出码（如果可用）
	OutputSize     int64           `json:"output_size"`               // 输出大小（字节）
	CommandResults []CommandResult `json:"command_results,omitempty"` // 每个命令的详细结果（多命令执行时使用）
}

// ErrorDetail 错误详情
type ErrorDetail struct {
	Type    ErrorType `json:"type"`              // 错误类型
	Code    string    `json:"code,omitempty"`    // 错误码
	Message string    `json:"message"`           // 错误消息
	Details string    `json:"details,omitempty"` // 详细错误信息（如堆栈等）
}

// TaskInfo 任务信息（保存请求信息，用于追溯）
type TaskInfo struct {
	ID           string    `json:"id" bson:"id"`                       // 任务ID
	ControllerID string    `json:"controller_id" bson:"controller_id"` // Controller实例ID（用于区分多实例）
	DeviceIP     string    `json:"device_ip" bson:"device_ip"`         // 设备IP
	DevicePort   int       `json:"device_port" bson:"device_port"`     // 设备端口
	Username     string    `json:"username" bson:"username"`           // 用户名
	CommandType  string    `json:"command_type" bson:"command_type"`   // 命令类型：commands/script/script_path
	Background   bool      `json:"background" bson:"background"`       // 是否后台执行
	Timeout      int       `json:"timeout" bson:"timeout"`             // 超时时间（秒）
	CreatedAt    time.Time `json:"created_at" bson:"created_at"`       // 任务创建时间
}

// AsyncTaskResult 异步任务结果
type AsyncTaskResult struct {
	// 基本信息
	Status   TaskStatus `json:"status"`    // 任务状态
	TaskInfo TaskInfo   `json:"task_info"` // 任务信息

	// 时间信息
	StartTime time.Time  `json:"start_time"`         // 开始时间
	EndTime   *time.Time `json:"end_time,omitempty"` // 结束时间
	Duration  *int64     `json:"duration,omitempty"` // 执行时长（毫秒）

	// 执行结果
	Result *ExecutionResult `json:"result,omitempty"` // 执行结果（仅成功时有）

	// 错误信息
	Error *ErrorDetail `json:"error,omitempty"` // 错误详情（仅失败时有）

	// 附加信息
	Message string `json:"message,omitempty"` // 状态消息（用于UI显示）
}

type AsyncExecuteCommandRequest struct {
	ID         string                     `json:"id"`                    // 任务ID（由客户端提供）
	RemoteInfo structs.L2DeviceRemoteInfo `json:"remote_info"`           // 设备连接信息
	Commands   []string                   `json:"commands,omitempty"`    // 命令列表（可选）
	Script     string                     `json:"script,omitempty"`      // 内联脚本（可选）
	ScriptPath string                     `json:"script_path,omitempty"` // 文件脚本路径（可选）
	Background bool                       `json:"background,omitempty"`  // 是否后台执行
	Timeout    int                        `json:"timeout,omitempty"`     // 超时时间（秒），默认60秒
}

// NodeMapCacheEntry NodeMap 缓存项
type NodeMapCacheEntry struct {
	NodeMap      *nodemap.NodeMap
	Context      context.Context
	ExpiresAt    time.Time // 过期时间
	LastAccessAt time.Time // 最后访问时间
	mu           sync.RWMutex
}

// IsExpired 检查是否已过期
func (e *NodeMapCacheEntry) IsExpired() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Now().After(e.ExpiresAt)
}

// Touch 更新最后访问时间并续期（滑动窗口）
func (e *NodeMapCacheEntry) Touch(ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	e.LastAccessAt = now
	e.ExpiresAt = now.Add(ttl)
}

// GetLastAccessAt 获取最后访问时间
func (e *NodeMapCacheEntry) GetLastAccessAt() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.LastAccessAt
}

type ControllerAPI struct {
	controller       *controller.Controller
	mongoClient      *mongo.Client
	controllerID     string
	asyncTasks       sync.Map      // map[string]*AsyncTaskResult (内存缓存，用于快速查询)
	nodeMapCache     sync.Map      // map[string]*NodeMapCacheEntry (NodeMap 缓存)
	nodeMapCacheTTL  time.Duration // NodeMap 缓存 TTL，默认 5 分钟
	cacheCleanupStop chan struct{} // 用于停止清理 goroutine
}

func NewControllerAPI(ctrl *controller.Controller, mongoClient *mongo.Client, controllerID string) *ControllerAPI {
	ap := &ControllerAPI{
		controller:       ctrl,
		mongoClient:      mongoClient,
		controllerID:     controllerID,
		nodeMapCacheTTL:  5 * time.Minute, // 默认 5 分钟 TTL
		cacheCleanupStop: make(chan struct{}),
	}

	// 初始化时创建 MongoDB 索引
	ap.ensureIndexes()

	// 启动缓存清理 goroutine
	go ap.startCacheCleanup()

	return ap
}

// startCacheCleanup 启动定期清理过期缓存的 goroutine
func (ap *ControllerAPI) startCacheCleanup() {
	ticker := time.NewTicker(1 * time.Minute) // 每分钟检查一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ap.cleanupExpiredCache()
		case <-ap.cacheCleanupStop:
			return
		}
	}
}

// cleanupExpiredCache 清理过期的缓存项
func (ap *ControllerAPI) cleanupExpiredCache() {
	now := time.Now()
	ap.nodeMapCache.Range(func(key, value interface{}) bool {
		entry := value.(*NodeMapCacheEntry)
		if now.After(entry.ExpiresAt) {
			ap.nodeMapCache.Delete(key)
			log.Printf("Cleaned up expired NodeMap cache: %s", key)
		}
		return true
	})
}

// cacheKeyDeviceConfig 用于缓存 key 生成的简化 DeviceConfig 结构
// 只包含影响 NodeMap 创建的字段，排除动态字段（如 MetaData）
type cacheKeyDeviceConfig struct {
	Host              string   `json:"host"`
	Mode              string   `json:"mode"`
	Port              int      `json:"port"`
	Config            string   `json:"config"`
	Ipv4Area          []string `json:"ipv4_area"`           // 简化为字符串列表，只包含关键信息
	Ipv6Area          []string `json:"ipv6_area"`           // 简化为字符串列表，只包含关键信息
	Ipv4SecurityZones []string `json:"ipv4_security_zones"` // 简化为字符串列表，只包含关键信息
	Ipv6SecurityZones []string `json:"ipv6_security_zones"` // 简化为字符串列表，只包含关键信息
}

// normalizeDeviceConfigForCache 将 DeviceConfig 转换为用于缓存 key 的简化结构
func normalizeDeviceConfigForCache(dc config.DeviceConfig) cacheKeyDeviceConfig {
	// 提取 Ipv4Area 的关键信息（Name + Interface）
	ipv4Areas := make([]string, 0, len(dc.Ipv4Area))
	for _, area := range dc.Ipv4Area {
		if area != nil {
			ipv4Areas = append(ipv4Areas, fmt.Sprintf("%s:%s", area.Name, area.Interface))
		}
	}
	sort.Strings(ipv4Areas)

	// 提取 Ipv6Area 的关键信息
	ipv6Areas := make([]string, 0, len(dc.Ipv6Area))
	for _, area := range dc.Ipv6Area {
		if area != nil {
			ipv6Areas = append(ipv6Areas, fmt.Sprintf("%s:%s", area.Name, area.Interface))
		}
	}
	sort.Strings(ipv6Areas)

	// 提取 Ipv4SecurityZones 的关键信息（ConfigZoneName + NetworkSegments）
	ipv4Zones := make([]string, 0, len(dc.Ipv4SecurityZones))
	for _, zone := range dc.Ipv4SecurityZones {
		if zone != nil {
			segments := make([]string, len(zone.NetworkSegments))
			copy(segments, zone.NetworkSegments)
			sort.Strings(segments)
			// 使用稳定的格式：ConfigZoneName|segment1,segment2,...
			zoneKey := zone.ConfigZoneName + "|" + strings.Join(segments, ",")
			ipv4Zones = append(ipv4Zones, zoneKey)
		}
	}
	sort.Strings(ipv4Zones)

	// 提取 Ipv6SecurityZones 的关键信息
	ipv6Zones := make([]string, 0, len(dc.Ipv6SecurityZones))
	for _, zone := range dc.Ipv6SecurityZones {
		if zone != nil {
			segments := make([]string, len(zone.NetworkSegments))
			copy(segments, zone.NetworkSegments)
			sort.Strings(segments)
			// 使用稳定的格式：ConfigZoneName|segment1,segment2,...
			zoneKey := zone.ConfigZoneName + "|" + strings.Join(segments, ",")
			ipv6Zones = append(ipv6Zones, zoneKey)
		}
	}
	sort.Strings(ipv6Zones)

	return cacheKeyDeviceConfig{
		Host:              dc.Host,
		Mode:              dc.Mode,
		Port:              dc.Port,
		Config:            dc.Config,
		Ipv4Area:          ipv4Areas,
		Ipv6Area:          ipv6Areas,
		Ipv4SecurityZones: ipv4Zones,
		Ipv6SecurityZones: ipv6Zones,
	}
}

// generateCacheKey 生成缓存 key（基于 deviceConfigs 和 templatePath）
func (ap *ControllerAPI) generateCacheKey(recordCode string, deviceConfigs []config.DeviceConfig, templatePath string) (string, error) {
	// 转换为缓存 key 结构（排除动态字段，排序所有 slice）
	cacheConfigs := make([]cacheKeyDeviceConfig, 0, len(deviceConfigs))
	for _, dc := range deviceConfigs {
		cacheConfigs = append(cacheConfigs, normalizeDeviceConfigForCache(dc))
	}

	// 按 Host、Mode、Port 排序，确保顺序一致
	sort.Slice(cacheConfigs, func(i, j int) bool {
		if cacheConfigs[i].Host != cacheConfigs[j].Host {
			return cacheConfigs[i].Host < cacheConfigs[j].Host
		}
		if cacheConfigs[i].Mode != cacheConfigs[j].Mode {
			return cacheConfigs[i].Mode < cacheConfigs[j].Mode
		}
		return cacheConfigs[i].Port < cacheConfigs[j].Port
	})

	// 创建一个包含所有关键信息的结构用于哈希
	keyData := struct {
		RecordCode    string                 `json:"record_code"`
		DeviceConfigs []cacheKeyDeviceConfig `json:"device_configs"`
		TemplatePath  string                 `json:"template_path"`
	}{
		RecordCode:    recordCode,
		DeviceConfigs: cacheConfigs,
		TemplatePath:  templatePath,
	}

	// 序列化为 JSON
	jsonData, err := json.Marshal(keyData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal cache key data: %w", err)
	}

	// 计算 SHA256 哈希
	hash := sha256.Sum256(jsonData)
	return fmt.Sprintf("nodemap:%s:%s", recordCode, hex.EncodeToString(hash[:])), nil
}

// getOrCreateNodeMap 获取或创建 NodeMap（带缓存）
func (ap *ControllerAPI) getOrCreateNodeMap(
	recordCode string,
	deviceConfigs []config.DeviceConfig,
	templatePath string,
	force bool,
	taskID uint,
) (*nodemap.NodeMap, context.Context, error) {
	// 生成缓存 key
	cacheKey, err := ap.generateCacheKey(recordCode, deviceConfigs, templatePath)
	if err != nil {
		log.Printf("Failed to generate cache key: %v, creating new NodeMap", err)
		return ap.createNodeMap(recordCode, deviceConfigs, templatePath, force, taskID)
	}
	log.Printf("Generated cache key: %s (recordCode: %s, deviceCount: %d, templatePath: %s, force: %v)",
		cacheKey, recordCode, len(deviceConfigs), templatePath, force)

	// 如果 force=true，跳过缓存并清除可能存在的缓存项
	if force {
		if _, ok := ap.nodeMapCache.Load(cacheKey); ok {
			ap.nodeMapCache.Delete(cacheKey)
			log.Printf("Force mode: cleared existing cache for %s", cacheKey)
		}
		log.Printf("Force mode: creating new NodeMap (bypassing cache): %s", cacheKey)
		nm, ctx, err := ap.createNodeMap(recordCode, deviceConfigs, templatePath, force, taskID)
		if err != nil {
			return nil, nil, err
		}

		// 即使 force=true，也存入缓存以供后续使用
		entry := &NodeMapCacheEntry{
			NodeMap:      nm,
			Context:      ctx,
			ExpiresAt:    time.Now().Add(ap.nodeMapCacheTTL),
			LastAccessAt: time.Now(),
		}
		ap.nodeMapCache.Store(cacheKey, entry)
		log.Printf("Cached new NodeMap (force mode): %s (expires at: %v)", cacheKey, entry.ExpiresAt)
		return nm, ctx, nil
	}

	// 尝试从缓存获取
	if value, ok := ap.nodeMapCache.Load(cacheKey); ok {
		entry := value.(*NodeMapCacheEntry)

		// 检查是否过期
		if !entry.IsExpired() {
			// 未过期，续期（滑动窗口）
			entry.Touch(ap.nodeMapCacheTTL)
			log.Printf("Using cached NodeMap: %s (expires at: %v)", cacheKey, entry.ExpiresAt)
			return entry.NodeMap, entry.Context, nil
		}

		// 已过期，删除
		ap.nodeMapCache.Delete(cacheKey)
		log.Printf("Removed expired NodeMap cache: %s", cacheKey)
	}

	// 缓存未命中或已过期，创建新的 NodeMap
	log.Printf("Creating new NodeMap (cache miss): %s", cacheKey)
	nm, ctx, err := ap.createNodeMap(recordCode, deviceConfigs, templatePath, force, taskID)
	if err != nil {
		return nil, nil, err
	}

	// 存入缓存
	entry := &NodeMapCacheEntry{
		NodeMap:      nm,
		Context:      ctx,
		ExpiresAt:    time.Now().Add(ap.nodeMapCacheTTL),
		LastAccessAt: time.Now(),
	}
	ap.nodeMapCache.Store(cacheKey, entry)
	log.Printf("Cached new NodeMap: %s (expires at: %v)", cacheKey, entry.ExpiresAt)

	return nm, ctx, nil
}

// createNodeMap 创建新的 NodeMap（不涉及缓存）
func (ap *ControllerAPI) createNodeMap(
	recordCode string,
	deviceConfigs []config.DeviceConfig,
	templatePath string,
	force bool,
	taskID uint,
) (*nodemap.NodeMap, context.Context, error) {
	var nodemapId uint = 0
	nm, ctx := nodemap.NewNodeMapFromNetwork(recordCode, deviceConfigs, force, taskID, &nodemapId, templatePath)

	if nm == nil {
		return nil, nil, fmt.Errorf("failed to create NodeMap")
	}

	// 确保 logger 已初始化
	logger := zap.NewNop().With(zap.String("function", "NodeMapCache"))
	nm.WithLogger(logger)

	// 设置 Redis 客户端（使用 controller 的 RedisManager）
	if ap.controller != nil && ap.controller.RedisManager != nil {
		redisClient := ap.controller.RedisManager.GetClient()
		if redisClient != nil {
			nm.WithRedisClient(nodemap.NewRedisV8Adapter(redisClient))
		}
	}

	return nm, ctx, nil
}

// ensureIndexes 创建 MongoDB 索引
func (ap *ControllerAPI) ensureIndexes() {
	if ap.mongoClient == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := ap.mongoClient.Database("controller").Collection("async_tasks")

	// 创建索引
	indexes := []mongo.IndexModel{
		// 唯一索引：controller_id + task_id (确保同一 controller 的任务ID唯一)
		{
			Keys: bson.D{
				{Key: "task_info.controller_id", Value: 1},
				{Key: "task_info.id", Value: 1},
			},
			Options: options.Index().SetUnique(true).SetName("unique_controller_task_id"),
		},
		// 索引：controller_id (用于查询特定 controller 的任务)
		{
			Keys:    bson.D{{Key: "task_info.controller_id", Value: 1}},
			Options: options.Index().SetName("idx_controller_id"),
		},
		// 索引：task_info.id (用于快速查找任务)
		{
			Keys:    bson.D{{Key: "task_info.id", Value: 1}},
			Options: options.Index().SetName("idx_task_id"),
		},
		// 索引：status (用于查询特定状态的任务)
		{
			Keys:    bson.D{{Key: "status", Value: 1}},
			Options: options.Index().SetName("idx_status"),
		},
		// 索引：device_ip (用于查询特定设备的任务)
		{
			Keys:    bson.D{{Key: "task_info.device_ip", Value: 1}},
			Options: options.Index().SetName("idx_device_ip"),
		},
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		log.Printf("Failed to create indexes for async_tasks collection: %v", err)
	} else {
		log.Println("Successfully created indexes for async_tasks collection")
	}

	// 创建 TTL 索引（用于自动清理 30 天前的数据）
	// 注意：TTL 索引需要单独创建，且只能在单字段索引上设置
	ttlIndexModel := mongo.IndexModel{
		Keys: bson.D{{Key: "start_time", Value: 1}},
		Options: options.Index().
			SetName("idx_start_time_ttl").
			SetExpireAfterSeconds(30 * 24 * 60 * 60), // 30天后自动删除（2592000秒）
	}

	// 尝试创建 TTL 索引（如果已存在会忽略）
	_, err = collection.Indexes().CreateOne(ctx, ttlIndexModel)
	if err != nil {
		// 如果索引已存在，忽略错误
		if !strings.Contains(err.Error(), "already exists") && !strings.Contains(err.Error(), "IndexOptionsConflict") {
			log.Printf("Failed to create TTL index for async_tasks collection: %v", err)
		}
	} else {
		log.Println("Successfully created TTL index for async_tasks collection (30 days expiration)")
	}
}

// saveTaskResultToMongoDB 保存任务结果到 MongoDB
func (ap *ControllerAPI) saveTaskResultToMongoDB(taskResult *AsyncTaskResult) error {
	if ap.mongoClient == nil {
		// 如果没有 MongoDB 客户端，只记录日志，不报错（降级处理）
		log.Printf("MongoDB client not available, skipping save for task %s", taskResult.TaskInfo.ID)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := ap.mongoClient.Database("controller").Collection("async_tasks")

	// 使用 upsert 操作，确保如果任务已存在则更新，不存在则插入
	filter := bson.M{
		"task_info.controller_id": taskResult.TaskInfo.ControllerID,
		"task_info.id":            taskResult.TaskInfo.ID,
	}

	update := bson.M{"$set": taskResult}

	opts := options.Update().SetUpsert(true)

	_, err := collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		log.Printf("Failed to save task result to MongoDB for task %s: %v", taskResult.TaskInfo.ID, err)
		return fmt.Errorf("failed to save task result to MongoDB: %w", err)
	}

	return nil
}

// loadTaskResultFromMongoDB 从 MongoDB 加载任务结果
func (ap *ControllerAPI) loadTaskResultFromMongoDB(taskID string) (*AsyncTaskResult, error) {
	if ap.mongoClient == nil {
		return nil, fmt.Errorf("MongoDB client not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := ap.mongoClient.Database("controller").Collection("async_tasks")

	// 查询任务，优先查询当前 controller 的任务，如果没有则查询所有 controller 的任务
	filter := bson.M{
		"$or": []bson.M{
			{
				"task_info.controller_id": ap.controllerID,
				"task_info.id":            taskID,
			},
			{
				"task_info.id": taskID,
			},
		},
	}

	var taskResult AsyncTaskResult
	err := collection.FindOne(ctx, filter).Decode(&taskResult)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("task %s not found", taskID)
		}
		return nil, fmt.Errorf("failed to load task result from MongoDB: %w", err)
	}

	return &taskResult, nil
}

func (ap *ControllerAPI) GetControllerStatus(w http.ResponseWriter, r *http.Request) {
	status, err := ap.controller.GetStatus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// // CreateDeployment handles POST /api/v1/deployments
func (ap *ControllerAPI) CreateDeployment(w http.ResponseWriter, r *http.Request) {
	var deploymentRequest models.DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&deploymentRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	deployment, err := ap.controller.CreateDeployment(deploymentRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(deployment)
}

// DeployAgentReq OneOps Agent部署请求
type DeployAgentReq struct {
	DeviceCode   string                 `json:"deviceCode"`   // 设备代码
	AgentCode    string                 `json:"agentCode"`    // Agent代码
	AgentVersion string                 `json:"agentVersion"` // Agent版本
	DownloadURL  string                 `json:"downloadURL"`  // Agent文件下载URL
	Config       map[string]interface{} `json:"config"`       // Agent配置
}

// DeployAgentResp OneOps Agent部署响应
type DeployAgentResp struct {
	TaskID  string `json:"taskID"`  // 部署任务ID
	Status  string `json:"status"`  // 状态
	Message string `json:"message"` // 消息
}

// DeployAgent 处理OneOps的Agent部署请求
func (ap *ControllerAPI) DeployAgent(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DeployAgent] 收到部署请求，Method: %s, URL: %s", r.Method, r.URL.String())

	if r.Method != http.MethodPost {
		log.Printf("[DeployAgent] 方法不允许: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DeployAgentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[DeployAgent] 解析请求体失败: %v", err)
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("[DeployAgent] 请求详情: DeviceCode=%s, AgentCode=%s, AgentVersion=%s, DownloadURL=%s, ConfigKeys=%d",
		req.DeviceCode, req.AgentCode, req.AgentVersion, req.DownloadURL, len(req.Config))

	// 验证必需字段
	if req.AgentCode == "" {
		log.Printf("[DeployAgent] 验证失败: agentCode为空")
		http.Error(w, "agentCode is required", http.StatusBadRequest)
		return
	}
	if req.DownloadURL == "" {
		log.Printf("[DeployAgent] 验证失败: downloadURL为空")
		http.Error(w, "downloadURL is required", http.StatusBadRequest)
		return
	}

	// 生成部署ID
	deploymentID := fmt.Sprintf("agent-deploy-%s-%d", req.AgentCode, time.Now().Unix())

	// 构建标准的DeploymentRequest
	// 注意：这里需要从Config中提取设备信息（IP、登录信息等）
	// 如果Config中没有，可能需要从其他地方获取
	variables := make(map[string]interface{})
	if req.Config != nil {
		variables = req.Config
	}
	// 添加下载URL到variables
	variables["download_url"] = req.DownloadURL
	variables["agent_version"] = req.AgentVersion

	// 提取部署工具信息（如果提供）
	if deploymentToolObjectName, ok := req.Config["deployment_tool_object_name"].(string); ok && deploymentToolObjectName != "" {
		variables["deployment_tool_object_name"] = deploymentToolObjectName
		log.Printf("[DeployAgent] 从Config获取部署工具ObjectName: %s", deploymentToolObjectName)
	} else {
		log.Printf("[DeployAgent] Config中未找到部署工具ObjectName，将使用默认路径")
	}

	// 构建TargetDevice
	// 注意：这里需要从Config或设备服务中获取IP和登录信息
	// 暂时使用默认值，实际应该从设备信息中获取
	targetDevice := models.TargetDevice{
		AgentCode:    req.AgentCode,
		Name:         req.DeviceCode,
		IP:           "", // 需要从设备信息中获取
		LoginMethod:  models.LoginMethodSSH,
		LoginDetails: models.LoginDetails{
			// 需要从设备信息中获取
		},
		Status: models.DeploymentStatusPending,
	}

	// 如果Config中有IP和登录信息，使用它们
	log.Printf("[DeployAgent] 从Config中提取设备信息")
	if ip, ok := req.Config["ip"].(string); ok && ip != "" {
		targetDevice.IP = ip
		log.Printf("[DeployAgent] 从Config获取IP: %s", ip)
	} else {
		log.Printf("[DeployAgent] Config中未找到IP地址")
	}
	if username, ok := req.Config["username"].(string); ok {
		targetDevice.LoginDetails.Username = username
		log.Printf("[DeployAgent] 从Config获取用户名: %s", username)
	} else {
		log.Printf("[DeployAgent] Config中未找到用户名")
	}
	if password, ok := req.Config["password"].(string); ok {
		targetDevice.LoginDetails.Password = password
		log.Printf("[DeployAgent] 从Config获取密码: [已设置]")
	} else {
		log.Printf("[DeployAgent] Config中未找到密码")
	}
	if sshKey, ok := req.Config["ssh_key"].(string); ok {
		targetDevice.LoginDetails.SSHKey = sshKey
		log.Printf("[DeployAgent] 从Config获取SSH密钥: [已设置，长度=%d]", len(sshKey))
	} else {
		log.Printf("[DeployAgent] Config中未找到SSH密钥")
	}

	// 如果IP仍然为空，尝试从Agent注册信息中获取
	if targetDevice.IP == "" {
		log.Printf("[DeployAgent] IP为空，尝试从Agent注册信息中获取")
		// 尝试从RegistryManager获取Agent信息
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		agents, total, err := ap.controller.RegistryManager.ListAgents(ctx, map[string]string{"id": req.AgentCode}, 1, 1)
		if err != nil {
			log.Printf("[DeployAgent] 查询Agent注册信息失败: %v", err)
		} else {
			log.Printf("[DeployAgent] 查询Agent注册信息结果: total=%d, agents=%d", total, len(agents))
			for _, agent := range agents {
				log.Printf("[DeployAgent] 找到Agent: ID=%s, Address=%s", agent.ID, agent.Address)
				if agent.ID == req.AgentCode {
					if agent.Address != "" {
						targetDevice.IP = agent.Address
						log.Printf("[DeployAgent] 从Agent注册信息获取IP: %s", agent.Address)
					}
					break
				}
			}
		}
	}

	// 如果仍然没有IP，返回错误
	if targetDevice.IP == "" {
		log.Printf("[DeployAgent] 无法确定设备IP地址，返回错误")
		log.Printf("[DeployAgent] 当前设备信息: AgentCode=%s, IP=%s, Username=%s, HasPassword=%v, HasSSHKey=%v",
			targetDevice.AgentCode, targetDevice.IP, targetDevice.LoginDetails.Username,
			targetDevice.LoginDetails.Password != "", targetDevice.LoginDetails.SSHKey != "")
		http.Error(w, "Unable to determine device IP address. Please provide 'ip' in config or ensure agent is registered.", http.StatusBadRequest)
		return
	}

	log.Printf("[DeployAgent] 设备信息已确定: IP=%s, Username=%s, HasPassword=%v, HasSSHKey=%v",
		targetDevice.IP, targetDevice.LoginDetails.Username,
		targetDevice.LoginDetails.Password != "", targetDevice.LoginDetails.SSHKey != "")

	deploymentRequest := models.DeploymentRequest{
		ID:            deploymentID,
		AppID:         "agent",
		Type:          "agent",
		Version:       req.AgentVersion,
		OperationType: models.OperationTypeDeploy, // 默认为部署操作
		Variables:     variables,
		TargetDevices: []models.TargetDevice{targetDevice},
	}

	// 记录 Variables 内容（用于调试）
	if deploymentToolObjectName, ok := variables["deployment_tool_object_name"].(string); ok {
		log.Printf("[DeployAgent] Variables中包含部署工具ObjectName: %s", deploymentToolObjectName)
	} else {
		log.Printf("[DeployAgent] Variables中未找到部署工具ObjectName")
		log.Printf("[DeployAgent] Variables内容: %+v", variables)
	}

	// 调用标准的CreateDeployment
	log.Printf("[DeployAgent] 调用CreateDeployment: ID=%s, AppID=%s, Type=%s, Version=%s, TargetDevices=%d, VariablesCount=%d",
		deploymentRequest.ID, deploymentRequest.AppID, deploymentRequest.Type,
		deploymentRequest.Version, len(deploymentRequest.TargetDevices), len(deploymentRequest.Variables))

	deployment, err := ap.controller.CreateDeployment(deploymentRequest)
	if err != nil {
		log.Printf("[DeployAgent] CreateDeployment失败: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create deployment: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[DeployAgent] CreateDeployment成功: DeploymentID=%s, Status=%s",
		deployment.ID, deployment.OverallStatus)

	// 返回OneOps期望的响应格式
	response := DeployAgentResp{
		TaskID:  deployment.ID,
		Status:  "accepted",
		Message: "Deployment request accepted",
	}

	log.Printf("[DeployAgent] 返回响应: TaskID=%s, Status=%s", response.TaskID, response.Status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

func (ap *ControllerAPI) GetDeployment(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deploymentID, ok := vars["deployment_id"]
	if !ok {
		http.Error(w, "Missing deployment_id", http.StatusBadRequest)
		return
	}
	log.Printf("Received request for deployment ID: %s", deploymentID)

	deployment, err := ap.controller.DeploymentManager.GetDeployment(deploymentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[GetDeployment] 返回部署信息: deploymentID=%s, logCount=%d, status=%s", deploymentID, len(deployment.Logs), deployment.OverallStatus)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(deployment)
}

// GetAppVariables handles GET /api/v1/apps/{app_id}/variables
// func (api *ControllerAPI) GetAppVariables(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	appID := vars["app_id"]
// 	env := r.URL.Query().Get("env")

// 	variables, err := api.controller.GetAppVariables(appID, env)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(variables)
// }

// GetAssets handles GET /api/v1/assets
func (ap *ControllerAPI) GetAssets(w http.ResponseWriter, r *http.Request) {
	tags := r.URL.Query().Get("tags")

	assets, err := ap.controller.GetAssets(tags)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assets)
}

// GetAppPackageList handles GET /api/v1/packages
func (ap *ControllerAPI) GetAppPackageList(w http.ResponseWriter, r *http.Request) {
	bucketName := ap.controller.ConfigManager.Config.Minio.BucketName
	packages, err := ap.controller.MinioManager.ListPackages(bucketName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(packages)
}

// GetPackageURL handles GET /api/v1/packages/{package_name}/url
func (ap *ControllerAPI) GetAppPackageURL(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	packageName := vars["package_name"]
	bucketName := ap.controller.ConfigManager.Config.Minio.BucketName

	url, err := ap.controller.MinioManager.GetProxyPackageURL(bucketName, packageName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{"url": url}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ap *ControllerAPI) UpdateDeploymentStatusAndResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deploymentID := vars["deployment_id"]

	var updateRequest struct {
		AgentCode string                  `json:"agent_code"`
		Status    models.DeploymentStatus `json:"status"`
		Message   string                  `json:"message"`
		// Results   map[string]interface{}  `json:"results"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 创建一个 DeviceStatus 对象
	deviceStatus := models.TargetDevice{
		AgentCode: updateRequest.AgentCode,
		Status:    updateRequest.Status,
		Message:   updateRequest.Message,
		// Results:   updateRequest.Results,
	}

	// 调用 DeploymentManager 来更新部署状态
	err := ap.controller.DeploymentManager.UpdateDeploymentDeviceStatus(deploymentID, deviceStatus)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Deployment device status updated successfully"})
}

func (ap *ControllerAPI) HandleListService(w http.ResponseWriter, r *http.Request) {
	srvList := ap.controller.RegistryManager.ListServices()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(srvList)
}

func (ap *ControllerAPI) HandleListAgents(w http.ResponseWriter, r *http.Request) {
	// 处理过滤条件
	filter := make(map[string]string)
	validFilterKeys := []string{"id", "status", "address", "hostname", "area", "zone", "version", "mode", "group", "deployment"}
	for _, key := range validFilterKeys {
		if value := r.URL.Query().Get(key); value != "" {
			filter[key] = value
		}
	}

	// 处理分页
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil || pageSize < 1 {
		pageSize = 10 // 默认每页10条
	}

	// 调用控制器方法
	agents, total, err := ap.controller.AgentManager.ListAgents(r.Context(), filter, page, pageSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 构造响应
	response := models.AgentsResponse{
		Agents:   agents,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// func (c *ControllerAPI) InstallPackage(w http.ResponseWriter, r *http.Request) {
// 	var req models.DeploymentRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body", http.StatusBadRequest)
// 		return
// 	}

// 	_, err := c.controller.AgentManager.InstallPackages(r.Context(), req)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Failed to install package: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	response := struct {
// 		InstallID string `json:"install_id"`
// 	}{
// 		InstallID: req.ID,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(response)
// }

// func (c *ControllerAPI) GetPackageInstallStatus(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	installID := vars["install_id"]

// 	status, err := c.controller.AgentManager.GetPackageInstallStatus(r.Context(), installID)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Failed to get install status: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(status)
// }

// func (c *ControllerAPI) GetVariables(w http.ResponseWriter, r *http.Request) {
// 	// 从请求中获取 agent_id（如果需要的话）
// 	agentCode := r.URL.Query().Get("agent_code")
// 	appID := r.URL.Query().Get("app_id")

// 	// 获取变量
// 	variables, err := c.controller.GetAgentVariables(r.Context(), agentCode, appID)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Failed to get variables: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	// 将变量转换为 JSON 并发送响应
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(variables)
// }

func (ap *ControllerAPI) GetVariables(w http.ResponseWriter, r *http.Request) {
	// 从查询参数中获取 agent_code 和 app_id
	agentCode := r.URL.Query().Get("agent_code")
	appID := r.URL.Query().Get("app_id")

	// 获取全局变量
	globalVars, err := ap.controller.ConfigManager.GetGlobalVariables()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get global variables: %v", err), http.StatusInternalServerError)
		return
	}

	// 合并变量（使用 interface{} 类型以支持数组）
	mergedVars := make(map[string]interface{})
	for k, v := range globalVars {
		mergedVars[k] = v
	}

	// 如果提供了 app_id，获取并合并应用特定变量
	if appID != "" {
		appVars, err := ap.controller.ConfigManager.GetAppVariables(appID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get app variables: %v", err), http.StatusInternalServerError)
			return
		}
		for k, v := range appVars {
			mergedVars[k] = v
		}
	}

	// 处理 runtime_vars
	if runtimeVarsStr, ok := mergedVars["runtime_vars"].(string); ok {
		runtimeVars := strings.Split(runtimeVarsStr, ",")
		for _, v := range runtimeVars {
			// 这里可以添加逻辑来获取 runtime_vars 的实际值
			// 暂时设置为空字符串
			mergedVars[v] = ""
		}
		delete(mergedVars, "runtime_vars")
	}

	// 如果提供了 agent_code，可以在这里添加 agent 特定的变量处理逻辑
	if agentCode != "" {
		// 示例：添加 agent_code 到变量中
		mergedVars["agent_code"] = agentCode
		// 这里可以添加更多 agent 特定的变量处理逻辑
	}

	vars, err := ap.controller.RegistryManager.GetVariables(r.Context(), agentCode, appID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get agent variables: %v", err), http.StatusInternalServerError)
		return
	}

	// 处理 etcd_endpoints：优先使用 vars 中的 etcd_endpoint（由 GetVariables 根据 use_docker_etcd 决定）
	// 注意：当使用Docker etcd时，GetVariables 已经返回了正确的地址（Controller主机IP+hostPort）
	// upstream.etcd_addresses 是用于Controller注册到上游etcd的，不应该用于Agent注册
	etcdEndpoints := make([]string, 0)
	if etcdEndpoint, ok := vars["etcd_endpoint"]; ok && etcdEndpoint != "" {
		// 优先使用 GetVariables 返回的 etcd_endpoint（已经根据 use_docker_etcd 处理过）
		etcdEndpoints = append(etcdEndpoints, etcdEndpoint)
	} else if len(ap.controller.ConfigManager.Config.Upstream.EtcdAddresses) > 0 {
		// 降级方案：如果没有 etcd_endpoint，使用 upstream.etcd_addresses（外部etcd场景）
		etcdEndpoints = append(etcdEndpoints, ap.controller.ConfigManager.Config.Upstream.EtcdAddresses...)
	}

	// 将 etcd_endpoints 数组添加到变量中（模板可以使用 range 遍历）
	if len(etcdEndpoints) > 0 {
		mergedVars["etcd_endpoints"] = etcdEndpoints
	}

	// 处理 metrics 增强型收集器配置（数组类型）
	// enhanced_collectors：启用的collectors列表（可选）
	// 如果未设置，模板会使用默认值（空列表表示启用所有）
	if enhancedCollectors, ok := vars["metrics_enhanced_collectors"]; ok && enhancedCollectors != "" {
		// 如果配置为字符串，尝试解析为数组（逗号分隔）
		collectors := strings.Split(enhancedCollectors, ",")
		trimmedCollectors := make([]string, 0, len(collectors))
		for _, c := range collectors {
			trimmed := strings.TrimSpace(c)
			if trimmed != "" {
				trimmedCollectors = append(trimmedCollectors, trimmed)
			}
		}
		if len(trimmedCollectors) > 0 {
			mergedVars["metrics_enhanced_collectors"] = trimmedCollectors
		}
	}

	// enhanced_exclude：排除的collectors列表（可选）
	if enhancedExclude, ok := vars["metrics_enhanced_exclude"]; ok && enhancedExclude != "" {
		// 如果配置为字符串，尝试解析为数组（逗号分隔）
		excludes := strings.Split(enhancedExclude, ",")
		trimmedExcludes := make([]string, 0, len(excludes))
		for _, e := range excludes {
			trimmed := strings.TrimSpace(e)
			if trimmed != "" {
				trimmedExcludes = append(trimmedExcludes, trimmed)
			}
		}
		if len(trimmedExcludes) > 0 {
			mergedVars["metrics_enhanced_exclude"] = trimmedExcludes
		}
	}

	// 合并其他变量（字符串类型）
	for k, v := range vars {
		mergedVars[k] = v
	}

	// 添加指标策略配置（如果agentCode存在）
	if agentCode != "" {
		// 尝试获取指标策略（如果服务可用）
		// 注意：这里需要MetricsStrategyService，暂时跳过，后续在Controller中集成
		// TODO: 在Controller中添加MetricsStrategyService，并在GetVariables中集成
	}

	// controller_url 必须由 RegistryManager.GetVariables 基于 BaseConfig.DefaultPort 构建
	// 如果不存在，说明配置有问题，返回错误
	controllerURLValue, exists := mergedVars["controller_url"]
	if !exists {
		http.Error(w, "controller_url is required but not provided by RegistryManager. Please check BaseConfig.DefaultPort configuration.", http.StatusInternalServerError)
		return
	}
	// 验证 controller_url 是字符串类型且不为空
	controllerURL, ok := controllerURLValue.(string)
	if !ok || controllerURL == "" {
		http.Error(w, fmt.Sprintf("controller_url is required but invalid (type: %T, value: %v). Please check Controller BaseConfig.DefaultPort configuration.", controllerURLValue, controllerURLValue), http.StatusInternalServerError)
		return
	}

	// 将结果转换为 JSON 并发送响应
	// 注意：返回 map[string]interface{} 以支持数组类型（如 etcd_endpoints）
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mergedVars)
}

// 在 pkg/controller/api/api.go 文件中

func (ap *ControllerAPI) StartPackage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentCode := vars["agent_code"]
	packageName := vars["package_name"]

	err := ap.controller.AgentManager.StartPackage(r.Context(), agentCode, packageName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to start package: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Package started successfully"})
}

func (ap *ControllerAPI) StopPackage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentCode := vars["agent_code"]
	packageName := vars["package_name"]

	err := ap.controller.AgentManager.StopPackage(r.Context(), agentCode, packageName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop package: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "Package stopped successfully"})
}

func (ap *ControllerAPI) GetPackageLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentCode := vars["agent_code"]
	packageName := vars["package_name"]
	countStr := r.URL.Query().Get("count")

	count, err := strconv.Atoi(countStr)
	if err != nil || count <= 0 {
		count = 100 // 默认获取最近100条日志
	}

	logs, err := ap.controller.AgentManager.GetPackageLogs(r.Context(), agentCode, packageName, int32(count))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get package logs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": logs,
	})
}

type ExecuteCommandRequest struct {
	Item    structs.CollectItem `json:"collect_item"`
	Command string              `json:"command"`
}

type ExecuteCommandResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// 服务器
// 交换机：structs.L2DeviceRemoteInfo+commandList

type ExecuteSwitchCommandRequest struct {
	ID          string                     `json:"id"`
	RemoteInfo  structs.L2DeviceRemoteInfo `json:"remote_info"`
	CommandList []string                   `json:"command_list"`
}

type ExecuteSwitchCommandResponse struct {
	ID     string `json:"id"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

func (ap *ControllerAPI) ExecuteCommand(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request for handleExecutePipeline")

	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Vendor             string                                `json:"vendor"`
		Platform           string                                `json:"platform"`
		Version            string                                `json:"version"`
		Attributes         map[string]string                     `json:"attributes"`
		CollectItemOptions map[string]structs.CollectItemOptions `json:"collect_item_options"`
		PipelineStates     []structs.PipelineStageSelectConfig   `json:"pipeline_states"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("Decoded request: Vendor=%s, Platform=%s, Version=%s, Attributes=%v, PipelineStates=%v",
		request.Vendor, request.Platform, request.Version, request.Attributes, request.PipelineStates)
	log.Printf("CollectItemOptions: %+v", request.CollectItemOptions)

	pipelineService := ps.NewPipelineService(ap.controller.ConfigManager.Config.BaseConfig.PipelineTemplates)

	result, err := pipelineService.ExecutePipeline(
		request.Vendor,
		request.Platform,
		request.Version,
		request.Attributes,
		request.CollectItemOptions,
		request.PipelineStates,
	)
	if err != nil {
		log.Printf("Error executing pipeline: %v", err)
		http.Error(w, fmt.Sprintf("Error executing pipeline: %v", err), http.StatusInternalServerError)
		return
	}

	log.Println("Successfully executed pipeline")

	if _, ok := result.([]map[string]string); !ok {
		log.Println("Pipeline execution result is not a map of string to string")
		http.Error(w, "Pipeline execution result is not a map of string to string", http.StatusInternalServerError)
		return
	}

	var deviceKey string
	if request.Attributes != nil {
		deviceKey = request.Attributes["DeviceKey"]
	}

	// 打印pipeline执行结果的详细信息
	log.Printf("Pipeline execution result: %+v", result)
	resultWrapper := map[string][]map[string]string{
		deviceKey: result.([]map[string]string),
	}

	resultTable, err := clitask.NewTableFromSliceMap(result.([]map[string]string))
	if err != nil {
		log.Printf("Error creating table from slice map: %v", err)
		http.Error(w, fmt.Sprintf("Error creating table from slice map: %v", err), http.StatusInternalServerError)
		return
	}
	// tableWrapper := map[string]clitask.Table{
	// 	deviceCode: *resultTable,
	// }

	// totalResult := map[string]interface{}{
	// 	"table": tableWrapper,
	// 	"map":   resultWrapper,
	// }
	resultTable.Pretty()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resultWrapper); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Println("Successfully sent pipeline execution response")
}

func (ap *ControllerAPI) AsyncExecuteCommand(w http.ResponseWriter, r *http.Request) {
	log.Printf("=== AsyncExecuteCommand called ===")
	log.Printf("Request Method: %s", r.Method)
	log.Printf("Request URL: %s", r.URL.String())
	log.Printf("Request RemoteAddr: %s", r.RemoteAddr)

	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Decoding request body...")
	var request AsyncExecuteCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}
	log.Printf("Request decoded successfully. ID: %s, Commands: %d, Script: %s, ScriptPath: %s",
		request.ID, len(request.Commands),
		func() string {
			if request.Script != "" {
				return "<present>"
			} else {
				return "<empty>"
			}
		}(),
		request.ScriptPath)

	// 验证请求参数
	// 注意：参数验证失败时不保存结果，直接返回错误
	if request.ID == "" {
		http.Error(w, "Missing required field: id", http.StatusBadRequest)
		return
	}

	// 验证至少有一种执行方式
	if len(request.Commands) == 0 && request.Script == "" && request.ScriptPath == "" {
		http.Error(w, "Must provide at least one of: commands, script, or script_path", http.StatusBadRequest)
		return
	}

	// 参数验证通过后，所有后续的错误情况都会保存结果

	// 设置默认超时时间
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = 60 // 默认60秒
	}

	// 确定命令类型
	commandType := "unknown"
	if len(request.Commands) > 0 {
		commandType = "commands"
	} else if request.Script != "" {
		commandType = "script"
	} else if request.ScriptPath != "" {
		commandType = "script_path"
	}

	// 初始化任务信息
	taskInfo := TaskInfo{
		ID:           request.ID,
		ControllerID: ap.controllerID,
		DeviceIP:     request.RemoteInfo.Ip,
		DevicePort:   request.RemoteInfo.Meta.SSHPort,
		Username:     request.RemoteInfo.Username,
		CommandType:  commandType,
		Background:   request.Background,
		Timeout:      timeout,
		CreatedAt:    time.Now(),
	}

	// 初始化任务状态
	taskResult := &AsyncTaskResult{
		Status:    TaskStatusRunning,
		TaskInfo:  taskInfo,
		StartTime: time.Now(),
		Message:   "任务正在执行中",
	}

	// 保存到内存缓存和 MongoDB
	ap.asyncTasks.Store(request.ID, taskResult)
	if err := ap.saveTaskResultToMongoDB(taskResult); err != nil {
		log.Printf("Warning: failed to save initial task state to MongoDB: %v", err)
		// 继续执行，不阻断任务提交
	}

	log.Printf("Created async task %s for command execution", request.ID)

	// 在goroutine中异步执行
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic in async command execution: %v", r)
				endTime := time.Now()
				duration := endTime.Sub(taskResult.StartTime).Milliseconds()
				taskResult.Status = TaskStatusFailed
				taskResult.EndTime = &endTime
				taskResult.Duration = &duration
				taskResult.Error = &ErrorDetail{
					Type:    ErrorTypeUnknown,
					Message: "执行过程中发生异常",
					Details: fmt.Sprintf("Panic: %v", r),
				}
				taskResult.Message = "任务执行失败：发生系统异常"
				// 确保Result字段被初始化（即使panic发生在命令执行之前，也要有结果）
				if taskResult.Result == nil {
					taskResult.Result = &ExecutionResult{
						ExitCode:       -1,
						OutputSize:     0,
						CommandResults: []CommandResult{}, // 空列表，表示没有执行任何命令或panic发生在执行中
					}
				}
				ap.asyncTasks.Store(request.ID, taskResult)
				_ = ap.saveTaskResultToMongoDB(taskResult) // 异步保存，忽略错误
			}
		}()

		log.Printf("Starting async command execution for task %s", request.ID)

		// 创建 logger
		logger, err := zap.NewDevelopment()
		if err != nil {
			log.Printf("Failed to create logger: %v", err)
			endTime := time.Now()
			duration := endTime.Sub(taskResult.StartTime).Milliseconds()
			taskResult.Status = TaskStatusFailed
			taskResult.EndTime = &endTime
			taskResult.Duration = &duration
			taskResult.Error = &ErrorDetail{
				Type:    ErrorTypeUnknown,
				Message: "系统初始化失败",
				Details: fmt.Sprintf("Failed to create logger: %v", err),
			}
			taskResult.Message = "任务执行失败：系统初始化错误"
			// 确保Result字段被初始化（即使没有命令被执行）
			taskResult.Result = &ExecutionResult{
				ExitCode:       -1,
				OutputSize:     0,
				CommandResults: []CommandResult{}, // 空列表，表示没有执行任何命令
			}
			ap.asyncTasks.Store(request.ID, taskResult)
			_ = ap.saveTaskResultToMongoDB(taskResult) // 异步保存，忽略错误
			return
		}
		defer logger.Sync()

		// 将 L2DeviceRemoteInfo 转换为 dispatch.BaseInfo
		baseInfo := &dispatch.BaseInfo{
			Host:     request.RemoteInfo.Ip,
			Port:     request.RemoteInfo.Meta.SSHPort,
			Username: request.RemoteInfo.Username,
			Password: request.RemoteInfo.Password,
			Telnet:   false, // 默认使用SSH
		}

		// 如果端口为0，使用默认SSH端口22
		if baseInfo.Port == 0 {
			baseInfo.Port = 22
		}

		// 根据 Catalog 判断设备类型并创建设备实例
		var device *netdevice.BaseNetworkDevice
		if request.RemoteInfo.Catalog == "SERVER" {
			// 服务器：使用简化配置（用于脚本执行）
			log.Printf("Creating server device for task %s (Catalog: SERVER)", request.ID)
			device, err = netdevice.NewBaseNetworkDeviceForScript(baseInfo, logger)
		} else {
			// 网络设备：使用完整配置（需要 modeConfig 和 hubConfig）
			log.Printf("Creating network device for task %s (Catalog: %s)", request.ID, request.RemoteInfo.Catalog)

			// 尝试从配置文件加载 modeConfig 和 hubConfig
			var modeConfig *structs.ModeConfig
			var hubConfig *structs.HubConfig

			vendor := request.RemoteInfo.Manufacturer
			platform := request.RemoteInfo.Platform

			// 从 Meta 中获取版本信息
			version := request.RemoteInfo.Meta.Version

			// 构建 attributes map
			attributes := make(map[string]string)
			if request.RemoteInfo.Site != "" {
				attributes["site"] = request.RemoteInfo.Site
			}
			if request.RemoteInfo.Env != "" {
				attributes["env"] = request.RemoteInfo.Env
			}

			// 如果 vendor 和 platform 为空，尝试自动检测
			if vendor == "" || platform == "" {
				log.Printf("Auto-detecting device for task %s (vendor: %s, platform: %s)", request.ID, vendor, platform)
				deviceDetector, err := detector.NewDeviceDetector(ap.controller.ConfigManager.Config.BaseConfig.PipelineTemplates)
				if err == nil {
					detectionResult, err := deviceDetector.Detect(&detector.DetectionRequest{
						IP:            request.RemoteInfo.Ip,
						SNMPCommunity: "",
						SSHCredentials: &detector.SSHCredentials{
							Username: request.RemoteInfo.Username,
							Password: request.RemoteInfo.Password,
							Port:     int(request.RemoteInfo.Meta.SSHPort),
						},
					})
					if err == nil && detectionResult != nil {
						// 使用检测结果更新vendor和platform
						if vendor == "" {
							vendor = detectionResult.Manufacturer
							request.RemoteInfo.Manufacturer = detectionResult.Manufacturer
						}
						if platform == "" {
							platform = detectionResult.Platform
							request.RemoteInfo.Platform = detectionResult.Platform
						}
						if version == "" && detectionResult.Version != "" {
							version = detectionResult.Version
							request.RemoteInfo.Meta.Version = detectionResult.Version
						}
						// 如果检测到了配置，直接使用
						if detectionResult.DeviceConfig != nil {
							modeConfig, hubConfig = ap.extractConfigsFromDeviceConfig(detectionResult.DeviceConfig)
							if modeConfig != nil && hubConfig != nil {
								log.Printf("Successfully auto-detected and loaded device config for task %s (vendor: %s, platform: %s, version: %s)",
									request.ID, vendor, platform, version)
							}
						}
					} else {
						log.Printf("Auto-detection failed for task %s: %v, will try manual config", request.ID, err)
					}
				} else {
					log.Printf("Failed to create detector for task %s: %v", request.ID, err)
				}
			}

			// 如果 vendor 和 platform 都存在，尝试加载配置
			if vendor != "" && platform != "" {
				pipelineService := ps.NewPipelineService(ap.controller.ConfigManager.Config.BaseConfig.PipelineTemplates)
				deviceConfig, err := pipelineService.GetDeviceConfig(vendor, platform, version, attributes)

				if err == nil && deviceConfig != nil {
					// 从 DeviceConfig 中提取 modeConfig 和 hubConfig
					modeConfig, hubConfig = ap.extractConfigsFromDeviceConfig(deviceConfig)
					if modeConfig != nil && hubConfig != nil {
						log.Printf("Successfully loaded device config for task %s (vendor: %s, platform: %s, version: %s)",
							request.ID, vendor, platform, version)
					} else {
						log.Printf("Warning: Device config loaded but no valid modeConfig/hubConfig found for task %s, using default", request.ID)
					}
				} else {
					log.Printf("Warning: Failed to load device config for task %s (vendor: %s, platform: %s, version: %s): %v, using default config",
						request.ID, vendor, platform, version, err)
				}
			} else {
				log.Printf("Warning: Missing vendor or platform info for task %s (vendor: %s, platform: %s), using default config",
					request.ID, vendor, platform)
			}

			// 如果没有获取到配置，使用默认配置（降级处理）
			if modeConfig == nil {
				modeConfig = &structs.ModeConfig{}
			}
			if hubConfig == nil {
				hubConfig = ap.getDefaultHubConfig()
			}

			device, err = netdevice.NewBaseNetworkDevice(baseInfo, modeConfig, hubConfig, logger)
		}

		if err != nil {
			log.Printf("Failed to create device for task %s: %v", request.ID, err)
			endTime := time.Now()
			duration := endTime.Sub(taskResult.StartTime).Milliseconds()
			taskResult.Status = TaskStatusFailed
			taskResult.EndTime = &endTime
			taskResult.Duration = &duration
			taskResult.Error = &ErrorDetail{
				Type:    ErrorTypeNetwork,
				Message: "无法创建设备连接",
				Details: fmt.Sprintf("Failed to create device: %v", err),
			}
			taskResult.Message = "任务执行失败：无法创建设备连接"
			// 确保Result字段被初始化（即使没有命令被执行）
			taskResult.Result = &ExecutionResult{
				ExitCode:       -1,
				OutputSize:     0,
				CommandResults: []CommandResult{}, // 空列表，表示没有执行任何命令
			}
			ap.asyncTasks.Store(request.ID, taskResult)
			_ = ap.saveTaskResultToMongoDB(taskResult) // 异步保存，忽略错误
			return
		}
		defer device.Close()

		// 建立连接并登录
		loginCtx, loginCancel := device.BuildLoginCtx(10, 60)
		defer loginCancel()

		// 根据设备类型选择登录方式
		if request.RemoteInfo.Catalog == "SERVER" {
			// 服务器设备：如果需要执行命令列表，使用轻量级登录（ExecuteScript不需要Executor）
			// 如果使用脚本，也是使用轻量级登录
			err = device.Login(loginCtx)
		} else {
			// 网络设备：如果需要执行命令列表，使用LoginAndInit初始化Executor
			// 如果使用脚本，可以使用轻量级Login
			if len(request.Commands) > 0 {
				// 有命令列表：需要Executor来执行命令
				err = device.LoginAndInit(loginCtx)
			} else {
				// 使用脚本：只需要轻量级登录
				err = device.Login(loginCtx)
			}
		}

		if err != nil {
			log.Printf("Failed to login for task %s: %v", request.ID, err)
			endTime := time.Now()
			duration := endTime.Sub(taskResult.StartTime).Milliseconds()
			taskResult.Status = TaskStatusFailed
			taskResult.EndTime = &endTime
			taskResult.Duration = &duration

			// 判断错误类型
			errorType := ErrorTypeNetwork
			errStr := strings.ToLower(err.Error())
			var message string

			if strings.Contains(errStr, "authentication") || strings.Contains(errStr, "password") ||
				strings.Contains(errStr, "key") || strings.Contains(errStr, "credential") {
				errorType = ErrorTypeAuthentication
				message = "任务执行失败：设备认证失败，请检查用户名和密码"
			} else if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "connect failed") {
				errorType = ErrorTypeNetwork
				message = fmt.Sprintf("任务执行失败：无法连接到设备 %s:%d（连接被拒绝，请检查设备是否在线、SSH服务是否运行）", request.RemoteInfo.Ip, baseInfo.Port)
			} else if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "timed out") {
				errorType = ErrorTypeNetwork
				message = "任务执行失败：连接设备超时（请检查网络连通性和防火墙设置）"
			} else if strings.Contains(errStr, "no route to host") || strings.Contains(errStr, "network is unreachable") {
				errorType = ErrorTypeNetwork
				message = fmt.Sprintf("任务执行失败：无法到达设备 %s（网络不可达）", request.RemoteInfo.Ip)
			} else {
				errorType = ErrorTypeNetwork
				message = fmt.Sprintf("任务执行失败：无法连接到设备 %s:%d", request.RemoteInfo.Ip, baseInfo.Port)
			}

			taskResult.Error = &ErrorDetail{
				Type:    errorType,
				Message: "设备登录失败",
				Details: fmt.Sprintf("Failed to login: %v", err),
			}
			taskResult.Message = message
			// 确保Result字段被初始化（即使没有命令被执行）
			taskResult.Result = &ExecutionResult{
				ExitCode:       -1,
				OutputSize:     0,
				CommandResults: []CommandResult{}, // 空列表，表示没有执行任何命令
			}
			ap.asyncTasks.Store(request.ID, taskResult)
			_ = ap.saveTaskResultToMongoDB(taskResult) // 异步保存，忽略错误
			return
		}

		// 创建执行上下文，设置超时
		execCtx, execCancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer execCancel()

		var output string
		var commandResults []CommandResult

		// 根据设备类型和执行方式选择不同的执行方法
		if len(request.Commands) > 0 {
			// 有命令列表
			if request.RemoteInfo.Catalog == "SERVER" {
				// 服务器设备：逐个执行命令（每个命令作为一个脚本执行，以便获取单独的输出）
				var allOutput strings.Builder
				commandResults = make([]CommandResult, 0, len(request.Commands))
				var firstError error

				for i, cmd := range request.Commands {
					cmdStartTime := time.Now()
					log.Printf("Executing command %d/%d for task %s: %s", i+1, len(request.Commands), request.ID, cmd)

					// 为每个命令创建一个简单的bash脚本（不使用set -e，以便可以继续执行）
					// 注意：对于服务器设备，我们仍然使用ExecuteScript，但每次只执行一个命令
					scriptContent := fmt.Sprintf("#!/bin/bash\n%s\n", cmd)
					cmdOutput, cmdErr := device.ExecuteScript(execCtx, scriptContent, "", request.Background)
					cmdDuration := time.Since(cmdStartTime).Milliseconds()

					// 记录每个命令的结果
					cmdResult := CommandResult{
						Index:      i,
						Command:    cmd,
						ExecutedAt: cmdStartTime,
						Duration:   cmdDuration,
					}

					if cmdErr != nil {
						cmdResult.Success = false
						cmdResult.Error = cmdErr.Error()
						cmdResult.Stderr = cmdErr.Error()
						if firstError == nil {
							firstError = fmt.Errorf("command '%s' failed: %w", cmd, cmdErr)
						}
					} else {
						cmdResult.Success = true
						cmdResult.Stdout = cmdOutput
						cmdResult.ExitCode = 0
						if i > 0 {
							allOutput.WriteString("\n")
						}
						allOutput.WriteString(cmdOutput)
					}

					commandResults = append(commandResults, cmdResult)

					// 如果命令失败，是否停止执行后续命令取决于业务需求
					// 这里我们选择继续执行，以便获取所有命令的结果
					// 但如果用户希望失败即停，可以取消注释下面的代码
					// if cmdErr != nil {
					// 	err = firstError
					// 	break
					// }
				}
				output = allOutput.String()
				// 如果有任何命令失败，设置整体错误
				if firstError != nil {
					err = firstError
				}
			} else {
				// 网络设备：使用Executor逐个执行命令（不包装成脚本）
				var allOutput strings.Builder
				commandResults = make([]CommandResult, 0, len(request.Commands))
				var firstError error

				for i, cmd := range request.Commands {
					cmdStartTime := time.Now()
					log.Printf("Executing command %d/%d for task %s: %s", i+1, len(request.Commands), request.ID, cmd)

					cmdOutput, cmdErr := device.ExecuteCommand(execCtx, cmd)
					cmdDuration := time.Since(cmdStartTime).Milliseconds()

					// 记录每个命令的结果
					cmdResult := CommandResult{
						Index:      i,
						Command:    cmd,
						ExecutedAt: cmdStartTime,
						Duration:   cmdDuration,
					}

					if cmdErr != nil {
						// 检查是否是误判的超时错误
						// 如果错误是 TIMEOUT_ERROR 且包含 "no output received for too long"
						// 但输出中包含了命令的实际结果和提示符，则认为命令执行成功
						errStr := cmdErr.Error()
						isFalseTimeout := strings.Contains(errStr, "TIMEOUT_ERROR") &&
							strings.Contains(errStr, "no output received for too long") &&
							len(cmdOutput) > 0 &&
							(strings.Contains(cmdOutput, cmd) || strings.Contains(cmdOutput, "$") || strings.Contains(cmdOutput, "#"))

						if isFalseTimeout {
							// 这是一个误判的超时，命令实际上已经执行完成
							log.Printf("Command '%s' reported timeout but has output, treating as success. Output length: %d", cmd, len(cmdOutput))
							cmdResult.Success = true
							cmdResult.Stdout = cmdOutput
							cmdResult.ExitCode = 0
							if i > 0 {
								allOutput.WriteString("\n")
							}
							allOutput.WriteString(cmdOutput)
							// 不记录为错误，继续执行
						} else {
							cmdResult.Success = false
							cmdResult.Error = cmdErr.Error()
							cmdResult.Stderr = cmdErr.Error()
							if firstError == nil {
								firstError = fmt.Errorf("command '%s' failed: %w", cmd, cmdErr)
							}
						}
					} else {
						cmdResult.Success = true
						cmdResult.Stdout = cmdOutput
						cmdResult.ExitCode = 0
						if i > 0 {
							allOutput.WriteString("\n")
						}
						allOutput.WriteString(cmdOutput)
					}

					commandResults = append(commandResults, cmdResult)

					// 命令失败时不停止执行，继续执行后续命令以便获取所有命令的结果
					// 记录第一个错误用于最终的状态判断
				}
				output = allOutput.String()
				// 如果有任何命令失败，设置整体错误（但不停止执行）
				if firstError != nil {
					err = firstError
				}
			}
		} else if request.Script != "" {
			// 使用内联脚本
			output, err = device.ExecuteScript(execCtx, request.Script, "", request.Background)
			// 脚本执行无法分解为单个命令结果，记录整个脚本的结果
			if err == nil {
				commandResults = []CommandResult{
					{
						Index:      0,
						Command:    "<inline script>",
						Stdout:     output,
						Success:    true,
						ExitCode:   0,
						ExecutedAt: time.Now(),
					},
				}
			} else {
				commandResults = []CommandResult{
					{
						Index:      0,
						Command:    "<inline script>",
						Error:      err.Error(),
						Success:    false,
						ExecutedAt: time.Now(),
					},
				}
			}
		} else if request.ScriptPath != "" {
			// 使用文件脚本
			output, err = device.ExecuteScript(execCtx, "", request.ScriptPath, request.Background)
			// 脚本执行无法分解为单个命令结果，记录整个脚本的结果
			if err == nil {
				commandResults = []CommandResult{
					{
						Index:      0,
						Command:    request.ScriptPath,
						Stdout:     output,
						Success:    true,
						ExitCode:   0,
						ExecutedAt: time.Now(),
					},
				}
			} else {
				commandResults = []CommandResult{
					{
						Index:      0,
						Command:    request.ScriptPath,
						Error:      err.Error(),
						Success:    false,
						ExecutedAt: time.Now(),
					},
				}
			}
		} else {
			err = fmt.Errorf("no commands, script, or scriptPath provided")
		}

		endTime := time.Now()
		duration := endTime.Sub(taskResult.StartTime).Milliseconds()
		taskResult.EndTime = &endTime
		taskResult.Duration = &duration

		if err != nil {
			log.Printf("Error executing script for task %s: %v", request.ID, err)

			// 判断错误类型
			var status TaskStatus
			var errorType ErrorType
			var message string
			var errorMsg string

			errStr := err.Error()

			if execCtx.Err() == context.DeadlineExceeded {
				status = TaskStatusTimeout
				errorType = ErrorTypeTimeout
				message = fmt.Sprintf("任务执行超时（%d秒）", timeout)
				errorMsg = fmt.Sprintf("Execution timeout after %d seconds: %v", timeout, err)
			} else if execCtx.Err() == context.Canceled {
				status = TaskStatusCancelled
				errorType = ErrorTypeCancelled
				message = "任务已被取消"
				errorMsg = fmt.Sprintf("Execution cancelled: %v", err)
			} else if strings.Contains(errStr, "resource shortage") || strings.Contains(errStr, "resource unavailable") {
				// SSH资源短缺错误（通常是设备端会话数达到上限）
				status = TaskStatusFailed
				errorType = ErrorTypeNetwork
				message = "设备资源不足，无法创建SSH会话"
				errorMsg = fmt.Sprintf("Device resource shortage: %v. This may be due to too many active SSH sessions on the device. Please try again later or check device SSH session limits.", err)
			} else if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "connect failed") {
				// 连接被拒绝
				status = TaskStatusFailed
				errorType = ErrorTypeNetwork
				message = fmt.Sprintf("连接被拒绝（设备 %s:%d 可能未启动SSH服务或端口不可达）", request.RemoteInfo.Ip, request.RemoteInfo.Meta.SSHPort)
				errorMsg = fmt.Sprintf("Connection refused: %v. Please check if SSH service is running on the device and the port is accessible.", err)
			} else if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "timed out") {
				// 连接超时
				status = TaskStatusFailed
				errorType = ErrorTypeNetwork
				message = fmt.Sprintf("连接超时（设备 %s 可能网络不可达）", request.RemoteInfo.Ip)
				errorMsg = fmt.Sprintf("Connection timeout: %v. Please check network connectivity and firewall settings.", err)
			} else if strings.Contains(errStr, "authentication") || strings.Contains(errStr, "password") ||
				strings.Contains(errStr, "key") || strings.Contains(errStr, "credential") {
				// 认证错误
				status = TaskStatusFailed
				errorType = ErrorTypeAuthentication
				message = "设备认证失败"
				errorMsg = fmt.Sprintf("Authentication failed: %v", err)
			} else {
				status = TaskStatusFailed
				errorType = ErrorTypeExecution
				message = "命令执行失败"
				errorMsg = err.Error()
			}

			// 即使有错误，也记录已执行的命令结果
			outputSize := int64(len(output))
			execResult := &ExecutionResult{
				Stdout:         output,
				ExitCode:       -1, // 失败时退出码为-1
				OutputSize:     outputSize,
				CommandResults: commandResults, // 保留已执行的命令结果
			}

			// 如果有命令结果，统计信息
			if len(commandResults) > 0 {
				successCount := 0
				failedCount := 0
				for _, cr := range commandResults {
					if cr.Success {
						successCount++
					} else {
						failedCount++
					}
				}
				if successCount > 0 {
					message = fmt.Sprintf("%s（已成功执行 %d/%d 个命令）", message, successCount, len(commandResults))
				}
			}

			taskResult.Status = status
			taskResult.Error = &ErrorDetail{
				Type:    errorType,
				Message: message,
				Details: errorMsg,
			}
			taskResult.Result = execResult // 即使失败，也返回部分结果
			taskResult.Message = message
			ap.asyncTasks.Store(request.ID, taskResult)
			_ = ap.saveTaskResultToMongoDB(taskResult) // 异步保存，忽略错误
			return
		}

		// 解析输出（如果可能，尝试分离 stdout 和 stderr）
		// 注意：netdevice.ExecuteScript 返回的是组合输出，这里我们将其作为 stdout
		outputSize := int64(len(output))

		// 构建执行结果，包含每个命令的详细结果
		execResult := &ExecutionResult{
			Stdout:         output, // 保留合并后的输出用于向后兼容
			OutputSize:     outputSize,
			CommandResults: commandResults, // 每个命令的详细结果
		}

		// 检查所有命令的执行结果，判断整体任务是否成功
		// 成功标准：所有命令都必须成功（cmdResult.Success = true）
		allCommandsSuccess := true
		successCount := 0
		failedCount := 0

		if len(commandResults) > 0 {
			// 统计成功和失败的数量，并检查是否有失败的命令
			for _, cr := range commandResults {
				if cr.Success {
					successCount++
				} else {
					failedCount++
					allCommandsSuccess = false
				}
			}
		}

		// 根据命令执行结果判断整体任务状态
		if allCommandsSuccess {
			// 所有命令都成功，任务完成
			log.Printf("Successfully completed async command execution for task %s (all %d commands succeeded)",
				request.ID, len(commandResults))
			taskResult.Status = TaskStatusCompleted
			execResult.ExitCode = 0 // 成功时退出码为0

			if len(commandResults) > 0 {
				taskResult.Message = fmt.Sprintf("任务执行成功（%d 个命令全部成功，耗时 %d 毫秒，输出 %d 字节）",
					len(commandResults), duration, outputSize)
			} else {
				taskResult.Message = fmt.Sprintf("任务执行成功（耗时 %d 毫秒，输出 %d 字节）", duration, outputSize)
			}
		} else {
			// 有命令失败，任务失败（即使部分命令成功）
			log.Printf("Failed async command execution for task %s (%d/%d commands failed)",
				request.ID, failedCount, len(commandResults))
			taskResult.Status = TaskStatusFailed
			execResult.ExitCode = -1 // 失败时退出码为-1

			// 构建错误信息
			var failedCommands []string
			for _, cr := range commandResults {
				if !cr.Success {
					failedCommands = append(failedCommands, cr.Command)
				}
			}

			errorMsg := fmt.Sprintf("%d/%d 个命令执行失败: %v", failedCount, len(commandResults), failedCommands)
			taskResult.Message = fmt.Sprintf("任务执行失败（%d/%d 成功，%d 失败，耗时 %d 毫秒）",
				successCount, len(commandResults), failedCount, duration)

			taskResult.Error = &ErrorDetail{
				Type:    ErrorTypeExecution,
				Message: "部分命令执行失败",
				Details: errorMsg,
			}
		}

		taskResult.Result = execResult
		ap.asyncTasks.Store(request.ID, taskResult)
		_ = ap.saveTaskResultToMongoDB(taskResult) // 异步保存，忽略错误
	}()

	// 立即返回任务信息
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"id":        request.ID,
		"status":    string(TaskStatusRunning),
		"message":   "任务已提交，正在执行中",
		"task_info": taskInfo,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully sent async task ID: %s", request.ID)
}

// GetAsyncExecuteResultRequest 批量查询任务结果的请求
type GetAsyncExecuteResultRequest struct {
	TaskIDs               []string `json:"task_ids"`               // 任务ID列表
	OnlyCurrentController bool     `json:"only_current,omitempty"` // 是否只查询当前 controller 的任务
}

// GetAsyncExecuteResultResponse 批量查询任务结果的响应
type GetAsyncExecuteResultResponse struct {
	Results map[string]*AsyncTaskResult `json:"results"`          // 任务ID -> 任务结果的映射
	Errors  map[string]string           `json:"errors,omitempty"` // 任务ID -> 错误信息的映射（未找到或查询失败的任务）
}

// getSingleTaskResult 获取单个任务结果（内部函数）
// 注意：返回的是深拷贝，避免批量查询时结果覆盖
func (ap *ControllerAPI) getSingleTaskResult(taskID string, onlyCurrentController bool) (*AsyncTaskResult, error) {
	var taskResult *AsyncTaskResult

	// 1. 优先从内存缓存中获取（快速查询）
	value, ok := ap.asyncTasks.Load(taskID)
	if ok {
		if tr, ok := value.(*AsyncTaskResult); ok {
			// 如果只查询当前 controller 的任务，检查 controller_id 是否匹配
			if !onlyCurrentController || tr.TaskInfo.ControllerID == ap.controllerID {
				taskResult = tr
			}
		}
	}

	// 2. 如果内存中没有找到，从 MongoDB 查询
	if taskResult == nil {
		mongoResult, err := ap.loadTaskResultFromMongoDB(taskID)
		if err != nil {
			return nil, fmt.Errorf("task %s not found: %w", taskID, err)
		}
		// 如果只查询当前 controller 的任务，检查 controller_id 是否匹配
		if onlyCurrentController && mongoResult.TaskInfo.ControllerID != ap.controllerID {
			return nil, fmt.Errorf("task %s not found (not from current controller)", taskID)
		}
		taskResult = mongoResult

		// 如果是运行中的任务，需要同步到内存（因为可能是从其他实例查询的）
		if taskResult.Status == TaskStatusRunning {
			// 只同步当前 controller 的任务到内存
			if taskResult.TaskInfo.ControllerID == ap.controllerID {
				ap.asyncTasks.Store(taskID, taskResult)
			}
		}
	}

	// 3. 创建深拷贝，避免批量查询时结果覆盖
	// 使用 JSON 序列化和反序列化来创建深拷贝
	if taskResult != nil {
		jsonData, err := json.Marshal(taskResult)
		if err != nil {
			log.Printf("Error marshaling task result for task %s: %v", taskID, err)
			// 如果序列化失败，返回原始结果（虽然不理想，但比返回错误好）
			return taskResult, nil
		}

		var copiedResult AsyncTaskResult
		if err := json.Unmarshal(jsonData, &copiedResult); err != nil {
			log.Printf("Error unmarshaling task result for task %s: %v", taskID, err)
			// 如果反序列化失败，返回原始结果
			return taskResult, nil
		}

		return &copiedResult, nil
	}

	return taskResult, nil
}

func (ap *ControllerAPI) GetAsyncExecuteResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request GetAsyncExecuteResultRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	// 验证请求
	if len(request.TaskIDs) == 0 {
		http.Error(w, "task_ids cannot be empty", http.StatusBadRequest)
		return
	}

	// 限制批量查询的数量（防止请求过大）
	if len(request.TaskIDs) > 100 {
		http.Error(w, "too many task_ids (maximum 100)", http.StatusBadRequest)
		return
	}

	// 批量查询任务结果
	results := make(map[string]*AsyncTaskResult)
	errors := make(map[string]string)

	for _, taskID := range request.TaskIDs {
		taskResult, err := ap.getSingleTaskResult(taskID, request.OnlyCurrentController)
		if err != nil {
			errors[taskID] = err.Error()
		} else {
			results[taskID] = taskResult
		}
	}

	// 构建响应
	response := GetAsyncExecuteResultResponse{
		Results: results,
	}
	if len(errors) > 0 {
		response.Errors = errors
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

func (ap *ControllerAPI) PushConfig(w http.ResponseWriter, r *http.Request) {
	type PushConfigResp struct {
		Code    int      `json:"code"`
		Success bool     `json:"success"`
		Msg     []string `json:"msg"`
	}

	var recordErr = func(msg string, rp *PushConfigResp) {
		rp.Code = -1
		rp.Success = false
		rp.Msg = append(rp.Msg, msg)
	}

	resp := new(PushConfigResp)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		msg := fmt.Sprintf("Method not allowed: %s", r.Method)
		log.Println(msg)
		recordErr(msg, resp)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	var request map[string][][]byte
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		recordErr(fmt.Sprintf("Error decoding request: %v", err), resp)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	serverSnmpComment := "# 服务器SNMP"
	serverSnmpTmpPath := "/tmp/all_server_snmp.conf"
	serverSnmpFileName := "all_server_snmp.conf"
	snmpComment := "# 通用SNMP"
	snmpTmpPath := "/tmp/all_snmp.conf"
	snmpFileName := "all_snmp.conf"
	pingComment := "# 探活PING"
	pingTmpPath := "/tmp/all_ping.conf"
	pingFileName := "all_ping.conf"

	for serverInfoStr, contentBytes := range request {
		var pingContent string
		var snmpContent string
		var serverSnmpContent string
		for _, c := range contentBytes {
			content := string(c)
			if strings.Contains(content, pingComment) {
				pingContent = content
				continue
			}
			if strings.Contains(content, snmpComment) {
				snmpContent = content
				continue
			}
			if strings.Contains(content, serverSnmpComment) {
				serverSnmpContent = content
			}
		}
		serverInfo := strings.Split(serverInfoStr, ",")
		remoteIP := serverInfo[0]
		remoteUsername := serverInfo[1]
		remotePassword := serverInfo[2]
		remotePrivateKey := serverInfo[3]
		remoteDirPath := serverInfo[4]

		sshCmd := fmt.Sprintf("sshpass -p '%s' ", remotePassword)
		if len(pingContent) != 0 {
			if err := ap.writeTelegrafContent(pingTmpPath, []byte(pingContent)); err != nil {
				msg := fmt.Sprintf("server[%s]写入telegraf ping配置临时文件失败", remoteIP)
				log.Println(msg, err)
				recordErr(fmt.Sprintf("msg: %v", err), resp)
				continue
			}

			mkdirCmd := fmt.Sprintf("sshpass -p '%s' ssh -o StrictHostKeyChecking=no %s@%s \"mkdir -p %s\"", remotePassword, remoteUsername, remoteIP, remoteDirPath)

			// PING
			pingCmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -p %s %s@%s:%s", pingTmpPath, remoteUsername, remoteIP, remoteDirPath+"/"+pingFileName)
			pingCommand := mkdirCmd + " &&\n" + sshCmd + pingCmd

			log.Println("ping copy指令:", pingCommand)
			ctx, _ := context.WithTimeout(context.Background(), time.Duration(25)*time.Second)
			//defer cancel()
			pingCmdExec := exec.CommandContext(ctx, "/bin/bash", "-c", pingCommand)

			output, err := pingCmdExec.CombinedOutput()
			if err != nil {
				msg := fmt.Sprintf("server[%s]ping command[%s]执行失败", remoteIP, pingCommand)
				log.Println(msg, err)
				recordErr(fmt.Sprintf("msg: %s %v", msg+":"+string(output), err), resp)
				continue
			}
			log.Println("ping command output:", string(output))
			_ = os.Remove(pingTmpPath)
		}

		if len(snmpContent) != 0 {
			if err := ap.writeTelegrafContent(snmpTmpPath, []byte(snmpContent)); err != nil {
				msg := fmt.Sprintf("server[%s]写入telegraf snmp配置临时文件失败", remoteIP)
				log.Println(msg, err)
				recordErr(fmt.Sprintf("msg: %v", err), resp)
				continue
			}
			// SNMP
			snmpCmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -p %s %s@%s:%s", snmpTmpPath, remoteUsername, remoteIP, remoteDirPath+"/"+snmpFileName)
			snmpCommand := sshCmd + snmpCmd

			log.Println("snmp copy指令:", snmpCommand)
			ctx2, _ := context.WithTimeout(context.Background(), time.Duration(25)*time.Second)
			//defer cancel2()
			snmpCmdExec := exec.CommandContext(ctx2, "/bin/bash", "-c", snmpCommand)

			output2, err := snmpCmdExec.CombinedOutput()
			if err != nil {
				msg := fmt.Sprintf("server[%s]snmp command[%s]执行失败", remoteIP, snmpCommand)
				log.Println(msg, err)
				recordErr(fmt.Sprintf("msg %s %v", string(output2), err), resp)
				continue
			}
			log.Println("snmp command output:", string(output2))
			_ = os.Remove(snmpTmpPath)
		}

		if len(serverSnmpContent) != 0 {
			if err := ap.writeTelegrafContent(serverSnmpTmpPath, []byte(serverSnmpContent)); err != nil {
				msg := fmt.Sprintf("server[%s]写入telegraf server snmp配置临时文件失败", remoteIP)
				log.Println(msg, err)
				recordErr(fmt.Sprintf("msg: %v", err), resp)
				continue
			}
			// Server SNMP
			serverSnmpCmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -p %s %s@%s:%s", serverSnmpTmpPath, remoteUsername, remoteIP, remoteDirPath+"/"+serverSnmpFileName)
			serverSnmpCommand := sshCmd + serverSnmpCmd

			log.Println("server snmp copy指令:", serverSnmpCommand)
			ctx3, _ := context.WithTimeout(context.Background(), time.Duration(25)*time.Second)
			//defer cancel2()
			serverSnmpCmdExec := exec.CommandContext(ctx3, "/bin/bash", "-c", serverSnmpCommand)

			output3, err := serverSnmpCmdExec.CombinedOutput()
			if err != nil {
				msg := fmt.Sprintf("server[%s]server snmp command[%s]执行失败", remoteIP, serverSnmpCommand)
				log.Println(msg, err)
				recordErr(fmt.Sprintf("msg %s %v", string(output3), err), resp)
				continue
			}
			log.Println("server snmp command output:", string(output3))
			_ = os.Remove(serverSnmpTmpPath)
		}

		log.Println(fmt.Sprintf("当前server[%s]临时配置文件信息全部写入完成", remoteIP))

		restartCmd := "kill -HUP `pidof oneops-telegraf`"
		base := &terminal.BaseInfo{
			Host:       remoteIP,
			Username:   remoteUsername,
			Password:   remotePassword,
			PrivateKey: remotePrivateKey,
		}

		var cmdList []*terminalmode.Command
		newExec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
		var options2 []interface{}
		options2 = append(options2, restartCmd)
		for index, ops := range options2 {
			key := strings.Join(strings.Fields(ops.(string)), "_")
			key = fmt.Sprintf("%s_%d", key, index+1)

			cmd := terminalmode.NewCommand(ops.(string), "", 5, key, "")
			newExec.AddCommand(cmd)
			cmdList = append(cmdList, cmd)
		}
		newExec.Id = uuid.Must(uuid.NewV4()).String()
		execResult := newExec.Run(false)
		if execResult.Error() != nil {
			err := execResult.Error()
			msg := fmt.Sprintf("server[%s]restart command[%s]执行失败", remoteIP, restartCmd)
			log.Println(msg, err)
			recordErr(fmt.Sprintf("msg: %v", err), resp)
			continue
		}
		log.Println(fmt.Sprintf("server[%s]telegraf配置重新加载完成", remoteIP))
	}

	//最后是统计输出(辨别是否全部成功或失败)
	if len(resp.Msg) == 0 {
		resp.Code = 0
		resp.Success = true
	}
	log.Println("resp----> code=", resp.Code, " success=", resp.Success, " msg=", resp.Msg)
	_ = json.NewEncoder(w).Encode(resp)
}

// extractConfigsFromDeviceConfig 从 DeviceConfig 中提取第一个可用的 modeConfig 和 hubConfig
func (ap *ControllerAPI) extractConfigsFromDeviceConfig(deviceConfig *structs.DeviceConfig) (*structs.ModeConfig, *structs.HubConfig) {
	if deviceConfig == nil {
		return nil, nil
	}

	// 遍历 Pipeline 阶段，查找 Collect 类型的阶段
	for _, stage := range deviceConfig.Pipeline {
		if stage.Type == "Collect" && len(stage.Config.CollectConfig.CollectItems) > 0 {
			// 使用第一个 CollectItem 的配置
			item := stage.Config.CollectConfig.CollectItems[0]

			// 验证配置是否有效（至少 hubConfig 不为空）
			if len(item.HubConfig.Dispatches) > 0 {
				return &item.ModeConfig, &item.HubConfig
			}
		}
	}

	return nil, nil
}

// getDefaultHubConfig 返回默认的 hubConfig（用于降级处理）
func (ap *ControllerAPI) getDefaultHubConfig() *structs.HubConfig {
	return &structs.HubConfig{
		Dispatches: []structs.DispatchConfig{
			{
				Name: "InitCompleted",
				Regex: []string{
					"\\$ $",          // bash prompt
					"# $",            // root prompt
					"^[^\\n]+[#$] $", // 通用 shell prompt
					"> ",             // 网络设备命令提示符
					"]$",             // 网络设备命令提示符
				},
				Action: "init_completed",
			},
		},
	}
}

func (ap *ControllerAPI) writeTelegrafContent(filePath string, content []byte) (err error) {
	dir := filepath.Dir(filePath)

	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		// 处理错误
		logger.Error("目录创建失败", zap.Error(err))
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		// 处理错误
		logger.Error("文件创建失败", zap.Error(err))
		return err
	}

	// 将内容写入目标文件
	_, err = file.Write(content)
	if err != nil {
		logger.Error("无法写入文件内容", zap.Error(err))
		return
	}
	defer func(file *os.File) {
		if err = file.Close(); err != nil {
			fmt.Println("文件IO关闭异常", err)
		}
	}(file)
	return
}

// MakeL3TemplatesRequest represents the request structure for MakeL3Templates API
type MakeL3TemplatesRequest struct {
	SourceInfo *agentStruct.NodemapInfo `json:"source_info"`
	RecordCode string                   `json:"meta_node_map_name"`
}

// MakeL3TemplatesResponse represents the response structure for MakeL3Templates API
type MakeL3TemplatesResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Data    *model.TemplatesReplay `json:"data,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// FirewallPolicyQueryRequest represents the request structure for FirewallPolicyQuery API
// type FirewallPolicyQueryRequest struct {
// 	QueryInfo       *agentStruct.L3Query `json:"query_info"`
// 	MetaNodeMapName string               `json:"meta_node_map_name"`
// }

type FirewallPolicyQueryRequest struct {
	SourceInfo *agentStruct.NodemapInfo `json:"source_info"`
	QueryInfo  *agentStruct.L3Query     `json:"query_info"`
	RecordCode string                   `json:"record_code"`
}

// FirewallPolicyQueryResponse represents the response structure for FirewallPolicyQuery API
type FirewallPolicyQueryResponse struct {
	Success bool                    `json:"success"`
	Message string                  `json:"message"`
	Data    *agentStruct.PolicyData `json:"data,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// MakeL3Templates handles POST /api/v1/make_l3_templates
// This endpoint calls the L3 service to generate firewall configuration templates
func (ap *ControllerAPI) MakeL3Templates(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request for MakeL3Templates")

	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request MakeL3TemplatesRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if request.SourceInfo == nil {
		http.Error(w, "source_info is required", http.StatusBadRequest)
		return
	}

	if request.RecordCode == "" {
		http.Error(w, "meta_node_map_name is required", http.StatusBadRequest)
		return
	}

	// TODO: In a production environment, you would need to retrieve the actual MetaNodeMap
	// based on the meta_node_map_name. For now, we'll create a placeholder.
	// In a real implementation, this would likely involve loading the MetaNodeMap from
	// a configuration or database.

	// Create a placeholder MetaNodeMap - in a real implementation, this should be loaded properly
	placeholderMetaNodeMap := meta.MetaNodeMap{
		Name: request.RecordCode,
		// In a real implementation, you would populate this with actual MetaNode data
		MetaNodes: []meta.MetaNode{},
	}

	// Create L3 service instance
	l3Service := &l3service.NodemapService{
		MNM: placeholderMetaNodeMap,
	}

	// Create result container
	result := &model.TemplatesReplay{}

	// Call MakeL3Templates function
	err := l3Service.MakeL3Templates(request.SourceInfo, result)

	// Prepare response
	response := MakeL3TemplatesResponse{}

	if err != nil {
		log.Printf("Error executing MakeL3Templates: %v", err)
		response.Success = false
		response.Error = err.Error()
		response.Message = "Failed to generate L3 templates"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		response.Success = true
		response.Data = result
		response.Message = "L3 templates generated successfully"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}

	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		log.Printf("Error encoding response: %v", encodeErr)
		http.Error(w, fmt.Sprintf("Error encoding response: %v", encodeErr), http.StatusInternalServerError)
		return
	}

	log.Println("Successfully processed MakeL3Templates request")
}

// FirewallPolicyQuery handles POST /api/v1/firewall_policy_query
// This endpoint calls the L3 service to query firewall policies
func (ap *ControllerAPI) FirewallPolicyQuery(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request for FirewallPolicyQuery")

	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request FirewallPolicyQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if request.QueryInfo == nil {
		http.Error(w, "query_info is required", http.StatusBadRequest)
		return
	}

	// Check if SourceInfo is provided
	if request.SourceInfo == nil {
		http.Error(w, "source_info is required", http.StatusBadRequest)
		return
	}

	placeholderMetaNodeMap := meta.MetaNodeMap{
		Name: request.RecordCode,
		// In a real implementation, you would populate this with actual MetaNode data from SourceInfo
		MetaNodes: []meta.MetaNode{},
	}

	// Create L3 service instance
	l3Service := &l3service.NodemapService{
		MNM: placeholderMetaNodeMap,
	}

	// Create result container
	result := &agentStruct.PolicyData{}

	// When using SourceInfo, we need to create device configs from SourceInfo
	// similar to how MakeL3Templates works
	deviceConfigs := makeDeviceConfigFromSourceInfo(request.SourceInfo)

	// 获取模板路径配置
	templatePath := ""
	if ap.controller != nil && ap.controller.ConfigManager != nil && ap.controller.ConfigManager.Config != nil {
		templatePath = ap.controller.ConfigManager.Config.BaseConfig.FirewallTemplatePath
	}

	// 使用缓存获取或创建 NodeMap（force=false 以启用缓存）
	nm, ctx, err := ap.getOrCreateNodeMap(request.RecordCode, deviceConfigs, templatePath, false, 123456)
	if err != nil {
		log.Printf("Error creating NodeMap: %v", err)
		errorResponse := FirewallPolicyQueryResponse{
			Success: false,
			Error:   err.Error(),
			Message: "Failed to create NodeMap",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}
	_ = ctx // 使用 ctx 如果需要

	// Update the service with the new NodeMap
	// Create a new MetaNodeMap from the NodeMap
	newMetaNodeMap := meta.MetaNodeMap{
		Name: request.RecordCode,
		// In a real implementation, you would populate this with actual MetaNode data from the NodeMap
		MetaNodes: []meta.MetaNode{},
	}
	l3Service.MNM = newMetaNodeMap

	// Call L3NodeMapQuery function with the generated NodeMap
	// Pass the already created NodeMap to avoid duplicate creation
	err = l3Service.L3NodeMapQuery(context.Background(), request.QueryInfo, deviceConfigs, result, nm)
	// Prepare response
	response := FirewallPolicyQueryResponse{}

	if err != nil {
		log.Printf("Error executing L3NodeMapQuery: %v", err)
		response.Success = false
		response.Error = err.Error()
		response.Message = "Failed to query firewall policies"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		response.Success = true
		response.Data = result
		response.Message = "Firewall policies queried successfully"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}

	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		log.Printf("Error encoding response: %v", encodeErr)
		http.Error(w, fmt.Sprintf("Error encoding response: %v", encodeErr), http.StatusInternalServerError)
		return
	}

	log.Println("Successfully processed FirewallPolicyQuery request")
}

// ComparePolicyRequest represents the request structure for ComparePolicy API
type ComparePolicyRequest struct {
	SourceInfo *agentStruct.NodemapInfo `json:"source_info"` // 设备信息，用于构建 NodeMap
	NodeName   string                   `json:"node_name"`   // 节点名称
	RuleName   string                   `json:"rule_name"`   // 规则名称
	Intent     *structs.IntentPair      `json:"intent"`      // 策略意图
	RecordCode string                   `json:"record_code"` // 记录代码
}

// ComparePolicyResponse represents the response structure for ComparePolicy API
type ComparePolicyResponse struct {
	Success bool                           `json:"success"`
	Message string                         `json:"message"`
	Data    *l3service.ComparePolicyResult `json:"data,omitempty"`
	Error   string                         `json:"error,omitempty"`
}

// ComparePolicy handles POST /api/v1/compare_policy
// This endpoint compares a firewall policy with an intent
func (ap *ControllerAPI) ComparePolicy(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request for ComparePolicy")

	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request ComparePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if request.NodeName == "" {
		http.Error(w, "node_name is required", http.StatusBadRequest)
		return
	}

	if request.RuleName == "" {
		http.Error(w, "rule_name is required", http.StatusBadRequest)
		return
	}

	if request.Intent == nil {
		http.Error(w, "intent is required", http.StatusBadRequest)
		return
	}

	// Check if SourceInfo is provided for NodeMap creation
	if request.SourceInfo == nil {
		http.Error(w, "source_info is required", http.StatusBadRequest)
		return
	}

	// Create placeholder MetaNodeMap
	placeholderMetaNodeMap := meta.MetaNodeMap{
		Name:      request.RecordCode,
		MetaNodes: []meta.MetaNode{},
	}

	// Create L3 service instance
	l3Service := &l3service.NodemapService{
		MNM: placeholderMetaNodeMap,
	}

	// Create device configs from SourceInfo
	deviceConfigs := makeDeviceConfigFromSourceInfo(request.SourceInfo)

	// 获取模板路径配置
	templatePath := ""
	if ap.controller != nil && ap.controller.ConfigManager != nil && ap.controller.ConfigManager.Config != nil {
		templatePath = ap.controller.ConfigManager.Config.BaseConfig.FirewallTemplatePath
	}

	// 使用缓存获取或创建 NodeMap（force=false 以启用缓存）
	nm, ctx, err := ap.getOrCreateNodeMap(request.RecordCode, deviceConfigs, templatePath, false, 123456)
	if err != nil {
		log.Printf("Error creating NodeMap: %v", err)
		errorResponse := ComparePolicyResponse{
			Success: false,
			Error:   err.Error(),
			Message: "Failed to create NodeMap",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}
	_ = ctx // 使用 ctx 如果需要

	// Convert IntentPair to policy.Intent
	intent := &request.Intent.Info

	// Call Compare function
	result, err := l3Service.Compare(request.NodeName, request.RuleName, intent, nm)

	// Prepare response
	response := ComparePolicyResponse{}

	if err != nil {
		log.Printf("Error executing Compare: %v", err)
		response.Success = false
		response.Error = err.Error()
		response.Message = "Failed to compare policy"
		// 即使有错误，如果 result 不为 nil，也返回部分结果
		if result != nil {
			response.Data = result
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		response.Success = true
		response.Data = result
		response.Message = "Policy compared successfully"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}

	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		log.Printf("Error encoding response: %v", encodeErr)
		http.Error(w, fmt.Sprintf("Error encoding response: %v", encodeErr), http.StatusInternalServerError)
		return
	}

	log.Println("Successfully processed ComparePolicy request")
}

// ApplyBlacklistWhitelist handles POST /api/v1/blacklist_whitelist/apply
// This endpoint applies blacklist/whitelist (add or remove IPs)
func (ap *ControllerAPI) ApplyBlacklistWhitelist(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request for ApplyBlacklistWhitelist")

	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request l3service.BlacklistWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if request.DeviceName == "" {
		http.Error(w, "device_name is required", http.StatusBadRequest)
		return
	}

	if request.PresetConfig == nil {
		http.Error(w, "preset_config is required", http.StatusBadRequest)
		return
	}

	// Create placeholder MetaNodeMap
	placeholderMetaNodeMap := meta.MetaNodeMap{
		Name:      request.DeviceName,
		MetaNodes: []meta.MetaNode{},
	}

	// Create L3 service instance
	l3Service := &l3service.NodemapService{
		MNM: placeholderMetaNodeMap,
	}

	// For MVP, we need device configs - this should come from the request or be retrieved
	// For now, we'll create an empty config list (this needs to be improved)
	deviceConfigs := []config.DeviceConfig{}

	// Call ApplyBlacklistWhitelist
	response, err := l3Service.ApplyBlacklistWhitelist(deviceConfigs, &request, nil)

	// Prepare HTTP response
	if err != nil {
		log.Printf("Error executing ApplyBlacklistWhitelist: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		errorResponse := map[string]interface{}{
			"success": false,
			"error":   err.Error(),
			"message": "Failed to apply blacklist/whitelist",
		}
		if response != nil {
			errorResponse["data"] = response
		}
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	log.Println("Successfully processed ApplyBlacklistWhitelist request")
}

// CheckPresetConfig handles POST /api/v1/blacklist_whitelist/check_preset
// This endpoint checks if preset configurations are ready
func (ap *ControllerAPI) CheckPresetConfig(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request for CheckPresetConfig")

	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request l3service.PresetConfigCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if request.DeviceName == "" {
		http.Error(w, "device_name is required", http.StatusBadRequest)
		return
	}

	if request.PresetConfig == nil {
		http.Error(w, "preset_config is required", http.StatusBadRequest)
		return
	}

	// Create placeholder MetaNodeMap
	placeholderMetaNodeMap := meta.MetaNodeMap{
		Name:      request.DeviceName,
		MetaNodes: []meta.MetaNode{},
	}

	// Create L3 service instance
	l3Service := &l3service.NodemapService{
		MNM: placeholderMetaNodeMap,
	}

	// For MVP, we need device configs - this should come from the request or be retrieved
	deviceConfigs := []config.DeviceConfig{}

	// Call CheckPresetConfig
	response, err := l3Service.CheckPresetConfig(deviceConfigs, &request, nil)

	// Prepare HTTP response
	if err != nil {
		log.Printf("Error executing CheckPresetConfig: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		errorResponse := map[string]interface{}{
			"success": false,
			"error":   err.Error(),
			"message": "Failed to check preset config",
		}
		if response != nil {
			errorResponse["data"] = response
		}
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	log.Println("Successfully processed CheckPresetConfig request")
}

// DetectDevice 检测设备接口
func (ap *ControllerAPI) DetectDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		IP             string `json:"ip"`
		SNMPCommunity  string `json:"snmp_community"`
		SSHCredentials *struct {
			Username   string `json:"username"`
			Password   string `json:"password"`
			Port       int    `json:"port"`
			PrivateKey string `json:"private_key"`
		} `json:"ssh_credentials"`
		TelnetCredentials *struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Port     int    `json:"port"`
		} `json:"telnet_credentials"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding detection request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	// 创建检测器
	deviceDetector, err := detector.NewDeviceDetector(ap.controller.ConfigManager.Config.BaseConfig.PipelineTemplates)
	if err != nil {
		log.Printf("Failed to create detector: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create detector: %v", err), http.StatusInternalServerError)
		return
	}

	// 构建检测请求
	detectionRequest := &detector.DetectionRequest{
		IP:            request.IP,
		SNMPCommunity: request.SNMPCommunity,
	}

	if request.SSHCredentials != nil {
		detectionRequest.SSHCredentials = &detector.SSHCredentials{
			Username:   request.SSHCredentials.Username,
			Password:   request.SSHCredentials.Password,
			Port:       request.SSHCredentials.Port,
			PrivateKey: request.SSHCredentials.PrivateKey,
		}
	}

	if request.TelnetCredentials != nil {
		detectionRequest.TelnetCredentials = &detector.TelnetCredentials{
			Username: request.TelnetCredentials.Username,
			Password: request.TelnetCredentials.Password,
			Port:     request.TelnetCredentials.Port,
		}
	}

	// 执行检测
	result, err := deviceDetector.Detect(detectionRequest)
	if err != nil {
		log.Printf("Device detection failed: %v", err)
		http.Error(w, fmt.Sprintf("Device detection failed: %v", err), http.StatusInternalServerError)
		return
	}

	// 检查是否包含完整配置（默认不包含，减少响应大小）
	includeConfig := r.URL.Query().Get("include_config") == "true"

	// 构建响应
	response := map[string]interface{}{
		"manufacturer": result.Manufacturer,
		"platform":     result.Platform,
		"version":      result.Version,
		"catalog":      result.Catalog,
		"confidence":   result.Confidence,
		"detected_at":  result.DetectedAt,
	}

	// 如果请求包含完整配置，则添加
	if includeConfig {
		response["device_config"] = result.DeviceConfig
	} else if result.DeviceConfig != nil {
		// 否则只返回配置的摘要信息
		response["device_config_summary"] = map[string]interface{}{
			"vendor":    result.DeviceConfig.Vendor,
			"platform":  result.DeviceConfig.Platform,
			"version":   result.DeviceConfig.Version,
			"available": true,
		}
	}

	// 如果有错误，也包含在响应中
	if len(result.Errors) > 0 {
		errorMessages := make([]string, 0, len(result.Errors))
		for _, err := range result.Errors {
			errorMessages = append(errorMessages, err.Error())
		}
		response["errors"] = errorMessages
	}

	// 返回结果
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// makeDeviceConfigFromSourceInfo creates device configs from SourceInfo similar to MakeL3Templates
func makeDeviceConfigFromSourceInfo(info *agentStruct.NodemapInfo) []config.DeviceConfig {
	var deviceConfigs []config.DeviceConfig
	for _, v := range info.DeviceInfos {
		dconf := config.DeviceConfig{}
		dconf.Config = v.ConfigText
		dconf.Mode = v.DeviceBase.Mode
		dconf.MetaData = v.MetaData

		dconf.Host = v.DeviceBase.Host
		dconf.Port = v.DeviceBase.Port
		dconf.Mode = v.DeviceBase.Mode
		dconf.Community = v.DeviceBase.Community
		dconf.Username = v.DeviceBase.Username
		dconf.Password = v.DeviceBase.Password
		dconf.Telnet = v.DeviceBase.Telnet
		dconf.AuthPass = v.DeviceBase.AuthPass

		for _, ipv4Area := range v.Ipv4Area {
			area := config.AreaInfo{}
			area.NodeName = v.DeviceRemoteInfo.DeviceName
			area.Name = ipv4Area.Name
			area.Interface = ipv4Area.Interface
			area.Force = true
			dconf.Ipv4Area = append(dconf.Ipv4Area, &area)
		}

		for _, ipv6Area := range v.Ipv6Area {
			area := config.AreaInfo{}
			area.NodeName = v.DeviceRemoteInfo.DeviceName
			area.Name = ipv6Area.Name
			area.Interface = ipv6Area.Interface
			area.Force = true
			dconf.Ipv6Area = append(dconf.Ipv6Area, &area)
		}

		for _, ipv4Stub := range v.Ipv4Stub {
			stub := config.StubConfigInfo{}
			stub.PortName = ipv4Stub.PortName
			dconf.Ipv4Stub = append(dconf.Ipv4Stub, &stub)
		}

		for _, ipv6Stub := range v.Ipv6Stub {
			stub := config.StubConfigInfo{}
			stub.PortName = ipv6Stub.PortName
			dconf.Ipv6Stub = append(dconf.Ipv6Stub, &stub)
		}

		// 处理 SecurityZones：将 SecurityZone 的网段信息转换为 SecurityZoneInfo，用于节点定位
		// 遍历每个 SecurityZone，将其 NetworkSegments 转换为 SecurityZoneInfo
		for _, zoneInfo := range v.SecurityZones {
			// 收集该 Zone 的所有网段
			var ipv4Segments []string
			var ipv6Segments []string

			for _, segment := range zoneInfo.NetworkSegments {
				if segment.NetworkSegment == "" {
					continue
				}
				// 判断是 IPv4 还是 IPv6（简单判断：包含 ":" 的是 IPv6）
				if strings.Contains(segment.NetworkSegment, ":") {
					ipv6Segments = append(ipv6Segments, segment.NetworkSegment)
				} else {
					ipv4Segments = append(ipv4Segments, segment.NetworkSegment)
				}
			}

			// 创建 IPv4 SecurityZoneInfo
			if len(ipv4Segments) > 0 {
				securityZoneInfo := &config.SecurityZoneInfo{
					ConfigZoneName:  zoneInfo.ConfigZoneName,       // 配置中的 Zone 名称
					NetworkSegments: ipv4Segments,                  // Zone 的所有 IPv4 网段
					NodeName:        v.DeviceRemoteInfo.DeviceName, // 关联的设备节点名称
					// Vrf 留空，使用默认 VRF
					Priority: 0, // 默认优先级
				}
				dconf.Ipv4SecurityZones = append(dconf.Ipv4SecurityZones, securityZoneInfo)
			}

			// 创建 IPv6 SecurityZoneInfo
			if len(ipv6Segments) > 0 {
				securityZoneInfo := &config.SecurityZoneInfo{
					ConfigZoneName:  zoneInfo.ConfigZoneName,       // 配置中的 Zone 名称
					NetworkSegments: ipv6Segments,                  // Zone 的所有 IPv6 网段
					NodeName:        v.DeviceRemoteInfo.DeviceName, // 关联的设备节点名称
					// Vrf 留空，使用默认 VRF
					Priority: 0, // 默认优先级
				}
				dconf.Ipv6SecurityZones = append(dconf.Ipv6SecurityZones, securityZoneInfo)
			}
		}

		deviceConfigs = append(deviceConfigs, dconf)
	}
	return deviceConfigs
}
