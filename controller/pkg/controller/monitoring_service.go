package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MonitoringService struct {
	mongoClient     *mongo.Client
	database        string
	configGenerator *TelegrafConfigGenerator
	templateService *PluginTemplateService
	telegrafManager *TelegrafManager
}

func ProvideMonitoringService(
	mongoClient *mongo.Client,
	config *Config,
	configGenerator *TelegrafConfigGenerator,
	templateService *PluginTemplateService,
	telegrafManager *TelegrafManager,
) (*MonitoringService, error) {
	return &MonitoringService{
		mongoClient:     mongoClient,
		database:        "controller",
		configGenerator: configGenerator,
		templateService: templateService,
		telegrafManager: telegrafManager,
	}, nil
}

// CreateTask 创建监控任务
func (ms *MonitoringService) CreateTask(ctx context.Context, task *models.MonitoringTask) error {
	if ms.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("monitoring_tasks")

	// 生成 ID
	if task.ID == "" {
		id, err := uuid.NewV4()
		if err != nil {
			return fmt.Errorf("failed to generate task ID: %w", err)
		}
		task.ID = id.String()
	}

	// 设置默认值
	if task.Status == "" {
		task.Status = models.TaskStatusStopped
	}
	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now()
	}
	task.UpdatedAt = time.Now()

	// 验证插件配置
	for i := range task.Plugins {
		if task.Plugins[i].ID == "" {
			id, err := uuid.NewV4()
			if err != nil {
				return fmt.Errorf("failed to generate plugin ID: %w", err)
			}
			task.Plugins[i].ID = id.String()
		}
		if task.Plugins[i].Priority == 0 {
			task.Plugins[i].Priority = 100 // 默认优先级
		}
	}

	_, err := collection.InsertOne(ctx, task)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("task %s already exists", task.ID)
		}
		return fmt.Errorf("failed to create task: %w", err)
	}

	return nil
}

// GetTask 获取监控任务
func (ms *MonitoringService) GetTask(ctx context.Context, taskID string) (*models.MonitoringTask, error) {
	if ms.mongoClient == nil {
		return nil, fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("monitoring_tasks")

	var task models.MonitoringTask
	err := collection.FindOne(ctx, bson.M{"_id": taskID}).Decode(&task)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("task %s not found", taskID)
		}
		return nil, fmt.Errorf("failed to get task: %w", err)
	}

	return &task, nil
}

// ListTasks 列出监控任务
func (ms *MonitoringService) ListTasks(ctx context.Context, filter map[string]interface{}) ([]*models.MonitoringTask, error) {
	if ms.mongoClient == nil {
		return nil, fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("monitoring_tasks")

	bsonFilter := bson.M{}
	if filter != nil {
		for k, v := range filter {
			bsonFilter[k] = v
		}
	}

	cursor, err := collection.Find(ctx, bsonFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list tasks: %w", err)
	}
	defer cursor.Close(ctx)

	var tasks []*models.MonitoringTask
	if err := cursor.All(ctx, &tasks); err != nil {
		return nil, fmt.Errorf("failed to decode tasks: %w", err)
	}

	return tasks, nil
}

// UpdateTask 更新监控任务
func (ms *MonitoringService) UpdateTask(ctx context.Context, taskID string, task *models.MonitoringTask) error {
	if ms.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("monitoring_tasks")

	task.ID = taskID
	task.UpdatedAt = time.Now()

	filter := bson.M{"_id": taskID}
	update := bson.M{"$set": task}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update task: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("task %s not found", taskID)
	}

	return nil
}

// DeleteTask 删除监控任务
func (ms *MonitoringService) DeleteTask(ctx context.Context, taskID string) error {
	if ms.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("monitoring_tasks")

	result, err := collection.DeleteOne(ctx, bson.M{"_id": taskID})
	if err != nil {
		return fmt.Errorf("failed to delete task: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("task %s not found", taskID)
	}

	return nil
}

// StartTask 启动监控任务
func (ms *MonitoringService) StartTask(ctx context.Context, taskID string) error {
	task, err := ms.GetTask(ctx, taskID)
	if err != nil {
		return err
	}

	if task.Status == models.TaskStatusActive {
		return fmt.Errorf("task %s is already active", taskID)
	}

	task.Status = models.TaskStatusActive
	if err := ms.UpdateTask(ctx, taskID, task); err != nil {
		return err
	}

	// 重新生成并应用配置
	return ms.reloadTelegrafConfig(ctx)
}

// StopTask 停止监控任务
func (ms *MonitoringService) StopTask(ctx context.Context, taskID string) error {
	task, err := ms.GetTask(ctx, taskID)
	if err != nil {
		return err
	}

	if task.Status == models.TaskStatusStopped {
		return fmt.Errorf("task %s is already stopped", taskID)
	}

	task.Status = models.TaskStatusStopped
	if err := ms.UpdateTask(ctx, taskID, task); err != nil {
		return err
	}

	// 重新生成并应用配置
	return ms.reloadTelegrafConfig(ctx)
}

// PauseTask 暂停监控任务
func (ms *MonitoringService) PauseTask(ctx context.Context, taskID string) error {
	task, err := ms.GetTask(ctx, taskID)
	if err != nil {
		return err
	}

	if task.Status == models.TaskStatusPaused {
		return fmt.Errorf("task %s is already paused", taskID)
	}

	task.Status = models.TaskStatusPaused
	if err := ms.UpdateTask(ctx, taskID, task); err != nil {
		return err
	}

	// 重新生成并应用配置
	return ms.reloadTelegrafConfig(ctx)
}

// CreatePlugin 创建独立插件配置
func (ms *MonitoringService) CreatePlugin(ctx context.Context, plugin *models.PluginConfig) error {
	if ms.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("plugin_configs")

	// 生成 ID
	if plugin.ID == "" {
		id, err := uuid.NewV4()
		if err != nil {
			return fmt.Errorf("failed to generate plugin ID: %w", err)
		}
		plugin.ID = id.String()
	}

	if plugin.Priority == 0 {
		plugin.Priority = 100
	}

	_, err := collection.InsertOne(ctx, plugin)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("plugin %s already exists", plugin.ID)
		}
		return fmt.Errorf("failed to create plugin: %w", err)
	}

	// 如果插件已启用，重新加载配置
	if plugin.Enabled {
		return ms.reloadTelegrafConfig(ctx)
	}

	return nil
}

// GetPlugin 获取插件配置
func (ms *MonitoringService) GetPlugin(ctx context.Context, pluginID string) (*models.PluginConfig, error) {
	if ms.mongoClient == nil {
		return nil, fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("plugin_configs")

	var plugin models.PluginConfig
	err := collection.FindOne(ctx, bson.M{"id": pluginID}).Decode(&plugin)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("plugin %s not found", pluginID)
		}
		return nil, fmt.Errorf("failed to get plugin: %w", err)
	}

	return &plugin, nil
}

// ListPlugins 列出插件配置
func (ms *MonitoringService) ListPlugins(ctx context.Context, filter map[string]interface{}) ([]*models.PluginConfig, error) {
	if ms.mongoClient == nil {
		return nil, fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("plugin_configs")

	bsonFilter := bson.M{}
	if filter != nil {
		for k, v := range filter {
			bsonFilter[k] = v
		}
	}

	cursor, err := collection.Find(ctx, bsonFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list plugins: %w", err)
	}
	defer cursor.Close(ctx)

	var plugins []*models.PluginConfig
	if err := cursor.All(ctx, &plugins); err != nil {
		return nil, fmt.Errorf("failed to decode plugins: %w", err)
	}

	return plugins, nil
}

// UpdatePlugin 更新插件配置
func (ms *MonitoringService) UpdatePlugin(ctx context.Context, pluginID string, plugin *models.PluginConfig) error {
	if ms.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("plugin_configs")

	plugin.ID = pluginID
	filter := bson.M{"id": pluginID}
	update := bson.M{"$set": plugin}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update plugin: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("plugin %s not found", pluginID)
	}

	// 如果插件已启用，重新加载配置
	if plugin.Enabled {
		return ms.reloadTelegrafConfig(ctx)
	}

	return nil
}

// DeletePlugin 删除插件配置
func (ms *MonitoringService) DeletePlugin(ctx context.Context, pluginID string) error {
	if ms.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := ms.mongoClient.Database(ms.database).Collection("plugin_configs")

	result, err := collection.DeleteOne(ctx, bson.M{"id": pluginID})
	if err != nil {
		return fmt.Errorf("failed to delete plugin: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("plugin %s not found", pluginID)
	}

	// 重新加载配置
	return ms.reloadTelegrafConfig(ctx)
}

// GetStatus 获取监控平台状态
func (ms *MonitoringService) GetStatus(ctx context.Context) (*models.MonitoringStatus, error) {
	// 获取所有任务
	tasks, err := ms.ListTasks(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list tasks: %w", err)
	}

	activeTasks := 0
	for _, task := range tasks {
		if task.Status == models.TaskStatusActive {
			activeTasks++
		}
	}

	// 获取所有插件
	plugins, err := ms.ListPlugins(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list plugins: %w", err)
	}

	// 获取所有模板
	templates, err := ms.templateService.ListTemplates(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}

	// 获取 telegraf 状态
	telegrafStatus := "unknown"
	if ms.telegrafManager != nil {
		status := ms.telegrafManager.GetStatus()
		if statusStr, ok := status["status"].(string); ok {
			telegrafStatus = statusStr
		}
	}

	return &models.MonitoringStatus{
		TelegrafStatus: telegrafStatus,
		ActiveTasks:    activeTasks,
		TotalTasks:     len(tasks),
		TotalPlugins:   len(plugins),
		TotalTemplates: len(templates),
		ConfigVersion:  fmt.Sprintf("%d", time.Now().Unix()),
	}, nil
}

// ReloadTelegrafConfig 重新加载 telegraf 配置（公开方法）
func (ms *MonitoringService) ReloadTelegrafConfig(ctx context.Context) error {
	return ms.reloadTelegrafConfig(ctx)
}

// reloadTelegrafConfig 重新加载 telegraf 配置
func (ms *MonitoringService) reloadTelegrafConfig(ctx context.Context) error {
	// 获取所有激活的任务
	tasks, err := ms.ListTasks(ctx, map[string]interface{}{
		"status": models.TaskStatusActive,
	})
	if err != nil {
		return fmt.Errorf("failed to list active tasks: %w", err)
	}

	// 获取所有启用的独立插件
	plugins, err := ms.ListPlugins(ctx, map[string]interface{}{
		"enabled": true,
		"task_id": bson.M{"$exists": false}, // 不属于任何任务的插件
	})
	if err != nil {
		return fmt.Errorf("failed to list enabled plugins: %w", err)
	}

	// 更新 telegraf 配置
	if ms.telegrafManager != nil {
		if err := ms.telegrafManager.UpdateConfigFromTasks(ctx, tasks, plugins); err != nil {
			return fmt.Errorf("failed to update telegraf config: %w", err)
		}
	}

	return nil
}

// EnsureIndexes 创建索引
func (ms *MonitoringService) EnsureIndexes(ctx context.Context) error {
	if ms.mongoClient == nil {
		return nil
	}

	// 为 monitoring_tasks 创建索引
	tasksCollection := ms.mongoClient.Database(ms.database).Collection("monitoring_tasks")
	taskIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "status", Value: 1}},
			Options: options.Index().SetName("idx_status"),
		},
		{
			Keys:    bson.D{{Key: "name", Value: 1}},
			Options: options.Index().SetName("idx_name"),
		},
		{
			Keys:    bson.D{{Key: "created_at", Value: -1}},
			Options: options.Index().SetName("idx_created_at"),
		},
	}

	_, err := tasksCollection.Indexes().CreateMany(ctx, taskIndexes)
	if err != nil {
		return fmt.Errorf("failed to create task indexes: %w", err)
	}

	// 为 plugin_configs 创建索引
	pluginsCollection := ms.mongoClient.Database(ms.database).Collection("plugin_configs")
	pluginIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "type", Value: 1}},
			Options: options.Index().SetName("idx_type"),
		},
		{
			Keys:    bson.D{{Key: "enabled", Value: 1}},
			Options: options.Index().SetName("idx_enabled"),
		},
		{
			Keys:    bson.D{{Key: "task_id", Value: 1}},
			Options: options.Index().SetName("idx_task_id"),
		},
	}

	_, err = pluginsCollection.Indexes().CreateMany(ctx, pluginIndexes)
	if err != nil {
		return fmt.Errorf("failed to create plugin indexes: %w", err)
	}

	return nil
}
