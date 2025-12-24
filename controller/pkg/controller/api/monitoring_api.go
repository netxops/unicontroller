package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/influxdata/telegraf/controller/pkg/controller"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
)

// MonitoringAPI 监控 API handlers
type MonitoringAPI struct {
	monitoringService *controller.MonitoringService
	templateService   *controller.PluginTemplateService
	telegrafManager   *controller.TelegrafManager
}

// NewMonitoringAPI 创建监控 API
func NewMonitoringAPI(
	monitoringService *controller.MonitoringService,
	templateService *controller.PluginTemplateService,
	telegrafManager *controller.TelegrafManager,
) *MonitoringAPI {
	return &MonitoringAPI{
		monitoringService: monitoringService,
		templateService:   templateService,
		telegrafManager:   telegrafManager,
	}
}

// ListTasks 列出所有监控任务
func (ma *MonitoringAPI) ListTasks(w http.ResponseWriter, r *http.Request) {
	filter := make(map[string]interface{})
	if status := r.URL.Query().Get("status"); status != "" {
		filter["status"] = status
	}

	tasks, err := ma.monitoringService.ListTasks(r.Context(), filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list tasks: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tasks)
}

// CreateTask 创建监控任务
func (ma *MonitoringAPI) CreateTask(w http.ResponseWriter, r *http.Request) {
	var task models.MonitoringTask
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := ma.monitoringService.CreateTask(r.Context(), &task); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create task: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(task)
}

// GetTask 获取监控任务详情
func (ma *MonitoringAPI) GetTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["task_id"]

	task, err := ma.monitoringService.GetTask(r.Context(), taskID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get task: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

// UpdateTask 更新监控任务
func (ma *MonitoringAPI) UpdateTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["task_id"]

	var task models.MonitoringTask
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := ma.monitoringService.UpdateTask(r.Context(), taskID, &task); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update task: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

// DeleteTask 删除监控任务
func (ma *MonitoringAPI) DeleteTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["task_id"]

	if err := ma.monitoringService.DeleteTask(r.Context(), taskID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete task: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StartTask 启动监控任务
func (ma *MonitoringAPI) StartTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["task_id"]

	if err := ma.monitoringService.StartTask(r.Context(), taskID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to start task: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// StopTask 停止监控任务
func (ma *MonitoringAPI) StopTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["task_id"]

	if err := ma.monitoringService.StopTask(r.Context(), taskID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop task: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// PauseTask 暂停监控任务
func (ma *MonitoringAPI) PauseTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["task_id"]

	if err := ma.monitoringService.PauseTask(r.Context(), taskID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to pause task: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
}

// ListPlugins 列出所有插件配置
func (ma *MonitoringAPI) ListPlugins(w http.ResponseWriter, r *http.Request) {
	filter := make(map[string]interface{})
	if enabled := r.URL.Query().Get("enabled"); enabled != "" {
		if enabled == "true" {
			filter["enabled"] = true
		} else if enabled == "false" {
			filter["enabled"] = false
		}
	}
	if pluginType := r.URL.Query().Get("type"); pluginType != "" {
		filter["type"] = pluginType
	}

	plugins, err := ma.monitoringService.ListPlugins(r.Context(), filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list plugins: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plugins)
}

// CreatePlugin 创建插件配置
func (ma *MonitoringAPI) CreatePlugin(w http.ResponseWriter, r *http.Request) {
	var plugin models.PluginConfig
	if err := json.NewDecoder(r.Body).Decode(&plugin); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := ma.monitoringService.CreatePlugin(r.Context(), &plugin); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create plugin: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(plugin)
}

// GetPlugin 获取插件配置详情
func (ma *MonitoringAPI) GetPlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginID := vars["plugin_id"]

	plugin, err := ma.monitoringService.GetPlugin(r.Context(), pluginID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get plugin: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plugin)
}

// UpdatePlugin 更新插件配置
func (ma *MonitoringAPI) UpdatePlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginID := vars["plugin_id"]

	var plugin models.PluginConfig
	if err := json.NewDecoder(r.Body).Decode(&plugin); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := ma.monitoringService.UpdatePlugin(r.Context(), pluginID, &plugin); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update plugin: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plugin)
}

// DeletePlugin 删除插件配置
func (ma *MonitoringAPI) DeletePlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginID := vars["plugin_id"]

	if err := ma.monitoringService.DeletePlugin(r.Context(), pluginID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete plugin: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListTemplates 列出所有插件模板
func (ma *MonitoringAPI) ListTemplates(w http.ResponseWriter, r *http.Request) {
	filter := make(map[string]interface{})
	if pluginType := r.URL.Query().Get("type"); pluginType != "" {
		filter["type"] = pluginType
	}

	templates, err := ma.templateService.ListTemplates(r.Context(), filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list templates: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

// CreateTemplate 创建插件模板
func (ma *MonitoringAPI) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	var template models.PluginTemplate
	if err := json.NewDecoder(r.Body).Decode(&template); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := ma.templateService.CreateTemplate(r.Context(), &template); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create template: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(template)
}

// GetTemplate 获取插件模板详情
func (ma *MonitoringAPI) GetTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["template_id"]

	tmpl, err := ma.templateService.GetTemplate(r.Context(), templateID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get template: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tmpl)
}

// UpdateTemplate 更新插件模板
func (ma *MonitoringAPI) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["template_id"]

	var tmpl models.PluginTemplate
	if err := json.NewDecoder(r.Body).Decode(&tmpl); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := ma.templateService.UpdateTemplate(r.Context(), templateID, &tmpl); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update template: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tmpl)
}

// DeleteTemplate 删除插件模板
func (ma *MonitoringAPI) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["template_id"]

	if err := ma.templateService.DeleteTemplate(r.Context(), templateID); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete template: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ValidateTemplateParameters 验证模板参数
func (ma *MonitoringAPI) ValidateTemplateParameters(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["template_id"]

	var params map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := ma.templateService.ValidateTemplateParameters(r.Context(), templateID, params); err != nil {
		http.Error(w, fmt.Sprintf("Invalid parameters: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
}

// GetMonitoringStatus 获取监控平台状态
func (ma *MonitoringAPI) GetMonitoringStatus(w http.ResponseWriter, r *http.Request) {
	status, err := ma.monitoringService.GetStatus(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get status: %v", err), http.StatusInternalServerError)
		return
	}

	// 添加 telegraf 配置版本信息
	if ma.telegrafManager != nil {
		status.ConfigVersion = ma.telegrafManager.GetConfigVersion()
		status.LastReloadTime = ma.telegrafManager.GetLastReloadTime()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// ReloadConfig 重新加载 telegraf 配置
func (ma *MonitoringAPI) ReloadConfig(w http.ResponseWriter, r *http.Request) {
	if ma.telegrafManager == nil {
		http.Error(w, "Telegraf manager not available", http.StatusServiceUnavailable)
		return
	}

	// 重新加载配置
	if err := ma.monitoringService.ReloadTelegrafConfig(r.Context()); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

// ApplyConfig 应用配置变更（批量操作）
func (ma *MonitoringAPI) ApplyConfig(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Tasks   []*models.MonitoringTask `json:"tasks,omitempty"`
		Plugins []*models.PluginConfig   `json:"plugins,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// 更新任务
	for _, task := range request.Tasks {
		if task.ID == "" {
			if err := ma.monitoringService.CreateTask(r.Context(), task); err != nil {
				http.Error(w, fmt.Sprintf("Failed to create task: %v", err), http.StatusInternalServerError)
				return
			}
		} else {
			if err := ma.monitoringService.UpdateTask(r.Context(), task.ID, task); err != nil {
				http.Error(w, fmt.Sprintf("Failed to update task: %v", err), http.StatusInternalServerError)
				return
			}
		}
	}

	// 更新插件
	for _, plugin := range request.Plugins {
		if plugin.ID == "" {
			if err := ma.monitoringService.CreatePlugin(r.Context(), plugin); err != nil {
				http.Error(w, fmt.Sprintf("Failed to create plugin: %v", err), http.StatusInternalServerError)
				return
			}
		} else {
			if err := ma.monitoringService.UpdatePlugin(r.Context(), plugin.ID, plugin); err != nil {
				http.Error(w, fmt.Sprintf("Failed to update plugin: %v", err), http.StatusInternalServerError)
				return
			}
		}
	}

	// 重新加载配置
	if err := ma.monitoringService.ReloadTelegrafConfig(r.Context()); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "applied"})
}
