package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/influxdata/telegraf/controller/pkg/controller"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"go.uber.org/zap"
)

// MetricsStrategyAPI 指标策略API处理器
// 注意：数据源是OneOps MySQL，Controller的MongoDB作为缓存/同步目标
// 策略数据流向：OneOps MySQL → Controller MongoDB → Agent
// 本API主要用于Agent查询策略配置，实际的数据管理在OneOps后端完成
type MetricsStrategyAPI struct {
	strategyService *controller.MetricsStrategyService
	logger          *zap.Logger
}

// NewMetricsStrategyAPI 创建指标策略API处理器
func NewMetricsStrategyAPI(strategyService *controller.MetricsStrategyService, logger *zap.Logger) *MetricsStrategyAPI {
	return &MetricsStrategyAPI{
		strategyService: strategyService,
		logger:          logger,
	}
}

// GetGlobalStrategy 获取全局策略
func (api *MetricsStrategyAPI) GetGlobalStrategy(w http.ResponseWriter, r *http.Request) {
	// 添加 panic 恢复
	defer func() {
		if rec := recover(); rec != nil {
			if api.logger != nil {
				api.logger.Error("GetGlobalStrategy发生panic",
					zap.Any("panic", rec),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
				)
			}
			http.Error(w, fmt.Sprintf("Internal server error: %v", rec), http.StatusInternalServerError)
		}
	}()

	if api.logger != nil {
		api.logger.Info("收到GetGlobalStrategy请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	strategy, err := api.strategyService.GetGlobalStrategy(r.Context())
	if err != nil {
		if api.logger != nil {
			api.logger.Error("GetGlobalStrategy执行失败", zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 确保设置正确的 Content-Type
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// 检查 JSON 编码错误
	if err := json.NewEncoder(w).Encode(strategy); err != nil {
		if api.logger != nil {
			api.logger.Error("GetGlobalStrategy JSON编码失败",
				zap.Error(err),
				zap.Any("strategy", strategy),
			)
		}
		// JSON 编码失败，但可能已经发送了部分响应，无法再发送错误响应
		// 记录错误并返回
		return
	}
}

// UpdateGlobalStrategy 更新全局策略
func (api *MetricsStrategyAPI) UpdateGlobalStrategy(w http.ResponseWriter, r *http.Request) {
	if api.logger != nil {
		api.logger.Info("收到UpdateGlobalStrategy请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	var strategy models.GlobalMetricStrategy
	if err := json.NewDecoder(r.Body).Decode(&strategy); err != nil {
		if api.logger != nil {
			api.logger.Error("Failed to decode request body", zap.Error(err))
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := api.strategyService.UpdateGlobalStrategy(r.Context(), &strategy); err != nil {
		if api.logger != nil {
			api.logger.Error("UpdateGlobalStrategy执行失败", zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(strategy)
}

// GetInstanceStrategy 获取实例策略
func (api *MetricsStrategyAPI) GetInstanceStrategy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentCode := vars["agentCode"]

	if api.logger != nil {
		api.logger.Info("收到GetInstanceStrategy请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("agentCode", agentCode),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	if agentCode == "" {
		http.Error(w, "agentCode is required", http.StatusBadRequest)
		return
	}

	strategy, err := api.strategyService.GetInstanceStrategy(r.Context(), agentCode)
	if err != nil {
		if api.logger != nil {
			api.logger.Error("GetInstanceStrategy执行失败",
				zap.String("agentCode", agentCode),
				zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(strategy)
}

// UpdateInstanceStrategy 更新实例策略
func (api *MetricsStrategyAPI) UpdateInstanceStrategy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentCode := vars["agentCode"]

	if api.logger != nil {
		api.logger.Info("收到UpdateInstanceStrategy请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("agentCode", agentCode),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	if agentCode == "" {
		http.Error(w, "agentCode is required", http.StatusBadRequest)
		return
	}

	var strategy models.InstanceMetricStrategy
	if err := json.NewDecoder(r.Body).Decode(&strategy); err != nil {
		if api.logger != nil {
			api.logger.Error("Failed to decode request body", zap.Error(err))
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 确保agentCode一致
	strategy.AgentCode = agentCode

	if err := api.strategyService.UpdateInstanceStrategy(r.Context(), &strategy); err != nil {
		if api.logger != nil {
			api.logger.Error("UpdateInstanceStrategy执行失败",
				zap.String("agentCode", agentCode),
				zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(strategy)
}

// GetAvailableMetrics 获取可用指标列表
func (api *MetricsStrategyAPI) GetAvailableMetrics(w http.ResponseWriter, r *http.Request) {
	agentCode := r.URL.Query().Get("agent_code")

	if api.logger != nil {
		api.logger.Info("收到GetAvailableMetrics请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("agentCode", agentCode),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	metrics, err := api.strategyService.GetAvailableMetrics(r.Context(), agentCode)
	if err != nil {
		if api.logger != nil {
			api.logger.Error("GetAvailableMetrics执行失败",
				zap.String("agentCode", agentCode),
				zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 返回符合 AvailableMetricsResponse 格式的响应
	response := models.AvailableMetricsResponse{
		Metrics: metrics,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// PreviewRule 预览规则
func (api *MetricsStrategyAPI) PreviewRule(w http.ResponseWriter, r *http.Request) {
	if api.logger != nil {
		api.logger.Info("收到PreviewRule请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	var rule models.MetricRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		if api.logger != nil {
			api.logger.Error("Failed to decode request body", zap.Error(err))
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	preview, err := api.strategyService.PreviewRule(r.Context(), rule)
	if err != nil {
		if api.logger != nil {
			api.logger.Error("PreviewRule执行失败", zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(preview)
}

// GetConfigStatus 获取配置状态
func (api *MetricsStrategyAPI) GetConfigStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentCode := vars["agentCode"]

	if api.logger != nil {
		api.logger.Info("收到GetConfigStatus请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("agentCode", agentCode),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	if agentCode == "" {
		http.Error(w, "agentCode is required", http.StatusBadRequest)
		return
	}

	status, err := api.strategyService.GetConfigStatus(r.Context(), agentCode)
	if err != nil {
		if api.logger != nil {
			api.logger.Error("GetConfigStatus执行失败",
				zap.String("agentCode", agentCode),
				zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// GetApplicationStrategy 获取应用指标策略
func (api *MetricsStrategyAPI) GetApplicationStrategy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentCode := vars["agentCode"]

	if api.logger != nil {
		api.logger.Info("收到GetApplicationStrategy请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("agentCode", agentCode),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	strategy, err := api.strategyService.GetApplicationStrategy(r.Context(), agentCode)
	if err != nil {
		if api.logger != nil {
			api.logger.Error("GetApplicationStrategy执行失败",
				zap.String("agentCode", agentCode),
				zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(strategy)
}

// UpdateApplicationStrategy 更新应用指标策略
func (api *MetricsStrategyAPI) UpdateApplicationStrategy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentCode := vars["agentCode"]

	if api.logger != nil {
		api.logger.Info("收到UpdateApplicationStrategy请求",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("agentCode", agentCode),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	}

	var strategy models.ApplicationMetricStrategy
	if err := json.NewDecoder(r.Body).Decode(&strategy); err != nil {
		if api.logger != nil {
			api.logger.Error("Failed to decode request body", zap.Error(err))
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 设置 ID
	if agentCode != "" {
		strategy.ID = agentCode
	}

	if err := api.strategyService.UpdateApplicationStrategy(r.Context(), &strategy); err != nil {
		if api.logger != nil {
			api.logger.Error("UpdateApplicationStrategy执行失败",
				zap.String("agentCode", agentCode),
				zap.Error(err))
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(strategy)
}
