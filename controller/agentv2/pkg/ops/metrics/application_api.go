package metrics

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// ApplicationMetricsAPI 应用指标 API 处理器
type ApplicationMetricsAPI struct {
	collector *ApplicationMetricsCollector
	logger    *zap.Logger
}

// NewApplicationMetricsAPI 创建应用指标 API
func NewApplicationMetricsAPI(collector *ApplicationMetricsCollector, logger *zap.Logger) *ApplicationMetricsAPI {
	return &ApplicationMetricsAPI{
		collector: collector,
		logger:    logger,
	}
}

// ReportMetricRequest 上报指标请求
type ReportMetricRequest struct {
	ServiceName string             `json:"service_name"`
	MetricName  string             `json:"metric_name"`
	Value       float64            `json:"value"`
	Labels      map[string]string  `json:"labels,omitempty"`
}

// ReportMetric 上报指标（HTTP POST）
func (api *ApplicationMetricsAPI) ReportMetric(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ReportMetricRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.logger.Warn("Failed to decode request", zap.Error(err))
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ServiceName == "" || req.MetricName == "" {
		http.Error(w, "service_name and metric_name are required", http.StatusBadRequest)
		return
	}

	if err := api.collector.ReportMetric(req.ServiceName, req.MetricName, req.Value, req.Labels); err != nil {
		api.logger.Error("Failed to report metric",
			zap.String("service", req.ServiceName),
			zap.String("metric", req.MetricName),
			zap.Error(err))
		http.Error(w, "Failed to report metric", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// GetApplicationMetrics 获取应用指标（HTTP GET）
func (api *ApplicationMetricsAPI) GetApplicationMetrics(w http.ResponseWriter, r *http.Request) {
	serviceName := r.URL.Query().Get("service_name")

	var response interface{}
	if serviceName != "" {
		metrics, exists := api.collector.GetApplicationMetrics(serviceName)
		if !exists {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		response = metrics
	} else {
		response = api.collector.GetAllApplicationMetrics()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// RegisterHTTPHandlers 注册 HTTP 处理器
func (api *ApplicationMetricsAPI) RegisterHTTPHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/metrics/application/report", api.ReportMetric)
	mux.HandleFunc("/api/v1/metrics/application", api.GetApplicationMetrics)
}

