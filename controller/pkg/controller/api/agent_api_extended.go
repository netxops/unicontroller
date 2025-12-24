package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/influxdata/telegraf/controller/pb"
)

// HandleGetApplicationMetrics 获取应用指标
func (ap *ControllerAPI) HandleGetApplicationMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	serviceName := r.URL.Query().Get("service_name")

	metricsQuery := ap.controller.AgentManager.GetMetricsQuery()
	if metricsQuery == nil {
		http.Error(w, "Metrics query not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 获取应用指标
	appMetrics, err := metricsQuery.GetApplicationMetrics(r.Context(), agentID, serviceName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get application metrics: %v", err), http.StatusInternalServerError)
		return
	}

	// 转换为 JSON 格式
	response := map[string]interface{}{
		"agent_id":  agentID,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if serviceName != "" {
		// 单个服务的应用指标
		if metrics, exists := appMetrics[serviceName]; exists {
			if metricsMap, ok := metrics.(*pb.ApplicationMetrics); ok {
				metricsData := map[string]interface{}{
					"service_name": metricsMap.ServiceName,
					"metrics":      metricsMap.Metrics,
					"labels":       metricsMap.Labels,
				}
				if metricsMap.Timestamp != nil {
					metricsData["timestamp"] = metricsMap.Timestamp.AsTime().Format(time.RFC3339)
				}
				response["metrics"] = metricsData
			}
		}
	} else {
		// 所有服务的应用指标
		servicesMap := make(map[string]interface{})
		for svcName, metrics := range appMetrics {
			if metricsMap, ok := metrics.(*pb.ApplicationMetrics); ok {
				metricsData := map[string]interface{}{
					"service_name": metricsMap.ServiceName,
					"metrics":      metricsMap.Metrics,
					"labels":       metricsMap.Labels,
				}
				if metricsMap.Timestamp != nil {
					metricsData["timestamp"] = metricsMap.Timestamp.AsTime().Format(time.RFC3339)
				}
				servicesMap[svcName] = metricsData
			}
		}
		response["services"] = servicesMap
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGetMetricsHistory 获取指标历史数据
func (ap *ControllerAPI) HandleGetMetricsHistory(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	metricType := r.URL.Query().Get("type") // "system" or "service"
	serviceName := r.URL.Query().Get("service_name")

	// 解析时间范围参数
	startTimeStr := r.URL.Query().Get("start_time")
	endTimeStr := r.URL.Query().Get("end_time")
	duration := r.URL.Query().Get("duration") // 例如 "1h", "30m"

	var startTime, endTime time.Time
	now := time.Now()

	if duration != "" {
		// 解析 duration（例如 "1h"）
		d, err := time.ParseDuration(duration)
		if err == nil {
			startTime = now.Add(-d)
			endTime = now
		} else {
			startTime = now.Add(-1 * time.Hour) // 默认1小时
			endTime = now
		}
	} else {
		// 解析具体时间
		if startTimeStr != "" {
			if t, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
				startTime = t
			} else {
				startTime = now.Add(-1 * time.Hour)
			}
		} else {
			startTime = now.Add(-1 * time.Hour)
		}

		if endTimeStr != "" {
			if t, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
				endTime = t
			} else {
				endTime = now
			}
		} else {
			endTime = now
		}
	}

	metricsQuery := ap.controller.AgentManager.GetMetricsQuery()
	if metricsQuery == nil {
		http.Error(w, "Metrics query not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 获取历史数据
	historyData, err := metricsQuery.GetMetricsHistory(r.Context(), agentID, metricType, serviceName, startTime, endTime)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get metrics history: %v", err), http.StatusInternalServerError)
		return
	}

	// 转换为 JSON 格式
	response := map[string]interface{}{
		"agent_id":    agentID,
		"type":        metricType,
		"start_time":  startTime.Format(time.RFC3339),
		"end_time":    endTime.Format(time.RFC3339),
		"data_points": []interface{}{},
	}

	// 从返回的 map 中提取数据
	if historyData != nil {
		if historyType, ok := historyData["type"].(string); ok {
			response["type"] = historyType
		}
		if serviceName, ok := historyData["service_name"].(string); ok && serviceName != "" {
			response["service_name"] = serviceName
		}
		if startTimeStr, ok := historyData["start_time"].(string); ok {
			response["start_time"] = startTimeStr
		}
		if endTimeStr, ok := historyData["end_time"].(string); ok {
			response["end_time"] = endTimeStr
		}
		if dataPoints, ok := historyData["data_points"].([]*pb.MetricsHistoryPoint); ok {
			pointsList := make([]interface{}, 0, len(dataPoints))
			for _, point := range dataPoints {
				pointMap := map[string]interface{}{
					"timestamp": point.Timestamp.AsTime().Format(time.RFC3339),
				}
				// 解析 metrics（JSON 字符串）
				if len(point.Metrics) > 0 {
					metricsMap := make(map[string]interface{})
					for k, v := range point.Metrics {
						var jsonValue interface{}
						if err := json.Unmarshal([]byte(v), &jsonValue); err == nil {
							metricsMap[k] = jsonValue
						} else {
							metricsMap[k] = v
						}
					}
					pointMap["metrics"] = metricsMap
				}
				pointsList = append(pointsList, pointMap)
			}
			response["data_points"] = pointsList
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleListFiles 列出文件
func (ap *ControllerAPI) HandleListFiles(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	dirPath := r.URL.Query().Get("path")
	if dirPath == "" {
		dirPath = "/"
	}

	fileOp := ap.controller.AgentManager.GetFileOperation()
	if fileOp == nil {
		http.Error(w, "File operation not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 列出文件
	filesResp, err := fileOp.ListFiles(r.Context(), agentID, dirPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list files: %v", err), http.StatusInternalServerError)
		return
	}

	// 转换为 JSON 格式
	response := map[string]interface{}{
		"agent_id": agentID,
		"path":     dirPath,
		"files":    []interface{}{},
	}

	// 从返回的 map 中提取数据
	if path, ok := filesResp["path"].(string); ok {
		response["path"] = path
	}
	if files, ok := filesResp["files"].([]interface{}); ok {
		response["files"] = files
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleGetFileInfo 获取文件信息
func (ap *ControllerAPI) HandleGetFileInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	fileOp := ap.controller.AgentManager.GetFileOperation()
	if fileOp == nil {
		http.Error(w, "File operation not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 获取文件信息
	fileInfoResp, err := fileOp.GetFileInfo(r.Context(), agentID, filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get file info: %v", err), http.StatusInternalServerError)
		return
	}

	// 转换为 JSON 格式
	response := map[string]interface{}{
		"agent_id": agentID,
		"path":     filePath,
		"exists":   false,
	}

	// 从返回的 map 中提取数据
	if exists, ok := fileInfoResp["exists"].(bool); ok {
		response["exists"] = exists
		if exists {
			if file, ok := fileInfoResp["file"].(map[string]interface{}); ok {
				response["file"] = file
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleStartFileUpload 开始文件上传
func (ap *ControllerAPI) HandleStartFileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	agentID := vars["agent_id"]

	var req struct {
		FilePath string `json:"file_path"`
		FileSize int64  `json:"file_size"`
		MD5      string `json:"md5,omitempty"`
		SHA256   string `json:"sha256,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	fileOp := ap.controller.AgentManager.GetFileOperation()
	if fileOp == nil {
		http.Error(w, "File operation not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 开始上传
	// 注意：需要先运行 protoc 生成 proto 代码后才能使用
	uploadResp, err := fileOp.StartFileUpload(r.Context(), agentID, req.FilePath, req.FileSize, req.MD5, req.SHA256)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to start file upload: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"session_id": uploadResp["session_id"],
		"agent_id":   agentID,
		"file_path":  req.FilePath,
		"chunk_size": uploadResp["chunk_size"],
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleUploadFileChunk 上传文件块
func (ap *ControllerAPI) HandleUploadFileChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	sessionID := vars["session_id"]

	chunkIndexStr := r.URL.Query().Get("chunk_index")
	chunkIndex, err := strconv.ParseInt(chunkIndexStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid chunk_index parameter", http.StatusBadRequest)
		return
	}

	// 读取块数据
	chunkData := make([]byte, r.ContentLength)
	if _, readErr := r.Body.Read(chunkData); readErr != nil && readErr.Error() != "EOF" {
		http.Error(w, fmt.Sprintf("Failed to read chunk data: %v", readErr), http.StatusBadRequest)
		return
	}

	fileOp := ap.controller.AgentManager.GetFileOperation()
	if fileOp == nil {
		http.Error(w, "File operation not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 上传块
	err = fileOp.UploadFileChunk(r.Context(), agentID, sessionID, chunkIndex, chunkData)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to upload file chunk: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"session_id":  sessionID,
		"chunk_index": chunkIndex,
		"status":      "received",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleGetUploadStatus 获取上传状态
func (ap *ControllerAPI) HandleGetUploadStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	sessionID := vars["session_id"]

	fileOp := ap.controller.AgentManager.GetFileOperation()
	if fileOp == nil {
		http.Error(w, "File operation not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 获取上传状态
	statusResp, err := fileOp.GetUploadStatus(r.Context(), agentID, sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get upload status: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResp)
}

// HandleDownloadFile 下载文件
func (ap *ControllerAPI) HandleDownloadFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	// 解析 offset 和 length 参数（用于范围请求）
	var offset, length int64
	offsetStr := r.URL.Query().Get("offset")
	lengthStr := r.URL.Query().Get("length")
	if offsetStr != "" {
		var err error
		offset, err = strconv.ParseInt(offsetStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid offset parameter", http.StatusBadRequest)
			return
		}
	}
	if lengthStr != "" {
		var err error
		length, err = strconv.ParseInt(lengthStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid length parameter", http.StatusBadRequest)
			return
		}
	}

	fileOp := ap.controller.AgentManager.GetFileOperation()
	if fileOp == nil {
		http.Error(w, "File operation not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 下载文件（流式传输）
	reader, err := fileOp.DownloadFile(r.Context(), agentID, filePath, offset, length)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to download file: %v", err), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	// 设置响应头
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(filePath)))

	// 流式传输文件数据
	_, err = io.Copy(w, reader)
	if err != nil {
		// 如果连接已关闭，不记录错误
		if err.Error() != "write: broken pipe" && err.Error() != "connection reset by peer" {
			http.Error(w, fmt.Sprintf("Failed to stream file: %v", err), http.StatusInternalServerError)
		}
		return
	}
}

// HandleDeleteFile 删除文件
func (ap *ControllerAPI) HandleDeleteFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	recursive := r.URL.Query().Get("recursive") == "true"

	fileOp := ap.controller.AgentManager.GetFileOperation()
	if fileOp == nil {
		http.Error(w, "File operation not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 删除文件
	deleteResp, err := fileOp.DeleteFile(r.Context(), agentID, filePath, recursive)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete file: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"agent_id": agentID,
		"path":     filePath,
		"success":  false,
	}

	// 从返回的 map 中提取数据
	if success, ok := deleteResp["success"].(bool); ok {
		response["success"] = success
	}
	if msg, ok := deleteResp["message"].(string); ok {
		response["message"] = msg
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleCreateDirectory 创建目录
func (ap *ControllerAPI) HandleCreateDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	agentID := vars["agent_id"]

	var req struct {
		Path string `json:"path"`
		Mode uint32 `json:"mode,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	// 设置默认权限模式（0755）
	mode := req.Mode
	if mode == 0 {
		mode = 0755
	}

	fileOp := ap.controller.AgentManager.GetFileOperation()
	if fileOp == nil {
		http.Error(w, "File operation not available", http.StatusServiceUnavailable)
		return
	}

	// 通过 gRPC 调用 Agent 创建目录
	createResp, err := fileOp.CreateDirectory(r.Context(), agentID, req.Path, mode)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create directory: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"agent_id": agentID,
		"path":     req.Path,
		"success":  false,
	}

	// 从返回的 map 中提取数据
	if success, ok := createResp["success"].(bool); ok {
		response["success"] = success
	}
	if msg, ok := createResp["message"].(string); ok {
		response["message"] = msg
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
