package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/influxdata/telegraf/controller/pb"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
)

// HandleGetAgent 获取 Agent 详情
func (ap *ControllerAPI) HandleGetAgent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]

	agent, err := ap.controller.AgentManager.GetAgentDetail(r.Context(), agentID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get agent: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agent)
}

// HandleGetAgentPackages 获取 Agent 管理的服务列表
func (ap *ControllerAPI) HandleGetAgentPackages(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]

	packages, err := ap.controller.AgentManager.GetAgentPackages(r.Context(), agentID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get agent packages: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id": agentID,
		"packages": packages,
	})
}

// HandleGetAgentHealth 获取 Agent 所有服务的健康状态
func (ap *ControllerAPI) HandleGetAgentHealth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]

	healthMonitor := ap.controller.AgentManager.GetHealthMonitor()
	if healthMonitor == nil {
		http.Error(w, "Health monitor not available", http.StatusServiceUnavailable)
		return
	}

	overallHealth, err := healthMonitor.GetAgentOverallHealth(r.Context(), agentID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get agent health: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(overallHealth)
}

// HandleGetServiceHealth 获取指定服务的健康状态
func (ap *ControllerAPI) HandleGetServiceHealth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]
	packageName := vars["package"]

	healthMonitor := ap.controller.AgentManager.GetHealthMonitor()
	if healthMonitor == nil {
		http.Error(w, "Health monitor not available", http.StatusServiceUnavailable)
		return
	}

	health, err := healthMonitor.GetServiceHealth(r.Context(), agentID, packageName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get service health: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// convertSystemMetricsToJSON 将 protobuf SystemMetrics 转换为 OneOps 期望的 JSON 格式
func convertSystemMetricsToJSON(metrics *pb.SystemMetrics) map[string]interface{} {
	result := make(map[string]interface{})

	if metrics == nil {
		return result
	}

	// CPU 指标
	cpu := make(map[string]interface{})
	cpu["usage"] = metrics.CpuUsage
	if metrics.CpuCores > 0 {
		cpu["cores"] = metrics.CpuCores
	}
	result["cpu"] = cpu

	// 内存指标（转换为 MB）
	memory := make(map[string]interface{})
	memoryTotalMB := metrics.MemoryTotal / (1024 * 1024)
	memoryUsedMB := (metrics.MemoryTotal - metrics.MemoryFree) / (1024 * 1024)
	memory["total"] = memoryTotalMB
	memory["used"] = memoryUsedMB
	memory["usage"] = metrics.MemoryUsage
	result["memory"] = memory

	// 磁盘指标（转换为 MB）
	disk := make(map[string]interface{})
	diskTotalMB := metrics.DiskTotal / (1024 * 1024)
	diskUsedMB := (metrics.DiskTotal - metrics.DiskFree) / (1024 * 1024)
	disk["total"] = diskTotalMB
	disk["used"] = diskUsedMB
	disk["usage"] = metrics.DiskUsage
	result["disk"] = disk

	// 网络指标
	network := make(map[string]interface{})
	interfaces := make([]map[string]interface{}, 0)

	// 优先使用 network_interfaces（如果存在）
	if len(metrics.NetworkInterfaces) > 0 {
		for _, iface := range metrics.NetworkInterfaces {
			interfaces = append(interfaces, map[string]interface{}{
				"name":     iface.Name,
				"rx_bytes": iface.RxBytes,
				"tx_bytes": iface.TxBytes,
			})
		}
	} else {
		// 降级：使用旧的 network_in/network_out（向后兼容）
		interfaces = append(interfaces, map[string]interface{}{
			"name":     "eth0",
			"rx_bytes": metrics.NetworkIn,
			"tx_bytes": metrics.NetworkOut,
		})
	}
	network["interfaces"] = interfaces
	result["network"] = network

	// 负载平均值
	if metrics.LoadAvg_1 > 0 || metrics.LoadAvg_5 > 0 || metrics.LoadAvg_15 > 0 {
		load := make(map[string]interface{})
		load["1min"] = metrics.LoadAvg_1
		load["5min"] = metrics.LoadAvg_5
		load["15min"] = metrics.LoadAvg_15
		result["load"] = load
	}

	// 时间戳
	if metrics.LastUpdated != nil {
		result["timestamp"] = metrics.LastUpdated.AsTime().Format(time.RFC3339)
	} else {
		result["timestamp"] = time.Now().Format(time.RFC3339)
	}

	return result
}

// HandleGetSystemMetrics 获取系统指标
func (ap *ControllerAPI) HandleGetSystemMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]

	metricsQuery := ap.controller.AgentManager.GetMetricsQuery()
	if metricsQuery == nil {
		http.Error(w, "Metrics query not available", http.StatusServiceUnavailable)
		return
	}

	metrics, err := metricsQuery.GetSystemMetrics(r.Context(), agentID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get system metrics: %v", err), http.StatusInternalServerError)
		return
	}

	// 转换为 OneOps 期望的 JSON 格式
	jsonMetrics := convertSystemMetricsToJSON(metrics)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonMetrics)
}

// convertServiceMetricsToJSON 将 protobuf ServiceMetrics 转换为 OneOps 期望的 JSON 格式
func convertServiceMetricsToJSON(metrics *pb.ServiceMetrics) map[string]interface{} {
	result := make(map[string]interface{})

	if metrics != nil {
		// CPU 指标
		cpu := make(map[string]interface{})
		cpu["usage"] = metrics.CpuUsage
		result["cpu"] = cpu

		// 内存指标（转换为 MB）
		memory := make(map[string]interface{})
		memoryMB := float64(metrics.MemoryBytes) / (1024 * 1024)
		memory["usage"] = memoryMB
		if metrics.MemoryUsage > 0 {
			memory["usage_percent"] = metrics.MemoryUsage
		}
		result["memory"] = memory
	}

	return result
}

// convertServiceMetricsListToJSON 将服务指标列表转换为 OneOps 期望的 JSON 格式
func convertServiceMetricsListToJSON(metricsList []*pb.ServiceMetrics) map[string]interface{} {
	services := make(map[string]interface{})

	for _, metrics := range metricsList {
		if metrics != nil && metrics.Package != "" {
			serviceMetrics := convertServiceMetricsToJSON(metrics)
			services[metrics.Package] = serviceMetrics
		}
	}

	return map[string]interface{}{
		"services": services,
	}
}

// HandleGetServiceMetrics 获取服务指标
func (ap *ControllerAPI) HandleGetServiceMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]

	metricsQuery := ap.controller.AgentManager.GetMetricsQuery()
	if metricsQuery == nil {
		http.Error(w, "Metrics query not available", http.StatusServiceUnavailable)
		return
	}

	// 检查是否有 package 参数
	packageName := r.URL.Query().Get("package")
	runningOnly := r.URL.Query().Get("running_only") == "true"

	w.Header().Set("Content-Type", "application/json")

	if packageName != "" {
		// 获取单个服务的指标
		metrics, err := metricsQuery.GetServiceMetrics(r.Context(), agentID, packageName)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get service metrics: %v", err), http.StatusInternalServerError)
			return
		}
		// 转换为 OneOps 期望的 JSON 格式
		jsonMetrics := convertServiceMetricsToJSON(metrics)
		json.NewEncoder(w).Encode(jsonMetrics)
	} else {
		// 获取所有服务的指标
		metrics, err := metricsQuery.ListServiceMetrics(r.Context(), agentID, runningOnly)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to list service metrics: %v", err), http.StatusInternalServerError)
			return
		}
		// 转换为 OneOps 期望的 JSON 格式
		jsonMetrics := convertServiceMetricsListToJSON(metrics)
		json.NewEncoder(w).Encode(jsonMetrics)
	}
}

// HandleBatchStart 批量启动服务
func (ap *ControllerAPI) HandleBatchStart(w http.ResponseWriter, r *http.Request) {
	var req models.BatchOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	batchOperator := ap.controller.AgentManager.GetBatchOperator()
	if batchOperator == nil {
		http.Error(w, "Batch operator not available", http.StatusServiceUnavailable)
		return
	}

	result, err := batchOperator.BatchStartPackages(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to batch start packages: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleBatchStop 批量停止服务
func (ap *ControllerAPI) HandleBatchStop(w http.ResponseWriter, r *http.Request) {
	var req models.BatchOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	batchOperator := ap.controller.AgentManager.GetBatchOperator()
	if batchOperator == nil {
		http.Error(w, "Batch operator not available", http.StatusServiceUnavailable)
		return
	}

	result, err := batchOperator.BatchStopPackages(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to batch stop packages: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// UninstallAgentReq OneOps Agent卸载请求
type UninstallAgentReq struct {
	DeviceCode string                 `json:"deviceCode"` // 设备代码
	AgentCode  string                 `json:"agentCode"`  // Agent代码
	Config     map[string]interface{} `json:"config"`     // Agent配置
}

// UninstallAgentResp OneOps Agent卸载响应
type UninstallAgentResp struct {
	TaskID  string `json:"taskID"`  // 卸载任务ID
	Status  string `json:"status"`  // 状态
	Message string `json:"message"` // 消息
}

// HandleUninstallAgent 卸载Agent（通过Deployment工具）
func (ap *ControllerAPI) HandleUninstallAgent(w http.ResponseWriter, r *http.Request) {
	log.Printf("[UninstallAgent] 收到卸载请求，Method: %s, URL: %s", r.Method, r.URL.String())

	if r.Method != http.MethodPost {
		log.Printf("[UninstallAgent] 方法不允许: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UninstallAgentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[UninstallAgent] 解析请求体失败: %v", err)
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("[UninstallAgent] 请求详情: DeviceCode=%s, AgentCode=%s, ConfigKeys=%d",
		req.DeviceCode, req.AgentCode, len(req.Config))

	// 验证必需字段
	if req.AgentCode == "" {
		log.Printf("[UninstallAgent] 验证失败: agentCode为空")
		http.Error(w, "agentCode is required", http.StatusBadRequest)
		return
	}

	// 生成卸载ID
	uninstallID := fmt.Sprintf("agent-uninstall-%s-%d", req.AgentCode, time.Now().Unix())

	// 构建标准的DeploymentRequest（操作类型为卸载）
	// 这里需要从Config中提取设备信息（IP、登录信息等）
	variables := make(map[string]interface{})
	if req.Config != nil {
		for k, v := range req.Config {
			variables[k] = v
		}
	}

	// 获取部署工具信息
	deploymentToolObjectName := ""
	if objName, ok := variables["deployment_tool_object_name"].(string); ok && objName != "" {
		deploymentToolObjectName = objName
	}
	if deploymentToolObjectName == "" {
		// 使用默认路径
		deploymentToolObjectName = "deployment-tools/deployment-agent"
	}
	variables["deployment_tool_object_name"] = deploymentToolObjectName

	// 构建目标设备信息
	targetDevice := models.TargetDevice{
		AgentCode:   req.AgentCode,
		Name:        req.DeviceCode,
		LoginMethod: models.LoginMethodSSH,
		Status:      models.DeploymentStatusPending,
	}

	// 从 Config 中提取设备信息
	if req.Config != nil {
		if ip, ok := req.Config["ip"].(string); ok && ip != "" {
			targetDevice.IP = ip
		}
		if username, ok := req.Config["username"].(string); ok && username != "" {
			targetDevice.LoginDetails.Username = username
		}
		if password, ok := req.Config["password"].(string); ok && password != "" {
			targetDevice.LoginDetails.Password = password
		}
		if sshKey, ok := req.Config["ssh_key"].(string); ok && sshKey != "" {
			targetDevice.LoginDetails.SSHKey = sshKey
		}
	}

	// 如果仍然没有IP，尝试从已注册的Agent获取
	if targetDevice.IP == "" {
		agent, err := ap.controller.AgentManager.GetAgent(r.Context(), req.AgentCode)
		if err == nil && agent != nil {
			// 从Agent的Address中提取IP
			if agent.Address != "" {
				parts := strings.Split(agent.Address, ":")
				if len(parts) > 0 {
					targetDevice.IP = parts[0]
				}
			}
		}
	}

	// 如果仍然没有IP，返回错误
	if targetDevice.IP == "" {
		log.Printf("[UninstallAgent] 无法确定设备IP地址，返回错误")
		http.Error(w, "Unable to determine device IP address. Please provide 'ip' in config or ensure agent is registered.", http.StatusBadRequest)
		return
	}

	log.Printf("[UninstallAgent] 设备信息已确定: IP=%s, Username=%s", targetDevice.IP, targetDevice.LoginDetails.Username)

	deploymentRequest := models.DeploymentRequest{
		ID:            uninstallID,
		AppID:         "agent",
		Type:          "agent",
		Version:       "",                            // 卸载不需要版本
		OperationType: models.OperationTypeUninstall, // 设置为卸载操作
		Variables:     variables,
		TargetDevices: []models.TargetDevice{targetDevice},
	}

	// 调用标准的CreateDeployment（但操作类型为卸载）
	log.Printf("[UninstallAgent] 调用CreateDeployment: ID=%s, OperationType=%s", deploymentRequest.ID, deploymentRequest.OperationType)

	deployment, err := ap.controller.CreateDeployment(deploymentRequest)
	if err != nil {
		log.Printf("[UninstallAgent] CreateDeployment失败: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create uninstall deployment: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[UninstallAgent] 卸载任务已创建: ID=%s", deployment.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UninstallAgentResp{
		TaskID:  deployment.ID,
		Status:  "accepted",
		Message: "Agent uninstall request has been submitted",
	})
}

// RestartAgentReq Agent重启请求
type RestartAgentReq struct {
	DeviceCode string                 `json:"deviceCode,omitempty"` // 设备代码（可选）
	AgentCode  string                 `json:"agentCode,omitempty"`  // Agent代码（可选，如果为空则从URL获取）
	Config     map[string]interface{} `json:"config,omitempty"`     // Agent配置（可选，包含IP、登录信息等）
}

// RestartAgentResp Agent重启响应
type RestartAgentResp struct {
	TaskID  string `json:"taskID"`  // 重启任务ID
	Status  string `json:"status"`  // 状态
	Message string `json:"message"` // 消息
}

// HandleRestartAgent 重启Agent（通过Deployment工具）
func (ap *ControllerAPI) HandleRestartAgent(w http.ResponseWriter, r *http.Request) {
	log.Printf("[RestartAgent] 收到重启请求，Method: %s, URL: %s", r.Method, r.URL.String())

	vars := mux.Vars(r)
	agentCode := vars["agent_id"]
	if agentCode == "" {
		http.Error(w, "Agent ID is required", http.StatusBadRequest)
		return
	}

	// 尝试解析请求体（可选）
	var req RestartAgentReq
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("[RestartAgent] 解析请求体失败（忽略，使用默认值）: %v", err)
		} else {
			log.Printf("[RestartAgent] 请求详情: DeviceCode=%s, AgentCode=%s, ConfigKeys=%d",
				req.DeviceCode, req.AgentCode, len(req.Config))
		}
	}

	// 如果请求体中没有AgentCode，使用URL中的
	if req.AgentCode == "" {
		req.AgentCode = agentCode
	}

	// 生成重启ID
	restartID := fmt.Sprintf("agent-restart-%s-%d", req.AgentCode, time.Now().Unix())

	// 构建标准的DeploymentRequest（操作类型为重启）
	variables := make(map[string]interface{})
	if req.Config != nil {
		for k, v := range req.Config {
			variables[k] = v
		}
	}

	// 获取部署工具信息
	deploymentToolObjectName := ""
	if objName, ok := variables["deployment_tool_object_name"].(string); ok && objName != "" {
		deploymentToolObjectName = objName
	}
	if deploymentToolObjectName == "" {
		// 使用默认路径
		deploymentToolObjectName = "deployment-tools/deployment-agent"
	}
	variables["deployment_tool_object_name"] = deploymentToolObjectName

	// 构建目标设备信息
	targetDevice := models.TargetDevice{
		AgentCode:   req.AgentCode,
		Name:        req.DeviceCode,
		LoginMethod: models.LoginMethodSSH,
		Status:      models.DeploymentStatusPending,
	}

	// 从 Config 中提取设备信息
	if req.Config != nil {
		if ip, ok := req.Config["ip"].(string); ok && ip != "" {
			targetDevice.IP = ip
		}
		if username, ok := req.Config["username"].(string); ok && username != "" {
			targetDevice.LoginDetails.Username = username
		}
		if password, ok := req.Config["password"].(string); ok && password != "" {
			targetDevice.LoginDetails.Password = password
		}
		if sshKey, ok := req.Config["ssh_key"].(string); ok && sshKey != "" {
			targetDevice.LoginDetails.SSHKey = sshKey
		}
	}

	// 如果仍然没有IP，尝试从已注册的Agent获取
	if targetDevice.IP == "" {
		agent, err := ap.controller.AgentManager.GetAgent(r.Context(), req.AgentCode)
		if err == nil && agent != nil {
			// 从Agent的Address中提取IP
			if agent.Address != "" {
				parts := strings.Split(agent.Address, ":")
				if len(parts) > 0 {
					targetDevice.IP = parts[0]
					log.Printf("[RestartAgent] 从Agent注册信息获取IP: %s", targetDevice.IP)
				}
			}
		} else {
			log.Printf("[RestartAgent] 无法获取Agent信息: %v", err)
		}
	}

	// 如果仍然没有IP，返回错误
	if targetDevice.IP == "" {
		log.Printf("[RestartAgent] 无法确定设备IP地址，返回错误")
		http.Error(w, "Unable to determine device IP address. Please provide 'ip' in config or ensure agent is registered.", http.StatusBadRequest)
		return
	}

	// 如果DeviceCode为空，使用AgentCode
	if targetDevice.Name == "" {
		targetDevice.Name = req.AgentCode
	}

	log.Printf("[RestartAgent] 设备信息已确定: IP=%s, Username=%s", targetDevice.IP, targetDevice.LoginDetails.Username)

	deploymentRequest := models.DeploymentRequest{
		ID:            restartID,
		AppID:         "agent",
		Type:          "agent",
		Version:       "",                          // 重启不需要版本
		OperationType: models.OperationTypeRestart, // 设置为重启操作
		Variables:     variables,
		TargetDevices: []models.TargetDevice{targetDevice},
	}

	// 调用标准的CreateDeployment（但操作类型为重启）
	log.Printf("[RestartAgent] 调用CreateDeployment: ID=%s, OperationType=%s", deploymentRequest.ID, deploymentRequest.OperationType)

	deployment, err := ap.controller.CreateDeployment(deploymentRequest)
	if err != nil {
		log.Printf("[RestartAgent] CreateDeployment失败: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create restart deployment: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[RestartAgent] CreateDeployment成功: DeploymentID=%s, Status=%s",
		deployment.ID, deployment.OverallStatus)

	// 返回OneOps期望的响应格式
	response := RestartAgentResp{
		TaskID:  deployment.ID,
		Status:  "accepted",
		Message: "Agent restart request accepted",
	}

	log.Printf("[RestartAgent] 返回响应: TaskID=%s, Status=%s", response.TaskID, response.Status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

// HandleBatchRestart 批量重启服务
func (ap *ControllerAPI) HandleBatchRestart(w http.ResponseWriter, r *http.Request) {
	var req models.BatchOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	batchOperator := ap.controller.AgentManager.GetBatchOperator()
	if batchOperator == nil {
		http.Error(w, "Batch operator not available", http.StatusServiceUnavailable)
		return
	}

	result, err := batchOperator.BatchRestartPackages(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to batch restart packages: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleBatchUpdateConfigs 批量更新配置
func (ap *ControllerAPI) HandleBatchUpdateConfigs(w http.ResponseWriter, r *http.Request) {
	var req models.BatchConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	batchOperator := ap.controller.AgentManager.GetBatchOperator()
	if batchOperator == nil {
		http.Error(w, "Batch operator not available", http.StatusServiceUnavailable)
		return
	}

	result, err := batchOperator.BatchUpdateConfigs(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to batch update configs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
