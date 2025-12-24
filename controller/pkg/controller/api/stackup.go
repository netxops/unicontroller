package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/l2service/sup"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	supstructs "github.com/influxdata/telegraf/controller/pkg/structs/sup"
)

// StackUpExecuteRequest 请求结构
type StackUpExecuteRequest struct {
	RemoteInfo    structs.L2DeviceRemoteInfo `json:"remote_info"`               // 设备连接信息
	Config        string                     `json:"config"`                    // YAML 格式的配置文件（可以是 base64 编码或原始字符串）
	ConfigType    string                     `json:"config_type,omitempty"`     // "yaml" 或 "base64"，默认为 "yaml"
	LocalDataPath string                     `json:"local_data_path,omitempty"` // 本地数据路径（可选）
}

// StackUpExecuteResponse 响应结构
type StackUpExecuteResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Results []StackUpCommandResult `json:"results,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// StackUpCommandResult 单个命令的执行结果
type StackUpCommandResult struct {
	Index   int    `json:"index"`   // 命令索引（从1开始）
	Command string `json:"command"` // 执行的命令
	Key     string `json:"key"`     // 命令的 key/name
	Output  string `json:"output"`  // 命令输出
	Msg     string `json:"msg"`     // 消息
	Status  string `json:"status"`  // 状态："true" 表示有错误，"false" 表示成功
}

// StackUpExecute 执行 StackUp 命令
// 这个方法类似于 Linux adapter 中的 stackUp 方法
// 它接收一个 YAML 格式的配置文件，解析后执行其中的命令
func (ap *ControllerAPI) StackUpExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request StackUpExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
		return
	}

	// 验证必要字段
	if request.Config == "" {
		http.Error(w, "config field is required", http.StatusBadRequest)
		return
	}

	// 解析配置文件
	var configBytes []byte
	var err error

	configType := request.ConfigType
	if configType == "" {
		configType = "yaml" // 默认为 yaml
	}

	switch configType {
	case "base64":
		configBytes, err = base64.StdEncoding.DecodeString(request.Config)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to decode base64 config: %v", err), http.StatusBadRequest)
			return
		}
	case "yaml":
		configBytes = []byte(request.Config)
	default:
		http.Error(w, fmt.Sprintf("Unsupported config_type: %s (supported: yaml, base64)", configType), http.StatusBadRequest)
		return
	}

	// 使用 sup 包解析配置
	conf, err := supstructs.NewSupConfg(configBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse config: %v", err), http.StatusBadRequest)
		return
	}

	// 确定本地数据路径
	localDataPath := request.LocalDataPath
	if localDataPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get current working directory: %v", err), http.StatusInternalServerError)
			return
		}
		localDataPath = cwd
	}

	// 创建 Stackup 实例
	stackup, err := sup.NewFromConfg(conf, localDataPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create stackup instance: %v", err), http.StatusInternalServerError)
		return
	}

	// 构建执行器
	exec, cmdList, err := stackup.BuildExecute(&request.RemoteInfo, conf.Env, nil, nil, conf.Commands...)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to build execute: %v", err), http.StatusInternalServerError)
		return
	}

	// 执行命令（stopOnErr = false，即使有错误也继续执行）
	stopOnErr := false
	execResult := exec.Run(stopOnErr)

	// 收集结果
	var results []StackUpCommandResult
	for index, cmd := range cmdList {
		_, data := execResult.GetResult(cmd.Name)
		msg := execResult.GetMsg(cmd.Name)

		// 确定状态字符串
		status := fmt.Sprintf("%t", execResult.Ok()) // 成功

		// 获取命令字符串
		commandStr := ""
		if cmd.Command != "" {
			commandStr = cmd.Command
		} else if cmd.Name != "" {
			commandStr = cmd.Name
		}

		result := StackUpCommandResult{
			Index:   index + 1,
			Command: commandStr,
			Key:     cmd.Name,
			Output:  strings.Join(data, "\n"),
			Msg:     msg,
			Status:  status,
		}
		results = append(results, result)
	}

	// 构建响应
	response := StackUpExecuteResponse{
		Success: true,
		Message: fmt.Sprintf("Executed %d commands", len(results)),
		Results: results,
	}

	// 检查是否有错误
	if !execResult.Ok() {
		response.Message = fmt.Sprintf("Executed %d commands with some errors", len(results))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}
