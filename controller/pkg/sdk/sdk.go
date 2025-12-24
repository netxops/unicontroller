package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/keys"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// ============================================================================
// 旧的 Client（用于其他 API，需要 username/password）
// ============================================================================

type Client struct {
	baseURL  string
	username string
	password string
	client   *http.Client
}

func NewClient(address, username, password string) *Client {
	return &Client{
		baseURL:  address,
		username: username,
		password: password,
		client:   &http.Client{},
	}
}

func (c *Client) doRequest(method, path string, body interface{}) ([]byte, error) {
	url := fmt.Sprintf("%s%s", c.baseURL, path)

	var req *http.Request
	var err error

	if body != nil {
		jsonBody, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return nil, marshalErr
		}
		req, err = http.NewRequest(method, url, bytes.NewBuffer(jsonBody))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func (c *Client) GetControllerStatus() (*models.ControllerStatus, error) {
	data, err := c.doRequest("GET", "/api/v1/status", nil)
	if err != nil {
		return nil, err
	}

	var status models.ControllerStatus
	err = json.Unmarshal(data, &status)
	return &status, err
}

// CreateDeployment creates a new deployment
func (c *Client) CreateDeployment(req models.DeploymentRequest) (*models.Deployment, error) {
	data, err := c.doRequest("POST", "/api/v1/deployments", req)
	if err != nil {
		return nil, err
	}

	var deployment models.Deployment
	err = json.Unmarshal(data, &deployment)
	return &deployment, err
}

// GetDeployment retrieves a deployment by its ID
func (c *Client) GetDeployment(deploymentID string) (*models.Deployment, error) {
	path := fmt.Sprintf("/api/v1/deployments/%s", deploymentID)
	data, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var deployment models.Deployment
	err = json.Unmarshal(data, &deployment)
	return &deployment, err
}

// ListDeployments retrieves a list of all deployments
func (c *Client) ListDeployments() ([]models.Deployment, error) {
	data, err := c.doRequest("GET", "/api/v1/deployments", nil)
	if err != nil {
		return nil, err
	}

	var deployments []models.Deployment
	err = json.Unmarshal(data, &deployments)
	return deployments, err
}

func (c *Client) ListAgents(filter map[string]string, page, pageSize int) (*models.AgentsResponse, error) {
	// {"id", "status", "address", "hostname", "area", "zone", "version", "mode", "group", "deployment"}
	// id == agent_code
	query := url.Values{}
	for k, v := range filter {
		query.Add(k, v)
	}
	query.Add("page", fmt.Sprintf("%d", page))
	query.Add("pageSize", fmt.Sprintf("%d", pageSize))

	path := fmt.Sprintf("/api/v1/agents?%s", query.Encode())
	data, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response models.AgentsResponse
	err = json.Unmarshal(data, &response)
	return &response, err
}

// StartPackage starts a package on a specific agent
func (c *Client) StartPackage(agentCode, packageName string) error {
	path := fmt.Sprintf("/api/v1/agents/%s/packages/%s/start", agentCode, packageName)
	_, err := c.doRequest("POST", path, nil)
	if err != nil {
		return fmt.Errorf("failed to start package: %v", err)
	}
	return nil
}

// StopPackage stops a package on a specific agent
func (c *Client) StopPackage(agentCode, packageName string) error {
	path := fmt.Sprintf("/api/v1/agents/%s/packages/%s/stop", agentCode, packageName)
	_, err := c.doRequest("POST", path, nil)
	if err != nil {
		return fmt.Errorf("failed to stop package: %v", err)
	}
	return nil
}

// GetPackageLogs retrieves logs for a specific package on a specific agent
func (c *Client) GetPackageLogs(agentCode, packageName string, count int) ([]string, error) {
	path := fmt.Sprintf("/api/v1/agents/%s/packages/%s/logs?count=%d", agentCode, packageName, count)
	data, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get package logs: %v", err)
	}

	var response struct {
		Logs []string `json:"logs"`
	}
	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal logs response: %v", err)
	}

	return response.Logs, nil
}

// ============================================================================
// ConfigDriver（用于 etcd 配置管理）
// ============================================================================

type ConfigDriver struct {
	keys.Keys
	EtcdEndpoints []string
	EtcdUsername  string
	EtcdPassword  string
}

func NewConfigDriver(base, area string, endpoints []string) *ConfigDriver {
	return NewConfigDriverWithAuth(base, area, endpoints, "", "")
}

func NewConfigDriverWithAuth(base, area string, endpoints []string, username, password string) *ConfigDriver {
	return &ConfigDriver{
		Keys:          keys.NewKeyBuilder(base, area),
		EtcdEndpoints: endpoints,
		EtcdUsername:  username,
		EtcdPassword:  password,
	}
}

func (cd *ConfigDriver) GetConfig(ctx context.Context, paths ...string) (map[string]interface{}, error) {
	etcdConfig := clientv3.Config{
		Endpoints:   cd.EtcdEndpoints,
		DialTimeout: 5 * time.Second,
	}
	if cd.EtcdUsername != "" && cd.EtcdPassword != "" {
		etcdConfig.Username = cd.EtcdUsername
		etcdConfig.Password = cd.EtcdPassword
	}
	cli, err := clientv3.New(etcdConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %v", err)
	}
	defer cli.Close()

	key := cd.Add(paths...).Separator("/").String()
	resp, err := cli.Get(ctx, key, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to get config from etcd: %v", err)
	}

	config := make(map[string]interface{})
	for _, kv := range resp.Kvs {
		var value interface{}
		if err := json.Unmarshal(kv.Value, &value); err != nil {
			return nil, fmt.Errorf("failed to unmarshal value: %v", err)
		}

		// 如果 value 是一个 map，直接使用它
		if valueMap, ok := value.(map[string]interface{}); ok {
			for k, v := range valueMap {
				config[k] = v
			}
		} else {
			// 否则，使用整个值
			relativeKey := string(kv.Key)[len(key):]
			if relativeKey == "" {
				relativeKey = "value"
			}
			config[relativeKey] = value
		}
	}

	return config, nil

}

func (cd *ConfigDriver) PutConfig(ctx context.Context, value interface{}, paths ...string) error {
	etcdConfig := clientv3.Config{
		Endpoints:   cd.EtcdEndpoints,
		DialTimeout: 5 * time.Second,
	}
	if cd.EtcdUsername != "" && cd.EtcdPassword != "" {
		etcdConfig.Username = cd.EtcdUsername
		etcdConfig.Password = cd.EtcdPassword
	}
	cli, err := clientv3.New(etcdConfig)
	if err != nil {
		return fmt.Errorf("failed to create etcd client: %v", err)
	}
	defer cli.Close()

	// 构建完整的键
	fullKey := cd.Add(paths...).Separator("/").String()

	// 将值转换为 JSON
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value to JSON: %v", err)
	}

	// 将配置存储到 etcd
	_, err = cli.Put(ctx, fullKey, string(jsonValue))
	if err != nil {
		return fmt.Errorf("failed to put config to etcd: %v", err)
	}

	return nil
}

func (cd *ConfigDriver) Enable(ctx context.Context, enable bool, paths ...string) error {
	config, err := cd.GetConfig(ctx, paths...)
	if err != nil {
		return err
	}
	config["enabled"] = enable
	return cd.PutConfig(ctx, config, paths...)
}

// ============================================================================
// AsyncExecuteClient（用于异步执行 API）
// ============================================================================

// TaskStatus 任务状态
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"   // 待执行
	TaskStatusRunning   TaskStatus = "running"   // 执行中
	TaskStatusCompleted TaskStatus = "completed" // 已完成
	TaskStatusFailed    TaskStatus = "failed"    // 执行失败
	TaskStatusTimeout   TaskStatus = "timeout"   // 执行超时
	TaskStatusCancelled TaskStatus = "cancelled" // 已取消
)

// ErrorType 错误类型
type ErrorType string

const (
	ErrorTypeNone           ErrorType = "none"
	ErrorTypeNetwork        ErrorType = "network"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeExecution      ErrorType = "execution"
	ErrorTypeTimeout        ErrorType = "timeout"
	ErrorTypeCancelled      ErrorType = "cancelled"
	ErrorTypeUnknown        ErrorType = "unknown"
)

// CommandResult 单个命令的执行结果
type CommandResult struct {
	Index      int       `json:"index"`
	Command    string    `json:"command"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	ExitCode   int       `json:"exit_code,omitempty"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	Duration   int64     `json:"duration,omitempty"`
	ExecutedAt time.Time `json:"executed_at"`
}

// ExecutionResult 执行结果详情
type ExecutionResult struct {
	Stdout         string          `json:"stdout,omitempty"`
	Stderr         string          `json:"stderr,omitempty"`
	ExitCode       int             `json:"exit_code,omitempty"`
	OutputSize     int64           `json:"output_size"`
	CommandResults []CommandResult `json:"command_results,omitempty"`
}

// ErrorDetail 错误详情
type ErrorDetail struct {
	Type    ErrorType `json:"type"`
	Code    string    `json:"code,omitempty"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
}

// TaskInfo 任务信息
type TaskInfo struct {
	ID           string    `json:"id"`
	ControllerID string    `json:"controller_id"`
	DeviceIP     string    `json:"device_ip"`
	DevicePort   int       `json:"device_port"`
	Username     string    `json:"username"`
	CommandType  string    `json:"command_type"`
	Background   bool      `json:"background"`
	Timeout      int       `json:"timeout"`
	CreatedAt    time.Time `json:"created_at"`
}

// AsyncTaskResult 异步任务结果
type AsyncTaskResult struct {
	Status   TaskStatus `json:"status"`
	TaskInfo TaskInfo   `json:"task_info"`

	StartTime time.Time  `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Duration  *int64     `json:"duration,omitempty"`

	Result *ExecutionResult `json:"result,omitempty"`
	Error  *ErrorDetail     `json:"error,omitempty"`

	Message string `json:"message,omitempty"`
}

// AsyncExecuteRequest 异步执行请求
type AsyncExecuteRequest struct {
	ID         string                     `json:"id"`
	RemoteInfo structs.L2DeviceRemoteInfo `json:"remote_info"`
	Commands   []string                   `json:"commands,omitempty"`
	Script     string                     `json:"script,omitempty"`
	ScriptPath string                     `json:"script_path,omitempty"`
	Background bool                       `json:"background,omitempty"`
	Timeout    int                        `json:"timeout,omitempty"`
}

// AsyncExecuteResponse 异步执行响应
type AsyncExecuteResponse struct {
	Success  bool     `json:"success,omitempty"`
	TaskID   string   `json:"id"` // API 返回的字段是 "id"
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	TaskInfo TaskInfo `json:"task_info"`
}

// GetResultRequest 查询结果请求
type GetResultRequest struct {
	TaskIDs               []string `json:"task_ids"`
	OnlyCurrentController bool     `json:"only_current,omitempty"`
}

// GetResultResponse 查询结果响应
type GetResultResponse struct {
	Results map[string]*AsyncTaskResult `json:"results"`
	Errors  map[string]string           `json:"errors,omitempty"`
}

// AsyncExecuteClientConfig SDK 客户端配置
type AsyncExecuteClientConfig struct {
	BaseURL         string        // API 基础 URL，例如 "http://localhost:8081"
	HTTPClient      *http.Client  // 自定义 HTTP 客户端（可选）
	DefaultTimeout  time.Duration // 默认请求超时时间
	PollInterval    time.Duration // 轮询间隔（同步调用时使用）
	MaxPollDuration time.Duration // 最大轮询时间（同步调用时使用）
	MaxPollAttempts int           // 最大轮询次数（同步调用时使用）
}

// DefaultAsyncExecuteClientConfig 返回默认配置
func DefaultAsyncExecuteClientConfig(baseURL string) *AsyncExecuteClientConfig {
	return &AsyncExecuteClientConfig{
		BaseURL:         baseURL,
		DefaultTimeout:  30 * time.Second,
		PollInterval:    1 * time.Second,
		MaxPollDuration: 5 * time.Minute,
		MaxPollAttempts: 300, // 5分钟 / 1秒 = 300次
	}
}

// AsyncExecuteClient SDK 客户端
type AsyncExecuteClient struct {
	config *AsyncExecuteClientConfig
	client *http.Client
}

// NewAsyncExecuteClient 创建新的 SDK 客户端
func NewAsyncExecuteClient(config *AsyncExecuteClientConfig) *AsyncExecuteClient {
	if config == nil {
		panic("config cannot be nil")
	}
	if config.BaseURL == "" {
		panic("BaseURL cannot be empty")
	}

	// 使用配置的 HTTP 客户端，或创建默认客户端
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.DefaultTimeout,
		}
	}

	return &AsyncExecuteClient{
		config: config,
		client: httpClient,
	}
}

// AsyncExecute 异步执行命令（提交任务，不等待结果）
func (c *AsyncExecuteClient) AsyncExecute(ctx context.Context, req *AsyncExecuteRequest) (*AsyncExecuteResponse, error) {
	url := fmt.Sprintf("%s/api/v1/async_execute", c.config.BaseURL)

	// 序列化请求
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// 创建 HTTP 请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// 解析响应
	var response AsyncExecuteResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// GetResult 查询任务结果（支持批量查询）
func (c *AsyncExecuteClient) GetResult(ctx context.Context, taskIDs []string, onlyCurrentController bool) (*GetResultResponse, error) {
	url := fmt.Sprintf("%s/api/v1/async_execute/result", c.config.BaseURL)

	req := GetResultRequest{
		TaskIDs:               taskIDs,
		OnlyCurrentController: onlyCurrentController,
	}

	// 序列化请求
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// 创建 HTTP 请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// 解析响应
	var response GetResultResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// GetSingleResult 查询单个任务结果（便捷方法）
func (c *AsyncExecuteClient) GetSingleResult(ctx context.Context, taskID string, onlyCurrentController bool) (*AsyncTaskResult, error) {
	resp, err := c.GetResult(ctx, []string{taskID}, onlyCurrentController)
	if err != nil {
		return nil, err
	}

	// 检查是否有错误
	if errMsg, ok := resp.Errors[taskID]; ok {
		return nil, fmt.Errorf("task %s error: %s", taskID, errMsg)
	}

	// 获取结果
	result, ok := resp.Results[taskID]
	if !ok {
		return nil, fmt.Errorf("task %s not found", taskID)
	}

	return result, nil
}

// SyncExecuteOptions 同步执行选项
type SyncExecuteOptions struct {
	PollInterval    time.Duration                                    // 轮询间隔，默认使用 AsyncExecuteClientConfig 中的值
	MaxPollDuration time.Duration                                    // 最大轮询时间，默认使用 AsyncExecuteClientConfig 中的值
	MaxPollAttempts int                                              // 最大轮询次数，默认使用 AsyncExecuteClientConfig 中的值
	OnStatusUpdate  func(status TaskStatus, result *AsyncTaskResult) // 状态更新回调（可选）
}

// SyncExecute 同步执行命令（提交任务并等待结果）
// 简洁实现：使用简单的轮询循环，逻辑清晰
func (c *AsyncExecuteClient) SyncExecute(ctx context.Context, req *AsyncExecuteRequest, opts *SyncExecuteOptions) (*AsyncTaskResult, error) {
	fmt.Printf("[SyncExecute] Starting sync execution, commands: %v\n", req.Commands)

	// 提交异步任务
	asyncResp, err := c.AsyncExecute(ctx, req)
	if err != nil {
		fmt.Printf("[SyncExecute] Failed to submit async task: %v\n", err)
		return nil, fmt.Errorf("failed to submit async task: %w", err)
	}

	taskID := asyncResp.TaskID
	if taskID == "" {
		fmt.Printf("[SyncExecute] ERROR: task ID is empty after submission\n")
		return nil, fmt.Errorf("task ID is empty after submission")
	}

	fmt.Printf("[SyncExecute] Task submitted successfully, taskID: %s\n", taskID)

	// 确定轮询参数
	pollInterval := c.config.PollInterval
	maxPollDuration := c.config.MaxPollDuration

	if opts != nil {
		if opts.PollInterval > 0 {
			pollInterval = opts.PollInterval
		}
		if opts.MaxPollDuration > 0 {
			maxPollDuration = opts.MaxPollDuration
		}
	}

	fmt.Printf("[SyncExecute] Polling config: interval=%v, maxDuration=%v\n", pollInterval, maxPollDuration)

	// 创建带超时的上下文
	pollCtx, cancel := context.WithTimeout(ctx, maxPollDuration)
	defer cancel()

	// 使用简单的定时器进行轮询
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// 记录任务开始时间
	taskStartTime := time.Now()
	var taskTimeoutSeconds int

	// 立即执行第一次查询
	fmt.Printf("[SyncExecute] Performing initial query for taskID: %s\n", taskID)
	result, err := c.GetSingleResult(pollCtx, taskID, true)
	fmt.Printf("[SyncExecute] Initial query result: %+v\n", result)
	if err == nil {
		// 获取任务超时时间
		if result.TaskInfo.Timeout > 0 {
			taskTimeoutSeconds = result.TaskInfo.Timeout
		} else {
			taskTimeoutSeconds = 60 // 默认60秒
		}
		fmt.Printf("[SyncExecute] Task timeout configured: %d seconds\n", taskTimeoutSeconds)

		// 使用任务的开始时间（如果可用）
		if !result.StartTime.IsZero() {
			taskStartTime = result.StartTime
			fmt.Printf("[SyncExecute] Using task start time: %v\n", taskStartTime)
		}

		fmt.Printf("[SyncExecute] Initial query successful, status: %s\n", result.Status)
		// 调用状态更新回调
		if opts != nil && opts.OnStatusUpdate != nil {
			opts.OnStatusUpdate(result.Status, result)
		}

		// 检查任务状态
		if result.Status == TaskStatusCompleted {
			fmt.Printf("[SyncExecute] Task completed immediately, taskID: %s\n", taskID)
			return result, nil
		}
		if result.Status == TaskStatusFailed {
			fmt.Printf("[SyncExecute] Task failed immediately, taskID: %s, error: %v\n", taskID, result.Error)
			return c.handleTaskFailure(result)
		}
		if result.Status == TaskStatusCancelled {
			fmt.Printf("[SyncExecute] Task cancelled immediately, taskID: %s\n", taskID)
			return result, fmt.Errorf("task cancelled: %s", result.Message)
		}
		if result.Status == TaskStatusTimeout {
			fmt.Printf("[SyncExecute] Task timeout detected, taskID: %s\n", taskID)
			return result, fmt.Errorf("task timeout: %s", result.Message)
		}
		fmt.Printf("[SyncExecute] Task is %s, starting polling loop\n", result.Status)
	} else {
		fmt.Printf("[SyncExecute] Initial query failed (will retry): %v\n", err)
		// 如果第一次查询失败，使用默认超时时间
		taskTimeoutSeconds = 60
	}

	// 轮询循环
	pollCount := 0
	for {
		select {
		case <-pollCtx.Done():
			// 超时或取消
			if pollCtx.Err() == context.DeadlineExceeded {
				fmt.Printf("[SyncExecute] Polling timeout after %v, taskID: %s, pollCount: %d\n", maxPollDuration, taskID, pollCount)
				return nil, fmt.Errorf("polling timeout after %v", maxPollDuration)
			}
			fmt.Printf("[SyncExecute] Polling cancelled, taskID: %s, error: %v\n", taskID, pollCtx.Err())
			return nil, fmt.Errorf("polling cancelled: %w", pollCtx.Err())
		case <-ticker.C:
			pollCount++
			fmt.Printf("[SyncExecute] Polling attempt #%d for taskID: %s\n", pollCount, taskID)
			// 轮询时间到，查询任务结果
			result, err := c.GetSingleResult(pollCtx, taskID, true)
			fmt.Printf("[SyncExecute] Polling result: %+v\n", result)
			if err != nil {
				// 查询失败，如果是超时则返回，否则继续重试
				if pollCtx.Err() == context.DeadlineExceeded {
					fmt.Printf("[SyncExecute] Query timeout during polling, taskID: %s, pollCount: %d\n", taskID, pollCount)
					return nil, fmt.Errorf("polling timeout after %v", maxPollDuration)
				}
				// 其他错误继续重试
				fmt.Printf("[SyncExecute] Query failed (will retry), taskID: %s, error: %v, pollCount: %d\n", taskID, err, pollCount)
				continue
			}

			// 更新任务超时时间（如果从结果中获取到）
			if result.TaskInfo.Timeout > 0 {
				taskTimeoutSeconds = result.TaskInfo.Timeout
			}

			// 检查任务是否超时（即使状态还是 running）
			elapsed := time.Since(taskStartTime)
			if elapsed > time.Duration(taskTimeoutSeconds)*time.Second {
				fmt.Printf("[SyncExecute] Task timeout detected: elapsed=%v, timeout=%ds, taskID: %s, pollCount: %d\n",
					elapsed, taskTimeoutSeconds, taskID, pollCount)
				// 构造超时错误结果
				timeoutResult := result
				timeoutResult.Status = TaskStatusTimeout
				timeoutResult.Message = fmt.Sprintf("任务执行超时（%d秒）", taskTimeoutSeconds)
				if timeoutResult.Error == nil {
					timeoutResult.Error = &ErrorDetail{
						Type:    ErrorTypeTimeout,
						Message: fmt.Sprintf("Execution timeout after %d seconds", taskTimeoutSeconds),
						Details: fmt.Sprintf("Task has been running for %v, exceeding the configured timeout of %d seconds", elapsed, taskTimeoutSeconds),
					}
				}
				return timeoutResult, fmt.Errorf("task timeout after %d seconds: %s", taskTimeoutSeconds, timeoutResult.Message)
			}

			fmt.Printf("[SyncExecute] Query successful, taskID: %s, status: %s, elapsed=%v, timeout=%ds, pollCount: %d\n",
				taskID, result.Status, elapsed, taskTimeoutSeconds, pollCount)

			// 调用状态更新回调
			if opts != nil && opts.OnStatusUpdate != nil {
				opts.OnStatusUpdate(result.Status, result)
			}

			// 检查任务状态
			switch result.Status {
			case TaskStatusCompleted:
				fmt.Printf("[SyncExecute] Task completed successfully, taskID: %s, pollCount: %d\n", taskID, pollCount)
				return result, nil
			case TaskStatusFailed:
				fmt.Printf("[SyncExecute] Task failed, taskID: %s, error: %v, pollCount: %d\n", taskID, result.Error, pollCount)
				return c.handleTaskFailure(result)
			case TaskStatusCancelled:
				fmt.Printf("[SyncExecute] Task cancelled, taskID: %s, message: %s, pollCount: %d\n", taskID, result.Message, pollCount)
				return result, fmt.Errorf("task cancelled: %s", result.Message)
			case TaskStatusTimeout:
				fmt.Printf("[SyncExecute] Task timeout detected by server, taskID: %s, pollCount: %d\n", taskID, pollCount)
				return result, fmt.Errorf("task timeout: %s", result.Message)
			case TaskStatusPending, TaskStatusRunning:
				// 继续等待，但记录已运行时间
				fmt.Printf("[SyncExecute] Task is %s, elapsed=%v, timeout=%ds, continuing to wait, pollCount: %d\n",
					result.Status, elapsed, taskTimeoutSeconds, pollCount)
				continue
			default:
				// 未知状态，继续等待
				fmt.Printf("[SyncExecute] Task has unknown status: %s, continuing to wait, pollCount: %d\n", result.Status, pollCount)
				continue
			}
		}
	}
}

// handleTaskFailure 处理任务失败的辅助方法
func (c *AsyncExecuteClient) handleTaskFailure(result *AsyncTaskResult) (*AsyncTaskResult, error) {
	if result.Error != nil {
		if result.Error.Details != "" {
			return result, fmt.Errorf("task failed: %s (type: %s) - Details: %s", result.Error.Message, result.Error.Type, result.Error.Details)
		}
		return result, fmt.Errorf("task failed: %s (type: %s)", result.Error.Message, result.Error.Type)
	}
	return result, fmt.Errorf("task failed: %s", result.Message)
}

// IsCompleted 检查任务是否已完成（成功或失败）
func (s TaskStatus) IsCompleted() bool {
	return s == TaskStatusCompleted || s == TaskStatusFailed || s == TaskStatusCancelled
}

// IsSuccess 检查任务是否成功完成
func (r *AsyncTaskResult) IsSuccess() bool {
	return r.Status == TaskStatusCompleted && r.Error == nil
}

// GetCombinedOutput 获取合并后的输出（兼容旧版本）
func (r *AsyncTaskResult) GetCombinedOutput() string {
	if r.Result != nil {
		if r.Result.Stdout != "" {
			return r.Result.Stdout
		}
		// 如果有多个命令结果，合并它们
		if len(r.Result.CommandResults) > 0 {
			var output strings.Builder
			for _, cmdResult := range r.Result.CommandResults {
				if cmdResult.Stdout != "" {
					output.WriteString(cmdResult.Stdout)
					output.WriteString("\n")
				}
			}
			return output.String()
		}
	}
	return ""
}

// GetCombinedError 获取合并后的错误输出
func (r *AsyncTaskResult) GetCombinedError() string {
	if r.Result != nil {
		if r.Result.Stderr != "" {
			return r.Result.Stderr
		}
		// 如果有多个命令结果，合并错误输出
		if len(r.Result.CommandResults) > 0 {
			var output strings.Builder
			for _, cmdResult := range r.Result.CommandResults {
				if cmdResult.Stderr != "" {
					output.WriteString(cmdResult.Stderr)
					output.WriteString("\n")
				}
			}
			return output.String()
		}
	}
	if r.Error != nil {
		return r.Error.Message
	}
	return ""
}

// ============================================================================
// StackUp 执行相关类型和方法
// ============================================================================

// StackUpExecuteRequest StackUp 执行请求
type StackUpExecuteRequest struct {
	RemoteInfo    structs.L2DeviceRemoteInfo `json:"remote_info"`               // 设备连接信息
	Config        string                     `json:"config"`                    // YAML 格式的配置文件（可以是 base64 编码或原始字符串）
	ConfigType    string                     `json:"config_type,omitempty"`     // "yaml" 或 "base64"，默认为 "yaml"
	LocalDataPath string                     `json:"local_data_path,omitempty"` // 本地数据路径（可选）
}

// StackUpExecuteResponse StackUp 执行响应
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
// 接收一个 YAML 格式的配置文件，解析后执行其中的命令
func (c *AsyncExecuteClient) StackUpExecute(ctx context.Context, req *StackUpExecuteRequest) (*StackUpExecuteResponse, error) {
	url := fmt.Sprintf("%s/api/v1/stackup/execute", c.config.BaseURL)

	// 序列化请求
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// 创建 HTTP 请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// 解析响应
	var response StackUpExecuteResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}
