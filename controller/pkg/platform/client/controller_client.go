package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
)

// ControllerClient Controller HTTP API 客户端
type ControllerClient struct {
	baseURL    string
	httpClient *http.Client
	area       string
	timeout    time.Duration
}

// NewControllerClient 创建 Controller 客户端
func NewControllerClient(baseURL string, area string) *ControllerClient {
	// 自动补全协议前缀
	if baseURL != "" && !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	return &ControllerClient{
		baseURL: baseURL,
		area:    area,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		timeout: 30 * time.Second,
	}
}

// SetTimeout 设置请求超时时间
func (c *ControllerClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	c.httpClient.Timeout = timeout
}

// ListAgents 获取区域内的 Agent 列表
func (c *ControllerClient) ListAgents(ctx context.Context, filters map[string]string, page, pageSize int) (*models.AgentsResponse, error) {
	url := fmt.Sprintf("%s/api/v1/agents", c.baseURL)

	// 构建查询参数
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	for k, v := range filters {
		q.Add(k, v)
	}
	if page > 0 {
		q.Add("page", fmt.Sprintf("%d", page))
	}
	if pageSize > 0 {
		q.Add("pageSize", fmt.Sprintf("%d", pageSize))
	}
	req.URL.RawQuery = q.Encode()

	var response models.AgentsResponse
	if err := c.doRequest(req, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// GetAgent 获取 Agent 详情
func (c *ControllerClient) GetAgent(ctx context.Context, agentID string) (*models.Agent, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s", c.baseURL, agentID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	var agent models.Agent
	if err := c.doRequest(req, &agent); err != nil {
		return nil, err
	}

	return &agent, nil
}

// GetAgentPackages 获取 Agent 管理的服务列表
func (c *ControllerClient) GetAgentPackages(ctx context.Context, agentID string) ([]models.PackageStatus, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s/packages", c.baseURL, agentID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	var response struct {
		AgentID  string                 `json:"agent_id"`
		Packages []models.PackageStatus `json:"packages"`
	}
	if err := c.doRequest(req, &response); err != nil {
		return nil, err
	}

	return response.Packages, nil
}

// GetAgentHealth 获取 Agent 所有服务的健康状态
func (c *ControllerClient) GetAgentHealth(ctx context.Context, agentID string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s/health", c.baseURL, agentID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	var health map[string]interface{}
	if err := c.doRequest(req, &health); err != nil {
		return nil, err
	}

	return health, nil
}

// GetServiceHealth 获取指定服务的健康状态
func (c *ControllerClient) GetServiceHealth(ctx context.Context, agentID, packageName string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s/health/%s", c.baseURL, agentID, packageName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	var health map[string]interface{}
	if err := c.doRequest(req, &health); err != nil {
		return nil, err
	}

	return health, nil
}

// GetSystemMetrics 获取系统指标
func (c *ControllerClient) GetSystemMetrics(ctx context.Context, agentID string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s/metrics/system", c.baseURL, agentID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	var metrics map[string]interface{}
	if err := c.doRequest(req, &metrics); err != nil {
		return nil, err
	}

	return metrics, nil
}

// GetServiceMetrics 获取服务指标
func (c *ControllerClient) GetServiceMetrics(ctx context.Context, agentID string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s/metrics/services", c.baseURL, agentID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	var response map[string]interface{}
	if err := c.doRequest(req, &response); err != nil {
		return nil, err
	}

	return response, nil
}

// BatchStart 批量启动服务
func (c *ControllerClient) BatchStart(ctx context.Context, req *models.BatchOperationRequest) (*models.BatchOperationResult, error) {
	url := fmt.Sprintf("%s/api/v1/agents/batch/start", c.baseURL)
	return c.batchOperation(ctx, url, req)
}

// BatchStop 批量停止服务
func (c *ControllerClient) BatchStop(ctx context.Context, req *models.BatchOperationRequest) (*models.BatchOperationResult, error) {
	url := fmt.Sprintf("%s/api/v1/agents/batch/stop", c.baseURL)
	return c.batchOperation(ctx, url, req)
}

// BatchRestart 批量重启服务
func (c *ControllerClient) BatchRestart(ctx context.Context, req *models.BatchOperationRequest) (*models.BatchOperationResult, error) {
	url := fmt.Sprintf("%s/api/v1/agents/batch/restart", c.baseURL)
	return c.batchOperation(ctx, url, req)
}

// BatchUpdateConfigs 批量更新配置
func (c *ControllerClient) BatchUpdateConfigs(ctx context.Context, req *models.BatchConfigRequest) (*models.BatchOperationResult, error) {
	url := fmt.Sprintf("%s/api/v1/agents/batch/configs", c.baseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	var result models.BatchOperationResult
	if err := c.doRequest(httpReq, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// batchOperation 执行批量操作
func (c *ControllerClient) batchOperation(ctx context.Context, url string, req *models.BatchOperationRequest) (*models.BatchOperationResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	var result models.BatchOperationResult
	if err := c.doRequest(httpReq, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// doRequest 执行 HTTP 请求
func (c *ControllerClient) doRequest(req *http.Request, result interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}
