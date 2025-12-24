package zone

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client 区域客户端
type Client struct {
	host   string
	token  string
	sessid string
	client *http.Client
}

// GetZonesRequest 获取区域列表请求参数
type GetZonesRequest struct {
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
	// 区域名字前缀过滤 (1-95字符)
	NamePrefix string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 指定排序字段 (最大100字符)
	SortBy string
	// 指定排序方式（正序/倒序）(asc/desc, 默认asc)
	Order string
}

// ZoneItem 区域项
type ZoneItem struct {
	UUID        string   `json:"uuid"`        // 唯一标识ID
	Name        string   `json:"name"`        // 区域名称
	Description string   `json:"description"` // 描述字段
	Interfaces  []string `json:"interfaces"`  // 关联的接口列表
	Priority    int32    `json:"priority"`    // 优先级
	Type        string   `json:"type"`        // 区域类型
	Enable      bool     `json:"enable"`      // 是否启用
}

// GetZonesResponse 获取区域列表响应
type GetZonesResponse struct {
	Code    int    `json:"code"`    // 错误码
	Message string `json:"message"` // 错误信息
	Data    struct {
		TotalItems    int32      `json:"totalItems"`    // 总共多少项目
		TotalPages    int32      `json:"totalPages"`    // 总共多少页
		PageNumber    int32      `json:"pageNumber"`    // 当前页码，从 1 开始
		PageSize      int32      `json:"pageSize"`      // 每页多大
		ItemsOffset   int32      `json:"itemsOffset"`   // 当前条目偏移，从 0 开始
		ItemLength    int32      `json:"itemLength"`    // 数据列表长度
		PrivateOffset uint64     `json:"privateOffset"` // 内部偏移
		Items         []ZoneItem `json:"items"`         // 有效数据列表
	} `json:"data"`
}

// NewClient 创建新的区域客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:   host,
		token:  token,
		sessid: sessid,
		client: httpClient,
	}
}

// GetZones 获取区域列表
func (c *Client) GetZones(req *GetZonesRequest) (*GetZonesResponse, error) {
	// 构建URL - 根据深信服防火墙API结构
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/zones", c.host)

	// 构建查询参数
	params := url.Values{}

	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.Select != "" {
		params.Add("_select", req.Select)
	}
	if req.NamePrefix != "" {
		params.Add("__nameprefix", req.NamePrefix)
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.SortBy != "" {
		params.Add("_sortby", req.SortBy)
	}
	if req.Order != "" {
		params.Add("_order", req.Order)
	}

	// 添加查询参数到URL
	if len(params) > 0 {
		apiURL += "?" + params.Encode()
	}

	// 创建GET请求
	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	// 设置Cookie认证
	cookieValue := ""
	if c.token != "" {
		cookieValue = fmt.Sprintf("token=%s", c.token)
	}
	if c.sessid != "" {
		if cookieValue != "" {
			cookieValue += "; SESSID=" + c.sessid
		} else {
			cookieValue = fmt.Sprintf("SESSID=%s", c.sessid)
		}
	}
	if cookieValue != "" {
		httpReq.Header.Set("Cookie", cookieValue)
	}

	// 发送请求
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// 解析响应
	var result GetZonesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetZonesResponse) IsSuccess() bool {
	return r.Code == 0
}

