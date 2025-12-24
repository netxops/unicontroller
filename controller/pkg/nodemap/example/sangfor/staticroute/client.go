package staticroute

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client 静态路由客户端
type Client struct {
	host   string
	token  string
	sessid string
	client *http.Client
}

// GetIPv4StaticRoutesRequest 获取IPv4静态路由列表请求参数
type GetIPv4StaticRoutesRequest struct {
	// 指定排序字段 (最大100字符)
	SortBy string
	// 目的ip地址/掩码，例如0.0.0.0/0 (IPv4地址格式，示例:192.168.1.0/24)
	Prefix string
	// 下一跳ip地址 (IPv4地址格式，示例:192.168.1.10)
	Gateway string
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
	// 路由管理距离，默认为1 (1-255)
	Distance uint8
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 出接口名称，自动选择接口识别到的接口不支持该参数过滤 (1-48字符)
	IfName string
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
	// 指定排序方式（正序/倒序）(asc/desc, 默认asc)
	Order string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 静态路由度量值 (0-255)
	Metric uint32
}

// StaticRouteItem IPv4静态路由项
type StaticRouteItem struct {
	// 基础信息
	UUID        string `json:"uuid"`        // 静态路由唯一资源ID
	Enable      bool   `json:"enable"`      // 静态路由启禁用开关
	Description string `json:"description"` // 描述信息 (0-95字符，不能包含特殊字符)

	// 路由配置
	Prefix string `json:"prefix"` // 目的IP地址/掩码 (IPv4地址格式，示例:192.168.1.0/24)
	Gateway string `json:"gateway"` // 下一跳ip地址 (IPv4地址格式，示例:192.168.1.10)
	IfName  string `json:"ifname"`  // 出接口名称 (1-48字符，不能包含特殊字符)

	// 路由参数
	Metric  uint32 `json:"metric"`  // 路由度量值 (0-255)
	Distance uint8 `json:"distance"` // 路由管理距离，默认为1 (1-255)
	Weight   uint8 `json:"weight"`   // ipv4静态路由权重，默认为1 (1-255)
	Tag      uint32 `json:"tag"`     // 路由标记，默认为0 (0-4294967295)

	// 链路探测
	LinkDTEnable bool   `json:"linkdtEnable"` // 静态路由关联接口链路探测启禁用开关，默认false
	LinkDT       string `json:"linkdt"`        // 静态路由关联链路探测

	// 虚拟系统
	VSys string `json:"vsys"` // 目的虚拟系统名称，默认为public (1-31字符)

	// 路由表
	TableID uint32 `json:"tableId"` // 路由表Id，不可修改
	// 可选值: 251(业务网络路由表), 250(管理网络路由表), 239(SSLVPN路由表)

	// 状态信息
	Status        uint8  `json:"status"`         // 状态信息，状态字段不可设置或修改
	InvalidReason string `json:"invalid_reason"` // 路由无效原因
}

// GetIPv4StaticRoutesResponse 获取IPv4静态路由列表响应
type GetIPv4StaticRoutesResponse struct {
	Code    int    `json:"code"`    // 错误码
	Message string `json:"message"` // 错误信息
	Data    struct {
		TotalItems    int32            `json:"totalItems"`    // 总共多少项目
		TotalPages    int32            `json:"totalPages"`    // 总共多少页
		PageNumber    int32            `json:"pageNumber"`    // 当前页码，从 1 开始
		PageSize      int32            `json:"pageSize"`      // 每页多大
		ItemsOffset   int32            `json:"itemsOffset"`   // 当前条目偏移，从 0 开始
		ItemLength    int32            `json:"itemLength"`    // 数据列表长度
		PrivateOffset uint64           `json:"privateOffset"` // 内部偏移
		Items         []StaticRouteItem `json:"items"`         // 有效数据列表
	} `json:"data"`
}

// NewClient 创建新的静态路由客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:   host,
		token:  token,
		sessid: sessid,
		client: httpClient,
	}
}

// GetIPv4StaticRoutes 获取IPv4静态路由列表
func (c *Client) GetIPv4StaticRoutes(req *GetIPv4StaticRoutesRequest) (*GetIPv4StaticRoutesResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/staticroutes/ipv4", c.host)

	// 构建查询参数
	params := url.Values{}

	if req.SortBy != "" {
		params.Add("_sortby", req.SortBy)
	}
	if req.Prefix != "" {
		params.Add("prefix", req.Prefix)
	}
	if req.Gateway != "" {
		params.Add("gateway", req.Gateway)
	}
	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
	}
	if req.Distance > 0 {
		params.Add("distance", strconv.Itoa(int(req.Distance)))
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.IfName != "" {
		params.Add("ifname", req.IfName)
	}
	if req.Select != "" {
		params.Add("_select", req.Select)
	}
	if req.Order != "" {
		params.Add("_order", req.Order)
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.Metric > 0 {
		params.Add("metric", strconv.FormatUint(uint64(req.Metric), 10))
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
	if c.token != "" {
		httpReq.Header.Set("Cookie", fmt.Sprintf("token=%s", c.token))
	}
	if c.sessid != "" {
		cookie := httpReq.Header.Get("Cookie")
		if cookie != "" {
			httpReq.Header.Set("Cookie", cookie+"; SESSID="+c.sessid)
		} else {
			httpReq.Header.Set("Cookie", fmt.Sprintf("SESSID=%s", c.sessid))
		}
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
	var result GetIPv4StaticRoutesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetIPv4StaticRoutesResponse) IsSuccess() bool {
	return r.Code == 0
}

