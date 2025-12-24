package route

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client 路由状态客户端
type Client struct {
	host      string
	token     string
	sessid    string
	namespace string // 命名空间，如果为空则使用@namespace
	client    *http.Client
}

// GetIPv4RoutesRequest 获取IPv4路由信息列表请求参数
type GetIPv4RoutesRequest struct {
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 获取路由的类型
	// ALL_ROUTE: 所有路由
	// STATIC_ROUTE: 静态路由
	// DIRECT_ROUTE: 直接路由
	// OSPF_ROUTE: OSPF 路由
	// OSPFV3_ROUTE: OSPFv3 路由
	// RIP_ROUTE: RIP 路由
	// RIPNG_ROUTE: RIPNG 路由
	// VPN_ROUTE: VPN 路由
	// SSL_VPN_ROUTE: SSL_VPN 路由
	// BGP_ROUTE: BGP 路由
	RouteType string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 路由表Id (0-256, 默认251)
	// 可选值: 250(管理网络路由表), 251(业务网络路由表)
	TableID uint32
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
}

// NextHopStatus 下一跳信息
type NextHopStatus struct {
	NextHopTypes     uint8  `json:"nexthopTypes"`     // 下一跳类型
	NextHopFlags     uint8  `json:"nexthopFlags"`     // 下一跳flag，包含下一跳状态信息，如:是否有效
	Weight           uint8  `json:"weight"`           // 权重
	ExtendEnable     bool   `json:"extendEnable"`     // 下一跳扩展信息中,路由使能标记
	LinkDTStatus     bool   `json:"linkdtStatus"`     // 下一跳扩展信息中,链路探测状态,true有效，false无效
	NextHopStatus    string `json:"nexthopStatus"`    // 下一挑状态
	FIBFlagCharacter string `json:"fibFlagCharacter"` // fib flag character
	InvalidReason    string `json:"invalid_reason"`   // 下一跳无效原因
}

// RouteItem IPv4路由项
type RouteItem struct {
	// 基础信息
	UUID        string `json:"uuid"`        // 资源唯一ID
	Description string `json:"description"` // 描述信息 (最大36字符)

	// 路由配置
	RouteType string   `json:"routeType"` // 类型 (如: "直连路由", "静态路由")
	Prefix    string   `json:"prefix"`    // 目的IP地址/掩码 (IPv4地址格式，示例:192.168.1.0/24)
	Gateway   []string `json:"gateway"`   // 下一跳地址 (字符串数组)
	IfName    []string `json:"ifname"`    // 接口 (字符串数组)

	// 路由参数
	Metric   uint32 `json:"metric"`   // 度量值
	Distance uint8  `json:"distance"` // 管理距离
	TableID  uint32 `json:"tableId"`  // 路由表Id
	Flags    uint8  `json:"flags"`    // 路由标记,包含路由是否有效信息
	Tag      uint32 `json:"tag"`      // zebra路由标记字段,用于过滤路由的需求

	// 状态信息
	Status                 string          `json:"status"`                 // 路由表项状态 (VALID/INVALID)
	NextHopStatus          []NextHopStatus `json:"nexthopStatus"`          // 下一跳信息列表
	LinkDT                 string          `json:"linkdt"`                 // 静态路由关联链路探测
	SelectedFlagsCharacter string          `json:"selectedFlagsCharacter"` // selected flag character
	InvalidReason          string          `json:"invalid_reason"`         // 路由无效原因
}

// GetIPv4RoutesResponse 获取IPv4路由信息列表响应
type GetIPv4RoutesResponse struct {
	Code    int             `json:"code"`    // 错误码
	Message string          `json:"message"` // 错误信息
	Data    json.RawMessage `json:"data"`    // 数据字段，可能是对象或字符串
}

// GetData 获取解析后的数据
func (r *GetIPv4RoutesResponse) GetData() *RouteData {
	if len(r.Data) == 0 || string(r.Data) == `""` {
		return &RouteData{}
	}
	var data RouteData
	if err := json.Unmarshal(r.Data, &data); err != nil {
		return &RouteData{}
	}
	return &data
}

// RouteData IPv4路由数据
type RouteData struct {
	TotalItems    int32       `json:"totalItems"`    // 总共多少项目
	TotalPages    int32       `json:"totalPages"`    // 总共多少页
	PageNumber    int32       `json:"pageNumber"`    // 当前页码，从 1 开始
	PageSize      int32       `json:"pageSize"`      // 每页多大
	ItemsOffset   int32       `json:"itemsOffset"`   // 当前条目偏移，从 0 开始
	ItemLength    int32       `json:"itemLength"`    // 数据列表长度
	PrivateOffset uint64      `json:"privateOffset"` // 内部偏移
	Items         []RouteItem `json:"items"`         // 有效数据列表
}

// NewClient 创建新的路由状态客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:   host,
		token:  token,
		sessid: sessid,
		client: httpClient,
	}
}

// NewClientWithNamespace 创建新的路由状态客户端（指定命名空间）
func NewClientWithNamespace(host, token, sessid, namespace string, httpClient *http.Client) *Client {
	return &Client{
		host:      host,
		token:     token,
		sessid:    sessid,
		namespace: namespace,
		client:    httpClient,
	}
}

// getNamespace 获取命名空间，如果未指定则使用@namespace
func (c *Client) getNamespace() string {
	if c.namespace != "" {
		return c.namespace
	}
	return "@namespace"
}

// GetIPv4Routes 获取IPv4路由信息列表
func (c *Client) GetIPv4Routes(req *GetIPv4RoutesRequest) (*GetIPv4RoutesResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/routes/ipv4", c.host, c.getNamespace())

	// 构建查询参数
	params := url.Values{}

	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.RouteType != "" {
		params.Add("routeType", req.RouteType)
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.TableID > 0 {
		params.Add("tableId", strconv.FormatUint(uint64(req.TableID), 10))
	}
	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
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
	var result GetIPv4RoutesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetIPv4RoutesResponse) IsSuccess() bool {
	return r.Code == 0
}

// GetIPv6RoutesRequest 获取IPv6路由信息列表请求参数
type GetIPv6RoutesRequest struct {
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 获取路由的类型
	// ALL_ROUTE: 所有路由
	// STATIC_ROUTE: 静态路由
	// DIRECT_ROUTE: 直接路由
	// OSPF_ROUTE: OSPF 路由
	// OSPFV3_ROUTE: OSPFv3 路由
	// RIP_ROUTE: RIP 路由
	// RIPNG_ROUTE: RIPNG 路由
	// VPN_ROUTE: VPN 路由
	// SSL_VPN_ROUTE: SSL_VPN 路由
	// BGP_ROUTE: BGP 路由
	RouteType string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 路由表Id (0-256, 默认251)
	// 可选值: 250(管理网络路由表), 251(业务网络路由表)
	TableID uint32
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
}

// IPv6RouteItem IPv6路由项
type IPv6RouteItem struct {
	// 基础信息
	UUID        string `json:"uuid"`        // 资源唯一ID
	Description string `json:"description"` // 描述信息 (最大36字符)

	// 路由配置
	RouteType string   `json:"routeType"` // 类型 (如: "直连路由", "静态路由")
	Prefix    string   `json:"prefix"`    // 目的IPv6地址/掩码 (IPv6地址格式，示例:fe80::40ca:81ff:fea9:a768/24)
	Gateway   []string `json:"gateway"`   // 下一跳IPv6地址 (字符串数组)
	IfName    []string `json:"ifname"`    // 出接口名称 (字符串数组)

	// 路由参数
	Metric   uint32 `json:"metric"`   // 静态路由度量值
	Distance uint8  `json:"distance"` // 路由管理距离
	TableID  uint32 `json:"tableId"`  // 路由表Id
	Flags    uint8  `json:"flags"`    // 路由标记,包含路由是否有效信息
	Tag      uint32 `json:"tag"`      // zebra路由标记字段,用于过滤路由的需求

	// 状态信息
	Status                 string          `json:"status"`                 // 路由表项状态 (VALID/INVALID)
	NextHopStatus          []NextHopStatus `json:"nexthopStatus"`          // 下一跳信息列表
	LinkDTEnable           bool            `json:"linkdtEnable"`           // 静态路由关联链路探测启,禁用开关
	LinkDT                 string          `json:"linkdt"`                 // 静态路由关联链路探测
	SelectedFlagsCharacter string          `json:"selectedFlagsCharacter"` // selected flag character
	InvalidReason          string          `json:"invalid_reason"`         // 路由无效原因
}

// GetIPv6RoutesResponse 获取IPv6路由信息列表响应
type GetIPv6RoutesResponse struct {
	Code    int             `json:"code"`    // 错误码
	Message string          `json:"message"` // 错误信息
	Data    json.RawMessage `json:"data"`    // 数据字段，可能是对象或字符串
}

// GetData 获取解析后的数据
func (r *GetIPv6RoutesResponse) GetData() *IPv6RouteData {
	if len(r.Data) == 0 || string(r.Data) == `""` {
		return &IPv6RouteData{}
	}
	var data IPv6RouteData
	if err := json.Unmarshal(r.Data, &data); err != nil {
		return &IPv6RouteData{}
	}
	return &data
}

// IPv6RouteData IPv6路由数据
type IPv6RouteData struct {
	TotalItems    int32           `json:"totalItems"`    // 总共多少项目
	TotalPages    int32           `json:"totalPages"`    // 总共多少页
	PageNumber    int32           `json:"pageNumber"`    // 当前页码，从 1 开始
	PageSize      int32           `json:"pageSize"`      // 每页多大
	ItemsOffset   int32           `json:"itemsOffset"`   // 当前条目偏移，从 0 开始
	ItemLength    int32           `json:"itemLength"`    // 数据列表长度
	PrivateOffset uint64          `json:"privateOffset"` // 内部偏移
	Items         []IPv6RouteItem `json:"items"`         // 有效数据列表
}

// GetIPv6Routes 获取IPv6路由信息列表
func (c *Client) GetIPv6Routes(req *GetIPv6RoutesRequest) (*GetIPv6RoutesResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/routes/ipv6", c.host, c.getNamespace())

	// 构建查询参数
	params := url.Values{}

	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.RouteType != "" {
		params.Add("routeType", req.RouteType)
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.TableID > 0 {
		params.Add("tableId", strconv.FormatUint(uint64(req.TableID), 10))
	}
	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
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
	var result GetIPv6RoutesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetIPv6RoutesResponse) IsSuccess() bool {
	return r.Code == 0
}
