package pbr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client 策略路由客户端
type Client struct {
	host   string
	token  string
	sessid string
	client *http.Client
}

// GetIPv4PBRsRequest 获取IPv4策略路由列表请求参数
type GetIPv4PBRsRequest struct {
	// 移动搜索参数项，例如搜索10，可获取名称带10以及位置处于10的策略路由 (1-95字符)
	MoveSearch string
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 指定排序方式（正序/倒序）(asc/desc, 默认asc)
	Order string
	// 指定排序字段 (最大100字符)
	SortBy string
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 移动搜索位置参数项
	Position int32
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
}

// OutInterface 策略路由出接口
type OutInterface struct {
	OutIfName string `json:"outifName"` // 出接口名称
	Gateway   string `json:"gateway"`   // 下一跳ip地址 (IPv4地址格式，示例:192.168.1.10)
	LinkDT    string `json:"linkdt"`    // 引用链路探测对象名称
}

// PBRItem IPv4策略路由项
type PBRItem struct {
	// 基础信息
	UUID        string `json:"uuid"`        // 策略路由唯一资源ID
	Name        string `json:"name"`        // 策略路由名称 (1-95字符，必填，不能包含特殊字符)
	Enable      bool   `json:"enable"`      // 启禁用开关
	Description string `json:"description"` // 描述字段 (0-95字符，不能包含特殊字符)

	// 时间计划
	Schedule string `json:"schedule"` // 时间计划名称

	// 匹配条件
	SrcZones      []string `json:"srcZones"`      // 关联区域列表 (必填)
	SrcIPGroups   []string `json:"srcIpGroups"`   // 源地址引用IP组列表 (必填)
	DstIPGroups   []string `json:"dstIpGroups"`   // 目的地址引用IP组列表，目的中3选1
	DstISP        []string `json:"dstIsp"`        // 目的地址引用ISP列表，目的中3选1
	DstCountryArea []string `json:"dstCountryArea"` // 目的地址引用国家/地区列表，目的中3选1

	// 服务和应用
	Services    []string `json:"services"`     // 服务对象列表 (必填)
	Applications []string `json:"applications"` // 关联应用列表

	// 出接口配置
	OutIf []OutInterface `json:"outif"` // 策略路由出接口列表 (必填)

	// 负载均衡
	LBMethod string `json:"lbMethod"` // 多线路模式下，接口选择策略
	// 可选值: POLL(轮询), BANDWIDTH(带宽比例), WEIGHTED_MINIMUM_FLOW(加权最小流量), PRIORITY_FRONT_LINE(优先使用前面线路)

	// 路由表
	TableID uint32 `json:"tableId"` // 策略路由表ID，默认为0 (0-1)

	// 状态信息
	Status   uint8  `json:"status"`   // 策略路由的状态值，状态字段不可设置或修改
	Position int32  `json:"position"` // 策略的位置，状态字段不可设置或修改
	PBRType  string `json:"pbrType"`  // 策略路由类型 (SRCADDRESS)
}

// GetIPv4PBRsResponse 获取IPv4策略路由列表响应
type GetIPv4PBRsResponse struct {
	Code    int    `json:"code"`    // 错误码
	Message string `json:"message"` // 错误信息
	Data    struct {
		TotalItems    int32     `json:"totalItems"`    // 总共多少项目
		TotalPages    int32     `json:"totalPages"`    // 总共多少页
		PageNumber    int32     `json:"pageNumber"`    // 当前页码，从 1 开始
		PageSize      int32     `json:"pageSize"`      // 每页多大
		ItemsOffset   int32     `json:"itemsOffset"`   // 当前条目偏移，从 0 开始
		ItemLength    int32     `json:"itemLength"`    // 数据列表长度
		PrivateOffset uint64    `json:"privateOffset"` // 内部偏移
		Items         []PBRItem `json:"items"`         // 有效数据列表
	} `json:"data"`
}

// NewClient 创建新的策略路由客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:   host,
		token:  token,
		sessid: sessid,
		client: httpClient,
	}
}

// GetIPv4PBRs 获取IPv4策略路由列表
func (c *Client) GetIPv4PBRs(req *GetIPv4PBRsRequest) (*GetIPv4PBRsResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/pbrs/ipv4", c.host)

	// 构建查询参数
	params := url.Values{}

	if req.MoveSearch != "" {
		params.Add("movesearch", req.MoveSearch)
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.Order != "" {
		params.Add("_order", req.Order)
	}
	if req.SortBy != "" {
		params.Add("_sortby", req.SortBy)
	}
	if req.Select != "" {
		params.Add("_select", req.Select)
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.Position > 0 {
		params.Add("position", strconv.FormatInt(int64(req.Position), 10))
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
	var result GetIPv4PBRsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetIPv4PBRsResponse) IsSuccess() bool {
	return r.Code == 0
}

