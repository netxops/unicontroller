package network

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client 网络对象客户端
type Client struct {
	host   string
	token  string
	sessid string
	client *http.Client
}

// GetNetObjsRequest 获取网络对象请求参数
type GetNetObjsRequest struct {
	// 过滤参数：是否过滤名字为全部的IP组 (TRUE/FALSE)
	ExcludeAll string
	// 网络对象组名字前缀过滤 (1-95字符)
	NamePrefix string
	// 过滤参数：是否过滤敏感数据业务 (TRUE/FALSE/ALL)
	HasSensitiveData string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 过滤参数：传入一个网络对象的uuid，查找指定网络对象被哪些地址组引用 (32字符)
	GetRefBy string
	// 过滤参数：ip协议版本 (IPV4/IPV6/ALL)
	AddressType string
	// 过滤参数：是否过滤被引用的网络对象 (TRUE/FALSE)
	HasRef string
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 过滤参数：重要级别 (COMMON/CORE/ALL)
	Important string
	// 指定排序字段 (最大100字符)
	SortBy string
	// 过滤参数：业务类型过滤
	// ADDRGROUP: 地址组
	// IP: IP地址
	// USER: 用户地址
	// BUSINESS: 业务地址
	// DOMAINS: 域名网络对象
	// OTHERTHANDOMAINS: 不是域名网络对象
	// ALL: 不过滤业务类型
	BusinessType string
	// 指定排序方式（正序/倒序）(asc/desc, 默认asc)
	Order string
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
}

// IPRange IP范围
// 根据 network.json 定义：ip表项组，包含起始IP、结束IP和掩码信息
type IPRange struct {
	Start string `json:"start"` // ip范围的起始位置 (ip-address格式，必填)
	End   string `json:"end"`   // ip范围的终止位置 (ip-address格式，可选)
	Bits  uint8  `json:"bits"`  // ip掩码简写 (可选)
}

// NetObjItem 网络对象项
// 根据 network.json 定义：完整的网络对象结构，包含所有字段
type NetObjItem struct {
	// 基础信息
	UUID        string `json:"uuid"`        // 资源唯一ID
	Name        string `json:"name"`        // 网络对象组名字 (1-95字符，必填，不能包含特殊字符)
	ID          uint16 `json:"id"`          // autoid
	Description string `json:"description"` // 描述字段 (0-95字符，可选，不能包含特殊字符)

	// 类型和分类
	BusinessType string `json:"businessType"` // 网络对象组类型 (必填)
	// 可选值: IP, BUSINESS, USER, ADDRGROUP, DOMAINS
	AddressType string `json:"addressType"` // 地址类型 (可选)
	// 可选值: IPV4, IPV6
	Important string `json:"important"` // 重要级别 (可选)
	// 可选值: COMMON(普通用户或普通业务), CORE(核心用户或核心业务)

	// IP范围信息
	IPRanges []IPRange `json:"ipRanges"` // ip表项组 (与refIpGroup二选一)
	// 每个IPRange包含: start(必填), end(可选), bits(可选)

	// 引用信息
	RefIPGroup []string `json:"refIpGroup"` // 地址组引用的IP组对象列表 (与ipRanges二选一)

	// 域名信息
	Domains           []string `json:"domains"`           // 域名对象 (字符串数组)
	DomainsDetectMode string   `json:"domainsDetectMode"` // 域名对象探测模式 (可选)
	// 可选值: ACTIVE(主动探测), PASSIVE(被动学习)

	// 敏感数据相关
	DataStatus string `json:"dataStatus"` // 敏感数据识别方式 (可选)
	// 可选值: AUTO(系统自动识别), EXIST(存在), NOT-EXIST(不存在)
	PageNum int32 `json:"pageNum"` // 敏感数据页面数

	// 状态信息
	HasRef    bool   `json:"hasref"`    // 标识是否被引用
	IsDefault bool   `json:"isdefault"` // 标识是否是默认配置
	ShowName  string `json:"showname"`  // 标识默认配置的名字
}

// GetNetObjsResponse 获取网络对象响应
type GetNetObjsResponse struct {
	Code    int    `json:"code"`    // 错误码
	Message string `json:"message"` // 错误信息
	Data    struct {
		TotalItems    int32        `json:"totalItems"`    // 总共多少项目
		TotalPages    int32        `json:"totalPages"`    // 总共多少页
		PageNumber    int32        `json:"pageNumber"`    // 当前页码，从 1 开始
		PageSize      int32        `json:"pageSize"`      // 每页多大
		ItemsOffset   int32        `json:"itemsOffset"`   // 当前条目偏移，从 0 开始
		ItemLength    int32        `json:"itemLength"`    // 数据列表长度
		PrivateOffset uint64       `json:"privateOffset"` // 内部偏移
		Items         []NetObjItem `json:"items"`         // 有效数据列表
	} `json:"data"`
}

// NewClient 创建新的网络对象客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:   host,
		token:  token,
		sessid: sessid,
		client: httpClient,
	}
}

// GetNetObjs 获取网络对象列表
func (c *Client) GetNetObjs(req *GetNetObjsRequest) (*GetNetObjsResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/ipgroups", c.host)

	// 构建查询参数
	params := url.Values{}

	if req.ExcludeAll != "" {
		params.Add("excludeAll", req.ExcludeAll)
	}
	if req.NamePrefix != "" {
		params.Add("__nameprefix", req.NamePrefix)
	}
	if req.HasSensitiveData != "" {
		params.Add("hasSensitiveData", req.HasSensitiveData)
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.GetRefBy != "" {
		params.Add("getRefBy", req.GetRefBy)
	}
	if req.AddressType != "" {
		params.Add("addressType", req.AddressType)
	}
	if req.HasRef != "" {
		params.Add("hasref", req.HasRef)
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.Important != "" {
		params.Add("important", req.Important)
	}
	if req.SortBy != "" {
		params.Add("_sortby", req.SortBy)
	}
	if req.BusinessType != "" {
		params.Add("businessType", req.BusinessType)
	}
	if req.Order != "" {
		params.Add("_order", req.Order)
	}
	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
	}
	if req.Select != "" {
		params.Add("_select", req.Select)
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
	var result GetNetObjsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetNetObjsResponse) IsSuccess() bool {
	return r.Code == 0
}
