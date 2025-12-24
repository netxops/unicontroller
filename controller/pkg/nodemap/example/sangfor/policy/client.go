package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client 安全防护策略客户端
type Client struct {
	host      string
	token     string
	sessid    string
	namespace string // 命名空间，如果为空则使用@namespace
	client    *http.Client
}

// GetSecuritysRequest 获取安全防护策略请求参数
type GetSecuritysRequest struct {
	// 筛选-源IP (ip-address格式)
	SrcIP string
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
	// 筛选-目的IP (ip-address格式)
	DstIP string
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 安全防护策略类型
	// SERVER: 业务防护策略
	// INTERNET_ACCESS: 用户防护策略
	PolicyType string
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
	// 模糊搜索关键字 (最大95字符)
	Search string
}

// SrcAddrs 源网络对象/用户
type SrcAddrs struct {
	SrcAddrType string   `json:"srcAddrType"` // 源地址类型 (NETOBJECT/USERS)
	Users       []string `json:"users"`       // 源用户
	UserGroups  []string `json:"userGroups"`  // 源用户组
	SrcIPGroups []string `json:"srcIpGroups"` // 源网络对象
}

// Monitor 评估
type Monitor struct {
	PVSEnable  bool   `json:"pvsEnable"`  // 开启实时漏洞分析
	CreateTime string `json:"createTime"` // PVS开启时间 (格式: YYYY-MM-DD HH:MM:SS)
}

// DefenceAction 防御动作
type DefenceAction struct {
	Enable   bool   `json:"enable"`   // 是否开启
	Template string `json:"template"` // 模板
	Action   string `json:"action"`   // 动作 (ALLOW/DENY)
}

// Defence 防御
type Defence struct {
	IPS         DefenceAction `json:"ips"`         // 漏洞攻击防护
	ContextSafe DefenceAction `json:"contextsafe"` // 内容安全
	WAF         DefenceAction `json:"waf"`         // WEB应用防护
}

// Block 联动封锁
type Block struct {
	Enable bool   `json:"enable"` // 开启联动封锁
	Type   string `json:"type"`   // 类型 (HIGH_THREATS/ANY_THREAT)
}

// Response 检测响应
type Response struct {
	UTM              DefenceAction `json:"utm"`              // 僵尸网络
	InnerDNSOptimize bool          `json:"innerDnsOptimize"` // 启用内网DNS服务器场景优化
	LocalDNSIP       []string      `json:"localDnsIp"`       // 内网DNS服务器
	RecordLog        bool          `json:"recordLog"`        // 记录日志
	Block            Block         `json:"block"`            // 联动封锁
}

// HighlightItem 高亮项
type HighlightItem struct {
	Exact    []string `json:"exact"`    // 精确搜索高亮字符串
	Fuzzy    string   `json:"fuzzy"`    // 模糊搜索高亮字符串
	Position string   `json:"position"` // 模糊搜索高亮位置
}

// Highlight 策略搜索结果，用于前端高亮
type Highlight struct {
	Search HighlightItem `json:"search"` // search字段搜索结果
	SrcIP  HighlightItem `json:"srcip"`  // 过滤源IP搜索结果
	DstIP  HighlightItem `json:"dstip"`  // 过滤目的IP搜索结果
}

// SecurityItem 安全防护策略项
type SecurityItem struct {
	UUID        string    `json:"uuid"`        // 唯一标识id
	Name        string    `json:"name"`        // 唯一标识名称
	Description string    `json:"description"` // 描述
	Enable      bool      `json:"enable"`      // 是否启用
	PolicyType  string    `json:"policyType"`  // 安全防护策略类型 (SERVER/INTERNET_ACCESS)
	SrcZones    []string  `json:"srcZones"`    // 源区域
	SrcAddrs    SrcAddrs  `json:"srcAddrs"`    // 源网络对象/用户
	DstZones    []string  `json:"dstZones"`    // 目的区域
	DstIPGroups []string  `json:"dstIpGroups"` // 目的网络对象
	Strategy    string    `json:"strategy"`    // 业务访问场景 (NOT_VIA_SNAT_CDN/VIA_SNAT_CDN)
	Position    uint32    `json:"position"`    // 位置 (0-1024)
	Monitor     Monitor   `json:"monitor"`     // 评估
	Defence     Defence   `json:"defence"`     // 防御
	Response    Response  `json:"response"`    // 检测响应
	Highlight   Highlight `json:"highlight"`   // 策略搜索结果，用于前端高亮
}

// GetSecuritysResponse 获取安全防护策略响应
type GetSecuritysResponse struct {
	Code    int    `json:"code"`    // 错误码
	Message string `json:"message"` // 错误信息
	Data    struct {
		TotalItems    int32          `json:"totalItems"`    // 总共多少项目
		TotalPages    int32          `json:"totalPages"`    // 总共多少页
		PageNumber    int32          `json:"pageNumber"`    // 当前页码，从 1 开始
		PageSize      int32          `json:"pageSize"`      // 每页多大
		ItemsOffset   int32          `json:"itemsOffset"`   // 当前条目偏移，从 0 开始
		ItemLength    int32          `json:"itemLength"`    // 数据列表长度
		PrivateOffset uint64         `json:"privateOffset"` // 内部偏移
		Items         []SecurityItem `json:"items"`         // 有效数据列表
	} `json:"data"`
}

// NewClient 创建新的安全防护策略客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:      host,
		token:     token,
		sessid:    sessid,
		namespace: "", // 默认使用@namespace
		client:    httpClient,
	}
}

// NewClientWithNamespace 创建新的安全防护策略客户端（指定命名空间）
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

// GetSecuritys 获取安全防护策略列表
func (c *Client) GetSecuritys(req *GetSecuritysRequest) (*GetSecuritysResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/securitys", c.host, c.getNamespace())
	// 构建查询参数
	params := url.Values{}

	if req.SrcIP != "" {
		params.Add("srcip", req.SrcIP)
	}
	if req.Select != "" {
		params.Add("_select", req.Select)
	}
	if req.DstIP != "" {
		params.Add("dstip", req.DstIP)
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.PolicyType != "" {
		params.Add("policyType", req.PolicyType)
	}
	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
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
	var result GetSecuritysResponse
	if err := json.Unmarshal(body, &result); err != nil {
		// 如果解析失败，返回包含原始响应体的错误
		return nil, fmt.Errorf("unmarshal response (HTTP %d): %w, body: %s", resp.StatusCode, err, string(body))
	}

	// 如果HTTP状态码不是200，记录警告信息
	if resp.StatusCode != http.StatusOK {
		return &result, fmt.Errorf("HTTP status %d: %s, body: %s", resp.StatusCode, resp.Status, string(body))
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetSecuritysResponse) IsSuccess() bool {
	return r.Code == 0
}

// GetAppcontrolsRequest 获取应用控制策略请求参数
type GetAppcontrolsRequest struct {
	// 过滤id，保留字段
	ID uint32
	// 匹配目的ip地址
	DstIP string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 过滤动作 (0:拒绝, 1:允许)
	Action uint32
	// 指定排序字段 (最大100字符)
	SortBy string
	// 指定排序方式（正序/倒序）(asc/desc, 默认asc)
	Order string
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
	// 过滤失效状态策略
	InvalidStatus bool
	// 匹配源ip地址
	SrcIP string
	// 过滤策略组
	PolicyGroup string
	// 资源名
	Name string
	// 过滤标签
	Label string
	// 资源全局唯一ID
	UUID string
	// 过滤启禁用
	Enable bool
	// 过滤或匹配目的区域
	DstZone string
	// 匹配时间
	ActionTime string
	// 匹配协议 (0-255)
	ProtoNum uint8
	// 匹配目的端口 (0-65535)
	DstPort uint16
	// 匹配源端口 (0-65535)
	SrcPort uint16
	// 过滤或匹配源区域
	SrcZone string
}

// AppcontrolSrcAddrs 应用控制策略源地址信息
type AppcontrolSrcAddrs struct {
	SrcAddrType string   `json:"srcAddrType"` // 源地址类型 (NETOBJECT/USERGROUP/MAC)
	SrcMacAddrs []string `json:"srcMacAddrs"` // 源mac地址列表，源地址类型为"MAC"时使用
	Users       []string `json:"users"`       // 用户列表，源地址类型为"USERGROUP"时使用
	UserGroups  []string `json:"userGroups"`  // 用户组列表，源地址类型为"USERGROUP"时使用
	SrcIPGroups []string `json:"srcIpGroups"` // 源ip组列表，源地址类型为"NETOBJECT"时使用
	UserAllList []string `json:"userAllList"` // appcontrol: user all list
}

// AppcontrolSrc 应用控制策略源地址
type AppcontrolSrc struct {
	SrcZones []string           `json:"srcZones"` // 源区域列表
	SrcAddrs AppcontrolSrcAddrs `json:"srcAddrs"` // 源地址信息
}

// AppcontrolDstAddrs 应用控制策略目的地址
type AppcontrolDstAddrs struct {
	DstAddrType string   `json:"dstAddrType"` // 目的地址类型 (NETOBJECT/MAC/DOMAIN)
	DstMacAddrs []string `json:"dstMacAddrs"` // 目的mac地址列表，目的地址类型为"MAC"时使用
	Domains     []string `json:"domains"`     // 域名列表，目的地址类型为"DOMAIN"时使用
	DstIPGroups []string `json:"dstIpGroups"` // 目的ip组列表，目的地址类型为"NETOBJECT"时使用
}

// AppcontrolDst 应用控制策略目的地址
type AppcontrolDst struct {
	DstZones     []string           `json:"dstZones"`     // 引用目的区域列表
	DstAddrs     AppcontrolDstAddrs `json:"dstAddrs"`     // 目的地址
	Services     []string           `json:"services"`     // 服务引用列表
	Applications []string           `json:"applications"` // 应用引用列表
}

// AdvanceOption 应用控制策略高级选项
type AdvanceOption struct {
	LogEnable               bool  `json:"logEnable"`               // 是否开启会话日志策略命中记录
	SessionDestroyLogEnable bool  `json:"sessionDestroyLogEnable"` // 是否开启会话结束日志
	AutoSynDNS              bool  `json:"autoSynDNS"`              // 是否开启主动查询域名
	KeepAlive               uint8 `json:"keepAlive"`               // 设置长连接，可选值[0,1,3,7,10,15]
}

// AppcontrolItem 应用控制策略项
type AppcontrolItem struct {
	UUID          string        `json:"uuid"`          // uuid
	Name          string        `json:"name"`          // 应用控制策略名称
	ShowName      string        `json:"showname"`      // 策略显示名称
	Description   string        `json:"description"`   // 应用控制策略描述
	Position      int32         `json:"position"`      // 应用控制策略位置
	Enable        bool          `json:"enable"`        // 应用控制策略启禁用
	UpdateTime    string        `json:"updateTime"`    // 应用控制策略更新时间
	DurationTime  string        `json:"durationTime"`  // 应用控制策略最近一次状态更新时间
	Group         string        `json:"group"`         // 应用控制策略组
	Labels        []string      `json:"labels"`        // 应用控制策略标签列表
	Src           AppcontrolSrc `json:"src"`           // 应用控制策略源地址
	Dst           AppcontrolDst `json:"dst"`           // 应用控制策略目的地址
	Action        uint32        `json:"action"`        // 应用控制策略动作，允许或拒绝 (0:拒绝, 1:允许)
	Schedule      string        `json:"schedule"`      // 应用控制策略生效时间
	AdvanceOption AdvanceOption `json:"advanceOption"` // 应用控制策略高级选项
	Reason        string        `json:"reason"`        // 应用控制策略变更原因
	IsDefault     bool          `json:"isdefault"`     // 是否是默认策略
	LastHitTime   string        `json:"lastHitTime"`   // 策略最近一次匹配命中时间
	Hits          uint64        `json:"hits"`          // 应用控制策略命中匹配次数
	Profile       string        `json:"profile"`       // acl policy profile
}

// GetAppcontrolsResponse 获取应用控制策略响应
type GetAppcontrolsResponse struct {
	Code    int    `json:"code"`    // 错误码
	Message string `json:"message"` // 错误信息
	Data    struct {
		TotalItems  int32            `json:"totalItems"`  // 总共多少项目
		TotalPages  int32            `json:"totalPages"`  // 总共多少页
		PageNumber  int32            `json:"pageNumber"`  // 当前页码，从 1 开始
		PageSize    int32            `json:"pageSize"`    // 每页多大
		ItemsOffset int32            `json:"itemsOffset"` // 当前条目偏移，从 0 开始
		ItemLength  int32            `json:"itemLength"`  // 数据列表长度
		Items       []AppcontrolItem `json:"items"`       // 有效数据列表
	} `json:"data"`
}

// GetAppcontrols 获取应用控制策略列表
func (c *Client) GetAppcontrols(req *GetAppcontrolsRequest) (*GetAppcontrolsResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/appcontrols/policys", c.host, c.getNamespace())

	// 构建查询参数
	params := url.Values{}

	if req.ID > 0 {
		params.Add("id", strconv.FormatUint(uint64(req.ID), 10))
	}
	if req.DstIP != "" {
		params.Add("dstIp", req.DstIP)
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	// Action可以是0(拒绝)或1(允许)
	// 注意：由于uint32零值就是0，我们无法区分"未设置"和"设置为0"
	// 如果用户需要过滤Action，应该明确设置Action值（0或1）
	// 这里我们假设如果用户设置了Action（包括0），就添加到请求中
	// 如果后续需要更精确的控制（区分"未设置"和"设置为0"），可以考虑使用指针类型 *uint32
	// 当前实现：如果Action<=1（即0或1），就添加到请求中
	// 这意味着如果用户没有设置Action，默认值0也会被添加，可能不是期望的行为
	// 如果不需要过滤Action，建议不要设置该字段，或者后续改为指针类型
	if req.SortBy != "" {
		params.Add("_sortby", req.SortBy)
	}
	if req.Order != "" {
		params.Add("_order", req.Order)
	}
	if req.Select != "" {
		params.Add("_select", req.Select)
	}
	if req.InvalidStatus {
		params.Add("invalidStatus", "true")
	}
	if req.SrcIP != "" {
		params.Add("srcIp", req.SrcIP)
	}
	if req.PolicyGroup != "" {
		params.Add("policyGroup", req.PolicyGroup)
	}
	if req.Name != "" {
		params.Add("name", req.Name)
	}
	if req.Label != "" {
		params.Add("label", req.Label)
	}
	if req.UUID != "" {
		params.Add("uuid", req.UUID)
	}
	if req.Enable {
		params.Add("enable", "true")
	}
	if req.DstZone != "" {
		params.Add("dstZone", req.DstZone)
	}
	if req.ActionTime != "" {
		params.Add("actionTime", req.ActionTime)
	}
	if req.ProtoNum > 0 {
		params.Add("protoNum", strconv.FormatUint(uint64(req.ProtoNum), 10))
	}
	if req.DstPort > 0 {
		params.Add("dstPort", strconv.FormatUint(uint64(req.DstPort), 10))
	}
	if req.SrcPort > 0 {
		params.Add("srcPort", strconv.FormatUint(uint64(req.SrcPort), 10))
	}
	if req.SrcZone != "" {
		params.Add("srcZone", req.SrcZone)
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
	var result GetAppcontrolsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		// 如果解析失败，返回包含原始响应体的错误
		return nil, fmt.Errorf("unmarshal response (HTTP %d): %w, body: %s", resp.StatusCode, err, string(body))
	}

	// 如果HTTP状态码不是200，记录警告信息
	if resp.StatusCode != http.StatusOK {
		return &result, fmt.Errorf("HTTP status %d: %s, body: %s", resp.StatusCode, resp.Status, string(body))
	}

	return &result, nil
}

// IsSuccess 检查应用控制策略请求是否成功
func (r *GetAppcontrolsResponse) IsSuccess() bool {
	return r.Code == 0
}
