package nat

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client NAT策略客户端
type Client struct {
	host   string
	token  string
	sessid string
	client *http.Client
}

// GetNatsRequest 获取NAT策略请求参数
type GetNatsRequest struct {
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
	// 移动搜索参数项 (1-95字符)
	MoveSearch string
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 移动搜索位置参数项
	Position int
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
	// NAT名字前缀过滤 (1-95字符)
	NamePrefix string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 用于指定转换类型, 可选SNAT,DNAT,BNAT
	TransType string
}

// IPRange IP范围
type IPRange struct {
	Start string `json:"start"` // IP范围起始地址
	End   string `json:"end"`   // IP范围结束地址
}

// PortRange 端口范围
type PortRange struct {
	Start int32 `json:"start"` // 网络端口起始值 (0-65535)
	End   int32 `json:"end"`   // 网络端口结束值 (0-65535)
}

// DstNetobj 目的网络对象（SNAT使用）
type DstNetobj struct {
	DstNetobjType string   `json:"dstNetobjType"` // 需要匹配的目的类型 (ZONE/INTERFACE)
	Interface     string   `json:"interface"`     // 目的接口，当dstNetobjType类型为INTERFACE时选择
	Zone          []string `json:"zone"`          // 目的区域，当dstNetobjType类型为ZONE时选择
}

// Transfer SNAT转换信息
type Transfer struct {
	TransferType string     `json:"transferType"` // 源转换类型
	Sticky       string     `json:"sticky"`       // 转换模式开关 (OFF/STRICT/LOOSE)
	IPRange      *IPRange   `json:"ipRange"`      // 源转换IP范围参数，当transferType转换类型为IP_RANGE时选择
	TranferMode  string     `json:"tranferMode"`  // IP范围转换模式 (STATIC/DYNAMIC)
	SpecifyIP    string     `json:"specifyIp"`    // 转换的单个IP
	IPGroups     []string   `json:"ipGroups"`     // 转换的IP组
	TransPort    *TransPort `json:"transPort"`    // 源转换端口配置参数
}

// TransPort 源转换端口配置参数
type TransPort struct {
	PortMode  string    `json:"portMode"`  // 端口分配类型 (RANDOM/STATIC_BLOCK)
	PortRange PortRange `json:"portRange"` // 端口范围
	BlockSize uint16    `json:"blockSize"` // 端口段大小
}

// SNATInfo SNAT信息
type SNATInfo struct {
	SrcZones    []string  `json:"srcZones"`    // 需要匹配的源区域
	SrcIPGroups []string  `json:"srcIpGroups"` // 需要匹配的源IP组
	DstNetobj   DstNetobj `json:"dstNetobj"`   // 需要匹配的目的区域或者接口
	DstIPGroups []string  `json:"dstIpGroups"` // 需要匹配的目的IP组
	NatService  []string  `json:"natService"`  // 引用的服务组
	Transfer    Transfer  `json:"transfer"`    // 源地址转换相关数据
}

// DstIPobj 目的IP对象（DNAT/BNAT使用）
type DstIPobj struct {
	DstIPobjType string   `json:"dstIpobjType"` // 目的类型 (IPGROUP/IP)
	SpecifyIP    []string `json:"specifyIp"`    // 指定的IP数组，当dstIpobjType目的类型为IP时选择
	IPGroups     []string `json:"ipGroups"`     // 目的地址指定的IP组，当dstIpobjType目的类型为IPGROUP时选择
}

// DNATTransfer DNAT转换信息
type DNATTransfer struct {
	TransferType         string      `json:"transferType"`         // 目的转换类型
	DNATEnableScheduling bool        `json:"dnatEnableScheduling"` // 目的转换使用负载均衡
	IPRange              *IPRange    `json:"ipRange"`              // 转换的IP范围，当transferType转换类型为IP_RANGE时选择
	SpecifyIP            string      `json:"specifyIp"`            // 转换的单个IP
	IPPrefix             string      `json:"ipPrefix"`             // IPv4网段,掩码格式
	IPGroups             []string    `json:"ipGroups"`             // 转换的IP组
	TransferPort         []PortRange `json:"transferPort"`         // 转换端口，数组为空表示不转换端口
	SLBPool              string      `json:"slbPool"`              // 引用负载均衡地址池对象
}

// DNATInfo DNAT信息
type DNATInfo struct {
	SrcZones      []string     `json:"srcZones"`      // 需要匹配的源区域
	SrcIPGroups   []string     `json:"srcIpGroups"`   // 需要匹配的源IP组
	DstIPobj      DstIPobj     `json:"dstIpobj"`      // 需要匹配的目的IP组或者IP
	NatService    []string     `json:"natService"`    // 引用的服务组
	Transfer      DNATTransfer `json:"transfer"`      // 目的地址转换相关数据
	DNATIgnoreACL bool         `json:"dnatIgnoreAcl"` // 忽略访问控制
	BypassACLLog  bool         `json:"bypassAclLog"`  // 忽略访问控制匹配上策略上报会话日志
}

// BNATTransferDst BNAT目的转换信息
type BNATTransferDst struct {
	TransferType         string      `json:"transferType"`         // 转换类型
	DNATEnableScheduling bool        `json:"dnatEnableScheduling"` // 双向转换使用负载均衡
	IPRange              *IPRange    `json:"ipRange"`              // 转换的IP范围，当transferType转换类型为IP_RANGE时选择
	SpecifyIP            string      `json:"specifyIp"`            // 转换的单个IP，当transferType转换类型为IP时选择
	IPPrefix             string      `json:"ipPrefix"`             // IPv4网段,掩码格式
	IPGroups             []string    `json:"ipGroups"`             // 转换的IP组，当transferType转换类型为IPGROUP时选择
	TransferPort         []PortRange `json:"transferPort"`         // 转换端口，数组为空表示不转换端口
	SLBPool              string      `json:"slbPool"`              // 引用负载均衡地址池对象
}

// BNATTransferSrc BNAT源转换信息
type BNATTransferSrc struct {
	TransferType string   `json:"transferType"` // 转换类型
	IPRange      *IPRange `json:"ipRange"`      // 转换的IP范围，当transferType转换类型为IP_RANGE时选择
	TranferMode  string   `json:"tranferMode"`  // 转换模式 (STATIC/DYNAMIC)
	SpecifyIP    string   `json:"specifyIp"`    // 转换的单个IP，当transferType转换类型为IP时选择
	IPGroups     []string `json:"ipGroups"`     // 转换的IP组，当transferType转换类型为IPGROUP时选择
}

// BNATInfo BNAT信息
type BNATInfo struct {
	SrcZones      []string        `json:"srcZones"`      // 需要匹配的源区域
	SrcIPGroups   []string        `json:"srcIpGroups"`   // 需要匹配的源IP组
	DstIPobj      DstIPobj        `json:"dstIpobj"`      // 需要匹配的目的IP组或者IP
	NatService    []string        `json:"natService"`    // 引用的服务组
	TransferDst   BNATTransferDst `json:"transferDst"`   // 目的转换相关数据
	DNATIgnoreACL bool            `json:"dnatIgnoreAcl"` // 忽略访问控制
	BypassACLLog  bool            `json:"bypassAclLog"`  // 忽略访问控制匹配上策略上报会话日志
	TransferSrc   BNATTransferSrc `json:"transferSrc"`   // 源转换相关数据
}

// NATItem NAT策略项
type NATItem struct {
	UUID        string    `json:"uuid"`        // 唯一标识ID
	Name        string    `json:"name"`        // 策略名称
	NATHit      uint64    `json:"natHit"`      // nat策略匹配次数
	Enable      bool      `json:"enable"`      // 是否启用
	Position    int32     `json:"position"`    // 表示位置状态
	NATType     string    `json:"natType"`     // nat类型 (SNAT/DNAT/BNAT)
	Description string    `json:"description"` // 描述
	Schedule    string    `json:"schedule"`    // 生效时间，引用时间计划对象
	SNAT        *SNATInfo `json:"snat"`        // snat信息,策略类型为源地址转换时使用
	DNAT        *DNATInfo `json:"dnat"`        // dnat信息,策略类型为目的地址转换时使用
	BNAT        *BNATInfo `json:"bnat"`        // bnat信息,策略类型为双向转换时使用
}

// GetNatsResponse 获取NAT策略响应
type GetNatsResponse struct {
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
		Items         []NATItem `json:"items"`         // 有效数据列表
	} `json:"data"`
}

// NewClient 创建新的NAT策略客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:   host,
		token:  token,
		sessid: sessid,
		client: httpClient,
	}
}

// GetNats 获取NAT策略列表
func (c *Client) GetNats(req *GetNatsRequest) (*GetNatsResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/nats", c.host)

	// 构建查询参数
	params := url.Values{}

	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
	}
	if req.MoveSearch != "" {
		params.Add("movesearch", req.MoveSearch)
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.Position > 0 {
		params.Add("position", strconv.Itoa(req.Position))
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
	if req.TransType != "" {
		params.Add("transType", req.TransType)
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
	var result GetNatsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetNatsResponse) IsSuccess() bool {
	return r.Code == 0
}
