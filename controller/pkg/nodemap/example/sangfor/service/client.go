package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client 服务客户端
type Client struct {
	host   string
	token  string
	sessid string
	client *http.Client
}

// GetServicesRequest 获取服务列表请求参数
type GetServicesRequest struct {
	// 服务名字前缀过滤 (1-95字符)
	NamePrefix string
	// 指定排序字段 (最大100字符)
	SortBy string
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 指定排序方式（正序/倒序）(asc/desc, 默认asc)
	Order string
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
	// 请求服务列表的模块名
	// OBJ_WAF: 对象-WEB应用防护
	QueryListModule string
	// 过滤服务类别
	// PREDEF_SERV: 预定义服务
	// USRDEF_SERV: 自定义服务
	// SERV: 服务
	// SERV_GRP: 服务组
	ServType string
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
}

// PortRange 端口范围
type PortRange struct {
	Start int32 `json:"start"` // 起始端口 (0-65535)
	End   int32 `json:"end"`   // 结束端口 (0-65535)
}

// TCPEntry TCP条目
type TCPEntry struct {
	SrcPorts []PortRange `json:"srcPorts"` // 源端口信息
	DstPorts []PortRange `json:"dstPorts"` // 目的端口信息
}

// UDPEntry UDP条目
type UDPEntry struct {
	SrcPorts []PortRange `json:"srcPorts"` // 源端口信息
	DstPorts []PortRange `json:"dstPorts"` // 目的端口信息
}

// ICMPEntry ICMP条目
type ICMPEntry struct {
	Type uint8 `json:"type"` // 类型，255表示全部 (0-255)
	Code uint8 `json:"code"` // 代码，255表示全部 (0-255)
}

// ICMPv6Entry ICMPv6条目
type ICMPv6Entry struct {
	Type uint8 `json:"type"` // 类型，255表示全部 (0-255)
	Code uint8 `json:"code"` // 代码，255表示全部 (0-255)
}

// ServiceItem 服务项
type ServiceItem struct {
	UUID        string        `json:"uuid"`        // 唯一资源id
	Name        string        `json:"name"`        // 服务名称
	ID          uint16        `json:"id"`          // autoid
	Description string        `json:"description"` // 描述字段
	ServType    string        `json:"servType"`    // 预定义服务或自定义服务或服务组
	TCPEntrys   []TCPEntry    `json:"tcpEntrys"`  // tcp条目列表，服务类型为预定义服务或自定义服务时使用
	UDPEntrys   []UDPEntry    `json:"udpEntrys"`  // udp条目列表，服务类型为预定义服务或自定义服务时使用
	ICMPEntrys  []ICMPEntry   `json:"icmpEntrys"` // icmp条目列表，服务类型为预定义服务或自定义服务时使用
	ICMPv6Entrys []ICMPv6Entry `json:"icmpv6Entrys"` // icmpv6条目列表，服务类型为预定义服务或自定义服务时使用
	Other       []uint16      `json:"other"`       // 其他协议号列表，其中256表示除tcp,udp,icmp,icmpv6之外的所有其他协议号
	ServsInfo   []string      `json:"servsInfo"`   // 服务组勾选的服务，服务类型为服务组时使用
	HasRef      bool          `json:"hasref"`      // 标识是否被引用
}

// GetServicesResponse 获取服务列表响应
type GetServicesResponse struct {
	Code    int    `json:"code"`    // 错误码
	Message string `json:"message"`  // 错误信息
	Data    struct {
		TotalItems   int32         `json:"totalItems"`   // 总共多少项目
		TotalPages   int32         `json:"totalPages"`   // 总共多少页
		PageNumber   int32         `json:"pageNumber"`   // 当前页码，从 1 开始
		PageSize     int32         `json:"pageSize"`     // 每页多大
		ItemsOffset  int32         `json:"itemsOffset"`  // 当前条目偏移，从 0 开始
		ItemLength   int32         `json:"itemLength"`   // 数据列表长度
		PrivateOffset uint64       `json:"privateOffset"` // 内部偏移
		Items         []ServiceItem `json:"items"`        // 有效数据列表
	} `json:"data"`
}

// NewClient 创建新的服务客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:   host,
		token:  token,
		sessid: sessid,
		client: httpClient,
	}
}

// GetServices 获取服务列表
func (c *Client) GetServices(req *GetServicesRequest) (*GetServicesResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/services", c.host)

	// 构建查询参数
	params := url.Values{}

	if req.NamePrefix != "" {
		params.Add("__nameprefix", req.NamePrefix)
	}
	if req.SortBy != "" {
		params.Add("_sortby", req.SortBy)
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.Order != "" {
		params.Add("_order", req.Order)
	}
	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
	}
	if req.QueryListModule != "" {
		params.Add("queryListModule", req.QueryListModule)
	}
	if req.ServType != "" {
		params.Add("servType", req.ServType)
	}
	if req.Select != "" {
		params.Add("_select", req.Select)
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
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
	var result GetServicesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetServicesResponse) IsSuccess() bool {
	return r.Code == 0
}

