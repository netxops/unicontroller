package interface_

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Client 接口客户端
type Client struct {
	host      string
	token     string
	sessid    string
	namespace string // 命名空间，如果为空则使用@namespace
	client    *http.Client
}

// GetInterfacesRequest 获取接口列表请求参数
type GetInterfacesRequest struct {
	// 获取可选择的HA接口
	HAItf bool
	// 获取虚拟IP可使用的接口
	VirtualHAItf bool
	// 获取监视端口vlan和接口
	HAMonitorItf bool
	// 模糊搜索关键字 (最大95字符)
	Search string
	// 过滤参数：接口类型
	// PHYSICALIF: 物理口
	// SUBIF: 子接口
	// CHANNELIF: 汇聚口
	// VLANIF: vlan对应的3层接口
	// LOOPBACK: 本地环回口
	// GRETUN: GRE隧道
	// VSYSIF: 虚拟接口
	// TUNNELIF: 隧道口
	IfType string
	// 起始位置，从 0 开始 (0-2000000, 默认0)
	Start int
	// 获取最大长度，限制最大值，如果数据不够可能返回小于 length (1-200, 默认100)
	Length int
	// 过滤参数：接口模式，用于物理口，聚合口
	// ROUTE: 路由类型，接口作为3层接口
	// SWITCH: 交换类型，接口作为2层接口
	// VIRTUALLINE: 虚拟线类型，接口作为虚拟线的一端
	// BYPASSMIRROR: 旁路镜像类型，该模式进来的报文，只处理不转发
	IfMode string
	// 指定排序字段 (最大100字符)
	SortBy string
	// 指定排序方式（正序/倒序）(asc/desc, 默认asc)
	Order string
	// 选择字段，字段用逗号分隔 (最大1000字符)
	Select string
	// 过滤wan口
	WanEnable bool
	// 是否去除被聚合口选择的物理口
	OptionalItf bool
	// 获取子接口可用的父接口
	SubFatherItf bool
	// 否为聚合口可选择的物理口
	SelectChannel bool
	// 接口对外公用插件
	FilterInterfaces string
	// 获取该接口所属于的聚合口的配置 (接口名称格式)
	GetChannel string
	// 过滤接口veth.0
	FilterVeth0 bool
	// 获取本地可用同步/传输网口
	MkptItf bool
	// 是否为区域可选择的接口
	ZoneItf bool
	// 过滤管理口
	OobManage bool
	// 获取所有三层接口
	RouteItf bool
	// 显示流量趋势支持的接口
	Traffics bool
}

// IPAddress IPv4地址范围
type IPAddress struct {
	Start string `json:"start"` // ip范围的起始位置 (ip-address格式，必填)
	End   string `json:"end"`   // ip范围的终止位置 (ip-address格式，可选)
	Bits  uint8  `json:"bits"`  // ip掩码简写 (可选)
}

// StaticIP IPv4静态IP配置
type StaticIP struct {
	IPAddress IPAddress `json:"ipaddress"` // IPv4地址
	IsSync    bool      `json:"isSync"`    // 是否不同步到备机的选项
}

// DHCP IPv4 DHCP客户端配置
type DHCP struct {
	Gateway bool `json:"gateway"` // 是否设置dhcp gateway
	DNS     bool `json:"dns"`     // 设置dns
	Unicast bool `json:"unicast"` // 是否设置dhcp 单播模式
}

// IPv4Config IPv4配置
type IPv4Config struct {
	IPv4Mode     string    `json:"ipv4Mode"`     // IPv4地址获取类型 (STATIC/DHCP/PPPOE)
	StaticIP     []StaticIP `json:"staticIp"`    // IPv4地址列表，三层模式IPv4为静态IP时使用
	DHCP         *DHCP      `json:"dhcp"`        // dhcp4 client配置，三层模式IPv4为DHCP时使用
	PPPOEGroupName string  `json:"pppoeGroupName"` // PPPoE名称，三层模式IPv4为PPPoE时使用
}

// IPv6StaticIP IPv6静态IP配置
type IPv6StaticIP struct {
	Start string `json:"start"` // ip范围的起始位置 (ip-address格式，必填)
	End   string `json:"end"`   // ip范围的终止位置 (ip-address格式，可选)
	Bits  uint8  `json:"bits"`  // ip掩码简写 (可选)
}

// IPv6ServerIP IPv6 DHCP6服务器IP范围
type IPv6ServerIP struct {
	Start string `json:"start"` // ip范围的起始位置 (ip-address格式，必填)
	End   string `json:"end"`   // ip范围的终止位置 (ip-address格式，可选)
	Bits  uint8  `json:"bits"`  // ip掩码简写 (可选)
}

// DHCP6 IPv6 DHCP6客户端配置
type DHCP6 struct {
	ClientMode      string       `json:"clientMode"`      // 客户端模式 (ADDR)
	ServerIP        *IPv6ServerIP `json:"serverIp"`       // dhcp6客户端指定的server ip
	RapidOption     bool         `json:"rapidOption"`     // 是否开启dhcp6 rapid-commit(快速分配)选项
	InfoOnlyOption  bool         `json:"infoOnlyOption"`   // 是否开启dhcp6 info-only(只获取信息)选项
}

// NDInspection ND检查
type NDInspection struct {
	InspectionType string `json:"inspectionType"` // NDP检查模式 (DROP/FORWARD/OFF)
	Trust          bool   `json:"trust"`          // 接口可信 (默认false)
	DenyRA         bool   `json:"denyra"`         // 禁止接收RA (默认false)
	RateLimit      uint32 `json:"rate_limit"`     // NDP报文速率限制 (0-10000)
}

// DAD 重复地址检测消息配置
type DAD struct {
	Time     uint32 `json:"time"`     // 发送DAD的间隔 (1000-3600000)
	Attempts uint32 `json:"attempts"` // 尝试的次数，超过则认为DAD检测成功 (0-600)
}

// NUD 邻居不可达检测配置
type NUD struct {
	RetryBase    uint32 `json:"retry_base"`    // 失败次数超过则nd表项做状态切换 (1-3)
	Attempts     uint32 `json:"attempts"`      // 发送NUD次数 (1-10)
	Interval     uint32 `json:"interval"`      // 发送NUD间隔 (1000-3600000)
	ReachableTime uint32 `json:"reachable_time"` // 判断ipv6节点是否可达的最大时间，超过则认为不可达 (1000-3600000)
}

// DNSServer RA消息中dns服务器配置
type DNSServer struct {
	IPv6Address string `json:"ipv6Address"` // dns服务器地址 (ip6-address格式)
	Lifetime    uint32 `json:"lifetime"`    // 首选生存时间 (0-4294967295)
}

// DNSDomain RA消息中dns域名
type DNSDomain struct {
	Name     string `json:"name"`     // dns域名 (最大127字符)
	Lifetime uint32 `json:"lifetime"` // 首选生存时间 (0-4294967295)
}

// Router IPv6路由相关配置
type Router struct {
	RAIntervalOption bool       `json:"ra_interval_option"` // ra中公告间隔选项是否打开
	Preference       string     `json:"prefence"`           // 路由器的优先级 (HIGH/LOW/MEDIUM)
	RAMinInterval    uint32     `json:"ra_min_interval"`    // RA发送最小间隔，单位s (3-1800)
	RAMaxInterval    uint32     `json:"ra_max_interval"`   // RA发送最大间隔，单位s (4-1800, max必须大于min)
	RALifetime       uint32     `json:"ra_lifetime"`       // RA中路由器的生命周期 (0-9000)
	RASupress        string     `json:"ra_supress"`        // ra的抑制配置 (ALL/PART/DISABLE)
	ManageFlag       bool       `json:"manage_flag"`       // RA报文中M标记位 (默认false)
	OtherFlag        bool       `json:"other_flag"`         // RA报文中O标记位 (默认false)
	NoLinkMTU        bool       `json:"no_linkmtu"`        // 用来配置RA消息中不携带MTU选项 (默认false)
	DNSServer        *DNSServer `json:"dns_server"`        // RA消息中dns服务器配置
	DNSDomain        *DNSDomain `json:"dns_domain"`         // RA消息中dns域名
	HopLimit         uint16     `json:"hopLimit"`          // TTL (0-255)
}

// RAPrefix IPv6 RA参数
type RAPrefix struct {
	Prefix          string `json:"prefix"`          // IPV6 ND前缀信息(前缀信息或者default)
	ValidLifetime   uint32 `json:"validLifetime"`   // 有效生存时间 (0-4294967295)
	PreferredLifetime uint32 `json:"perferredLifetime"` // 首选生存时间 (0-4294967295)
	NoAutoconfig    bool   `json:"noAutoconfig"`   // IPV6 ND前缀autoconfig选项 (默认false)
	OffLink         bool   `json:"offLink"`         // 控制IPV6 ND前缀分配给本地链路开关选项 (默认false)
	NoAdvertise     bool   `json:"noAdvertise"`     // 控制IPV6 ND前缀是否包含在RA消息中开关选项 (默认false)
}

// RoutePrefix IPv6 ROUTE参数
type RoutePrefix struct {
	Prefix   string `json:"prefix"`   // IPV6 路由前缀信息 (IPv6地址格式，示例:fe80::40ca:81ff:fea9:a768/24)
	Lifetime uint32 `json:"lifetime"` // 生存时间 (0-4294967295)
	Preference string `json:"prefence"` // 路由前缀的优先级 (HIGH/LOW/MEDIUM)
}

// ND IPv6 ND协议配置
type ND struct {
	DAD        *DAD          `json:"dad"`         // 重复地址检测消息配置
	NUD        *NUD         `json:"nud"`        // 邻居不可达检测配置
	Router     *Router      `json:"router"`    // ipv6，路由相关配置
	RAPrefix   []RAPrefix   `json:"ra_prefix"`  // ipv6 RA参数
	RoutePrefix []RoutePrefix `json:"route_prefix"` // ipv6 ROUTE参数
	NSInterval uint32       `json:"ns_interval"` // NS重传间隔,单位为毫秒 (1000-4294967295)
}

// IPv6Param IPv6参数
type IPv6Param struct {
	Enable      bool          `json:"enable"`       // 是否启用ipv6 (默认false)
	MTU         uint32        `json:"mtu"`          // 最大传输单元设置 (1280-1500)
	NDLearning  bool          `json:"nd_learning"` // 是否启用nd学习
	NDInspection *NDInspection `json:"nd_inspection"` // ND检查
	ND          *ND           `json:"nd"`          // ipv6ND协议配置
}

// IPv6Config IPv6配置
type IPv6Config struct {
	IPv6Mode         string      `json:"ipv6Mode"`         // IPv6地址获取类型，路由模式有效 (STATIC/DHCP6)
	AutoconfigEnable bool        `json:"autoconfigEnable"` // AUTOCONFIG模式是否开启
	AutoconfigDefaultRoute bool  `json:"autoconfigDefaultRoute"` // default route 是否设置
	StaticIP         []IPv6StaticIP `json:"staticIp"`     // IPv6地址列表，IPv6地址为静态IP时使用
	DHCP6            *DHCP6      `json:"dhcp6"`            // dhcp6客户端配置
	IPv6Param        *IPv6Param  `json:"ipv6Param"`       // ipv6参数
}

// DefaultGateway 接口默认网关
type DefaultGateway struct {
	IPv4Gateway string `json:"ipv4Gateway"` // ipv4 gateway (IPv4地址格式，示例:192.168.1.10)
	IPv6Gateway string `json:"ipv6Gateway"` // ipv6 gateway (ip6-address格式)
}

// ReverseRoute 接口源进源出下一跳
type ReverseRoute struct {
	IPv4Nexthop string `json:"ipv4Nexthop"` // reverse route ipv4 gnexthop (IPv4地址格式，示例:192.168.1.10)
	IPv6Nexthop string `json:"ipv6Nexthop"` // reverse route ipv6 gnexthop (ip6-address格式)
}

// BandSwitch 接口接收或发送的带宽限制
type BandSwitch struct {
	IngressBandSwitch struct {
		Value uint64 `json:"value"` // 数值大小 (0-1099511627776)
	} `json:"ingressbandSwitch"` // 接口接收的带宽限制
	EgressBandSwitch struct {
		Value uint64 `json:"value"` // 数值大小 (0-1099511627776)
	} `json:"egressbandSwitch"` // 接口发送的带宽限制
}

// Manage 本地策略控制
type Manage struct {
	SSH   bool `json:"ssh"`   // 是否启用ssh (默认false)
	SNMP  bool `json:"snmp"`  // 是否启用snmp (默认false)
	HTTPS bool `json:"https"` // 是否启用https
	Ping  bool `json:"ping"`  // 是否启用ping
}

// TrunkRange Trunk VLAN范围
type TrunkRange struct {
	Start uint32 `json:"start"` // vlan范围起始值 (1-4094)
	End   uint32 `json:"end"`   // vlan范围结束值 (1-4094)
}

// TrunkConfig Trunk配置
type TrunkConfig struct {
	NativeID   int32        `json:"nativeId"`   // trunk native vlanid (1-4094, 必填)
	TrunkRange []TrunkRange `json:"trunkRange"` // trunk vlan 范围 (必填)
}

// VLANConfig VLAN配置
type VLANConfig struct {
	VLANMode   string       `json:"vlanMode"`   // vlan模式 (ACCESS/TRUNK)
	AccessID   uint32       `json:"accessId"`   // access vlan id，透明模式下选择access时使用 (1-4094)
	TrunkConfig *TrunkConfig `json:"trunkConfig"` // trunk配置，透明模式下选择trunk时使用
}

// SpeedDuplex 速率双工配置
type SpeedDuplex struct {
	Autoneg bool   `json:"autoneg"` // 接口速率工作模式自动协商，为true时speed和duplex不再生效
	Speed   uint32 `json:"speed"`   // 接口速率，autoneg为false时speed配置生效 (100/1000/10000/40000/100000)
	Duplex  string `json:"duplex"`  // 双工模式，autoneg为false时duplex配置生效 (half/full)
}

// BypassMirror 旁路镜像模式配置
type BypassMirror struct {
	StatsEnable bool     `json:"statsEnable"` // 是否启用流量统计 (必填)
	IPGroup     []string `json:"ipGroup"`     // 内网网络对象，旁路镜像模式开启流量统计时使用
}

// PhysicalIf 物理口相关配置
type PhysicalIf struct {
	SpeedDuplex  SpeedDuplex   `json:"speedDuplex"`  // 速率双工配置 (必填)
	BypassMirror *BypassMirror `json:"bypassMirror"` // 旁路镜像模式配置，物理接口旁路镜像模式时使用
}

// SubIf 子接口相关配置
type SubIf struct {
	FatherInterface string `json:"fatherInterface"` // 接口的父接口，子接口时表示父接口 (必填)
}

// Failover 故障转移
type Failover struct {
	Preempt       bool   `json:"preempt"`       // 主备模式下的抢占或非抢占
	ChannelPrimary string `json:"channelPrimary"` // 聚合口主备模式的主接口，状态字段，配置无效
}

// ChannelStatic 聚合口静态模式下的相关配置
type ChannelStatic struct {
	StaticMode string    `json:"staticMode"` // 模式选择 (FAILOVER/LOADBALANCE, 必填)
	Failover   *Failover `json:"failover"`   // 故障转移
	LoadBalance string   `json:"loadbalance"` // 负载均衡的方法，聚合口静态模式选择负载均衡时使用 (ROUNDROBIN/L2HASH/L3HASH/L4HASH/TLB)
}

// ChannelLACP 聚合口动态模式下的相关配置
type ChannelLACP struct {
	HashMode      string `json:"hashMode"`      // 哈希策略 (MAC/2TUPLE/3TUPLE, 必填)
	NegotiateMode string `json:"negotiateMode"` // 协商模式 (INITIATIVE/PASSIVE, 必填)
}

// ChannelIf 聚合口相关配置
type ChannelIf struct {
	ChannelMode   string        `json:"channelMode"`   // 汇聚口的工作模式配置 (STATIC/LACP, 必填)
	ChannelStatic *ChannelStatic `json:"channelStatic"` // 聚合口静态模式下的相关配置，聚合口工作模式为静态时使用
	ChannelLACP   *ChannelLACP  `json:"channelLacp"`   // 聚合口动态模式下的相关配置，聚合口工作模式为动态时使用
	EthSelect     []string      `json:"ethSelect"`      // 选择的物理口列表 (必填)
	BypassMirror  *BypassMirror `json:"bypassMirror"`  // 旁路镜像模式有效
}

// Keepalive Keepalive相关配置
type Keepalive struct {
	AliveEnable bool   `json:"aliveEnable"` // 是否开启keepalive保活功能 (默认false)
	Interval    uint16 `json:"interval"`    // 间隔时间 (1-32767)
	Attempt     uint16 `json:"attempt"`     // 最大发送次数 (1-255)
}

// GRETunIf GRE隧道口相关配置
type GRETunIf struct {
	Type           string     `json:"type"`           // 隧道IP地址类型 (IPV4/IPV6)
	TunnelSrc      string     `json:"tunnelSrc"`      // 隧道的源地址 (ip-address格式)
	TunnelDst      string     `json:"tunnelDst"`      // 隧道的目的地址 (ip-address格式)
	GREKey         int64      `json:"greKey"`         // gre的密钥 (-1-4294967295)
	CheckSumEnable bool       `json:"checkSumEnable"` // 是否开启报文检验和 (默认false)
	Keepalive      *Keepalive `json:"keepalive"`      // keepalive相关配置
	CreateTime     string     `json:"createTime"`     // 隧道创建时间 (格式:YYYY-MM-DD HH:MM:SS)
}

// TunnelIf 隧道口相关配置
type TunnelIf struct {
	Type        string `json:"type"`        // 隧道类型 (IPIPV6/IPV6IP/6TO4/ISATAP)
	Source      string `json:"source"`      // 隧道源信息
	Destination string `json:"destination"` // 隧道目的信息 (ip-address格式)
}

// BasicTLV 基本tlv
type BasicTLV struct {
	ManagementAddress bool `json:"managementAddress"` // 管理地址tlv
	SystemCapability  bool `json:"systemCapability"`   // 系统能力tlv
	SystemDescription bool `json:"systemDescription"` // 系统描述tlv
	SystemName        bool `json:"systemName"`         // 系统名称tlv
	PortDescription   bool `json:"portDescription"`    // 端口描述tlv
}

// Dot1TLV 802.1tlv
type Dot1TLV struct {
	PortVlanID bool `json:"portVlanId"` // 端口vlan id tlv (默认false)
}

// Dot3TLV 802.3tlv
type Dot3TLV struct {
	LinkAggregation bool `json:"linkAggregation"` // 链路聚合tlv (默认false)
	MacPhysic       bool `json:"macPhysic"`       // 物理信息tlv (默认false)
	MaximumFrameSize bool `json:"maximumFrameSize"` // 最大帧长度tlv (默认false)
}

// LLDPConfig 接口lldp参数配置信息
type LLDPConfig struct {
	State    string    `json:"state"`    // 工作模式 (DISABLE/RX/TX/TXRX)
	BasicTLV *BasicTLV `json:"basicTlv"` // 基本tlv
	Dot1TLV  *Dot1TLV  `json:"dot1Tlv"`  // 802.1tlv
	Dot3TLV  *Dot3TLV  `json:"dot3Tlv"`  // 802.3tlv
}

// RSTP RSTP接口配置信息
type RSTP struct {
	RSTPState   bool   `json:"rstpState"`   // 接口是否起禁用rstp (默认false)
	RSTPPriority uint8 `json:"rstpPriority"` // 端口优先级 (0-240)
	PortEdge     bool   `json:"portEdge"`    // 设置边缘端口, 为true时，自动管理；false时：强制指定为非边缘端口
	PortPathCost uint32 `json:"portPathCost"` // rstp端口开销 (1-200000000)
	PortP2P     string `json:"portP2P"`     // 指定端口是否是点对点链路 (FORCETRUE/FORCEFALSE/AUTO)
}

// InterfaceItem 接口项
type InterfaceItem struct {
	// 基础信息
	UUID        string   `json:"uuid"`        // uuid
	Name        string   `json:"name"`        // 接口名称 (必填，接口名称格式)
	Description string   `json:"description"` // 接口描述 (0-95字符，不能包含特殊字符)
	VSys        []string `json:"vsys"`        // 虚拟系统
	MTU         int32   `json:"mtu"`         // 最大传输单元 (68-1500)

	// 接口类型和模式
	IfType  string `json:"ifType"`  // 表示接口类型 (必填)
	// 可选值: PHYSICALIF, SUBIF, CHANNELIF, VLANIF, VPNTUN, LOOPBACK, GRETUN, SSLTUN, VSYSIF, TUNNELIF
	IfMode  string `json:"ifMode"`  // 接口的工作模式，接口类型为物理口和聚合口时使用
	// 可选值: ROUTE, SWITCH, VIRTUALLINE, BYPASSMIRROR

	// 物理口和聚合口特有字段
	MAC     string `json:"mac"`     // 接口的mac地址，接口类型为物理口和聚合口时使用
	Shutdown bool  `json:"shutdown"` // 接口的启用或禁用，接口类型为物理口和聚合口时使用

	// IPv4配置
	IPv4 *IPv4Config `json:"ipv4"` // 接口ipv4相关配置，三层模式时使用

	// IPv6配置
	IPv6 *IPv6Config `json:"ipv6"` // 接口ipv6相关配置，三层模式时使用

	// 其他配置
	WanEnable        bool          `json:"wanEnable"`        // 是否开启接口的wan模式，接口类型为物理口和聚合口时使用
	DefaultGateway   *DefaultGateway `json:"defaultGateway"` // 接口默认网关
	ReverseRoute     *ReverseRoute   `json:"reverseRoute"`    // 接口源进源出下一跳
	ReverseRouteEnable bool         `json:"reverseRouteEnable"` // 标识接口是否开启源进源出
	BandSwitch       *BandSwitch    `json:"bandSwitch"`      // 接口接收或发送的带宽限制，物理口和聚合口的路由模式时使用
	Manage           *Manage         `json:"manage"`          // 本地策略控制，接口上控制是否放行对应类型的报文，三层模式时使用
	Jumbo            bool            `json:"jumbo"`           // 巨帧模式 (默认false)
	VLAN             *VLANConfig     `json:"vlan"`           // vlan配置，物理口和聚合口透明模式时使用
	VLANID           uint32          `json:"vlanId"`         // 标识子接口和vlan口的vlanid，接口类型为物理口和聚合口时使用 (0-4094)

	// 接口类型特定配置
	PhysicalIf *PhysicalIf `json:"physicalif"` // 物理口相关配置，接口类型为物理接口时使用
	SubIf      *SubIf      `json:"subif"`      // 子接口相关配置，接口类型为子接口时使用
	ChannelIf  *ChannelIf  `json:"channelif"`   // 聚合口相关配置，接口类型为聚合接口时使用
	GRETunIf   *GRETunIf   `json:"gretunif"`    // GRE隧道口相关配置
	TunnelIf   *TunnelIf   `json:"tunnelif"`   // 隧道口相关配置

	// 其他配置
	OobManage  bool        `json:"oobManage"`  // 带外管理起禁用
	LLDPConfig *LLDPConfig `json:"lldpConfig"` // 接口lldp参数配置信息
	RSTP       *RSTP       `json:"rstp"`       // rstp接口配置信息，按条件选择
	IPMacBind  string      `json:"ipmacBind"`  // ip-mac绑定 (DISABLE/LOOSE/STRICT)
}

// GetInterfacesResponse 获取接口列表响应
type GetInterfacesResponse struct {
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
		Items         []InterfaceItem `json:"items"`         // 有效数据列表
	} `json:"data"`
}

// NewClient 创建新的接口客户端
func NewClient(host, token, sessid string, httpClient *http.Client) *Client {
	return &Client{
		host:   host,
		token:  token,
		sessid: sessid,
		client: httpClient,
	}
}

// NewClientWithNamespace 创建新的接口客户端（指定命名空间）
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

// GetInterfaces 获取接口列表
func (c *Client) GetInterfaces(req *GetInterfacesRequest) (*GetInterfacesResponse, error) {
	// 构建URL
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/interfaces", c.host, c.getNamespace())

	// 构建查询参数
	params := url.Values{}

	if req.HAItf {
		params.Add("haItf", "true")
	}
	if req.VirtualHAItf {
		params.Add("VirtualHaItf", "true")
	}
	if req.HAMonitorItf {
		params.Add("haMonitorItf", "true")
	}
	if req.Search != "" {
		params.Add("_search", req.Search)
	}
	if req.IfType != "" {
		params.Add("ifType", req.IfType)
	}
	if req.Start > 0 {
		params.Add("_start", strconv.Itoa(req.Start))
	}
	if req.Length > 0 {
		params.Add("_length", strconv.Itoa(req.Length))
	}
	if req.IfMode != "" {
		params.Add("ifMode", req.IfMode)
	}
	if req.SortBy != "" {
		params.Add("_sortby", req.SortBy)
	}
	if req.Order != "" {
		params.Add("_order", req.Order)
	}
	if req.Select != "" {
		params.Add("_select", req.Select)
	}
	if req.WanEnable {
		params.Add("wanEnable", "true")
	}
	if req.OptionalItf {
		params.Add("optionalItf", "true")
	}
	if req.SubFatherItf {
		params.Add("subFatherItf", "true")
	}
	if req.SelectChannel {
		params.Add("selectChannel", "true")
	}
	if req.FilterInterfaces != "" {
		params.Add("filterInterfaces", req.FilterInterfaces)
	}
	if req.GetChannel != "" {
		params.Add("getChannel", req.GetChannel)
	}
	if req.FilterVeth0 {
		params.Add("filterVeth0", "true")
	}
	if req.MkptItf {
		params.Add("mkptItf", "true")
	}
	if req.ZoneItf {
		params.Add("zoneItf", "true")
	}
	if req.OobManage {
		params.Add("oobManage", "true")
	}
	if req.RouteItf {
		params.Add("routeItf", "true")
	}
	if req.Traffics {
		params.Add("traffics", "true")
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
	var result GetInterfacesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// IsSuccess 检查请求是否成功
func (r *GetInterfacesResponse) IsSuccess() bool {
	return r.Code == 0
}

