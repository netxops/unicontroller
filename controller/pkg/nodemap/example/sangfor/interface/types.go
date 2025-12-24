package interface_

// 常量定义

// Order 排序方式
const (
	OrderAsc  = "asc"  // 按升序排列
	OrderDesc = "desc" // 按降序排列
)

// InterfaceType 接口类型
const (
	InterfaceTypePhysicalIf = "PHYSICALIF" // 物理口
	InterfaceTypeSubIf      = "SUBIF"      // 子接口
	InterfaceTypeChannelIf  = "CHANNELIF"  // 聚合口
	InterfaceTypeVlanIf     = "VLANIF"     // vlan对应的3层接口
	InterfaceTypeVpnTun     = "VPNTUN"     // vpn隧道口
	InterfaceTypeLoopback   = "LOOPBACK"   // 回环口
	InterfaceTypeGreTun     = "GRETUN"     // GRE隧道口
	InterfaceTypeSslTun     = "SSLTUN"     // SSL隧道口
	InterfaceTypeVsysIf     = "VSYSIF"     // 虚拟系统的虚拟接口
	InterfaceTypeTunnelIf   = "TUNNELIF"   // 隧道口
)

// InterfaceMode 接口工作模式
const (
	InterfaceModeRoute        = "ROUTE"        // 路由类型，接口作为3层接口
	InterfaceModeSwitch       = "SWITCH"       // 交换类型，接口作为2层接口
	InterfaceModeVirtualLine  = "VIRTUALLINE"  // 虚拟线类型，接口作为虚拟线的一端
	InterfaceModeBypassMirror = "BYPASSMIRROR" // 旁路镜像类型，该模式进来的报文，只处理不转发
)

// IPv4Mode IPv4地址获取类型
const (
	IPv4ModeStatic = "STATIC" // 静态配置
	IPv4ModeDHCP   = "DHCP"   // dhcp方式获取
	IPv4ModePPPOE  = "PPPOE"  // pppoe方式获取
)

// IPv6Mode IPv6地址获取类型
const (
	IPv6ModeStatic = "STATIC" // static IP
	IPv6ModeDHCP6  = "DHCP6"  // dhcp6
)

// DHCP6ClientMode DHCP6客户端模式
const (
	DHCP6ClientModeAddr = "ADDR" // dhcp6 client addr模式
)

// NDInspectionType NDP检查模式
const (
	NDInspectionTypeDrop    = "DROP"    // 丢包
	NDInspectionTypeForward = "FORWARD" // 转发
	NDInspectionTypeOff     = "OFF"     // 关闭
)

// RouterPreference 路由器优先级
const (
	RouterPreferenceHigh   = "HIGH"   // 高优先级
	RouterPreferenceLow    = "LOW"    // 低优先级
	RouterPreferenceMedium = "MEDIUM" // 中优先级
)

// RASupress RA的抑制配置
const (
	RASupressAll     = "ALL"     // 周期性发送RA
	RASupressPart    = "PART"    // 不主动发送RA，收到RS会回应
	RASupressDisable = "DISABLE" // 不主动发送，也不应答
)

// VLANMode VLAN模式
const (
	VLANModeAccess = "ACCESS" // access模式
	VLANModeTrunk  = "TRUNK"  // trunk模式
)

// ChannelMode 汇聚口的工作模式配置
const (
	ChannelModeStatic = "STATIC" // 静态
	ChannelModeLACP   = "LACP"   // 动态
)

// StaticMode 模式选择
const (
	StaticModeFailover    = "FAILOVER"    // 故障转移
	StaticModeLoadBalance = "LOADBALANCE" // 负载均衡
)

// LoadBalance 负载均衡的方法
const (
	LoadBalanceRoundRobin = "ROUNDROBIN" // 平衡轮询策略
	LoadBalanceL2Hash     = "L2HASH"     // hash负载分担平衡策略
	LoadBalanceL3Hash     = "L3HASH"     // hash负载分担平衡策略
	LoadBalanceL4Hash     = "L4HASH"     // hash负载分担平衡策略
	LoadBalanceTLB        = "TLB"        // tlb策略
)

// HashMode 哈希策略
const (
	HashModeMAC    = "MAC"    // 源与目的mac
	HashMode2Tuple = "2TUPLE" // 源与目的IP、mac
	HashMode3Tuple = "3TUPLE" // 源与目的IP、mac、port
)

// NegotiateMode 协商模式
const (
	NegotiateModeInitiative = "INITIATIVE" // 源与目的IP
	NegotiateModePassive    = "PASSIVE"    // 源与目的IP、mac
)

// GRETunnelType 隧道IP地址类型
const (
	GRETunnelTypeIPv4 = "IPV4" // IPV4 隧道封装
	GRETunnelTypeIPv6 = "IPV6" // IPV6 隧道封装
)

// TunnelIfType 隧道类型
const (
	TunnelIfTypeIPIPv6 = "IPIPV6" // IPv4 over IPv6隧道
	TunnelIfTypeIPv6IP = "IPV6IP" // IPv6 over IPv4隧道
	TunnelIfType6To4   = "6TO4"   // 6to4自动隧道
	TunnelIfTypeISATAP = "ISATAP" // ISATAP自动隧道
)

// LLDPState LLDP工作模式
const (
	LLDPStateDisable = "DISABLE" // 既不能接收LLDP报文，也不能发送LLDP报文
	LLDPStateRX      = "RX"      // 只能接收LLDP报文
	LLDPStateTX      = "TX"      // 只能发送LLDP报文
	LLDPStateTXRX    = "TXRX"    // 既能接收LLDP报文，也能发送LLDP报文
)

// PortP2P 指定端口是否是点对点链路
const (
	PortP2PForceTrue  = "FORCETRUE"  // 强制指定为点对点链路
	PortP2PForceFalse = "FORCEFALSE" // 强制指定为非点对点链路
	PortP2PAuto       = "AUTO"       // 系统自动检测是否为点对点链路
)

// IPMacBind IP-MAC绑定
const (
	IPMacBindDisable = "DISABLE" // 禁用
	IPMacBindLoose   = "LOOSE"   // 宽松模式
	IPMacBindStrict  = "STRICT"  // 严格模式
)

// Speed 接口速率
const (
	Speed100Mbps    = 100    // 选择100Mbps
	Speed1000Mbps   = 1000   // 选择1000Mbps
	Speed10000Mbps  = 10000  // 选择10000Mbps
	Speed40000Mbps  = 40000  // 选择40000Mbps
	Speed100000Mbps = 100000 // 选择100000Mbps
)

// Duplex 双工模式
const (
	DuplexHalf = "half" // 半双工模式
	DuplexFull = "full" // 全双工模式
)
