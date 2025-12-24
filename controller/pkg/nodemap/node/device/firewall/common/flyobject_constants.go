package common

// FlyObject 标准字段常量定义
// 用于统一各防火墙的 FlyConfig 配置解析

// 核心标准字段（所有防火墙通用）
const (
	// FlyObjectNetwork 网络对象（地址对象、地址组）的CLI字符串
	FlyObjectNetwork = "NETWORK"
	// FlyObjectService 服务对象（服务对象、服务组）的CLI字符串
	FlyObjectService = "SERVICE"
	// FlyObjectNat NAT规则的CLI字符串（统一字段）
	FlyObjectNat = "NAT"
	// FlyObjectPool SNAT池对象的CLI字符串
	FlyObjectPool = "POOL"
	// FlyObjectSecurityPolicy 安全策略的CLI字符串
	FlyObjectSecurityPolicy = "SECURITY_POLICY"
)

// 扩展字段（部分防火墙使用）
const (
	// FlyObjectAcl ACL规则的CLI字符串（SecPath, Common V2）
	FlyObjectAcl = "ACL"
	// FlyObjectVip VIP对象的CLI字符串（Common V2, FortiGate使用STATIC_NAT）
	FlyObjectVip = "VIP"
	// FlyObjectMip MIP对象的CLI字符串（Common V2）
	FlyObjectMip = "MIP"
	// FlyObjectStaticNat 静态NAT规则（Sangfor, FortiGate）
	FlyObjectStaticNat = "STATIC_NAT"
	// FlyObjectDynamicNat 动态NAT规则（Sangfor, FortiGate）
	FlyObjectDynamicNat = "DYNAMIC_NAT"
)

// FortiGate特定扩展字段
const (
	// FlyObjectNetworkObjectGroup 网络对象组（FortiGate）
	FlyObjectNetworkObjectGroup = "NETWORK_OBJECT_GROUP"
	// FlyObjectServiceGroup 服务对象组（FortiGate）
	FlyObjectServiceGroup = "SERVICE_GROUP"
	// FlyObjectClis CLI命令列表（FortiGate）
	FlyObjectClis = "CLIS"
)

// SecPath特定扩展字段（XML格式）
const (
	// FlyObjectNetworkIPv4Object IPv4网络对象（SecPath XML格式）
	FlyObjectNetworkIPv4Object = "NETWORK_IPv4_OBJECT"
	// FlyObjectNetworkIPv6Object IPv6网络对象（SecPath XML格式）
	FlyObjectNetworkIPv6Object = "NETWORK_IPv6_OBJECT"
	// FlyObjectNetworkIPv4Group IPv4网络组（SecPath XML格式）
	FlyObjectNetworkIPv4Group = "NETWORK_IPv4_GROUP"
	// FlyObjectNetworkIPv6Group IPv6网络组（SecPath XML格式）
	FlyObjectNetworkIPv6Group = "NETWORK_IPv6_GROUP"
	// FlyObjectServerOnInterface 接口上的服务器（SecPath XML格式）
	FlyObjectServerOnInterface = "SERVER_ON_INTERFACE"
	// FlyObjectNatPolicy NAT策略（SecPath XML格式）
	FlyObjectNatPolicy = "NAT_POLICY"
)


