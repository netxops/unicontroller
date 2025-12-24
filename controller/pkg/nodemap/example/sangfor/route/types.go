package route

// 常量定义

// RouteType 路由类型
const (
	RouteTypeAll     = "ALL_ROUTE"     // 所有路由
	RouteTypeStatic  = "STATIC_ROUTE"  // 静态路由
	RouteTypeDirect  = "DIRECT_ROUTE"  // 直接路由
	RouteTypeOSPF    = "OSPF_ROUTE"    // OSPF 路由
	RouteTypeOSPFv3  = "OSPFV3_ROUTE"  // OSPFv3 路由
	RouteTypeRIP     = "RIP_ROUTE"     // RIP 路由
	RouteTypeRIPNG   = "RIPNG_ROUTE"   // RIPNG 路由
	RouteTypeVPN     = "VPN_ROUTE"     // VPN 路由
	RouteTypeSSLVPN  = "SSL_VPN_ROUTE" // SSL_VPN 路由
	RouteTypeBGP     = "BGP_ROUTE"     // BGP 路由
)

// RouteStatus 路由表项状态
const (
	RouteStatusValid   = "VALID"   // 有效
	RouteStatusInvalid = "INVALID" // 无效
)

// TableID 路由表ID
const (
	TableIDManagement = 250 // 管理网络路由表
	TableIDBusiness  = 251 // 业务网络路由表
)

