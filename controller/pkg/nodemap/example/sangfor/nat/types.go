package nat

// 常量定义

// TransType 转换类型（请求参数）
const (
	TransTypeSNAT = "SNAT" // 转换类型为snat
	TransTypeDNAT = "DNAT" // 转换类型为dnat
	TransTypeBNAT = "BNAT" // 转换类型为bnat
)

// NATType NAT类型（响应中的natType）
const (
	NATTypeSNAT = "SNAT" // 转换类型为源地址转换
	NATTypeDNAT = "DNAT" // 转换类型为目的地址转换
	NATTypeBNAT = "BNAT" // 转换类型为双向地址转换
)

// DstNetobjType 目的网络对象类型（SNAT使用）
const (
	DstNetobjTypeZone      = "ZONE"      // 区域
	DstNetobjTypeInterface = "INTERFACE" // 接口
)

// DstIPobjType 目的IP对象类型（DNAT/BNAT使用）
const (
	DstIPobjTypeIPGroup = "IPGROUP" // IP组
	DstIPobjTypeIP     = "IP"      // 指定的IP列表
)

// TransferType 转换类型（SNAT源转换）
const (
	TransferTypeOutifIP  = "OUTIF_IP"  // 出接口ip
	TransferTypeIPRange  = "IP_RANGE"  // ip范围
	TransferTypeIP       = "IP"        // 单个IP
	TransferTypeIPGroup  = "IPGROUP"   // ip组
	TransferTypeNoTrans  = "NO_TRANS"  // 不转换
)

// DNATTransferType DNAT转换类型
const (
	DNATTransferTypeIPRange  = "IP_RANGE"  // ip范围
	DNATTransferTypeIP       = "IP"        // 单个IP
	DNATTransferTypeIPPrefix = "IP_PREFIX" // 转换前缀
	DNATTransferTypeIPGroup  = "IPGROUP"   // ip组
	DNATTransferTypeNoTrans  = "NO_TRANS"  // 不转换
	DNATTransferTypeSLBPool  = "SLB_POOL"  // slb地址池转换
)

// Sticky 转换模式开关
const (
	StickyOff    = "OFF"    // 关闭sticky功能
	StickyStrict = "STRICT" // 开启sticky功能严格模式
	StickyLoose  = "LOOSE"  // 开启sticky功能宽松模式
)

// TranferMode 转换模式
const (
	TranferModeStatic  = "STATIC"  // 静态转换
	TranferModeDynamic = "DYNAMIC" // 动态转换
)

// PortMode 端口分配类型
const (
	PortModeRandom     = "RANDOM"      // 自由分配
	PortModeStaticBlock = "STATIC_BLOCK" // 静态端口段
)

