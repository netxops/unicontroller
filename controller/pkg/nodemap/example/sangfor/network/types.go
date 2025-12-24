package network

// 常量定义

// ExcludeAll 是否过滤名字为全部的IP组
const (
	ExcludeAllTrue  = "TRUE"  // 过滤名字为全部的IP组
	ExcludeAllFalse = "FALSE" // 不过滤名字为全部的IP组
)

// HasSensitiveData 是否过滤敏感数据业务
const (
	HasSensitiveDataTrue  = "TRUE"  // 过滤敏感数据业务
	HasSensitiveDataFalse = "FALSE" // 过滤非敏感数据业务
	HasSensitiveDataAll   = "ALL"   // 不过滤敏感数据业务
)

// AddressType IP协议版本
const (
	AddressTypeIPv4 = "IPV4" // ip协议版本为ipv4
	AddressTypeIPv6 = "IPV6" // ip协议版本为ipv6
	AddressTypeAll  = "ALL"  // 不过滤ip协议版本
)

// HasRef 是否过滤被引用的网络对象
const (
	HasRefTrue  = "TRUE"  // 过滤被引用的网络对象
	HasRefFalse = "FALSE" // 过滤没有被引用的网络对象
)

// Important 重要级别
const (
	ImportantCommon = "COMMON" // 重要级别为普通
	ImportantCore   = "CORE"   // 重要级别为核心
	ImportantAll    = "ALL"    // 不过滤重要级别
)

// Order 排序方式
const (
	OrderAsc  = "asc"  // 按升序排列
	OrderDesc = "desc" // 按降序排列
)

// BusinessType 业务类型
const (
	BusinessTypeAddrGroup        = "ADDRGROUP"        // 业务类型为地址组
	BusinessTypeIP               = "IP"               // 业务类型是IP地址
	BusinessTypeUser             = "USER"             // 业务类型是用户地址
	BusinessTypeBusiness         = "BUSINESS"         // 业务类型是业务地址
	BusinessTypeDomains          = "DOMAINS"          // 业务类型是域名网络对象
	BusinessTypeOtherThanDomains = "OTHERTHANDOMAINS" // 业务类型不是域名网络对象
	BusinessTypeAll              = "ALL"              // 不过滤业务类型
)

// NetObjBusinessType 网络对象组类型（响应中的businessType）
const (
	NetObjBusinessTypeIP        = "IP"        // ip组类型
	NetObjBusinessTypeBusiness  = "BUSINESS"  // 业务组类型
	NetObjBusinessTypeUser      = "USER"      // 用户组类型
	NetObjBusinessTypeAddrGroup = "ADDRGROUP" // 地址组类型
	NetObjBusinessTypeDomains   = "DOMAINS"   // 域名类型
)

// NetObjAddressType 地址类型（响应中的addressType）
const (
	NetObjAddressTypeIPv4 = "IPV4" // IPv4类型
	NetObjAddressTypeIPv6 = "IPV6" // IPv6类型
)

// NetObjImportant 重要级别（响应中的important）
const (
	NetObjImportantCommon = "COMMON" // 普通用户或普通业务
	NetObjImportantCore   = "CORE"   // 核心用户或核心业务
)

// DomainsDetectMode 域名对象探测模式
const (
	DomainsDetectModeActive  = "ACTIVE"  // 主动探测
	DomainsDetectModePassive = "PASSIVE" // 被动学习
)

// DataStatus 敏感数据识别方式
const (
	DataStatusAuto     = "AUTO"      // 系统自动识别
	DataStatusExist    = "EXIST"     // 存在
	DataStatusNotExist = "NOT-EXIST" // 不存在
)
