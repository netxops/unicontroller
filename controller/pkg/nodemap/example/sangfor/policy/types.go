package policy

// 常量定义

// PolicyType 安全防护策略类型
const (
	PolicyTypeServer        = "SERVER"         // 业务防护策略
	PolicyTypeInternetAccess = "INTERNET_ACCESS" // 用户防护策略
)

// SrcAddrType 源地址类型
const (
	SrcAddrTypeNetObject = "NETOBJECT" // 网络对象
	SrcAddrTypeUsers     = "USERS"     // 用户/组
)

// Strategy 业务访问场景
const (
	StrategyNotViaSNATCDN = "NOT_VIA_SNAT_CDN" // 访问未经过源地址转换或CDN
	StrategyViaSNATCDN    = "VIA_SNAT_CDN"     // 访问经过源地址转换或CDN
)

// Action 动作
const (
	ActionAllow = "ALLOW" // 允许
	ActionDeny  = "DENY"  // 拒绝
)

// BlockType 联动封锁类型
const (
	BlockTypeHighThreats = "HIGH_THREATS" // 高危行为联动封锁
	BlockTypeAnyThreat   = "ANY_THREAT"   // 任意攻击行为联动封锁
)

// HighlightPosition 模糊搜索高亮位置
const (
	HighlightPositionMatchName              = "MATCH_NAME"                // SECURITY_SEARCH_NAME
	HighlightPositionMatchSrcZone           = "MATCH_SRC_ZONE"            // 模糊搜索到源区域名称
	HighlightPositionMatchSrcUsers          = "MATCH_SRC_USERS"           // 模糊搜索到源用户名称
	HighlightPositionMatchSrcUserGroups     = "MATCH_SRC_USERGROUPS"      // 模糊搜索到源用户组名称
	HighlightPositionMatchSrcIPGroup        = "MATCH_SRC_IPGROUP"        // 模糊搜索到源网络对象名称
	HighlightPositionMatchSrcIPGroupByIP    = "MATCH_SRC_IPGROUP_BYIP"   // 精确搜索到源网络对象中IP区间
	HighlightPositionMatchDstZone          = "MATCH_DST_ZONE"            // 模糊搜索到目的区域名称
	HighlightPositionMatchDstIPGroup        = "MATCH_DST_IPGROUP"         // 模糊搜索到目的网络对象名称
	HighlightPositionMatchDstIPGroupByIP    = "MATCH_DST_IPGROUP_BYIP"   // 精确搜索到目的网络对象中IP区间
)

