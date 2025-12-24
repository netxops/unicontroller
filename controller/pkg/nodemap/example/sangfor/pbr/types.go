package pbr

// 常量定义

// Order 排序方式
const (
	OrderAsc  = "asc"  // 按升序排列
	OrderDesc = "desc" // 按降序排列
)

// LBMethod 多线路模式下，接口选择策略
const (
	LBMethodPoll              = "POLL"                // 轮询
	LBMethodBandwidth         = "BANDWIDTH"            // 带宽比例
	LBMethodWeightedMinFlow   = "WEIGHTED_MINIMUM_FLOW" // 加权最小流量
	LBMethodPriorityFrontLine = "PRIORITY_FRONT_LINE"  // 优先使用前面线路
)

// PBRType 策略路由类型
const (
	PBRTypeSrcAddress = "SRCADDRESS" // 源地址策略路由
)

