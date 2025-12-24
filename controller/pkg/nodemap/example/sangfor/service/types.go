package service

// 常量定义

// ServType 服务类型
const (
	ServTypePredefServ = "PREDEF_SERV" // 预定义服务
	ServTypeUsrdefServ = "USRDEF_SERV" // 自定义服务
	ServTypeServ       = "SERV"        // 服务
	ServTypeServGrp    = "SERV_GRP"    // 服务组
)

// Order 排序方式
const (
	OrderAsc  = "asc"  // 按升序排列
	OrderDesc = "desc" // 按降序排列
)

// QueryListModule 请求服务列表的模块名
const (
	QueryListModuleObjWAF = "OBJ_WAF" // 对象-WEB应用防护
)

