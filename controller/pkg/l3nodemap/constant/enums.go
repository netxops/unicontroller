package constant

// L3_GLOBAL_OPRT_KEY 用于对L3的策略执行操作，分布式全局锁，redis
const L3_GLOBAL_EXPIRE_TIME_MINUTES = "10m"

// DEFAULT_VRF 默认的VRF常量值 =======================
const DEFAULT_VRF string = "default"

// ConnectType 连接方式 =======================
type ConnectType string

const (
	SSH     ConnectType = "SSH"
	RESTFUL ConnectType = "RESTFUL"
	TELNET  ConnectType = "TELNET"
)

// DeviceCategory 设备功能分类 =======================
type DeviceCategory string

const (
	SERVER   DeviceCategory = "SERVER"
	FIREWALL DeviceCategory = "FIREWALL"
	ROUTER   DeviceCategory = "ROUTER"
	LB       DeviceCategory = "LB"
)

func ContainsDeviceCategory(dc DeviceCategory) bool {
	switch dc {
	case SERVER, FIREWALL, LB, ROUTER:
		return true
	default:
		return false
	}
}

// SpecificCategory 设备具体类别 =======================
type SpecificCategory string

const (
	ASA SpecificCategory = "ASA"
	F5  SpecificCategory = "F5"
	SRX SpecificCategory = "SRX"
	ACI SpecificCategory = "ACI"
)

func ContainsSpecificCategory(sc SpecificCategory) bool {
	switch sc {
	case ASA, F5, SRX, ACI:
		return true
	default:
		return false
	}
}

func FindDeviceCategoryBySpecificCategory(sc string) DeviceCategory {
	switch sc {
	case string(ASA), string(SRX), string(ACI):
		return FIREWALL
	case string(F5):
		return LB
	default:
		return ""
	}
}
