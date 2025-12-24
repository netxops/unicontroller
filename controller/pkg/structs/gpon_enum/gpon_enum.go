package gpon_enum

const NoInformation = "-"

// 定义枚举类型
type DownCause int

const (
	OntDeleted DownCause = iota // 0
	LinkedDown                  // 1
	Losi
	Lofi
	Sfi
	Loai
	Loami
	Disablefail
	Deactivated
	Reset
	Reregister
	Popupfail
	Authfail
	Powerdown
	Reserved
	Loki
	RingDeactivated            DownCause = 18
	TurnOffOptic               DownCause = 30
	CmdReboot                  DownCause = 31
	OntResetkeyReboot          DownCause = 32
	OntSoftwareReset           DownCause = 33
	BroadcastAttackDeactivated DownCause = 34
	OperatorCheckFail          DownCause = 35
	OntOltIncompatible         DownCause = 36
	RogueOntselfDetected       DownCause = 37
	AutoIsolateReset           DownCause = 38
	AutoIsolateDeact           DownCause = 39
	OntNotInWhiteList          DownCause = 40
	Noerror                    DownCause = 255
)

// 根据数字返回相应的解释
func GetDownCause(code DownCause) string {
	switch code {
	case OntDeleted:
		return "已删除" // The cause of ONT's down is that the ont is deleted
	case LinkedDown: // 1
		return "连接丢失" // "The cause of ONT's down is that the ont is disconnected
	case Losi:
		return "ONUi信号或突发丢失" // The cause of ONT's down is LOSi(Loss of signal for ONUi) or LOBi (Loss of burst for ONUi)
	case Lofi:
		return "OLT无法从ONT接收到预期的光帧" // The cause of ONT's down is that the ont is lofi(OLT can not receive expected optical frame from ONT)
	case Sfi:
		return "ONUi信号失败" // The cause of ONT's down is that the ont is sfi(Signal fail of ONUi)
	case Loai:
		return "与ONUi的确认丢失" // The cause of ONT's down is that the ont is loai(Loss of acknowledge with ONUi)
	case Loami:
		return "ONUi的PLOAM丢失" // The cause of ONT's down is that the ont is loami(Loss of PLOAM for ONUi)
	case Disablefail:
		return "激活失败" // The cause of ONT's down is that the ont fails to be deactivated
	case Deactivated:
		return "停用" // The cause of ONT's down is that the ont is deactivated
	case Reset:
		return "复位" // The cause of ONT's down is that the ont is reseted
	case Reregister:
		return "重新注册" // The cause of ONT's down is that the ont is registered again
	case Popupfail:
		return "Popup测试失败" // The cause of ONT's down is that the ont popup test fails
	case Authfail:
		return "认证失败" // The cause of ONT's down is that the ont authentication fails
	case Powerdown:
		return "关闭电源" // The cause of ONT's down is that the ont is powered off
	case Reserved:
		return "保留" // Reserved
	case Loki:
		return "与ONUi的键同步丢失" // The cause of ONT's down is that the ont is loki(Loss of key synch with ONUi)
	case RingDeactivated:
		return "由于环路停用" // The cause of ONT's down is that the ont is deactivated due to the ring
	case TurnOffOptic:
		return "光模块关闭" // The cause of ONT's down is that the ont optical module is shut down
	case CmdReboot:
		return "命令行重启" // The cause of ONT's down is that the ont is reset by ont command
	case OntResetkeyReboot:
		return "设备按钮复位" // The cause of ONT's down is that the ont is reset by ont reset button
	case OntSoftwareReset:
		return "软件复位" // The cause of ONT's down is that the ont is reset by ont software
	case BroadcastAttackDeactivated:
		return "广播攻击导致停用" // The cause of ONT's down is that the ont is deactivated due to broadcast attack
	case OperatorCheckFail:
		return "校验失败" // The cause of ONT's down is that operator check fail
	case OntOltIncompatible:
		return "ONT与OLT不兼容" // The cause of ONT's down is that the ont is incompatible with the OLT
	case RogueOntselfDetected:
		return "非法ONT导致停用" // The cause of ONT's down is that the rogue ont detected by itself
	case AutoIsolateReset:
		return "自动隔离复位" // The cause of ONT's down is that the ont resets to prevent rogue ont attacks
	case AutoIsolateDeact:
		return "自动隔离导致停用" // The cause of ONT's down is that the ont is deactivated to prevent rogue ont attacks
	case OntNotInWhiteList:
		return "不在白名单中" // The cause of ONT's down is that the ont is not in the white list
	case Noerror:
		return "无错误" // The cause of ONT's down is that the ont is noerror
	default:
		return NoInformation
	}
}

type ActiveStatus int

const (
	ActiveStatusActivate ActiveStatus = iota + 1 // 0
	ActiveStatusDeactivate
	ActiveStatusInvalid ActiveStatus = -1
)

func GetActiveStatus(code ActiveStatus) string {
	switch code {
	case ActiveStatusActivate:
		return "激活"
	case ActiveStatusDeactivate:
		return "未激活"
	case ActiveStatusInvalid:
		return NoInformation
	default:
		return NoInformation
	}
}

type ConfigStatus int

const (
	ConfigStatusInitialization ConfigStatus = iota + 1 // 0
	ConfigStatusNormal
	ConfigStatusFailed
	ConfigStatusNoresume
	ConfigStatusConfig
	ConfigStatusInvalid ConfigStatus = -1
)

// 配置恢复过程
func GetConfigStatus(code ConfigStatus) string {
	switch code {
	case ConfigStatusInitialization:
		return "初始化"
	case ConfigStatusNormal:
		return "正常"
	case ConfigStatusFailed:
		return "失败"
	case ConfigStatusNoresume:
		return "未恢复" // Indicates that the ONT configuration resume status is not resumed
	case ConfigStatusConfig:
		return "配置中" // Indicates that the ONT configuration resume status is configuration
	case ConfigStatusInvalid:
		return NoInformation
	default:
		return NoInformation
	}
}

type BatteryStatus int

const (
	BatteryStatusNotSupport BatteryStatus = iota // 0
	BatteryStatusCharge
	BatteryStatusDischarge
	BatteryStatusHolding
	BatteryStatusSupportButInvalid
	BatteryStatusUnknownStatus BatteryStatus = -1
)

func GetBatteryStatus(code BatteryStatus) string {
	switch code {
	case BatteryStatusNotSupport:
		return "不支持"
	case BatteryStatusCharge:
		return "充电"
	case BatteryStatusDischarge:
		return "放电"
	case BatteryStatusHolding:
		return "保持"
	case BatteryStatusSupportButInvalid:
		return "不可充电"
	case BatteryStatusUnknownStatus:
		return NoInformation
	default:
		return NoInformation
	}
}

type MatchStatus int

const (
	MatchStatusInitialization MatchStatus = iota + 1 // 0
	MatchStatusMatch
	MatchStatusMismatch
	MatchStatusInvalid MatchStatus = -1
)

func GetMatchStatus(code MatchStatus) string {
	switch code {
	case MatchStatusInitialization:
		return "初始化"
	case MatchStatusMatch:
		return "匹配"
	case MatchStatusMismatch:
		return "不匹配"
	case MatchStatusInvalid:
		return NoInformation
	default:
		return NoInformation
	}
}

type ManagementMode int

const (
	ManagementModeOmci ManagementMode = iota + 1 // 0
	ManagementModeSnmp
	ManagementModeExtendFrame
	ManagementModeInvalid ManagementMode = -1
)

func GetManagementModeStatus(code ManagementMode) string {
	switch code {
	case ManagementModeOmci:
		return "OMCI"
	case ManagementModeSnmp:
		return "SNMP"
	case ManagementModeExtendFrame:
		return "ExtendFrame"
	case ManagementModeInvalid:
		return NoInformation
	default:
		return NoInformation
	}
}
