package l2struct

type IfTableKey = string

const (
	IfTableName = IfTableKey("name")
)

type MetaKey = string

const (
	MetaRestfullPort   = MetaKey("restfull_port")
	MetaNetconfPort    = MetaKey("netconf_port")
	MetaTelnetPort     = MetaKey("telnet_port")
	MetaSShPort        = MetaKey("ssh_port")
	MetaIpmiPort       = MetaKey("ipmi_port")
	MetaRedfishPort    = MetaKey("redfish_port")
	MetaEnable         = MetaKey("enable")
	MetaEnableSSh      = MetaKey("enable_ssh")
	MetaEnableTelnet   = MetaKey("enable_telnet")
	MetaEnableNetconf  = MetaKey("enable_netconf")
	MetaEnableRestfull = MetaKey("enable_restfull")
	MetaEnableIpmi     = MetaKey("enable_ipmi")
	MetaEnableSnmp     = MetaKey("enable_snmp")
	MetaEnableRedfish  = MetaKey("enable_redfish")
	MetaVersion        = MetaKey("version")
	MetaRedfishVersion = MetaKey("redfish_version")
	MetaPatchVersion   = MetaKey("patch_version")
)

type LLdpKey = string

const (
	LLdpOutgoing      = LLdpKey("outgoing")
	LLdpPeerInterface = LLdpKey("peer_interface")
	LLdpName          = LLdpKey("name")
	LLdpIp            = LLdpKey("ip")
)

type CdpKey = string

const (
	CdpOutgoing = CdpKey("outgoing")
)

type PortChannelKey = string

const (
	PortChannelName      = PortChannelKey("portchannel")
	PortChannelInterface = PortChannelKey("interface")
)

type PortInfoKey = string

const (
	PortInfoInterface = PortInfoKey("interface")
	PortInfoState     = PortInfoKey("state")
	PortInfoDeviceIp  = PortInfoKey("device_ip")
)

type ArpTableKey = string

const (
	ArpTableIp      = ArpTableKey("ip")
	ArpTableMac     = ArpTableKey("mac")
	ArpTableIfindex = ArpTableKey("ifindex")
	ArpTableIpMac   = ArpTableKey("ip_mac")
	ArpInterface    = ArpTableKey("interface")
)

type MacTableKey = string

const (
	MacTableMac  = MacTableKey("mac")
	MacTableVlan = MacTableKey("vlan")
	MacTableName = MacTableKey("name")
	MacTableType = MacTableKey("type")
)

type Dot1dPortKey = string

const (
	Dot1dPortName = Dot1dPortKey("name")
)

type StpKey = string

const (
	StpPort    = StpKey("port")
	StpSend    = StpKey("send")
	StpReceive = StpKey("receive")
	StpVlan    = StpKey("vlan")
)

type Ipv6NeighborKey = string

const (
	Ipv6NeighborIpv6      = Ipv6NeighborKey("ipv6")
	Ipv6NeighborInterface = Ipv6NeighborKey("interface")
	Ipv6NeighborLink      = Ipv6NeighborKey("link")
	Ipv6NeighborVlan      = Ipv6NeighborKey("vlan")
	Ipv6NeighborVpn       = Ipv6NeighborKey("vpn")
)

type CommKey = string

const (
	CommonKeyBefore = CommKey("before")
	CommonKeyAfter  = CommKey("after")
	CommonCommand   = CommKey("command")
	CommonKey       = CommKey("key")
	CommonOutput    = CommKey("output")
	CommonStatus    = CommKey("status")
)

type VersionKey = string

const (
	VersionNum    = VersionKey("version")
	SubVersionNum = VersionKey("version_child")
	ImageName     = VersionKey("image")
)

type CheckKey = string

const (
	LineCheck = CheckKey("check")
	LineMsg   = CheckKey("msg")
)

type DirKey = string

const (
	DirFree  = DirKey("free")
	DirTotal = DirKey("total")
)

type CheckLineKey = string

const (
	CheckOneLine = CheckLineKey("checkline")
	CheckOneMsg  = CheckLineKey("msg")
)

type HotFixInstallKey = string

const (
	HotFixInstallStatus  = HotFixInstallKey("status")
	HotFixInstallCommand = HotFixInstallKey("command")
)

type InstallImpactKey = string

const (
	InstallImpactCheckLine    = InstallImpactKey("checkline")
	InstallImpactBootable     = InstallImpactKey("bootable")
	InstallImpactNxos         = InstallImpactKey("nxos")
	InstallImpactBios         = InstallImpactKey("bios")
	InstallImpactYesCheckline = InstallImpactKey("yescheckline")
)

type NetworkDeviceVersionKey = string

const (
	NetworkDeviceVersion = NetworkDeviceVersionKey("version")
	NetworkDeviceType    = NetworkDeviceVersionKey("device_type")
)

type OnuCollectKey = string

const (
	OnuName            = OnuCollectKey("name")
	OnuSoftwareVersion = OnuCollectKey("software_version")
	OnuEquipmentID     = OnuCollectKey("equipment_id")
	OnuSn              = OnuCollectKey("sn")
	OnuMac             = OnuCollectKey("mac")
	OnuIp              = OnuCollectKey("ip")
	OnuManagementMode  = OnuCollectKey("management_mode")
	OnuLineProfName    = OnuCollectKey("line_prof_name")
	OnuSrvProfName     = OnuCollectKey("srv_prof_name")
	OnuDesc            = OnuCollectKey("desc")
	OnuUpTime          = OnuCollectKey("up_time")
	OnuDownTime        = OnuCollectKey("down_time")
	OnuDownCause       = OnuCollectKey("down_cause")
	OnuActiveStatus    = OnuCollectKey("active_status")
	OnuConfigStatus    = OnuCollectKey("config_status")
	OnuBatteryStatus   = OnuCollectKey("battery_status")
	OnuMatchStatus     = OnuCollectKey("match_status")
	OnuRunStatus       = OnuCollectKey("run_status")
	OnuDyingGaspTime   = OnuCollectKey("dying_gasp_time")
)

type IbnetDiscoverKey = string

const (
	IBNetDiscover = IbnetDiscoverKey("ibnetdiscover")
)

type IpmiLogKey = string

const (
	IpmiLogID          = IpmiLogKey("id")
	IpmiLogDate        = IpmiLogKey("data")
	IpmiLogTime        = IpmiLogKey("tm")
	IpmiLogSensorName  = IpmiLogKey("sensor_name")
	IpmiLogDescription = IpmiLogKey("description")
	IpmiLogStatus      = IpmiLogKey("status")
)

type GPUKey = string

const (
	GPUName            = GPUKey("name")
	GPUSerialNumber    = GPUKey("serial_number")
	GPUManufacture     = GPUKey("manufacture")
	GPUMemoryTotal     = GPUKey("memory_total")
	GPUFirmwareVersion = GPUKey("vbios_version")
	GPUDriverVersion   = GPUKey("driver_version")
	GPUBusID           = GPUKey("bus_id")
	GPUUuID            = GPUKey("uuid")
)
