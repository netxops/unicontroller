package enum

type SupportMetric string

const (
	Snmp          SupportMetric = "snmp"
	Ping          SupportMetric = "ping"
	SnmpInterface SupportMetric = "snmp_interface"
	Tail          SupportMetric = "tail"
)

type DataKey string

const (
	DeviceForSnmp    DataKey = "DeviceForSnmp"
	DeviceForTail    DataKey = "DeviceForTail"
	IpAddrForPing    DataKey = "IpAddrForPing"
	InterfaceForSnmp DataKey = "InterfaceForSnmp"
	DeviceForAgent   DataKey = "DeviceForAgent"
)
