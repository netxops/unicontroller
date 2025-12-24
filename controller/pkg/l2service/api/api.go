package api

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"

	clitask "github.com/netxops/utils/task"
)

// type MetaReply struct {
// Meta model.L2DeviceMeta
// Metrics
// }
//
// type Reply struct {
// Table       *clitask.Table
// Result      []map[string]string
// FileData    map[string][][]string
// FileNameMap map[string][]string
// Uuid        string
// MasterKey   string
// Metrics
// }
//
// type TopoServerType int
//
// func (t TopoServerType) String() string {
// return []string{"SYSTEM_NAME", "IFTABLE", "Dot1dPorts", "PORTIP", "VLAN", "Stp",
// "MacTable", "Arps", "NeighborCdp", "Neighbor", "NeighborLldp", "Other", "YAML_ARP",
// "Port_Statistics", "Port_Channel", "Ipv6_Neighbor", "REDFISH_CPU", "REDFISH_MEM", "REDFISH_DISK",
// "REDFISH_VERSION", "REDFISH_NETWORKINTERFACE", "REDFISH_BMC", "REDFISH_BASEINFO", "REDFISH_NETWORK", "VMWARE_RESOURCES", "REDFISH_POWER",
// "VMWARE_VM", "VMWARE_TEMPLATE", "VMWARE_DATASTORE", "VMWARE_INFO", "VMWARE_INTERFACES",
// "SDN_FABRIC", "SDN_VPC", "SDN_LOGICPORT", "LINUX_IFCONFIG_INTERFACES", "LINUX_BATCH_CMD", "LINUX_STEP_CMD", "META", "DEVICEMETA", "VZENTRY", "SDN_GET", "SDN_FABRICAPATHEP",
// "SDN_FABRICINST", "SDN_FVBD", "SDN_EPTRACKER", "SDN_VZBRCP", "SDN_FABRICPATHEP", "SDN_CONTROLLER", "SDN_CONTROLLERSSIZE",
// "SDN_FVAP", "SDN_FVSUBNET", "SDN_FORTYPOLICY", "SDN_FORTISUBNET", "SDN_FORTISERVICE", "SDN_FIRMWARE", "SDN_VZFILTER",
// "SDN_VZENTRY", "SDN_CONTRACT", "SDN_INFRA", "SDN_FABRIC2", "CHECKDEVICE"}[t-1]
// }
//
// type Args struct {
// ServiceType TopoServerType
// Uuid        string
// Id          uint
// Ip          string
// StructType  string
// Platform    string
// IsRedfish   bool
// Remote      *structs.L2DeviceRemoteInfo
// Meta        *L2DeviceMeta
// Options []interface{}
// }
type L2NodemapServiceCenterInterface interface {
	Select(remote *structs.L2DeviceRemoteInfo, srv string) L2NodemapServiceInterface
}

type L2NodemapServiceInterface interface {
	ServiceName() string
	Run(remote *structs.L2DeviceRemoteInfo, options ...interface{}) (*clitask.Table, error)
}

//

// type SnmpTaskGenerator interface {
// NewSnmpTask(host, community string) *snmp.SnmpTask
// }

type L2NodemapTaskConfigInterface interface {
	IsSelected(string, string) bool
	GetMethod() string
	// NewSnmpTask(host, community string) *snmp.SnmpTask
	// NewSSHTask(reote l2model.structs.L2DeviceRemoteInfo) (*terminal.Execute, error)
	NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error)
	GetMainConfig() L2NodemapServiceCenterInterface
	// NewRedfishTask(remote l2model.structs.L2DeviceRemoteInfo) *redfish.RedfishTask
	WithMainConfig(L2NodemapServiceCenterInterface)
	GetSubOid(key string) string
	SupportVersion() []string
	IsPretty() bool
}

type L2NodemapInstanceInterface interface {
	Process(remote *structs.L2DeviceRemoteInfo, taskConfig L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error)
}
