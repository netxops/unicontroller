package structs

import "github.com/vmware/govmomi/vim25/types"

type VirtualMachines struct {
	Name       string `json:"Name"`
	System     string `json:"System"`
	CPU        int    `json:"CPU"`
	Mem        int    `json:"Mem"`
	PowerState int    `json:"PowerState"`
	Self       Self   `json:"Self"`
	VM         types.ManagedObjectReference
	Disk       int    `json:"DISK"`
	IPV4       string `json:"IPV4"`
	Mac        string `json:"Mac"`
	//VmValue  string `json:"VmValue"`
}

type TemplateInfo struct {
	Name       string `json:"Name"`
	System     string `json:"System"`
	CreateDate string `json:"CreateDate"`
	CPU        int    `json:"CPU"`
	Mem        int    `json:"Mem"`
	Disk       int    `json:"DISK"`
	Self       Self
	VM         types.ManagedObjectReference
	IPV4       string `json:"IPV4"`
	Mac        string `json:"Mac"`
	//VmValue  string `json:"VmValue"`
}

type DatastoreSummary struct {
	Datastore          Datastore `json:"Datastore"`
	Name               string    `json:"Name"`
	URL                string    `json:"Url"`
	Capacity           int64     `json:"Capacity"`
	FreeSpace          int64     `json:"FreeSpace"`
	Uncommitted        int64     `json:"Uncommitted"`
	Accessible         bool      `json:"Accessible"`
	MultipleHostAccess bool      `json:"MultipleHostAccess"`
	Type               string    `json:"Type"`
	MaintenanceMode    string    `json:"MaintenanceMode"`
	DatastoreSelf      types.ManagedObjectReference
}

type Datastore struct {
	Type  string `json:"Type"`
	Value string `json:"Value"`
}

type HostSummary struct {
	Host               Host   `json:"Host"`
	Name               string `json:"Name"`
	UsedCPU            int64  `json:"UsedCPU"`
	TotalCPU           int64  `json:"TotalCPU"`
	FreeCPU            int64  `json:"FreeCPU"`
	UsedMemory         int64  `json:"UsedMemory"`
	TotalMemory        int64  `json:"TotalMemory"`
	FreeMemory         int64  `json:"FreeMemory"`
	PowerState         string `json:"PowerState"`
	ManagementServerIp string `json:"ManagementServerIp"`
	HostIp             string `json:"HostIp"`
	HostSelf           types.ManagedObjectReference
}

type Host struct {
	Type  string `json:"Type"`
	Value string `json:"Value"`
}

type HostVM struct {
	Host map[string][]VMS
}

type VMS struct {
	Name  string
	Value string
}

type DataCenter struct {
	Datacenter      Self
	Name            string
	VmFolder        Self
	HostFolder      Self
	DatastoreFolder Self
}

type ClusterInfo struct {
	Cluster      Self
	Name         string
	Parent       Self
	ResourcePool Self
	Hosts        []types.ManagedObjectReference
	Datastore    []types.ManagedObjectReference
}

type ResourcePoolInfo struct {
	ResourcePool     Self
	Name             string
	Parent           Self
	ResourcePoolList []types.ManagedObjectReference
	Resource         types.ManagedObjectReference
}

type FolderInfo struct {
	Folder      Self
	Name        string
	ChildEntity []types.ManagedObjectReference
	Parent      Self
	FolderSelf  types.ManagedObjectReference
}

type Self struct {
	Type  string
	Value string
}

type CreateMap struct {
	TempName    string
	Datacenter  string
	Cluster     string
	Host        string
	Resources   string
	Storage     string
	VmName      string
	SysHostName string
	Network     string
}

type SourceInfo struct {
	TotalSpace         string
	FreeSpace          string
	UseSpace           string
	TotalCpu           string
	UseCpu             string
	FreeCpu            string
	TotalMem           string
	UseMem             string
	FreeMem            string
	HostTotal          string
	ConnTotal          string
	DisconnTotal       string
	MaintainTotal      string
	VmTotal            string
	ManagementServerIp string
}

type InterfaceVM struct {
	MacAddress  string
	IpAddress   []string
	Network     string
	VmName      string
	VmIpAddress []VmIpAddress
}

type VmIpAddress struct {
	Name      string
	IpAddress []string
}
