package vm

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/virtualmachine"

	clitask "github.com/netxops/utils/task"
)

type Vmware struct {
}

func (v *Vmware) VmwareClient(remote *structs.L2DeviceRemoteInfo) *virtualmachine.VmWare {
	return virtualmachine.NewVmWare(remote.Ip, remote.Username, remote.Password)
}

func (v *Vmware) getVMResources(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	resourceList, err := server.GetAllResourcePool()
	tb := clitask.NewEmptyTableWithKeys([]string{"name"})
	for _, resource := range resourceList {
		p := map[string]string{}
		p["name"] = resource.Name
		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, nil
}

func (v *Vmware) getVMClient(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	vmList, _, err := server.GetAllVmClient()
	tb := clitask.NewEmptyTableWithKeys([]string{"Name", "System", "CPU", "Mem", "PowerState", "Disk", "Mac", "IPV4", "VMValue"})
	for _, client := range vmList {
		p := map[string]string{}
		p["Name"] = client.Name
		p["System"] = client.System
		p["CPU"] = fmt.Sprintf("%d", client.CPU)
		p["Mem"] = fmt.Sprintf("%d", client.Mem)
		p["PowerState"] = fmt.Sprintf("%d", client.PowerState)
		p["Disk"] = fmt.Sprintf("%d", client.Disk)
		p["IPV4"] = fmt.Sprintf("%s", client.IPV4)
		p["Mac"] = fmt.Sprintf("%s", client.Mac)
		p["VMValue"] = fmt.Sprintf("%s", client.Self.Value)
		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	// tb.Pretty()
	return tb, nil
}

func (v *Vmware) getVMTemplate(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	_, templateList, err := server.GetAllVmClient()
	tb := clitask.NewEmptyTableWithKeys([]string{"Name", "System", "CPU", "Mem", "Disk", "CreateDate"})
	for _, client := range templateList {
		p := map[string]string{}
		p["Name"] = client.Name
		p["System"] = client.System
		p["CPU"] = fmt.Sprintf("%d", client.CPU)
		p["Mem"] = fmt.Sprintf("%d", client.Mem)
		p["Disk"] = fmt.Sprintf("%d", client.Disk)
		p["CreateDate"] = client.CreateDate
		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, nil
}
func (v *Vmware) getVMHost(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	hostList, err := server.GetAllHost()
	tb := clitask.NewEmptyTableWithKeys([]string{"Name", "UsedMemory", "FreeCPU", "TotalCPU", "TotalCPU", "UsedCPU",
		"TotalMemory", "HostIp", "PowerState", "FreeMemory", "ManagementServerIp"})
	for _, client := range hostList {
		p := map[string]string{}
		p["Name"] = client.Name
		p["UsedMemory"] = fmt.Sprintf("%d", client.UsedMemory)
		p["FreeCPU"] = fmt.Sprintf("%d", client.FreeCPU)
		p["TotalCPU"] = fmt.Sprintf("%d", client.TotalCPU)
		p["UsedCPU"] = fmt.Sprintf("%d", client.UsedCPU)
		p["TotalMemory"] = fmt.Sprintf("%d", client.TotalMemory)
		p["HostIp"] = client.HostIp
		p["PowerState"] = client.PowerState
		p["FreeMemory"] = fmt.Sprintf("%d", client.FreeMemory)
		p["ManagementServerIp"] = client.ManagementServerIp
		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, nil
}
func (v *Vmware) getVMCluster(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	clusterList, _ := server.GetAllCluster()
	tb := clitask.NewEmptyTableWithKeys([]string{"Name"})
	for _, client := range clusterList {
		p := map[string]string{}
		p["Name"] = client.Name
		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, nil
}

func (v *Vmware) getVMHostBaseValue(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	resVm, err := server.GetHostVm()
	// clusterList, _ := server.GetAllCluster()
	tb := clitask.NewEmptyTableWithKeys([]string{"Ip", "Name"})
	for ip, valuelist := range resVm {
		p := map[string]string{}
		p["Ip"] = ip
		for _, eachValue := range valuelist {
			p["Name"] = eachValue.Name
			err = tb.PushRow("", p, false, "")
			if err != nil {
				return nil, err
			}
		}
	}
	return tb, nil
}

func (v *Vmware) getVMIPdata(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	iplist, err := server.GetVmIpData()
	if err != nil {
		return nil, err
	}
	tb := clitask.NewEmptyTableWithKeys([]string{"Config", "Ip"})
	for config, eachlist := range iplist {
		p := map[string]string{}
		p["Config"] = config
		for _, eachip := range eachlist {
			p["Ip"] = eachip
			err = tb.PushRow("", p, false, "")
			if err != nil {
				return nil, err
			}
		}
	}
	return tb, nil
}
func (v *Vmware) getVMDatastore(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	datastoreList, err := server.GetAllDatastore()
	if err != nil {
		return nil, err
	}
	tb := clitask.NewEmptyTableWithKeys([]string{"name", "url", "capacity", "freeSpace", "uncommitted", "accessible", "multipleHostAccess", "type", "maintenanceMode"})
	for _, client := range datastoreList {
		p := map[string]string{}
		p["name"] = client.Name
		p["url"] = client.URL
		p["capacity"] = fmt.Sprintf("%d", client.Capacity)
		p["freeSpace"] = fmt.Sprintf("%d", client.FreeSpace)
		p["uncommitted"] = fmt.Sprintf("%d", client.Uncommitted)
		p["accessible"] = fmt.Sprintf("%t", client.Accessible)
		p["multipleHostAccess"] = fmt.Sprintf("%t", client.MultipleHostAccess)
		p["type"] = client.Type
		p["maintenanceMode"] = client.MaintenanceMode

		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, nil
}

func (v *Vmware) getVMInfoData(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	sourceInfo := server.GetSourceData()
	tb := clitask.NewEmptyTableWithKeys([]string{"totalSpace", "freeSpace", "useSpace", "totalCpu", "useCpu", "freeCpu", "totalMem", "useMem", "freeMem", "hostTotal",
		"connTotal", "disconnTotal", "maintainTotal", "vmTotal", "managementServerIp"})
	p := map[string]string{}
	p["totalSpace"] = sourceInfo.TotalSpace
	p["freeSpace"] = sourceInfo.FreeSpace
	p["useSpace"] = sourceInfo.UseSpace
	p["totalCpu"] = sourceInfo.TotalCpu
	p["useCpu"] = sourceInfo.UseCpu
	p["freeCpu"] = sourceInfo.FreeCpu
	p["totalMem"] = sourceInfo.TotalMem
	p["useMem"] = sourceInfo.UseMem
	p["freeMem"] = sourceInfo.FreeMem
	p["hostTotal"] = sourceInfo.HostTotal
	p["connTotal"] = sourceInfo.ConnTotal
	p["disconnTotal"] = sourceInfo.DisconnTotal
	p["maintainTotal"] = sourceInfo.MaintainTotal
	p["vmTotal"] = sourceInfo.VmTotal
	p["managementServerIp"] = sourceInfo.ManagementServerIp
	err = tb.PushRow("", p, false, "")
	if err != nil {
		return nil, err
	}
	return tb, nil
}

func (v *Vmware) getVMwareInterface(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	interfacesList, err := server.GetVMInterface()
	tb := clitask.NewEmptyTableWithKeys([]string{"interfaces"})
	for _, interfaces := range interfacesList {
		p := map[string]string{}
		p["interfaces"] = fmt.Sprintf("%s", interfaces)
		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, nil
}

func (v *Vmware) getLinuxIfConfig(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *virtualmachine.VmWare) (result *clitask.Table, err error) {
	interfacesList, err := server.GetConfigData()
	tb := clitask.NewEmptyTableWithKeys([]string{"interfaces"})
	for _, interfaces := range interfacesList {
		p := map[string]string{}
		p["interfaces"] = fmt.Sprintf("%s", interfaces)
		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, nil
}

func (v *Vmware) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	vmServer := v.VmwareClient(remote)
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "VMWARE_RESOURCES":
		result, err = v.getVMResources(remote, taskConfig, vmServer)
		fmt.Println("this is from vm resources: ", remote)
	case "VMWARE_VM":
		result, err = v.getVMClient(remote, taskConfig, vmServer)
		fmt.Println("this is from vm client: ", remote)
	case "VMWARE_TEMPLATE":
		result, err = v.getVMTemplate(remote, taskConfig, vmServer)
		fmt.Println("this is from vm template: ", remote)
	case "VMWARE_DATASTORE":
		result, err = v.getVMDatastore(remote, taskConfig, vmServer)
		fmt.Println("this is from vm datastore: ", remote)
	case "VMWARE_INFO":
		result, err = v.getVMInfoData(remote, taskConfig, vmServer)
		fmt.Println("this is from vm source info data: ", remote)
	case "VMWARE_HOST":
		result, err = v.getVMHost(remote, taskConfig, vmServer)
	case "VMWARE_CLUSTER":
		result, err = v.getVMCluster(remote, taskConfig, vmServer)
	case "VMWARE_HOST_BASE":
		result, err = v.getVMHostBaseValue(remote, taskConfig, vmServer)
	case "VMWARE_IPDATA":
		result, err = v.getVMIPdata(remote, taskConfig, vmServer)
	// case "VMWARE_INTERFACES":
	//	result, err = v.getVMwareInterface(remote, taskConfig, vmServer)
	//	fmt.Println("this is from vm interfaces: ", remote)
	//	return
	case "VMWARE_INTERFACES":
		result, err = v.getLinuxIfConfig(remote, taskConfig, vmServer)
		fmt.Println("this is from linux interfaces: ", remote)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}
