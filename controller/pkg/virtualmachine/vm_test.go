package virtualmachine

import (
	"fmt"
	"testing"

	clitask "github.com/netxops/utils/task"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/vmware/govmomi/vim25/types"
)

var vmAllListTests = []struct {
	Name   string
	System string
	Self   structs.Self
	VM     types.ManagedObjectReference
}{
	{"测试机器two", "Red Hat Enterprise Linux 7 (64-bit)", structs.Self{Type: "VirtualMachine", Value: "vm-904"},
		types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-904"}},
	{"EVE-PRO(100.222)", "Ubuntu Linux (64-bit)", structs.Self{Type: "VirtualMachine", Value: "vm-902"},
		types.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-902"}},
}

func TestVmWare_GetAllVmClient(t *testing.T) {
	vm := NewVmWare("192.168.100.200", "Administrator@vsphere.local", "!@AsiaLink@2020")
	vmList, _, _ := vm.GetAllVmClient()
	for _, vm := range vmList {
		for _, vmtest := range vmAllListTests {
			if vm.Name == vmtest.Name {
				t.Log("获取虚拟机测试通过")
			}
		}
	}
}

var hostListTests = []struct {
	Name string
}{
	{"192.168.100.201"},
	{"192.168.100.202"},
	{"192.168.100.203"},
	{"192.168.100.204"},
}

func TestVmWare_GetAllHost(t *testing.T) {
	vm := NewVmWare("192.168.100.200", "Administrator@vsphere.local", "!@AsiaLink@2020")
	hostAllList, _ := vm.GetAllHost()
	var hostName []string
	for _, host := range hostAllList {
		hostName = append(hostName, host.Name)
	}
	for _, hostTest := range hostListTests {
		if IsContain(hostName, hostTest.Name) {
			t.Logf("宿主机%s: 获取成功", hostTest.Name)
		} else {
			t.Logf("宿主机%s: 获取失败", hostTest.Name)
		}
	}
	// resourceList, err := vm.GetAllResourcePool()
	// if err != nil {
	//	panic(err)
	// }
	// var resourceStr, resourceID string
	// //var poolRef types.ManagedObjectReference
	// for _, resource := range resourceList {
	//	resourceStr = resource.Name
	//	resourceID = resource.ResourcePool.Value
	//	//poolRef = resource.Resource
	//	fmt.Println("//////", resourceStr, resourceID)
	// }
	// dataCenterList, err := vm.GetAllDatacenter()
	// if err != nil {
	//	panic(err)
	// }
	// var datacenterID, datacenterName string
	// for _, datacenter := range dataCenterList {
	//	datacenterID = datacenter.Datacenter.Value
	//	datacenterName = datacenter.Name
	//	fmt.Println("----", datacenterID, datacenterName)
	// }
	// clusterList, err := vm.GetAllCluster()
	// if err != nil {
	//	panic(err)
	// }
	// var clusterID, clusterName string
	// for _, cluster := range clusterList {
	//	clusterID = cluster.Cluster.Value
	//	clusterName = cluster.Name
	//	fmt.Println("--11--", clusterID, clusterName)
	// }
	// datastoreList, err := vm.GetAllDatastore()
	// if err != nil {
	//	panic(err)
	// }
	// var datastoreID, datastoreStr string
	// //var datastoreRef types.ManagedObjectReference
	// for _, datastore := range datastoreList {
	//	datastoreID = datastore.Datastore.Value
	//	datastoreStr = datastore.Name
	//	//datastoreRef = datastore.DatastoreSelf
	//	fmt.Println("sss", datastoreID, datastoreStr)
	// }
}

var vmNetworkTests = []struct {
	Name string
}{
	{"vlan100"},
	{"vlan80"},
}

func TestVmWare_GetAllNetwork(t *testing.T) {
	vm := NewVmWare("192.168.100.200", "Administrator@vsphere.local", "!@AsiaLink@2020")
	networkList, _ := vm.GetAllNetwork()
	var networkName []string
	for _, network := range networkList {
		networkName = append(networkName, network["Vlan"])
	}
	for _, networkTest := range vmNetworkTests {
		if IsContain(networkName, networkTest.Name) {
			t.Logf("网络-%s: 获取成功", networkTest.Name)
		} else {
			t.Logf("网络-%s: 获取失败", networkTest.Name)
		}
	}
}

var vmDatastoreTests = []struct {
	Name string
}{
	{"local-esxi-201"},
	{"local-esxi-202"},
	{"local-esxi-203"},
	{"local-esxi-204"},
}

func TestVmWare_GetAllDatastore(t *testing.T) {
	vm := NewVmWare("192.168.100.200", "Administrator@vsphere.local", "!@AsiaLink@2020")
	datastoreList, _ := vm.GetAllDatastore()
	var datastoreName []string
	for _, datastore := range datastoreList {
		datastoreName = append(datastoreName, datastore.Name)
	}
	for _, datastoreTest := range vmDatastoreTests {
		if IsContain(datastoreName, datastoreTest.Name) {
			t.Logf("数据存储-%s: 获取成功", datastoreTest.Name)
		} else {
			t.Logf("数据存储-%s: 获取失败", datastoreTest.Name)
		}
	}
}

var vmCloneTests = []struct {
	Name string
}{
	{"测试机器"},
}

func TestVmWare_CloneVM(t *testing.T) {
	fmt.Println("ssssstart")
	vm := NewVmWare("192.168.100.200", "Administrator@vsphere.local", "!@AsiaLink@2020")
	vm.CloneVM("CentOS7-Mini-Template", "AsiaLink-Test", "AsiaLink-Test", "192.168.100.201", "开发环境", "DiskArray-Host201-6TB", "ttt111", "test", "off", "", "", "")
	vmList, _, _ := vm.GetAllVmClient()
	var vmName []string
	for _, vm := range vmList {
		vmName = append(vmName, vm.Name)
	}
	for _, vmTest := range vmCloneTests {
		if IsContain(vmName, vmTest.Name) {
			t.Logf("虚拟机-%s: 创建成功", vmTest.Name)
		} else {
			t.Logf("虚拟机-%s: 创建失败", vmTest.Name)
		}
	}
}

func TestVmWare_Resource(t *testing.T) {
	fmt.Println("ssssstart")
	vm := NewVmWare("192.168.100.200", "Administrator@vsphere.local", "!@AsiaLink@2020")
	vm.GetAllResourcePool()
	//
}
func TestVmWare_Host(t *testing.T) {
	fmt.Println("ssssstart")
	vm := NewVmWare("192.168.100.200", "Administrator@vsphere.local", "!@AsiaLink@2020")
	// host, _ := vm.GetVmIpData()
	// a, _ := json.Marshal(host)
	// fmt.Println("/////", string(a))
	//
	iplist, err := vm.GetVmIpData()
	if err != nil {
		return
	}
	tb := clitask.NewEmptyTableWithKeys([]string{"Config", "Ip"})
	for config, eachlist := range iplist {
		p := map[string]string{}
		p["Config"] = config
		for _, eachip := range eachlist {
			p["Ip"] = eachip
			err = tb.PushRow("", p, false, "")
			if err != nil {
				return
			}
		}
	}
	tb.Pretty()
}

//
