package virtualmachine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/netxops/cli"

	// "github.com/netxops/unify/service"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"

	// "github.com/vmware/govmomi/property"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/vmware/govmomi/units"
	"github.com/vmware/govmomi/vapi/library"
	"github.com/vmware/govmomi/vapi/rest"
	"github.com/vmware/govmomi/vapi/vcenter"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

type VmWare struct {
	IP     string
	User   string
	Pwd    string
	client *govmomi.Client
	ctx    context.Context
	clt    *vim25.Client
}

func NewVmWare(IP, User, Pwd string) *VmWare {
	u := &url.URL{
		Scheme: "https",
		Host:   IP,
		Path:   "/sdk",
	}
	ctx := context.Background()
	u.User = url.UserPassword(User, Pwd)
	client, err := govmomi.NewClient(ctx, u, true)
	if err != nil {
		msg := fmt.Sprintf("连接vc错误,用户名:%s,密码:%s,错误信息:%s", User, Pwd, err)
		fmt.Println(msg)
		return nil
	}
	return &VmWare{
		IP:     IP,
		User:   User,
		Pwd:    Pwd,
		client: client,
		ctx:    ctx,
	}
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func (vw *VmWare) getBase(tp string) (v *view.ContainerView, error error) {
	m := view.NewManager(vw.client.Client)

	v, err := m.CreateContainerView(vw.ctx, vw.client.Client.ServiceContent.RootFolder, []string{tp}, true)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (vw *VmWare) GetAllVmClient() (vmList []structs.VirtualMachines, templateList []structs.TemplateInfo, err error) {
	v, err := vw.getBase("VirtualMachine")
	if err != nil {
		return nil, nil, err
	}
	defer v.Destroy(vw.ctx)
	var vms []mo.VirtualMachine
	err = v.Retrieve(vw.ctx, []string{"VirtualMachine"}, []string{"summary", "config", "guest"}, &vms)
	if err != nil {
		return nil, nil, err
	}
	for _, vm := range vms {
		// if vm.Summary.Config.Name == "测试机器" {
		//	v := object.NewVirtualMachine(vw.client.Client, vm.Self)
		//	vw.setIP(v)
		// }
		var diskint int64
		b := object.NewVirtualMachine(vw.client.Client, vm.Self)
		devices, _ := b.Device(vw.ctx)
		for _, eachDe := range devices {
			if disk, ok := eachDe.(*types.VirtualDisk); ok {
				diskint = diskint + disk.CapacityInKB
				// fmt.Printf("size=%d", disk.CapacityInKB)
			}
		}
		ipv4, macAddress := "", ""
		if vm.Guest.IpAddress != "" {
			ipv4 = vm.Guest.IpAddress
			for _, k := range vm.Guest.Net {
				for _, s := range k.IpAddress {
					if s == ipv4 {
						macAddress = k.MacAddress
					}
				}
			}
		}
		// fmt.Println("-----ip", ipv4, macAddress)
		if vm.Summary.Config.Template {
			templateList = append(templateList, structs.TemplateInfo{
				Name:       vm.Summary.Config.Name,
				System:     vm.Summary.Config.GuestFullName,
				CPU:        int(vm.Summary.Config.NumCpu),
				Mem:        int(vm.Summary.Config.MemorySizeMB),
				Disk:       int(diskint) / (1024 * 1024),
				CreateDate: fmt.Sprintf("%s", vm.Config.CreateDate),
				Self: structs.Self{
					Type:  vm.Self.Type,
					Value: vm.Self.Value,
				},
				VM:   vm.Self,
				IPV4: ipv4,
				Mac:  macAddress,
			})
		} else {
			var keyStuas int
			if vm.Summary.Runtime.PowerState == "poweredOn" {
				keyStuas = 1
			} else {
				keyStuas = 2
			}
			vmList = append(vmList, structs.VirtualMachines{
				Name:       vm.Summary.Config.Name,
				System:     vm.Summary.Config.GuestFullName,
				CPU:        int(vm.Summary.Config.NumCpu),
				Mem:        int(vm.Summary.Config.MemorySizeMB),
				Disk:       int(diskint) / (1024 * 1024),
				PowerState: keyStuas,
				Self: structs.Self{
					Type:  vm.Self.Type,
					Value: vm.Self.Value,
				},
				VM:   vm.Self,
				IPV4: ipv4,
				Mac:  macAddress,
			})
		}
	}
	// fmt.Println(vmList)
	return vmList, templateList, nil
}

func (vw *VmWare) GetAllHost() (hostList []*structs.HostSummary, err error) {
	v, err := vw.getBase("HostSystem")
	if err != nil {
		return nil, err
	}
	defer v.Destroy(vw.ctx)
	var hss []mo.HostSystem
	err = v.Retrieve(vw.ctx, []string{"HostSystem"}, []string{"summary", "config"}, &hss)
	if err != nil {
		return nil, err
	}
	for _, hs := range hss {
		// s, _ := json.Marshal(hs)
		// fmt.Println(string(s))
		// break
		// fmt.Println(hs.Summary.ManagementServerIp)
		totalCPU := int64(hs.Summary.Hardware.CpuMhz) * int64(hs.Summary.Hardware.NumCpuCores)
		freeCPU := int64(totalCPU) - int64(hs.Summary.QuickStats.OverallCpuUsage)
		freeMemory := int64(hs.Summary.Hardware.MemorySize) - (int64(hs.Summary.QuickStats.OverallMemoryUsage) * 1024 * 1024)
		hostList = append(hostList, &structs.HostSummary{
			Host: structs.Host{
				Type:  hs.Summary.Host.Type,
				Value: hs.Summary.Host.Value,
			},
			Name:               hs.Summary.Config.Name,
			UsedCPU:            int64(hs.Summary.QuickStats.OverallCpuUsage),
			TotalCPU:           totalCPU,
			FreeCPU:            freeCPU,
			UsedMemory:         int64((units.ByteSize(hs.Summary.QuickStats.OverallMemoryUsage)) * 1024 * 1024),
			TotalMemory:        int64(units.ByteSize(hs.Summary.Hardware.MemorySize)),
			FreeMemory:         freeMemory,
			HostSelf:           hs.Self,
			PowerState:         string(hs.Summary.Runtime.PowerState),
			ManagementServerIp: hs.Summary.ManagementServerIp,
			// HostIp:             hs.Config.Vmotion.IpConfig.IpAddress,
			HostIp: hs.Summary.Config.Name,
		})
	}
	// fmt.Println(hostList)
	// networkList, err := vw.GetAllNetwork()
	// if err != nil {
	//	panic(err)
	// }
	// var networkID, networkStr string
	// for _, network := range networkList {
	//	networkStr = network["Vlan"]
	//	networkID = network["NetworkID"]
	//	fmt.Println("---", networkID, networkStr)
	// }
	return hostList, err
}

func (vw *VmWare) GetAllNetwork() (networkList []map[string]string, err error) {
	v, err := vw.getBase("Network")
	if err != nil {
		return nil, err
	}
	defer v.Destroy(vw.ctx)
	var networks []mo.Network
	err = v.Retrieve(vw.ctx, []string{"Network"}, nil, &networks)
	if err != nil {
		return nil, err
	}
	for _, net := range networks {
		networkList = append(networkList, map[string]string{
			"Vlan":      net.Name,
			"NetworkID": strings.Split(net.Reference().String(), ":")[1],
		})
	}
	return networkList, nil
}

func (vw *VmWare) GetAllDatastore() (datastoreList []structs.DatastoreSummary, err error) {
	v, err := vw.getBase("Datastore")
	if err != nil {
		return nil, err
	}
	defer v.Destroy(vw.ctx)
	var dss []mo.Datastore
	err = v.Retrieve(vw.ctx, []string{"Datastore"}, []string{"summary"}, &dss)
	if err != nil {
		return nil, err
	}
	for _, ds := range dss {
		datastoreList = append(datastoreList, structs.DatastoreSummary{
			Name: ds.Summary.Name,
			Datastore: structs.Datastore{
				Type:  ds.Summary.Datastore.Type,
				Value: ds.Summary.Datastore.Value,
			},
			Type:          ds.Summary.Type,
			Capacity:      int64(units.ByteSize(ds.Summary.Capacity)),
			FreeSpace:     int64(units.ByteSize(ds.Summary.FreeSpace)),
			DatastoreSelf: ds.Self,
		})
	}
	return
}

// // map["1.1.1.1"] = []structs.VMS{{"Name": "vm1", "Value": "xxx"}, {"Name": "vm2", "Value": "yyyy"}}
// // map["1.1.1.1"] = []string{ "vm1",  "vm2" }
// // map["2.2.2.2"] = []string{ "vm3", "vm4"}
// // []map[string]string = []map[string]string{ {{"ip": "1.1.1.1", "vmName": "vm1"}, {"ip": "1.1.1.1", "vmName": "vm2"},
// //                                             {"ip": "2.2.2.2", "vmName": "vm3", "ip": "2.2.2.2", "vmName": "vm4"}}
// // map[uint][]map[string]string
// // 实际上是一个VCenter的数据, 所以对应于L2的结构来，map[uint]的key是vcenter的id
// func (vw *VmWare) GetHostVm2() (resVm map[string][]string, err error) {
//	hostList, err := vw.GetAllHost() //
//	if err != nil {
//		return
//	}
//	var hostIDList []string
//	hostVm := make(map[string][]structs.VMS)
//	for _, host := range hostList {
//		hostIDList = append(hostIDList, host.Host.Value)
//		hostVm[host.Host.Value] = []structs.VMS{}
//	}
//	v, err := vw.getBase("VirtualMachine")
//	if err != nil {
//		return nil, err
//	}
//	defer v.Destroy(vw.ctx)
//	var vms []mo.VirtualMachine
//	err = v.Retrieve(vw.ctx, []string{"VirtualMachine"}, []string{"summary"}, &vms)
//	if err != nil {
//		return nil, err
//	}
//	for _, vm := range vms {
//		//s, _ := json.Marshal(vm)
//		//fmt.Println(string(s))
//		//break
//		if IsContain(hostIDList, vm.Summary.Runtime.Host.Value) {
//			hostVm[vm.Summary.Runtime.Host.Value] = append(hostVm[vm.Summary.Runtime.Host.Value], structs.VMS{
//				Name:  vm.Summary.Config.Name,
//				Value: vm.Summary.Vm.Value,
//			})
//		}
//		//s, _ := json.Marshal(vm.Summary)
//		//fmt.Println(string(s))
//		//break
//	}
//	resVm = make(map[string][]structs.VMS)
//
//	for _, host := range hostList {
//		// host.Host.Value相当于一个IP
//		if _, ok := hostVm[host.Host.Value]; ok {
//			resVm[host.HostIp] = hostVm[host.Host.Value]
//		}
//
//	}
//	//fmt.Println(resVm)
//	return
// }

func (vw *VmWare) GetHostVm() (resVm map[string][]structs.VMS, err error) {
	hostList, err := vw.GetAllHost() //
	if err != nil {
		return
	}
	var hostIDList []string
	hostVm := make(map[string][]structs.VMS)
	for _, host := range hostList {
		hostIDList = append(hostIDList, host.Host.Value)
		hostVm[host.Host.Value] = []structs.VMS{}
	}
	v, err := vw.getBase("VirtualMachine")
	if err != nil {
		return nil, err
	}
	defer v.Destroy(vw.ctx)
	var vms []mo.VirtualMachine
	err = v.Retrieve(vw.ctx, []string{"VirtualMachine"}, []string{"summary"}, &vms)
	if err != nil {
		return nil, err
	}
	for _, vm := range vms {
		// s, _ := json.Marshal(vm)
		// fmt.Println(string(s))
		// break
		if IsContain(hostIDList, vm.Summary.Runtime.Host.Value) {
			hostVm[vm.Summary.Runtime.Host.Value] = append(hostVm[vm.Summary.Runtime.Host.Value], structs.VMS{
				Name:  vm.Summary.Config.Name,
				Value: vm.Summary.Vm.Value,
			})
		}
		// s, _ := json.Marshal(vm.Summary)
		// fmt.Println(string(s))
		// break
	}
	resVm = make(map[string][]structs.VMS)

	for _, host := range hostList {
		if _, ok := hostVm[host.Host.Value]; ok {
			resVm[host.HostIp] = hostVm[host.Host.Value]
		}

	}
	// fmt.Println(resVm)
	return
}

func (vw *VmWare) GetAllCluster() (clusterList []structs.ClusterInfo, err error) {
	v, err := vw.getBase("ClusterComputeResource")
	if err != nil {
		return nil, err
	}
	defer v.Destroy(vw.ctx)
	var crs []mo.ClusterComputeResource
	err = v.Retrieve(vw.ctx, []string{"ClusterComputeResource"}, []string{}, &crs)
	if err != nil {
		return nil, err
	}
	for _, cr := range crs {
		clusterList = append(clusterList, structs.ClusterInfo{
			Cluster: structs.Self{
				Type:  cr.Self.Type,
				Value: cr.Self.Value,
			},
			Name: cr.Name,
			Parent: structs.Self{
				Type:  cr.Parent.Type,
				Value: cr.Parent.Value,
			},
			ResourcePool: structs.Self{
				Type:  cr.ResourcePool.Type,
				Value: cr.ResourcePool.Value,
			},
			Hosts:     cr.Host,
			Datastore: cr.Datastore,
		})
	}
	fmt.Println("--====", clusterList)
	return
}

func (vw *VmWare) GetAllDatacenter() (dataCenterList []structs.DataCenter, err error) {
	v, err := vw.getBase("Datacenter")
	if err != nil {
		return nil, err
	}
	defer v.Destroy(vw.ctx)
	var dcs []mo.Datacenter
	err = v.Retrieve(vw.ctx, []string{"Datacenter"}, []string{}, &dcs)
	if err != nil {
		return nil, err
	}
	for _, dc := range dcs {
		dataCenterList = append(dataCenterList, structs.DataCenter{
			Datacenter: structs.Self{
				Type:  dc.Self.Type,
				Value: dc.Self.Value,
			},
			Name: dc.Name,
			VmFolder: structs.Self{
				Type:  dc.VmFolder.Type,
				Value: dc.VmFolder.Value,
			},
			HostFolder: structs.Self{
				Type:  dc.HostFolder.Type,
				Value: dc.HostFolder.Value,
			},
			DatastoreFolder: structs.Self{
				Type:  dc.DatastoreFolder.Type,
				Value: dc.DatastoreFolder.Value,
			},
		})
	}
	fmt.Println(dataCenterList)
	return
}

func (vw *VmWare) GetAllResourcePool() (resourceList []structs.ResourcePoolInfo, err error) {
	v, err := vw.getBase("ResourcePool")
	if err != nil {
		return nil, err
	}
	defer v.Destroy(vw.ctx)
	var rps []mo.ResourcePool
	err = v.Retrieve(vw.ctx, []string{"ResourcePool"}, []string{}, &rps)
	for _, rp := range rps {
		// if rp.Name == "测试虚机" {
		// }
		a, _ := json.Marshal(rp)
		fmt.Println("/////", string(a))
		resourceList = append(resourceList, structs.ResourcePoolInfo{
			ResourcePool: structs.Self{
				Type:  rp.Self.Type,
				Value: rp.Self.Value,
			},
			Name: rp.Name,
			Parent: structs.Self{
				Type:  rp.Parent.Type,
				Value: rp.Parent.Value,
			},
			ResourcePoolList: rp.ResourcePool,
			Resource:         rp.Self,
		})
	}
	return
}

func (vw *VmWare) GetFolder() (folderList []structs.FolderInfo, err error) {
	v, err := vw.getBase("Folder")
	if err != nil {
		return nil, err
	}
	defer v.Destroy(vw.ctx)
	var folders []mo.Folder
	err = v.Retrieve(vw.ctx, []string{"Folder"}, []string{}, &folders)
	for _, folder := range folders {
		// newFolder := object.NewFolder(vw.client.Client, folder.Self)
		// fmt.Println(newFolder)
		folderList = append(folderList, structs.FolderInfo{
			Folder: structs.Self{
				Type:  folder.Self.Type,
				Value: folder.Self.Value,
			},
			Name:        folder.Name,
			ChildEntity: folder.ChildEntity,
			Parent: structs.Self{
				Type:  folder.Parent.Type,
				Value: folder.Parent.Value,
			},
			FolderSelf: folder.Self,
		})
		// break
	}
	return folderList, nil
}

func (vw *VmWare) getLibraryItem(ctx context.Context, rc *rest.Client) (*library.Item, error) {
	const (
		libraryName     = "模板"
		libraryItemName = "template-rehl7.7"
		libraryItemType = "ovf"
	)

	m := library.NewManager(rc)
	libraries, err := m.FindLibrary(ctx, library.Find{Name: libraryName})
	if err != nil {
		fmt.Printf("Find library by name %s failed, %v", libraryName, err)
		return nil, err
	}

	if len(libraries) == 0 {
		fmt.Printf("Library %s was not found", libraryName)
		return nil, fmt.Errorf("library %s was not found", libraryName)
	}

	if len(libraries) > 1 {
		fmt.Printf("There are multiple libraries with the name %s", libraryName)
		return nil, fmt.Errorf("there are multiple libraries with the name %s", libraryName)
	}

	items, err := m.FindLibraryItems(ctx, library.FindItem{Name: libraryItemName,
		Type: libraryItemType, LibraryID: libraries[0]})

	if err != nil {
		fmt.Printf("Find library item by name %s failed", libraryItemName)
		return nil, fmt.Errorf("find library item by name %s failed", libraryItemName)
	}

	if len(items) == 0 {
		fmt.Printf("Library item %s was not found", libraryItemName)
		return nil, fmt.Errorf("library item %s was not found", libraryItemName)
	}

	if len(items) > 1 {
		fmt.Printf("There are multiple library items with the name %s", libraryItemName)
		return nil, fmt.Errorf("there are multiple library items with the name %s", libraryItemName)
	}

	item, err := m.GetLibraryItem(ctx, items[0])
	if err != nil {
		fmt.Printf("Get library item by %s failed, %v", items[0], err)
		return nil, err
	}
	return item, nil
}

func (vw *VmWare) CreateVM() {
	// 构建创建的map数据
	createData := structs.CreateMap{
		TempName:    "template-rehl7.7",
		Datacenter:  "Datacenter",
		Cluster:     "AsiaLink-Production",
		Host:        "192.168.100.201",
		Resources:   "测试虚机",
		Storage:     "local-esxi-201",
		VmName:      "测试机器one",
		SysHostName: "test",
		Network:     "vlan80",
	}
	_, templateList, err := vw.GetAllVmClient()
	if err != nil {
		panic(err)
	}
	var templateNameList []string
	for _, template := range templateList {
		templateNameList = append(templateNameList, template.Name)
	}
	if !IsContain(templateNameList, createData.TempName) {
		fmt.Fprintf(os.Stderr, "模版不存在，虚拟机创建失败")
		return
	}
	resourceList, err := vw.GetAllResourcePool()
	if err != nil {
		panic(err)
	}
	var resourceStr, resourceID string
	for _, resource := range resourceList {
		if resource.Name == createData.Resources {
			resourceStr = resource.Name
			resourceID = resource.ResourcePool.Value
		}
	}
	if resourceStr == "" {
		fmt.Fprintf(os.Stderr, "资源池不存在，虚拟机创建失败")
		return
	}
	fmt.Println("ResourceID", resourceID)
	datastoreList, err := vw.GetAllDatastore()
	if err != nil {
		panic(err)
	}
	var datastoreID, datastoreStr string
	for _, datastore := range datastoreList {
		if datastore.Name == createData.Storage {
			datastoreID = datastore.Datastore.Value
			datastoreStr = datastore.Name
		}
	}
	if datastoreStr == "" {
		fmt.Fprintf(os.Stderr, "存储中心不存在，虚拟机创建失败")
		return
	}
	fmt.Println("DatastoreID", datastoreID)
	networkList, err := vw.GetAllNetwork()
	if err != nil {
		panic(err)
	}
	var networkID, networkStr string
	for _, network := range networkList {
		if network["Vlan"] == createData.Network {
			networkStr = network["Vlan"]
			networkID = network["NetworkID"]
		}
	}

	if networkStr == "" {
		fmt.Fprintf(os.Stderr, "网络不存在，虚拟机创建失败")
		return
	}
	fmt.Println("NetworkID", networkID)
	finder := find.NewFinder(vw.client.Client)
	// resourcePools, err := finder.DatacenterList(vw.ctx, "*")
	// if err != nil {
	//	fmt.Fprintf(os.Stderr, "Failed to list resource pool at vc %v", err)
	//	os.Exit(1)
	// }
	// fmt.Println(reflect.TypeOf(resourcePools[0].Reference().Value), resourcePools)
	// 注意path
	folders, err := finder.FolderList(vw.ctx, "*")
	var folderID string
	for _, folder := range folders {
		if folder.InventoryPath == "/"+createData.Datacenter+"/vm" {
			folderID = folder.Reference().Value
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list folder at vc  %v", err)
		return
	}
	rc := rest.NewClient(vw.client.Client)
	if err := rc.Login(vw.ctx, url.UserPassword(vw.User, vw.Pwd)); err != nil {
		fmt.Fprintf(os.Stderr, "rc Login filed, %v", err)
		return
	}
	item, err := vw.getLibraryItem(vw.ctx, rc)
	if err != nil {
		panic(err)
	}
	// cloneSpec := &types.VirtualMachineCloneSpec{
	//	PowerOn:  false,
	//	Template: cmd.template,
	// }
	// 7fa9e782-cba2-4061-95fc-4ebb08ec127a
	fmt.Println("Item", item.ID)

	m := vcenter.NewManager(rc)
	fr := vcenter.FilterRequest{
		Target: vcenter.Target{
			ResourcePoolID: resourceID,
			FolderID:       folderID,
		},
	}
	r, err := m.FilterLibraryItem(vw.ctx, item.ID, fr)
	if err != nil {
		panic(err)
	}
	fmt.Println(r)
	fmt.Println(11111111111, r.Networks, r.StorageGroups)
	networkKey := r.Networks[0]
	// storageKey := r.StorageGroups[0]

	// 存储一般是精简的thin
	deploy := vcenter.Deploy{
		DeploymentSpec: vcenter.DeploymentSpec{
			Name:               createData.VmName,
			DefaultDatastoreID: datastoreID,
			AcceptAllEULA:      true,
			NetworkMappings: []vcenter.NetworkMapping{
				{
					Key:   networkKey,
					Value: networkID,
				},
			},
			StorageMappings: []vcenter.StorageMapping{{
				Key: "",
				Value: vcenter.StorageGroupMapping{
					Type:         "DATASTORE",
					DatastoreID:  datastoreID,
					Provisioning: "thin",
				},
			}},
			StorageProvisioning: "thin",
		},
		Target: vcenter.Target{
			ResourcePoolID: resourceID,
			FolderID:       folderID,
		},
	}
	ref, err := vcenter.NewManager(rc).DeployLibraryItem(vw.ctx, item.ID, deploy)
	if err != nil {
		fmt.Println(4444444444, err)
		panic(err)
	}
	f := find.NewFinder(vw.client.Client)
	obj, err := f.ObjectReference(vw.ctx, *ref)
	if err != nil {
		panic(err)
	}
	_ = obj.(*object.VirtualMachine)

	// datastores, err := finder.VirtualMachineList(vw.ctx, "*/group-v629")
	// if err != nil {
	//	fmt.Fprintf(os.Stderr, "Failed to list datastore at vc %v", err)
	//	os.Exit(1)
	// }
	// fmt.Println(datastores)
}

func (vw *VmWare) CloneVM(TempName, Datacenter, Cluster, HostStr, Resources, Storage, VmName, SysHostName, cloneDoneVmPower, nicAddress, netMask, nicGateway string) (err error) {
	// 被克隆数据组装
	cloneData := structs.CreateMap{
		TempName:    TempName,
		Datacenter:  Datacenter,
		Cluster:     Cluster,
		Host:        HostStr,
		Resources:   Resources,
		Storage:     Storage,
		VmName:      VmName,
		SysHostName: SysHostName,
		Network:     "vlan80",
	}
	vmList, templateList, err := vw.GetAllVmClient()
	if err != nil {
		panic(err)
	}
	var templateNameList []string
	var vmTemplate types.ManagedObjectReference
	for _, template := range templateList {
		fmt.Println("-----", template.Name)
		templateNameList = append(templateNameList, template.Name)
		if template.Name == cloneData.TempName {
			vmTemplate = template.VM
		}
	}
	if !IsContain(templateNameList, cloneData.TempName) {
		fmt.Fprintf(os.Stderr, "模版不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	dataCenterList, err := vw.GetAllDatacenter()
	if err != nil {
		panic(err)
	}
	var datacenterID, datacenterName string
	for _, datacenter := range dataCenterList {
		if datacenter.Name == cloneData.Datacenter {
			datacenterID = datacenter.Datacenter.Value
			datacenterName = datacenter.Name
		}
	}
	// clusterList2, err := vw.GetAllCluster()
	// if err != nil {
	//	panic(err)
	// }
	// //var clusterID, clusterName string
	// for _, cluster := range clusterList2 {
	//	fmt.Println("ccccccluster--", cluster.Cluster.Value, cluster.Name)
	//	//if cluster.Name == cloneData.Cluster {
	//	//	clusterID = cluster.Cluster.Value
	//	//	clusterName = cluster.Name
	//	//}
	// }
	if datacenterName == "" {
		fmt.Fprintf(os.Stderr, "数据中心不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	hostList, err := vw.GetAllHost()
	if err != nil {
		panic(err)
	}
	var hostName string
	//
	var hostRef types.ManagedObjectReference
	for _, host := range hostList {
		if host.Name == cloneData.Host {
			hostName = host.Name
			hostRef = host.HostSelf
		}
	}
	if hostName == "" {
		fmt.Fprintf(os.Stderr, "主机不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	resourceList, err := vw.GetAllResourcePool()
	if err != nil {
		panic(err)
	}
	var resourceStr, resourceID string
	var poolRef types.ManagedObjectReference
	for _, resource := range resourceList {
		fmt.Println("resource---", resource.Name, resource.ResourcePool.Value)
		if resource.Name == cloneData.Resources {
			resourceStr = resource.Name
			resourceID = resource.ResourcePool.Value
			poolRef = resource.Resource
		}
	}
	if resourceStr == "" {
		fmt.Fprintf(os.Stderr, "资源池不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	fmt.Println("ResourceID", resourceID)
	datastoreList, err := vw.GetAllDatastore()
	if err != nil {
		panic(err)
	}
	var datastoreID, datastoreStr string
	var datastoreRef types.ManagedObjectReference
	for _, datastore := range datastoreList {
		if datastore.Name == cloneData.Storage {
			datastoreID = datastore.Datastore.Value
			datastoreStr = datastore.Name
			datastoreRef = datastore.DatastoreSelf
		}
	}
	if datastoreStr == "" {
		fmt.Fprintf(os.Stderr, "存储中心不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	fmt.Println("DatastoreID", datastoreID)
	networkList, err := vw.GetAllNetwork()
	if err != nil {
		panic(err)
	}
	var networkID, networkStr string
	for _, network := range networkList {
		if network["Vlan"] == cloneData.Network {
			networkStr = network["Vlan"]
			networkID = network["NetworkID"]
		}
	}

	if networkStr == "" {
		fmt.Fprintf(os.Stderr, "网络不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	fmt.Println("NetworkID", networkID)
	clusterList, err := vw.GetAllCluster()
	if err != nil {
		panic(err)
	}
	var clusterID, clusterName string
	for _, cluster := range clusterList {
		fmt.Println("ccccccluster--", cluster.Cluster.Value, cluster.Name)
		if cluster.Name == cloneData.Cluster {
			clusterID = cluster.Cluster.Value
			clusterName = cluster.Name
		}
	}
	if clusterName == "" {
		fmt.Fprintf(os.Stderr, "集群不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	configSpecs := []types.BaseVirtualDeviceConfigSpec{}
	fmt.Println("ClusterID", clusterID)
	for _, vms := range vmList {
		if vms.Name == cloneData.VmName {
			fmt.Fprintf(os.Stderr, "虚机已存在，虚拟机克隆失败")
			return errors.New("虚拟机克隆失败")
		}
	}
	return
	finder := find.NewFinder(vw.client.Client)
	folders, err := finder.FolderList(vw.ctx, "*")
	var Folder *object.Folder
	for _, folder := range folders {
		if folder.InventoryPath == "/"+cloneData.Datacenter+"/vm" {
			Folder = folder
		}
	}
	fmt.Println(Folder)
	folderList, err := vw.GetFolder()
	if err != nil {
		panic(err)
	}

	// 只需要注意这个类型并且去vm中找到对应类型
	var folderRef types.ManagedObjectReference
	for _, folder := range folderList {
		if folder.Parent.Value == datacenterID && folder.Name == "vm" {
			folderRef = folder.FolderSelf
		}
	}
	fmt.Println("poolRef", poolRef)
	// 克隆的位置属性组装
	relocateSpec := types.VirtualMachineRelocateSpec{
		DeviceChange: configSpecs,
		Folder:       &folderRef,
		Pool:         &poolRef,
		Host:         &hostRef,
		Datastore:    &datastoreRef,
	}
	vmConf := &types.VirtualMachineConfigSpec{
		NumCPUs:  4,
		MemoryMB: 16 * 1024,
	}
	cloneSpec := &types.VirtualMachineCloneSpec{
		PowerOn:  false,
		Template: false,
		Location: relocateSpec,
		Config:   vmConf,
	}
	t := object.NewVirtualMachine(vw.client.Client, vmTemplate)
	newFolder := object.NewFolder(vw.client.Client, folderRef)
	fmt.Println(newFolder)
	fmt.Println(cloneData.VmName)
	fmt.Println(cloneSpec.Location)
	task, err := t.Clone(vw.ctx, newFolder, cloneData.VmName, *cloneSpec)
	if err != nil {
		panic(err)
	}
	// fmt.Println("克隆任务开始，", task.Wait(vw.ctx))
	res := task.Wait(vw.ctx)
	// 克隆完成后给vm开始适配IP
	vmNewList, _, _ := vw.GetAllVmClient()
	for _, vmNew := range vmNewList {
		if VmName == vmNew.Name {
			v := object.NewVirtualMachine(vw.client.Client, vmNew.VM)
			err := vw.setIP(v, nicAddress, netMask, nicGateway, SysHostName)
			if err != nil {

			}
			if cloneDoneVmPower == "on" {
				_, _ = v.PowerOn(vw.ctx)
			} else {
				_, _ = v.PowerOff(vw.ctx)
			}
			break
		}
	}
	return res
}

// 和CloneVM 可以整合为一个，这个是不需要集群，CloneVM是需要集群的克隆
func (vw *VmWare) CloneVMPlus(TempName, Datacenter, HostStr, Resources, Storage, VmName, SysHostName, cloneDoneVmPower, nicAddress, netMask, nicGateway string) (err error) {
	// 组装克隆的map数据
	cloneData := structs.CreateMap{
		TempName:    TempName,
		Datacenter:  Datacenter,
		Host:        HostStr,
		Resources:   Resources,
		Storage:     Storage,
		VmName:      VmName,
		SysHostName: SysHostName,
		Network:     "vlan80",
	}
	vmList, templateList, err := vw.GetAllVmClient()
	if err != nil {
		panic(err)
	}
	var templateNameList []string
	var vmTemplate types.ManagedObjectReference
	for _, template := range templateList {
		templateNameList = append(templateNameList, template.Name)
		if template.Name == cloneData.TempName {
			vmTemplate = template.VM
		}
	}
	if !IsContain(templateNameList, cloneData.TempName) {
		fmt.Fprintf(os.Stderr, "模版不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	dataCenterList, err := vw.GetAllDatacenter()
	if err != nil {
		panic(err)
	}
	var datacenterID, datacenterName string
	for _, datacenter := range dataCenterList {
		if datacenter.Name == cloneData.Datacenter {
			datacenterID = datacenter.Datacenter.Value
			datacenterName = datacenter.Name
		}
	}
	if datacenterName == "" {
		fmt.Fprintf(os.Stderr, "数据中心不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	hostList, err := vw.GetAllHost()
	if err != nil {
		panic(err)
	}
	var hostName string
	var hostRef types.ManagedObjectReference
	for _, host := range hostList {
		if host.Name == cloneData.Host {
			hostName = host.Name
			hostRef = host.HostSelf
		}
	}
	if hostName == "" {
		fmt.Fprintf(os.Stderr, "主机不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	resourceList, err := vw.GetAllResourcePool()
	if err != nil {
		panic(err)
	}
	var resourceStr, resourceID string
	var poolRef types.ManagedObjectReference
	for _, resource := range resourceList {
		if resource.Name == cloneData.Resources {
			resourceStr = resource.Name
			resourceID = resource.ResourcePool.Value
			poolRef = resource.Resource
		}
	}
	if resourceStr == "" {
		fmt.Fprintf(os.Stderr, "资源池不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	fmt.Println("ResourceID", resourceID)
	datastoreList, err := vw.GetAllDatastore()
	if err != nil {
		panic(err)
	}
	var datastoreID, datastoreStr string
	var datastoreRef types.ManagedObjectReference
	for _, datastore := range datastoreList {
		if datastore.Name == cloneData.Storage {
			datastoreID = datastore.Datastore.Value
			datastoreStr = datastore.Name
			datastoreRef = datastore.DatastoreSelf
		}
	}
	if datastoreStr == "" {
		fmt.Fprintf(os.Stderr, "存储中心不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	fmt.Println("DatastoreID", datastoreID)
	networkList, err := vw.GetAllNetwork()
	if err != nil {
		panic(err)
	}
	var networkID, networkStr string
	for _, network := range networkList {
		if network["Vlan"] == cloneData.Network {
			networkStr = network["Vlan"]
			networkID = network["NetworkID"]
		}
	}

	if networkStr == "" {
		fmt.Fprintf(os.Stderr, "网络不存在，虚拟机克隆失败")
		return errors.New("虚拟机克隆失败")
	}
	fmt.Println("NetworkID", networkID)
	// clusterList, err := vw.GetAllCluster()
	// if err != nil {
	//	panic(err)
	// }
	// var clusterID, clusterName string
	// for _, cluster := range clusterList {
	//	if cluster.Name == cloneData.Cluster {
	//		clusterID = cluster.Cluster.Value
	//		clusterName = cluster.Name
	//	}
	// }
	// if clusterName == "" {
	//	fmt.Fprintf(os.Stderr, "集群不存在，虚拟机克隆失败")
	//	return errors.New("虚拟机克隆失败")
	// }
	configSpecs := []types.BaseVirtualDeviceConfigSpec{}
	// fmt.Println("ClusterID", clusterID)
	for _, vms := range vmList {
		if vms.Name == cloneData.VmName {
			fmt.Fprintf(os.Stderr, "虚机已存在，虚拟机克隆失败")
			return errors.New("虚拟机克隆失败")
		}
	}
	finder := find.NewFinder(vw.client.Client)
	folders, err := finder.FolderList(vw.ctx, "*")
	var Folder *object.Folder
	for _, folder := range folders {
		if folder.InventoryPath == "/"+cloneData.Datacenter+"/vm" {
			Folder = folder
		}
	}
	fmt.Println(Folder)
	folderList, err := vw.GetFolder()
	if err != nil {
		panic(err)
	}
	var folderRef types.ManagedObjectReference
	for _, folder := range folderList {
		if folder.Parent.Value == datacenterID && folder.Name == "vm" {
			folderRef = folder.FolderSelf
		}
	}
	fmt.Println("poolRef", poolRef)
	relocateSpec := types.VirtualMachineRelocateSpec{
		DeviceChange: configSpecs,
		Folder:       &folderRef,
		Pool:         &poolRef,
		Host:         &hostRef,
		Datastore:    &datastoreRef,
	}
	vmConf := &types.VirtualMachineConfigSpec{
		NumCPUs:  4,
		MemoryMB: 16 * 1024,
	}
	cloneSpec := &types.VirtualMachineCloneSpec{
		PowerOn:  false,
		Template: false,
		Location: relocateSpec,
		Config:   vmConf,
	}
	t := object.NewVirtualMachine(vw.client.Client, vmTemplate)
	newFolder := object.NewFolder(vw.client.Client, folderRef)
	fmt.Println(newFolder)
	fmt.Println(cloneData.VmName)
	fmt.Println(cloneSpec.Location)
	task, err := t.Clone(vw.ctx, newFolder, cloneData.VmName, *cloneSpec)
	if err != nil {
		panic(err)
	}
	// fmt.Println("克隆任务开始，", task.Wait(vw.ctx))
	res := task.Wait(vw.ctx)
	vmNewList, _, _ := vw.GetAllVmClient()
	for _, vmNew := range vmNewList {
		if VmName == vmNew.Name {
			v := object.NewVirtualMachine(vw.client.Client, vmNew.VM)
			err := vw.setIP(v, nicAddress, netMask, nicGateway, SysHostName)
			if err != nil {

			}
			if cloneDoneVmPower == "on" {
				_, _ = v.PowerOn(vw.ctx)
			} else {
				_, _ = v.PowerOff(vw.ctx)
			}
			break
		}
	}
	return res
}

func (vw *VmWare) setIP(vm *object.VirtualMachine, nicAddress, netMask, nicGateway, SysHostName string) error {
	// 注意有多少个网卡才能加多少个IP
	if strings.Contains(nicAddress, ",") {
		nicAddressList := strings.Split(nicAddress, ",")
		netMaskList := strings.Split(netMask, ",")
		nicGatewayList := strings.Split(nicGateway, ",")
		var nicSetMapList []types.CustomizationAdapterMapping
		// 设置IP
		for index, ipaddress := range nicAddressList {
			ipAddr := IpAddr{
				ip:      ipaddress,
				netmask: netMaskList[index],
				gateway: nicGatewayList[index],
			}
			cam := types.CustomizationAdapterMapping{
				Adapter: types.CustomizationIPSettings{
					Ip:         &types.CustomizationFixedIp{IpAddress: ipAddr.ip},
					SubnetMask: ipAddr.netmask,
					Gateway:    []string{ipAddr.gateway},
				},
			}
			nicSetMapList = append(nicSetMapList, cam)
		}
		customSpec := types.CustomizationSpec{
			NicSettingMap: nicSetMapList,
			Identity:      &types.CustomizationLinuxPrep{HostName: &types.CustomizationFixedName{Name: SysHostName}},
		}
		task, err := vm.Customize(vw.ctx, customSpec)
		if err != nil {
			return err
		}
		return task.Wait(vw.ctx)
	} else {
		ipAddr := IpAddr{
			ip:       nicAddress,
			netmask:  netMask,
			gateway:  nicGateway,
			hostname: SysHostName,
		}
		cam := types.CustomizationAdapterMapping{
			Adapter: types.CustomizationIPSettings{
				Ip:         &types.CustomizationFixedIp{IpAddress: ipAddr.ip},
				SubnetMask: ipAddr.netmask,
				Gateway:    []string{ipAddr.gateway},
			},
		}
		customSpec := types.CustomizationSpec{
			NicSettingMap: []types.CustomizationAdapterMapping{cam},
			Identity:      &types.CustomizationLinuxPrep{HostName: &types.CustomizationFixedName{Name: ipAddr.hostname}},
		}
		task, err := vm.Customize(vw.ctx, customSpec)
		if err != nil {
			return err
		}
		return task.Wait(vw.ctx)
	}
}

type IpAddr struct {
	ip       string
	netmask  string
	gateway  string
	hostname string
}

func (vw *VmWare) MigrateVM() {
	migrateData := "测试虚机"
	v, err := vw.getBase("VirtualMachine")
	if err != nil {
		panic(err)
	}
	defer v.Destroy(vw.ctx)
	var vms []mo.VirtualMachine
	err = v.Retrieve(vw.ctx, []string{"VirtualMachine"}, []string{"summary"}, &vms)
	if err != nil {
		panic(err)
	}
	// 得到虚拟机在vm中的一个自身ID对象
	var vmTarget types.ManagedObjectReference
	for _, vm := range vms {
		if vm.Summary.Config.Name == migrateData {
			vmTarget = vm.Self
		}
	}
	resourceList, err := vw.GetAllResourcePool()
	if err != nil {
		panic(err)
	}
	var resourceStr, resourceID string
	var poolRef types.ManagedObjectReference
	for _, resource := range resourceList {
		if resource.Name == "" {
			resourceStr = resource.Name
			resourceID = resource.ResourcePool.Value
			poolRef = resource.Resource
		}
	}
	if resourceStr == "" {
		fmt.Fprintf(os.Stderr, "资源池不存在，虚拟机迁移失败")
		return
	}
	fmt.Println("ResourceID", resourceID)
	hostList, err := vw.GetAllHost()
	if err != nil {
		panic(err)
	}
	var hostName string
	var hostRef types.ManagedObjectReference
	for _, host := range hostList {
		if host.Name == "192.168.100.201" {
			hostName = host.Name
			hostRef = host.HostSelf
		}
	}
	if hostName == "" {
		fmt.Fprintf(os.Stderr, "主机不存在，虚拟机迁移失败")
		return
	}
	// 生成一个可以迁移的虚拟机对象
	t := object.NewVirtualMachine(vw.client.Client, vmTarget)
	pool := object.NewResourcePool(vw.client.Client, poolRef)
	host := object.NewHostSystem(vw.client.Client, hostRef)
	// var priority types.VirtualMachineMovePriority
	// var state types.VirtualMachinePowerState
	task, err := t.Migrate(vw.ctx, pool, host, "defaultPriority", "poweredOff")
	if err != nil {
		panic(err)
	}
	fmt.Println("虚拟机迁移中......")
	_ = task.Wait(vw.ctx)
	fmt.Println("虚拟机迁移完成.....")
}

func (vw *VmWare) DestroyVM() {
	destroyData := "测试虚机"
	v, err := vw.getBase("VirtualMachine")
	if err != nil {
		panic(err)
	}
	defer v.Destroy(vw.ctx)
	var vms []mo.VirtualMachine
	err = v.Retrieve(vw.ctx, []string{"VirtualMachine"}, []string{"summary"}, &vms)
	if err != nil {
		panic(err)
	}
	var vmTarget types.ManagedObjectReference
	for _, vm := range vms {
		if vm.Summary.Config.Name == destroyData {
			vmTarget = vm.Self
		}
	}
	vmObj := object.NewVirtualMachine(vw.client.Client, vmTarget)
	task, err := vmObj.PowerOff(vw.ctx)
	if err != nil {
		panic(err)
	}
	_ = task.Wait(vw.ctx)
	task, err = vmObj.Destroy(vw.ctx)
	if err != nil {
		panic(err)
	}
	_ = task.Wait(vw.ctx)
	fmt.Fprintf(os.Stderr, "%s 此虚拟机销毁成功", destroyData)
}

func (vw *VmWare) GetSourceData() (resultSource structs.SourceInfo) {
	datastoreList, err := vw.GetAllDatastore()
	Ktb := 1024 * 1024 * 1024 * 1024
	if err != nil {
		panic(err)
	}
	var totalSpace, freeSpace, useSpace int
	for _, datastore := range datastoreList {
		totalSpace = totalSpace + int(datastore.Capacity)
		freeSpace = freeSpace + int(datastore.FreeSpace)
	}
	useSpace = totalSpace - freeSpace
	totalSpaceValue := float64(totalSpace) / float64(Ktb)
	resultSource.TotalSpace = fmt.Sprintf("%.2f", totalSpaceValue)
	freeSpaceValue := float64(freeSpace) / float64(Ktb)
	resultSource.FreeSpace = fmt.Sprintf("%.2f", freeSpaceValue)
	useSpaceValue := float64(useSpace) / float64(Ktb)
	resultSource.UseSpace = fmt.Sprintf("%.2f", useSpaceValue)
	hostList, err := vw.GetAllHost()
	if err != nil {
		panic(err)
	}
	resultSource.HostTotal = strconv.Itoa(len(hostList))
	var totalCPU, freeCPU, useCPU int
	var totalMem, freeMem, useMem int
	var totalConnHost, totalDisConnHost, totalMaintail int
	var ManagementServerIp string
	for _, host := range hostList {
		totalCPU = totalCPU + int(host.TotalCPU)
		totalMem = totalMem + int(host.TotalMemory)
		freeCPU = freeCPU + int(host.FreeCPU)
		freeMem = freeMem + int(host.FreeMemory)
		ManagementServerIp = host.ManagementServerIp
		if host.PowerState == "poweredOn" {
			totalConnHost += 1
		} else if host.PowerState == "poweredOff" {
			totalDisConnHost += 1
		}
	}
	resultSource.ManagementServerIp = ManagementServerIp
	useCPU = totalCPU - freeCPU
	useMem = totalMem - freeMem
	totalMaintail = len(hostList) - totalConnHost - totalDisConnHost
	resultSource.ConnTotal = strconv.Itoa(totalConnHost)
	resultSource.DisconnTotal = strconv.Itoa(totalConnHost)
	resultSource.MaintainTotal = strconv.Itoa(totalMaintail)
	totalCPUValue := float64(totalCPU) / float64(1000)
	resultSource.TotalCpu = fmt.Sprintf("%.2f", totalCPUValue)
	freeCPUValue := float64(freeCPU) / float64(1000)
	resultSource.FreeCpu = fmt.Sprintf("%.2f", freeCPUValue)
	useCPUValue := float64(useCPU) / float64(1000)
	resultSource.UseCpu = fmt.Sprintf("%.2f", useCPUValue)
	totalMemValue := float64(totalMem) / float64(1024*1024*1024)
	resultSource.TotalMem = fmt.Sprintf("%.2f", totalMemValue)
	freeMemValue := float64(freeMem) / float64(1024*1024*1024)
	resultSource.FreeMem = fmt.Sprintf("%.2f", freeMemValue)
	useMemValue := float64(useMem) / float64(1024*1024*1024)
	resultSource.UseMem = fmt.Sprintf("%.2f", useMemValue)
	vmList, _, _ := vw.GetAllVmClient()
	// fmt.Println(len(vmList), 11111)
	resultSource.VmTotal = strconv.Itoa(len(vmList))
	return
}

func (vw *VmWare) GetVMInterface() (interfaces [][]map[string]structs.InterfaceVM, err error) {
	fmt.Println("iiiiiiii")
	v, err := vw.getBase("VirtualMachine")
	if err != nil {
		return nil, err
	}
	fmt.Println("3333333")
	defer v.Destroy(vw.ctx)
	var vms []mo.VirtualMachine
	err = v.Retrieve(vw.ctx, []string{"VirtualMachine"}, []string{"guest", "summary"}, &vms)
	if err != nil {
		fmt.Println("55555", err)
		return nil, err
	}
	fmt.Println("444444")
	for _, vm := range vms {
		// if vm.Summary.Config.Name == "测试机器t6" {
		//	s, _ := json.Marshal(vm)
		//	fmt.Println(string(s))
		//	break
		// }
		fmt.Println("2222222", vm.Summary.Config.Template)
		if !vm.Summary.Config.Template {
			num := 1
			var net []map[string]structs.InterfaceVM
			for _, vmNet := range vm.Guest.Net {
				fmt.Println("------", vmNet.MacAddress, vmNet.IpAddress)
				net = append(net, map[string]structs.InterfaceVM{
					"interface" + strconv.Itoa(num): {
						MacAddress: vmNet.MacAddress,
						IpAddress:  vmNet.IpAddress,
						Network:    vmNet.Network,
						VmName:     vm.Summary.Config.Name,
					},
				})
				num += 1
			}
			// if len(vm.Guest.Net) != 0 {
			//	s, _ := json.Marshal(vm)
			//	fmt.Println(string(s))
			//	break
			// }

			interfaces = append(interfaces, net)
		}
	}
	return
}

func (vw *VmWare) GetVMVersion() (version string, err error) {
	m := view.NewManager(vw.client.Client)
	// 注意: flags.BuildVersion 在新版本的 govmomi 中已不可用
	// 如果需要版本信息，可以从 ServiceContent.About 获取
	v, err := m.CreateContainerView(vw.ctx, vw.client.Client.ServiceContent.RootFolder, []string{}, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(v)
	// v, err := vw.getBase("HostNetworkSystem")
	// if err != nil {
	//	return "", err
	// }
	// defer v.Destroy(vw.ctx)
	// var vms []mo.HostNetworkSystem
	//
	// //pc := property.DefaultCollector(vw.clt)
	// //ns, err := flags.NewClientFlag(vw.ctx).HostNetworkSystem()
	// err = v.Retrieve(vw.ctx, []string{"HostNetworkSystem"}, []string{}, &vms)
	// if err != nil {
	//	fmt.Println(err)
	// }
	//
	// fmt.Println(vms)
	return
}

func (vw *VmWare) GetConfigData() (linuxResult map[string]map[string]string, err error) {
	v, err := vw.getBase("VirtualMachine")
	defer v.Destroy(vw.ctx)
	var vms []mo.VirtualMachine
	err = v.Retrieve(vw.ctx, []string{"VirtualMachine"}, []string{"guest", "summary"}, &vms)
	if err != nil {
		return nil, err
	}
	var VmIpAddress = make(map[string][]string)
	for _, vm := range vms {
		if !vm.Summary.Config.Template {
			for _, vmNet := range vm.Guest.Net {
				// fmt.Println("333333",vmNet.IpAddress,vm.Summary.Config.Name)
				VmIpAddress[vm.Summary.Config.Name] = vmNet.IpAddress
			}
		}
	}
	for vmName, IpList := range VmIpAddress {
		for _, ip := range IpList {
			// if _, num := service.ParseIP(ip) {
			if ip == "192.168.80.191" {
				linuxResult = cli.GetLinuxNetworkData(ip, "root", "!@AsiaLink@2020", "")
				fmt.Println(vmName)
				return
			}
			// var linuxResult map[string]map[string]string
			// fmt.Println("----",ip)
			//		linuxResult = cli.GetLinuxNetworkData(ip, "root", "!@AsiaLink@2020","")
			//		fmt.Println(vmName)
			//		return
			// }
			// }
		}
	}

	return
}

func (vw *VmWare) GetVmIpData() (VmIpAddress map[string][]string, err error) {
	v, err := vw.getBase("VirtualMachine")

	defer v.Destroy(vw.ctx)
	var vms []mo.VirtualMachine
	err = v.Retrieve(vw.ctx, []string{"VirtualMachine"}, []string{"guest", "summary"}, &vms)
	if err != nil {
		return nil, err
	}
	VmIpAddress = make(map[string][]string)
	for _, vm := range vms {

		if !vm.Summary.Config.Template {
			for _, vmNet := range vm.Guest.Net {
				VmIpAddress[vm.Summary.Config.Name] = vmNet.IpAddress
			}
		}
	}
	// for vmName, IpList := range VmIpAddress {
	//	for _, ip := range IpList {
	//		if _, num := service.ParseIP(ip); num == 4 {
	//			if ip == "192.168.80.191" {
	//				//var linuxResult map[string]map[string]string
	//				//linuxResult = cli.GetLinuxNetworkData("192.168.80.191", "root", "!@AsiaLink@2020")
	//				fmt.Println(vmName)
	//				return
	//			}
	//		}
	//	}
	// }

	return
}
