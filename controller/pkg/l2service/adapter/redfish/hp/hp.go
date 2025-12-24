package hp

import (
	"fmt"
	"strings"

	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"

	RedfishBase "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish"
	"github.com/influxdata/telegraf/controller/pkg/structs"

	"github.com/netxops/utils/mygofish"
	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	"github.com/spf13/cast"
)

type Hp struct{}

func (s *Hp) GofishClient(remote *structs.L2DeviceRemoteInfo) *mygofish.HardCollect {
	server := RedfishBase.NormalGofishClient(remote)
	return server
}

func (s *Hp) gofishcpuV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishcpuV1Collect(remote, taskConfig, server)
}

func (s *Hp) gofishmemV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishmemV1Collect(remote, taskConfig, server)
}

func (s *Hp) gofishdiskV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishdiskV1Collect(remote, taskConfig, server)
}

func (s *Hp) gofishRedfishVersionV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishRedfishVersionV1Collect(remote, taskConfig, server)
}
func (s *Hp) gofishNetworkInterfaceV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkInterfaceV1Collect(remote, taskConfig, server)
}

func (s *Hp) gofishPowerControlV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerControlV1Collect(remote, taskConfig, server)
}
func (s *Hp) gofishPowerV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerV1Collect(remote, taskConfig, server)
}
func (s *Hp) gofishNetworkV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkV1Collect(remote, taskConfig, server)
}

func (s *Hp) redfishNetWorkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetWorkV1Collect(c)
}

func (s *Hp) gofishbaseinfoV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishbaseinfoV1Collect(remote, taskConfig, server)
}
func (s *Hp) RedfishClient(remote *structs.L2DeviceRemoteInfo) (*v2.Client, error) {
	return RedfishBase.NormalRedfishClient(remote)
}

func (s *Hp) redfishCpuV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishCpuV1Collect(c)
}

func (s *Hp) redfishMEMV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishMEMV1Collect(c)
}

func (s *Hp) redfishBaseInfoV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBaseInfoV1Collect(c)
}

func (s *Hp) redfishVersionV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishVersionV1Collect(c)
}

func (s *Hp) redfishBMCV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBMCV1Collect(c)
}

func (s *Hp) gofishBMCV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishBMCV1Collect(remote, taskConfig, server)
}

func (s *Hp) redfishNetworkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetworkV1Collect(c)
}

func (s *Hp) redfishPowerControlV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerControlV1Collect(c)
}

func (s *Hp) redfishPowerV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerV1Collect(c)
}
func (s *Hp) redfishDiskV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishDiskV1Collect(c)
}

func (s *Hp) SnmpGetCpuV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	type f func(*clitask.Table, string, map[string]string) error
	table, err := RedfishBase.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	table.ForEach(
		func() f {
			return func(t *clitask.Table, index string, row map[string]string) (e error) {
				row["name"] = "CPU" + fmt.Sprintf("%d", cast.ToInt(index)+1)
				if row["structs"] != "" {
					splitManufacture := strings.Split(row["structs"], " ")
					if len(splitManufacture) >= 1 {
						row["manufacture"] = strings.Split(row["structs"], " ")[0]
					}
				}
				row["socket"] = ""
				if !t.IsContainKey("name") {
					t.Keys = append(t.Keys, "name")
				}
				if !t.IsContainKey("socket") {
					t.Keys = append(t.Keys, "socket")
				}
				if !t.IsContainKey("manufacture") {
					t.Keys = append(t.Keys, "manufacture")
				}
				return e
			}
		}())
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return table, err
}

func (s *Hp) SnmpGetMEMV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	type f func(*clitask.Table, string, map[string]string) error
	table, err := RedfishBase.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	nt := table.Grep(func(table *clitask.Table, index string, row map[string]string) bool {
		size := RedfishBase.FilterDisk(row["cacheSizeMiB"])
		if size == "" && row["manufacture"] == "" {
			return false
		}
		return true
	})
	if nt != nil && !nt.IsEmpty() {
		nt.ForEach(
			func() f {
				return func(t *clitask.Table, index string, row map[string]string) (e error) {
					row["manufacture"] = strings.TrimSpace(row["manufacture"])
					row["memoryDeviceType"] = ""
					if !t.IsContainKey("memoryDeviceType") {
						t.Keys = append(t.Keys, "memoryDeviceType")
					}
					row["serialNumber"] = ""
					if !t.IsContainKey("serialNumber") {
						t.Keys = append(t.Keys, "serialNumber")
					}
					return e
				}
			}())
	}
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return nt, err
}

func (s *Hp) SnmpGetDISKV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	type f func(*clitask.Table, string, map[string]string) error
	table, err := RedfishBase.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	nt := table.Grep(func(table *clitask.Table, index string, row map[string]string) bool {
		disk := RedfishBase.FilterDisk(row["capacityBytes"])
		if disk == "" && row["manufacture"] == "" {
			return false
		}
		return true
	})
	if nt != nil && !nt.IsEmpty() {
		nt.ForEach(
			func(t *clitask.Table, index string, row map[string]string) (e error) {
				row["name"] = "DISK" + fmt.Sprintf("%d", cast.ToInt(index)+1)
				row["serialNumber"] = strings.TrimSpace(row["serialNumber"])
				row["manufacture"] = ""
				row["protocol"] = ""
				row["partNumber"] = ""
				row["manufacture"] = strings.TrimSpace(row["manufacture"])
				if !t.IsContainKey("protocol") {
					t.Keys = append(t.Keys, "protocol")
				}
				if !t.IsContainKey("partNumber") {
					t.Keys = append(t.Keys, "partNumber")
				}
				if !t.IsContainKey("manufacture") {
					t.Keys = append(t.Keys, "manufacture")
				}
				return e
			})
	}
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return nt, err
}

func (s *Hp) SnmpGetNETWORKMANAGERV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	type f func(*clitask.Table, string, map[string]string) error
	table, err := RedfishBase.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	table.ForEach(
		func() f {
			return func(t *clitask.Table, index string, row map[string]string) (e error) {
				row["name"] = "NETWORK" + fmt.Sprintf("%d", cast.ToInt(index)+1)
				// row["serialNumber"] = strings.TrimSpace(row["serialNumber"])
				// row["protocol"] = ""
				// if !t.IsContainKey("protocol") {
				//	t.Keys = append(t.Keys, "protocol")
				// }
				// if !t.IsContainKey("partNumber") {
				//	t.Keys = append(t.Keys, "partNumber")
				// }
				return e
			}
		}())
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return table, err
}

func (s *Hp) SnmpGetBaseInfoV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	type f func(*clitask.Table, string, map[string]string) error
	table, err := RedfishBase.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	table.ForEach(
		func() f {
			return func(t *clitask.Table, index string, row map[string]string) (e error) {
				row["serialNumber"] = strings.TrimSpace(row["serialNumber"])
				// row["serialNumber"] = strings.TrimSpace(row["serialNumber"])
				// row["protocol"] = ""
				// if !t.IsContainKey("protocol") {
				//	t.Keys = append(t.Keys, "protocol")
				// }
				// if !t.IsContainKey("partNumber") {
				//	t.Keys = append(t.Keys, "partNumber")
				// }
				return e
			}
		}())
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return table, err
}
func (s *Hp) SnmpGetNETWORKADAPTERV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	type f func(*clitask.Table, string, map[string]string) error
	table, err := RedfishBase.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	table.ForEach(
		func() f {
			return func(t *clitask.Table, index string, row map[string]string) (e error) {
				row["name"] = "NETWORK" + fmt.Sprintf("%d", cast.ToInt(index)+1)
				// row["serialNumber"] = strings.TrimSpace(row["serialNumber"])
				// row["protocol"] = ""
				// if !t.IsContainKey("protocol") {
				//	t.Keys = append(t.Keys, "protocol")
				// }
				// if !t.IsContainKey("partNumber") {
				//	t.Keys = append(t.Keys, "partNumber")
				// }
				return e
			}
		}())
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return table, err
}

func (s *Hp) SnmpGetREDFISHVERSIONV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	type f func(*clitask.Table, string, map[string]string) error
	table, err := RedfishBase.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	table.ForEach(
		func() f {
			return func(t *clitask.Table, index string, row map[string]string) (e error) {
				row["version"] = strings.Split(row["version"], " ")[0]
				// row["serialNumber"] = strings.TrimSpace(row["serialNumber"])
				// row["protocol"] = ""
				// if !t.IsContainKey("protocol") {
				//	t.Keys = append(t.Keys, "protocol")
				// }
				// if !t.IsContainKey("partNumber") {
				//	t.Keys = append(t.Keys, "partNumber")
				// }
				return e
			}
		}())
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return table, err
}
func (s *Hp) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "HP_GOFISH_CPUV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishcpuV1Collect(remote, taskConfig, server)

		fmt.Println("===this is from hp cpu v1: ", remote)
	case "HP_REDFISH_CPUV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishCpuV1Collect(client)
			fmt.Println("===eerr", err)
		}
		fmt.Println("this is from hp cpu v2: ", remote)
	case "HP_SNMP_CPUV1":
		result, err = s.SnmpGetCpuV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp cpuv1", result)
		} else {
			fmt.Println("get cpu err:", err)
		}
		fmt.Println("===this is from hp snmo cpu v1: ", remote)
	case "HP_GOFISH_MEMV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishmemV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish mem v1: ", remote)
	case "HP_SNMP_MEMV1":
		result, err = s.SnmpGetMEMV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get hp snmp cpuv1", result)
		} else {
			fmt.Println("get mem err:", err)
		}
		fmt.Println("===this is from h3c mem v1: ", remote)
	case "HP_REDFISH_MEMV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishMEMV1Collect(client)
		} else {
			fmt.Println("======mem err", err)
		}
		fmt.Println("===this is from hp redfish mem v1: ", remote)
	case "HP_GOFISH_DISKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishdiskV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish disk v1: ", remote)
	case "HP_REDFISH_DISKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishDiskV1Collect(client)
		} else {
			fmt.Println("====client err", err)
		}
		fmt.Println("===this is from hp redfish disk v1: ", remote)
	case "HP_SNMP_DISKV1":
		result, err = s.SnmpGetDISKV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp disk1", result)
		} else {
			fmt.Println("get disk err:", err)
		}
		fmt.Println("===this is from h3c disk v1: ", remote)
	case "HP_GOFISH_BASEINFOV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishbaseinfoV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish baseinfo v1: ", remote)
	case "HP_REDFISH_BASEINFOV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBaseInfoV1Collect(client)
		}
		fmt.Println("===this is from hp redfish baseinfo v1: ", remote)
	case "HP_SNMP_BASEINFOV1":
		result, err = s.SnmpGetBaseInfoV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp baseinfo", result)
		} else {
			fmt.Println("get network err:", err)
		}
		fmt.Println("===this is from hp snmp baseinfo: ", remote)
	case "HP_GOFISH_NETWORKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish network v1: ", remote)
	case "HP_REDFISH_NETWORKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetWorkV1Collect(client)
		} else {
			fmt.Println("===err", err2)
		}
		fmt.Println("===this is from hp redfish network v1: ", remote)
	case "HP_SNMP_NETWORKMANAGERV1":
		result, err = s.SnmpGetNETWORKMANAGERV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp network interface", result)
		} else {
			fmt.Println("get network err:", err)
		}
		fmt.Println("===this is from h3c network nterfacev1: ", remote)
	case "HP_SNMP_NETWORKV1":
		result, err = s.SnmpGetNETWORKADAPTERV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp network1", result)
		} else {
			fmt.Println("get network err:", err)
		}
		fmt.Println("===this is from h3c network v1: ", remote)
	case "HP_GOFISH_REDFISHVERSIONV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishRedfishVersionV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish version v1: ", remote)
	case "HP_REDFISH_REDFISHVERSIONV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishVersionV1Collect(client)
		}
		fmt.Println("===this is from hp redfish version v1: ", remote)
	case "HP_SNMP_REDFISHVERSIONV1":
		result, err = s.SnmpGetREDFISHVERSIONV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp redfishversion", result)
		} else {
			fmt.Println("get redfishversion err:", err)
		}
		fmt.Println("===this is from h3c network v1: ", remote)
	case "HP_GOFISH_POWERV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish power v1: ", remote)
	case "HP_REDFISH_POWERV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerV1Collect(client)
		}
		fmt.Println("===this is from hp redfish power v1: ", remote)
	case "HP_GOFISH_POWERCONTROLV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerControlV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish powercontrol v1: ", remote)
	case "HP_REDFISH_POWERCONTROLV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerControlV1Collect(client)
		}
	case "HP_GOFISH_INTERFACEV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkInterfaceV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish networkinterface v1: ", remote)
	case "HP_REDFISH_INTERFACEV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetworkV1Collect(client)
		} else {
			fmt.Println("====dddd", err2)
		}
		fmt.Println("===this is from hp redfish interface v1: ", remote)
	case "HP_GOFISH_BMCV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishBMCV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from hp gofish bmc v1: ", remote)
	case "HP_REDFISH_BMCV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBMCV1Collect(client)
		}
		fmt.Println("===this is from hp redfish bmc v1: ", remote)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}
