package ibm

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

type IBM struct{}

func (s *IBM) GofishClient(remote *structs.L2DeviceRemoteInfo) *mygofish.HardCollect {
	server := RedfishBase.NormalGofishClient(remote)
	return server
}

func (s *IBM) gofishcpuV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishcpuV1Collect(remote, taskConfig, server)
}

func (s *IBM) gofishmemV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishmemV1Collect(remote, taskConfig, server)
}

func (s *IBM) gofishdiskV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishdiskV1Collect(remote, taskConfig, server)
}

func (s *IBM) gofishRedfishVersionV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishRedfishVersionV1Collect(remote, taskConfig, server)
}
func (s *IBM) gofishNetworkInterfaceV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkInterfaceV1Collect(remote, taskConfig, server)
}

func (s *IBM) gofishPowerV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerV1Collect(remote, taskConfig, server)
}
func (s *IBM) gofishNetworkV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkV1Collect(remote, taskConfig, server)
}

func (s *IBM) redfishNetWorkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetWorkV1Collect(c)
}

func (s *IBM) gofishbaseinfoV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishbaseinfoV1Collect(remote, taskConfig, server)
}
func (s *IBM) RedfishClient(remote *structs.L2DeviceRemoteInfo) (*v2.Client, error) {
	// red = redfish.NewRedFish()
	// _, err = red.RedfishCollect(remote.Ip, remote.Username, remote.Password, remote.Platform)
	// return red, err
	RedfishBase.NormalRedfishClient(remote)
	return RedfishBase.NormalRedfishClient(remote)
}

func (s *IBM) redfishCpuV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishCpuV1Collect(c)
}

func (s *IBM) redfishMEMV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishMEMV1Collect(c)
}

func (s *IBM) redfishBaseInfoV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBaseInfoV1Collect(c)
}

func (s *IBM) redfishVersionV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishVersionV1Collect(c)
}

func (s *IBM) redfishBMCV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBMCV1Collect(c)
}

func (s *IBM) gofishBMCV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishBMCV1Collect(remote, taskConfig, server)
}

func (s *IBM) redfishNetworkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetworkV1Collect(c)
}
func (s *IBM) redfishPowerV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerV1Collect(c)
}
func (s *IBM) redfishDiskV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishDiskV1Collect(c)
}
func (s *IBM) SnmpGetCpuV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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
				row["manufacture"] = strings.TrimSpace(row["manufacture"])
				row["socket"] = ""
				if !t.IsContainKey("name") {
					t.Keys = append(t.Keys, "name")
				}
				if !t.IsContainKey("socket") {
					t.Keys = append(t.Keys, "socket")
				}
				return e
			}
		}())
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return table, err
}

func (s *IBM) redfishPowerControlV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerControlV1Collect(c)
}
func (s *IBM) gofishPowerControlV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerControlV1Collect(remote, taskConfig, server)
}
func (s *IBM) SnmpGetMEMV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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
func (s *IBM) SnmpGetBaseInfoV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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
				return e
			}
		}())
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return table, err
}
func (s *IBM) SnmpGetREDFISHVERSIONV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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
func (s *IBM) SnmpGetNETWORKMANAGERV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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
func (s *IBM) SnmpGetDISKV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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
			func() f {
				return func(t *clitask.Table, index string, row map[string]string) (e error) {
					row["name"] = "DISK" + fmt.Sprintf("%d", cast.ToInt(index)+1)
					row["serialNumber"] = strings.TrimSpace(row["serialNumber"])
					row["manufacture"] = strings.TrimSpace(row["manufacture"])
					row["protocol"] = ""
					if !t.IsContainKey("protocol") {
						t.Keys = append(t.Keys, "protocol")
					}
					if !t.IsContainKey("partNumber") {
						t.Keys = append(t.Keys, "partNumber")
					}
					return e
				}
			}())
	}
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return nt, err
}
func (s *IBM) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "IBM_GOFISH_CPUV1":
		fmt.Println("=======5555")
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishcpuV1Collect(remote, taskConfig, server)

		fmt.Println("===this is from ibm cpu v1: ", remote)
	case "IBM_REDFISH_CPUV1":
		fmt.Println("4444")
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishCpuV1Collect(server)
			fmt.Println("===eerr", err)
		}
		fmt.Println("this is from ibm cpu v2: ", remote)
	case "IBM_SNMP_CPUV1":
		result, err = s.SnmpGetCpuV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp cpuv1", result)
		} else {
			fmt.Println("get cpu err:", err)
		}
		fmt.Println("===this is from ibm cpu v1: ", remote)
	case "IBM_SSH_CPUV1":
		fmt.Println("this is from ibm cpu v3: ", remote)
	case "IBM_GOFISH_MEMV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishmemV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from ibm gofish mem v1: ", remote)
	case "IBM_REDFISH_MEMV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishMEMV1Collect(server)
		} else {
			fmt.Println("======mem err", err)
		}
		fmt.Println("===this is from ibm redfish mem v1: ", remote)
	case "IBM_SNMP_MEMV1":
		result, err = s.SnmpGetMEMV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp cpuv1", result)
		} else {
			fmt.Println("get mem err:", err)
		}
		fmt.Println("===this is from IBM mem v1: ", remote)
	case "IBM_SNMP_DISKV1":
		fmt.Println("=======567")
		result, err = s.SnmpGetDISKV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp disk1", result)
		} else {
			fmt.Println("get disk err:", err)
		}
		fmt.Println("===this is from IBM disk v1: ", remote)
	case "IBM_GOFISH_DISKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishdiskV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from ibm gofish disk v1: ", remote)
	case "IBM_REDFISH_DISKV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishDiskV1Collect(server)
		} else {
			fmt.Println("====client err", err)
		}
		fmt.Println("===this is from ibm redfish disk v1: ", remote)
	case "IBM_GOFISH_BASEINFOV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishbaseinfoV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from ibm gofish baseinfo v1: ", remote)
	case "IBM_REDFISH_BASEINFOV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBaseInfoV1Collect(server)
		}
		fmt.Println("===this is from ibm redfish baseinfo v1: ", remote)
	case "IBM_SNMP_BASEINFOV1":
		fmt.Println("=======567")
		result, err = s.SnmpGetBaseInfoV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp baseinfo", result)
		} else {
			fmt.Println("get baseinfok err:", err)
		}
		fmt.Println("===this is from IBM baseinfo v1: ", remote)
	case "IBM_GOFISH_NETWORKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from ibm gofish network v1: ", remote)
	case "IBM_REDFISH_NETWORKV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetWorkV1Collect(server)
		} else {
			fmt.Println("===err", err2)
		}
		fmt.Println("===this is from ibm redfish network v1: ", remote)
	case "IBM_GOFISH_REDFISHVERSIONV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishRedfishVersionV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from ibm gofish version v1: ", remote)
	case "IBM_REDFISH_REDFISHVERSIONV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishVersionV1Collect(server)
		}
		fmt.Println("===this is from ibm redfish version v1: ", remote)
	case "IBM_GOFISH_POWERV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from ibm gofish power v1: ", remote)
	case "IBM_REDFISH_POWERV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerV1Collect(server)
		}
		fmt.Println("===this is from ibm redfish power v1: ", remote)
	case "IBM_GOFISH_INTERFACEV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkInterfaceV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from ibm gofish networkinterface v1: ", remote)
	case "IBM_REDFISH_INTERFACEV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetworkV1Collect(server)
		} else {
			fmt.Println("====dddd", err2)
		}
		fmt.Println("===this is from ibm redfish interface v1: ", remote)
	case "IBM_SNMP_NETWORKMANAGERV1":
		fmt.Println("=======568")
		result, err = s.SnmpGetNETWORKMANAGERV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp network interface", result)
		} else {
			fmt.Println("get network err:", err)
		}
		fmt.Println("===this is from h3c network nterfacev1: ", remote)
	case "IBM_GOFISH_BMCV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishBMCV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from ibm gofish bmc v1: ", remote)
	case "IBM_REDFISH_BMCV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBMCV1Collect(server)
		}
		fmt.Println("===this is from ibm redfish bmc v1: ", remote)
	case "IBM_SNMP_REDFISHVERSIONV1":
		fmt.Println("=======568")
		result, err = s.SnmpGetREDFISHVERSIONV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp redfishversion", result)
		} else {
			fmt.Println("get redfishversion err:", err)
		}
		fmt.Println("===this is from h3c network v1: ", remote)
	case "IBM_GOFISH_POWERCONTROLV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerControlV1Collect(remote, taskConfig, server)
	case "IBM_REDFISH_POWERCONTROLV1":
		server, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerControlV1Collect(server)
		}
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}
