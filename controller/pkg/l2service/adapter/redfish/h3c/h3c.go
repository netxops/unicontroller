package h3c

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"
	"github.com/influxdata/telegraf/controller/pkg/structs/l2struct"
	"github.com/influxdata/telegraf/controller/pkg/tol"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"

	RedfishBase "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish"
	"github.com/influxdata/telegraf/controller/pkg/structs"

	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	"github.com/spf13/cast"
)

type H3C struct {
}

func (s *H3C) RedfishClient(remote *structs.L2DeviceRemoteInfo) (*v2.Client, error) {
	return RedfishBase.NormalRedfishClient(remote)
}

func (s *H3C) redfishCpuV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishCpuV1Collect(c)
}
func (s *H3C) SnmpGetCpuV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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

func (s *H3C) SnmpGetMEMV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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

func (s *H3C) SnmpGetDISKV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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

func (s *H3C) SnmpGetNETWORKMANAGERV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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

func (s *H3C) IPMIGetSNV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return RedfishBase.IPMIGetSNV1(remote, taskConfig)
}

func (s *H3C) SnmpGetNETWORKADAPTERV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
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

func (s *H3C) redfishMEMV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishMEMV1Collect(c)
}

func (s *H3C) redfishBaseInfoV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBaseInfoV1Collect(c)
}
func (s *H3C) redfishNetWorkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetWorkV1Collect(c)
}
func parseNetworkInfo(text string) []map[string]string {
	networks := strings.Split(text, "*-network")
	var networkInfo []map[string]string

	for _, network := range networks {
		if network == "" {
			continue
		}
		lines := strings.Split(strings.TrimSpace(network), "\n")
		info := make(map[string]string)

		for _, line := range lines {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if parts[0] == "" {
					continue
				}
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				info[key] = value
			}
		}

		networkInfo = append(networkInfo, info)
	}

	return networkInfo
}
func (s *H3C) sshNetworkV1(remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
	}
	base.WithActionID(remote.ActionID)
	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	// var options []interface{}
	// options = append(options, "nvidia-smi --query-gpu=timestamp,name,serial,vbios_version --format=csv")
	// for index, ops := range options {
	// 	// cmd := ops.(*terminalmode.Command)
	// 	key := strings.Join(strings.Fields(ops.(string)), "_")
	// 	key = fmt.Sprintf("%s_%d", key, index+1)
	//
	// 	cmd := terminalmode.NewCommand(ops.(string), "", 3, key, "")
	// 	exec.AddCommand(cmd)
	// 	cmdList = append(cmdList, cmd)
	// }
	exec.Add("lshw -class network", "", 5, "network", "")
	exec.Id = uuid.Must(uuid.NewV4()).String()

	r := exec.Run(true)
	if r.Error() != nil {
		err = r.Error()
		return
	}
	ok, lines := r.GetResult("network")
	if !ok {
		err = fmt.Errorf("get cmd result failed, cmd=%s", "lshw -class network")
		return
	}
	// type Network struct {
	// 	Name         string `json:"name"`
	// 	Manufacture  string `json:"manufacture"`
	// 	Model        string `json:"model"`
	// 	PartNumber   string `json:"partNumber"`
	// 	SerialNumber string `json:"serialNumber"`
	// }
	result = clitask.NewEmptyTableWithKeys([]string{"name", "serialNumber", "manufacture", "model"})
	if len(lines) >= 2 {
		lines = lines[1 : len(lines)-1]
		text := strings.Join(lines, "\n")
		infoList := parseNetworkInfo(text)

		for _, v := range infoList {
			m := make(map[string]string)
			// m["name"] = v["name"]
			if strings.TrimSpace(v["logical name"]) == "" {
				continue
			}
			m["name"] = strings.TrimSpace(v["logical name"])
			m["serialNumber"] = strings.TrimSpace(v["serial"])
			m["manufacture"] = strings.TrimSpace(v["vendor"])
			m["model"] = strings.TrimSpace(v["product"])
			result.PushRow("", m, true, "")
		}
	} else {
		fmt.Println("返回网卡信息错误,内容", lines)
		return
	}
	return result, err
}
func (s *H3C) redfishVersionV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishVersionV1Collect(c)
}

func (s *H3C) redfishBMCV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBMCV1Collect(c)
}

func (s *H3C) redfishNetworkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetworkV1Collect(c)
}

func (s *H3C) redfishPowerControlV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerControlV1Collect(c)
}

func (s *H3C) redfishPowerV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerV1Collect(c)
}
func (s *H3C) redfishDiskV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishDiskV1Collect(c)
}

func (s *H3C) sshGPUV1(remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
	}
	base.WithActionID(remote.ActionID)
	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	// var options []interface{}
	// options = append(options, "nvidia-smi --query-gpu=timestamp,name,serial,vbios_version --format=csv")
	// for index, ops := range options {
	// 	// cmd := ops.(*terminalmode.Command)
	// 	key := strings.Join(strings.Fields(ops.(string)), "_")
	// 	key = fmt.Sprintf("%s_%d", key, index+1)
	//
	// 	cmd := terminalmode.NewCommand(ops.(string), "", 3, key, "")
	// 	exec.AddCommand(cmd)
	// 	cmdList = append(cmdList, cmd)
	// }
	exec.Add("nvidia-smi --query-gpu=name,uuid,serial,driver_version,vbios_version,pci.bus_id,memory.total --format=csv", "", 3, "gpu", "")
	exec.Id = uuid.Must(uuid.NewV4()).String()

	r := exec.Run(true)
	if r.Error() != nil {
		err = r.Error()
		return
	}
	ok, lines := r.GetResult("gpu")
	if !ok {
		err = fmt.Errorf("get cmd result failed, cmd=%s", "nvidia-smi --query-gpu=name,uuid,serial,driver_version,vbios_version,pci.bus_id,memory.total --format=csv")
		return
	}
	result = clitask.NewEmptyTableWithKeys([]string{
		l2struct.GPUName, l2struct.GPUSerialNumber, l2struct.GPUBusID,
		l2struct.GPUManufacture, l2struct.GPUMemoryTotal, l2struct.GPUFirmwareVersion,
		l2struct.GPUDriverVersion, l2struct.GPUUuID})
	if len(lines) >= 2 {
		lines = lines[1 : len(lines)-1]
		gpuText := strings.Join(lines, "\n")
		infoList, err := getGPUInfo(gpuText)
		if err != nil {
			fmt.Println("解析gpu信息错误", err)
			return result, err
		}
		for _, v := range infoList {
			m := make(map[string]string)
			m[l2struct.GPUName] = v["name"]
			m[l2struct.GPUSerialNumber] = strings.TrimSpace(v["serial"])
			m[l2struct.GPUFirmwareVersion] = strings.TrimSpace(v["vbios_version"])
			m[l2struct.GPUManufacture] = "Nvidia"
			m[l2struct.GPUMemoryTotal] = v["memory.total [MiB]"]
			m[l2struct.GPUDriverVersion] = strings.TrimSpace(v["driver_version"])
			m[l2struct.GPUBusID] = strings.TrimSpace(v["pci.bus_id"])
			if strings.TrimSpace(v["uuid"]) != "" {
				gpuUUIDSplit := strings.Split(strings.TrimSpace(v["uuid"]), "GPU-")
				if len(gpuUUIDSplit) > 1 {
					m[l2struct.GPUUuID] = gpuUUIDSplit[1]
				} else {
					m[l2struct.GPUUuID] = strings.TrimSpace(v["uuid"])
				}
			}
			result.PushRow("", m, true, "")
		}
	} else {
		fmt.Println("返回gpu信息错误,内容", lines)
		return
	}
	return result, err
}
func getGPUInfo(gpuText string) (result []map[string]string, err error) {
	lines := strings.Split(gpuText, "\n")
	if len(lines) == 0 {
		return result, fmt.Errorf("解析gpu信息错误")
	}
	keys := strings.Split(lines[0], ",")
	for i := 1; i < len(lines); i++ {
		values := strings.Split(lines[i], ",")
		entry := make(map[string]string)
		for j := 0; j < len(keys); j++ {
			newKey := strings.Replace(strings.TrimSpace(tol.CleanUnPrint(keys[j])), "[?2004l", "", -1)
			newValue := strings.Replace(strings.TrimSpace(tol.CleanUnPrint(values[j])), "[?2004l", "", -1)
			entry[newKey] = newValue
		}
		result = append(result, entry)
	}
	return
}

func (s *H3C) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	fmt.Println("ggggggg", taskConfig.GetMethod())
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "H3C_SNMP_CPUV1":
		result, err = s.SnmpGetCpuV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp cpuv1", result)
		} else {
			fmt.Println("get cpu err:", err)
		}
		fmt.Println("===this is from h3c cpu v1: ", remote)
	case "H3C_REDFish_CPUV1":
	//	fmt.Println("4444")
	//	server, err2 := s.RedfishClient(remote)
	//	if err2 == "" {
	//		result, err = s.redfishCpuV1Collect(remote, taskConfig, server)
	//		fmt.Println("===eerr", err)
	//	}
	//	fmt.Println("this is from h3c redfish cpu v2: ", remote)
	case "H3C_SNMP_MEMV1":
		result, err = s.SnmpGetMEMV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp cpuv1", result)
		} else {
			fmt.Println("get mem err:", err)
		}
		fmt.Println("===this is from h3c mem v1: ", remote)
	case "H3C_SNMP_DISKV1":
		fmt.Println("=======567")
		result, err = s.SnmpGetDISKV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp disk1", result)
		} else {
			fmt.Println("get disk err:", err)
		}
		fmt.Println("===this is from h3c disk v1: ", remote)
	case "H3C_SNMP_NETWORKMANAGERV1":
		fmt.Println("=======568")
		result, err = s.SnmpGetNETWORKMANAGERV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp network interface", result)
		} else {
			fmt.Println("get network err:", err)
		}
		fmt.Println("===this is from h3c network nterfacev1: ", remote)
	case "H3C_SNMP_NETWORKV1":
		fmt.Println("=======568")
		result, err = s.SnmpGetNETWORKADAPTERV1(remote, taskConfig)
		if err != nil {
			fmt.Println("======get snmp network1", result)
		} else {
			fmt.Println("get network err:", err)
		}
		fmt.Println("===this is from h3c network v1: ", remote)
	case "H3C_IPMI_BASEINFOV1":
		s.IPMIGetSNV1(remote, taskConfig)
	case "H3C_REDFISH_CPUV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishCpuV1Collect(client)
			fmt.Println("===eerr", err)
		}
		fmt.Println("this is from  cpu v1: ", remote)
	case "H3C_REDFISH_MEMV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishMEMV1Collect(client)
		} else {
			fmt.Println("======mem err", err)
		}
		fmt.Println("===this is from redfish mem v1: ", remote)
	case "H3C_REDFISH_DISKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishDiskV1Collect(client)
		} else {
			fmt.Println("====client err", err)
		}
		fmt.Println("===this is from redfish disk v1: ", remote)
	case "H3C_REDFISH_BASEINFOV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBaseInfoV1Collect(client)
		}
		fmt.Println("===this is from redfish baseinfo v1: ", remote)
	case "H3C_REDFISH_NETWORKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetWorkV1Collect(client)
		} else {
			fmt.Println("===err", err2)
		}
		fmt.Println("===this is from dell redfish network v1: ", remote)
	case "H3C_SSH_NETWORKV1":
		result, err = s.sshNetworkV1(remote)
		fmt.Println("this is from chaoqing ssh NETWORKV1 v1: ", remote)
	case "H3C_REDFISH_REDFISHVERSIONV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishVersionV1Collect(client)
		}
		fmt.Println("===this is from redfish version v1: ", remote)
	case "H3C_REDFISH_POWERV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerV1Collect(client)
		}
		fmt.Println("===this is from redfish power v1: ", remote)
	case "H3C_REDFISH_POWERCONTROLV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerControlV1Collect(client)
		}
	case "H3C_REDFISH_INTERFACEV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetworkV1Collect(client)
		} else {
			fmt.Println("====dddd", err2)
		}
		fmt.Println("===this is from redfish interface v1: ", remote)
	case "H3C_REDFISH_BMCV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBMCV1Collect(client)
		}
		fmt.Println("===this is from redfish bmc v1: ", remote)
	case "H3C_SSH_GPUV1":
		result, err = s.sshGPUV1(remote)
		fmt.Println("this is from dell gpu v3: ", remote)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}
	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}
