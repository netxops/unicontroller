package chaoqing

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	RedfishBase "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish"
	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/structs/l2struct"
	"github.com/influxdata/telegraf/controller/pkg/tol"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/mygofish"
	clitask "github.com/netxops/utils/task"
)

type ChaoQing struct{}

func (s *ChaoQing) gofishcpuV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishcpuV1Collect(remote, taskConfig, server)
}

func (s *ChaoQing) gofishmemV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishmemV1Collect(remote, taskConfig, server)
}

func (s *ChaoQing) gofishdiskV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishdiskV1Collect(remote, taskConfig, server)
}

func (s *ChaoQing) gofishbaseinfoV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishbaseinfoV1Collect(remote, taskConfig, server)
}

func (s *ChaoQing) gofishRedfishVersionV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishRedfishVersionV1Collect(remote, taskConfig, server)
}
func (s *ChaoQing) gofishNetworkInterfaceV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkInterfaceV1Collect(remote, taskConfig, server)
}

func (s *ChaoQing) gofishPowerControlV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerControlV1Collect(remote, taskConfig, server)
}
func (s *ChaoQing) gofishPowerV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerV1Collect(remote, taskConfig, server)
}
func (s *ChaoQing) gofishNetworkV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkV1Collect(remote, taskConfig, server)
}

func (s *ChaoQing) gofishBMCV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishBMCV1Collect(remote, taskConfig, server)
}

func (s *ChaoQing) GofishClient(remote *structs.L2DeviceRemoteInfo) *mygofish.HardCollect {
	server := RedfishBase.NormalGofishClient(remote)
	return server
}

func (s *ChaoQing) redfishNetWorkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetWorkV1Collect(c)
}

func (s *ChaoQing) RedfishClient(remote *structs.L2DeviceRemoteInfo) (c *v2.Client, err error) {
	return RedfishBase.NormalRedfishClient(remote)
}

func (s *ChaoQing) redfishCpuV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishCpuV1Collect(c)
}

func (s *ChaoQing) redfishMEMV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishMEMV1Collect(c)
}

func (s *ChaoQing) redfishBaseInfoV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBaseInfoV1Collect(c)
}

func (s *ChaoQing) redfishVersionV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishVersionV1Collect(c)
}

func (s *ChaoQing) redfishBMCV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBMCV1Collect(c)
}

func (s *ChaoQing) redfishNetworkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetworkV1Collect(c)
}

func (s *ChaoQing) redfishPowerControlV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerControlV1Collect(c)
}

func (s *ChaoQing) redfishPowerV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerV1Collect(c)
}
func (s *ChaoQing) redfishDiskV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishDiskV1Collect(c)
}

func (s *ChaoQing) sshGPUV1(remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
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
func (s *ChaoQing) sshNetworkV1(remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
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
func (s *ChaoQing) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "CHAOQING_GOFISH_CPUV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishcpuV1Collect(remote, taskConfig, server)
		// result.Pretty()
		fmt.Println("===this is from dell cpu v1: ", remote)
	case "CHAOQING_REDFISH_CPUV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishCpuV1Collect(client)
			fmt.Println("===eerr", err)
		}
		fmt.Println("this is from dell cpu v2: ", remote)
	case "CHAOQING_SSH_CPUV1":
		fmt.Println("this is from dell cpu v3: ", remote)
	case "CHAOQING_GOFISH_MEMV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishmemV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish mem v1: ", remote)
	case "CHAOQING_REDFISH_MEMV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishMEMV1Collect(client)
		} else {
			fmt.Println("======mem err", err)
		}
		fmt.Println("===this is from dell redfish mem v1: ", remote)
	case "CHAOQING_GOFISH_DISKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishdiskV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish disk v1: ", remote)
	case "CHAOQING_REDFISH_DISKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishDiskV1Collect(client)
		} else {
			fmt.Println("====client err", err)
		}
		fmt.Println("===this is from dell redfish disk v1: ", remote)
	case "CHAOQING_GOFISH_BASEINFOV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishbaseinfoV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish baseinfo v1: ", remote)
	case "CHAOQING_REDFISH_BASEINFOV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBaseInfoV1Collect(client)
		}
		fmt.Println("===this is from dell redfish baseinfo v1: ", remote)

	case "CHAOQING_GOFISH_NETWORKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish network v1: ", remote)
	case "CHAOQING_REDFISH_NETWORKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetWorkV1Collect(client)
		} else {
			fmt.Println("===err", err2)
		}
		fmt.Println("===this is from dell redfish network v1: ", remote)
	case "CHAOQING_SSH_NETWORKV1":
		result, err = s.sshNetworkV1(remote)
		fmt.Println("this is from chaoqing ssh NETWORKV1 v1: ", remote)
	case "CHAOQING_GOFISH_REDFISHVERSIONV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishRedfishVersionV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish version v1: ", remote)
	case "CHAOQING_REDFISH_REDFISHVERSIONV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishVersionV1Collect(client)
		}
		fmt.Println("===this is from dell redfish version v1: ", remote)
	case "CHAOQING_GOFISH_POWERV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish power v1: ", remote)
	case "CHAOQING_REDFISH_POWERV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerV1Collect(client)
		}
		fmt.Println("===this is from dell redfish power v1: ", remote)
	case "CHAOQING_GOFISH_POWERCONTROLV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerControlV1Collect(remote, taskConfig, server)
	case "CHAOQING_REDFISH_POWERCONTROLV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerControlV1Collect(client)
		}
	case "CHAOQING_GOFISH_INTERFACEV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkInterfaceV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish networkinterface v1: ", remote)
	case "CHAOQING_REDFISH_INTERFACEV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetworkV1Collect(client)
		} else {
			fmt.Println("====dddd", err2)
		}
		fmt.Println("===this is from dell redfish interface v1: ", remote)
	case "CHAOQING_GOFISH_BMCV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishBMCV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish bmc v1: ", remote)
	case "CHAOQING_REDFISH_BMCV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBMCV1Collect(client)
		}
		fmt.Println("===this is from dell redfish bmc v1: ", remote)
	case "CHAOQING_SSH_GPUV1":
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
