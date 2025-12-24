package huawei

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	RedfishBase "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish"
	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"
	"github.com/influxdata/telegraf/controller/pkg/tol"
	"github.com/netxops/cli/terminal"

	"github.com/influxdata/telegraf/controller/pkg/structs/l2struct"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminalmode"

	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	// "github.com/influxdata/telegraf/controller/pkg/l2service/temp/snmp"
)

type HuaWei struct{}

func (s *HuaWei) Arp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalArp(remote, taskConfig)
}

func (s *HuaWei) SshArp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiSshArp(remote, taskConfig)
}

func (s *HuaWei) IfTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}

	table, err := switchs.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		return table, err
	}

	exclude := []string{
		"unrouted VLAN",
	}
	t := table.Grep(func(table *clitask.Table, index string, row map[string]string) bool {
		for _, e := range exclude {
			if strings.Index(row[l2struct.IfTableName], e) == 0 {
				return false
			}
		}
		return true
	})
	return t, err
}

func (s *HuaWei) Dot1dPort(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalDot1dPort(remote, taskConfig)
}

func (s *HuaWei) Vlan(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalVlan(remote, taskConfig)
}

func (s *HuaWei) SystemName(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalSystemName(remote, taskConfig)
}

func (s *HuaWei) PortIp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalPortIp(remote, taskConfig)
}

func (s *HuaWei) MacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiMacTable(remote, taskConfig)
}

func (s *HuaWei) SshMacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiSshMacTable(remote, taskConfig)
}

func (s *HuaWei) Cdp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiCdp(remote, taskConfig)
}
func (s *HuaWei) LLdp2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWARELLdp2(remote, taskConfig)
}

func (s *HuaWei) LLdp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiSshLldp(remote, taskConfig)
}

func (s *HuaWei) SshVlan(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiSshVlan(remote, taskConfig)
}

func (s *HuaWei) Stp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiStp(remote, taskConfig)
}

func (s *HuaWei) Stp82(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiStp82(remote, taskConfig)
}

func (s *HuaWei) PortStatistics(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.PortStatistics(remote, taskConfig)
}

func (s *HuaWei) PortChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiPortChannel(remote, taskConfig)
}

func (s *HuaWei) Ipv6Neighbor(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.Ipv6Neighbor(remote, taskConfig)
}

func (s *HuaWei) config(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Config(terminalmode.HuaWei, remote, taskConfig, options...)
}
func (s *HuaWei) exec(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Exec(terminalmode.HuaWei, remote, taskConfig, options...)
}

func (s *HuaWei) execWithTime(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ExecWithTime(terminalmode.HuaWei, remote, taskConfig, remote.TimeOut, options...)
}
func (s *HuaWei) configWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ConfigWithTerminalCmd(terminalmode.HuaWei, remote, taskConfig, options...)
}

func (s *HuaWei) execWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ExecWithTerminalCmd(terminalmode.HuaWei, remote, taskConfig, options...)
}

func (s *HuaWei) version1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckVersion(terminalmode.HuaWei, remote, taskConfig, options...)
}
func (s *HuaWei) getVersionBySnmp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.SnmpGetVersion(remote, nil)
}
func (s *HuaWei) patch_version1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.PatchVersion(terminalmode.HuaWei, remote, taskConfig, options...)
}

func (s *HuaWei) reboot(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Reboot(terminalmode.HuaWei, remote, taskConfig, options...)
}

func (s *HuaWei) dir1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckDir(terminalmode.HuaWei, remote, taskConfig, options...)
}
func (s *HuaWei) portInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.HuaWeiPortInfo(remote, taskConfig)
}

func (s *HuaWei) status1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckStatus(terminalmode.HuaWei, remote, taskConfig, options...)
}

func (s *HuaWei) install1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckInstall2(terminalmode.HuaWei, remote, taskConfig, options...)
}

func (s *HuaWei) install_hotfix1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.InstallHotFix(terminalmode.HuaWei, remote, taskConfig, options...)
}
func (s *HuaWei) impact1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckImpact(terminalmode.HuaWei, remote, taskConfig, options...)
}
func (s *HuaWei) importFile(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ImportFtp(terminalmode.HuaWei, remote, taskConfig, options...)
}
func (s *HuaWei) boot1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckBoot(terminalmode.HuaWei, remote, taskConfig, options...)
}

func (s *HuaWei) RedfishClient(remote *structs.L2DeviceRemoteInfo) (*v2.Client, error) {
	return RedfishBase.NormalRedfishClient(remote)
}

func (s *HuaWei) redfishCpuV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishCpuV1Collect(c)
}
func (s *HuaWei) redfishMEMV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishMEMV1Collect(c)
}

func (s *HuaWei) redfishBaseInfoV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBaseInfoV1Collect(c)
}
func (s *HuaWei) redfishNetWorkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetWorkV1Collect(c)
}
func (s *HuaWei) redfishVersionV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishVersionV1Collect(c)
}

func (s *HuaWei) redfishBMCV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBMCV1Collect(c)
}

func (s *HuaWei) redfishNetworkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetworkV1Collect(c)
}

func (s *HuaWei) redfishPowerControlV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerControlV1Collect(c)
}

func (s *HuaWei) redfishPowerV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerV1Collect(c)
}
func (s *HuaWei) redfishDiskV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishDiskV1Collect(c)
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
func (s *HuaWei) sshNetworkV1(remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
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
func (s *HuaWei) sshGPUV1(remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
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
func (s *HuaWei) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "HUAWEI_ARP":
		result, err = s.Arp(remote, taskConfig)
	case "HUAWEI_SSHARP":
		result, err = s.SshArp(remote, taskConfig)
	case "HUAWEI_SSHARP2":
		result, err = s.SshArp(remote, taskConfig)
	case "HUAWEI_IFTABLE":
		result, err = s.IfTable(remote, taskConfig)
	case "HUAWEI_DOT1DPORT":
		result, err = s.Dot1dPort(remote, taskConfig)
	case "HUAWEI_VLAN":
		result, err = s.Vlan(remote, taskConfig)
	case "HUAWEI_SYSTEMNAME":
		result, err = s.SystemName(remote, taskConfig)
	case "HUAWEI_PORTIP":
		result, err = s.PortIp(remote, taskConfig)
	case "HUAWEI_MACTABLE":
		result, err = s.MacTable(remote, taskConfig)
	case "HUAWEI_SSHMACTABLE":
		result, err = s.SshMacTable(remote, taskConfig)
	case "HUAWEI_CDP":
		result, err = s.Cdp(remote, taskConfig)
	case "HUAWEI_LLDP2":
		result, err = s.LLdp2(remote, taskConfig)
	case "HUAWEI_LLDP":
		result, err = s.LLdp(remote, taskConfig)
	case "HUAWEI_SSHLLDP":
		result, err = s.LLdp(remote, taskConfig)
	case "HUAWEI_SSHVLAN":
		result, err = s.SshVlan(remote, taskConfig)
	case "HUAWEI_STP":
		result, err = s.Stp(remote, taskConfig)
	case "HUAWEI_STP_82":
		result, err = s.Stp82(remote, taskConfig)
	case "HUAWEI_PORTSTATISTICS":
		result, err = s.PortStatistics(remote, taskConfig)
	case "HUAWEI_PORTCHANNEL":
		result, err = s.PortChannel(remote, taskConfig)
	case "HUAWEI_IPV6NEIGHBOR":
		result, err = s.Ipv6Neighbor(remote, taskConfig)
	case "HUAWEI_CONFIG":
		result, err = s.config(remote, taskConfig, options...)
	case "HUAWEI_CONFIG_TERMINAL":
		result, err = s.configWithTerminal(remote, taskConfig, options...)
	case "HUAWEI_EXEC_TERMINAL":
		result, err = s.execWithTerminal(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_EXEC":
		result, err = s.exec(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_EXEC_WITH_TIME":
		result, err = s.execWithTime(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_SNMP_VERSION":
		result, err = s.getVersionBySnmp(remote, taskConfig, options...)
	case "HUAWEI_PORTINFO":
		result, err = s.portInfo(remote, taskConfig)
	case "HUAWEI_SWITCH_VERSION1":
		result, err = s.version1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_PATCH_VERSION1":
		result, err = s.patch_version1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_VERSION2":
		result, err = s.version1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_DIR1":
		result, err = s.dir1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_STATUS1":
		result, err = s.status1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_INSTALL1":
		result, err = s.install1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_HOTFIX1":
		result, err = s.install_hotfix1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_IMPACT1":
		result, err = s.impact1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_BOOT1":
		result, err = s.boot1(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_REBOOT":
		result, err = s.reboot(remote, taskConfig, options...)
	case "HUAWEI_SWITCH_IMPORT1":
		result, err = s.importFile(remote, taskConfig, options...)
	case "HUAWEI_REDFISH_CPUV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishCpuV1Collect(client)
			fmt.Println("===eerr", err)
		}
		fmt.Println("this is from  cpu v1: ", remote)
	case "HUAWEI_REDFISH_MEMV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishMEMV1Collect(client)
		} else {
			fmt.Println("======mem err", err)
		}
		fmt.Println("===this is from redfish mem v1: ", remote)
	case "HUAWEI_REDFISH_DISKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishDiskV1Collect(client)
		} else {
			fmt.Println("====client err", err)
		}
		fmt.Println("===this is from redfish disk v1: ", remote)
	case "HUAWEI_REDFISH_BASEINFOV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBaseInfoV1Collect(client)
		}
		fmt.Println("===this is from redfish baseinfo v1: ", remote)
	case "HUAWEI_REDFISH_NETWORKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetWorkV1Collect(client)
		} else {
			fmt.Println("===err", err2)
		}
		fmt.Println("===this is from dell redfish network v1: ", remote)
	case "HUAWEI_SSH_NETWORKV1":
		result, err = s.sshNetworkV1(remote)
		fmt.Println("this is from chaoqing ssh NETWORKV1 v1: ", remote)
	case "HUAWEI_REDFISH_REDFISHVERSIONV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishVersionV1Collect(client)
		}
		fmt.Println("===this is from redfish version v1: ", remote)
	case "HUAWEI_REDFISH_POWERV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerV1Collect(client)
		}
		fmt.Println("===this is from redfish power v1: ", remote)
	case "HUAWEI_REDFISH_POWERCONTROLV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerControlV1Collect(client)
		}
	case "HUAWEI_REDFISH_INTERFACEV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetworkV1Collect(client)
		} else {
			fmt.Println("====dddd", err2)
		}
		fmt.Println("===this is from redfish interface v1: ", remote)
	case "HUAWEI_REDFISH_BMCV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBMCV1Collect(client)
		}
		fmt.Println("===this is from redfish bmc v1: ", remote)
	case "HUAWEI_SSH_GPUV1":
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
