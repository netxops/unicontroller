package switchs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/netxops/cli/utils"

	"github.com/influxdata/telegraf/controller/pkg/structs/l2struct"

	"github.com/influxdata/telegraf/controller/pkg/uploader/netdevice/cisco"
	"github.com/influxdata/telegraf/controller/pkg/uploader/netdevice/huawei"

	"github.com/netxops/log"

	"github.com/gofrs/uuid"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/uploader"

	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/parser"
	"github.com/netxops/utils/reachable"
	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"

	"github.com/mohae/deepcopy"
	"go.uber.org/zap"

	"github.com/spf13/cast"
)

type PortInfo struct {
	TablePort RowPort `json:"TABLE_interface"`
}

type RowPort struct {
	Ports []PortTxt `json:"Row_interface"`
}

type PortTxt struct {
	Interface string `json:"interface"`
	State     string `json:"state"`
}

func RunSnmpTask(task *snmp.SnmpTask, remote *structs.L2DeviceRemoteInfo) (*clitask.Table, error) {
	result := task.Run(true)
	if result.Error() != nil {
		return nil, result.Error()
	}
	return task.Table()
}

func NormalArp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){"2": snmp.MacPDU}
	arpTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("NormalArp.arpTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	// TODO 删除下面混合解析改有Unify合并
	// iftableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "iftable")
	// if !desc.Ok() {
	// 	return nil, desc.Error()
	// }
	// iftableTable, err := iftableSerivce.Run(remote)
	// if err != nil {
	// 	logger.Error("NormalArp.iftableTable", log.Tag("remote", remote), zap.Error(err))
	// 	return nil, err
	// }
	//
	// arpTable.ForEach(ArpIndexProcess)
	// err = arpTable.AddKeyFromTable(l2struct.ArpInterface, "ifindex", "name", "", iftableTable, "")
	// if err != nil {
	// 	logger.Error("NormalArp.arpTable", log.Tag("remote", remote), zap.Error(err))
	// 	return nil, err
	// }

	return arpTable, nil
}

func NormalPortIp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	portIpTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("NormalPortIp.portIpTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	iftableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "iftable")
	if !desc.Ok() {
		return nil, desc.Error()
	}
	iftableTable, err := iftableSerivce.Run(remote)
	if err != nil {
		logger.Error("NormalPortIp.iftableTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	portIpTable.ForEach(PortIpIndexProcess)
	err = portIpTable.AddKeyFromTable("port", "interface", "name", "", iftableTable, "")
	if err != nil {
		logger.Error("NormalPortIp.portIpTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}

	return portIpTable, nil
}

func NormalDot1dPort(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	dot1dTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("NormalDot1dPort.dot1dTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	iftableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "iftable")
	if !desc.Ok() {
		return nil, desc.Error()
	}
	iftableTable, err := iftableSerivce.Run(remote)
	if err != nil {
		logger.Error("NormalDot1dPort.iftableTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	dot1dTable.ForEach(Dot1dIndexProcess)
	err = dot1dTable.AddKeyFromTable(l2struct.Dot1dPortName, "value", "name", "", iftableTable, "")
	if err != nil {
		logger.Warn("NormalDot1dPort.dot1dTable", log.Tag("remote", remote), zap.Error(err))
	}

	return dot1dTable, err
}

func NormalMacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	dot1dSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "dot1dport")
	if !desc.Ok() {
		return nil, desc.Error()
	}
	dot1dportTable, err := dot1dSerivce.Run(remote)
	if err != nil {
		logger.Error("NormalMacTable.dot1dportTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	vlanService, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "vlan")
	if !desc.Ok() {
		return nil, desc.Error()
	}
	vlanTable, err := vlanService.Run(remote)
	if err != nil {
		logger.Error("NormalMacTable.vlanTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}

	var mactables *clitask.Table
	for _, vlan := range vlanTable.Data {
		copyRemote := deepcopy.Copy(remote).(*structs.L2DeviceRemoteInfo)
		comm := fmt.Sprintf("%s@%s", remote.Community[0], vlan["vlan"])
		copyRemote.Community = []string{comm}

		macTask, err := taskConfig.NewExecutor(copyRemote)
		// macTask.PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
		macTask.(*snmp.SnmpTask).IndexCall = func(i string) (result string, err error) {
			return vlan["vlan"] + "_" + i, nil
		}

		// macTable, err := RunSnmpTask(macTask, remote)
		macTable, err := RunSnmpTask(macTask.(*snmp.SnmpTask), remote)
		if err != nil {
			logger.Error("NormalMacTable.macTable", log.Tag("remote", remote), zap.Error(err))
			return nil, err
		}
		macTable.AddKeyFromTable(l2struct.MacTableName, "ifindex", "name", "", dot1dportTable, "NO_INTERFACE_NAME")
		type f func(*clitask.Table, string, map[string]string) error

		macTable.ForEach(
			func() f {
				return func(t *clitask.Table, index string, row map[string]string) (e error) {
					vi := net.HardwareAddr(l2struct.MacTableMac).String()
					viList := strings.Split(vi, ":")
					macStr := strings.Join(viList, "")
					row[l2struct.MacTableMac] = "0x" + macStr
					row[l2struct.MacTableName] = strings.Replace(l2struct.MacTableName, "Et", "Ethernet", 1)
					row[l2struct.MacTableVlan] = vlan["vlan"]
					if !t.IsContainKey("vlan") {
						t.Keys = append(t.Keys, "vlan")
					}
					return e
				}
			}())
		if mactables == nil || mactables.IsEmpty() {
			mactables = macTable
		} else {
			if !macTable.IsEmpty() {
				mactables.Concat(macTable)
			}
		}
	}
	// mactables.Pretty()
	return mactables, nil
}

func NormalVlan(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	vlan, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("NormalVlan.vlan", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	vlan.ForEach(VlanIndexProcess)
	// vlan.Pretty()
	return vlan, nil
}

func NormalSystemName(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	name, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("NormalSysteName.name", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	// name.Pretty()
	return name, nil
}

func NormalCdp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, useDot1D bool) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	// snmpTask.PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){"4": snmp.IpPDU, "7": snmp.CiscoCdpInterface}
	cdpTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("NormalCdp.cdpTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	cdpTable.ForEach(func(tb *clitask.Table, index string, row map[string]string) error {
		if !tools.Contains(tb.Keys, "ifindex") {
			tb.Keys = append(tb.Keys, "ifindex")
		}
		row["ifindex"] = strings.Split(index, ".")[0]

		return nil
	})

	// cdpTable.Pretty()
	//
	// var iftableTable *clitask.Table
	// if useDot1D {
	// 	dot1dSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "dot1dport")
	// 	if !desc.Ok() {
	// 		return nil, desc.Error()
	// 	}
	// 	iftableTable, err = dot1dSerivce.Run(remote)
	// } else {
	// 	iftableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "iftable")
	// 	if !desc.Ok() {
	// 		return nil, desc.Error()
	// 	}
	// 	iftableTable, err = iftableSerivce.Run(remote)
	// }
	// // fmt.Println("sssssssssssss")
	// // iftableTable.Pretty()
	// if err != nil {
	// 	logger.Error("NormalCdp.iftableTable", log.Tag("remote", remote), zap.Error(err))
	// 	return nil, err
	// }
	//
	// err = cdpTable.AddKeyFromTable(l2struct.CdpOutgoing, "ifindex", "name", "", iftableTable, "")
	// if err == nil {
	// 	logger.Info("NormalCdp.cdpTable", log.Tag("remote", remote), zap.Error(err))
	// }
	// cdpTable.Pretty()
	return cdpTable, nil
}

func NormalCdp2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, useDot1D bool) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	// snmpTask.PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){"4": snmp.IpPDU, "7": snmp.CiscoCdpInterface}
	cdpTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("NormalCdp.cdpTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	// cdpTable.ForEach(func(tb *clitask.Table, index string, row map[string]string) error {
	// 	if !tools.Contains(tb.Keys, "ifindex") {
	// 		tb.Keys = append(tb.Keys, "ifindex")
	// 	}
	// 	row["ifindex"] = strings.Split(index, ".")[0]
	//
	// 	return nil
	// })
	//
	// // cdpTable.Pretty()
	//
	// var iftableTable *clitask.Table
	// if useDot1D {
	// 	dot1dSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "dot1dport")
	// 	if !desc.Ok() {
	// 		return nil, desc.Error()
	// 	}
	// 	iftableTable, err = dot1dSerivce.Run(remote)
	// } else {
	// 	iftableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "iftable")
	// 	if !desc.Ok() {
	// 		return nil, desc.Error()
	// 	}
	// 	iftableTable, err = iftableSerivce.Run(remote)
	// }
	// // fmt.Println("sssssssssssss")
	// // iftableTable.Pretty()
	// if err != nil {
	// 	logger.Error("NormalCdp.iftableTable", log.Tag("remote", remote), zap.Error(err))
	// 	return nil, err
	// }
	//
	// err = cdpTable.AddKeyFromTable(l2struct.CdpOutgoing, "ifindex", "name", "", iftableTable, "")
	// if err == nil {
	// 	logger.Info("NormalCdp.cdpTable", log.Tag("remote", remote), zap.Error(err))
	// }
	// cdpTable.Pretty()
	return cdpTable, nil
}
func COMWARELLdp2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	snmpTask.(*snmp.SnmpTask).IndexCall = snmp.H3CLldpIndex2
	lldpTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("COMWARELLdp2.lldpTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	// lldpTable.Pretty()
	lldpTable.ForEach(LLdpIndexProcess2)
	if err == nil {
		logger.Info("COMWARELLdp2.lldpTabler", log.Tag("remote", remote), zap.Error(err))
		// lldpTable.Pretty()
	}
	return lldpTable, nil
}

func COMWARELLdp1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	snmpTask.(*snmp.SnmpTask).IndexCall = snmp.H3CLldpIndex1
	lldpTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("COMWARELLdp1.lldpTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	iftableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "iftable")
	if !desc.Ok() {
		return nil, desc.Error()
	}
	iftableTable, err := iftableSerivce.Run(remote)
	if err != nil {
		logger.Error("COMWARELLdp1.iftableTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	// dot1dSerivce := taskConfig.GetMainConfig().Select(remote, "dot1dport")
	// dot1dportTable, err := dot1dSerivce.Run(remote)
	// dot1dportTable.Pretty()
	// if err != nil {
	// logger.Info("COMWARELLdp1 error", zap.Error( err))
	// return nil, err
	// }
	lldp2Service, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "lldp2")
	if !desc.Ok() {
		return nil, desc.Error()
	}
	lldp2Table, err := lldp2Service.Run(remote)
	if err != nil {
		logger.Error("COMWARELLdp1.lldp2Table", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	lldpTable.ForEach(LLdpIndexProcess)
	lldpTable.AddKeyFromTable("outgoing", "ifindex", "name", "", iftableTable, "")
	lldpTable.AddKeyFromTable("ip", "", "ip", "ifindex", lldp2Table, "NO_IP")
	// lldpTable.Pretty()
	return lldpTable, nil
}

func HuaWeiLLdp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	snmpTask, err := taskConfig.NewExecutor(remote)
	// snmpTask.PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	lldpTable, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	if err != nil {
		logger.Error("HuaWeiLLdp.lldpTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	// lldpTable.Pretty()
	iftableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "iftable")
	if !desc.Ok() {
		return nil, desc.Error()
	}
	iftableTable, err := iftableSerivce.Run(remote)
	if err != nil {
		logger.Error("HuaWeiLLdp.iftableTable", log.Tag("remote", remote), zap.Error(err))
		return nil, err
	}
	err = lldpTable.AddKeyFromTable("name", "", "name", "", iftableTable, "NO_INTERFACE_NAME")
	if err != nil {
		logger.Error("HuaWeiLLdp.lldpTable", log.Tag("remote", remote), zap.Error(err))
		// lldpTable.Pretty()
	}
	return lldpTable, nil
}

func HuaWeiSshVlan(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (tableResult *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	vlanRegexMap := map[string]string{
		"regex": `(?P<vlan>\d+)`,
		"name":  "vlan",
		"flags": "sx",
		"pcre":  "true",
	}

	// sshTask, err := taskConfig.NewSSHTask(remote)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "HuaWeiSshVlan.sshTask", 3, logger)

	// var retryBack clitask.ExecuteState
	//
	// var data string
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("HuaWeiSshVlan.sshTask", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, huawei_stp error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		logger.Info("HuaWeiSshVlan.cliExecuteResult", log.Tag("remote", remote), zap.Error(err))
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }

	if retryBack == clitask.EXEC_SUCCESS {
		result := text.IndentSection(data)

		for t := result.Iterator(); t.HasNext(); {
			_, _, resultMap := t.Next()
			if strings.Contains(resultMap["section"], "VLAN ID") {
				vlanResult, err := text.SplitterProcessOneTime(vlanRegexMap, resultMap["section"])
				if err != nil {
					logger.Info("HuaWeiSshVlan.vlanResult", log.Tag("remote", remote), zap.Error(err))
					return nil, err
				}
				tmpTable, err := vlanResult.Table()
				if err != nil {
					logger.Info("HuaWeiSshVlan.tmpTable", log.Tag("remote", remote), zap.Error(err))
					return nil, err
				}

				if tableResult == nil {
					tableResult = tmpTable
					if err != nil {
						logger.Info("HuaWeiSshVlan.tableResult", log.Tag("remote", remote), zap.Error(err))
						return nil, err
					}
				} else {
					tableResult.Concat(tmpTable)
				}
			}
		}
	}

	if tableResult != nil {
		tableResult.PushRawData(rawData)
		// tableResult.Pretty()
	}
	return
}

func COMWARESshLldp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (lldp_table *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result_data, rawData, retryBack, err := retryRun(remote, taskConfig, "ComwareSshLldp.lldp_result", 1, logger)

	// lldp_task, err := taskConfig.NewExecutor(remote)
	// if err != nil {
	// 	logger.Error("ComwareSshLldp.lldp_task", log.Tag("remote", remote), zap.Error(err))
	// 	return nil, err
	// }
	//
	// var retryBack clitask.ExecuteState
	// var result_data string
	// for retry := 0; retry < 1; retry++ {
	// 	lldp_task.(*terminal.Execute).Prepare(true)
	// 	lldp_result := lldp_task.Run(true)
	// 	if lldp_result.State == clitask.EXEC_SUCCESS {
	// 		retryBack = lldp_result.State
	// 		result_data = strings.Join(lldp_result.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, comware_mac error, result:%s", remote.Ip, lldp_result.ErrMsg)
	// 		logger.Info("ComwareSshLldp.lldp_result", log.Tag("remote", remote), zap.Error(err))
	// 		retryBack = lldp_result.State
	// 	}
	// }
	// 预处理ssh结果
	//

	lldpRegexMap := map[string]string{
		"regex": `(\d+\[(?P<outgoing>\S+)\]:) |
							(Chassis\s+ID\s+:\s+(?P<chassis_id>\S+)) |
							(Port\sID\s+:\s+(?P<peer_interface>\S+)) |
							(System\sname\s+:\s+(?P<name>\S+)) |
							(Management\s+address\s+:\s+(?P<ip>\S+))
		`,
		"name":  "lldp",
		"flags": "mx",
		"pcre":  "true",
	}

	lldp_table = clitask.NewEmptyTableWithKeys([]string{"outgoing", "peer_interface", "name", "ip"})
	lldp_table.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.RegexSplit("[\r\n]{3}", result_data)
		for _, section := range sections {
			lldpRegexResult, err := text.SplitterProcessOneTime(lldpRegexMap, section)

			if err != nil {
				logger.Info("ComwareSshLldp.lldpRegexResult", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			m, err := lldpRegexResult.Projection([]string{}, "_", [][]string{})

			data := make(map[string]string)
			data[l2struct.LLdpOutgoing] = strings.TrimSpace(m["outgoing"])
			data[l2struct.LLdpPeerInterface] = strings.TrimSpace(m["peer_interface"])
			data[l2struct.LLdpName] = strings.TrimSpace(m["name"])
			data[l2struct.LLdpIp] = strings.TrimSpace(m["ip"])
			lldp_table.PushRow("", data, false, "")
		}
	}
	// lldp_table.Pretty()
	return
}

func COMWARESshLldp2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (lldp_table *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result_data, rawData, retryBack, err := retryRun(remote, taskConfig, "ComwareSshLldp2.lldp_result", 1, logger)

	// lldp_task, err := taskConfig.NewExecutor(remote)
	// if err != nil {
	// 	logger.Error("ComwareSshLldp.lldp_task", log.Tag("remote", remote), zap.Error(err))
	// 	return nil, err
	// }
	//
	// var retryBack clitask.ExecuteState
	// var result_data string
	// for retry := 0; retry < 1; retry++ {
	// 	lldp_task.(*terminal.Execute).Prepare(true)
	// 	lldp_result := lldp_task.Run(true)
	// 	if lldp_result.State == clitask.EXEC_SUCCESS {
	// 		retryBack = lldp_result.State
	// 		result_data = strings.Join(lldp_result.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, comware_mac error, result:%s", remote.Ip, lldp_result.ErrMsg)
	// 		logger.Info("ComwareSshLldp.lldp_result", log.Tag("remote", remote), zap.Error(err))
	// 		retryBack = lldp_result.State
	// 	}
	// }
	// 预处理ssh结果
	//

	lldpRegexMap := map[string]string{
		"regex": `(\d+\[(?P<outgoing>\S+)\]:) |
							(Chassis\s+ID\s+:\s+(?P<chassis_id>\S+)) |
							(Port\sID\s+:\s+(?P<peer_interface>\S+)) |
							(System\sname\s+:\s+(?P<name>\S+)) |
							(Management\s+address\s+:\s+(?P<ip>\S+))
		`,
		"name":  "lldp",
		"flags": "mx",
		"pcre":  "true",
	}

	lldp_table = clitask.NewEmptyTableWithKeys([]string{"outgoing", "peer_interface", "name", "ip"})
	lldp_table.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		// sections := text.IndentSection(result_data)
		// for it := sections.Iterator(); it.HasNext(); {
		//	_, _, sectionMap := it.Next()
		//	section := sectionMap["section"]
		sections := text.RegexSplit(`LLDP neighbor-information`, result_data)
		for _, section := range sections {
			lldpRegexResult, err := text.SplitterProcessOneTime(lldpRegexMap, section)

			if err != nil {
				if err == text.ErrNoMatched {
					continue
				}
				logger.Info("ComwareSshLldp.lldpRegexResult", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			m, err := lldpRegexResult.Projection([]string{}, "_", [][]string{})

			data := make(map[string]string)
			if strings.TrimSpace(m["outgoing"]) == "" {
				continue
			}
			data[l2struct.LLdpOutgoing] = strings.TrimSpace(m["outgoing"])
			data[l2struct.LLdpPeerInterface] = strings.TrimSpace(m["peer_interface"])
			data[l2struct.LLdpName] = strings.TrimSpace(m["name"])
			data[l2struct.LLdpIp] = strings.TrimSpace(m["ip"])
			lldp_table.PushRow("", data, false, "")
		}
	}
	// lldp_table.Pretty()
	return
}

func HuaWeiSshLldp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (lldp_table *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result_data, rawData, retryBack, err := retryRun(remote, taskConfig, "HuaWeiSshLldp.lldp_task", 3, logger)
	// var retryBack clitask.ExecuteState
	// var result_data string
	// for retry := 0; retry < 3; retry++ {
	// 	lldp_task, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("HuaWeiSshLldp.lldp_task", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	lldp_task.(*terminal.Execute).Prepare(true)
	// 	lldp_result := lldp_task.Run(true)
	// 	if lldp_result.State == clitask.EXEC_SUCCESS {
	// 		retryBack = lldp_result.State
	// 		result_data = strings.Join(lldp_result.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, huawei_mac error, result:%s", remote.Ip, lldp_result.ErrMsg)
	// 		logger.Info("HuaWeiSshLldp.lldp_result", log.Tag("remote", remote), zap.Error(err))
	// 		retryBack = lldp_result.State
	// 	}
	// }
	// 预处理ssh结果

	data := strings.ReplaceAll(result_data, "\x1b[16D                \x1b[16D", "")
	data = strings.ReplaceAll(data, "  ---- More ----", "")

	var processedData string
	if retryBack == clitask.EXEC_SUCCESS {
		lines := strings.Split(data, "\n")

		d := []string{}
		for _, line := range lines {
			if strings.Index(line, "neighbor(s)") > 0 {
				d = append(d, line)
			} else {
				d = append(d, "  "+line)
			}
		}
		processedData = strings.Join(d, "\n")
	}

	lldp_table = clitask.NewEmptyTableWithKeys([]string{l2struct.LLdpOutgoing, l2struct.LLdpPeerInterface, l2struct.LLdpName, l2struct.LLdpIp})
	lldp_table.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.IndentSection(processedData)
		for it := sections.Iterator(); it.HasNext(); {
			_, _, sectionMap := it.Next()

			rs, err := text.GetFieldByRegex(`(?P<outgoing>\S+)\shas\s(?P<count>\d+)\sneighbor\(s\)`, sectionMap["section"], []string{"outgoing", "count"})
			if err != nil {
				if err == text.ErrNoMatched {
					logger.Warn("HuaWeiSshLldp.GetFieldByRegex NoMatched", log.Tag("remote", remote))
					continue
				}
				logger.Info("HuaWeiSshLldp.GetFieldByRegex", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			if rs["count"] == "0" {
				continue

			}

			regexMap := map[string]string{
				// "regex": `\s+Port\sID\s+:(?P<peer_interface>[^\n]+).*?System\sname\s+:(?P<name>[^\n]+).*?Management\saddress\s+:(?P<ip>[^\n]+)`,
				// "regex": `Port\sID\s+:(?P<peer_interface>[^\n]+).*?System\sname\s+:(?P<name>[^\n]+).*?Management\saddress\s+(value\s+)?:(?P<ip>[^\n]+)`,
				"regex": `
						Port\sID\s+:(?P<peer_interface>[^\n]+) | 
						System\sname\s+:(?P<name>[^\n]+) |
						Management\saddress\s+(value\s+)?:(?P<ip>[\d\.]+)
				`,
				"name":  "lldp",
				"flags": "mx",
				"pcre":  "true",
			}

			lldpRegexResult, err := text.SplitterProcessOneTime(regexMap, sectionMap["section"])
			if err != nil {
				if err == text.ErrNoMatched {
					logger.Warn("HuaWeiSshLldp.lldpRegexResult NoMatched", log.Tag("remote", remote))
					continue
				}
				logger.Info("HuaWeiSshLldp.lldpRegexResult", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}

			m, err := lldpRegexResult.Projection([]string{}, "", [][]string{})
			if err != nil {
				return nil, err
			}
			var data map[string]string
			data = make(map[string]string)
			data[l2struct.LLdpOutgoing] = strings.TrimSpace(rs["outgoing"])
			data[l2struct.LLdpPeerInterface] = tools.Conditional(m["peer_interface"] == "--", "", m["peer_interface"]).(string)
			data[l2struct.LLdpName] = tools.Conditional(m["name"] == "--", "", m["name"]).(string)
			data[l2struct.LLdpName] = strings.TrimSpace(data["name"])
			data[l2struct.LLdpIp] = tools.Conditional(m["ip"] == "--", "", m["ip"]).(string)
			data[l2struct.LLdpIp] = strings.TrimSpace(data["ip"])

			lldp_table.PushRow("", data, false, "")
		}
	}
	// lldp_table.Pretty()
	return
}

func HuaWeiStp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Huawei Stp", 3, logger)
	// var retryBack clitask.ExecuteState
	// var err error
	// var data string
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("HuaWeiStp.sshTask", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, huawei_stp error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		logger.Info("HuaWeiStp.cliExecuteResult", log.Tag("remote", remote), zap.Error(err))
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.StpPort, l2struct.StpSend, l2struct.StpReceive, l2struct.StpVlan})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.RegexSplit(`-----+\n`, data)
		result := strings.Split(sections[2], "\n")
		for i := 0; i < len(result)-1; i += 2 {
			stpStr := strings.TrimSpace(result[i] + result[i+1])
			res := text.RegexSplit(`\s+`, stpStr)
			var data2 map[string]string
			data2 = make(map[string]string)
			data2[l2struct.StpPort] = res[1]
			data2[l2struct.StpSend] = res[2]
			data2[l2struct.StpReceive] = res[6]
			data2[l2struct.StpVlan] = res[0]
			tb.PushRow("", data2, true, "")
		}
	}
	// tb.Pretty()
	return tb, err
}

func CiscoStp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (tableResult *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	stpRegexMap := map[string]string{
		"regex": `        
		# 这是一个正则表达式
		Port\s(?P<port>\d+)\s\((?P<name>[^\)]+)\)\sof\s(?P<vlan>\S+)\sis\s(?P<state>[^\n]+)\s
        .*?
        BPDU:\ssent\s(?P<send>\d+),\sreceived\s(?P<receive>\d+)
		`,
		"name":  "stp",
		"flags": "sx",
		"pcre":  "true",
	}
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Cisco stp", 3, logger)
	// var retryBack clitask.ExecuteState
	//
	// var data string
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("CiscoStp.sshTask", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, cisco_stp error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		logger.Info("CiscoStp.cliExecuteResult", log.Tag("remote", remote), zap.Error(err))
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	if retryBack == clitask.EXEC_SUCCESS {
		vlanResult, err := text.SplitterProcessOneTime(stpRegexMap, data)

		if err != nil {
			logger.Info("CiscoStp.vlanResult", log.Tag("remote", remote), zap.Error(err))
			return nil, err
		}
		tmpTable, err := vlanResult.Table()
		if err != nil {
			logger.Info("CiscoStp.tmpTable", log.Tag("remote", remote), zap.Error(err))
		}

		if tableResult == nil {
			tableResult = tmpTable
		} else {
			tableResult.Concat(tmpTable)
		}
	}
	tableResult.PushRawData(rawData)
	// }
	return tableResult, err
}

func NexusPortChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Nexus port channel", 3, logger)
	regexMap := map[string]string{
		"regex": `interface\s(?P<name>\S+).*?channel-group\s(?P<portchannel>\d+)`,
		"name":  "portChannel",
		"flags": "s",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortChannelName, l2struct.PortChannelInterface})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		result := text.IndentSection(data)

		for t := result.Iterator(); t.HasNext(); {
			_, _, resultMap := t.Next()
			if strings.Contains(resultMap["section"], "channel-group") {
				pcResult, _ := text.SplitterProcessOneTime(regexMap, resultMap["section"])
				for it := pcResult.Iterator(); it.HasNext(); {
					_, _, pcMap := it.Next()
					var pcdata map[string]string
					pcdata = make(map[string]string)
					pcdata[l2struct.PortChannelName] = "port-channel" + pcMap["portchannel"]
					pcdata[l2struct.PortChannelInterface] = pcMap["name"]
					tb.PushRow("", pcdata, false, "")
				}
			}
		}
	}
	// tb.Pretty()

	return tb, err
}

func NexusShRun(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Nexus ssh run", 3, logger)
	// var retryBack clitask.ExecuteState
	//
	// var data string
	// var err error
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("Nexus sh run.sshTask is error", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, nexus sh run is error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	regexMap := map[string]string{
		"regex": `(^interface\s+(?P<interface>\S+))\s*(?P<other>(\n[ ]+[^\n]+)+)`,
		"name":  "interface",
		"flags": "mx",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{"interface", "other"})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		regexResult, err := text.SplitterProcessOneTime(regexMap, data)
		if err != nil {
			logger.Error("NexusSh run regex error", log.Tag("remote", remote), zap.Error(err))
			return nil, err
		}
		// fmt.Println(lldpRegexResult)
		// unfree_port_list := []string{}
		for it := regexResult.Iterator(); it.HasNext(); {
			_, _, lMap := it.Next()
			var portData = make(map[string]string)
			other := strings.TrimSpace(lMap["other"])
			// if other != "switchport" && other != "shutdown" {
			//	unfree_port_list = append(unfree_port_list,lMap["interface"])
			// }
			portData["interface"] = lMap["interface"]
			portData["other"] = other
			tb.PushRow("", portData, false, "")

		}
	}
	// tb.Pretty()

	return tb, err
}

func IOSPortInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "IOSPortInfo", 3, logger)

	regexMap := map[string]string{
		"regex": `^(?P<interface>[\S]*)\sis.*?line\sprotocol\sis\s(?P<state>connected|down|up|disabled)`,
		"name":  "portinfo",
		"flags": "m",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortInfoInterface, l2struct.PortInfoState, l2struct.PortInfoDeviceIp})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		regexResult, err := text.SplitterProcessOneTime(regexMap, data)
		if err != nil {
			logger.Error("NexusPortInfo regex error", log.Tag("remote", remote), zap.Error(err))
			return nil, err
		}
		for it := regexResult.Iterator(); it.HasNext(); {
			_, _, lMap := it.Next()
			var portData = make(map[string]string)
			portData[l2struct.PortInfoInterface] = lMap["interface"]
			st := ""
			if lMap["state"] == "down" || lMap["state"] == "notconnec" {
				st = "down"
			} else if lMap["state"] == "up" {
				st = "up"
			} else {
				st = "unknown"
			}
			portData[l2struct.PortInfoState] = st
			portData[l2struct.PortInfoDeviceIp] = remote.Ip
			tb.PushRow("", portData, false, "")
		}
	}
	// tb.Pretty()

	return tb, err
}
func RuijiePortInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "RuijiePort info", 3, logger)
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("RuijiePortInfo error", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, nexus_portinfo error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	regexMap := map[string]string{
		"regex": `^(?i)(?P<interface>\w+[\s\d\/\.]+)\sis\s\w+\s*,\sline\sprotocol\sis\s(?P<state>connected|down|up|disabled)`,
		"name":  "portinfo",
		"flags": "m",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortInfoInterface, l2struct.PortInfoState, l2struct.PortInfoDeviceIp})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		regexResult, err := text.SplitterProcessOneTime(regexMap, data)
		if err != nil {
			logger.Error("RuijiePortInfo regex error", log.Tag("remote", remote), zap.Error(err))
			return nil, err
		}
		for it := regexResult.Iterator(); it.HasNext(); {
			_, _, lMap := it.Next()
			var portData = make(map[string]string)
			sp := strings.Split(strings.TrimSpace(lMap["interface"]), " ")
			interName := strings.Join(sp, "")
			portData[l2struct.PortInfoInterface] = interName
			st := ""
			if strings.ToLower(lMap["state"]) == "down" || strings.ToLower(lMap["state"]) == "notconnec" {
				st = "down"
			} else if strings.ToLower(lMap["state"]) == "up" {
				st = "up"
			} else {
				st = "unknown"
			}
			portData[l2struct.PortInfoState] = st
			portData[l2struct.PortInfoDeviceIp] = remote.Ip
			tb.PushRow("", portData, false, "")
		}
	}
	// tb.Pretty()

	return tb, err
}

func retryRun(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, method string, retryCountInput int, logger *log.Logger) (data string, rawData interface{}, retryBack clitask.ExecuteState, err error) {
	// First check if the remote device is alive using ping
	if !reachable.IsAlive(remote.Ip) {
		msg := fmt.Sprintf("%s device is not reachable", method)
		logger.Error(msg, log.Tag("remote", remote))
		return "", nil, clitask.EXEC_FAILED, fmt.Errorf("host:%s is not reachable", remote.Ip)
	}

	var retryCount int
	if retryCountInput == 0 {
		retryCount = 3
	} else {
		retryCount = retryCountInput
	}
	for retry := 0; retry < retryCount; retry++ {
		sshTask, err := taskConfig.NewExecutor(remote)
		if err != nil {
			msg := fmt.Sprintf("%s execute err", method)
			logger.Error(msg, log.Tag("remote", remote), zap.Error(err))
			return "", nil, clitask.EXEC_FAILED, err
		}
		sshTask.(*terminal.Execute).Prepare(true)
		cliExecuteResult := sshTask.Run(true)

		if cliExecuteResult.State == clitask.EXEC_SUCCESS {
			retryBack = cliExecuteResult.State
			rawData = cliExecuteResult
			data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
			break
		} else {
			err = fmt.Errorf("host:%s, %s error, result:%s", remote.Ip, method, cliExecuteResult.ErrMsg)
			retryBack = cliExecuteResult.State
		}
	}
	return
}

func NexusPortInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)

	data, rawData, retryBack, err := retryRun(remote, taskConfig, "NexusPortInfo", 3, logger)
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("NexusPortInfo error", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	// 		rd = cliExecuteResult
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, nexus_portinfo error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	regexMap := map[string]string{
		"regex": `(?P<interface>Eth[\S]*).*?(?P<state>connected|down|notconnec|disabled)`,
		"name":  "portinfo",
		"flags": "m",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortInfoInterface, l2struct.PortInfoState, l2struct.PortInfoDeviceIp})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		regexResult, err := text.SplitterProcessOneTime(regexMap, data)
		if err != nil {
			logger.Error("NexusPortInfo regex error", log.Tag("remote", remote), zap.Error(err))
			return nil, err
		}
		// fmt.Println(lldpRegexResult)
		for it := regexResult.Iterator(); it.HasNext(); {
			_, _, lMap := it.Next()
			var portData = make(map[string]string)
			portData[l2struct.PortInfoInterface] = lMap["interface"]
			st := ""
			if lMap["state"] == "down" || lMap["state"] == "notconnec" {
				st = "down"
			} else if lMap["state"] == "connected" {
				st = "up"
			} else {
				st = "unknown"
			}
			portData[l2struct.PortInfoState] = st
			portData[l2struct.PortInfoDeviceIp] = remote.Ip
			tb.PushRow("", portData, false, "")

		}
	}
	// var portInfo PortInfo
	// if retryBack == clitask.EXEC_SUCCESS {
	//	newIndex := strings.Index(data, "{")
	//	lastIndex := strings.LastIndex(data, "}")
	//	if newIndex < 0 {
	//		var portData = make(map[string]string)
	//		portData["error"] = "Index error"
	//		portData["device_ip"] = remote.Ip
	//		tb.PushRow("", portData, false, "")
	//		return tb, err
	//	} else {
	//		fmt.Println("data===========>", data[newIndex:lastIndex+1])
	//		err := json.Unmarshal([]byte(data[newIndex:lastIndex+1]), &portInfo)
	//		if err != nil {
	//			fmt.Printf("Unmarshal with error : %+v\n", err)
	//		}
	//		fmt.Println("==============>", portInfo)
	//	}
	//	for _, port := range portInfo.TablePort.Ports {
	//		var portData = make(map[string]string)
	//		portData["interface"] = port.Interface
	//		portData["state"] = port.State
	//		portData["device_ip"] = remote.Ip
	//		portData["error"] = ""
	//		tb.PushRow("", portData, false, "")
	//	}
	// }
	// tb.Pretty()

	return tb, err
}

// sh interface |json
func NexusPortInfo2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "NexusPortInfo", 3, logger)

	// var retryBack clitask.ExecuteState
	//
	// var data string
	// var err error
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("NexusPortInfo error", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, nexus_portinfo error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	tb := clitask.NewEmptyTableWithKeys([]string{"interface", "state", "device_ip", "error"})
	tb.PushRawData(rawData)
	var portInfo PortInfo
	if retryBack == clitask.EXEC_SUCCESS {
		newIndex := strings.Index(data, "{")
		lastIndex := strings.LastIndex(data, "}")
		if newIndex < 0 {
			var portData = make(map[string]string)
			portData["error"] = "Index error"
			portData["device_ip"] = remote.Ip
			tb.PushRow("", portData, false, "")
			return tb, err
		} else {
			fmt.Println("data===========>", data[newIndex:lastIndex+1])
			err := json.Unmarshal([]byte(data[newIndex:lastIndex+1]), &portInfo)
			if err != nil {
				fmt.Printf("Unmarshal with error : %+v\n", err)
			}
			fmt.Println("==============>", portInfo)
		}
		for _, port := range portInfo.TablePort.Ports {
			var portData = make(map[string]string)
			portData["interface"] = port.Interface
			portData["state"] = port.State
			portData["device_ip"] = remote.Ip
			portData["error"] = ""
			tb.PushRow("", portData, false, "")
		}
	}
	// tb.Pretty()

	return tb, err
}

func IOSPortChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "IOS PortChannel", 3, logger)

	// var retryBack clitask.ExecuteState
	//
	// var data string
	// var err error
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, ios_portchannel error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	regexMap := map[string]string{
		"regex": `interface\s(?P<name>\S+).*?channel-group\s(?P<portchannel>\d+)`,
		"name":  "portChannel",
		"flags": "s",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortChannelName, l2struct.PortChannelInterface})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		result := text.IndentSection(data)

		for t := result.Iterator(); t.HasNext(); {
			_, _, resultMap := t.Next()
			if strings.Contains(resultMap["section"], "channel-group") {
				pcResult, _ := text.SplitterProcessOneTime(regexMap, resultMap["section"])
				for it := pcResult.Iterator(); it.HasNext(); {
					_, _, pcMap := it.Next()
					var pcdata map[string]string
					pcdata = make(map[string]string)
					pcdata[l2struct.PortChannelName] = "port-channel" + pcMap["portchannel"]
					pcdata[l2struct.PortChannelInterface] = pcMap["name"]
					tb.PushRow("", pcdata, false, "")
				}
			}
		}
	}
	// tb.Pretty()

	return tb, err
}

func HuaWeiPortChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "huawei_portchannel", 3, logger)

	// var retryBack clitask.ExecuteState
	//
	// var data string
	// var err error
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, huawei_portchannel error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	regexMap := map[string]string{
		"regex": `interface\s(?P<name>\S+).*?eth-trunk\s+(?P<portchannel>\d+)`,
		"name":  "portChannel",
		"flags": "s",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortChannelName, l2struct.PortChannelInterface})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		result := text.IndentSection(data)

		for t := result.Iterator(); t.HasNext(); {
			_, _, resultMap := t.Next()
			if strings.Contains(resultMap["section"], "eth-trunk") {
				pcResult, _ := text.SplitterProcessOneTime(regexMap, resultMap["section"])
				for it := pcResult.Iterator(); it.HasNext(); {
					_, _, pcMap := it.Next()
					var pcdata map[string]string
					pcdata = make(map[string]string)
					pcdata[l2struct.PortChannelName] = "eth-trunk" + pcMap["portchannel"]
					pcdata[l2struct.PortChannelInterface] = pcMap["name"]
					tb.PushRow("", pcdata, false, "")
				}
			}
		}
	}
	// tb.Pretty()

	return tb, err
}

func Ipv6Neighbor(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (tb *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	ipv6RegexMap := map[string]string{
		"regex": `
		(IPv6\s+Address\s+:\s+(?P<ipv6>\S+)) |
		(Link-layer\s+:\s+(?P<link>\S+)) |
		(Interface\s+:\s+(?P<interface>\S+)) |
		(VLAN\s+:\s+(?P<vlan>\d+)) |
		(VPN\s+name\s+:\s+(?P<vpn>\S+))`,
		"name":  "ipv6",
		"flags": "mx",
		"pcre":  "true",
	}
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Ipv6 Neighbor", 3, logger)

	// var retryBack clitask.ExecuteState
	//
	// var data string
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("Ipv6Neighbor.sshTask", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, ipv6_neighbor error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		logger.Info("Ipv6Neighbor.cliExecuteResult", log.Tag("remote", remote), zap.Error(err))
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }

	tb = clitask.NewEmptyTableWithKeys([]string{l2struct.Ipv6NeighborIpv6, l2struct.Ipv6NeighborInterface, l2struct.Ipv6NeighborLink, l2struct.Ipv6NeighborVlan, l2struct.Ipv6NeighborVpn})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.RegexSplit(`-----+\n`, data)
		result := text.RegexSplit(`\n\n`, sections[1])
		for _, r := range result {
			ipv6Result, err := text.SplitterProcessOneTime(ipv6RegexMap, r)
			if err != nil {
				logger.Info("Ipv6Neighbor.ipv6Result", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			m, err := ipv6Result.Projection([]string{}, "_", [][]string{})
			if err != nil {
				logger.Info("Ipv6Neighbor.ipv6Result", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			if len(m) > 0 {
				tb.PushRow("", m, false, "")
			}
		}
		// tb.Pretty()
	}
	return
}

func ArpIndexProcess(t *clitask.Table, index string, arp map[string]string) error {
	ip := strings.Split(index, ".")[1:]
	arp[l2struct.ArpTableIp] = strings.Join(ip, ".")
	arp[l2struct.ArpTableMac] = "0x" + arp[l2struct.ArpTableIpMac]
	arp[l2struct.ArpTableIfindex] = strings.Split(index, ".")[0]
	// arp["ifindex"] = strings.Split(index)[0]
	if !t.IsContainKey(l2struct.ArpTableIp) {
		t.Keys = append(t.Keys, l2struct.ArpTableIp)
	}
	if !t.IsContainKey(l2struct.ArpTableMac) {
		t.Keys = append(t.Keys, l2struct.ArpTableMac)
	}
	if !t.IsContainKey(l2struct.ArpTableIfindex) {
		t.Keys = append(t.Keys, l2struct.ArpTableIfindex)
	}
	return nil
}

func Dot1dIndexProcess(t *clitask.Table, index string, dot1d map[string]string) error {
	dot1d["port_index"] = dot1d["value"]
	if !t.IsContainKey("port_index") {
		t.Keys = append(t.Keys, "port_index")
	}
	return nil
}

func LLdpIndexProcess2(t *clitask.Table, index string, lldp map[string]string) error {
	indexList := strings.Split(index, "_")
	lldp["ifindex"] = indexList[1]
	lldp["ip"] = indexList[0]
	if !t.IsContainKey("ifindex") {
		t.Keys = append(t.Keys, "ifindex")
	}
	if !t.IsContainKey("ip") {
		t.Keys = append(t.Keys, "ip")
	}
	return nil
}

func LLdpIndexProcess(t *clitask.Table, index string, lldp map[string]string) error {
	indexList := strings.Split(index, ".")
	lldp["ifindex"] = indexList[1]
	if !t.IsContainKey("ifindex") {
		t.Keys = append(t.Keys, "ifindex")
	}
	return nil
}

func VlanIndexProcess(t *clitask.Table, index string, vlan map[string]string) error {
	vlan["vlan"] = index
	if !t.IsContainKey("vlan") {
		t.Keys = append(t.Keys, "vlan")
	}
	return nil
}

func PortIpIndexProcess(t *clitask.Table, index string, portip map[string]string) error {
	portip["ip"] = index
	portip["ifindex"] = portip["interface"]
	if !t.IsContainKey("ip") {
		t.Keys = append(t.Keys, "ip")
	}
	if !t.IsContainKey("ifindex") {
		t.Keys = append(t.Keys, "ifindex")
	}

	return nil
}

func CdpIndexProcess(t *clitask.Table, index string, cdp map[string]string) error {
	indexList := strings.Split(index, ".")
	cdp["ifindex"] = indexList[0]
	if !t.IsContainKey("ifindex") {
		t.Keys = append(t.Keys, "ifindex")
	}
	return nil
}

func MacProcess(t *clitask.Table, index string, mac map[string]string) error {

	info := strings.Split(index, ".")
	mac["mac"] = info[0]
	mac["name"] = strings.Replace(mac["name"], "Et", "Ethernet", 1)
	mac["vlan"] = info[1]
	if !t.IsContainKey("vlan") {
		t.Keys = append(t.Keys, "vlan")
	}

	// info := strings.Split(index, ".")
	// mac["mac"] = info[0]
	// mac["vlan"] = info[1]
	// mac["index"] = mac["value"]
	// mac["name"] = index
	// if t.IsContainKey("mac") {
	// t.Keys = append(t.Keys, "mac")
	// }
	// if t.IsContainKey("vlan") {
	// t.Keys = append(t.Keys, "vlan")
	// }
	// if t.IsContainKey("index") {
	// t.Keys = append(t.Keys, "index")
	// }
	// if t.IsContainKey("name") {
	// t.Keys = append(t.Keys, "name")
	// }

	return nil
}

func HuaWeiMacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	// snmpTask, err := taskConfig.NewExecutor(remote)
	// snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	iftableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "iftable")
	if !desc.Ok() {
		return nil, desc.Error()
	}

	ifTable, err := iftableSerivce.Run(remote)
	if err != nil {
		return nil, err
	}

	// macTask := taskConfig.NewSnmpTask(remote.Ip, remote.Community[0])
	macTask, err := taskConfig.NewExecutor(remote)
	macTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	macTask.(*snmp.SnmpTask).IndexCall = snmp.HuaweiMacIndex
	macTable, err := RunSnmpTask(macTask.(*snmp.SnmpTask), remote)
	if err != nil {
		return nil, err
	}
	macTable.AddKeyFromTable("name", "value", "name", "", ifTable, "NO_INTERFACE_NAME")
	macTable.ForEach(MacProcess)
	return macTable, nil

}

func HuaWeiSshArp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Huawei ssh arp", 3, logger)

	// var retryBack clitask.ExecuteState
	//
	// var data string
	// var err error
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, huawei_mactable error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	regexMap := map[string]string{
		"regex": `^(?P<ip>(\d+)\.(\d+)\.(\d+)\.(\d+))\s+(?P<mac>(\w{4}\-\w{4}\-\w{4}))`,
		"name":  "arptable",
		"flags": "m",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.ArpTableIp, l2struct.ArpTableMac})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		// sections := text.RegexSplit(`-----+\n`, data)
		// result := strings.Split(sections[2], "\n")
		// result := strings.Split(data, "\n")
		// loop:
		// for _, t := range result {
		arpResult, _ := text.SplitterProcessOneTime(regexMap, data)
		for it := arpResult.Iterator(); it.HasNext(); {
			_, _, arpMap := it.Next()
			// ok, _ := regexp.MatchString(`[a-zA-Z]`, macMap["name"])
			// if ok == false {
			// continue loop
			// }
			var arpdata map[string]string
			arpdata = make(map[string]string)
			arpdata[l2struct.ArpTableMac] = "0x" + strings.ReplaceAll(arpMap["mac"], "-", "")
			arpdata[l2struct.ArpTableIp] = arpMap["ip"]
			// macdata["name"] = macMap["name"]
			// macdata["vlan"] = macMap["vlan"]
			tb.PushRow("", arpdata, false, "")
		}
		// }
	}
	// tb.Pretty()
	return tb, err
}

func HuaWeiCdp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.CdpOutgoing})
	// arpdata := make(map[string]string)
	// tb.PushRow("", arpdata, false, "")
	// tb.Pretty()
	return tb, fmt.Errorf("HuaWei不支持CDP采集")
}

func HuaWeiSshMacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	tools.RandSleep(10)
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Huawei ssh mac table", 3, logger)

	// var retryBack clitask.ExecuteState
	//
	// var data string
	// var err error
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	//
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, huawei_mactable error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	regexMap := map[string]string{
		"regex": `(?P<mac>(\w{4}\-\w{4}\-\w{4}))\s+(?P<vlan>\S+)\s+(?P<name>.*?)\s+(?P<type>.*?)\s+`,
		"name":  "mactable",
		"flags": "s",
		"pcre":  "true",
	}
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.MacTableMac, l2struct.MacTableVlan, l2struct.MacTableName, l2struct.MacTableType})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.RegexSplit(`-----+\n`, data)
		if len(sections) < 3 {
			fmt.Println("----------------length < 3----------------------")
			fmt.Println(data)
			return tb, fmt.Errorf("length < 3")
		}
		result := strings.Split(sections[2], "\n")
	loop:
		for _, t := range result {
			macResult, _ := text.SplitterProcessOneTime(regexMap, t)
			for it := macResult.Iterator(); it.HasNext(); {
				_, _, macMap := it.Next()
				ok, _ := regexp.MatchString(`[a-zA-Z]`, macMap["name"])
				if ok == false {
					continue loop
				}
				var macdata map[string]string
				macdata = make(map[string]string)
				macdata[l2struct.MacTableMac] = "0x" + strings.ReplaceAll(macMap["mac"], "-", "")
				macdata[l2struct.MacTableType] = macMap["type"]
				macdata[l2struct.MacTableName] = macMap["name"]
				macdata[l2struct.MacTableVlan] = macMap["vlan"]
				tb.PushRow("", macdata, false, "")
			}
		}
	}
	return tb, err
}

func COMWAREMacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	// snmpTask, err := taskConfig.NewExecutor(remote)
	// snmpTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	dot1dtableSerivce, desc := taskConfig.GetMainConfig().Select(context.TODO(), remote, "dot1dport")
	if !desc.Ok() {
		return nil, desc.Error()
	}

	dot1dTable, err := dot1dtableSerivce.Run(remote)
	if err != nil {
		return nil, err
	}
	macTask, err := taskConfig.NewExecutor(remote)
	macTask.(*snmp.SnmpTask).PrefixCallMap = map[string]func(byte, string, interface{}) (string, error){}
	macTable, err := RunSnmpTask(macTask.(*snmp.SnmpTask), remote)

	if err != nil {
		return nil, err
	}
	err = macTable.AddKeyFromTable("name", "value", "name", "", dot1dTable, "NO_INTERFACE_NAME")
	if err != nil {
		panic(err)
	}
	macTable.ForEach(
		func(tb *clitask.Table, index string, row map[string]string) error {
			fields := strings.Split(index, ".")
			if len(fields) != 7 {
				return fmt.Errorf("snmp result has error, index=%s", index)
			}
			row["vlan"] = fields[0]
			mac := "0x"
			for _, field := range fields[1:] {
				mac += fmt.Sprintf("%02x", cast.ToInt(field))
			}
			row["mac"] = mac
			if !tools.Contains(tb.Keys, "vlan") {
				tb.Keys = append(tb.Keys, "vlan")
			}

			if !tools.Contains(tb.Keys, "mac") {
				tb.Keys = append(tb.Keys, "mac")
			}

			return nil
		})

	// macTable.Pretty()
	// macTable.ForEach(MacProcess)
	// macTable.Pretty()
	return macTable, nil

}

func COMWARESshStp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (stp_table *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)
	ssh_data, rawData, retryBack, err := retryRun(remote, taskConfig, "Comware ssh stp", 3, logger)

	stpRegexMap := map[string]string{
		"regex": `Port: (?P<port>\S+).*?RST\s+sent\s+(?P<send>\d+).*?RST\s+received\s+(?P<received>\d+)`,
		"name":  "stp",
		"flags": "s",
		"pcre":  "true",
	}

	if retryBack == clitask.EXEC_SUCCESS {
		stpRegexResult, err := text.SplitterProcessOneTime(stpRegexMap, ssh_data)
		if err != nil {
			panic(err)
		}
		tb, err := stpRegexResult.Table()
		if err != nil {
			panic(err)
		}
		// tb.Pretty()

		if stp_table == nil || stp_table.IsEmpty() {
			stp_table = tb
		} else {
			if !tb.IsEmpty() {
				stp_table.Concat(tb)
			}
		}
	}
	stp_table.PushRawData(rawData)
	return
}

func CiscoSshNexusMactable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (mac_table *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "mac table", 3, logger)

	macRegexMap := map[string]string{
		"regex": `(?P<vlan>\d+)\s+(?P<mac>[\w\.\d]+)\s+(?P<type>\S+).*?(?P<name>\S+)\s*$`,
		"name":  "mac",
		"flags": "mx",
		"pcre":  "true",
	}
	fieldList := []string{l2struct.MacTableVlan, l2struct.MacTableMac, l2struct.MacTableType, l2struct.MacTableName}
	if retryBack == clitask.EXEC_SUCCESS {
		// 处理正则
		// fmt.Println(data)
		mac_result_re, err := text.SplitterProcessOneTime(macRegexMap, data)
		if err != nil {
			panic(err)
		}

		if mac_result_re != nil {
			mac_table, err = mac_result_re.Table()
			if err != nil {
				panic(err)
			}
			if !text.CheckTableField(mac_table, fieldList) {
				panic("返回字段与需要的不一致")
			}
			err = mac_table.ForEach(nexusSSHMacTableFieldNameProcess)
			// mac_table.Pretty()
			mac_table.PushRawData(rawData)
		}
	}
	return

}

func CiscoSshIosMactable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (mac_table *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Mac table", 3, logger)

	macRegexMap := map[string]string{
		"regex": `
		(?P<vlan>\d+)\s+(?P<mac>[\w\.\d]+)\s+[A-Z]+\s+(pv\s+)?(?P<name>\S+)
		`,
		"name":  "mac",
		"flags": "mx",
		"pcre":  "true",
	}
	fieldList := []string{l2struct.MacTableVlan, l2struct.MacTableMac, l2struct.MacTableName}
	if retryBack == clitask.EXEC_SUCCESS {
		// 处理正则
		mac_result_re, err := text.SplitterProcessOneTime(macRegexMap, data)
		if err != nil {
			return mac_table, err
		}

		if mac_result_re != nil {
			mac_table, err = mac_result_re.Table()
			if err != nil {
				panic(err)
			}
			mac_table.PushRawData(rawData)
			if !text.CheckTableField(mac_table, fieldList) {
				panic("返回字段与需要的不一致")
			}
			err = mac_table.ForEach(nexusSSHMacTableFieldNameProcess)
		}
	}
	return

}

func nexusSSHMacTableFieldNameProcess(t *clitask.Table, index string, mac map[string]string) error {
	viList := strings.Split(mac["mac"], ".")
	macStr := strings.Join(viList, "")

	mac["mac"] = "0x" + macStr
	return nil
}

func CiscoSshLldp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (lldp_table *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "CiscoSshLldp", 3, logger)

	lldpRegexMap := map[string]string{
		"regex": `
				(Chassis\sid:\s+(?P<id>\S+))|                                        
				(Port\sid:\s(?P<peer_interface>\S+))|
				(Local\sPort\sid:\s+(?P<outgoing>[^\n]+))|
        (System\sName:\s+(?P<name>[^\n]+))|
        (Management\sAddress:\s(?P<ip>[^\n]+))`,
		"name":  "lldp",
		"flags": "mx",
		"pcre":  "true",
	}

	lldp_table = clitask.NewEmptyTableWithKeys([]string{"peer_interface", "outgoing", "name", "ip"})
	lldp_table.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		// sections := text.RegexSplit(`-----+\n`, data)
		result := text.RegexSplit(`\n\n`, data)
		for _, r := range result {
			lldpResult, err := text.SplitterProcessOneTime(lldpRegexMap, r)
			if err == text.ErrNoMatched {
				continue
			}
			if err != nil {
				logger.Info("CiscoSshLldp.lldpResult", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			m, err := lldpResult.Projection([]string{}, "_", [][]string{})
			if err != nil {
				logger.Info("CiscoSshLldp.lldpResult", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			if len(m) > 0 {
				row := map[string]string{}
				row["peer_interface"] = strings.TrimSpace(m["peer_interface"])
				row["outgoing"] = strings.TrimSpace(m["outgoing"])
				row["name"] = strings.TrimSpace(tools.Conditional(m["name"] != "", m["name"], m["id"]).(string))
				row["ip"] = strings.TrimSpace(m["ip"])
				lldp_table.PushRow("", row, false, "")
			}
		}
		// tb.Pretty()
	}

	return
}

func RuijieSshLldp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (lldp_table *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result_data, rawData, retryBack, err := retryRun(remote, taskConfig, "ssh lldp", 3, logger)

	lldpRegexMap := map[string]string{
		"regex": `
				(Port\sID\s*:\s(?P<peer_interface>\S+))|
				(information\sof\sport\s*\s+\[(?P<outgoing>[^\n]+))\]|
        (System\sname\s*:\s+(?P<name>[^\n]+))|
        (Management\saddress\s*:\s(?P<ip>[^\n]+))`,
		"name":  "lldp",
		"flags": "mx",
		"pcre":  "true",
	}

	lldp_table = clitask.NewEmptyTableWithKeys([]string{"peer_interface", "outgoing", "name", "ip"})
	lldp_table.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		// sections := text.RegexSplit(`-----+\n`, data)
		result := text.RegexSplit(`LLDP neighbor`, result_data)
		for index, r := range result {
			if index == 0 {
				continue
			}
			lldpResult, err := text.SplitterProcessOneTime(lldpRegexMap, r)
			if err == text.ErrNoMatched {
				continue
			}
			if err != nil {
				logger.Info("RuijieSshLldp.lldpResult", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			m, err := lldpResult.Projection([]string{}, "_", [][]string{})
			if err != nil {
				logger.Info("RuijieSshLldp.lldpResult", log.Tag("remote", remote), zap.Error(err))
				return nil, err
			}
			if len(m) > 0 {
				row := map[string]string{}
				row["peer_interface"] = strings.TrimSpace(m["peer_interface"])
				sp := strings.Split(strings.TrimSpace(m["outgoing"]), " ")
				row["outgoing"] = strings.Join(sp, "")
				row["name"] = strings.TrimSpace(tools.Conditional(m["name"] != "", m["name"], m["id"]).(string))
				row["ip"] = strings.TrimSpace(m["ip"])
				lldp_table.PushRow("", row, false, "")
			}
		}
		// tb.Pretty()
	}

	return
}
func PortStatistics(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(nil, true)
	result_data, rawData, retryBack, err := retryRun(remote, taskConfig, "Iport statistics", 3, logger)

	if retryBack == clitask.EXEC_SUCCESS {
		port_stat_maps := []map[string]string{}
		mode := terminalmode.NewDeviceType(remote.Platform)
		switch mode {
		case terminalmode.IOS: // IOS
			port_statistics, err := parser.IosShowIntInfo(result_data)
			if err != nil {
				return nil, err
			}
			for _, ps := range port_statistics {
				port_stat_maps = append(port_stat_maps, parser.ToMap(ps))
			}

		case terminalmode.HuaWei: // huawei
			port_statistics, err := parser.HuaweiShowIntInfo(result_data)
			if err != nil {
				return nil, err
			}
			for _, ps := range port_statistics {
				port_stat_maps = append(port_stat_maps, parser.ToMap(ps))
			}

		case terminalmode.Comware: // COMWARE
			port_statistics, err := parser.H3cShowIntInfo(result_data)
			if err != nil {
				return nil, err
			}
			for _, ps := range port_statistics {
				port_stat_maps = append(port_stat_maps, parser.ToMap(ps))
			}

		case terminalmode.Nexus: // nexus
			port_statistics, err := parser.NexusShowIntInfo(result_data)
			if err != nil {
				return nil, err
			}
			for _, ps := range port_statistics {
				port_stat_maps = append(port_stat_maps, parser.ToMap(ps))
			}
		}
		if len(port_stat_maps) > 0 {
			keys := []string{"name", "peak_input", "peak_input_time", "peak_input_time", "input_pkts", "input_bytes", "input_percent",
				"input_unicasts", "input_broadcasts", "input_multicasts", "input_discard", "input_errors", "peak_output", "peak_output_time",
				"peak_output_time", "output_pkts", "output_bytes", "output_percent", "output_unicasts", "output_broadcasts", "output_multicasts",
				"output_discard", "output_errors"}
			tb := clitask.NewEmptyTableWithKeys(keys)
			for _, port_stat_map := range port_stat_maps {
				tb.PushRow("", port_stat_map, false, "")
			}
			// tb.Pretty()
			tb.PushRawData(rawData)
			return tb, nil
		}
	}
	return nil, err
}

func HuaWeiStp82(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "stp82", 3, logger)
	if err != nil {
		logger.ErrorNoStack("stp err", zap.Error(err))
	}
	tb := clitask.NewEmptyTableWithKeys([]string{"port", "send", "receive", "vlan"})
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.RegexSplit(`\n\n`, data)
		fmt.Println("-------------------------------------------")
		fmt.Println(sections)
		fmt.Println(len(sections))

		result := strings.Split(sections[2], "\n")
		fmt.Println("-------------------------------------------")
		fmt.Println(result)
	}
	tb.PushRawData(rawData)
	// tb.Pretty()
	// return tb, err
	return nil, nil

}

func COMWAREPortChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (comware_table *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "PortChannel", 3, logger)
	if retryBack == clitask.EXEC_SUCCESS {
		regexMap := map[string]string{
			"regex": `(interface\s+(?P<interface>\S+)).*?(port\slink-aggregation\s+group\s+(?P<port>\d+))`,
			"name":  "vlan",
			"flags": "s",
			"pcre":  "true",
		}
		port_prefix := "Bridge-Aggregation"
		comware_table = clitask.NewEmptyTableWithKeys([]string{l2struct.PortChannelInterface, l2struct.PortChannelName})
		comware_table.PushRawData(rawData)
		sections := text.IndentSection(data)
		for t := sections.Iterator(); t.HasNext(); {
			_, _, resultMap := t.Next()
			if strings.Contains(resultMap["section"], "port link-aggregation group") {
				regexResult, err := text.SplitterProcessOneTime(regexMap, resultMap["section"])
				if err != nil {
					return nil, err
				}
				p := make(map[string]string)
				for t := regexResult.Iterator(); t.HasNext(); {
					_, _, regexresultMap := t.Next()
					// fmt.Println(regexresultMap)
					// if p["port_channel"] != "" {
					port := fmt.Sprintf("%s%s", port_prefix, regexresultMap["port"])
					p[l2struct.PortChannelName] = port
					// }
					// if p["interface"] != "" {
					p[l2struct.PortChannelInterface] = regexresultMap["interface"]
					// }
				}
				comware_table.PushRow("", p, false, "")
			}
		}
	}
	return
}

func COMWARESshMactable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (mactable *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Mac Table", 3, logger)
	if retryBack == clitask.EXEC_SUCCESS {
		mactable = clitask.NewEmptyTableWithKeys([]string{l2struct.MacTableMac, l2struct.MacTableVlan, l2struct.MacTableName, l2struct.MacTableType})
		mactable.PushRawData(rawData)
		sections := text.RegexSplit(`\n`, data)
		for i, section := range sections {
			if i < 2 {
				continue
			}
			mactable_list := text.RegexSplit(`\s+`, section)
			p := make(map[string]string)
			if len(mactable_list) > 4 {
				p[l2struct.MacTableName] = mactable_list[3]
				p[l2struct.MacTableVlan] = mactable_list[1]
				mac := mactable_list[0]
				p[l2struct.MacTableMac] = fmt.Sprintf("%s%s", "0x", strings.ReplaceAll(mac, "-", ""))

				mactable.PushRow("", p, false, "")
			}
		}
	}

	return
}

func Config(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}

	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	for index, ops := range options {
		key := strings.Join(strings.Fields(ops.(string)), "_")
		key = fmt.Sprintf("%s_%d", key, index+1)

		cmd := terminalmode.NewCommand(ops.(string), "", 50, key, "")
		exec.AddCommand(cmd)
		cmdList = append(cmdList, cmd)
	}
	fmt.Println("cmddddd======>", options)
	fmt.Println("cmd======>", cmdList)
	exec.Id = uuid.Must(uuid.NewV4()).String()

	result = clitask.NewEmptyTableWithKeys([]string{l2struct.CommonKeyBefore, l2struct.CommonKeyAfter})
	exec.Prepare(false)
	r := exec.Run(false)
	result.PushRawData(r)
	_, beforeList := r.GetResult(l2struct.CommonKeyBefore)
	_, afterList := r.GetResult(l2struct.CommonKeyAfter)
	if r.Error() != nil {
		err = r.Error()
		fmt.Println("config_err:==========>", err)
		return
	} else {
		before := strings.Join(beforeList, "\n")
		after := strings.Join(afterList, "\n")
		s := make(map[string]string)
		s[l2struct.CommonKeyBefore] = before
		s[l2struct.CommonKeyAfter] = after
		result.PushRow("0", s, true, "")
	}
	return
}

func ExecWithTerminalCmd(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}

	cmdsList := []string{}
	exec := terminal.NewExecute(terminalmode.VIEW, deviceType, base)
	for index, ops := range options {
		var cmd terminalmode.Command
		err = json.Unmarshal(ops.([]byte), &cmd)
		if err != nil {
			return
		}
		if cmd.Name == "" {
			cmd.Name = strings.Join(strings.Fields(cmd.Command), "_")
			cmd.Name = fmt.Sprintf("%s_%d", cmd.Name, index+1)
		}
		cmdsList = append(cmdsList, cmd.Command)
	}
	exec.Id = uuid.Must(uuid.NewV4()).String()
	cmdsText := strings.Join(cmdsList, "\n")
	err = utils.CommandHelper(exec, cmdsText)

	cmds := []*terminalmode.Command{}
	for i, _ := range exec.DeviceMode.Chain {
		cmds = append(cmds, exec.DeviceMode.Chain[i])
	}

	result = clitask.NewEmptyTableWithKeys([]string{l2struct.CommonCommand, l2struct.CommonKey, l2struct.CommonOutput, l2struct.CommonStatus})
	stopOnErr := false
	r := exec.Run(stopOnErr)
	result.PushRawData(r)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	for index, cmd := range cmds {
		ok, data := r.GetResult(cmd.Name)
		m := map[string]string{
			l2struct.CommonCommand: cmd.Command,
			l2struct.CommonKey:     cmd.Name,
			l2struct.CommonOutput:  strings.Join(data, "\n"),
			l2struct.CommonStatus:  tools.Conditional(ok, "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}
	return
}

func ConfigWithTerminalCmd(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}

	// cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	cmdsList := []string{}
	for _, ops := range options {
		var cmd terminalmode.Command
		err = json.Unmarshal(ops.([]byte), &cmd)
		if err != nil {
			return
		}
		cmdsList = append(cmdsList, cmd.Command)
	}
	cmdsText := strings.Join(cmdsList, "\n")
	err = utils.CommandHelper(exec, cmdsText)
	if err != nil {
		panic(err)
	}
	// for index, ops := range options {
	// 	var cmd terminalmode.Command
	// 	err = json.Unmarshal(ops.([]byte), &cmd)
	// 	if err != nil {
	// 		return
	// 	}
	// 	fmt.Println("22222222", cmd.Command, cmd.Prompt, cmd.Timeout)
	// 	if cmd.Name == "" {
	// 		cmd.Name = strings.Join(strings.Fields(cmd.Command), "_")
	// 		cmd.Name = fmt.Sprintf("%s_%d", cmd.Name, index+1)
	// 	}
	//
	// 	if cmd.Timeout == 0 {
	// 		cmd.Timeout = 5
	// 	}
	// 	exec.AddCommand(&cmd)
	// 	cmdList = append(cmdList, &cmd)
	// }
	fmt.Println("cmd======>", cmdsText)
	exec.Id = uuid.Must(uuid.NewV4()).String()

	// r := exec.Run(true)
	// if r.Error() != nil {
	// 	err = r.Error()
	// 	fmt.Println("config_err:==========>", err)
	// 	return
	// }
	result = clitask.NewEmptyTableWithKeys([]string{l2struct.CommonKeyBefore, l2struct.CommonKeyAfter})
	exec.Prepare(false)
	r := exec.Run(false)
	result.PushRawData(r)
	_, beforeList := r.GetResult(l2struct.CommonKeyBefore)
	_, afterList := r.GetResult(l2struct.CommonKeyAfter)
	if !r.Ok() {
		err = r.Error()
		fmt.Println("config err=?", err)
		return
	} else {
		before := strings.Join(beforeList, "\n")
		after := strings.Join(afterList, "\n")
		s := make(map[string]string)
		s[l2struct.CommonKeyBefore] = before
		s[l2struct.CommonKeyAfter] = after
		result.PushRow("0", s, true, "")
	}
	return
}

func snmpVersionParser(desc string, mode terminalmode.DeviceType) (version, deviceType string, err error) {
	var result map[string]string
	switch mode {
	case terminalmode.IOS:
		// Version 12.2(20100802:165548)
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.\w\(\)]+),`, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.]+),?`, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.VRP:
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.]+),?`, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// return result["version"], nil
	case terminalmode.HuaWei:
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.\w\(\)]+)`, desc, []string{"version"})
		lines := strings.Split(strings.TrimSpace(desc), "\n")
		if len(lines) > 0 {
			deviceType = lines[0]
		}
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		version = result["version"]
	}
	return
}

func sshVersionParser(desc string, mode terminalmode.DeviceType) (version, versionChild, deviceType string, err error) {
	var result map[string]string
	switch mode {
	case terminalmode.IOS:
		// Version 12.2(20100802:165548)
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		result, err = text.GetFieldByRegex(`NXOS:\sversion (?P<version>\d[\d\.\w\(\)]+)`, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.]+),\sRelease\s(?P<version_child>[\w]+)`, desc, []string{"version", "version_child"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.VRP:
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.]+),?`, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// return result["version"], nil
	case terminalmode.HuaWei:
		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.\w\(\)]+)\s\((?P<version_child>.*)\)\s`, desc, []string{"version", "version_child"})
		lines := strings.Split(strings.TrimSpace(desc), "\n")
		if len(lines) > 0 {
			deviceType = lines[0]
		}
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		versionChild = result["version_child"]
		version = result["version"]
	}
	return
}

func hotFixParser(desc string, mode terminalmode.DeviceType) (result bool, err error) {
	switch mode {
	case terminalmode.IOS:
	case terminalmode.Nexus:

	case terminalmode.Comware:

	case terminalmode.VRP:

	case terminalmode.HuaWei:
		lines := strings.Split(desc, "\n")
		for _, line := range lines {
			fmt.Println("--a-aaa", line)
			if strings.Contains(line, "Finished loading the patch") {
				return true, nil
			}
			if strings.Contains(line, "Finished activating the patch") {
				return true, nil
			}
			if strings.Contains(line, "Finished running the patch") {
				return true, nil
			}
		}
		return false, fmt.Errorf("未知输出,output:%s", lines)
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	return
}

func sshPatchVersion(desc string, mode terminalmode.DeviceType) (version string, err error) {
	switch mode {
	case terminalmode.IOS:
	case terminalmode.Nexus:

	case terminalmode.Comware:

	case terminalmode.VRP:

	case terminalmode.HuaWei:
		lines := strings.Split(desc, "\n")
		for _, line := range lines {
			if strings.Contains(line, "No patch exists") {
				return "nil", nil
			}
			if strings.Contains(line, "Package Version:") {
				ss := strings.Split(line, ":")
				if len(ss) > 1 {
					return ss[1], nil
				} else {
					return "nil", nil
				}

			}
		}
		return "", fmt.Errorf("未知输出,output:%s", lines)
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	return
}
func sshImageParser(desc string, mode terminalmode.DeviceType) (image, deviceType string, err error) {
	var result map[string]string
	switch mode {
	case terminalmode.IOS:
		result, err = text.GetFieldByRegex(`image file is:\s+(?P<image>[\S]+)`, desc, []string{"image"})

	case terminalmode.Nexus:
		result, err = text.GetFieldByRegex(`image file is:\s+(?P<image>[\S]+)`, desc, []string{"image"})

	case terminalmode.Comware:
		// result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.]+),?`, desc, []string{"version"})
		fmt.Println(" no support")
	case terminalmode.VRP:
		fmt.Println(" no support")
	case terminalmode.HuaWei:
		fmt.Println(" no support")
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		image = result["image"]
	}
	return
}

func sshDirParser(desc string, mode terminalmode.DeviceType) (result map[string]string, deviceType string, err error) {
	// var result map[string]string
	switch mode {
	case terminalmode.IOS:
		// Version 12.2(20100802:165548)
		result, err = text.GetFieldByRegex(`(?P<total>[\d]+)\sbytes\stotal\s\((?P<free>[\d]+)\sbytes\sfree`, desc, []string{"total", "free"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		result, err = text.GetFieldByRegex(`(?P<used>[\d]+)\sbytes\sused\s+(?P<free>[\d]+)\sbytes\sfree\s+(?P<total>[\d]+)\sbytes\stotal`, desc, []string{"used", "free", "total"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		result, err = text.GetFieldByRegex(`(?P<total>[\d]+)\sKB\stotal\s\((?P<free>[\d]+)\sKB\sfree\)`, desc, []string{"total", "free"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.VRP:
		result, err = text.GetFieldByRegex(``, desc, []string{"total", "free"})
		// if err != nil {
		// return "", err
		// }
		// return result["version"], nil
	case terminalmode.HuaWei:
		result, err = text.GetFieldByRegex(`(?P<total>[\d\,]+?)\sKB\stotal\s\((?P<free>[\d\,]+?)\sKB\sfree`, desc, []string{"total", "free"})
		// lines := strings.Split(strings.TrimSpace(desc), "\n")
		// if len(lines) > 0 {
		// 	deviceType = lines[0]
		// }
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		return
	}
	return
}

func sshStatusParser(desc string, mode terminalmode.DeviceType) (result *clitask.Table, deviceType string, err error) {
	// var result map[string]string
	switch mode {
	case terminalmode.IOS:
		regex := `.*?\n{2,}`
		table := text.TextTable(desc, regex, "Mod")
		result = table
		// Version 12.2(20100802:165548)
		// result, err = text.GetFieldByRegex(`(?P<total>[\d]+)\sbytes\stotal\s\((?P<free>[\d]+)\sbytes\sfree`, desc, []string{"total", "free"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		regex := `.*?\n{2,}`
		table := text.TextTable(desc, regex, "Mod")
		result = table
		// result, err = text.GetFieldByRegex(`(?P<used>[\d]+)\sbytes\sused\s+(?P<free>[\d]+)\sbytes\sfree\s+(?P<total>[\d]+)\sbytes\stotal`, desc, []string{"used", "free", "total"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
		regex := `.*?\n{2,}`
		table := text.TextTable(desc, regex, "Mod")
		result = table
	case terminalmode.VRP:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		regex := `.*?\n{2,}`
		table := text.TextTable(desc, regex, "Mod")
		result = table
	case terminalmode.HuaWei:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// lines := strings.Split(strings.TrimSpace(desc), "\n")
		// if len(lines) > 0 {
		//	deviceType = lines[0]
		// }
		regex := `.*?\n{2,}`
		table := text.TextTable(desc, regex, "Mod")
		result = table
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		return
	}
	return
}

func sshInstallParser(desc string, mode terminalmode.DeviceType) (result map[string]string, deviceType string, err error) {
	// var result map[string]string
	result = make(map[string]string)
	switch mode {
	case terminalmode.IOS:
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
		// Version 12.2(20100802:165548)
		// result, err = text.GetFieldByRegex(`(?P<total>[\d]+)\sbytes\stotal\s\((?P<free>[\d]+)\sbytes\sfree`, desc, []string{"total", "free"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		regex2 := `Images will be upgraded.*?\n\n`
		res2 := text.MustSectionsByRegex(regex2, desc)
		if res2 != nil {
			if len(res2.Texts) > 0 {
				// fmt.Println("---", res)
				regex3 := `.*?\n{2,}`
				// fmt.Println("---res", res2.Texts[0])
				table := text.TextTable(res2.Texts[0], regex3, "Mod")
				for _, h := range table.Data {
					if h["Image"] == "nxos" {
						result["nxos"] = h["Upg-Required"]
						// if h["Upg-Required"] != "yes" {
						//	result = "false"
						// }
					}
					if h["Image"] == "bios" {
						result["bios"] = h["Upg-Required"]
						// if h["Upg-Required"] != "no" {
						//	result = "false"
						// }
					}
				}
			}
		}
		// result, err = text.GetFieldByRegex(`(?P<used>[\d]+)\sbytes\sused\s+(?P<free>[\d]+)\sbytes\sfree\s+(?P<total>[\d]+)\sbytes\stotal`, desc, []string{"used", "free", "total"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.VRP:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.HuaWei:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// lines := strings.Split(strings.TrimSpace(desc), "\n")
		// if len(lines) > 0 {
		//	deviceType = lines[0]
		// }
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		return
	}
	return
}

func sshInstallBootableParser(desc string, mode terminalmode.DeviceType) (result string, err error) {
	// var result map[string]string
	switch mode {
	case terminalmode.IOS:
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
		// Version 12.2(20100802:165548)
		// result, err = text.GetFieldByRegex(`(?P<total>[\d]+)\sbytes\stotal\s\((?P<free>[\d]+)\sbytes\sfree`, desc, []string{"total", "free"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		regex := `Compatibility check.*?\n\n`
		res := text.MustSectionsByRegex(regex, desc)
		if res != nil {
			if len(res.Texts) > 0 {
				result2, err := text.GetFieldByRegex(`\d\s+(?P<bootable>[a-zA-Z]+)`, res.Texts[0], []string{"bootable"})
				if err != nil {
					fmt.Println("--GetFieldByRegex- err--", res.Texts[0])
					return "", err
				}
				check := result2["bootable"]
				result = check
				return result, err
			}
		}
		// result, err = text.GetFieldByRegex(`(?P<used>[\d]+)\sbytes\sused\s+(?P<free>[\d]+)\sbytes\sfree\s+(?P<total>[\d]+)\sbytes\stotal`, desc, []string{"used", "free", "total"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.VRP:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.HuaWei:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// lines := strings.Split(strings.TrimSpace(desc), "\n")
		// if len(lines) > 0 {
		//	deviceType = lines[0]
		// }
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		return
	}
	return
}
func LinkCheckPass(desc string) (result *clitask.Table) {
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.LineCheck, l2struct.LineMsg})
	var data map[string]string
	data = make(map[string]string)
	lines := strings.Split(desc, "\n")

	for _, line := range lines {
		if strings.Contains(line, "########") {
			fmt.Println(line)
			if !strings.Contains(line, "SUCCESS") {
				data[l2struct.LineCheck] = "false"
				data[l2struct.LineMsg] = line
				tb.PushRow("", data, false, "")
				tb.Pretty()
				return tb
			}
		}
	}
	data["check"] = "true"
	data["msg"] = ""
	tb.PushRow("", data, false, "")
	// tb.Pretty()
	return tb
}

func LinkCheckImport(desc string) (result *clitask.Table) {
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.LineCheck, l2struct.LineMsg})
	var data map[string]string
	data = make(map[string]string)
	lines := strings.Split(desc, "\n")

	for _, line := range lines {
		if strings.Contains(line, "this image is not allowed") {
			fmt.Println("////", line)
			data[l2struct.LineCheck] = "false"
			data[l2struct.LineMsg] = line
			tb.PushRow("", data, false, "")
			tb.Pretty()
			return tb
		}
		if strings.Contains(line, "Copy complete") {
			data[l2struct.LineCheck] = "true"
			data[l2struct.LineMsg] = ""
			tb.PushRow("", data, false, "")
			tb.Pretty()
			return tb
		}
	}
	data[l2struct.LineCheck] = "true"
	data[l2struct.LineMsg] = ""
	tb.PushRow("", data, false, "")
	// tb.Pretty()
	return tb
}
func sshCheckLineParser(desc string, mode terminalmode.DeviceType) (result *clitask.Table, deviceType string, err error) {
	// var result map[string]string
	switch mode {
	case terminalmode.IOS:
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
		// Version 12.2(20100802:165548)
		// result, err = text.GetFieldByRegex(`(?P<total>[\d]+)\sbytes\stotal\s\((?P<free>[\d]+)\sbytes\sfree`, desc, []string{"total", "free"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		table := LinkCheckPass(desc)
		result = table
		return
		// result, err = text.GetFieldByRegex(`(?P<used>[\d]+)\sbytes\sused\s+(?P<free>[\d]+)\sbytes\sfree\s+(?P<total>[\d]+)\sbytes\stotal`, desc, []string{"used", "free", "total"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.VRP:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.HuaWei:
		tb := clitask.NewEmptyTableWithKeys([]string{l2struct.LineCheck, l2struct.LineMsg})
		var data map[string]string
		data = make(map[string]string)
		lines := strings.Split(desc, "\n")

		for _, line := range lines {
			if strings.Contains(line, "Succeeded in setting the software for booting system") {
				data[l2struct.LineCheck] = "true"
				data[l2struct.LineMsg] = ""
				tb.PushRow("", data, false, "")
				result = tb
				return
			}
		}
		data[l2struct.LineCheck] = "false"
		data[l2struct.LineMsg] = desc
		fmt.Println("----安装输出--", lines)
		tb.PushRow("", data, false, "")
		result = tb
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		return
	}
	return
}

func sshRebootLineParser(desc string, mode terminalmode.DeviceType) (result *clitask.Table, err error) {
	// var result map[string]string
	switch mode {
	case terminalmode.IOS:
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
		// Version 12.2(20100802:165548)
		// result, err = text.GetFieldByRegex(`(?P<total>[\d]+)\sbytes\stotal\s\((?P<free>[\d]+)\sbytes\sfree`, desc, []string{"total", "free"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		table := LinkCheckPass(desc)
		result = table
		return
		// result, err = text.GetFieldByRegex(`(?P<used>[\d]+)\sbytes\sused\s+(?P<free>[\d]+)\sbytes\sfree\s+(?P<total>[\d]+)\sbytes\stotal`, desc, []string{"used", "free", "total"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.VRP:
	case terminalmode.HuaWei:
		tb := clitask.NewEmptyTableWithKeys([]string{l2struct.LineCheck, l2struct.LineMsg})
		var data map[string]string
		data = make(map[string]string)
		lines := strings.Split(desc, "\n")

		for _, line := range lines {
			if strings.Contains(line, "System is going down for reboot or halt now") {
				data[l2struct.LineCheck] = "true"
				data[l2struct.LineMsg] = ""
				tb.PushRow("", data, false, "")
				result = tb
				return
			}
		}
		data[l2struct.LineCheck] = "false"
		data[l2struct.LineMsg] = "重启失败"
		tb.PushRow("", data, false, "")
		result = tb
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		return
	}
	return
}
func sshCheckImportReply(desc string, mode terminalmode.DeviceType) (result *clitask.Table, deviceType string, err error) {
	// var result map[string]string
	switch mode {
	case terminalmode.IOS:
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
		// Version 12.2(20100802:165548)
		// result, err = text.GetFieldByRegex(`(?P<total>[\d]+)\sbytes\stotal\s\((?P<free>[\d]+)\sbytes\sfree`, desc, []string{"total", "free"})
		// version = result["version"]
	// case terminalmode.IOS:
	//	// Version 12.2(20100802:165548)
	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
	//	if err != nil {
	//		return "", err
	//	}
	//	return result["version"], nil
	case terminalmode.Nexus:
		table := LinkCheckImport(desc)
		result = table
		return
		// result, err = text.GetFieldByRegex(`(?P<used>[\d]+)\sbytes\sused\s+(?P<free>[\d]+)\sbytes\sfree\s+(?P<total>[\d]+)\sbytes\stotal`, desc, []string{"used", "free", "total"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
	case terminalmode.Comware:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// version = result["version"]
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.VRP:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// if err != nil {
		// return "", err
		// }
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	case terminalmode.HuaWei:
		// result, err = text.GetFieldByRegex(``, desc, []string{"version"})
		// lines := strings.Split(strings.TrimSpace(desc), "\n")
		// if len(lines) > 0 {
		//	deviceType = lines[0]
		// }
		// regex := `.*?\n{2,}`
		// table := text.TextTable(desc, regex, "Mod")
		// result = table
	default:
		err = fmt.Errorf("unsupport platform")
		// return "", fmt.Errorf("unsupport platform")
	}

	if err == nil {
		return
	}
	return
}
func SnmpGetVersion(remote *structs.L2DeviceRemoteInfo, logger *log.Logger) (result *clitask.Table, err error) {
	if logger == nil {
		logger = log.NewLogger(remote.ActionID, true)
	}
	var version string
	st, err := snmp.NewSnmpTask(
		remote.Ip,
		remote.Community[0],
		"1.3.6.1.2.1.1",
		[]int{1},
		[]int{0},
		map[string]string{"1": "version", "3": "uptime", "5": "sysName"},
		map[string]func(byte, string, interface{}) (string, error){},
		nil)

	st.Run(true)
	table, err := st.Table()
	table.Keys = append(table.Keys, "device_type")
	//
	// result = clitask.NewEmptyTableWithKeys([]string{"version"})
	if err != nil {
		logger.Error("checkNetworkDeviceVersion", zap.Any("msg", "网络设备版本采集失败"), zap.Any("ip", remote.Ip), zap.Any("platform", remote.Platform), zap.Any("err", err))
		return table, err
	}

	err = table.ForEach(func(t *clitask.Table, index string, row map[string]string) error {
		value := row[l2struct.NetworkDeviceVersion]
		row[l2struct.NetworkDeviceType] = ""
		if terminalmode.IsSupport(remote.Platform) {
			mode := terminalmode.NewDeviceType(remote.Platform)
			version, device_type, err := snmpVersionParser(value, mode)
			if err == nil {
				row[l2struct.NetworkDeviceVersion] = version
				row[l2struct.NetworkDeviceType] = device_type
			}
			return err
		} else {
			err = fmt.Errorf("unspport mode = %s", remote.Platform)
			return err
		}
	})

	if err != nil {
		logger.Error("网络设备版本采集失败", zap.Any("platform", remote.Platform), zap.Error(err))
		return table, err
	}

	logger.Debug("网络设备版本采集成功", zap.Any("platform", remote.Platform), zap.Any("version", version))
	return table, err
}

func SSHGetWithCMD(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table, err error) {
	return Exec(deviceType, remote, nil, options...)
}

func SSHGetWithCMDTimeOut(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, timeout int, options ...interface{}) (result *clitask.Table, err error) {
	return ExecWithTime(deviceType, remote, nil, timeout, options...)
}

func SSHGetWithCmcPrompt(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table, err error) {
	return StepWitchCMDs(deviceType, remote, nil, options...)
}

func SSHGetWithCmdPrompt(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table, err error) {
	return StepSwitchInteraction(deviceType, remote, nil, options...)
}
func SSHGetWithConfig(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table, err error) {
	return ConfigCMDEXECOutput(deviceType, remote, nil, options...)
}

func GetVersionMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (version string) {
	var rs *clitask.Table
	var err error
	var ok bool
	timeout := 15
	rs, err = SnmpGetVersion(remote, logger) // snmp方法
	if err != nil {
		logger.Warn("snmp get version failed，try ssh method", zap.Error(err), log.Tag("remote", remote))
		rs, err = SSHGetWithCMDTimeOut(remote, deviceType, logger, timeout, options...)
		if err != nil {
			logger.Error("ssh get version also failed", zap.Error(err), log.Tag("remote", remote))
		} else {
			for _, v := range rs.Data {
				if v[l2struct.CommonOutput] != "" {
					mode := terminalmode.NewDeviceType(remote.Platform)
					version, _, _, err = sshVersionParser(v[l2struct.CommonOutput], mode)
				}
			}
		}
	} else {
		version, ok = rs.IndexToValue("version", "0")
		if !ok {
			err = fmt.Errorf("updateRemoteInfo: IndexToValue return is empty,snmpwalk -c %s -v2c -O n %s 1.3.6.1.2.1.1", remote.Community[0], remote.Ip)
		}
	}
	return
}

func GetVersionMethod2(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (version, versionChild string) {
	var rs *clitask.Table
	var err error
	var ok bool
	timeout := 15
	rs, err = SSHGetWithCMDTimeOut(remote, deviceType, logger, timeout, options...)
	if err != nil {
		logger.Error("ssh get version also failed", zap.Error(err), log.Tag("remote", remote))
		rs, err = SnmpGetVersion(remote, logger) // snmp方法
		if err == nil {
			version, ok = rs.IndexToValue("version", "0")
			if !ok {
				err = fmt.Errorf("updateRemoteInfo: IndexToValue return is empty,snmpwalk -c %s -v2c -O n %s 1.3.6.1.2.1.1", remote.Community[0], remote.Ip)
			}
		}
	} else {
		for _, v := range rs.Data {
			if v[l2struct.CommonOutput] != "" {
				mode := terminalmode.NewDeviceType(remote.Platform)
				version, versionChild, _, err = sshVersionParser(v[l2struct.CommonOutput], mode)
			}
		}
	}
	return
}

func GetPatchVersionMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {
	var rs *clitask.Table
	var err error
	timeout := 60
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.VersionNum})
	rs, err = SSHGetWithCMDTimeOut(remote, deviceType, logger, timeout, options...)
	if err != nil {
		data := make(map[string]string)
		logger.Error("get patch version err", zap.Error(err), log.Tag("remote", remote))
		data[l2struct.VersionNum] = ""
		tb.PushRow("", data, false, "")
		return tb
	} else {
		for _, v := range rs.Data {
			mode := terminalmode.NewDeviceType(remote.Platform)
			st, err2 := sshPatchVersion(v[l2struct.CommonOutput], mode)
			data := make(map[string]string)
			if err2 != nil {
				data[l2struct.VersionNum] = ""
				tb.PushRow("", data, false, "")
				return tb
			} else {
				if st != "" {
					data[l2struct.VersionNum] = st
					tb.PushRow("", data, false, "")
					return tb
				}
			}
		}
	}
	return tb
}
func GetVersionAndImageMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (version, image string) {
	var rs *clitask.Table
	var err error
	timeout := 15
	rs, err = SSHGetWithCMDTimeOut(remote, deviceType, logger, timeout, options...)
	if err != nil {
		logger.Error("ssh get version also failed", zap.Error(err), log.Tag("remote", remote))
	} else {
		for _, v := range rs.Data {
			if v[l2struct.CommonOutput] != "" {
				mode := terminalmode.NewDeviceType(remote.Platform)
				version, _, _, err = sshVersionParser(v[l2struct.CommonOutput], mode)
				image, _, err = sshImageParser(v[l2struct.CommonOutput], mode)
			}
		}
	}
	return
}
func HotFixMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {
	var rs *clitask.Table
	var err error
	timeout := 60
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.HotFixInstallStatus, l2struct.HotFixInstallCommand})
	rs, err = SSHGetWithCMDTimeOut(remote, deviceType, logger, timeout, options...)
	if err != nil {
		data := make(map[string]string)
		logger.Error("hot fix exec err ", zap.Error(err), log.Tag("remote", remote))
		data[l2struct.HotFixInstallStatus] = "false"
		tb.PushRow("", data, false, "")
		return tb
	} else {
		for _, v := range rs.Data {
			logger.Info("-----hotfix cmd", zap.Any("command", v["command"]))
			mode := terminalmode.NewDeviceType(remote.Platform)
			st, err2 := hotFixParser(v[l2struct.CommonOutput], mode)
			data := make(map[string]string)
			data[l2struct.HotFixInstallCommand] = v["command"]
			if err2 != nil {
				data[l2struct.HotFixInstallStatus] = "false"
				tb.PushRow("", data, false, "")
				// return tb
			} else {
				if st != true {
					data[l2struct.HotFixInstallStatus] = "false"
					tb.PushRow("", data, false, "")
					// return tb
				} else {
					data[l2struct.HotFixInstallStatus] = "true"
					tb.PushRow("", data, false, "")
				}
			}
		}
	}
	return tb
}
func GetDirMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result map[string]string) {
	var rs *clitask.Table
	var err error
	// var ok bool
	rs, err = SSHGetWithCMD(remote, deviceType, logger, options...)
	if err != nil {
		logger.Warn("ssh get dir  failed,try another method", zap.Error(err), log.Tag("remote", remote))
	} else {
		for _, v := range rs.Data {
			if v[l2struct.CommonOutput] != "" {
				mode := terminalmode.NewDeviceType(remote.Platform)
				result, _, err = sshDirParser(v[l2struct.CommonOutput], mode)
				if err == nil {
					return result
				}
			}
		}
	}
	return
}

func GetStatusMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {
	var rs *clitask.Table
	var err error
	// var ok bool
	rs, err = SSHGetWithCMD(remote, deviceType, logger, options...)
	if err != nil {
		logger.Warn("ssh get dir  failed,try another method", zap.Error(err), log.Tag("remote", remote))
	} else {
		for _, v := range rs.Data {
			if v[l2struct.CommonOutput] != "" {
				mode := terminalmode.NewDeviceType(remote.Platform)
				result, _, err = sshStatusParser(v[l2struct.CommonOutput], mode)
				if result == nil {
					logger.Warn("GetStatusMethod empty", zap.Any("输出", v[l2struct.CommonOutput]))
				}
				if err == nil {
					return result
				}
			}
		}
	}
	return
}

func GetInstallMethod2(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {
	var rs *clitask.Table
	var err error
	// var ok bool
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.CheckOneLine})
	data := make(map[string]string)
	rs, err = SSHGetWithCmdPrompt(remote, deviceType, logger, options...)
	if err != nil {
		logger.Warn("SSHGetWithCmdPrompt  failed", zap.Error(err), log.Tag("remote", remote))
	} else {
		for _, v := range rs.Data {
			if v[l2struct.CommonOutput] != "" {
				mode := terminalmode.NewDeviceType(remote.Platform)
				result, _, err = sshCheckLineParser(v[l2struct.CommonOutput], mode)
				if result != nil {
					for _, s := range result.Data {
						if s["check"] == "false" {
							data[l2struct.CheckOneLine] = s["msg"]
							// tb.PushRow("", data, false, "")
							// return tb
						} else {
							data[l2struct.CheckOneLine] = s["check"]
						}
					}
				} else {
					data[l2struct.CheckOneLine] = "false"
				}

			}
		}
	}
	tb.PushRow("", data, false, "")
	// tb.Pretty()
	return tb
}
func GetInstallMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {
	var rs *clitask.Table
	var err error
	// var ok bool
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.InstallImpactCheckLine, l2struct.InstallImpactBootable, l2struct.InstallImpactYesCheckline, l2struct.InstallImpactNxos, l2struct.InstallImpactBios})
	data := make(map[string]string)
	rs, err = SSHGetWithCmdPrompt(remote, deviceType, logger, options...)
	if err != nil {
		logger.Warn("SSHGetWithCmcPrompt  failed", zap.Error(err), log.Tag("remote", remote))
	} else {
		for index, v := range rs.Data {
			if index == "1" {
				if v[l2struct.CommonOutput] != "" {
					mode := terminalmode.NewDeviceType(remote.Platform)
					result, _, err = sshCheckLineParser(v[l2struct.CommonOutput], mode)
					if result != nil {
						for _, s := range result.Data {
							if s["check"] == "false" {
								data[l2struct.CheckOneLine] = s["msg"] + "/" + s["check"]
								// tb.PushRow("", data, false, "")
								// return tb
							} else {
								data[l2struct.CheckOneLine] = s["check"]
							}
						}
					}
					bootable, err := sshInstallBootableParser(v[l2struct.CommonOutput], mode)
					if err != nil {
						fmt.Println("sshInstallBootableParser err", err)
					}
					if bootable == "yes" {
						data[l2struct.InstallImpactBootable] = "true"
					} else if bootable == "" {
						data[l2struct.InstallImpactBootable] = "NULL"
					} else {
						data[l2struct.InstallImpactBootable] = "false"
					}
					result2, _, err := sshInstallParser(v[l2struct.CommonOutput], mode)
					if err != nil {
						fmt.Println("sshInstallParser err", err)
					} else {
						data[l2struct.InstallImpactNxos] = result2["nxos"]
						data[l2struct.InstallImpactBios] = result2["bios"]
					}
					fmt.Println("---res--", result2)

				}
			} else if index == "2" {
				mode := terminalmode.NewDeviceType(remote.Platform)
				result, _, err = sshCheckLineParser(v[l2struct.CommonOutput], mode)
				if result != nil {
					for _, s := range result.Data {
						if s["check"] == "false" {
							data[l2struct.InstallImpactYesCheckline] = s["msg"] + "/" + s["check"]
							// tb.PushRow("", data, false, "")
							// return tb
						} else {
							data[l2struct.InstallImpactYesCheckline] = s["check"]
							// tb.PushRow("", data, false, "")
						}
					}
				}
			}
		}
	}
	tb.PushRow("", data, false, "")
	// tb.Pretty()
	return tb
}

func RebootMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {
	// var rs *clitask.Table
	var err error
	// var ok bool
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.LineCheck, l2struct.LineMsg})
	data := make(map[string]string)
	_, err = SSHGetWithCmdPrompt(remote, deviceType, logger, options...)
	if err != nil {
		data[l2struct.LineCheck] = "false"
		data[l2struct.LineMsg] = "执行命令失败"
		logger.Warn("SSHGetWithCmcPrompt  failed", zap.Error(err), log.Tag("remote", remote))
	} else {
		data[l2struct.LineCheck] = "true"
		// for index, v := range rs.Data {
		// 	if index == "1" {
		// 		fmt.Println("---step1-", v["command"])
		// 	} else if index == "2" {
		// 		fmt.Println("---step2-", v["command"])
		// 		mode := terminalmode.NewDeviceType(remote.Platform)
		// 		result, err = sshRebootLineParser(v[l2struct.CommonOutput], mode)
		// 		if result != nil {
		// 			for _, s := range result.Data {
		// 				data["check"] = s["check"]
		// 				data["msg"] = s["msg"]
		// 			}
		// 		} else {
		// 			data["check"] = "false"
		// 			data["msg"] = "执行错误"
		// 		}
		// 	}
		// }
	}
	tb.PushRow("", data, false, "")
	// tb.Pretty()
	return tb
}

// onuExtractKeyValuePairs 函数接受一个字符串文本，并返回一个包含键值对的切片
func onuExtractKeyValuePairs(text string) []map[string]string {
	lines := strings.Split(text, "\n")

	var keyValuePairs []map[string]string
	var keyValueMap map[string]string

	// 遍历每一行
	for _, line := range lines {
		// 如果当前行包含"-------"，表示段落结束，将当前的键值对map存入切片并初始化一个新的map
		if strings.Contains(line, "-------") {
			if keyValueMap != nil {
				keyValuePairs = append(keyValuePairs, keyValueMap)
			}
			keyValueMap = make(map[string]string)
			continue
		}

		// 按":"分割键值对
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// 将键值对存入当前的map
			keyValueMap[key] = value
		} else if len(parts) == 1 {
			// 处理只有键没有值的情况
			key := strings.TrimSpace(parts[0])
			// 将键设为空字符串
			keyValueMap[key] = ""
		}
	}

	// 将最后一个段落的键值对map存入切片
	if keyValueMap != nil {
		keyValuePairs = append(keyValuePairs, keyValueMap)
	}

	return keyValuePairs
}

func ImportFtpMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {

	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.CheckOneLine, l2struct.CheckOneMsg})
	if len(options) == 0 {
		tb.PushRow("", map[string]string{l2struct.CheckOneLine: "false", l2struct.CheckOneMsg: "options参数为空"}, false, "")
		return tb
	}

	var src, dest *structs.FileUrl
	// var ok bool
	if len(options) >= 1 {
		err := json.Unmarshal(options[0].([]byte), &src)
		if err != nil {
			tb.PushRow("", map[string]string{l2struct.CheckOneLine: "false", l2struct.CheckOneMsg: "src路径参数转换错误"}, false, "")
			return tb
		}
		// if src, ok = options[0].(*structs.FileUrl); !ok {
		// 	tb.PushRow("", map[string]string{"checkline": "src路径参数转换错误"}, false, "")
		// 	return tb
		// }
	}

	if len(options) >= 2 {
		err := json.Unmarshal(options[1].([]byte), &dest)
		if err != nil {
			tb.PushRow("", map[string]string{l2struct.CheckOneLine: "false", l2struct.CheckOneMsg: "dst路径参数转换错误"}, false, "")
			return tb
		}
		// if dest, ok = options[0].(*structs.FileUrl); !ok {
		// 	tb.PushRow("", map[string]string{"checkline": "dst路径参数转换错误"}, false, "")
		// 	return tb
		// }
	}

	var up uploader.Uploader
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}
	exec := terminal.NewExecute(terminalmode.VIEW, deviceType, base)

	var err error
	switch deviceType {
	case terminalmode.Nexus:
		u := &cisco.CiscoUploader{}
		u.WithVrf("default")
		u.WithTerminalExecute(exec)
		if dest == nil {
			if err, dest = u.DefaultDest(*src, structs.BOOTFLASH); err != nil {
				tb.PushRow("", map[string]string{l2struct.CheckOneLine: "false", l2struct.CheckOneMsg: fmt.Sprintf("默认upload目标转换错误:%s", err)}, false, "")
				return tb
			}
		}
		up = u
	case terminalmode.HuaWei:
		u := &huawei.HuaWeiUploader{}
		u.WithVrf("default")
		u.WithTerminalExecute(exec)
		if dest == nil {
			if err, dest = u.DefaultDest(*src, structs.FLASH); err != nil {
				tb.PushRow("", map[string]string{l2struct.CheckOneLine: "false", l2struct.CheckOneMsg: fmt.Sprintf("默认upload目标转换错误:%s", err)}, false, "")
				return tb
			}
		}
		up = u
	}

	err, data := up.Upload(*src, *dest, 300, true)
	tb.PushRow("", data, false, "")
	// tb.Pretty()
	return tb
}

func GeImpactMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {
	var rs *clitask.Table
	var err error
	// var ok bool
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.InstallImpactCheckLine, l2struct.InstallImpactBootable, l2struct.InstallImpactNxos, l2struct.InstallImpactBios})
	data := make(map[string]string)
	timeOut := 240
	rs, err = SSHGetWithCMDTimeOut(remote, deviceType, logger, timeOut, options...)
	if err != nil {
		logger.Warn("SSHGetWithCmcPrompt  failed", zap.Error(err), log.Tag("remote", remote))
	} else {
		for _, v := range rs.Data {
			if v[l2struct.CommonOutput] != "" {
				mode := terminalmode.NewDeviceType(remote.Platform)
				result, _, err = sshCheckLineParser(v[l2struct.CommonOutput], mode)
				if result != nil {
					for _, s := range result.Data {
						if s["check"] == "false" {
							data[l2struct.InstallImpactCheckLine] = s["msg"] + "/" + s["check"]
							// tb.PushRow("", data, false, "")
							// return tb
						} else {
							data[l2struct.InstallImpactCheckLine] = s["check"]
						}
					}
				}
				bootable, err := sshInstallBootableParser(v[l2struct.CommonOutput], mode)
				if err != nil {
					fmt.Println("sshInstallBootableParser err", err)
				}
				if bootable == "yes" {
					data[l2struct.InstallImpactBootable] = "true"
				} else if bootable == "" {
					data[l2struct.InstallImpactBootable] = "NULL"
				} else {
					data[l2struct.InstallImpactBootable] = "false"
				}
				result2, _, err := sshInstallParser(v[l2struct.CommonOutput], mode)
				if err != nil {
					fmt.Println("sshInstallParser err", err)
				} else {
					data[l2struct.InstallImpactNxos] = result2["nxos"]
					data[l2struct.InstallImpactBios] = result2["bios"]
				}
				fmt.Println("---res--", result2)

			}
		}
	}
	tb.PushRow("", data, false, "")
	// tb.Pretty()
	return tb
}

func GetBootMethod(remote *structs.L2DeviceRemoteInfo, deviceType terminalmode.DeviceType, logger *log.Logger, options ...interface{}) (result *clitask.Table) {
	var rs *clitask.Table
	var err error
	// var ok bool
	rs, err = SSHGetWithConfig(remote, deviceType, logger, options...)
	if err != nil {
		logger.Warn("ssh get dir  failed,try another method", zap.Error(err), log.Tag("remote", remote))
	} else {
		for _, v := range rs.Data {
			if v[l2struct.CommonOutput] != "" {
				// mode := terminalmode.NewDeviceType(remote.Platform)
				// result, _, err = sshInstallParser(v[l2struct.CommonOutput], mode)
				// if result == nil {
				//	logger.Warn("GetStatusMethod empty", zap.Any(l2struct.CommonOutput, v[l2struct.CommonOutput]))
				// }
				if err == nil {
					return result
				}
			}
		}
	}
	return
}

func CheckVersion(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	version, versionChild := GetVersionMethod2(remote, deviceType, logger, options...)
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.VersionNum, l2struct.SubVersionNum})
	var data map[string]string
	data = make(map[string]string)
	data[l2struct.VersionNum] = version
	data[l2struct.SubVersionNum] = versionChild
	tb.PushRow("", data, false, "")
	tb.Pretty()
	return tb, err
}

func PatchVersion(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	tb := GetPatchVersionMethod(remote, deviceType, logger, options...)
	tb.Pretty()
	return tb, err
}
func GetVersionAndImage(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.VersionNum, l2struct.ImageName})
	var data map[string]string
	var rs *clitask.Table
	data = make(map[string]string)
	rs, err = SnmpGetVersion(remote, logger) // snmp方法
	if err != nil {
		logger.Warn("snmp get version  failed,try another method", zap.Error(err), log.Tag("remote", remote))
	} else {
		version, ok := rs.IndexToValue("version", "0")
		if ok {
			data[l2struct.VersionNum] = version
		}
	}
	version2, image := GetVersionAndImageMethod(remote, deviceType, logger, options...)
	if version2 != "" {
		data[l2struct.VersionNum] = version2
	}
	data[l2struct.ImageName] = image
	tb.PushRow("", data, false, "")
	tb.Pretty()
	return tb, err
}

func CheckDir(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	res := GetDirMethod(remote, deviceType, logger, options...)
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.DirFree, l2struct.DirTotal})
	var data map[string]string
	data = make(map[string]string)
	data[l2struct.DirFree] = res["free"]
	data[l2struct.DirTotal] = res["total"]
	tb.PushRow("", data, false, "")
	tb.Pretty()
	return tb, err
}

func CheckStatus(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = GetStatusMethod(remote, deviceType, logger, options...)
	// tb := clitask.NewEmptyTableWithKeys([]string{"module", "status"})
	// var data map[string]string
	// data = make(map[string]string)
	// data["module"] = res["module"]
	// data["status"] = res["status"]
	// tb.PushRow("", data, false, "")
	result.Pretty()
	return result, err
}

func CheckInstall(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = GetInstallMethod(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}

func CheckInstall2(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = GetInstallMethod2(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}

func Reboot(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = RebootMethod(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}

func InstallHotFix(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = HotFixMethod(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}

func ImportFtp(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = ImportFtpMethod(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}

func BackupFile(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = ImportFtpMethod(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}
func ExecCmdMaps(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result, err = SSHGetWithCmcPrompt(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}

func CheckImpact(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = GeImpactMethod(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}

func CheckBoot(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	result = GetBootMethod(remote, deviceType, logger, options...)
	result.Pretty()
	return result, err
}

func Exec(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}
	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.VIEW, deviceType, base)
	for index, ops := range options {
		key := strings.Join(strings.Fields(ops.(string)), "_")
		key = fmt.Sprintf("%s_%d", key, index+1)
		cmd := terminalmode.NewCommand(ops.(string), "", 50, key, "")
		exec.AddCommand(cmd)
		cmdList = append(cmdList, cmd)
	}
	exec.Id = uuid.Must(uuid.NewV4()).String()

	result = clitask.NewEmptyTableWithKeys([]string{l2struct.CommonCommand, l2struct.CommonKey, l2struct.CommonOutput, l2struct.CommonStatus})
	stopOnErr := false
	r := exec.Run(stopOnErr)
	result.PushRawData(r)
	if r.Error() != nil {
		err = r.Error()
		return
	}
	for index, cmd := range cmdList {
		ok, data := r.GetResult(cmd.Name)
		m := map[string]string{
			l2struct.CommonCommand: cmd.Command,
			l2struct.CommonKey:     cmd.Name,
			l2struct.CommonOutput:  strings.Join(data, "\n"),
			l2struct.CommonStatus:  tools.Conditional(ok, "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}
	return
}

func ExecWithTime(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, timeout int, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}
	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.VIEW, deviceType, base)
	for index, ops := range options {
		key := strings.Join(strings.Fields(ops.(string)), "_")
		key = fmt.Sprintf("%s_%d", key, index+1)
		cmd := terminalmode.NewCommand(ops.(string), "", timeout, key, "")
		exec.AddCommand(cmd)
		cmdList = append(cmdList, cmd)
	}
	fmt.Println("cmddddd======>", options)
	exec.Id = uuid.Must(uuid.NewV4()).String()

	// result = clitask.NewEmptyTableWithKeys([]string{})

	// r := exec.Run(true)
	// if r.Error() != nil {
	//	err = r.Error()
	//	fmt.Println("config_err:==========>", err)
	//	return
	// }
	result = clitask.NewEmptyTableWithKeys([]string{l2struct.CommonCommand, l2struct.CommonKey, l2struct.CommonOutput, l2struct.CommonStatus})
	stopOnErr := false
	r := exec.Run(stopOnErr)
	result.PushRawData(r)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	for index, cmd := range cmdList {
		ok, data := r.GetResult(cmd.Name)
		m := map[string]string{
			l2struct.CommonCommand: cmd.Command,
			l2struct.CommonKey:     cmd.Name,
			l2struct.CommonOutput:  strings.Join(data, "\n"),
			l2struct.CommonStatus:  tools.Conditional(ok, "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}
	return
}

func StepWitchCMDs(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}
	base.WithDispatchTimeout(20)
	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.VIEW, deviceType, base)
	// exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	for index, ops := range options {
		var cmd terminalmode.Command
		err = json.Unmarshal(ops.([]byte), &cmd)
		if err != nil {
			return
		}
		fmt.Println("22222222", cmd.Command, cmd.Prompt, cmd.Timeout)
		if cmd.Name == "" {
			cmd.Name = strings.Join(strings.Fields(cmd.Command), "_")
			cmd.Name = fmt.Sprintf("%s_%d", cmd.Name, index+1)
		}

		if cmd.Timeout == 0 {
			cmd.Timeout = 3
		}
		exec.AddCommand(&cmd)
		cmdList = append(cmdList, &cmd)
	}
	exec.Id = uuid.Must(uuid.NewV4()).String()
	result = clitask.NewEmptyTableWithKeys([]string{l2struct.CommonCommand, l2struct.CommonKey, l2struct.CommonOutput, l2struct.CommonStatus})
	stopOnErr := false
	r := exec.Run(stopOnErr)
	result.PushRawData(r)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	for index, cmd := range cmdList {
		ok, data := r.GetResult(cmd.Name)
		m := map[string]string{
			l2struct.CommonCommand: cmd.Command,
			l2struct.CommonKey:     cmd.Name,
			l2struct.CommonOutput:  strings.Join(data, "\n"),
			l2struct.CommonStatus:  tools.Conditional(ok, "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}
	return
}

func StepSwitchInteraction(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}
	base.WithDispatchTimeout(20)
	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.VIEW, deviceType, base)
	// exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	for index, ops := range options {
		var cmdInteraction structs.CmdInteraction
		err = json.Unmarshal(ops.([]byte), &cmdInteraction)
		if err != nil {
			return
		}
		// {"cmd":"install all nxos xxx","name":"install","prompt":"Do you want to continue","prompt_cmd":"y","mulitlist":["prompt":"sure","cmd":"yes"]}

		eachCmd := terminalmode.NewCommand(cmdInteraction.Cmd, "", cmdInteraction.TimeOut, cmdInteraction.Name, "")
		if err != nil {
			return
		}
		fmt.Println("install cmd----", eachCmd.Command, eachCmd.Timeout)
		if eachCmd.Name == "" {
			eachCmd.Name = strings.Join(strings.Fields(eachCmd.Command), "_")
			eachCmd.Name = fmt.Sprintf("%s_%d", eachCmd.Name, index+1)
		}
		if eachCmd.Timeout == 0 {
			eachCmd.Timeout = 3
		}
		exec.AddCommand(eachCmd)
		for index2, v := range cmdInteraction.MultipleCmdList {
			f := func(data string, cmd *terminalmode.Command) (bool, string) {
				if cmd.Name != eachCmd.Name {
					return false, ""
				}
				p := regexp.MustCompile(v.Want)
				if matched := p.FindString(data); matched != "" {
					fmt.Println("////匹配成功------", v.Prompt, v.TimeOut, v.Cmd)
					if v.Name == "" {
						v.Name = strings.Join(strings.Fields(v.Cmd), "_")
						v.Name = fmt.Sprintf("%s_%d", v.Name, index2+1)
					}
					pass := terminalmode.NewCommand(v.Cmd, v.Prompt, v.TimeOut, v.Name, "")
					if v.Close {
						pass.WithClose(true)
					}
					cmd.Sub_commands = append(cmd.Sub_commands, pass)
					return true, matched
				}

				return false, ""
			}
			exec.AddOpts(f)
		}
		cmdList = append(cmdList, eachCmd)
	}
	exec.Id = uuid.Must(uuid.NewV4()).String()
	result = clitask.NewEmptyTableWithKeys([]string{l2struct.CommonCommand, l2struct.CommonKey, l2struct.CommonOutput, l2struct.CommonStatus})
	stopOnErr := false
	r := exec.Run(stopOnErr)
	result.PushRawData(r)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	for index, cmd := range cmdList {
		ok, data := r.GetResult(cmd.Name)
		m := map[string]string{
			l2struct.CommonCommand: cmd.Command,
			l2struct.CommonKey:     cmd.Name,
			l2struct.CommonOutput:  strings.Join(data, "\n"),
			l2struct.CommonStatus:  tools.Conditional(ok, "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}
	return
}

func ConfigCMDEXECOutput(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}
	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	for index, ops := range options {
		key := strings.Join(strings.Fields(ops.(string)), "_")
		key = fmt.Sprintf("%s_%d", key, index+1)

		cmd := terminalmode.NewCommand(ops.(string), "", 50, key, "")
		exec.AddCommand(cmd)
		cmdList = append(cmdList, cmd)
	}
	fmt.Println("cmddddd======>", options)
	exec.Id = uuid.Must(uuid.NewV4()).String()

	// result = clitask.NewEmptyTableWithKeys([]string{})

	// r := exec.Run(true)
	// if r.Error() != nil {
	//	err = r.Error()
	//	fmt.Println("config_err:==========>", err)
	//	return
	// }
	result = clitask.NewEmptyTableWithKeys([]string{l2struct.CommonCommand, l2struct.CommonKey, l2struct.CommonOutput, l2struct.CommonStatus})
	stopOnErr := false
	r := exec.Run(stopOnErr)
	result.PushRawData(r)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	for index, cmd := range cmdList {
		ok, data := r.GetResult(cmd.Name)
		m := map[string]string{
			l2struct.CommonCommand: cmd.Command,
			l2struct.CommonKey:     cmd.Name,
			l2struct.CommonOutput:  strings.Join(data, "\n"),
			l2struct.CommonStatus:  tools.Conditional(ok, "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}
	return
}
func ConfigWithCommand(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	result = clitask.NewEmptyTableWithKeys([]string{})
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
	}

	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	for index, ops := range options {
		var cmd terminalmode.Command
		err = json.Unmarshal(ops.([]byte), &cmd)
		if err != nil {
			return
		}

		if cmd.Name == "" {
			cmd.Name = strings.Join(strings.Fields(cmd.Command), "_")
			cmd.Name = fmt.Sprintf("%s_%d", cmd.Name, index+1)
		}

		if cmd.Timeout == 0 {
			cmd.Timeout = 3
		}

		//
		// key := strings.Join(strings.Fields(ops.(string)), "_")
		// key = fmt.Sprintf("%s_%d", key, index+1)
		//
		// cmd := terminalmode.NewCommand(ops.(string), "", 3, key, "")
		exec.AddCommand(&cmd)
		cmdList = append(cmdList, &cmd)
	}
	fmt.Println("cmddddd======>", options)
	exec.Id = uuid.Must(uuid.NewV4()).String()

	r := exec.Run(true)
	result.PushRawData(r)
	if r.Error() != nil {
		err = r.Error()
		fmt.Println("config_err:==========>", err)
		return
	}

	return
}

func H3cPortInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Port Info", 3, logger)

	// var retryBack clitask.ExecuteState
	// var data string
	// var err error
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortInfoInterface, l2struct.PortInfoState, l2struct.PortInfoDeviceIp})
	tb.PushRawData(rawData)
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("H3cPortInfo error", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, h3c_portinfo error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.RegexSplit(`outErrors\n`, data)
		if len(sections) == 1 {
			sections = text.RegexSplit(`Description`, data)
		}

		if len(sections) <= 1 {
			err = fmt.Errorf("host:%s, h3c_portinfo error, result: split failed", remote.Ip)
			return tb, err
		}

		result := text.RegexSplit(`\n<`, sections[1])
		regexMap := map[string]string{
			"regex": `^(?P<name>\S+)\s+(?P<state>\S+)`,
			"name":  "portInfo",
			"flags": "s",
			"pcre":  "true",
		}
		resList := strings.Split(result[0], "\n")
		for _, d := range resList {
			info := strings.TrimSpace(d)
			infoResult, _ := text.SplitterProcessOneTime(regexMap, info)
			for it := infoResult.Iterator(); it.HasNext(); {
				_, _, pcMap := it.Next()
				var portData map[string]string
				portData = make(map[string]string)
				portData[l2struct.PortInfoInterface] = pcMap["name"]
				if pcMap["state"] == "*down" {
					portData[l2struct.PortInfoState] = "down"
				} else if pcMap["state"] == "*up" {
					portData[l2struct.PortInfoState] = "up"
				} else {
					portData[l2struct.PortInfoState] = pcMap["state"]
				}
				portData[l2struct.PortInfoDeviceIp] = remote.Ip
				tb.PushRow("", portData, false, "")
			}
		}
		tb.Pretty()
	}
	return tb, err
}

func H3cPortInfo2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Port Info", 3, logger)

	// var retryBack clitask.ExecuteState
	// var data string
	// var err error
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("H3cPortInfo2 error", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, nexus_portinfo error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }
	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortInfoInterface, l2struct.PortInfoState, l2struct.PortInfoDeviceIp})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.RegexSplit(`\n\n`, data)
		if len(sections) == 0 {
			return tb, fmt.Errorf("切割失败")
		}
		regexMap := map[string]string{
			"regex": `^(?P<name>\S+)\s+(?P<state>(UP|DOWN))\s+(UP|DOWN|UP\(s\)|DOWN\(s\))\s+(?P<ip>([\d\.]+|(--)))`,
			"name":  "portInfo",
			"flags": "m",
			"pcre":  "true",
		}
		sections3 := text.RegexSplit(`Interface\s+Link`, sections[0])
		infoResult, _ := text.SplitterProcessOneTime(regexMap, sections3[1])
		for it := infoResult.Iterator(); it.HasNext(); {
			_, _, pcMap := it.Next()
			var portData map[string]string
			portData = make(map[string]string)
			portData[l2struct.PortInfoInterface] = pcMap["name"]
			if pcMap["state"] == "DOWN" {
				portData[l2struct.PortInfoState] = "down"
			} else if pcMap["state"] == "UP" {
				portData[l2struct.PortInfoState] = "up"
			} else {
				portData[l2struct.PortInfoState] = pcMap["state"]
			}
			portData[l2struct.PortInfoDeviceIp] = remote.Ip
			tb.PushRow("", portData, false, "")
		}
		if len(sections) > 1 {
			sections1 := text.RegexSplit(`Interface\s+Link`, sections[1])
			regexMap2 := map[string]string{
				"regex": `^(?P<name>\S+)\s+(?P<state>(UP|DOWN|ADM))`,
				"name":  "portInfo",
				"flags": "m",
				"pcre":  "true",
			}
			if len(sections1) == 0 {
				return tb, fmt.Errorf("切割第二段失败")
			}
			infoResult2, _ := text.SplitterProcessOneTime(regexMap2, sections1[1])
			for it := infoResult2.Iterator(); it.HasNext(); {
				_, _, pcMap := it.Next()
				var portData map[string]string
				portData = make(map[string]string)
				portData[l2struct.PortInfoInterface] = pcMap["name"]
				if pcMap["state"] == "DOWN" || pcMap["state"] == "ADM" {
					portData[l2struct.PortInfoState] = "down"
				} else if pcMap["state"] == "UP" {
					portData[l2struct.PortInfoState] = "up"
				} else {
					portData[l2struct.PortInfoState] = pcMap["state"]
				}
				portData[l2struct.PortInfoDeviceIp] = remote.Ip
				tb.PushRow("", portData, false, "")
			}
			tb.Pretty()
		}
	}
	return tb, err
}
func HuaWeiPortInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	logger := log.NewLogger(remote.ActionID, true)
	data, rawData, retryBack, err := retryRun(remote, taskConfig, "Port Info", 3, logger)

	// var retryBack clitask.ExecuteState
	// var data string
	// var err error
	// for retry := 0; retry < 3; retry++ {
	// 	sshTask, err := taskConfig.NewExecutor(remote)
	// 	if err != nil {
	// 		logger.Error("HuaWeiPortInfo error", log.Tag("remote", remote), zap.Error(err))
	// 		return nil, err
	// 	}
	// 	sshTask.(*terminal.Execute).Prepare(true)
	// 	cliExecuteResult := sshTask.Run(true)
	//
	// 	if cliExecuteResult.State == clitask.EXEC_SUCCESS {
	// 		retryBack = cliExecuteResult.State
	// 		data = strings.Join(cliExecuteResult.Output[0].Value, "\n")
	// 		break
	// 	} else {
	// 		err = fmt.Errorf("host:%s, huawei_portinfo error, result:%s", remote.Ip, cliExecuteResult.ErrMsg)
	// 		logger.Warn("HuaWeiPortInfo run failed try retry", zap.Any("host", remote.Ip), log.Tag("remote", remote), zap.Any("msg", cliExecuteResult.ErrMsg))
	// 		retryBack = cliExecuteResult.State
	// 	}
	// }

	data = strings.ReplaceAll(data, "\x1b[16D                \x1b[16D", "")
	data = strings.ReplaceAll(data, "  ---- More ----", "")

	tb := clitask.NewEmptyTableWithKeys([]string{l2struct.PortInfoInterface, l2struct.PortInfoState, l2struct.PortInfoDeviceIp})
	tb.PushRawData(rawData)
	if retryBack == clitask.EXEC_SUCCESS {
		sections := text.RegexSplit(`outErrors\n`, data)
		if len(sections) < 1 {
			logger.Error("HuaWeiPortInfo 切割失败", log.Tag("remote", remote), zap.Any("data", data))
			return tb, fmt.Errorf("切割失败")
		}
		result := text.RegexSplit(`\n<`, sections[1])
		regexMap := map[string]string{
			// "regex": `^(?P<name>[\w\d\._:\/]\S+)\s+(?P<state>\S+)`,
			"regex": `^\s*(?P<name>[\w\d\._:\/\#\-\|]+)(\(\d+G\))?\s+(?P<state>[-\w_\*\?\#]+)\s+[^\n]+$`,
			"name":  "portInfo",
			"flags": "m",
			"pcre":  "true",
		}
		resList := strings.Split(result[0], "\n")
		for _, d := range resList {
			info := strings.TrimSpace(d)
			if info == "\x00" {
				continue
			}
			infoResult, _ := text.SplitterProcessOneTime(regexMap, info)
			for it := infoResult.Iterator(); it.HasNext(); {
				_, _, pcMap := it.Next()
				var portData map[string]string
				portData = make(map[string]string)
				portData[l2struct.PortInfoInterface] = pcMap["name"]
				if pcMap["state"] == "*down" || pcMap["state"] == "down" {
					portData[l2struct.PortInfoState] = "down"
				} else if pcMap["state"] == "*up" || pcMap["state"] == "up" {
					portData[l2struct.PortInfoState] = "up"
				} else {
					portData[l2struct.PortInfoState] = pcMap["state"]
				}
				portData[l2struct.PortInfoDeviceIp] = remote.Ip
				tb.PushRow("", portData, false, "")
			}
		}
		tb.Pretty()
	} else {
		logger.Error("HuaWeiPortInfo run 3 time error", log.Tag("remote", remote), zap.Error(err))
	}
	return tb, err
}
