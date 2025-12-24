package ios

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/structs/l2struct"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminalmode"

	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	// "github.com/influxdata/telegraf/controller/pkg/l2service/temp/snmp"
)

type IOS struct{}

func (s *IOS) SystemName(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalSystemName(remote, taskConfig)
}

func (s *IOS) IfTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}

	table, err := switchs.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)

	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)
	exclude := []string{
		"unrouted VLAN",
		"ii",
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

func (s *IOS) Dot1dPort(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalDot1dPort(remote, taskConfig)
}

func (s *IOS) PortIp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalPortIp(remote, taskConfig)
}

func (s *IOS) Arp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalArp(remote, taskConfig)
}

func (s *IOS) MacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalMacTable(remote, taskConfig)
}

func (s *IOS) Vlan(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalVlan(remote, taskConfig)
}

func (s *IOS) Cdp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	useDot1D := false
	return switchs.NormalCdp(remote, taskConfig, useDot1D)
}

func (s *IOS) Stp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.CiscoStp(remote, taskConfig)
}

func (s *IOS) SshMactable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.CiscoSshIosMactable(remote, taskConfig)
}

func (s *IOS) SshLldp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.CiscoSshLldp(remote, taskConfig)

}

func (s *IOS) portStatistics(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.PortStatistics(remote, taskConfig)
}

func (s *IOS) portChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.IOSPortChannel(remote, taskConfig)
}

func (s *IOS) sshipv6neighbor(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.Ipv6Neighbor(remote, taskConfig)
}

func (s *IOS) config(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Config(terminalmode.IOS, remote, taskConfig, options...)
}

func (s *IOS) configWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ConfigWithTerminalCmd(terminalmode.IOS, remote, taskConfig, options...)
}

func (s *IOS) execWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ExecWithTerminalCmd(terminalmode.IOS, remote, taskConfig, options...)
}

func (s *IOS) portInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.IOSPortInfo(remote, taskConfig)
}

func (s *IOS) version1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckVersion(terminalmode.IOS, remote, taskConfig, options...)
}

func (s *IOS) dir1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckDir(terminalmode.IOS, remote, taskConfig, options...)
}

func (s *IOS) status1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckStatus(terminalmode.IOS, remote, taskConfig, options...)
}

func (s *IOS) exec1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Exec(terminalmode.IOS, remote, taskConfig, options...)
}

func (s *IOS) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "IOS_SYSTEMNAME":
		result, err = s.SystemName(remote, taskConfig)
	case "IOS_IFTABLE":
		result, err = s.IfTable(remote, taskConfig)
	case "IOS_DOT1DPORT":
		result, err = s.Dot1dPort(remote, taskConfig)
	case "IOS_MACTABLE":
		result, err = s.MacTable(remote, taskConfig)
	case "IOS_ARP":
		result, err = s.Arp(remote, taskConfig)
	case "IOS_VLAN":
		result, err = s.Vlan(remote, taskConfig)
	case "IOS_PORTIP":
		result, err = s.PortIp(remote, taskConfig)
	case "IOS_CDP":
		result, err = s.Cdp(remote, taskConfig)
	case "IOS_STP":
		result, err = s.Stp(remote, taskConfig)
	case "IOS_SSHMACTABLE":
		result, err = s.SshMactable(remote, taskConfig)
	case "IOS_SSHLLDP":
		result, err = s.SshLldp(remote, taskConfig)
	case "IOS_PORTSTATISTICS":
		result, err = s.portStatistics(remote, taskConfig)
	case "IOS_PORTCHANNEL":
		result, err = s.portChannel(remote, taskConfig)
	case "IOS_IPV6_NEIGHBOR":
		result, err = s.sshipv6neighbor(remote, taskConfig)
	case "IOS_CONFIG":
		result, err = s.config(remote, taskConfig, options...)
	case "IOS_CONFIG_TERMINAL":
		result, err = s.configWithTerminal(remote, taskConfig, options...)
	case "IOS_EXEC_TERMINAL":
		result, err = s.execWithTerminal(remote, taskConfig, options...)
	case "IOS_PORTINFO":
		result, err = s.portInfo(remote, taskConfig)
	case "IOS_SWITCH_VERSION1":
		result, err = s.version1(remote, taskConfig, options...)
	case "IOS_SWITCH_DIR1":
		result, err = s.dir1(remote, taskConfig, options...)
	case "IOS_SWITCH_STATUS1":
		result, err = s.status1(remote, taskConfig, options...)
	case "IOS_SWITCH_EXEC1":
		result, err = s.exec1(remote, taskConfig, options...)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))

	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}
	return
}
