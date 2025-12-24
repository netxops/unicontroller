package h3c

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminalmode"

	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	// "github.com/influxdata/telegraf/controller/pkg/l2service/temp/snmp"
)

type H3C struct{}

func (s *H3C) arp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalArp(remote, taskConfig)
}

func (s *H3C) ifTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	return switchs.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
}

func (s *H3C) dot1dPort(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalDot1dPort(remote, taskConfig)
}

func (s *H3C) vlan(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalVlan(remote, taskConfig)
}

func (s *H3C) systemName(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalSystemName(remote, taskConfig)
}

func (s *H3C) portIp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalPortIp(remote, taskConfig)
}

func (s *H3C) macTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWAREMacTable(remote, taskConfig)
}

func (s *H3C) lldp2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWARELLdp2(remote, taskConfig)
}

func (s *H3C) lldp1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWARELLdp1(remote, taskConfig)
}

func (s *H3C) sshLldp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWARESshLldp(remote, taskConfig)
}

func (s *H3C) sshLldp2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWARESshLldp2(remote, taskConfig)
}

func (s *H3C) sshStp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWARESshStp(remote, taskConfig)
}

func (s *H3C) PortStatistics(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.PortStatistics(remote, taskConfig)
}

func (s *H3C) portChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWAREPortChannel(remote, taskConfig)
}

func (s *H3C) sshmactable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.COMWARESshMactable(remote, taskConfig)
}

func (s *H3C) sshipv6neighbor(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.Ipv6Neighbor(remote, taskConfig)
}

func (s *H3C) config(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Config(terminalmode.Comware, remote, taskConfig, options...)
}

func (s *H3C) configWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ConfigWithTerminalCmd(terminalmode.Comware, remote, taskConfig, options...)
}

func (s *H3C) execWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ExecWithTerminalCmd(terminalmode.Comware, remote, taskConfig, options...)
}
func (s *H3C) exec1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Exec(terminalmode.Comware, remote, taskConfig, options...)
}

func (s *H3C) portInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.H3cPortInfo(remote, taskConfig)
}
func (s *H3C) portInfo2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.H3cPortInfo2(remote, taskConfig)
}

func (s *H3C) version1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckVersion(terminalmode.Comware, remote, taskConfig, options...)
}

func (s *H3C) dir1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckDir(terminalmode.Comware, remote, taskConfig, options...)
}
func (s *H3C) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "COMWARE_ARP":
		result, err = s.arp(remote, taskConfig)
	case "COMWARE_IFTABLE":
		result, err = s.ifTable(remote, taskConfig)
	case "COMWARE_DOT1DPORT":
		result, err = s.dot1dPort(remote, taskConfig)
	case "COMWARE_VLAN":
		result, err = s.vlan(remote, taskConfig)
	case "COMWARE_SYSTEMNAME":
		result, err = s.systemName(remote, taskConfig)
	case "COMWARE_PORTIP":
		result, err = s.portIp(remote, taskConfig)
	case "COMWARE_MACTABLE":
		result, err = s.macTable(remote, taskConfig)
	case "COMWARE_LLDP2":
		result, err = s.lldp2(remote, taskConfig)
	case "COMWARE_LLDP1":
		result, err = s.lldp1(remote, taskConfig)
	case "COMWARE_SSHLLDP":
		result, err = s.sshLldp(remote, taskConfig)
	case "COMWARE_SSHLLDP2":
		result, err = s.sshLldp2(remote, taskConfig)
	case "COMWARE_STP":
		result, err = s.sshStp(remote, taskConfig)
	case "COMWARE_PORTSTATISTICS":
		result, err = s.PortStatistics(remote, taskConfig)
	case "COMWARE_PORTCHANNEL":
		result, err = s.portChannel(remote, taskConfig)
	case "COMWARE_SSH_MACTABLE":
		result, err = s.sshmactable(remote, taskConfig)
	case "COMWARE_IPV6_NEIGHBOR":
		result, err = s.sshipv6neighbor(remote, taskConfig)
	case "COMWARE_CONFIG":
		result, err = s.config(remote, taskConfig, options...)
	case "COMWARE_CONFIG_TERMINAL":
		result, err = s.configWithTerminal(remote, taskConfig, options...)
	case "COMWARE_EXEC_TERMINAL":
		result, err = s.execWithTerminal(remote, taskConfig, options...)
	case "COMWARE_SWITCH_EXEC1":
		result, err = s.exec1(remote, taskConfig, options...)
	case "COMWARE_PORTINFO":
		result, err = s.portInfo(remote, taskConfig)
	case "COMWARE_PORTINFO2":
		result, err = s.portInfo2(remote, taskConfig)
	case "COMWARE_SWITCH_VERSION1":
		result, err = s.version1(remote, taskConfig, options...)
	case "COMWARE_SWITCH_DIR1":
		result, err = s.dir1(remote, taskConfig, options...)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))

	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}
	return
}
