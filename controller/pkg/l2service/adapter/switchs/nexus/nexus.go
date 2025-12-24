package nexus

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

type Nexus struct{}

func (s *Nexus) SystemName(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalSystemName(remote, taskConfig)
}

func (s *Nexus) IfTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}

	table, err := switchs.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
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
	// t.RawData = table.GetRawData()
	// t.Pretty()
	return t, err
}

func (s *Nexus) Arp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalArp(remote, taskConfig)
}

func (s *Nexus) PortIp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalPortIp(remote, taskConfig)
}

func (s *Nexus) Dot1dPort(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalDot1dPort(remote, taskConfig)
}

func (s *Nexus) MacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalMacTable(remote, taskConfig)
}

func (s *Nexus) Vlan(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalVlan(remote, taskConfig)
}

func (s *Nexus) Cdp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	useDot1D := false
	return switchs.NormalCdp(remote, taskConfig, useDot1D)
}
func (s *Nexus) Cdp2(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	useDot1D := false
	return switchs.NormalCdp2(remote, taskConfig, useDot1D)
}
func (s *Nexus) Stp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.CiscoStp(remote, taskConfig)
}
func (s *Nexus) SshMactable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.CiscoSshNexusMactable(remote, taskConfig)
}

func (s *Nexus) SshLldp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.CiscoSshLldp(remote, taskConfig)
}

func (s *Nexus) portStatistics(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.PortStatistics(remote, taskConfig)
}

func (s *Nexus) portChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NexusPortChannel(remote, taskConfig)
}

func (s *Nexus) shRun(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NexusShRun(remote, taskConfig)
}

func (s *Nexus) sshipv6neighbor(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.Ipv6Neighbor(remote, taskConfig)
}

func (s *Nexus) portInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NexusPortInfo(remote, taskConfig)
}

func (s *Nexus) config(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Config(terminalmode.Nexus, remote, taskConfig, options...)
}

func (s *Nexus) configWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ConfigWithTerminalCmd(terminalmode.Nexus, remote, taskConfig, options...)
}

func (s *Nexus) execWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ExecWithTerminalCmd(terminalmode.Nexus, remote, taskConfig, options...)
}

func (s *Nexus) version1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckVersion(terminalmode.Nexus, remote, taskConfig, options...)
}
func (s *Nexus) versionAndImage(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.GetVersionAndImage(terminalmode.Nexus, remote, taskConfig, options...)
}
func (s *Nexus) dir1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckDir(terminalmode.Nexus, remote, taskConfig, options...)
}

func (s *Nexus) status1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckStatus(terminalmode.Nexus, remote, taskConfig, options...)
}

func (s *Nexus) exec1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Exec(terminalmode.Nexus, remote, taskConfig, options...)
}

func (s *Nexus) install1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckInstall(terminalmode.Nexus, remote, taskConfig, options...)
}

func (s *Nexus) importFile(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ImportFtp(terminalmode.Nexus, remote, taskConfig, options...)
}
func (s *Nexus) backUpFile(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.BackupFile(terminalmode.Nexus, remote, taskConfig, options...)
}
func (s *Nexus) execCmdMaps(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ExecCmdMaps(terminalmode.Nexus, remote, taskConfig, options...)
}
func (s *Nexus) impact1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckImpact(terminalmode.Nexus, remote, taskConfig, options...)
}

func (s *Nexus) boot1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckBoot(terminalmode.Nexus, remote, taskConfig, options...)
}
func (s *Nexus) reboot(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Reboot(terminalmode.Nexus, remote, taskConfig, options...)
}
func (s *Nexus) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "NEXUS_SYSTEMNAME":
		result, err = s.SystemName(remote, taskConfig)
		// switchs.SaveInterfaceByIp(remote, taskConfig)
	case "NEXUS_IFTABLE":
		result, err = s.IfTable(remote, taskConfig)
	case "NEXUS_DOT1DPORT":
		result, err = s.Dot1dPort(remote, taskConfig)
	case "NEXUS_ARP":
		result, err = s.Arp(remote, taskConfig)
	case "NEXUS_MACTABLE":
		result, err = s.MacTable(remote, taskConfig)
	case "NEXUS_VLAN":
		result, err = s.Vlan(remote, taskConfig)
	case "NEXUS_PORTIP":
		result, err = s.PortIp(remote, taskConfig)
	case "NEXUS_CDP":
		result, err = s.Cdp(remote, taskConfig)
	case "NEXUS_CDP2":
		result, err = s.Cdp2(remote, taskConfig)
	case "NEXUS_STP":
		result, err = s.Stp(remote, taskConfig)
	case "NEXUS_SSHMACTABLE":
		result, err = s.SshMactable(remote, taskConfig)
	case "NEXUS_SSHLLDP":
		result, err = s.SshLldp(remote, taskConfig)
	case "NEXUS_PORTSTATISTICS":
		result, err = s.portStatistics(remote, taskConfig)
	case "NEXUS_PORTCHANNEL":
		result, err = s.portChannel(remote, taskConfig)
	case "NEXUS_INTERFACE":
		result, err = s.shRun(remote, taskConfig)
	case "NEXUS_PORTINFO":
		result, err = s.portInfo(remote, taskConfig)
	case "NEXUS_IPV6_NEIGHBOR":
		result, err = s.sshipv6neighbor(remote, taskConfig)
	case "NEXUS_CONFIG":
		result, err = s.config(remote, taskConfig, options...)
	case "NEXUS_CONFIG_TERMINAL":
		result, err = s.configWithTerminal(remote, taskConfig, options...)
	case "NEXUS_EXEC_TERMINAL":
		result, err = s.execWithTerminal(remote, taskConfig, options...)
	case "NEXUS_SWITCH_VERSION1":
		result, err = s.versionAndImage(remote, taskConfig, options...)
	case "NEXUS_SWITCH_DIR1":
		result, err = s.dir1(remote, taskConfig, options...)
	case "NEXUS_SWITCH_STATUS1":
		result, err = s.status1(remote, taskConfig, options...)
	case "NEXUS_SWITCH_EXEC1":
		result, err = s.exec1(remote, taskConfig, options...)
	case "NEXUS_SWITCH_INSTALL1":
		result, err = s.install1(remote, taskConfig, options...)
	case "NEXUS_SWITCH_IMPORT1":
		result, err = s.importFile(remote, taskConfig, options...)
	case "NEXUS_SWITCH_EXEC_MAP":
		result, err = s.execCmdMaps(remote, taskConfig, options...)
	case "NEXUS_SWITCH_IMPACT1":
		result, err = s.impact1(remote, taskConfig, options...)
	case "NEXUS_SWITCH_BOOT1":
		result, err = s.boot1(remote, taskConfig, options...)
	case "NEXUS_SWITCH_REBOOT1":
		result, err = s.reboot(remote, taskConfig, options...)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}
