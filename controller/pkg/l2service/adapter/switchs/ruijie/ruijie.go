package ruijie

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

type Ruijie struct{}

func (s *Ruijie) SystemName(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalSystemName(remote, taskConfig)
}

func (s *Ruijie) IfTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}

	table, err := switchs.RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)

	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)
	exclude := []string{
		"unrouted VLAN",
		"ii",
		"Null0",
	}
	table.ForEach(
		func(tb *clitask.Table, index string, row map[string]string) error {
			sp := strings.Split(strings.TrimSpace(row[l2struct.IfTableName]), " ")
			row[l2struct.IfTableName] = strings.Join(sp, "")

			return nil
		})

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

func (s *Ruijie) Dot1dPort(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalDot1dPort(remote, taskConfig)
}

func (s *Ruijie) PortIp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalPortIp(remote, taskConfig)
}

func (s *Ruijie) Arp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalArp(remote, taskConfig)
}

func (s *Ruijie) MacTable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalMacTable(remote, taskConfig)
}

func (s *Ruijie) Vlan(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.NormalVlan(remote, taskConfig)
}

func (s *Ruijie) Cdp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	useDot1D := false
	return switchs.NormalCdp(remote, taskConfig, useDot1D)
}

func (s *Ruijie) Stp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.CiscoStp(remote, taskConfig)
}

func (s *Ruijie) SshMactable(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.CiscoSshIosMactable(remote, taskConfig)
}

func (s *Ruijie) SshLldp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.RuijieSshLldp(remote, taskConfig)

}

func (s *Ruijie) portStatistics(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.PortStatistics(remote, taskConfig)
}

func (s *Ruijie) portChannel(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.IOSPortChannel(remote, taskConfig)
}

func (s *Ruijie) sshipv6neighbor(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.Ipv6Neighbor(remote, taskConfig)
}

func (s *Ruijie) config(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Config(terminalmode.Ruijie, remote, taskConfig, options...)
}

func (s *Ruijie) configWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ConfigWithTerminalCmd(terminalmode.Ruijie, remote, taskConfig, options...)
}

func (s *Ruijie) execWithTerminal(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.ExecWithTerminalCmd(terminalmode.Ruijie, remote, taskConfig, options...)
}

func (s *Ruijie) portInfo(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	return switchs.RuijiePortInfo(remote, taskConfig)
}

func (s *Ruijie) version1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckVersion(terminalmode.Ruijie, remote, taskConfig, options...)
}

func (s *Ruijie) dir1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckDir(terminalmode.Ruijie, remote, taskConfig, options...)
}

func (s *Ruijie) status1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.CheckStatus(terminalmode.Ruijie, remote, taskConfig, options...)
}

func (s *Ruijie) exec1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	return switchs.Exec(terminalmode.Ruijie, remote, taskConfig, options...)
}

func (s *Ruijie) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "RUIJIE_SYSTEMNAME":
		result, err = s.SystemName(remote, taskConfig)
	case "RUIJIE_IFTABLE":
		result, err = s.IfTable(remote, taskConfig)
	case "RUIJIE_DOT1DPORT":
		result, err = s.Dot1dPort(remote, taskConfig)
	case "RUIJIE_MACTABLE":
		result, err = s.MacTable(remote, taskConfig)
	case "RUIJIE_ARP":
		result, err = s.Arp(remote, taskConfig)
	case "RUIJIE_VLAN":
		result, err = s.Vlan(remote, taskConfig)
	case "RUIJIE_PORTIP":
		result, err = s.PortIp(remote, taskConfig)
	case "RUIJIE_CDP":
		result, err = s.Cdp(remote, taskConfig)
	case "RUIJIE_STP":
		result, err = s.Stp(remote, taskConfig)
	case "RUIJIE_SSHMACTABLE":
		result, err = s.SshMactable(remote, taskConfig)
	case "RUIJIE_SSHLLDP":
		result, err = s.SshLldp(remote, taskConfig)
	case "RUIJIE_PORTSTATISTICS":
		result, err = s.portStatistics(remote, taskConfig)
	case "RUIJIE_PORTCHANNEL":
		result, err = s.portChannel(remote, taskConfig)
	case "RUIJIE_IPV6_NEIGHBOR":
		result, err = s.sshipv6neighbor(remote, taskConfig)
	case "RUIJIE_CONFIG":
		result, err = s.config(remote, taskConfig, options...)
	case "RUIJIE_CONFIG_TERMINAL":
		result, err = s.configWithTerminal(remote, taskConfig, options...)
	case "RUIJIE_EXEC_TERMINAL":
		result, err = s.execWithTerminal(remote, taskConfig, options...)
	case "RUIJIE_PORTINFO":
		result, err = s.portInfo(remote, taskConfig)
	case "RUIJIE_SWITCH_VERSION1":
		result, err = s.version1(remote, taskConfig, options...)
	case "RUIJIE_SWITCH_DIR1":
		result, err = s.dir1(remote, taskConfig, options...)
	case "RUIJIE_SWITCH_STATUS1":
		result, err = s.status1(remote, taskConfig, options...)
	case "RUIJIE_SWITCH_EXEC1":
		result, err = s.exec1(remote, taskConfig, options...)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))

	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}
	return
}
