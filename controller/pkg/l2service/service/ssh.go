package service

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/structs"

	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/reachable"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/tools"
)

type CmdPair struct {
	Key     string `yaml:"key" mapstructure:"key"`
	Cmd     string `yaml:"cmd" mapstructure:"cmd"`
	Timeout int    `yaml:"timeout" mapstructure:"timeout"`
}

type SSHTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
	Commands       []*CmdPair `yaml:"commands" mapstructure:"commands"`
	ConfigMode     bool       `yaml:"config_mode" mapstructure:"config_mode"`
}

// func (s SSHTaskConfig) NewSSHTask(remote *structs.L2DeviceRemoteInfo) (*terminal.Execute, error) {
func (s SSHTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	mode := tools.Conditional(s.ConfigMode, terminalmode.CONFIG, terminalmode.VIEW).(terminalmode.ModeType)

	deviceType := terminalmode.NewDeviceType(remote.Platform)

	if (remote.Meta.EnableSSH == nil || !*remote.Meta.EnableSSH) && (remote.Meta.EnableTelnet == nil || !*remote.Meta.EnableTelnet) {
		return nil, fmt.Errorf("device %s can not suport ssh and telnet", remote.Ip)
	}

	var enableTelnet bool
	port := remote.Meta.SSHPort

	// Determine which protocol to use (SSH or Telnet)
	if *remote.Meta.EnableTelnet == true && *remote.Meta.EnableSSH == true {
		enableTelnet = false
	} else if *remote.Meta.EnableTelnet == true {
		enableTelnet = true
		port = remote.Meta.TelnetPort
	}

	// Check if the target port is alive before proceeding
	portStr := fmt.Sprint(port)
	if !reachable.TCPPortAlive(remote.Ip, portStr) {
		protocol := "SSH"
		if enableTelnet {
			protocol = "Telnet"
		}
		return nil, fmt.Errorf("device %s %s port %d is not reachable", remote.Ip, protocol, port)
	}

	baseInfo := terminal.BaseInfo{
		Host:       remote.Ip,
		Port:       port,
		Telnet:     enableTelnet,
		PrivateKey: remote.PrivateKey,
		Username:   remote.Username,
		Password:   remote.Password,
		AuthPass:   remote.AuthPass,
	}

	baseInfo.WithActionID(remote.ActionID)

	fmt.Printf("=========ssh baseInfo======%#v\n", baseInfo)
	exec := terminal.NewExecute(mode, deviceType, &baseInfo)

	for _, pair := range s.Commands {
		exec.Add(pair.Cmd, "", tools.Conditional(pair.Timeout == 0, DEFAULT_SSH_CMD_TIMEOUT, pair.Timeout).(int), pair.Key, "")
	}

	return exec, nil
}

//
// func (s SSHTaskConfig) NewSnmpTask(host, community string) *snmp.SnmpTask {
// return nil
// }

func (s SSHTaskConfig) GetSubOid(key string) string {
	return ""
}

//
// func (s SSHTaskConfig) NewRedfishTask(remote *structs.L2DeviceRemoteInfo) *redfish.RedfishTask {
// return nil
// }
