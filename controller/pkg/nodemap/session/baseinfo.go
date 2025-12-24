package session

import (
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
)

type DeviceBaseInfo struct {
	terminal.BaseInfo `json:"base_info" mapstructure:"base_info" yaml:"base_info"`
	// Host       string `json:"host" mapstructure:"host" yaml:"host"`
	// Username   string `json:"username" mapstructure:"username" yaml:"username"`
	// Password   string `json:"password" mapstructure:"password" yaml:"password"`
	// AuthPass   string `json:"auth_pass" mapstructure:"auth_pass" yaml:"auth_pass"`
	// Port       int    `json:"port" mapstructure:"port" yaml:"port"`
	// Authorize  bool   `json:"authorize" mapstructure:"authorize" yaml:"authorize"`
	// SshOptions string `json:"ssh_options" mapstructure:"ssh_options" yaml:"ssh_options"`
	Community string `json:"community" mapstructure:"community" yaml:"community"`
	Mode      string `json:"mode" mapstructure:"mode" yaml:"mode"`
	Sn        string `json:"sn" mapstructure:"sn" yaml:"sn"`
	Token     string `json:"token" mapstructure:"token" yaml:"token"`
	// Timeout    int    `json:"timeout" mapstructure:"timeout" yaml:"timeout"`
}

func NewDeviceBaseInfo(host, user, pass, devType, community string, port int) *DeviceBaseInfo {
	typ := devType
	if typ == "USG" {
		typ = "HuaWei"
	}
	return &DeviceBaseInfo{
		BaseInfo: terminal.BaseInfo{
			Host:     host,
			Username: user,
			Password: pass,
			Type:     terminalmode.NewDeviceType(typ),
			Port:     port,
		},
		Community: community,
	}
}

func (dbi *DeviceBaseInfo) WithToken(token string) *DeviceBaseInfo {
	dbi.Token = token
	return dbi
}

func (dbi *DeviceBaseInfo) WithAuthPass(auth_pass string) *DeviceBaseInfo {
	dbi.BaseInfo.AuthPass = auth_pass
	return dbi
}

func (dbi *DeviceBaseInfo) WithSshOptions(ssh_options string) *DeviceBaseInfo {
	dbi.BaseInfo.SshOptions = ssh_options
	return dbi
}

func (dbi *DeviceBaseInfo) WithMode(mode string) *DeviceBaseInfo {
	dbi.Mode = mode
	return dbi
}

func (dbi *DeviceBaseInfo) WithTelnet(telnet bool) *DeviceBaseInfo {
	dbi.BaseInfo.Telnet = telnet
	return dbi
}

func (dbi *DeviceBaseInfo) WithSn(sn string) *DeviceBaseInfo {
	dbi.Sn = sn
	return dbi
}
