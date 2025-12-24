package model

type L2DeviceMeta struct {
	ID           uint
	Meta         Meta
	DcimDeviceID *uint
}

type Meta struct {
	RestfullPort   int    `yaml:"restfull_port" json:"restfull_port" mapstructure:"restfull_port"`
	NetconfPort    int    `yaml:"netconf_port" json:"netconf_port" mapstructure:"netconf_port"`
	TelnetPort     int    `yaml:"telnet_port" json:"telnet_port" mapstructure:"telnet_port"`
	SSHPort        int    `yaml:"ssh_port" json:"ssh_port" mapstructure:"ssh_port"`
	RedfishPort    int    `yaml:"redfish_port" json:"redfish_port" mapstructure:"redfish_port"`
	Enable         *bool  `json:"enable" yaml:"enable" mapstructure:"enable"`
	EnableSSH      *bool  `yaml:"enable_ssh" json:"enable_ssh" mapstructure:"enable_ssh"`
	EnableTelnet   *bool  `yaml:"enable_telnet" json:"enable_telnet" mapstructure:"enable_telnet"`
	EnableNetconf  *bool  `yaml:"enable_netconf" json:"enable_netconf" mapstructure:"enable_netconf"`
	EnableRestfull *bool  `yaml:"enable_restfull" json:"enable_restfull" mapstructure:"enable_restfull"`
	EnableSnmp     *bool  `yaml:"enable_snmp" json:"enable_snmp" mapstructure:"enable_snmp"`
	EnableRedfish  *bool  `yaml:"enable_redfish" json:"enable_redfish" mapstructure:"enable_redfish"`
	Version        string `yaml:"version" json:"version" mapstructure:"version"`
	RedfishVersion string `yaml:"redfish_version" mapstructure:"redfish_version" json:"redfish_version"`
}

type L2DeviceRemoteInfo struct {
	Ip             string   `yaml:"ip" mapstructure:"ip" json:"ip"`
	Username       string   `yaml:"username" mapstructure:"username" json:"username"`
	Password       string   `yaml:"password" mapstructure:"password" json:"password"`
	AuthPass       string   `yaml:"auth_pass" mapstructure:"auth_pass" json:"auth_pass"`
	PrivateKey     string   `yaml:"private_key" json:"private_key" mapstructure:"private_key"`
	Community      []string `yaml:"community" mapstructure:"community" json:"community"`
	Platform       string   `yaml:"platform" mapstructure:"platform" json:"platform"`
	Catalog        string   `yaml:"catalog" json:"catalog" mapstructure:"catalog"`
	Manufacturer   string   `yaml:"manufacturer" json:"manufacturer" mapstructure:"manufacturer"`
	RedfishVersion string   `yaml:"redfish_version" mapstructure:"redfish_version" json:"redfish_version"`
	MetaID         uint     `yaml:"meta_id" json:"meta_id" mapstructure:"meta_id"`
	IsRedfish      bool     `yaml:"is_redfish" json:"is_redfish" mapstructure:"is_redfish"`
	// Meta           internal.Meta `yaml:"meta" mapstructure:"meta" json:"meta"`
	Meta         Meta   `yaml:"meta" mapstructure:"meta" json:"meta"`
	TaskId       string `yaml:"task_id" json:"task_id" mapstructure:"task_id"`
	DeviceType   string `yaml:"device_type" json:"device_type" mapstructure:"device_type"`
	RestfullPort int    `yaml:"restfull_port" json:"restfull_port" mapstructure:"restfull_port"`
	NetconfPort  int    `yaml:"netconf_port" json:"netconf_port" mapstructure:"netconf_port"`
	TelnetPort   int    `yaml:"telnet_port" json:"telnet_port" mapstructure:"telnet_port"`
	SSHPort      int    `yaml:"ssh_port" json:"ssh_port" mapstructure:"ssh_port"`
	RedfishPort  int    `yaml:"redfish_port" json:"redfish_port" mapstructure:"redfish_port"`
}
