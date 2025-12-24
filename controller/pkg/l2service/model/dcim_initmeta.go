// 自动生成模板DeviceMeta
package model

// 如果含有time.Time 请自行import time包
type L2DcimInitMeta struct {
	GVA_MODEL `mapstructure:",squash"`
	// internal.Meta    `mapstructure:", squash"`
	// RestfullPort     int `json:"restfull_port" form:"restfull_port" gorm:"column:restfull_port;comment:;type:bigint;size:19;" mapstructure:"restfull_port"`
	// NetconfPort      int `json:"netconf_port" form:"netconf_port" gorm:"column:netconf_port;comment:;type:bigint;size:19;" mapstructure:"netconf_port"`
	// TelnetPort       int `json:"telnet_port" form:"telnet_port" gorm:"column:telnet_port;comment:;type:bigint;size:19;" mapstructure:"telnet_port"`
	// SshPort          int `json:"ssh_port" form:"ssh_port" gorm:"column:ssh_port;comment:;type:bigint;size:19;" mapstructure:"ssh_port"`
	RestfullPort int   `yaml:"restfull_port" json:"restfull_port" mapstructure:"restfull_port"`
	NetconfPort  int   `yaml:"netconf_port" json:"netconf_port" mapstructure:"netconf_port"`
	TelnetPort   int   `yaml:"telnet_port" json:"telnet_port" mapstructure:"telnet_port"`
	SSHPort      int   `yaml:"ssh_port" json:"ssh_port" mapstructure:"ssh_port"`
	RedfishPort  int   `yaml:"redfish_port" json:"redfish_port" mapstructure:"redfish_port"`
	Enable       *bool `json:"enable" yaml:"enable" mapstructure:"enable"`

	//
	// Enable *bool `json:"enable" form:"enable" gorm:"column:enable;comment:" mapstructure:"enable"`
	//
	// EnableSsh *bool `json:"enable_ssh" form:"enable_ssh" gorm:"column:enable_ssh;comment:" mapstructure:"enable_ssh"`
	//
	// EnableTelnet *bool `json:"enable_telnet" form:"enable_telnet" gorm:"column:enable_telnet;comment:" mapstructure:"enable_telnet"`
	//
	// EnableNetconf *bool `json:"enable_netconf" form:"enable_netconf" gorm:"column:enable_netconf;comment:" mapstructure:"enable_netconf"`
	//
	// EnableRestfull *bool `json:"enable_restfull" form:"enable_restfull" gorm:"column:enable_restfull;comment:" mapstructure:"enable_restfull"`
	//
	// EnableSnmp *bool `json:"enable_snmp" form:"enable_snmp" gorm:"column:enable_snmp;comment:" mapstructure:"enable_snmp"`
	//
	// Version string `json:"version" form:"version" gorm:"column:version;comment:;type:varchar(191);size:191;" mapstructure:"version"`
	// DevTablesId  int         `json:"dev_tables_id" form:"dev_tables_id" gorm:"column:dev_tables_id;comment:;type:bigint;size:20;" mapstructure:"dev_tables_id"`
	// DcimDeviceID *uint       `json:"dcim_device_id" form:"dcim_device_id" gorm:"column:dcim_device_id;comment:;type:int;" mapstructure:"dcim_device_id"`
	// DcimDevice   *DcimDevice `json:"dcim_device" form:"dcim_device" mapstructure:"dcim_device"`
	//
	// RedfishVersion          string                 `json:"redfish_version" form:"redfish_version" gorm:"column:redfish_version;comment:;type:varchar(191);size:191;" mapstructure:"redfish_version"`
	// VirtualizationClusterID *uint                  `json:"virtualization_cluster_id" form:"virtualization_cluster_id" gorm:"column:virtualization_cluster_id;comment:;type:int;" mapstructure:"virtualization_cluster_id"`
	// VirtualizationCluster   *VirtualizationCluster `json:"virtualization_cluster" form:"virtualization_cluster" mapstructure:"virtualization_cluster"`
	//
	// SdnControllerID *uint          `json:"sdn_controller_id" form:"sdn_controller_id" gorm:"column:sdn_controller_id;comment:;type:int;" mapstructure:"sdn_controller_id"`
	// SdnController   *SdnController `json:"sdn_controller" form:"sdn_controller" mapstructure:"sdn_controller"`
	//
	// VirtualizationVirtualmachineID *uint                         `json:"virtualization_virtualmachine_id" mapstructure:"virtualization_virtualmachine_id" gorm:"column:virtualization_virtualmachine_id;type:int"`
	// VirtualizationVirtualmachine   *VirtualizationVirtualmachine `json:"virtualization_virtualmachine" mapstructure:"virtualization_virtualmachine"`

	// RedfishPort int `json:"redfish_port" form:"redfish_port" gorm:"column:redfish_port;comment:" mapstructure:"redfish_port"`
	// EnableRedfish *bool `json:"enable_redfish" form:"enable_redfish" gorm:"column:enable_redfish;comment:" mapstructure:"enable_redfish"`
}

func (L2DcimInitMeta) TableName() string {
	return "dcim_initmeta"
}
