package config

import (
	"github.com/netxops/utils/network"

	"github.com/mitchellh/mapstructure"
)

type VsInfo struct {
	Type    string
	Network string
	Vrf     string
}

type VsRange struct {
	VsRange []*VsInfo `json:"vs_range" mapstructure:"vs_range"`
}

type ConnectionInfo struct {
	Interface string   `json:"interface" maptructure:"interface"`
	Vrf       string   `json:"vrf" maptructure:"vrf"`
	PeerVrf   []string `json:"peer_vrf" maptructure:"peer_vrf"`
}

type StubConfigInfo struct {
	// NodeName string `json:"node_name" mapstructure:"node_name" yaml:"node_name"`
	PortName string `json:"port_name" mapstructure:"port_name" yaml:"port_name"`
}

type SnatDesignInfo struct {
	From        string `json:"from" mapstructure:"from" yaml:"from"`
	To          string `json:"to" mapstructure:"to" yaml:"to"`
	FromAddress string `json:"from_address" mapstructure:"from_address" yaml:"from_address"`
	ToAddress   string `json:"to_address" mapstructure:"to_address" yaml:"to_address"`
	Pool        string `json:"pool" mapstructure:"pool" yaml:"pool"`
}

type AreaInfo struct {
	Interface string `json:"interface" mapstructure:"interface" yaml:"interface"`
	Name      string `json:"name" mapstructure:"name" yaml:"name"`
	NodeName  string `json:"node_name" mapstructure:"node_name" yaml:"node_name"`
	Force     bool   `json:"force" mapstructure:"force" yaml:"force"`
}

// SecurityZoneInfo 安全区域配置信息
// 用于通过安全区域的网段来定位节点
type SecurityZoneInfo struct {
	// ConfigZoneName 配置中的区域名称，用于与防火墙设备的接口的 Zone() 进行匹配
	ConfigZoneName string `json:"config_zone_name" mapstructure:"config_zone_name" yaml:"config_zone_name"`
	// NetworkSegments 网段列表，支持IP地址、CIDR网段等格式
	// 例如: ["192.168.1.0/24", "10.0.0.0/8"]
	NetworkSegments []string `json:"network_segments" mapstructure:"network_segments" yaml:"network_segments"`
	// NodeName 关联的节点名称
	NodeName string `json:"node_name" mapstructure:"node_name" yaml:"node_name"`
	// Vrf VRF名称（可选，用于多VRF环境）
	Vrf string `json:"vrf" mapstructure:"vrf" yaml:"vrf"`
	// Priority 优先级（可选，数字越小优先级越高，默认为0）
	Priority int `json:"priority" mapstructure:"priority" yaml:"priority"`
}

type DeviceConfig struct {
	Host              string                 `json:"host" mapstructure:"host" yaml:"host"`
	Username          string                 `json:"username" mapstructure:"username" yaml:"username"`
	Password          string                 `json:"password" mapstructure:"password" yaml:"password"`
	AuthPass          string                 `json:"auth_pass" mapstructure:"auth_pass" yaml:"auth_pass"`
	Port              int                    `json:"port" mapstructure:"port" yaml:"port"`
	Community         string                 `json:"community" mapstructure:"community" yaml:"community"`
	Mode              string                 `json:"mode" mapstructure:"mode" yaml:"mode"`
	Telnet            bool                   `json:"telnet" mapstructure:"telnet" yaml:"telnet"`
	DevTablesID       uint                   `json:"dev_tables_id" mapstructure:"dev_tables_id" yaml:"dev_tables_id"`
	Connection        []*ConnectionInfo      `json:"connection" mapstructure:"connection" yaml:"connection"`
	VsRange           []*VsInfo              `json:"vs_range" mapstructure:"vs_range" yaml:"vs_range"`
	Ipv4Area          []*AreaInfo            `json:"ipv4_area" mapstructure:"ipv4_area" yaml:"ipv4_area"`
	Ipv6Area          []*AreaInfo            `json:"ipv6_area" mapstructure:"ipv6_area" yaml:"ipv6_area"`
	Ipv4SecurityZones []*SecurityZoneInfo    `json:"ipv4_security_zones" mapstructure:"ipv4_security_zones" yaml:"ipv4_security_zones"`
	Ipv6SecurityZones []*SecurityZoneInfo    `json:"ipv6_security_zones" mapstructure:"ipv6_security_zones" yaml:"ipv6_security_zones"`
	Ipv4Stub          []*StubConfigInfo      `json:"ipv4_stub" mapstructure:"ipv4_stub" yaml:"ipv4_stub"`
	Ipv6Stub          []*StubConfigInfo      `json:"ipv6_stub" mapstructure:"ipv6_stub" yaml:"ipv6_stub"`
	Config            string                 `json:"config" mapstructure:"config" yaml:"config"`
	Token             string                 `json:"token" mapstructure:"token" yaml:"token"`
	Snat              []*SnatDesignInfo      `json:"snat" mapstructure:"snat" yaml:"snat"`
	MetaData          map[string]interface{} `json:"metadata" mapstructure:"metadata" yaml:"metadata"`
	// Naming      struct {
	// 	PolicyTemplate string `json:"policy_template" mapstructure:"policy_template" yaml:"policy_template"`
	// 	ObjectTemplate string `json:"object_template" mapstructure:"object_template" yaml:"object_template"`
	// } `json:"naming" mapstructure:"naming" yaml:"naming"`
}

func NewDeviceConfig(device interface{}) *DeviceConfig {
	var config DeviceConfig
	mapstructure.Decode(device, &config)
	return &config
}

func (dc *DeviceConfig) WithToken(token string) *DeviceConfig {
	dc.Token = token
	return dc
}

func (dc *DeviceConfig) WithTelnet() *DeviceConfig {
	dc.Telnet = true
	return dc
}

func (dc *DeviceConfig) WithConnection(connection interface{}) *DeviceConfig {
	var infoList []*ConnectionInfo
	if err := mapstructure.Decode(connection, &infoList); err != nil {
		panic(err)
	}

	dc.Connection = append(dc.Connection, infoList...)
	return dc
}

func (dc *DeviceConfig) WithVsRange(vs interface{}) *DeviceConfig {
	var vsInfoList []*VsInfo
	if err := mapstructure.Decode(vs, &vsInfoList); err != nil {
		panic(err)
	}
	dc.VsRange = append(dc.VsRange, vsInfoList...)
	return dc
}

func (dc *DeviceConfig) WithArea(area interface{}, af network.IPFamily) *DeviceConfig {
	var infoList []*AreaInfo
	if err := mapstructure.Decode(area, &infoList); err != nil {
		panic(err)
	}

	if af == network.IPv4 {
		dc.Ipv4Area = append(dc.Ipv4Area, infoList...)
	} else {
		dc.Ipv6Area = append(dc.Ipv6Area, infoList...)
	}

	return dc
}
