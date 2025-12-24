package meta

import "github.com/influxdata/telegraf/controller/pkg/l3nodemap/constant"

type MetaNode struct {
	Name                   string                    `json:"name" mapstructure:"name"`
	NodeType               constant.DeviceCategory   `json:"node_type" mapstructure:"node_type"`
	Model                  constant.SpecificCategory `json:"model" mapstructure:"model"`
	AuthLogin              AuthLogin                 `json:"auth_login" mapstructure:"auth_login"`
	DeviceInterconnections []DeviceInterconnection   `json:"device_interconnections" mapstructure:"device_interconnections"`
	VsRanges               []VsRange                 `json:"vs_ranges" mapstructure:"vs_ranges"`
	Ipv4Areas              []Area                    `json:"ipv4_areas" mapstructure:"ipv4_areas"`
	Ipv6Areas              []Area                    `json:"ipv6_areas" mapstructure:"ipv6_areas"`
	Ipv4Stubs              []Stub                    `json:"ipv4_stubs" mapstructure:"ipv4_stubs"`
	Ipv6Stubs              []Stub                    `json:"ipv6_stubs" mapstructure:"ipv6_stubs"`
}
