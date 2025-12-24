package meta

import "github.com/influxdata/telegraf/controller/pkg/l3nodemap/constant"

type AuthLogin struct {
	Host        string               `json:"host" mapstructure:"host"`
	Port        int                  `json:"port" mapstructure:"port"`
	UserName    string               `json:"user_name" mapstructure:"user_name"`
	Password    string               `json:"password" mapstructure:"password"`
	AuthPass    string               `json:"auth_pass" mapstructure:"auth_pass"`
	ConnectType constant.ConnectType `json:"connect_type" mapstructure:"connect_type"`
	Community   string               `json:"community" mapstructure:"community"`
	Telnet      bool                 `json:"telnet" mapstructure:"telnet"`
}
