package config

import (
	"fmt"

	"github.com/netxops/utils/snmp"
	"github.com/spf13/viper"

	// "gopkg.in/fsnotify.v1"
	"github.com/fsnotify/fsnotify"
)

//
// import (
// "fmt"
//
// "github.com/netxops/utils/snmp"
//
// "github.com/fsnotify/fsnotify"
//
// "github.com/spf13/viper"
// )
//
type Server struct {
	Mysql        Mysql        `mapstructure:"mysql" json:"mysql" yaml:"mysql"`
	Etcd         Etcd         `mapstructure:"etcd" json:"etcd" yaml:"etcd"`
	Redis        Redis        `mapstructure:"redis" json:"redis" yaml:"reids"`
	DeployFolder DeployFolder `mapstructure:"deploy_folder" json:"deploy_folder" yaml:"deploy_folder"`
	PluginFolder PluginFolder `mapstructure:"plugin_folder" json:"plugin_folder" yaml:"plugin_folder"`
	SecretKey    SecretKey    `mapstructure:"secret_key" json:"secret_key" yaml:"secret_key"`
	RoleConfig   RoleConfig   `mapstructure:"role_config" json:"role_config" yaml:"role_config"`
}

type EachRole struct {
	Type string `json:"type" yaml:"type" mapstructure:"type"`
	Name string `json:"name" yaml:"name" mapstructure:"name"`
}

type RoleConfig struct {
	InbandSecret   EachRole `json:"inbandSecret" yaml:"inbandSecret" mapstructure:"inbandSecret"`
	OutbandSecret  EachRole `json:"outbandSecret" yaml:"outbandSecret" mapstructure:"outbandSecret"`
	OutbandRedfish EachRole `json:"outbandRedfish" yaml:"outbandRedfish" mapstructure:"outbandRedfish"`
	InbandSnmp     EachRole `json:"inbandSnmp" yaml:"inbandSnmp" mapstructure:"inbandSnmp"`
	OutbandSnmp    EachRole `json:"outbandSnmp" yaml:"outbandSnmp" mapstructure:"outbandSnmp"`
	VmwareSecret   EachRole `json:"vmwareSecret" yaml:"vmwareSecret" mapstructure:"vmwareSecret"`
}

//
type PlatForm struct {
	Device map[string][]DeviceInfo `yaml:"device"`
}

type DeviceInfo struct {
	Manufacture string   `yaml:"Manufacture"`
	Mode        string   `yaml:"Mode"`
	Type        string   `yaml:"Type"`
	Version     []string `yaml:"Version"`
}

var (
	DEFAULT_CONFIG_FILE     = "../snmp.yaml"
	TaskSnmp                snmp.TaskSnmp
	DEFAULT_L2NEWCONFIG_FIL = "../internal/app/service/l2service/snmp.yaml"
)

func SnmpViper(path string) {
	v := viper.New()
	v.SetConfigFile(path)

	err := v.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	v.WatchConfig()

	v.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("config file changed:", e.Name)
		if err := v.Unmarshal(&TaskSnmp); err != nil {
			fmt.Println(err)
		}
	})

	if err := v.Unmarshal(&TaskSnmp); err != nil {
		fmt.Println(err)
	}
	// fmt.Println("======================task", TaskSnmp)

}

//
type Infor struct {
	Information Information `mapstructure:"information" json:"information" yaml:"information"`
}

type PluginInfor struct {
	PInformation Information `mapstructure:"information" json:"information" yaml:"information"`
}

type Desc struct {
	Infor        Infor         `mapstructure:"infor" json:"infor" form:"infor"`
	PluginInfors []PluginInfor `mapstructure:"plugin_infor" json:"plugin_infor" form:"plugin_infor"`
}

type Excel struct {
	Dir       string `mapstructure:"dir" json:"dir" yaml:"dir"`
	ExcelName string `mapstructure:"excel_name" json:"excel_name" yaml:"excel_name"`
}

type DeployFolder struct {
	Dir string `mapstructure:"dir" json:"dir" yaml:"dir"`
}

type PluginFolder struct {
	Dir string `mapstructure:"dir" json:"dir" yaml:"dir"`
}

type Information struct {
	TarName      string   `json:"tar_name" mapstructure:"tar-name" yaml:"tar-name"`
	MainFileName string   `json:"main_file_name" mapstructure:"main-file-name" yaml:"main-file-name"`
	Version      string   `mapstructure:"version" json:"version" yaml:"version"`
	SavePath     string   `mapstructure:"save-path" json:"save_path" yaml:"save-path"`
	DeployPath   string   `mapstructure:"deploy-path" json:"deploy_path" yaml:"deploy-path"`
	Md5          string   `mapstructure:"md5" json:"md5" yaml:"md5"`
	UpdateTime   string   `mapstructure:"update-time" json:"update_time" yaml:"update-time"`
	FileSize     int      `mapstructure:"file-size" json:"file_size" yaml:"file-size"`
	Plugins      []string `mapstructure:"plugins" json:"plugins" yaml:"plugins"`
	Plugin       string   `mapstructure:"plugin" json:"plugin" yaml:"plugin"`
}

type SecretKey struct {
	MasterKey string `mapstructure:"master_key" json:"master_key" yaml:"master_key"`
}
