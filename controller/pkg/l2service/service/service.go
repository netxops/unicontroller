package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish/chaoqing"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs/mlnxos"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs/ruijie"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/fw"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/lb"

	"github.com/influxdata/telegraf/controller/pkg/l2service/service/sdn/adapter/aci"
	"github.com/netxops/log"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/check"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/vmware/vm"
	"github.com/influxdata/telegraf/controller/pkg/structs"

	"github.com/netxops/utils/tools"

	clitask "github.com/netxops/utils/task"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/linux"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish/dell"
	redfishH3C "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish/h3c"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish/hp"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish/lenovo"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish/nettrix"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish/sugon"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs/h3c"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs/huawei"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs/ios"
	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/switchs/nexus"

	// aci "github.com/netxops/unify/cmd/sdn/adapter/aci"
	huaweiSDN "github.com/influxdata/telegraf/controller/pkg/l2service/service/sdn/adapter/huawei"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	DEFAULT_SERVICE_FILE    = "../config/service.yaml"
	Config                  = &ServiceConfig{}
	DEFAULT_SSH_CMD_TIMEOUT = 5
	// DEFAULT_NEWL2SERVICE_FILE = "../internal/app/service/l2service/service.yaml.back"
	DEFAULT_NEWL2SERVICE_FILE = "../config/service.yaml"
)

var svsLogger *zap.Logger

func init() {
	svsLogger, _ = zap.NewDevelopment(zap.AddCallerSkip(1))
}

func ServiceConfigViper(path string) {
	v := viper.New()
	v.SetConfigFile(path)

	err := v.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	v.WatchConfig()

	v.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("config file changed:", e.Name)
		Config = &ServiceConfig{}
		if err := v.Unmarshal(Config); err != nil {
			fmt.Println(err)
		}
	})

	if err := v.Unmarshal(Config); err != nil {
		fmt.Println(err)
	}

}

//
// var MethodMap map[string]func(dev *structs.DevTables) *clitask.Table = map[string]func(dev *structs.DevTables) *clitask.Table{
// "IOS_ARP_V16": ios.Arp,
// "NEXUS_ARP_V9": nexus.ArpTable{}.Arp,
// }

// L2NodemapInstanceInterface包含Process方法，该方法是不同类型设备的处理入口
func NewInstance(mode string, isRedfish bool, localDataPath string) structs.L2NodemapInstanceInterface {
	var instance structs.L2NodemapInstanceInterface
	if isRedfish {
		switch strings.ToUpper(mode) {
		case "DELL":
			instance = &dell.Dell{}
		case "CHAOQING":
			instance = &chaoqing.ChaoQing{}
		case "HP":
			instance = &hp.Hp{}
		case "LENOVO":
			instance = &lenovo.Lenovo{}
		case "SUGON":
			instance = &sugon.Sugon{}
		case "NETTRIX":
			instance = &nettrix.Nettrix{}
		case "H3C":
			instance = &redfishH3C.H3C{}
		case "HUAWEI":
			instance = &huawei.HuaWei{}
		}

		return instance
	}

	switch strings.ToUpper(mode) {
	case "IOS":
		instance = &ios.IOS{}
	case "NEXUS":
		instance = &nexus.Nexus{}
	case "RUIJIE":
		instance = &ruijie.Ruijie{}
	case "COMWARE":
		instance = &h3c.H3C{}
	case "VRP":
		instance = &h3c.H3C{}
	case "HUAWEI":
		instance = &huawei.HuaWei{}
	case "ACI":
		instance = &aci.ACI{}
	case "HUAWEISDN":
		instance = &huaweiSDN.HuaWeiSDN{}
	case "VMWARE":
		instance = &vm.Vmware{}
	case "LINUX":
		instance = &linux.Linux{LocalDataPath: localDataPath}
	case "UBUNTU":
		instance = &linux.Linux{LocalDataPath: localDataPath}
	case "MLNXOS":
		instance = &mlnxos.Mlnxos{}
	case "CENTOS":
		instance = &linux.Linux{LocalDataPath: localDataPath}
	case "REDHAT":
		instance = &linux.Linux{LocalDataPath: localDataPath}
	case "EXCELCHECK":
		instance = &check.ExcelCheck{}
	case "ASA":
		instance = &fw.Asa{}
	case "F5":
		instance = &lb.F5{}
	case "FORTIGATE":
		instance = &fw.Forti{}
	case "SANGFOROS":
		instance = &fw.Sangfor{}
	case "USG":
		instance = &fw.Usg{}
	case "DPTECH":
		instance = &fw.Dptech{}
	case "SECPATH":
		instance = &fw.SecPath{}
	case "DEBIAN":
		instance = &linux.Linux{LocalDataPath: localDataPath}
	case "ALMALINUX":
		instance = &linux.Linux{LocalDataPath: localDataPath}
	default:
		panic(fmt.Sprintf("unsupport mode=%s", mode))
	}

	return instance
}

type ServiceConfig struct {
	Service []*ServiceModeConfig
}

type selectMatchedPair struct {
	Name    string
	Matched bool
}

type selectDescrib struct {
	ManufacturerPair selectMatchedPair
	Service          selectMatchedPair
	IsRedfish        bool
}

func (s selectDescrib) Ok() bool {
	return s.ManufacturerPair.Matched && s.Service.Matched
}

func (s selectDescrib) Error() error {
	if !s.ManufacturerPair.Matched {
		return fmt.Errorf("Unsupport manufacturer %q", s.ManufacturerPair.Name)
	}

	if !s.Service.Matched {
		return fmt.Errorf("Unsupport service name %q", s.Service.Name)
	}

	return nil
}

func (sc ServiceConfig) Select(ctx context.Context, remote *structs.L2DeviceRemoteInfo, srv string) (structs.L2NodemapServiceInterface, structs.OK) {
	logger := log.NewLogger(remote.ActionID, true)
	describ := selectDescrib{}
	describ.ManufacturerPair.Name = remote.Manufacturer
	describ.Service.Name = srv
	describ.IsRedfish = remote.IsRedfish
	dataPath := ctx.Value("local_data_path")
	var dp string
	if dataPath != nil {
		dp = dataPath.(string)
	}

	logger.Debug("ServiceConfig.Select",
		log.Tag("remote", remote),
		zap.Any("srv", srv))
	if remote.IsRedfish {
		for _, c := range sc.Service {
			if strings.ToLower(c.Manufacturer) == strings.ToLower(remote.Manufacturer) {
				describ.ManufacturerPair.Matched = true
				instance := NewInstance(c.Manufacturer, remote.IsRedfish, dp)
				for _, s := range c.Service {
					if strings.ToLower(s.Name) == strings.ToLower(srv) {
						describ.Service.Matched = true
						s.WithInstance(instance)
						logger.Debug("ServiceConfig.Select", zap.Any("selected", true), zap.Any("serviceName", s.Name),
							zap.Any("instance", fmt.Sprintf("%T", instance)))
						return s, describ
					}
				}
			}
		}
	} else {
		for _, c := range sc.Service {
			if strings.ToLower(c.Platform) == strings.ToLower(remote.Platform) {
				instance := NewInstance(c.Platform, remote.IsRedfish, dp)
				describ.ManufacturerPair.Matched = true

				for _, s := range c.Service {
					if strings.ToLower(s.Name) == strings.ToLower(srv) {
						describ.Service.Matched = true
						s.WithInstance(instance)
						logger.Debug("ServiceConfig.Select", zap.Any("selected", true), zap.Any("serviceName", s.Name),
							zap.Any("instance", fmt.Sprintf("%T", instance)))
						return s, describ
					}
				}
			}
		}
	}

	return nil, describ
}

type Option func(*ServiceModeConfig)

// 选择器
type ServiceModeConfig struct {
	Platform     string
	Manufacturer string
	Catalog      string
	Service      []*Service
	instance     interface{}
}

// 选择器中具体的服务列表
type Service struct {
	Name     string                             `yaml:"name" json:"name" mapstructure:"name"`
	Snmp     []*SnmpTaskConfig                  `yaml:"snmp" json:"snmp" mapstructure:"snmp"`
	Restful  []*RestfulTaskConfig               `yaml:"restful" json:"restful" mapstructure:"restful"`
	SSH      []*SSHTaskConfig                   `yaml:"ssh" json:"ssh" mapstructure:"ssh"`
	Redfish  []*RedfishTaskConfig               `yaml:"redfish" json:"redfish" mapstructure:"redfish"`
	Gofish   []*GofishTaskConfig                `yaml:"gofish" mapstructure:"gofish" json:"gofish"`
	Sdn      []*SdnTaskConfig                   `yaml:"sdn" mapstructure:"sdn" json:"sdn"`
	Rshell   []*RshellTaskConfig                `yaml:"rshell" mapstructure:"rshell" json:"rshell"`
	Vmware   []*VmwareTaskConfig                `yaml:"vmware" json:"vmware" mapstructure:"vmware"`
	Excel    []*CheckTaskConfig                 `yaml:"excel" json:"excel" mapstructure:"excel"`
	IPMI     []*IPMITaskConfig                  `yaml:"ipmi" json:"ipmi" mapstructure:"ipmi"`
	instance structs.L2NodemapInstanceInterface `yaml:"instance" json:"instance" mapstructure:"instance"`
}

func (s *Service) WithInstance(instance structs.L2NodemapInstanceInterface) {
	s.instance = instance
}

func (s Service) ServiceName() string {
	return s.Name
}

func (s Service) Run(remote *structs.L2DeviceRemoteInfo, options ...interface{}) (resultTable *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	hited := 0
	if remote.IsRedfish {
		taskConfigList := []structs.L2NodemapTaskConfigInterface{}
		for _, p := range s.Gofish {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.Redfish {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.Snmp {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.IPMI {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.SSH {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range taskConfigList {
			if p.IsSelected(remote.RedfishVersion, remote.DeviceType) {
				p.WithMainConfig(Config)
				resultTable, err = s.instance.Process(remote, p, options...)
				hited++
				logger.Debug("Service.Run",
					zap.Any("redfish_version", remote.RedfishVersion),
					zap.Any("hited", hited),
					zap.Any("count", clitask.RowCount(resultTable)),
					zap.Any("task_config", p),
					zap.Error(err))
			}

			if resultTable != nil && !resultTable.IsEmpty() {
				return
			}
		}
	} else {
		// version := remote.Meta.Version
		taskConfigList := []structs.L2NodemapTaskConfigInterface{}
		for _, p := range s.Snmp {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.Restful {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.SSH {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.Rshell {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.Sdn {
			taskConfigList = append(taskConfigList, p)
		}
		for _, p := range s.Excel {
			taskConfigList = append(taskConfigList, p)
		}

		for _, p := range s.Vmware {
			taskConfigList = append(taskConfigList, p)
		}

		for _, p := range taskConfigList {
			if p.IsSelected(remote.Meta.Version, remote.DeviceType) {
				p.WithMainConfig(Config)
				resultTable, err = s.instance.Process(remote, p, options...)
				hited++
				logger.Debug("Service.Run",
					zap.Any("version", remote.Meta.Version),
					zap.Any("hited", hited),
					zap.Any("count", clitask.RowCount(resultTable)),
					zap.Any("task_config", p),
					zap.Error(err))
			}

			if resultTable != nil && !resultTable.IsEmpty() {
				return
			}
		}

	}
	logger.Info("Service.Run",
		zap.Any("redfish_version", remote.RedfishVersion),
		zap.Any("version", remote.Meta.Version),
		zap.Any("hited", hited),
		// zap.Any("result_table", resultTable),
		zap.Error(err))

	return
}

type BaseTaskConfig struct {
	Version    []string                                `yaml:"version" mapstructure:"version"`
	Method     string                                  `yaml:"method" mapstructure:"method"`
	Type       []string                                `yaml:"type" mapstructure:"type"`
	mainConfig structs.L2NodemapServiceCenterInterface `yaml:"main_config" mapstructure:"main_config"`
	Pretty     bool                                    `yaml:"pretty" mapstructure:"pretty"`
	// localDataPath string                                  `yaml:"-"`
}

//
// func (s *BaseTaskConfig) withLocalDataPath(path string) {
// s.localDataPath = path
// }
//
// func (s *BaseTaskConfig) LocalDataPath() string {
// return s.localDataPath
// }

func (s *BaseTaskConfig) WithMainConfig(cf structs.L2NodemapServiceCenterInterface) {
	s.mainConfig = cf
}

func (s BaseTaskConfig) GetMainConfig() structs.L2NodemapServiceCenterInterface {
	return s.mainConfig
}

func (s BaseTaskConfig) GetMethod() string {
	return s.Method
}

func (s BaseTaskConfig) IsSelected(version, deviceType string) bool {
	if len(s.Type) > 0 {
		return tools.ContainsWithoutCase(s.Type, deviceType) && tools.ContainsVersion(s.Version, version)
	} else {
		return tools.ContainsVersion(s.Version, version)
	}
}

func (s BaseTaskConfig) SupportVersion() []string {
	return s.Version
}

func (s BaseTaskConfig) IsPretty() bool {
	return s.Pretty
}
