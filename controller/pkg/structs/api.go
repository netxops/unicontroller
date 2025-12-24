package structs

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"
	"github.com/netxops/utils/action_id"
	"github.com/netxops/utils/policy"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/validator"
	"gorm.io/gorm"
)

type L2DeviceMeta struct {
	// ID           uint
	// Meta         Meta
	// DcimDeviceID *uint

	ID                             uint           `gorm:"primarykey" mapstructure:"id"`
	CreatedAt                      time.Time      `mapstructure:"createdAt"`
	UpdatedAt                      time.Time      `mapstructure:"updatedAt"`
	DeletedAt                      gorm.DeletedAt `gorm:"index" json:"-" mapstructure:"deletedAt"`
	Meta                           `mapstructure:", squash"`
	DcimDeviceID                   *uint  `json:"dcim_device_id" form:"dcim_device_id" gorm:"column:dcim_device_id;comment:;type:int;" mapstructure:"dcim_device_id"`
	RedfishVersion                 string `json:"redfish_version" form:"redfish_version" gorm:"column:redfish_version;comment:;type:varchar(191);size:191;" mapstructure:"redfish_version"`
	VirtualizationClusterID        *uint  `json:"virtualization_cluster_id" form:"virtualization_cluster_id" gorm:"column:virtualization_cluster_id;comment:;type:int;" mapstructure:"virtualization_cluster_id"`
	SdnControllerID                *uint  `json:"sdn_controller_id" form:"sdn_controller_id" gorm:"column:sdn_controller_id;comment:;type:int;" mapstructure:"sdn_controller_id"`
	VirtualizationVirtualmachineID *uint  `json:"virtualization_virtualmachine_id" mapstructure:"virtualization_virtualmachine_id" gorm:"column:virtualization_virtualmachine_id;type:int"`
	// EnableRedfish *bool `json:"enable_redfish" form:"enable_redfish" gorm:"column:enable_redfish;comment:" mapstructure:"enable_redfish"`
}

type Meta struct {
	RestfullPort   int    `yaml:"restfull_port" json:"restfull_port" mapstructure:"restfull_port"`
	NetconfPort    int    `yaml:"netconf_port" json:"netconf_port" mapstructure:"netconf_port"`
	TelnetPort     int    `yaml:"telnet_port" json:"telnet_port" mapstructure:"telnet_port"`
	SSHPort        int    `yaml:"ssh_port" json:"ssh_port" mapstructure:"ssh_port"`
	IPMIPort       int    `yaml:"ipmi_port" json:"ipmi_port" mapstructure:"ipmi_port"`
	RedfishPort    int    `yaml:"redfish_port" json:"redfish_port" mapstructure:"redfish_port"`
	Enable         *bool  `json:"enable" yaml:"enable" mapstructure:"enable" log:"enable"`
	EnableSSH      *bool  `yaml:"enable_ssh" json:"enable_ssh" mapstructure:"enable_ssh" log:"enable_ssh"`
	EnableTelnet   *bool  `yaml:"enable_telnet" json:"enable_telnet" mapstructure:"enable_telnet"`
	EnableNetconf  *bool  `yaml:"enable_netconf" json:"enable_netconf" mapstructure:"enable_netconf"`
	EnableRestfull *bool  `yaml:"enable_restfull" json:"enable_restfull" mapstructure:"enable_restfull"`
	EnableIPMI     *bool  `json:"enable_ipmi" yaml:"enable_ipmi" mapstructure:"enable_ipmi"`
	EnableSnmp     *bool  `yaml:"enable_snmp" json:"enable_snmp" mapstructure:"enable_snmp"`
	EnableRedfish  *bool  `yaml:"enable_redfish" json:"enable_redfish" mapstructure:"enable_redfish" log:"enable_redfish"`
	Version        string `yaml:"version" json:"version" mapstructure:"version" log:"version"`
	PatchVersion   string `yaml:"patch_version" json:"patch_version" mapstructure:"patch_version" log:"patch_version"`
	RedfishVersion string `yaml:"redfish_version" mapstructure:"redfish_version" json:"redfish_version" log:"redfish_version"`
	SNMPVersion    string `yaml:"snmp_version" json:"snmp_version" mapstructure:"snmp_version" log:"snmp_version"`
	SNMPTimeout    int    `yaml:"snmp_timeout" json:"snmp_timeout" mapstructure:"snmp_timeout"`
	SNMPRetries    int    `yaml:"snmp_retries" json:"snmp_retries" mapstructure:"snmp_retries"`
	SNMPPort       int    `yaml:"snmp_port" json:"snmp_port" mapstructure:"snmp_port"`
	// IPMIVersion    string `yaml:"ipmi_version" json:"ipmi_version" mapstructure:"ipmi_version"`
}

type L2DeviceRemoteInfo struct {
	ID             uint               `yaml:"id" json:"id" mapstructure:"id"`
	Uuid           string             `yaml:"uuid" mapstructure:"uuid"`
	Ip             string             `yaml:"ip" mapstructure:"ip" json:"ip" log:"ip"`
	DeviceName     string             `yaml:"device_name" mapstructure:"device_name" json:"device_name" log:"device_name"`
	Username       string             `yaml:"username" mapstructure:"username" json:"username" log:"username"`
	Password       string             `yaml:"password" mapstructure:"password" json:"password" log:"password"`
	AuthPass       string             `yaml:"auth_pass" mapstructure:"auth_pass" json:"auth_pass" log:"auth_pass"`
	PrivateKey     string             `yaml:"private_key" json:"private_key" mapstructure:"private_key"`
	Community      []string           `yaml:"community" mapstructure:"community" json:"community" log:"community"`
	Platform       string             `yaml:"platform" mapstructure:"platform" json:"platform" log:"platform"`
	Catalog        string             `yaml:"catalog" json:"catalog" mapstructure:"catalog" log:"catalog"`
	Manufacturer   string             `yaml:"manufacturer" json:"manufacturer" mapstructure:"manufacturer" log:"manufacturer"`
	RedfishVersion string             `yaml:"redfish_version" mapstructure:"redfish_version" json:"redfish_version" log:"redfish_version"`
	MetaID         uint               `yaml:"meta_id" json:"meta_id" mapstructure:"meta_id"`
	IsRedfish      bool               `yaml:"is_redfish" json:"is_redfish" mapstructure:"is_redfish" log:"is_redfish"`
	Meta           Meta               `yaml:"meta" mapstructure:"meta" json:"meta" log:"meta"`
	TaskId         string             `yaml:"task_id" json:"task_id" mapstructure:"task_id"`
	DeviceType     string             `yaml:"device_type" json:"device_type" mapstructure:"device_type" log:"device_type"`
	Site           string             `yaml:"site" mapstructure:"site" json:"site"`
	Env            string             `yaml:"env" mapstructure:"env" json:"env"`
	ActionID       action_id.ActionID `yaml:"action_id" mapstructure:"action_id" json:"action_id"`
	AuthCmd        string             `json:"auth_cmd" yaml:"auth_cmd" mapstructure:"auth_cmd"`
	Token          string             `json:"token" yaml:"token" mapstructure:"token"`
	TimeOut        int                `json:"time_out" yaml:"time_out" mapstructure:"time_out"`
	Snmp           Snmp               `json:"snmp" yaml:"snmp" mapstructure:"snmp"`
}

type Snmp struct {
	SnmpVersion  string `yaml:"snmp_version" json:"snmp_version" mapstructure:"snmp_version"`
	AuthProtocol string `yaml:"auth_protocol" json:"auth_protocol" mapstructure:"auth_protocol"`
	PrivProtocol string `yaml:"priv_protocol" json:"priv_protocol" mapstructure:"priv_protocol"`
	PrivPass     string `yaml:"priv_pass" json:"priv_pass" mapstructure:"priv_pass"`
}

type ValidateFunc func(map[string]interface{}) validator.Result

func NewValidator() *normalValidator {
	return &normalValidator{}
}

type normalValidator struct {
	opts []ValidateFunc
}

func (nv *normalValidator) ValidateRemoteInfo(remote L2DeviceRemoteInfo) validator.Result {
	d := map[string]interface{}{
		"data": remote,
	}
	return nv.Validate(d)
}

func (nv *normalValidator) Options(fn ValidateFunc) *normalValidator {
	nv.opts = append(nv.opts, fn)
	return nv
}

func (nv *normalValidator) WithL3Options() *normalValidator {
	return nv.Options(
		func(data map[string]interface{}) (result validator.Result) {
			remote := data["data"].(L2DeviceRemoteInfo)
			if remote.DeviceName == "" {
				return validator.NewValidateResult(false, "DEVICE NAME字段为空")
			}

			return validator.NewValidateResult(true, "")
		})
}

func (nv *normalValidator) WithDeviceType() *normalValidator {
	return nv.Options(
		func(data map[string]interface{}) (result validator.Result) {
			remote := data["data"].(L2DeviceRemoteInfo)
			if remote.DeviceName == "" {
				return validator.NewValidateResult(false, "DEVICE TYPE字段为空")
			}

			return validator.NewValidateResult(true, "")
		})
}

func (nv *normalValidator) WithCommunify() *normalValidator {
	return nv.Options(
		func(data map[string]interface{}) (result validator.Result) {
			remote := data["data"].(L2DeviceRemoteInfo)
			if len(remote.Community) == 0 {
				return validator.NewValidateResult(false, "COMMUNITY字段为空")
			}

			return validator.NewValidateResult(true, "")
		})
}

//
// func NormalValidate(remote L2DeviceRemoteInfo) validator.Result {
// d := map[string]interface{}{
// "data": remote,
// }
//
// return normalValidator{}.Validate(d)
// }

func (nv normalValidator) Validate(d map[string]interface{}) (result validator.Result) {
	if d == nil || len(d) == 0 {
		return validator.NewValidateResult(false, "L2DeviceRemoteInfo校验参数为空")
	}

	if _, ok := d["data"]; !ok {
		return validator.NewValidateResult(false, "L2DeviceRemoteInfo为空")
	}

	var data L2DeviceRemoteInfo
	var ok bool

	data, ok = d["data"].(L2DeviceRemoteInfo)
	if !ok {
		return validator.NewValidateResult(false, "L2DeviceRemoteInfo类型错误")
	}

	if len(data.Ip) == 0 {
		return validator.NewValidateResult(false, "IP字段为空")
	}

	if data.ActionID.Zero() {
		return validator.NewValidateResult(false, "ACTION ID内容为空")
	}

	if len(data.Platform) == 0 {
		return validator.NewValidateResult(false, "PLATFORM字段为空")
	}

	if len(data.Catalog) == 0 {
		return validator.NewValidateResult(false, "CATALOG字段为空")
	}

	if len(data.Manufacturer) == 0 {
		return validator.NewValidateResult(false, "MANUFACTURER字段为空")
	}

	meta := data.Meta
	if meta.Enable != nil && !*meta.Enable {
		return validator.NewValidateResult(false, "Meta Enable字段为空或false")
	}

	if data.IsRedfish {
		if meta.EnableRedfish != nil && !*meta.EnableRedfish {
			return validator.NewValidateResult(false, "Meta EnableRedfish字段为空或false")
		}
		if meta.RedfishVersion == "" && data.RedfishVersion == "" {
			return validator.NewValidateResult(false, "Meta RedfishVersion字段为空")
		}

		if meta.RedfishPort == 0 {
			return validator.NewValidateResult(false, "Meta RedfishPort字段为0")
		}
	} else {
		if meta.TelnetPort == 0 && meta.SSHPort == 0 && meta.RestfullPort == 0 {
			return validator.NewValidateResult(false, "Meta Telenet、SSH、Restfull端口都为0")
		}
	}

	if data.Site == "" && data.Env == "" {
		return validator.NewValidateResult(false, "SITE和ENV同时为空")
	}

	for _, opt := range nv.opts {
		if r := opt(d); !r.Status() {
			return r
		}
	}

	return validator.NewValidateResult(true, "")
}

type Metrics struct {
	Method     string    `json:"method"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Duration   float64   `json:"duration"`
	Error      error     `json:"error"`
	Total      int       `json:"total"`
	Success    int       `json:"success"`
	Failed     int       `json:"failed"`
	Challenged int       `json:"challenged"`
}

type MetaReply struct {
	Meta *Meta
	Metrics
}

type Reply struct {
	Table       *clitask.Table
	Result      []map[string]string
	RawData     []byte
	FileData    map[string][][]string
	FileNameMap map[string][]string
	Uuid        string
	MasterKey   string
	Metrics
	Meta *Meta
}

//
// type TopoServerType int
//
// func (t TopoServerType) String() string {
// return []string{"SYSTEM_NAME", "IFTABLE", "Dot1dPorts", "PORTIP", "VLAN", "Stp",
// "MacTable", "Arps", "NeighborCdp", "Neighbor", "NeighborLldp", "Other", "YAML_ARP",
// "Port_Statistics", "Port_Channel", "Ipv6_Neighbor", "REDFISH_CPU", "REDFISH_MEM", "REDFISH_DISK",
// "REDFISH_VERSION", "REDFISH_NETWORKINTERFACE", "REDFISH_BMC", "REDFISH_BASEINFO", "REDFISH_NETWORK", "VMWARE_RESOURCES", "REDFISH_POWER",
// "VMWARE_VM", "VMWARE_TEMPLATE", "VMWARE_DATASTORE", "VMWARE_INFO", "VMWARE_INTERFACES",
// "SDN_FABRIC", "SDN_VPC", "SDN_LOGICPORT", "LINUX_IFCONFIG_INTERFACES", "LINUX_BATCH_CMD", "LINUX_STEP_CMD", "META", "DEVICEMETA", "VZENTRY", "SDN_GET", "SDN_FABRICAPATHEP",
// "SDN_FABRICINST", "SDN_FVBD", "SDN_EPTRACKER", "SDN_VZBRCP", "SDN_FABRICPATHEP", "SDN_CONTROLLER", "SDN_CONTROLLERSSIZE",
// "SDN_FVAP", "SDN_FVSUBNET", "SDN_FORTYPOLICY", "SDN_FORTISUBNET", "SDN_FORTISERVICE", "SDN_FIRMWARE", "SDN_VZFILTER",
// "SDN_VZENTRY", "SDN_CONTRACT", "SDN_INFRA", "SDN_FABRIC2", "CHECKDEVICE"}[t-1]
// }
//
// type ServiceSelect struct {
// Site string
// Env  string
// }

type Request interface {
	ActionID() action_id.ActionID
	Site() string
	Env() string
}

type Args struct {
	ServiceType string `log:"service_type"`
	Uuid        string
	Id          uint
	Ip          string `log:"ip"`
	Platform    string `log:"platform"`
	IsRedfish   bool
	Remote      *L2DeviceRemoteInfo `log:"remote"`
	Meta        *L2DeviceMeta       `log:"-"`
	DevType     string
	Options     []interface{} `log:"-"`
	DeviceConfig
}

func (a *Args) ActionID() action_id.ActionID {
	return a.Remote.ActionID
}

func (a *Args) Site() string {
	return a.Remote.Site
}

func (a *Args) Env() string {
	return a.Remote.Env
}

func (a *Args) KeyMap() (m map[string]string) {
	m = make(map[string]string)
	m["ip"] = a.Ip
	m["platform"] = a.Remote.Platform
	m["catalog"] = a.Remote.Catalog
	m["device"] = a.Remote.DeviceName
	m["manufacturer"] = a.Remote.Manufacturer
	m["type"] = a.Remote.DeviceType
	m["username"] = a.Remote.Username
	m["site"] = a.Remote.Site
	m["env"] = a.Remote.Env

	m["version"] = ""
	m["redfish"] = ""
	if a.Meta != nil {
		m["version"] = a.Meta.Version
		m["redfish"] = a.Meta.RedfishVersion
	}

	m["private_key"] = "false"
	if a.Remote.PrivateKey != "" {
		m["private_key"] = "true"
	}
	// m["ctx_id"] = a.Remote.CtxID

	return m
}

type SyncArgs struct {
	ServiceType SyncServerType
	Id          uint
	Ip          string
	StructType  string
	Platform    string
	DataMap     map[string]string
	BulkGetPath map[string][]string
	CsvInfo     CsvInfo
}

type CsvInfo struct {
	NewFolder    string
	OldFolder    string
	FileNameList []string
	CsvData      [][]string
}

type ExcelStruct struct {
	Address []map[string]string
	Prefix  []map[string]string
}

type SyncReply struct {
	ExcelStruct    *ExcelStruct
	Result         []map[string]string
	FileData       map[string][][]string
	FileNameMap    map[string][]string
	ValidateResult map[string][]string
	MasterKey      string
	FileSizeMap    map[string]string
	ZipDataMap     map[string][]byte
	WorkorderData  []*WorkorderData
}

type WorkorderData struct {
	WorkorderDir string
	CsvData      [][]string
	ZipData      []byte
	FileInfos    []*FileInfo
}

type FileInfo struct {
	FileName string
	FileMD5  string
}

type SyncServerType int

const (
	_ SyncServerType = iota
	IPAddressManager
	DIR
	GET
	PUT
	BULK_GET
	WorkorderDir
)

type DeviceWithMeta interface {
	Meta() *L2DeviceMeta
}

type DeviceWithPlatform interface {
	Catalog() string
	Platform() string
	Manufacturer() string
	DeviceType() string
	DeviceID() uint
	OutOfBound() string
	InBound() string
	DeviceName() string
	StructType() string
	Env() string
	Site() string
	// Meta() *L2DeviceMeta
}

type DeviceWithPlatform2 interface {
	CatalogName() string
	PlatformName() string
	ManufacturerName() string
	DeviceModelName() string
	DeviceCode() string
	DeviceID() string
	OutOfBound() string
	InBound() string
	DevName() string
	StructType() string
	// Env() string
	SiteName() string
	Login() string
	OutBandVersion() string
	InBandVersion() string
	// Meta() *L2DeviceMeta
}

type AbbrDeviceInterface interface {
	ParsePlatform(interface{}) (string, error)
	ParseMeta(interface{}) (*L2DeviceMeta, error)
	ParseCatalog(interface{}) (string, error)
	ParseSite(interface{}) (string, error)
	ParseEnv(interface{}) (string, error)
	ParseRemoteInfo(interface{}, string, string) (*L2DeviceRemoteInfo, error)
}

type BaseDevice struct {
	AbbrDeviceInterface
	parsePlatform   func(interface{}) (string, error)
	parseMeta       func(interface{}) (*L2DeviceMeta, error)
	parseCatalog    func(interface{}) (string, error)
	parseSite       func(interface{}) (string, error)
	parseEnv        func(interface{}) (string, error)
	parseRemoteInfo func(interface{}, string, string) (*L2DeviceRemoteInfo, error)
}

func (b *BaseDevice) ParsePlatform(data interface{}) (string, error) {
	return b.parsePlatform(data)
}

func (b *BaseDevice) ParseMeta(data interface{}) (*L2DeviceMeta, error) {
	return b.parseMeta(data)
}

func (b *BaseDevice) ParseCatalog(data interface{}) (string, error) {
	return b.parseCatalog(data)
}

func (b *BaseDevice) ParseRemoteInfo(data interface{}, secretRole, snmpRole string) (*L2DeviceRemoteInfo, error) {
	return b.parseRemoteInfo(data, secretRole, snmpRole)
}

func (b *BaseDevice) WithParsePlatform(f func(interface{}) (string, error)) {
	b.parseCatalog = f
}

func (b *BaseDevice) WithParseSite(f func(interface{}) (string, error)) {
	b.parseSite = f
}

func (b *BaseDevice) WithParseEnv(f func(interface{}) (string, error)) {
	b.parseEnv = f
}

func (b *BaseDevice) WithParseMeta(f func(interface{}) (*L2DeviceMeta, error)) {
	b.parseMeta = f
}

func (b *BaseDevice) WithParseCatalog(f func(interface{}) (string, error)) {
	b.parseCatalog = f
}

func (b *BaseDevice) WithRemoteInfo(f func(interface{}, string, string) (*L2DeviceRemoteInfo, error)) {
	b.parseRemoteInfo = f
}

type OK interface {
	Error() error
	Ok() bool
}

type L2NodemapServiceCenterInterface interface {
	Select(ctx context.Context, remote *L2DeviceRemoteInfo, srv string) (L2NodemapServiceInterface, OK)
}

type L2NodemapServiceInterface interface {
	ServiceName() string
	Run(remote *L2DeviceRemoteInfo, options ...interface{}) (*clitask.Table, error)
}

//

// type SnmpTaskGenerator interface {
// NewSnmpTask(host, community string) *snmp.SnmpTask
// }

type L2NodemapTaskConfigInterface interface {
	IsSelected(string, string) bool
	GetMethod() string
	// NewSnmpTask(host, community string) *snmp.SnmpTask
	// NewSSHTask(reote l2model.structs.L2DeviceRemoteInfo) (*terminal.Execute, error)
	NewExecutor(remote *L2DeviceRemoteInfo) (clitask.Executor, error)
	GetMainConfig() L2NodemapServiceCenterInterface
	// NewRedfishTask(remote l2model.structs.L2DeviceRemoteInfo) *redfish.RedfishTask
	WithMainConfig(L2NodemapServiceCenterInterface)
	GetSubOid(key string) string
	SupportVersion() []string
	IsPretty() bool
}

type L2NodemapInstanceInterface interface {
	Process(remote *L2DeviceRemoteInfo, taskConfig L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error)
}

type IntentParamPair struct {
	Key  string              `json:"key" mapstructure:"key" comment:"工单项key键"`
	Info policy.IntentParams `json:"info" mapstructure:"info" comment:"工单项信息"`
}

type IntentPair struct {
	Key  string        `json:"key" mapstructure:"key" comment:"工单项key键"`
	Info policy.Intent `json:"info" mapstructure:"info" comment:"工单项信息"`
}

type SecurityZoneInfo struct {
	Code            string               `json:"code" mapstructure:"code"`
	Name            string               `json:"name" mapstructure:"name"`
	ConfigZoneName  string               `json:"config_zone_name" mapstructure:"config_zone_name"`
	NetworkSegments []NetworkSegmentInfo `json:"network_segments" mapstructure:"network_segments"`
}

type NetworkSegmentInfo struct {
	Code           string `json:"code" mapstructure:"code"`
	Name           string `json:"name" mapstructure:"name"`
	NetworkSegment string `json:"network_segment" mapstructure:"network_segment"`
}

// NodemapInfo NodemapInfo结构体，用于统一访问l3nodemap服务
type NodemapInfo struct {
	OrderID       string                `json:"order_id" mapstructure:"order_id" comment:"工单ID"`
	DeviceInfos   []DeviceInfo          `json:"device_infos" mapstructure:"device_infos" comment:"源设备信息"`
	IntentInfos   []IntentParamPair     `json:"intent_infos" mapstructure:"intent_infos" comment:"工单数据"`
	DeviceConfigs []config.DeviceConfig `json:"device_configs" mapstructure:"device_configs" comment:"设备配置信息"`
}

func (n NodemapInfo) ActionID() action_id.ActionID {
	aid := action_id.NewActionID()
	aid.Append("OrderID", n.OrderID)
	return *aid
}

func (n NodemapInfo) Site() string {
	if len(n.DeviceInfos) > 0 {
		return n.DeviceInfos[0].DeviceRemoteInfo.Site
	}

	return ""
}

func (n NodemapInfo) Env() string {
	if len(n.DeviceInfos) > 0 {
		return n.DeviceInfos[0].DeviceRemoteInfo.Env
	}

	return ""
}

type L3Query struct {
	QueryKey      string                `json:"query_key"`
	Condition     Condition             `json:"condition"`
	L3Config      L3Config              `json:"l3config"`
	DeviceConfigs []config.DeviceConfig `json:"device_configs"`
}

func (lq L3Query) ActionID() action_id.ActionID {
	aid := action_id.NewActionID()
	aid.Append("L3QueryTask", lq.QueryKey)
	return *aid
}

func (lq L3Query) Site() string {
	return ""
}

func (lq L3Query) Env() string {
	return ""
}

// DeviceInfo DeviceInfo结构体，l3服务所需的设备信息封装
type DeviceInfo struct {
	DeviceBase       DeviceBase                  `json:"device_base" mapstructure:"device_base"`
	ConfigText       string                      `json:"config_text" mapstructure:"config_text"`
	DeviceRemoteInfo L2DeviceRemoteInfo          `json:"device_remote_info" mapstructure:"device_remote_info"`
	Connection       []config.ConnectionInfo     `json:"connection" mapstructure:"connection"`
	VsRange          []config.VsInfo             `json:"vs_range" mapstructure:"vs_range"`
	Ipv4Area         []config.AreaInfo           `json:"ipv4_area" mapstructure:"ipv4_area"`
	Ipv6Area         []config.AreaInfo           `json:"ipv6_area" mapstructure:"ipv6_area"`
	Ipv4Stub         []config.StubConfigInfo     `json:"ipv4_stub" mapstructure:"ipv4_stub"`
	Ipv6Stub         []config.StubConfigInfo     `json:"ipv6_stub" mapstructure:"ipv6_stub"`
	MetaData         map[string]interface{}      `json:"meta_data" mapstructure:"meta_data"`
	SecurityZones    map[string]SecurityZoneInfo `json:"security_zones" mapstructure:"security_zones"`
}

// DeviceBase DeviceBase结构体，设备的基础信息
type DeviceBase struct {
	Host      string `json:"host" mapstructure:"host"`
	Username  string `json:"username" mapstructure:"username"`
	Password  string `json:"password" mapstructure:"password"`
	AuthPass  string `json:"auth_pass" mapstructure:"auth_pass"`
	Port      int    `json:"port" mapstructure:"port"`
	Community string `json:"community" mapstructure:"community"`
	Mode      string `json:"mode" mapstructure:"mode"`
	Telnet    bool   `json:"telnet" mapstructure:"telnet"`
	Token     string `json:"token" mapstructure:"token"`
}

const (
	ConfigConflict               string = "配置冲突"
	MissRoute                    string = "路由缺失"
	SimylationVerificationFailed string = "仿真验证失败"
	PolicyDeny                   string = "Deny策略"
	RouteLoop                    string = "路由环路"
	RouteQuery                   string = "路由查询失败"
	SrcNodePoositionErr          string = "源节点定位失败"
	NextHop_Empty                string = "下一跳路由为空"
	Not_Support_Multi_Route      string = "不支持多路由"
)

type L3TemplatesReplay struct {
	// Results *nodemap.TraverseResult
	Results           []byte
	Result            model.TemplateResult
	RouteDecisionInfo map[string][]RouteDecisionInfo `json:"route_decision_info,omitempty"` // 路由跟踪信息
}

// RouteTraceInfo 路由跟踪信息 - 用于返回给运维平台
type RouteTraceInfo struct {
	IntentID       string              `json:"intent_id"`
	Duration       time.Duration       `json:"duration"`
	StartTime      time.Time           `json:"start_time"`
	EndTime        time.Time           `json:"end_time"`
	RouteHops      []RouteHopInfo      `json:"route_hops"`
	RoutePath      string              `json:"route_path"`
	RouteDecisions []RouteDecisionInfo `json:"route_decisions"`
	ExitInfo       *ExitInfoAPI        `json:"exit_info"`
	NodesVisited   []string            `json:"nodes_visited"`
	DecisionCounts map[string]int      `json:"decision_counts"`
	Success        bool                `json:"success"`
	ErrorMessage   string              `json:"error_message,omitempty"`
}

// RouteHopInfo 路由跳信息 - API格式
type RouteHopInfo struct {
	InPort  string `json:"in_port"`
	Node    string `json:"node"`
	OutPort string `json:"out_port"`
}

// RouteDecisionInfo 路由决策信息 - API格式
type RouteDecisionInfo struct {
	Timestamp    time.Time         `json:"timestamp"`
	DecisionType string            `json:"decision_type"`
	Node         string            `json:"node"`
	Port         string            `json:"port"`
	VRF          string            `json:"vrf"`
	Area         string            `json:"area"`
	Criteria     map[string]string `json:"criteria"`
	Result       string            `json:"result"`
	Reason       string            `json:"reason"`
	Details      map[string]string `json:"details"`
}

// ExitInfoAPI 退出信息 - API格式
type ExitInfoAPI struct {
	Timestamp time.Time         `json:"timestamp"`
	Reason    string            `json:"reason"`
	Node      string            `json:"node"`
	Port      string            `json:"port"`
	VRF       string            `json:"vrf"`
	Details   map[string]string `json:"details"`
	Success   bool              `json:"success"`
	ErrorMsg  string            `json:"error_msg,omitempty"`
}

type RepoResult struct {
	Type        string        `json:"type"`
	PlayBook    []interface{} `json:"playbook"`
	NomadScript string        `json:"nomad_script"`
	Config      struct {
		Type     string   `json:"type"`
		Desc     string   `json:"desc"`
		File     string   `json:"file"`
		FileName string   `json:"file_name"`
		Resource []string `json:"resource"`
		Args     []struct {
			Key      string `json:"key"`
			Label    string `json:"label"`
			Type     string `json:"type"`
			Required bool   `json:"required"`
			Rule     string `json:"rule"`
			Default  string `json:"default"`
			Desc     string `json:"desc"`
		} `json:"args"`
	} `json:"config"`
	OrderID               string                 `json:"order_id" mapstructure:"order_id" log:"order_id"`
	EnvValue              string                 `json:"env_value" mapstructure:"env_value" log:"env_value"`
	SiteValue             string                 `json:"site_value" mapstructure:"site_value" log:"site_value"`
	Inventory             []string               `json:"inventory" mapstructure:"inventory" log:"inventory"`
	FileContent           []map[string][]byte    `json:"file_content" mapstructure:"file_content" log:"file_content"`
	ExtraVars             map[string]interface{} `json:"extra_vars" mapstructure:"extra_vars" log:"extra_vars"`
	AnsibleConnUser       string                 `json:"ansible_conn_user" mapstructure:"ansible_conn_user" log:"ansible_conn_user"`
	AnsibleConnPrivateKey string                 `json:"ansible_conn_private_key" mapstructure:"ansible_conn_private_key" log:"ansible_conn_private_keyr"`
	AnsibleTimeOut        int                    `json:"ansible_time_out" mapstructure:"ansible_time_out" log:"ansible_time_out"`
}

func (n RepoResult) ActionID() action_id.ActionID {
	aid := action_id.NewActionID()
	aid.Append("OrderID", n.OrderID)
	return *aid
}

func (n RepoResult) Site() string {
	// if len(n.DeviceInfos) > 0 {
	//	return n.DeviceInfos[0].DeviceRemoteInfo.Site
	// }

	return n.SiteValue
}

func (n RepoResult) Env() string {
	// if len(n.DeviceInfos) > 0 {
	//	return n.DeviceInfos[0].DeviceRemoteInfo.Env
	// }

	return n.EnvValue
}

type AnsibleTask struct {
	Task   string `json:"task"`
	Msg    string `json:"msg"`
	Stdout string `json:"stdout"`
	StdErr string `json:"std_err"`
	Failed bool   `json:"failed"`
	// Hosts []*AnsibleTaskHost `json:"hosts"`
}
type AnsibleTaskStatus struct {
	Changed     int `json:"changed"`
	Failures    int `json:"failures"`
	Ignored     int `json:"ignored"`
	Ok          int `json:"ok"`
	Rescued     int `json:"rescued"`
	Skipped     int `json:"skipped"`
	Unreachable int `json:"unreachable"`
}

// type AnsibleTaskHost struct {
//	//Host   string `json:"host"`
//	Msg    string `json:"msg"`
//	Stdout string `json:"stdout"`
// }

type AnsibleHost struct {
	Host  string         `json:"host"`
	Tasks []*AnsibleTask `json:"tasks"`
}
type AnsibleTaskResult struct {
	Hosts []*AnsibleHost `json:"hosts"`
	// Tasks []*AnsibleTask
	Stats map[string]*AnsibleTaskStatus `json:"stats"`
	Start string                        `json:"start"`
	End   string                        `json:"end"`
}

//	type AnsibleTaskReply struct {
//		TaskName  string `json:"task_name"`
//		Host      string `json:"host"`
//		ResultMsg string `json:"result_msg"`
//		Stdout    string `json:"stdout"`
//	}
//
//	type AnsibleTaskResult struct {
//		Host        string              `json:"host"`
//		Failures    int                 `json:"failures"`
//		Ignored     int                 `json:"ignored"`
//		Ok          int                 `json:"ok"`
//		Rescued     int                 `json:"rescued"`
//		Skipped     int                 `json:"skipped"`
//		Unreachable int                 `json:"unreachable"`
//		Info        []*AnsibleTaskReply `json:"info"`
//	}
type RepoResultTaskReplay struct {
	AnsibleTaskResult *AnsibleTaskResult
}

type OrchArgs struct {
	OrderID  string `json:"order_id"`
	EndPoint string `json:"end_point"`
	LuaPath  string `json:"lua_path"`
}

func (a *OrchArgs) ActionID() action_id.ActionID {
	aid := action_id.NewActionID()
	aid.Append("OrderID", a.OrderID)
	return *aid
}

func (a *OrchArgs) Site() string {
	return ""
}

func (a *OrchArgs) Env() string {
	return ""
}

type OrchReply struct {
	Result []map[string]string
}

type CmdInteraction struct {
	Name            string        `json:"name"`              // 命令名
	Cmd             string        `json:"cmd"`               // 输入的命令
	Prompt          string        `json:"prompt"`            // 正则匹配的提示
	TimeOut         int           `json:"time_out"`          // 超时
	MultipleCmdList []MultipleCmd `json:"multiple_cmd_list"` // 多次回调命令
}

type MultipleCmd struct {
	Name    string `json:"name"`
	Want    string `json:"want"`
	Prompt  string `json:"prompt"`
	Cmd     string `json:"cmd"`
	TimeOut int    `json:"time_out"`
	Close   bool   `json:"close"`
}

type ResultType string

const (
	ResultTypeTable   = ResultType("Table")
	ResultTypeString  = ResultType("String")
	ResultTypeMap     = ResultType("Map")
	ResultTypeJSON    = ResultType("Json")
	ResultTypeListMap = ResultType("ListMap")
)

type ServiceDescrib struct {
	ResultType ResultType
}

type PipelineStageSelectConfig struct {
	Stage  string
	Method string
}

type PipelineStageInf interface {
	Process(input *PipelineData, config PipelineStageConfig) error
}

type CollectContext struct {
	Item   CollectItem
	Config *CollectConfig
}

type DeviceConfig struct {
	// 基本信息
	Vendor   string `yaml:"vendor"`
	Platform string `yaml:"platform"`
	Version  string `yaml:"version"`

	Fields []string `yaml:"fields"`

	// 数据采集和处理流水线
	Pipeline []PipelineStage `yaml:"pipeline"`

	// 结果处理
	ResultType ResultType `yaml:"resultType"`

	// 调试选项
	Debug          bool `yaml:"debug"`
	VerboseLogging bool `yaml:"verboseLogging"`

	// 用于存储 CollectItem 的选项
	CollectItemOptionsMap map[string]CollectItemOptions `yaml:"collectItemOptionsMap"`
}

type PipelineResult struct {
	Data          interface{}            // 最终处理后的数据
	Errors        []error                // 执行过程中的所有错误
	StageResults  map[string]interface{} // 每个阶段的中间结果
	ExecutionTime time.Duration          // 总执行时间
	LastStage     string                 // 最后执行的阶段名称
}

// type PipelineStageConfig struct {
// 	CollectConfig     *CollectConfig     `yaml:"collectConfig,omitempty"`
// 	ParseConfig       *ParseConfig       `yaml:"parseConfig,omitempty"`
// 	TransformConfig   *TransformConfig   `yaml:"transformConfig,omitempty"`
// 	DeriveConfig      *DeriveConfig      `yaml:"deriveConfig,omitempty"`
// 	TextFSMConfig     *TextFSMConfig     `yaml:"textFSMConfig,omitempty"`
// 	SnmpProcessConfig *SnmpProcessConfig `yaml:"snmpProcessConfig,omitempty"`
// }

// 更新 PipelineStageConfig 以包含每种类型的配置
type PipelineStageConfig struct {
	AliveCheckConfig  *AliveCheckConfig  `yaml:"aliveCheckConfig,omitempty" json:"aliveCheckConfig,omitempty"`
	CollectConfig     *CollectConfig     `yaml:"collectConfig,omitempty" json:"collectConfig,omitempty"`
	ParseConfig       *ParseConfig       `yaml:"parseConfig,omitempty" json:"parseConfig,omitempty"`
	TransformConfig   *TransformConfig   `yaml:"transformConfig,omitempty" json:"transformConfig,omitempty"`
	DeriveConfig      *DeriveConfig      `yaml:"deriveConfig,omitempty" json:"deriveConfig,omitempty"`
	TextFSMConfig     *TextFSMConfig     `yaml:"textFSMConfig,omitempty" json:"textFSMConfig,omitempty"`
	SnmpProcessConfig *SnmpProcessConfig `yaml:"snmpProcessConfig,omitempty" json:"snmpProcessConfig,omitempty"`
	JoinConfig        *JoinConfig        `yaml:"joinConfig,omitempty" json:"joinConfig,omitempty"`
}

// Field 定义了一个通用的字段结构
type Field struct {
	Name string   `yaml:"name" json:"name"`
	Type DataType `yaml:"type" json:"type"`
	// Description string   `yaml:"description" json:"description"`
	// Required    bool     `yaml:"required" json:"required"`
	// Default     interface{} `yaml:"default" json:"default,omitempty"`
}

// PipelineStage 结构升级
type PipelineStage struct {
	Type        string              `yaml:"type" json:"type"`
	Config      PipelineStageConfig `yaml:"config" json:"config"`
	InputFields []string            `yaml:"inputFields" json:"inputFields"`
	Fields      []string            `yaml:"fields" json:"fields"`
	// InputFields  []Field             `yaml:"inputFields" json:"inputFields"`
	// OutputFields []Field             `yaml:"outputFields" json:"outputFields"`
}

func (ps *PipelineStage) GetInputFields() []Field {
	switch ps.Type {
	case "Collect":
		return ps.Config.CollectConfig.GetInputFields()
	case "Parse":
		return ps.Config.ParseConfig.GetInputFields()
	case "Transform":
		return ps.Config.TransformConfig.GetInputFields()
	case "Derive":
		return ps.Config.DeriveConfig.GetInputFields()
	case "TextFSM":
		return ps.Config.TextFSMConfig.GetInputFields()
	case "SnmpProcess":
		return ps.Config.SnmpProcessConfig.GetInputFields()
	case "Join":
		return ps.Config.JoinConfig.GetInputFields()
	default:
		return nil
	}
}

func (ps *PipelineStage) GetOutputFields() []Field {
	switch ps.Type {
	case "AliveCheck":
		return ps.Config.AliveCheckConfig.GetOutputFields()
	case "Collect":
		return ps.Config.CollectConfig.GetOutputFields()
	case "Parse":
		return ps.Config.ParseConfig.GetOutputFields()
	case "Transform":
		return ps.Config.TransformConfig.GetOutputFields()
	case "Derive":
		return ps.Config.DeriveConfig.GetOutputFields()
	case "TextFSM":
		return ps.Config.TextFSMConfig.GetOutputFields()
	case "SnmpProcess":
		return ps.Config.SnmpProcessConfig.GetOutputFields()
	case "Join":
		return ps.Config.JoinConfig.GetOutputFields()
	default:
		return nil
	}
}

// type PipelineStage struct {
// 	Type        string              `yaml:"type"`   // "Collect", "Parse", "Transform", "Derive", "TextFSM", "SnmpProcess"
// 	Config      PipelineStageConfig `yaml:"config"` // 根据 Type 不同，可能是 CollectConfig, ParseConfig, TransformConfig, 或 DeriveConfig
// 	InputFields []string            `yaml:"inputFields"`
// 	Fields      []string            `yaml:"fields"`
// }

type AliveCheckConfig struct {
	AliveCheckItem *AliveCheckItem `yaml:"aliveCheckItem"`
}

func (acc *AliveCheckConfig) GetInputFields() []Field {
	return []Field{}
}

func (acc *AliveCheckConfig) GetOutputFields() []Field {
	return []Field{
		{Name: "reachable", Type: TypeMapStringString},
	}
}

type CollectConfig struct {
	CollectItems []CollectItem `yaml:"collectItems"`
}

func (cc *CollectConfig) GetInputFields() []Field {
	return []Field{}
}

func (cc *CollectConfig) GetOutputFields() []Field {
	outputs := []Field{}
	for _, item := range cc.CollectItems {
		f := Field{
			Name: item.Name,
			Type: item.Type,
		}
		outputs = append(outputs, f)
	}
	return outputs
}

type CollectItemOptions struct {
	SNMPOptions   *SNMPOptions   `yaml:"snmpOptions,omitempty"`
	SSHOptions    *SSHOptions    `yaml:"sshOptions,omitempty"`
	APIOptions    *APIOptions    `yaml:"apiOptions,omitempty"`
	TelnetOptions *TelnetOptions `yaml:"telnetOptions,omitempty"`
}

type ExpectedType string

const (
	JSON       = ExpectedType("JSON")
	SNMPList   = ExpectedType("SNMPList")
	SNMPSingle = ExpectedType("SNMPSingle")
)

type DataType string

const (
	TypeString                   DataType = "string"
	TypeInteger                  DataType = "integer"
	TypeFloat                    DataType = "float"
	TypeBoolean                  DataType = "boolean"
	TypeStringSlice              DataType = "[]string"
	TypeMapStringString          DataType = "map[string]string"
	TypeSliceMapStringString     DataType = "[]map[string]string"
	TypeMapStringMapStringString DataType = "map[string]map[string]string"
	TypeMapSliceMapstringString  DataType = "map[string][]map[string]string"
	// TypeJSON            DataType = "json"
	// TypeSNMPList        DataType = "snmplist"
	// TypeSNMPSingle      DataType = "snmpsingle"
	// TypeTable           DataType = "table"
)

type CollectMethod string

const (
	SNMP   = CollectMethod("SNMP")
	SSH    = CollectMethod("SSH")
	TELNET = CollectMethod("TELNET")
	API    = CollectMethod("API")
)

type AliveCheckItem struct {
	Name    string             `yaml:"name"`
	Method  CollectMethod      `yaml:"method"`   // "SNMP", "SSH", "TELNET", "API", etc.
	Type    DataType           `yaml:"dataType"` // "string", "integer", "float", "boolean", "json", etc.
	Target  string             `yaml:"target"`   // OID for SNMP, command for SSH, endpoint for API
	Options CollectItemOptions `yaml:"options"`  // Additional options specific to the method
}

type CollectItem struct {
	Name                 string             `yaml:"name"`
	Method               CollectMethod      `yaml:"method"` // "SNMP", "SSH", "TELNET", "API", etc.
	Target               string             `yaml:"target"` // OID for SNMP, command for SSH, endpoint for API
	LoginTimeout         int                `yaml:"loginTimeout"`
	NoOutputTimeout      int                `yaml:"noOutputTimeout"`
	ExpectedType         ExpectedType       `yaml:"expectedType"` // "String", "SNMPList", "SNMPSingle", "JSON"
	Options              CollectItemOptions `yaml:"options"`      // Additional options specific to the method
	ModeConfig           ModeConfig         `yaml:"modeConfig"`
	HubConfig            HubConfig          `yaml:"hubConfig"`
	ModeConfigFile       string             `yaml:"modeConfigFile,omitempty"`
	ConnectionOptionName string             `yaml:"connectionOptionName,omitempty"`
	HubConfigFile        string             `yaml:"hubConfigFile,omitempty"`
	Type                 DataType           `yaml:"dataType"` // "string", "integer", "float", "boolean", "json", etc.
}

type SNMPOptions struct {
	Name      string `yaml:"name"`
	Version   string `yaml:"version"`
	Community string `yaml:"community"`
	Timeout   int    `yaml:"timeout"`
	Retries   int    `yaml:"retries"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	// Other SNMP specific options
}

type SSHOptions struct {
	Name         string  `yaml:"name"`
	Username     string  `yaml:"username"`
	Password     string  `yaml:"password"`
	PrivateKey   string  `yaml:"privateKey"`
	Host         string  `yaml:"host"`
	Port         int     `yaml:"port"`
	AuthPassword string  `yaml:"authPassword"`
	Timeout      int     `yaml:"timeout"`
	Mode         SSHMode `yaml:"mode"`
}

type TelnetOptions struct {
	Name         string `yaml:"name"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	AuthPassword string `yaml:"authPassword"`
	Timeout      int    `yaml:"timeout"`
}

type SSHMode string

const (
	SSHServer        = SSHMode("SSHServer")
	SSHNetworkDevice = SSHMode("SSHNetworkDevice")
)

type APIOptions struct {
	Method      string            `yaml:"method"`      // HTTP 方法：GET, POST, PUT, DELETE 等
	URL         string            `yaml:"url"`         // API 端点 URL
	Headers     map[string]string `yaml:"headers"`     // 自定义 HTTP 头
	QueryParams map[string]string `yaml:"queryParams"` // URL 查询参数
	Body        []byte            `yaml:"body"`        // 请求体
	Timeout     time.Duration     `yaml:"timeout"`     // 请求超时时间

	// 认证选项
	AuthType string `yaml:"authType"` // 认证类型：Basic, Bearer, Custom
	Username string `yaml:"username"` // 用于 Basic 认证
	Password string `yaml:"password"` // 用于 Basic 认证
	Token    string `yaml:"token"`    // 用于 Bearer Token 认证

	// TLS/SSL 选项
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"` // 是否跳过 SSL 证书验证
	CertFile           string `yaml:"certFile"`           // 客户端证书文件路径
	KeyFile            string `yaml:"keyFile"`            // 客户端密钥文件路径
	CAFile             string `yaml:"caFile"`             // CA 证书文件路径

	// 重试选项
	MaxRetries int           `yaml:"maxRetries"` // 最大重试次数
	RetryDelay time.Duration `yaml:"retryDelay"` // 重试间隔

	// 代理设置
	ProxyURL string `yaml:"proxyURL"` // 代理服务器 URL

	// 响应处理选项
	ExpectedStatusCodes []int  `yaml:"expectedStatusCodes"` // 预期的 HTTP 状态码
	ResponseFormat      string `yaml:"responseFormat"`      // 期望的响应格式：JSON, XML, Text 等

	// 调试选项
	Debug bool `yaml:"debug"` // 是否启用调试模式
}

type ParseConfig struct {
	ParseItems []ParseItem `yaml:"parseItems"`
}

func (pc *ParseConfig) GetInputFields() []Field {
	var fields []Field
	for _, item := range pc.ParseItems {
		fields = append(fields, Field{Name: item.InputField, Type: TypeString})
	}
	return fields
}

func (pc *ParseConfig) GetOutputFields() []Field {
	var fields []Field
	for _, item := range pc.ParseItems {
		fields = append(fields, Field{Name: item.OutputField, Type: DataType(item.ExpectedType)})
	}
	return fields
}

type ParseItem struct {
	Name           string `yaml:"name"`           // 解析项的名称
	InputField     string `yaml:"inputField"`     // 输入字段名
	OutputField    string `yaml:"outputField"`    // 输出字段名
	ExpectedType   string `yaml:"expectedType"`   // 期望的输出类型，如 "String", "Integer", "Float", "Boolean", "List", "Map"
	Operation      string `yaml:"operation"`      // 解析操作类型，如 "Regex", "Split", "Trim", "Replace", "Extract"
	Pattern        string `yaml:"pattern"`        // 用于操作的模式，如正则表达式、分隔符等
	PreprocessFunc string `yaml:"preprocessFunc"` // 预处理函数名，用于在主要操作之前对输入进行处理
}

func (pi *ParseItem) GetInputFields() []Field {
	return []Field{{Name: pi.InputField, Type: TypeString}}
}

func (pi *ParseItem) GetOutputFields() []Field {
	return []Field{{Name: pi.OutputField, Type: DataType(pi.ExpectedType)}}
}

type SnmpProcessConfig struct {
	ProcessItems []SnmpProcessItem `yaml:"processItems"`
}

func (sc *SnmpProcessConfig) GetInputFields() []Field {
	var fields []Field
	for _, item := range sc.ProcessItems {
		fields = append(fields, item.GetInputFields()...)
	}
	return fields
}

func (sc *SnmpProcessConfig) GetOutputFields() []Field {
	var fields []Field
	for _, item := range sc.ProcessItems {
		fields = append(fields, item.GetOutputFields()...)
	}
	return fields
}

type SnmpProcessItem struct {
	InputField string `yaml:"inputField"` // 输入字段名

	Name string `yaml:"name"` // 处理项的名称

	// IndexPositions 存储用于从 OID 后缀中提取索引值的位置
	IndexPositions []int `yaml:"indexPositions"`

	// ClassifierPositions 存储用于从 OID 后缀中提取前缀值的位置
	ClassifierPositions []int `yaml:"classifierPositions"`

	// ClassifierToNameMap 将前缀映射到对应的名称
	ClassifierToNameMap map[string]string `yaml:"classifierToNameMap"`

	// ClassifierProcessors 存储与特定前缀关联的处理函数名称
	ClassifierProcessors map[string]string `yaml:"classifierProcessors"`

	// CustomIndexProcessor 是一个可选的函数名称，用于自定义索引处理
	CustomIndexProcessor string `yaml:"customIndexProcessor"`

	// AppendProcessors 是一个可选的函数名称，用于自定义处理
	AppendProcessors []string `yaml:"appendProcessors"`

	// ValueMapping 用于定义值的映射规则
	ValueMapping map[string]map[string]string `yaml:"valueMapping"`
}

func (spi *SnmpProcessItem) GetInputFields() []Field {
	return []Field{{Name: spi.InputField, Type: TypeSliceMapStringString}}
}

func (spi *SnmpProcessItem) GetOutputFields() []Field {
	var fields []Field
	// for _, name := range spi.ClassifierToNameMap {
	// 	fields = append(fields, Field{Name: name, Type: TypeString})
	// }
	fields = append(fields, Field{Name: spi.Name, Type: TypeSliceMapStringString})
	return fields
}

type TransformConfig struct {
	TransformItems []TransformItem `yaml:"transformItems"`
}

func (tc *TransformConfig) GetInputFields() []Field {
	var fields []Field
	for _, item := range tc.TransformItems {
		fields = append(fields, item.GetInputFields()...)
	}
	return fields
}

func (tc *TransformConfig) GetOutputFields() []Field {
	var fields []Field
	for _, item := range tc.TransformItems {
		// fields = append(fields, item.GetOutputFields()...)
		fields = append(fields, Field{Name: item.Name, Type: DataType(strings.Join([]string{string(TypeMapStringString),
			string(TypeMapSliceMapstringString), string(TypeSliceMapStringString),
			string(TypeMapStringMapStringString)}, "|"))})
	}
	return fields
}

type TransformItem struct {
	Name     string         `yaml:"name"` // 转换项的名称
	Mappings []FieldMapping `yaml:"mappings"`
}

func (ti *TransformItem) GetInputFields() []Field {
	var fields []Field
	for _, mapping := range ti.Mappings {
		fields = append(fields, Field{Name: mapping.InputField, Type: TypeString})
	}
	return fields
}

func (ti *TransformItem) GetOutputFields() []Field {
	var fields []Field
	for _, mapping := range ti.Mappings {
		fields = append(fields, Field{Name: mapping.OutputField, Type: TypeMapStringMapStringString})
	}
	return fields
}

type FieldMapping struct {
	InputField   string `yaml:"inputField"`
	OutputField  string `yaml:"outputField"`
	Regex        string `yaml:"regex"`
	Parser       string `yaml:"parser"`
	Unchanged    bool   `yaml:"unchanged"`    // 指示是否需要对该字段进行任何更改
	FlattenSlice bool   `yaml:"flattenSlice"` //用于控制是否将 []map[string]string 扁平化为 map[string]string
}

type DeriveConfig struct {
	DeriveItems []DeriveItem `yaml:"deriveItems"`
}

func (dc *DeriveConfig) GetInputFields() []Field {
	var fields []Field
	for _, item := range dc.DeriveItems {
		fields = append(fields, item.GetInputFields()...)
	}
	return fields
}

func (dc *DeriveConfig) GetOutputFields() []Field {
	var fields []Field
	for _, item := range dc.DeriveItems {
		fields = append(fields, item.GetOutputFields()...)
	}
	return fields
}

type DeriveItem struct {
	Name   string         `yaml:"name"` // 派生项的名称
	Fields []DerivedField `yaml:"fields"`
}

func (di *DeriveItem) GetInputFields() []Field {
	var fields []Field
	for _, derivedField := range di.Fields {
		for _, sourceField := range derivedField.SourceFields {
			fields = append(fields, Field{Name: sourceField, Type: TypeString})
		}
	}
	return fields
}

func (di *DeriveItem) GetOutputFields() []Field {
	var fields []Field
	for _, derivedField := range di.Fields {
		fields = append(fields, Field{Name: derivedField.Name, Type: TypeString})
	}
	return fields
}

type DerivedField struct {
	Name         string   `yaml:"name"`
	SourceFields []string `yaml:"sourceFields"`
	Expression   string   `yaml:"expression"`
	Regex        string   `yaml:"regex"`
	Parser       string   `yaml:"parser"`
}

type TextFSMConfig struct {
	TextFSMItems []TextFSMItem `yaml:"textFSMItems"`
}

func (tc *TextFSMConfig) GetInputFields() []Field {
	var fields []Field
	for _, item := range tc.TextFSMItems {
		fields = append(fields, item.GetInputFields()...)
	}
	return fields
}

func (tc *TextFSMConfig) GetOutputFields() []Field {
	var fields []Field
	for _, item := range tc.TextFSMItems {
		fields = append(fields, Field{Name: item.Name, Type: TypeSliceMapStringString})
	}
	return fields
}

type TextFSMItem struct {
	Name       string   `yaml:"name"`       // TextFSM项的名称
	Template   string   `yaml:"template"`   // TextFSM模板内容
	InputField string   `yaml:"inputField"` // 指定要处理的输入字段名
	RowFields  []string `yaml:"rowFields"`  // 指定TextFSM处理后应输出的字段名列表
}

func (ti *TextFSMItem) GetInputFields() []Field {
	return []Field{{Name: ti.InputField, Type: TypeString}}
}

func (ti *TextFSMItem) GetOutputFields() []Field {
	var fields []Field
	for _, rowField := range ti.RowFields {
		fields = append(fields, Field{Name: rowField, Type: TypeString})
	}
	return fields
}

type JoinConfig struct {
	JoinItems []JoinItem `yaml:"joinItems"`
}

type JoinItem struct {
	Name        string           `yaml:"name"`
	LeftInput   string           `yaml:"leftInput"`   // 左表输入字段
	RightInputs []RightInputInfo `yaml:"rightInputs"` // 右表输入字段信息（可以有多个）
	OutputField string           `yaml:"outputField"`
	JoinType    string           `yaml:"joinType"` // 例如: "inner", "left", "right", "full"
	LeftKey     string           `yaml:"leftKey"`  // 左表的 join key
}

type RightInputInfo struct {
	Name   string `yaml:"name"`   // 右表名称
	Key    string `yaml:"key"`    // 该右表的 join key
	Prefix string `yaml:"prefix"` // 可选：用于在输出中为该表的字段添加前缀
}

func (jc *JoinConfig) GetInputFields() []Field {
	var fields []Field
	for _, item := range jc.JoinItems {
		// 添加左表输入字段
		fields = append(fields, Field{Name: item.LeftInput, Type: TypeSliceMapStringString})

		// 添加右表输入字段
		for _, rightInput := range item.RightInputs {
			fields = append(fields, Field{Name: rightInput.Name, Type: TypeSliceMapStringString})
		}
	}
	return fields
}

func (jc *JoinConfig) GetOutputFields() []Field {
	var fields []Field
	for _, item := range jc.JoinItems {
		// 输出字段类型保持不变，但我们可以添加更多信息
		outputField := Field{
			Name: item.OutputField,
			Type: TypeSliceMapStringString,
		}

		// 可以考虑在这里添加更多的元数据，例如连接类型
		// outputField.Metadata = map[string]interface{}{
		//     "joinType": item.JoinType,
		//     "leftKey": item.LeftKey,
		//     "rightKeys": make([]string, len(item.RightInputs)),
		// }
		// for i, rightInput := range item.RightInputs {
		//     outputField.Metadata["rightKeys"].([]string)[i] = rightInput.Key
		// }

		fields = append(fields, outputField)
	}
	return fields
}

// func GetInputValue(input PipelineData, field string) (string, bool) {
// 	if val, ok := input.SNMPSingleData[field]; ok {
// 		return val, true
// 	}

// 	if val, ok := input.JSONData[field]; ok {
// 		switch v := val.(type) {
// 		case string:
// 			return v, true
// 		case []map[string]string:
// 			// 处理 TextFSM 生成的数据
// 			jsonBytes, err := json.Marshal(v)
// 			if err == nil {
// 				return string(jsonBytes), true
// 			}
// 		case []interface{}:
// 			// 处理其他类型的列表
// 			jsonBytes, err := json.Marshal(v)
// 			if err == nil {
// 				return string(jsonBytes), true
// 			}
// 		case map[string]interface{}:
// 			// 处理嵌套的 JSON 对象
// 			jsonBytes, err := json.Marshal(v)
// 			if err == nil {
// 				return string(jsonBytes), true
// 			}
// 		default:
// 			// 尝试将其他类型转换为字符串
// 			return fmt.Sprintf("%v", v), true
// 		}
// 	}

// 	if val, ok := input.SNMPListData[field]; ok {
// 		values := make([]string, 0, len(val))
// 		for _, item := range val {
// 			values = append(values, item["value"])
// 		}
// 		return strings.Join(values, "\n"), true
// 	}

// 	return "", false
// }

type ModeConfig struct {
	Type            string   `yaml:"type"`
	Prompts         []string `yaml:"prompts"`
	ErrPrompts      []string `yaml:"err_prompts"`
	IgnorePrompts   []string `yaml:"ignore_prompts"`
	PossiblePrompts []string `yaml:"possible_prompts"`
	PagerPrompts    []string `yaml:"pager_prompts"`
	PagerCommand    string   `yaml:"pager_command"`
	InitCommands    []string `yaml:"init_commands"`
	SaveCommands    []string `yaml:"save_commands"`
	FirstChain      []string `yaml:"first_chain"`
	LastChain       []string `yaml:"last_chain"`
	AuthCmd         string   `yaml:"auth_cmd"`
}

type DispatchConfig struct {
	Name   string   `yaml:"name"`
	Regex  []string `yaml:"regex"`
	Action string   `yaml:"action"`
}

type HubConfig struct {
	Dispatches []DispatchConfig `yaml:"dispatches"`
}

// type PipelineData struct {
// 	Data     map[string]interface{}
// 	Metadata map[string]interface{}
// 	Stages   []StageResult
// 	errors   []error
// }

// type StageResult struct {
// 	StageName string
// 	Data      map[string]interface{}
// 	Error     error
// }

// func NewPipelineData() *PipelineData {
// 	return &PipelineData{
// 		Data:     make(map[string]interface{}),
// 		Metadata: make(map[string]interface{}),
// 		Stages:   make([]StageResult, 0),
// 	}
// }

// func (pd *PipelineData) Set(key string, value interface{}) {
// 	pd.Data[key] = value
// }

// func (pd *PipelineData) Get(key string) (interface{}, bool) {
// 	value, exists := pd.Data[key]
// 	return value, exists
// }

// func (pd *PipelineData) SetMetadata(key string, value interface{}) {
// 	pd.Metadata[key] = value
// }

// func (pd *PipelineData) GetMetadata(key string) (interface{}, bool) {
// 	value, exists := pd.Metadata[key]
// 	return value, exists
// }

// func (pd *PipelineData) AddStageResult(stageName string, data map[string]interface{}, err error) {
// 	pd.Stages = append(pd.Stages, StageResult{
// 		StageName: stageName,
// 		Data:      data,
// 		Error:     err,
// 	})
// }

// func (pd *PipelineData) GetLastStageResult() *StageResult {
// 	if len(pd.Stages) > 0 {
// 		return &pd.Stages[len(pd.Stages)-1]
// 	}
// 	return nil
// }

// // AddError 添加一个错误到 PipelineData
// func (pd *PipelineData) AddError(err error) {
// 	pd.errors = append(pd.errors, err)
// }

// // HasErrors 检查是否有任何错误
// func (pd *PipelineData) HasErrors() bool {
// 	return len(pd.errors) > 0
// }

// // GetErrors 返回所有错误
// func (pd *PipelineData) GetErrors() []error {
// 	return pd.errors
// }

type PipelineData struct {
	data     map[string]interface{}
	metadata map[string]interface{}
	stages   []StageResult
	errors   []error
}

type StageResult struct {
	StageName string
	Data      interface{}
	Error     error
}

func (sr *StageResult) GetMapStringString() (map[string]string, bool) {
	if data, ok := sr.Data.(map[string]string); ok {
		return data, true
	}
	return nil, false
}

func (sr *StageResult) GetSliceMapStringString() ([]map[string]string, bool) {
	if data, ok := sr.Data.([]map[string]string); ok {
		return data, true
	}
	return nil, false
}

func NewPipelineData() *PipelineData {
	return &PipelineData{
		data:     make(map[string]interface{}),
		metadata: make(map[string]interface{}),
		stages:   make([]StageResult, 0),
		errors:   make([]error, 0),
	}
}

// Set 设置数据
func (pd *PipelineData) Set(key string, value interface{}) {
	pd.data[key] = value
}

// Get 获取数据，返回 interface{} 和是否存在的标志
func (pd *PipelineData) Get(key string) (interface{}, bool) {
	value, exists := pd.data[key]
	return value, exists
}

func (pd *PipelineData) Data() map[string]interface{} {
	return pd.data
}

func (pd *PipelineData) MetaData() map[string]interface{} {
	return pd.metadata
}

// GetString 获取字符串类型的数据
func (pd *PipelineData) GetString(key string) (string, bool) {
	if value, exists := pd.data[key]; exists {
		if strValue, ok := value.(string); ok {
			return strValue, true
		}
	}
	return "", false
}

// GetInt 获取整数类型的数据
func (pd *PipelineData) GetInt(key string) (int, bool) {
	if value, exists := pd.data[key]; exists {
		if intValue, ok := value.(int); ok {
			return intValue, true
		}
	}
	return 0, false
}

// GetFloat 获取浮点数类型的数据
func (pd *PipelineData) GetFloat(key string) (float64, bool) {
	if value, exists := pd.data[key]; exists {
		if floatValue, ok := value.(float64); ok {
			return floatValue, true
		}
	}
	return 0, false
}

// GetStringSlice 获取字符串切片类型的数据
func (pd *PipelineData) GetStringSlice(key string) ([]string, bool) {
	if value, exists := pd.data[key]; exists {
		if sliceValue, ok := value.([]string); ok {
			return sliceValue, true
		}
	}
	return nil, false
}

// SetMetadata 设置元数据
func (pd *PipelineData) SetMetadata(key string, value interface{}) {
	pd.metadata[key] = value
}

// GetMetadata 获取元数据
func (pd *PipelineData) GetMetadata(key string) (interface{}, bool) {
	value, exists := pd.metadata[key]
	return value, exists
}

// AddStageResult 添加阶段结果
func (pd *PipelineData) AddStageResult(stageName string, data interface{}) {
	result := StageResult{
		StageName: stageName,
		Data:      data,
	}

	// 验证数据类型
	switch data.(type) {
	case string, map[string]string, []map[string]string, map[string]interface{}:
		// 数据类型正确
	default:
		result.Error = fmt.Errorf("invalid data type for stage result")
	}

	pd.stages = append(pd.stages, result)
}

// GetLastStageResult 获取最后一个阶段的结果
func (pd *PipelineData) GetLastStageResult() *StageResult {
	if len(pd.stages) > 0 {
		return &pd.stages[len(pd.stages)-1]
	}
	return nil
}

// GetStageResults 获取所有阶段的结果
func (pd *PipelineData) GetStageResults() []StageResult {
	return pd.stages
}

// AddError 添加错误
func (pd *PipelineData) AddError(err error) {
	pd.errors = append(pd.errors, err)
}

// HasErrors 检查是否有错误
func (pd *PipelineData) HasErrors() bool {
	return len(pd.errors) > 0
}

// GetErrors 获取所有错误
func (pd *PipelineData) GetErrors() []error {
	return pd.errors
}

// Validate 验证数据是否符合预期
func (pd *PipelineData) Validate(schema map[string]string) error {
	for key, expectedType := range schema {
		value, exists := pd.data[key]
		if !exists {
			return fmt.Errorf("missing required field: %s", key)
		}

		switch expectedType {
		case "string":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("field %s should be a string", key)
			}
		case "int":
			if _, ok := value.(int); !ok {
				return fmt.Errorf("field %s should be an integer", key)
			}
		case "float":
			if _, ok := value.(float64); !ok {
				return fmt.Errorf("field %s should be a float", key)
			}
		case "[]string":
			if _, ok := value.([]string); !ok {
				return fmt.Errorf("field %s should be a string slice", key)
			}
		case "map[string]string":
			if _, ok := value.(map[string]string); !ok {
				return fmt.Errorf("field %s should be a map[string]string", key)
			}
		case "[]map[string]string":
			if _, ok := value.([]map[string]string); !ok {
				return fmt.Errorf("field %s should be a slice of map[string]string", key)
			}
		default:
			return fmt.Errorf("unknown type %s for field %s", expectedType, key)
		}
	}
	return nil
}
