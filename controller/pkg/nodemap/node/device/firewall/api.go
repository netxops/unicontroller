package firewall

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

type ObjectSearchType int

const (
	_ ObjectSearchType = iota
	SEARCH_GROUP
	SEARCH_OBJECT
	SEARCH_OBJECT_OR_GROUP
)

type NatType int

const (
	_ NatType = iota
	STATIC_NAT
	DYNAMIC_NAT
	DESTINATION_NAT
	TWICE_NAT
)

func (nt NatType) String() string {
	return []string{"STATIC_NAT", "DYNAMIC_NAT", "DESTINATION_NAT"}[nt-1]
}

type NatMatchState int

const (
	NAT_MATCH_NONE NatMatchState = iota
	NAT_MATCH_OK
	NAT_MATCH_NOT_OK
)

type NatStatus int

const (
	_ NatStatus = iota
	NAT_ACTIVE
	NAT_INACTIVE
)

func (ns NatStatus) String() string {
	return []string{"NAT_ACTIVE", "NAT_INACTIVE"}[ns-1]
}

// func (a NatType) String() string {
// return []string{"STATIC_NAT", "DYNAMIC_NAT", "DESTINATION_NAT"}[a-1]
// }
type FirewallConfigAction interface {
	RunConfig(interface{}) (interface{}, error)
}

type ZoneFirewall interface {
	Zone() string
}

type PoolIdFirewall interface {
	NextPoolId(id string) string
}

// type IteratorOption interface {
// 	Apply(interface{})
// }

type IteratorOption func(interface{})

type IteratorFirewall interface {
	PolicyIterator(opts ...IteratorOption) NamerIterator
	AclIterator(opts ...IteratorOption) NamerIterator
	NetworkIterator(opts ...IteratorOption) NamerIterator
	ServiceIterator(opts ...IteratorOption) NamerIterator
	SnatIterator(opts ...IteratorOption) NamerIterator
	DnatIterator(opts ...IteratorOption) NamerIterator
	StaticNatIterator(opts ...IteratorOption) NamerIterator
	NatPoolIterator(opts ...IteratorOption) NamerIterator
}

// 为每种迭代器类型定义具体的选项结构
type PolicyIteratorOption struct {
	// 通用选项字段
	Zone     string
	IPFamily network.IPFamily
	// 其他通用选项...

	// 特定选项字段（使用 interface{} 类型以支持不同防火墙的特定实现）
	SpecificOptions map[string]interface{}
}

// func (o PolicyIteratorOption) apply(i interface{}) {
// 	if it, ok := i.(*PolicyIterator); ok {
// 		// 应用选项到迭代器
// 		it.applyOptions(o)
// 	}
// }

// func WithZone(zone string) IteratorOption {
// 	return PolicyIteratorOption{Zone: zone}
// }

// func WithIPFamily(family network.IPFamily) IteratorOption {
// 	return PolicyIteratorOption{IPFamily: family}
// }

// func WithSpecificOption(key string, value interface{}) IteratorOption {
// 	return PolicyIteratorOption{
// 		SpecificOptions: map[string]interface{}{key: value},
// 	}
// }

type PolicyIdFirewall interface {
	NextPolicyId(ipType network.IPFamily) int
	FirstPolicyRuleId(ipType network.IPFamily) string
}

type NatObjectType int

const (
	_ NatObjectType = iota
	UNSUPPORTED
	VIP
	MIP
	SNAT_POOL
	INTERFACE
	NETWORK_OBJECT
	INLINE
)

type FirewallNode interface {
	// api.Node
	InputNat(intent *policy.Intent, inPort api.Port) processor.AbstractMatchResult
	// 用于在生成配置模板时，检查Dnat对应内部服务器是否已经进行过其他映射
	InputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, FirewallNatRule)
	OutputNat(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult
	InputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult
	OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult

	GetObjectByNetworkGroup(*network.NetworkGroup, ObjectSearchType, api.Port) (FirewallNetworkObject, bool)
	GetObjectByService(*service.Service, ObjectSearchType) (FirewallServiceObject, bool)
	GetPoolByNetworkGroup(ng *network.NetworkGroup, natType NatType) (FirewallNetworkObject, bool)
	Network(zone, name string) (*network.NetworkGroup, bool)
	Service(name string) (*service.Service, bool)
	L4Port(name string) (*service.L4Port, bool)
	HasObjectName(name string) bool
	HasPolicyName(name string) bool
	HasPoolName(name string) bool
	HasNatName(name string) bool
	// IfIndex() int
	Type() terminalmode.DeviceType

	// GetPolicyName 获取策略名称（用于不需要命名模板的防火墙，如ASA）
	// 如果返回空字符串，则使用命名模板生成
	GetPolicyName(ctx *PolicyContext) (string, error)

	// GetSupportedNatObjectTypes 获取该防火墙支持的NAT对象类型
	// natType: "DNAT" 或 "SNAT"
	// 返回支持的NAT对象类型列表：
	//   - DNAT: 可能返回 {VIP, MIP, NETWORK_OBJECT} 等
	//   - SNAT: 可能返回 {SNAT_POOL, INTERFACE, NETWORK_OBJECT, INLINE} 等
	// 其中 VIP、MIP、SNAT_POOL 表示对应的特殊语法layout
	// NETWORK_OBJECT 表示使用网络对象（地址对象）
	// INLINE 表示内联模式（在NAT策略中直接使用地址，不生成对象）
	GetSupportedNatObjectTypes(natType string) []NatObjectType

	// GetObjectByVipMipSnatPool 检查VIP/MIP/SNAT_POOL对象是否已存在（复用检查）
	// objectType: "VIP", "MIP", "SNAT_POOL"
	// intent: 包含real_ip、real_port等信息
	// 返回 (对象, 是否找到)
	GetObjectByVipMipSnatPool(objectType string, intent *policy.Intent) (FirewallNetworkObject, bool)

	// GenerateVipMipSnatPoolName 自动生成VIP/MIP/SNAT_POOL对象名称（可选）
	// 如果Node不提供此接口，则使用配置的命名模板
	// objectType: "VIP", "MIP", "SNAT_POOL"
	// intent: 包含real_ip、real_port等信息
	// metaData: 包含policy_name等元数据
	// 返回生成的对象名称，如果返回空字符串，则使用配置的命名模板
	GenerateVipMipSnatPoolName(objectType string, intent *policy.Intent, metaData map[string]interface{}) string

	GetReuseNatObject(natType string, intent *policy.Intent, metaData map[string]interface{}) (name string, reused bool)
	DetermineNatObjectType(natType string, metaData map[string]interface{}) (NatObjectType, bool)

	DefaultStep(fp *FirewallProcess)
	UpdateSnatStep(from, to api.Port, intent *policy.Intent, fp *FirewallProcess)
	FlyConfig(cli interface{})

	Policies() []FirewallPolicy
}

// RouteCheckFirewall 提供内部路由检查接口的防火墙节点
// 用于替代反射调用 IpRouteCheckInternal 方法
type RouteCheckFirewall interface {
	FirewallNode
	// IpRouteCheckInternal 内部路由检查方法，返回 RouteCheckResult（包含警告信息）
	IpRouteCheckInternal(netList network.NetworkList, inPort, vrf string, af network.IPFamily) *model.RouteCheckResult
}

type FirewallPort interface {
	api.Port
	MainIpv4() string
	MainIpv6() string
}

type FirewallNatRule interface {
	Name() string
	Cli() string
	Original() policy.PolicyEntryInf
	Translate() policy.PolicyEntryInf
	Extended() map[string]interface{}
}

type FirewallPolicy interface {
	Description() string
	Action() Action
	Name() string
	ID() string
	Cli() string
	PolicyEntry() policy.PolicyEntryInf
	Extended() map[string]interface{}
	FromZones() []string
	ToZones() []string
	FromPorts() []api.Port
	ToPorts() []api.Port

	// GetSourceAddressObject 获取策略使用的源地址对象
	// 如果策略使用地址组，返回地址组对象；如果使用单个地址对象，返回地址对象；如果未使用对象，返回 nil
	GetSourceAddressObject() (FirewallNetworkObject, bool)

	// GetDestinationAddressObject 获取策略使用的目标地址对象
	// 如果策略使用地址组，返回地址组对象；如果使用单个地址对象，返回地址对象；如果未使用对象，返回 nil
	GetDestinationAddressObject() (FirewallNetworkObject, bool)

	// GetServiceObject 获取策略使用的服务对象
	// 如果策略使用服务组，返回服务组对象；如果使用单个服务对象，返回服务对象；如果未使用对象，返回 nil
	GetServiceObject() (FirewallServiceObject, bool)
}

type FirewallMatchResult interface {
	//FromPort() api.Port
	//OutPort() api.Port
	//Action() Action
	//Name() string
	//Cli() string
	processor.MatchResult
}

type TemplatesRequest struct {
	Node    api.Node
	InPort  api.Port
	OutPort api.Port
	Intent  *policy.Intent
}

type FirewallServiceObject interface {
	api.JSONSerializer
	api.TypedInterface
	Cli() string
	Name() string
	Service(FirewallNode) *service.Service
	Type() FirewallObjectType
}

type FirewallNetworkObject interface {
	api.JSONSerializer
	api.TypedInterface
	Cli() string
	Name() string
	Network(FirewallNode) *network.NetworkGroup
	Type() FirewallObjectType
}

type FirewallL4PortObject interface {
	Cli() string
	Name() string
	L4Port(map[string]FirewallL4PortObject) *service.L4Port
	Type() FirewallObjectType
}

type ObjectReferenceMethod int

const (
	USE_ADDRESS ObjectReferenceMethod = iota + 1
	USE_SUBNET
	USE_IPRANGE
	USE_OBJECT
)

type FirewallObjectType int

const (
	POOL FirewallObjectType = iota + 1
	OBJECT_NETWORK
	OBJECT_SERVICE
	GROUP_NETWORK
	GROUP_SERVICE
	GROUP_PROTOCOL
	GROUP_ICMP_TYPE
	L4PORT
	OBJECT_POOL
)

func (aot FirewallObjectType) String() string {
	return []string{"POOL", "OBJECT_NETWORK", "OBJECT_SERVICE", "GROUP_NETWORK", "GROUP_SERVICE", "GROUP_PROTOCOL", "GROUP_ICMP_TYPE"}[aot-1]
}

type FirewallTemplates interface {
	MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *PolicyContext) (flyObject interface{}, cmdList command.CmdList)
	MakeDynamicNatCli(from, out api.Port, intent *policy.Intent, ctx *PolicyContext) (flyObject interface{}, cmdList command.CmdList)
	MakeInputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *PolicyContext) (flyObject interface{}, cmdList command.CmdList, moveRule []string)
	MakeOutputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *PolicyContext) (flyObject interface{}, cmdList command.CmdList)
	FlyObjectToFlattenCli(flyObject interface{}, ctx *PolicyContext) string
}

type UrlConfigStruct struct {
	Url    string
	Object interface{}
}

// NatPool 接口定义了 NAT 池的基本操作
type NatPool interface {
	ID() string
	Name() string
	MatchNetworkGroup(*network.NetworkGroup) bool
	Cli() string
}

type NatPoolManager interface {
	CreateNatPool(*network.NetworkGroup, string) (NatPool, error)
}

// PresetConfig 预设配置信息（用于黑白名单）
type PresetConfig struct {
	BlacklistPolicyName string `json:"blacklist_policy_name"`         // 预设黑名单策略名称
	BlacklistPolicyID   string `json:"blacklist_policy_id,omitempty"` // 预设黑名单策略ID
	WhitelistPolicyName string `json:"whitelist_policy_name"`         // 预设白名单策略名称
	WhitelistPolicyID   string `json:"whitelist_policy_id,omitempty"` // 预设白名单策略ID
	BlacklistGroupName  string `json:"blacklist_group_name"`          // 预设黑名单地址组名称
	WhitelistGroupName  string `json:"whitelist_group_name"`          // 预设白名单地址组名称
}

// PresetConfigCheckResult 预设配置检查结果
type PresetConfigCheckResult struct {
	BlacklistPolicyOK bool              `json:"blacklist_policy_ok"` // 黑名单策略是否存在
	WhitelistPolicyOK bool              `json:"whitelist_policy_ok"` // 白名单策略是否存在
	BlacklistGroupOK  bool              `json:"blacklist_group_ok"`  // 黑名单地址组是否存在
	WhitelistGroupOK  bool              `json:"whitelist_group_ok"`  // 白名单地址组是否存在
	Details           map[string]string `json:"details,omitempty"`   // 详细信息
}

// BlacklistWhitelistHandler 黑白名单处理器接口
type BlacklistWhitelistHandler interface {
	// AddIPsToGroup 添加IP到预设地址组（策略方式）
	AddIPsToGroup(
		listType string, // "blacklist" 或 "whitelist"
		groupName string, // 预设地址组名称
		ips []string, // IP 地址列表
	) (string, error) // 返回CLI命令

	// RemoveIPsFromGroup 从预设地址组移除IP（策略方式）
	RemoveIPsFromGroup(
		listType string, // "blacklist" 或 "whitelist"
		groupName string, // 预设地址组名称
		ips []string, // IP 地址列表
	) (string, error) // 返回CLI命令

	// AddIPsViaAPI 通过API添加IP（专门功能方式）
	AddIPsViaAPI(
		listType string, // "blacklist" 或 "whitelist"
		ips []string, // IP 地址列表
	) (map[string]interface{}, error) // 返回API调用信息

	// RemoveIPsViaAPI 通过API移除IP（专门功能方式）
	RemoveIPsViaAPI(
		listType string, // "blacklist" 或 "whitelist"
		ips []string, // IP 地址列表
	) (map[string]interface{}, error) // 返回API调用信息

	// CheckPresetConfig 检查预设配置是否存在
	CheckPresetConfig(
		presetConfig *PresetConfig,
	) (*PresetConfigCheckResult, error)

	// GetImplementationMethod 获取实现方式
	GetImplementationMethod() string // 返回 "policy" 或 "api"
}
