package v4

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/keys"
	"github.com/netxops/utils/policy"
)

// AddressObjectResult 地址对象生成结果
type AddressObjectResult struct {
	ObjectNames []string // 对象名称列表
	IsGroup     bool     // 是否是地址组
	CLIString   string   // 生成的CLI
	Keys        []string // 对象键列表
}

// ServiceObjectResult 服务对象生成结果
type ServiceObjectResult struct {
	ObjectNames  []string // 对象名称列表
	IsGroup      bool     // 是否是服务组
	CLIString    string   // 生成的CLI
	Keys         []string // 对象键列表
	IsIPProtocol bool     // 是否是IP协议（所有协议）
}

// VipMipResult VIP/MIP生成结果
type VipMipResult struct {
	ObjectName string   // 对象名称
	Type       string   // 类型：VIP 或 MIP
	CLIString  string   // 生成的CLI
	Keys       []string // 对象键列表
}

// SnatPoolResult SNAT_POOL生成结果
type SnatPoolResult struct {
	PoolName  string   // 地址池名称
	PoolId    string   // 地址池ID（可选）
	CLIString string   // 生成的CLI
	Keys      []string // 对象键列表
	Type      string   // 实现类型：POOL, ADDRESS_OBJECT, INTERFACE, INLINE
}

// PolicyResult 策略生成结果
type PolicyResult struct {
	PolicyName         string            // 策略名称
	PolicyId           string            // 策略ID
	CLIString          string            // 生成的CLI（包含所有CLI，用于向后兼容）
	SourceObjects      []string          // 源地址对象名称列表
	DestinationObjects []string          // 目标地址对象名称列表
	ServiceObjects     []string          // 服务对象名称列表
	Keys               []string          // 对象键列表（包含所有生成的对象）
	IsReused           bool              // 是否复用了现有策略
	ReusedPolicyName   string            // 复用的策略名称（如果复用）
	IsIPProtocol       bool              // 是否是IP协议（所有协议）
	FlyObject          map[string]string // 分离后的CLI对象（NETWORK, SERVICE, SECURITY_POLICY等）
}

// NatPolicyResult NAT策略生成结果
type NatPolicyResult struct {
	NatName            string            // NAT策略名称
	NatType            string            // NAT类型：DNAT 或 SNAT
	CLIString          string            // 生成的CLI（包含所有CLI，用于向后兼容）
	VipMipName         string            // VIP/MIP对象名称（DNAT）
	SnatPoolName       string            // SNAT_POOL名称（SNAT）
	SnatPoolId         string            // SNAT_POOL ID（SNAT，用于某些防火墙如USG，可能与SnatPoolName不同）
	SourceObjects      []string          // 源地址对象名称列表（如果生成）
	DestinationObjects []string          // 目标地址对象名称列表（如果生成）
	ServiceObjects     []string          // 服务对象名称列表（如果生成）
	Keys               []string          // 对象键列表（包含所有生成的对象）
	IsReused           bool              // 是否复用了现有VIP/MIP/POOL
	IsIPProtocol       bool              // 是否是IP协议（所有协议）
	FlyObject          map[string]string // 分离后的CLI对象（NETWORK, SERVICE, NAT, VIP, POOL等）
}

// ObjectResultMerger 接口，用于统一 PolicyResult 和 NatPolicyResult 的 CLI 合并操作
type ObjectResultMerger interface {
	// GetFlyObject 获取 FlyObject map
	GetFlyObject() map[string]string
	// GetCLIString 获取 CLIString
	GetCLIString() string
	// SetFlyObject 设置 FlyObject 中的某个类别
	SetFlyObject(category, value string)
	// AppendCLIString 追加 CLI 字符串
	AppendCLIString(cli string)
	// GetSourceObjects 获取源地址对象列表
	GetSourceObjects() []string
	// GetDestinationObjects 获取目标地址对象列表
	GetDestinationObjects() []string
	// GetServiceObjects 获取服务对象列表
	GetServiceObjects() []string
	// GetKeys 获取对象键列表
	GetKeys() []string
	// SetSourceObjects 设置源地址对象列表
	SetSourceObjects([]string)
	// SetDestinationObjects 设置目标地址对象列表
	SetDestinationObjects([]string)
	// SetServiceObjects 设置服务对象列表
	SetServiceObjects([]string)
	// AppendKeys 追加对象键
	AppendKeys([]string)
}

// 实现 ObjectResultMerger 接口 - PolicyResult
func (r *PolicyResult) GetFlyObject() map[string]string {
	if r.FlyObject == nil {
		r.FlyObject = make(map[string]string)
	}
	return r.FlyObject
}

func (r *PolicyResult) GetCLIString() string {
	return r.CLIString
}

func (r *PolicyResult) SetFlyObject(category, value string) {
	if r.FlyObject == nil {
		r.FlyObject = make(map[string]string)
	}
	r.FlyObject[category] = value
}

func (r *PolicyResult) AppendCLIString(cli string) {
	r.CLIString += cli
}

func (r *PolicyResult) GetSourceObjects() []string {
	return r.SourceObjects
}

func (r *PolicyResult) GetDestinationObjects() []string {
	return r.DestinationObjects
}

func (r *PolicyResult) GetServiceObjects() []string {
	return r.ServiceObjects
}

func (r *PolicyResult) GetKeys() []string {
	return r.Keys
}

func (r *PolicyResult) SetSourceObjects(objs []string) {
	r.SourceObjects = objs
}

func (r *PolicyResult) SetDestinationObjects(objs []string) {
	r.DestinationObjects = objs
}

func (r *PolicyResult) SetServiceObjects(objs []string) {
	r.ServiceObjects = objs
}

func (r *PolicyResult) AppendKeys(keys []string) {
	r.Keys = append(r.Keys, keys...)
}

// 实现 ObjectResultMerger 接口 - NatPolicyResult
func (r *NatPolicyResult) GetFlyObject() map[string]string {
	if r.FlyObject == nil {
		r.FlyObject = make(map[string]string)
	}
	return r.FlyObject
}

func (r *NatPolicyResult) GetCLIString() string {
	return r.CLIString
}

func (r *NatPolicyResult) SetFlyObject(category, value string) {
	if r.FlyObject == nil {
		r.FlyObject = make(map[string]string)
	}
	r.FlyObject[category] = value
}

func (r *NatPolicyResult) AppendCLIString(cli string) {
	r.CLIString += cli
}

func (r *NatPolicyResult) GetSourceObjects() []string {
	return r.SourceObjects
}

func (r *NatPolicyResult) GetDestinationObjects() []string {
	return r.DestinationObjects
}

func (r *NatPolicyResult) GetServiceObjects() []string {
	return r.ServiceObjects
}

func (r *NatPolicyResult) GetKeys() []string {
	return r.Keys
}

func (r *NatPolicyResult) SetSourceObjects(objs []string) {
	r.SourceObjects = objs
}

func (r *NatPolicyResult) SetDestinationObjects(objs []string) {
	r.DestinationObjects = objs
}

func (r *NatPolicyResult) SetServiceObjects(objs []string) {
	r.ServiceObjects = objs
}

func (r *NatPolicyResult) AppendKeys(keys []string) {
	r.Keys = append(r.Keys, keys...)
}

// GeneratorContext 生成器上下文，包含所有生成器需要的共享资源
type GeneratorContext struct {
	Node      firewall.FirewallNode
	Templates TemplatesV4
	MetaData  map[string]interface{}
}

// AddressObjectGeneratorConfig 地址对象生成器配置
type AddressObjectGeneratorConfig struct {
	UseSourceObject                     bool
	UseDestinationObject                bool
	ReuseAddressObject                  bool
	PreferMultiSourceAddressObject      bool   // 如果为true，优先使用多地址object而不是地址组
	PreferMultiDestinationAddressObject bool   // 如果为true，优先使用多地址object而不是地址组
	SourceAddressGroupStyle             string // 源地址组样式：object 或 inline
	DestinationAddressGroupStyle        string // 目标地址组样式：object 或 inline
}

// ServiceObjectGeneratorConfig 服务对象生成器配置
type ServiceObjectGeneratorConfig struct {
	UseServiceObject         bool
	ReuseServiceObject       bool
	PreferMultiServiceObject bool   // 如果为true，优先使用多服务object而不是服务组
	ServiceGroupStyle        string // 服务组样式：object 或 inline
}

// NatObjectGeneratorConfig NAT对象生成器配置
type NatObjectGeneratorConfig struct {
	NatType        string // "DNAT" 或 "SNAT"
	DnatObjectType string // "VIP", "MIP", "NETWORK_OBJECT", "INLINE"
	SnatPoolType   string // "SNAT_POOL", "INTERFACE", "NETWORK_OBJECT", "INLINE"
}

// PolicyReuseMode 策略复用模式
type PolicyReuseMode string

const (
	ReuseModeStandard PolicyReuseMode = "standard" // 标准复用（当前实现）
	ReuseModeEnhanced PolicyReuseMode = "enhanced" // 增强复用（新实现）
)

// PolicyGeneratorConfig 策略生成器配置
type PolicyGeneratorConfig struct {
	PolicyName          string
	PolicyNameTemplate  string
	PolicyId            string
	Action              string
	Enable              bool
	Description         string
	ReusePolicy         bool
	ReusePolicyMode     PolicyReuseMode // 复用模式：standard 或 enhanced
	EmptyZoneMatchesAny bool
	AddressObjectConfig AddressObjectGeneratorConfig
	ServiceObjectConfig ServiceObjectGeneratorConfig
}

// NatPolicyGeneratorConfig NAT策略生成器配置
type NatPolicyGeneratorConfig struct {
	NatName               string
	NatNameTemplate       string
	NatId                 string
	PolicyId              string
	NatType               string
	Enable                bool
	Description           string
	NatStyle              string // "twice" 或 "object" (仅ASA)
	AddressObjectConfig   AddressObjectGeneratorConfig
	ServiceObjectConfig   ServiceObjectGeneratorConfig
	NatObjectConfig       NatObjectGeneratorConfig
	RealPortServiceObject bool
	IsSourcePort          bool
}

// TemplatesV4 模板接口，提供V4版本的layouts
type TemplatesV4 interface {
	GetLayout(key keys.Keys) string
}

// GeneratorInput 生成器输入参数
type GeneratorInput struct {
	Intent                *policy.Intent
	FromPort              api.Port
	ToPort                api.Port
	FromZone              string
	ToZone                string
	FromInterface         string
	ToInterface           string
	FromArea              string
	ToArea                string
	IsSourceStubArea      bool
	IsDestinationStubArea bool
	Context               *firewall.PolicyContext
}
