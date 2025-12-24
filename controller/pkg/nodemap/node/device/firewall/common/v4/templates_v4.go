package v4

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
)

// CommonTemplatesV4 V4版本的通用模板实现
type CommonTemplatesV4 struct {
	ctx *GeneratorContext
}

// NewCommonTemplatesV4 创建新的V4通用模板实例（使用 Starlark 模板）
// node: 防火墙节点
// templateDir: Starlark 模板文件所在目录（如 "pkg/nodemap/node/device/firewall/common/v4/templates"）
// metaData: 元数据
func NewCommonTemplatesV4(node firewall.FirewallNode, templateDir string, metaData map[string]interface{}) (*CommonTemplatesV4, error) {
	// 创建 Starlark 模板适配器
	templates, err := NewStarlarkTemplatesAdapterFromNode(node, templateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create Starlark templates adapter: %w", err)
	}

	ctx := &GeneratorContext{
		Node:      node,
		Templates: templates,
		MetaData:  metaData,
	}

	return &CommonTemplatesV4{
		ctx: ctx,
	}, nil
}

// MakePolicyV4 生成安全策略（V4版本，使用struct组织）
func (ct *CommonTemplatesV4) MakePolicyV4(from, to api.Port, intent *policy.Intent, ctx *firewall.PolicyContext, metaData map[string]interface{}) (*PolicyResult, error) {
	// 更新上下文中的metaData
	ct.ctx.MetaData = metaData

	// 提取zone和接口信息
	fromZone, toZone := ct.extractZoneInfo(from, to, ctx)
	fromInterface, toInterface := ct.extractInterfaceInfo(from, to)
	// 提取area信息
	fromArea, toArea := ct.extractAreaInfo(from, to, intent)
	// 提取stub area信息
	isSourceStubArea, isDestinationStubArea := ct.extractStubAreaInfo(from, to, intent)
	ct.ctx.MetaData["isSourceStubArea"] = isSourceStubArea
	ct.ctx.MetaData["isDestinationStubArea"] = isDestinationStubArea
	ct.ctx.MetaData["sourceArea"] = fromArea
	ct.ctx.MetaData["destinationArea"] = toArea
	ct.ctx.MetaData["fromZone"] = fromZone
	ct.ctx.MetaData["toZone"] = toZone
	ct.ctx.MetaData["fromInterface"] = fromInterface
	ct.ctx.MetaData["toInterface"] = toInterface

	// 创建输入参数
	input := &GeneratorInput{
		Intent:                intent,
		FromPort:              from,
		ToPort:                to,
		FromZone:              fromZone,
		ToZone:                toZone,
		FromInterface:         fromInterface,
		ToInterface:           toInterface,
		FromArea:              fromArea,
		ToArea:                toArea,
		IsSourceStubArea:      isSourceStubArea,
		IsDestinationStubArea: isDestinationStubArea,
		Context:               ctx,
	}

	// 创建配置
	config := ct.buildPolicyConfig(metaData)

	// 创建生成器并生成
	generator := NewPolicyGenerator(ct.ctx, config)
	return generator.Generate(input)
}

// MakeNatPolicyV4 生成NAT策略（V4版本，使用struct组织）
func (ct *CommonTemplatesV4) MakeNatPolicyV4(from, to api.Port, intent *policy.Intent, ctx *firewall.PolicyContext, metaData map[string]interface{}) (*NatPolicyResult, error) {
	// 更新上下文中的metaData
	ct.ctx.MetaData = metaData

	// 提取zone和接口信息
	fromZone, toZone := ct.extractZoneInfo(from, to, ctx)
	fromInterface, toInterface := ct.extractInterfaceInfo(from, to)
	fromArea, toArea := ct.extractAreaInfo(from, to, intent)
	isSourceStubArea, isDestinationStubArea := ct.extractStubAreaInfo(from, to, intent)

	// 判断NAT类型
	natType := ct.determineNatType(intent, metaData)
	ct.ctx.MetaData["fromZone"] = fromZone
	ct.ctx.MetaData["toZone"] = toZone
	ct.ctx.MetaData["fromInterface"] = fromInterface
	ct.ctx.MetaData["toInterface"] = toInterface
	ct.ctx.MetaData["sourceArea"] = fromArea
	ct.ctx.MetaData["destinationArea"] = toArea
	ct.ctx.MetaData["isSourceStubArea"] = isSourceStubArea
	ct.ctx.MetaData["isDestinationStubArea"] = isDestinationStubArea

	// 创建输入参数
	input := &GeneratorInput{
		Intent:        intent,
		FromPort:      from,
		ToPort:        to,
		FromZone:      fromZone,
		ToZone:        toZone,
		FromInterface: fromInterface,
		ToInterface:   toInterface,
		Context:       ctx,
	}

	// 创建配置
	config := ct.buildNatPolicyConfig(metaData, natType)

	// 创建生成器并生成
	generator := NewNatPolicyGenerator(ct.ctx, config)
	return generator.Generate(input)
}

// buildPolicyConfig 构建策略配置
func (ct *CommonTemplatesV4) buildPolicyConfig(metaData map[string]interface{}) PolicyGeneratorConfig {
	config := PolicyGeneratorConfig{}

	// 策略名称相关
	config.PolicyName = getStringFromMeta(metaData, "policy_name", "")
	config.PolicyNameTemplate = getStringFromMeta(metaData, "securitypolicy.policy_name_template", "")
	if config.PolicyNameTemplate == "" {
		config.PolicyNameTemplate = getStringFromMeta(metaData, "policy_name_template", "")
	}
	if config.PolicyNameTemplate == "" {
		config.PolicyNameTemplate = "POLICY_{SEQ:id:5:1:1:MAIN}"
	}
	config.PolicyId = getStringFromMeta(metaData, "policy_id", "")

	// 对象模式配置
	config.AddressObjectConfig.UseSourceObject = getBoolFromMeta(metaData, "securitypolicy.use_source_address_object", false)
	config.AddressObjectConfig.UseDestinationObject = getBoolFromMeta(metaData, "securitypolicy.use_destination_address_object", false)
	config.ServiceObjectConfig.UseServiceObject = getBoolFromMeta(metaData, "securitypolicy.use_service_object", false)

	// 复用配置 - 只有在使用对象模式时才有意义
	// ReuseAddressObject 只有在源或目标使用对象时才有意义
	if config.AddressObjectConfig.UseSourceObject || config.AddressObjectConfig.UseDestinationObject {
		config.AddressObjectConfig.ReuseAddressObject = getBoolFromMeta(metaData, "securitypolicy.reuse_address_object", false)
	} else {
		config.AddressObjectConfig.ReuseAddressObject = false
	}
	// ReuseServiceObject 只有在使用服务对象时才有意义
	if config.ServiceObjectConfig.UseServiceObject {
		config.ServiceObjectConfig.ReuseServiceObject = getBoolFromMeta(metaData, "securitypolicy.reuse_service_object", false)
	} else {
		config.ServiceObjectConfig.ReuseServiceObject = false
	}
	config.ReusePolicy = getBoolFromMeta(metaData, "securitypolicy.reuse_policy", false)
	// 解析复用模式，默认为 standard
	reuseModeStr := getStringFromMeta(metaData, "securitypolicy.reuse_policy_mode", "standard")
	if reuseModeStr == "enhanced" {
		config.ReusePolicyMode = ReuseModeEnhanced
	} else {
		config.ReusePolicyMode = ReuseModeStandard
	}
	config.EmptyZoneMatchesAny = getBoolFromMeta(metaData, "securitypolicy.empty_zone_matches_any", true)

	// 多地址object配置
	config.AddressObjectConfig.PreferMultiSourceAddressObject = getBoolFromMeta(metaData, "securitypolicy.multi_source_address_object", false)
	config.AddressObjectConfig.PreferMultiDestinationAddressObject = getBoolFromMeta(metaData, "securitypolicy.multi_destination_address_object", false)
	// 多服务object配置
	config.ServiceObjectConfig.PreferMultiServiceObject = getBoolFromMeta(metaData, "securitypolicy.multi_service_object", false)

	config.AddressObjectConfig.SourceAddressGroupStyle = getStringFromMeta(metaData, "securitypolicy.source_address_group_style", "inline")
	config.AddressObjectConfig.DestinationAddressGroupStyle = getStringFromMeta(metaData, "securitypolicy.destination_address_group_style", "inline")
	config.ServiceObjectConfig.ServiceGroupStyle = getStringFromMeta(metaData, "securitypolicy.service_group_style", "inline")

	// 策略行为配置
	config.Action = getStringFromMeta(metaData, "action", "")
	config.Enable = getBoolFromMeta(metaData, "securitypolicy.enable", true)
	config.Description = getStringFromMeta(metaData, "description", "")

	return config
}

// buildNatPolicyConfig 构建NAT策略配置
func (ct *CommonTemplatesV4) buildNatPolicyConfig(metaData map[string]interface{}, natType string) NatPolicyGeneratorConfig {
	config := NatPolicyGeneratorConfig{}

	// NAT策略名称相关
	config.NatName = getStringFromMeta(metaData, "nat_name", "")
	config.NatNameTemplate = getStringFromMeta(metaData, "natpolicy.name_template", "")
	config.NatId = getStringFromMeta(metaData, "nat_id", "")
	config.PolicyId = getStringFromMeta(metaData, "policy_id", "")

	// NAT类型相关
	config.NatType = natType
	config.NatObjectConfig.NatType = natType
	config.NatObjectConfig.DnatObjectType = getStringFromMeta(metaData, "dnat_object_type", "")
	// 优先读取 snat_object_type，如果没有则读取 snat_pool_type
	snatObjectType := getStringFromMeta(metaData, "snat_object_type", "")
	if snatObjectType == "" {
		snatObjectType = getStringFromMeta(metaData, "snat_pool_type", "POOL")
	}
	config.NatObjectConfig.SnatPoolType = snatObjectType
	fmt.Printf("[DEBUG] buildNatPolicyConfig: snat_object_type=%q, snat_pool_type=%q, final SnatPoolType=%q\n",
		getStringFromMeta(metaData, "snat_object_type", ""),
		getStringFromMeta(metaData, "snat_pool_type", ""),
		config.NatObjectConfig.SnatPoolType)

	// 对象模式配置 - NAT策略优先读取 natpolicy.{type}.* 配置，否则使用 securitypolicy.* 配置
	var prefix string
	if natType == "DNAT" {
		prefix = "dnat"
	} else if natType == "SNAT" {
		prefix = "snat"
	}

	// 统一处理三个配置项：优先读取 natpolicy.{prefix}.*，否则使用 securitypolicy.*
	getNatPolicyBool := func(natKey, secKey string) bool {
		if prefix != "" {
			if val := getBoolFromMeta(metaData, fmt.Sprintf("natpolicy.%s.%s", prefix, natKey), false); val {
				return true
			}
		}
		return getBoolFromMeta(metaData, secKey, false)
	}

	config.AddressObjectConfig.UseSourceObject = getNatPolicyBool("source_object", "securitypolicy.use_source_address_object")
	config.AddressObjectConfig.UseDestinationObject = getNatPolicyBool("destination_object", "securitypolicy.use_destination_address_object")
	config.ServiceObjectConfig.UseServiceObject = getNatPolicyBool("service_object", "securitypolicy.use_service_object")

	// 复用配置 - 只有在使用对象模式时才有意义
	// ReuseAddressObject 只有在源或目标使用对象时才有意义
	if config.AddressObjectConfig.UseSourceObject || config.AddressObjectConfig.UseDestinationObject {
		config.AddressObjectConfig.ReuseAddressObject = getBoolFromMeta(metaData, "securitypolicy.reuse_address_object", false)
	} else {
		config.AddressObjectConfig.ReuseAddressObject = false
	}
	// ReuseServiceObject 只有在使用服务对象时才有意义
	if config.ServiceObjectConfig.UseServiceObject {
		config.ServiceObjectConfig.ReuseServiceObject = getBoolFromMeta(metaData, "securitypolicy.reuse_service_object", false)
	} else {
		config.ServiceObjectConfig.ReuseServiceObject = false
	}

	// 多地址object配置
	config.AddressObjectConfig.PreferMultiSourceAddressObject = getBoolFromMeta(metaData, "securitypolicy.multi_source_address_object", false)
	config.AddressObjectConfig.PreferMultiDestinationAddressObject = getBoolFromMeta(metaData, "securitypolicy.multi_destination_address_object", false)
	config.AddressObjectConfig.SourceAddressGroupStyle = getStringFromMeta(metaData, "securitypolicy.source_address_group_style", "inline")
	config.AddressObjectConfig.DestinationAddressGroupStyle = getStringFromMeta(metaData, "securitypolicy.destination_address_group_style", "inline")
	// 多服务object配置
	config.ServiceObjectConfig.PreferMultiServiceObject = getBoolFromMeta(metaData, "securitypolicy.multi_service_object", false)
	config.ServiceObjectConfig.ServiceGroupStyle = getStringFromMeta(metaData, "securitypolicy.service_group_style", "inline")

	// NAT策略行为配置
	config.Enable = getBoolFromMeta(metaData, "enable", true)
	config.Description = getStringFromMeta(metaData, "description", "")

	// NAT风格配置
	config.NatStyle = getStringFromMeta(metaData, "natpolicy.asa.nat_style", "twice")
	config.RealPortServiceObject = getBoolFromMeta(metaData, "natpolicy.asa.real_port_service_object", false)
	config.IsSourcePort = getBoolFromMeta(metaData, "natpolicy.asa.is_source_port", false)

	return config
}

// determineNatType 判断NAT类型
func (ct *CommonTemplatesV4) determineNatType(intent *policy.Intent, metaData map[string]interface{}) string {
	if intent.RealIp != "" {
		return "DNAT"
	}
	if intent.Snat != "" {
		return "SNAT"
	}

	snatPoolType := getStringFromMeta(metaData, "snat_pool_type", "POOL")
	if snatPoolType == "INTERFACE" {
		return "SNAT"
	}

	// 从input.nat/output.nat判断
	inputNat := getStringFromMeta(metaData, "input.nat", "")
	if inputNat == "natpolicy.dnat" {
		return "DNAT"
	}
	outputNat := getStringFromMeta(metaData, "output.nat", "")
	if outputNat == "natpolicy.snat" {
		return "SNAT"
	}

	return ""
}

// extractZoneInfo 提取zone信息
func (ct *CommonTemplatesV4) extractZoneInfo(from, to api.Port, ctx *firewall.PolicyContext) (fromZone, toZone string) {
	if from != nil {
		if zf, ok := from.(firewall.ZoneFirewall); ok {
			fromZone = zf.Zone()
		}
	}
	if to != nil {
		if zf, ok := to.(firewall.ZoneFirewall); ok {
			toZone = zf.Zone()
		}
	}

	if fromZone == "" && ctx != nil && ctx.InPort != nil {
		if zf, ok := ctx.InPort.(firewall.ZoneFirewall); ok {
			fromZone = zf.Zone()
		}
	}
	if toZone == "" && ctx != nil && ctx.OutPort != nil {
		if zf, ok := ctx.OutPort.(firewall.ZoneFirewall); ok {
			toZone = zf.Zone()
		}
	}

	return fromZone, toZone
}

// extractInterfaceInfo 提取接口信息
func (ct *CommonTemplatesV4) extractInterfaceInfo(from, to api.Port) (fromInterface, toInterface string) {
	if from != nil {
		fromInterface = from.Name()
	}
	if to != nil {
		toInterface = to.Name()
	}
	return fromInterface, toInterface
}

// extractAreaInfo 提取area信息
// 从 from 和 to port 中提取 area 信息，根据 intent 的 IP 地址族（优先 IPv4）来确定使用哪个 area
func (ct *CommonTemplatesV4) extractAreaInfo(from, to api.Port, intent *policy.Intent) (fromArea, toArea string) {
	// 确定 IP 地址族：优先使用 IPv4，如果 IPv4 为空则使用 IPv6
	var ipFamily network.IPFamily = network.IPv4
	if intent != nil && intent.Src() != nil {
		srcIPv4 := intent.Src().IPv4()
		if srcIPv4 == nil || srcIPv4.IsEmpty() {
			ipFamily = network.IPv6
		}
	} else if intent != nil && intent.Dst() != nil {
		dstIPv4 := intent.Dst().IPv4()
		if dstIPv4 == nil || dstIPv4.IsEmpty() {
			ipFamily = network.IPv6
		}
	}

	// 从 from port 获取 area
	if from != nil {
		fromArea = from.Area(ipFamily)
	}

	// 从 to port 获取 area
	if to != nil {
		toArea = to.Area(ipFamily)
	}

	return fromArea, toArea
}

// extractStubAreaInfo 提取stub area信息
// 从 from 和 to port 中提取 stub area 标记，根据 intent 的 IP 地址族（优先 IPv4）来确定使用哪个标记
func (ct *CommonTemplatesV4) extractStubAreaInfo(from, to api.Port, intent *policy.Intent) (isSourceStubArea, isDestinationStubArea bool) {
	// 确定 IP 地址族：优先使用 IPv4，如果 IPv4 为空则使用 IPv6
	var ipFamily network.IPFamily = network.IPv4
	if intent != nil && intent.Src() != nil {
		srcIPv4 := intent.Src().IPv4()
		if srcIPv4 == nil || srcIPv4.IsEmpty() {
			ipFamily = network.IPv6
		}
	} else if intent != nil && intent.Dst() != nil {
		dstIPv4 := intent.Dst().IPv4()
		if dstIPv4 == nil || dstIPv4.IsEmpty() {
			ipFamily = network.IPv6
		}
	}

	// 从 from port 获取 stub area 标记
	if from != nil {
		isSourceStubArea = from.IsStubArea(ipFamily)
	}

	// 从 to port 获取 stub area 标记
	if to != nil {
		isDestinationStubArea = to.IsStubArea(ipFamily)
	}

	return isSourceStubArea, isDestinationStubArea
}
