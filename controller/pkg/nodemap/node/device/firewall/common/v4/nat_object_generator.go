package v4

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/keys"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
)

// NatObjectGenerator NAT对象生成器（VIP/MIP/SNAT_POOL）
type NatObjectGenerator struct {
	ctx    *GeneratorContext
	config NatObjectGeneratorConfig
	om     *common.ObjectNameManager
}

// NewNatObjectGenerator 创建NAT对象生成器
func NewNatObjectGenerator(ctx *GeneratorContext, config NatObjectGeneratorConfig) *NatObjectGenerator {
	return &NatObjectGenerator{
		ctx:    ctx,
		config: config,
		om:     common.NewObjectNameManager(),
	}
}

// Generate 生成NAT对象
func (g *NatObjectGenerator) Generate(intent *policy.Intent, fromZone, toZone string, from, to api.Port, ctx *firewall.PolicyContext) (*VipMipResult, *SnatPoolResult, error) {
	if g.config.NatType == "DNAT" {
		result, err := g.generateDnatObject(intent, fromZone, toZone, from, to, ctx)
		return result, nil, err
	} else if g.config.NatType == "SNAT" {
		result, err := g.generateSnatObject(intent, fromZone, toZone, from, to, ctx)
		return nil, result, err
	}
	return nil, nil, fmt.Errorf("unsupported NAT type: %s", g.config.NatType)
}

// generateDnatObject 生成DNAT对象（VIP/MIP）
func (g *NatObjectGenerator) generateDnatObject(intent *policy.Intent, fromZone, toZone string, from, to api.Port, ctx *firewall.PolicyContext) (*VipMipResult, error) {
	result := &VipMipResult{
		Keys: []string{},
	}

	// 检查复用
	reusedName, reused := g.ctx.Node.GetReuseNatObject("DNAT", intent, g.ctx.MetaData)
	if reused {
		result.ObjectName = reusedName
		result.Keys = append(result.Keys, reusedName)
		return result, nil
	}

	// 判断对象类型
	objectType := g.config.DnatObjectType
	if objectType == "" {
		natObjectType, ok := g.ctx.Node.DetermineNatObjectType("DNAT", g.ctx.MetaData)
		if !ok {
			return nil, fmt.Errorf("invalid DNAT configuration")
		}
		objectType = natObjectTypeToString(natObjectType)
	}

	// INLINE 模式不生成对象
	if objectType == "INLINE" {
		return result, nil
	}

	// 根据对象类型生成
	switch objectType {
	case "NETWORK_OBJECT":
		return g.generateDnatNetworkObject(intent, ctx)
	case "VIP", "MIP":
		return g.generateVipMip(intent, objectType, fromZone, toZone, from, to, ctx)
	default:
		return nil, fmt.Errorf("unsupported DNAT object type: %s", objectType)
	}
}

// generateDnatNetworkObject 生成DNAT网络对象
func (g *NatObjectGenerator) generateDnatNetworkObject(intent *policy.Intent, ctx *firewall.PolicyContext) (*VipMipResult, error) {
	if intent.RealIp == "" {
		return nil, fmt.Errorf("RealIp is empty")
	}

	realIpNg, _ := network.NewNetworkGroupFromString(intent.RealIp)
	addressIntent := &policy.Intent{
		PolicyEntry: *policy.NewPolicyEntryWithAll(
			network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
			realIpNg,
			nil,
		),
		RealIp:   intent.RealIp,
		RealPort: intent.RealPort,
	}

	// 使用地址对象生成器
	addrConfig := AddressObjectGeneratorConfig{
		ReuseAddressObject: getBoolFromMeta(g.ctx.MetaData, "securitypolicy.reuse_address_object", false),
	}
	addrGen := NewAddressObjectGenerator(g.ctx, addrConfig)
	addrResult, err := addrGen.Generate(addressIntent, false, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create address object: %w", err)
	}

	if len(addrResult.ObjectNames) > 0 {
		return &VipMipResult{
			ObjectName: addrResult.ObjectNames[0],
			Type:       "NETWORK_OBJECT",
			CLIString:  addrResult.CLIString,
			Keys:       addrResult.Keys,
		}, nil
	}

	return nil, fmt.Errorf("failed to create address object: no object names returned")
}

// generateVipMip 生成VIP/MIP对象
func (g *NatObjectGenerator) generateVipMip(intent *policy.Intent, objType, fromZone, toZone string, from, to api.Port, ctx *firewall.PolicyContext) (*VipMipResult, error) {
	result := &VipMipResult{
		Type: objType,
		Keys: []string{},
	}

	// 生成对象名称
	objectName := g.generateVipMipName(intent, objType)
	key := keys.NewKeyBuilder(objectName).Separator("_")
	key, isNew, err := g.generateUniqueObjectName(keys.NewAutoIncrementKeys(key, 2), intent.Dst())
	if err != nil {
		return nil, fmt.Errorf("failed to generate unique object name: %v", err)
	}

	// 准备meta数据
	vipMipMeta := g.prepareVipMipMetaData(intent, fromZone, toZone, from, to)
	vipMipMeta["object_name"] = key.String()
	vipMipMeta["obj_type"] = objType
	if !isNew {
		vipMipMeta["is_reused"] = true
	} else {
		vipMipMeta["is_reused"] = false
	}

	// 如果未复用，直接使用 Starlark 模板适配器渲染
	if isNew {
		if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
			// 直接基于 objType 判断是 VIP 还是 MIP
			var templateName string
			if objType == "VIP" {
				templateName = "VIP"
			} else if objType == "MIP" {
				templateName = "MIP"
			} else {
				return nil, fmt.Errorf("unsupported objType: %s", objType)
			}

			vipMipCli, err := adapter.RenderStarlarkTemplate(templateName, intent, vipMipMeta)
			if err != nil {
				return nil, fmt.Errorf("failed to render Starlark template '%s': %w", templateName, err)
			}
			if vipMipCli == "" {
				return nil, fmt.Errorf("failed to render Starlark template '%s': empty result", templateName)
			}
			result.CLIString = vipMipCli
		} else {
			return nil, fmt.Errorf("templates adapter is not StarlarkTemplatesAdapter")
		}
	}

	result.ObjectName = key.String()
	result.Keys = append(result.Keys, key.String())

	return result, nil
}

// generateSnatObject 生成SNAT对象（SNAT_POOL）
func (g *NatObjectGenerator) generateSnatObject(intent *policy.Intent, fromZone, toZone string, from, to api.Port, ctx *firewall.PolicyContext) (*SnatPoolResult, error) {
	result := &SnatPoolResult{
		Keys: []string{},
	}

	// 判断对象类型（在检查复用之前，因为 INTERFACE 模式不检查复用）
	objectType := g.config.SnatPoolType
	fmt.Printf("[DEBUG] generateSnatObject: config.SnatPoolType=%s\n", objectType)
	if objectType == "" {
		natObjectType, ok := g.ctx.Node.DetermineNatObjectType("SNAT", g.ctx.MetaData)
		if !ok {
			return nil, fmt.Errorf("invalid SNAT configuration")
		}
		objectType = natObjectTypeToString(natObjectType)
		fmt.Printf("[DEBUG] generateSnatObject: DetermineNatObjectType returned %s\n", objectType)
	}

	// 兼容处理：如果 objectType 是 "POOL"，转换为 "SNAT_POOL"
	if objectType == "POOL" {
		objectType = "SNAT_POOL"
		fmt.Printf("[DEBUG] generateSnatObject: converted POOL to SNAT_POOL\n")
	}

	fmt.Printf("[DEBUG] generateSnatObject: final objectType=%s\n", objectType)

	// INLINE 或 INTERFACE 模式不生成对象，也不检查复用
	if objectType == "INLINE" || objectType == "INTERFACE" {
		// 返回一个空的 result，确保 PoolName 为空
		fmt.Printf("[DEBUG] generateSnatObject: INTERFACE/INLINE mode, returning empty SnatPoolResult (PoolName=\"\", Type=%s)\n", objectType)
		return &SnatPoolResult{
			Type: objectType,
			Keys: []string{},
		}, nil
	}

	// 检查复用（仅对 SNAT_POOL 和 NETWORK_OBJECT 模式）
	reusedName, reused := g.ctx.Node.GetReuseNatObject("SNAT", intent, g.ctx.MetaData)
	if reused {
		result.PoolName = reusedName
		result.PoolId = reusedName
		result.Keys = append(result.Keys, reusedName)
		return result, nil
	}

	// 根据对象类型生成
	switch objectType {
	case "NETWORK_OBJECT":
		return g.generateSnatNetworkObject(intent, ctx)
	case "SNAT_POOL":
		return g.generateSnatPool(intent, fromZone, toZone, from, to, ctx)
	default:
		return nil, fmt.Errorf("unsupported SNAT object type: %s", objectType)
	}
}

// generateSnatNetworkObject 生成SNAT网络对象
func (g *NatObjectGenerator) generateSnatNetworkObject(intent *policy.Intent, ctx *firewall.PolicyContext) (*SnatPoolResult, error) {
	if intent.Snat == "" {
		return nil, fmt.Errorf("snat is empty")
	}

	snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SNAT network: %v", err)
	}

	// 检查是否已存在
	existingObj, foundExisting := g.ctx.Node.GetObjectByNetworkGroup(snatNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
	if foundExisting {
		return &SnatPoolResult{
			PoolName: existingObj.Name(),
			PoolId:   existingObj.Name(),
			Type:     "NETWORK_OBJECT",
			Keys:     []string{existingObj.Name()},
		}, nil
	}

	// 生成新对象
	addressIntent := &policy.Intent{
		PolicyEntry: *policy.NewPolicyEntryWithAll(
			snatNg,
			network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
			nil,
		),
		Snat: intent.Snat,
	}

	addrConfig := AddressObjectGeneratorConfig{
		ReuseAddressObject: getBoolFromMeta(g.ctx.MetaData, "securitypolicy.reuse_address_object", false),
	}
	addrGen := NewAddressObjectGenerator(g.ctx, addrConfig)
	addrResult, err := addrGen.Generate(addressIntent, true, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create address object for SNAT_POOL: %v", err)
	}

	if len(addrResult.ObjectNames) > 0 {
		return &SnatPoolResult{
			PoolName:  addrResult.ObjectNames[0],
			PoolId:    addrResult.ObjectNames[0],
			CLIString: addrResult.CLIString,
			Type:      "NETWORK_OBJECT",
			Keys:      addrResult.Keys,
		}, nil
	}

	return nil, fmt.Errorf("failed to create address object for SNAT_POOL")
}

// generateSnatPool 生成SNAT_POOL对象
// 基于 v2 的 MakeSnatPoolV2 逻辑
func (g *NatObjectGenerator) generateSnatPool(intent *policy.Intent, fromZone, toZone string, from, to api.Port, ctx *firewall.PolicyContext) (*SnatPoolResult, error) {
	result := &SnatPoolResult{
		Type: "SNAT_POOL",
		Keys: []string{},
	}

	// 获取layout
	layout := g.ctx.Templates.GetLayout(keys.NewKeyBuilder("SnatPool", "OneLoop"))
	if layout == "" || strings.TrimSpace(layout) == "" {
		return nil, fmt.Errorf("SNAT_POOL layout is empty")
	}

	// 从配置读取控制变量
	poolName := getStringFromMeta(g.ctx.MetaData, "pool_name", "")
	poolNameTemplate := getStringFromMeta(g.ctx.MetaData, "snat_object_name_template", "")

	// 生成池名称（参考 v2 的逻辑）
	if poolName == "" && poolNameTemplate != "" {
		var snatNg *network.NetworkGroup
		if intent.Snat != "" {
			ng, err := network.NewNetworkGroupFromString(intent.Snat)
			if err == nil {
				snatNg = ng
			}
		}
		if snatNg != nil {
			// 将 snat 添加到 metaData，以便模板中的 {snat} 占位符可以访问
			nameMeta := copyMap(g.ctx.MetaData)
			nameMeta["snat"] = intent.Snat
			// 使用 DSL 生成对象名称（简化实现，参考 v2 的 generateObjectNameFromTemplate）
			poolName = strings.TrimSpace(formatWithNetworkGroup(g.ctx, snatNg, poolNameTemplate, nameMeta))
		}
	}
	if poolName == "" {
		poolName = "SNAT_POOL"
	}

	// 检查池复用（参考 v2 的逻辑）
	// 对于 SNAT_POOL，应该使用 intent.Snat 对应的网络组来检查对象是否已存在
	var snatNg *network.NetworkGroup
	if intent.Snat != "" {
		ng, err := network.NewNetworkGroupFromString(intent.Snat)
		if err == nil {
			snatNg = ng
		}
	}
	// 如果无法解析 Snat，使用 intent.Src() 作为 fallback
	if snatNg == nil {
		snatNg = intent.Src()
	}

	// 检查复用（参考 v2 的 GetReuseNatObject 逻辑）
	reusedName, reused := g.ctx.Node.GetReuseNatObject("SNAT", intent, g.ctx.MetaData)
	if reused && reusedName != "" {
		// 池被复用，不生成 CLI
		result.PoolName = reusedName
		result.PoolId = reusedName
		result.Keys = append(result.Keys, reusedName)
		return result, nil
	}

	// 准备meta数据
	poolMeta := copyMap(g.ctx.MetaData)
	poolMeta["snat_pool_type"] = "POOL"
	poolMeta["pool_name"] = poolName

	// 将 snat 添加到 poolMeta，以便 DSL 模板可以直接使用 {snat}
	if intent.Snat != "" {
		poolMeta["snat"] = intent.Snat
		poolMeta["has_snat"] = true
	}

	// 对于需要数字 pool_id 的设备（如 USG），检查 node 是否实现了 PoolIdFirewall 接口
	var poolId string
	if poolIdFirewall, ok := g.ctx.Node.(firewall.PoolIdFirewall); ok {
		// 尝试从 metaData 获取 pool_id，如果没有则使用 NextPoolId 生成
		existingPoolId := getStringFromMeta(g.ctx.MetaData, "pool_id", "")
		poolId = poolIdFirewall.NextPoolId(existingPoolId)
		poolMeta["pool_id"] = poolId
	} else {
		poolId = poolName
		poolMeta["pool_id"] = poolId
	}

	// 设置 section_count（USG 格式需要，通常为 0 表示只有一个 section）
	poolMeta["section_count"] = "0"

	// 创建临时intent，将snat网络组设置到Src中，以便模板可以使用intent.src
	var poolIntent *policy.Intent
	if intent.Snat != "" && snatNg != nil {
		poolIntent = &policy.Intent{
			PolicyEntry: *policy.NewPolicyEntryWithAll(
				snatNg,
				intent.Dst(),
				intent.Service(),
			),
		}
	}
	if poolIntent == nil {
		poolIntent = intent
	}

	// 生成CLI
	if layout != "" && strings.TrimSpace(layout) != "" {
		poolCli := renderLayout(g.ctx, poolIntent, layout, poolMeta)
		if poolCli != "" {
			result.CLIString = poolCli
		}
	}

	result.PoolName = poolName
	result.PoolId = poolId // 使用生成的 poolId，可能与 PoolName 不同（如 USG 的情况）
	result.Keys = append(result.Keys, poolName)

	return result, nil
}

// generateVipMipName 生成VIP/MIP对象名称
func (g *NatObjectGenerator) generateVipMipName(intent *policy.Intent, objType string) string {
	// 优先使用直接指定的对象名称
	objectName := getStringFromMeta(g.ctx.MetaData, "object_name", "")
	if objectName != "" {
		return objectName
	}

	// 只支持 vip_name_template 和 mip_name_template
	var nameTemplate string
	if objType == "VIP" {
		nameTemplate = getStringFromMeta(g.ctx.MetaData, "vip_name_template", "")
	} else if objType == "MIP" {
		nameTemplate = getStringFromMeta(g.ctx.MetaData, "mip_name_template", "")
	}

	// 如果有模板，直接通过 intent 进行渲染
	if nameTemplate != "" {
		nameMeta := copyMap(g.ctx.MetaData)
		objectName = strings.TrimSpace(formatWithIntent(g.ctx, intent, nameTemplate, nameMeta))
		if objectName != "" {
			return objectName
		}
	}

	// 如果没有对应的 template，直接返回一个预设名称
	// if intent.RealIp != "" {
	// 	return objType + "_" + strings.ReplaceAll(intent.RealIp, ".", "_")
	// }
	return objType + "_OBJECT"
}

// prepareVipMipMetaData 准备VIP/MIP渲染所需的meta数据
func (g *NatObjectGenerator) prepareVipMipMetaData(intent *policy.Intent, fromZone, toZone string, from, to api.Port) map[string]interface{} {
	vipMipMeta := copyMap(g.ctx.MetaData)

	if intent.RealPort != "" {
		vipMipMeta["has_real_port"] = true
		vipMipMeta["real_port"] = intent.RealPort
	}

	if intent.RealIp != "" {
		vipMipMeta["real_ip"] = intent.RealIp
		if strings.Contains(intent.RealIp, "-") {
			parts := strings.Split(intent.RealIp, "-")
			if len(parts) == 2 {
				vipMipMeta["real_ip_start"] = strings.TrimSpace(parts[0])
				vipMipMeta["real_ip_end"] = strings.TrimSpace(parts[1])
			}
		}
	}

	if fromZone != "" {
		vipMipMeta["fromZone"] = fromZone
	} else if from != nil {
		vipMipMeta["fromPort"] = from.Name()
	}
	if toZone != "" {
		vipMipMeta["toZone"] = toZone
	} else if to != nil {
		vipMipMeta["toPort"] = to.Name()
	}

	return vipMipMeta
}

// generateUniqueObjectName 生成唯一的对象名称
func (g *NatObjectGenerator) generateUniqueObjectName(auto *keys.AutoIncrementKeys, ng *network.NetworkGroup) (keys.Keys, bool, error) {
	var getIterator func() firewall.NamerIterator
	if iteratorNode, ok := g.ctx.Node.(firewall.IteratorFirewall); ok {
		getIterator = func() firewall.NamerIterator {
			return iteratorNode.NetworkIterator()
		}
	} else {
		getIterator = func() firewall.NamerIterator {
			return &emptyNamerIterator{}
		}
	}

	return common.GenerateObjectName(
		auto,
		ng,
		getIterator,
		g.ctx.Node,
		nil,
		common.RetryMethodNext,
		g.om,
		true,
	)
}

// natObjectTypeToString 将 NatObjectType 转换为字符串
func natObjectTypeToString(t firewall.NatObjectType) string {
	switch t {
	case firewall.VIP:
		return "VIP"
	case firewall.MIP:
		return "MIP"
	case firewall.SNAT_POOL:
		return "SNAT_POOL"
	case firewall.INTERFACE:
		return "INTERFACE"
	case firewall.NETWORK_OBJECT:
		return "NETWORK_OBJECT"
	case firewall.INLINE:
		return "INLINE"
	default:
		return "UNSUPPORTED"
	}
}
