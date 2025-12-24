package v4

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/keys"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

// PolicyGenerator 策略生成器
type PolicyGenerator struct {
	ctx           *GeneratorContext
	config        PolicyGeneratorConfig
	addressGen    *AddressObjectGenerator
	serviceGen    *ServiceObjectGenerator
	policyNameGen *PolicyNameGenerator
}

// NewPolicyGenerator 创建策略生成器
func NewPolicyGenerator(ctx *GeneratorContext, config PolicyGeneratorConfig) *PolicyGenerator {
	addressGen := NewAddressObjectGenerator(ctx, config.AddressObjectConfig)
	serviceGen := NewServiceObjectGenerator(ctx, config.ServiceObjectConfig)
	policyNameGen := NewPolicyNameGenerator(ctx)

	return &PolicyGenerator{
		ctx:           ctx,
		config:        config,
		addressGen:    addressGen,
		serviceGen:    serviceGen,
		policyNameGen: policyNameGen,
	}
}

// Generate 生成策略
func (g *PolicyGenerator) Generate(input *GeneratorInput) (*PolicyResult, error) {
	result := &PolicyResult{
		SourceObjects:      []string{},
		DestinationObjects: []string{},
		ServiceObjects:     []string{},
		Keys:               []string{},
		FlyObject:          make(map[string]string),
	}

	// 1. 生成策略名称和ID
	policyName, policyId, err := g.generatePolicyNameAndId(input.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to generate policy name and id: %v", err)
	}
	result.PolicyName = policyName
	result.PolicyId = policyId

	// 2. 处理策略复用
	var reuseResult *ReuseResult
	if g.config.ReusePolicy {
		var err error
		reuseResult, err = g.handlePolicyReuse(input.Intent, input.FromZone, input.ToZone)
		if err != nil {
			return nil, fmt.Errorf("failed to handle policy reuse: %v", err)
		}
		if reuseResult.IsReused {
			result.IsReused = true
			result.ReusedPolicyName = reuseResult.ReusedPolicyName
			result.PolicyName = reuseResult.ReusedPolicyName
			g.ctx.MetaData["policy_name"] = reuseResult.ReusedPolicyName
			g.ctx.MetaData["is_reused"] = true
			result.PolicyId = reuseResult.MatchedPolicy.ID()

			// 如果有组更新CLI，分别添加到对应的类别中
			if reuseResult.AddressGroupUpdateCLI != "" {
				g.mergeObjectCLI(result, "NETWORK", reuseResult.AddressGroupUpdateCLI)
			}
			if reuseResult.ServiceGroupUpdateCLI != "" {
				g.mergeObjectCLI(result, "SERVICE", reuseResult.ServiceGroupUpdateCLI)
			}

			// 如果所有差异都通过组更新处理了，直接返回，不再继续生成策略
			if !reuseResult.ShouldGeneratePolicy {
				// 只返回组更新CLI，不生成策略
				return result, nil
			}

			// 如果有更新后的 intent，使用它（用于生成包含差异的策略）
			if reuseResult.UpdatedIntent != nil {
				input.Intent = reuseResult.UpdatedIntent
			}
		}
	}

	// 3. 生成地址对象
	if g.config.AddressObjectConfig.UseSourceObject && input.Intent.Src() != nil && !input.Intent.Src().IsEmpty() {
		// 将源地址相关的 area 信息添加到 MetaData 中，供 AddressObjectGenerator 使用
		// if input.FromArea != "" {
		// 	g.ctx.MetaData["sourceArea"] = input.FromArea
		// }
		// if input.IsSourceStubArea {
		// 	g.ctx.MetaData["isStubArea"] = true
		// } else {
		// 	g.ctx.MetaData["isStubArea"] = false
		// }

		srcResult, err := g.addressGen.Generate(input.Intent, true, input.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to create source address object: %v", err)
		}
		result.SourceObjects = srcResult.ObjectNames
		result.AppendKeys(srcResult.Keys)
		if srcResult.CLIString != "" {
			g.mergeObjectCLI(result, "NETWORK", srcResult.CLIString)
		}
	}

	if g.config.AddressObjectConfig.UseDestinationObject && input.Intent.Dst() != nil && !input.Intent.Dst().IsEmpty() {
		// 将目标地址相关的 area 信息添加到 MetaData 中，供 AddressObjectGenerator 使用
		// if input.ToArea != "" {
		// 	g.ctx.MetaData["destinationArea"] = input.ToArea
		// }
		// if input.IsDestinationStubArea {
		// 	g.ctx.MetaData["isStubArea"] = true
		// } else {
		// 	g.ctx.MetaData["isStubArea"] = false
		// }

		dstResult, err := g.addressGen.Generate(input.Intent, false, input.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to create destination address object: %v", err)
		}
		result.DestinationObjects = dstResult.ObjectNames
		result.AppendKeys(dstResult.Keys)
		if dstResult.CLIString != "" {
			g.mergeObjectCLI(result, "NETWORK", dstResult.CLIString)
		}
	}

	// 4. 生成服务对象
	// 先检查是否为IP协议（无论是否使用服务对象，都需要检查）
	result.IsIPProtocol = false
	if input.Intent.Service() != nil {
		input.Intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
			if l3, ok := item.(*service.L3Protocol); ok && l3.Protocol() == service.IP {
				result.IsIPProtocol = true
				return false
			}
			return true
		})
	}

	if g.config.ServiceObjectConfig.UseServiceObject && input.Intent.Service() != nil && !input.Intent.Service().IsEmpty() {
		svcResult, err := g.serviceGen.Generate(input.Intent, input.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to create service object: %v", err)
		}
		result.ServiceObjects = svcResult.ObjectNames
		result.AppendKeys(svcResult.Keys)
		// 确保 IsIPProtocol 与 svcResult 一致
		result.IsIPProtocol = svcResult.IsIPProtocol
		if svcResult.CLIString != "" {
			g.mergeObjectCLI(result, "SERVICE", svcResult.CLIString)
		}
	}

	// 5. 生成策略CLI（根据复用结果决定是否生成）
	shouldGeneratePolicy := true
	if reuseResult != nil && reuseResult.IsReused {
		shouldGeneratePolicy = reuseResult.ShouldGeneratePolicy
	}

	if shouldGeneratePolicy {
		data := g.preparePolicyTemplateData(input, result)

		// 直接使用 Starlark 模板适配器渲染 "Policy" 模板
		var policyCli string
		if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
			var err error
			policyCli, err = adapter.RenderStarlarkTemplate("Policy", input.Intent, data)
			if err != nil {
				return nil, fmt.Errorf("failed to render Starlark template 'Policy': %w", err)
			}
			if policyCli == "" {
				return nil, fmt.Errorf("failed to render Starlark template 'Policy': empty result")
			}
		} else {
			return nil, fmt.Errorf("templates adapter is not StarlarkTemplatesAdapter")
		}

		result.FlyObject["SECURITY_POLICY"] = policyCli
		result.AppendCLIString(policyCli)
	}

	return result, nil
}

// generatePolicyNameAndId 生成策略名称和ID
func (g *PolicyGenerator) generatePolicyNameAndId(ctx *firewall.PolicyContext) (string, string, error) {
	// 如果配置中直接指定了策略名称，使用它
	if g.config.PolicyName != "" {
		policyId := g.config.PolicyId
		if policyId == "" {
			policyId = "1"
		}
		return g.config.PolicyName, policyId, nil
	}

	// 使用 PolicyNameGenerator 生成策略名称（支持 IDTemplate 和 DSL）
	// 将配置中的 PolicyNameTemplate 设置到 metaData 中
	if g.config.PolicyNameTemplate != "" {
		g.ctx.MetaData["policy_name_template"] = g.config.PolicyNameTemplate
	}
	if g.config.PolicyId != "" {
		g.ctx.MetaData["policy_id"] = g.config.PolicyId
	}

	mainID, policyName, policyId, err := g.policyNameGen.Generate(ctx, g.ctx.MetaData)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate policy name: %w", err)
	}

	// 如果 mainID > 0，说明使用了 IDTemplate 的 MAIN 标记，更新 policyId
	if mainID > 0 && policyId == "1" {
		policyId = fmt.Sprintf("%d", mainID)
	}

	return policyName, policyId, nil
}

// createDiffOnlyIntent 创建一个只包含差异部分的 Intent，保留元数据字段
func createDiffOnlyIntent(originalIntent *policy.Intent, diffSrc, diffDst *network.NetworkGroup, diffSrv *service.Service) *policy.Intent {
	newIntent := &policy.Intent{
		TicketNumber: originalIntent.TicketNumber,
		SubTicket:    originalIntent.SubTicket,
		Area:         originalIntent.Area,
		InputNode:    originalIntent.InputNode,
		Snat:         originalIntent.Snat,
		RealIp:       originalIntent.RealIp,
		RealPort:     originalIntent.RealPort,
	}

	// 只设置差异部分
	if diffSrc != nil {
		newIntent.SetSrc(diffSrc)
	} else {
		newIntent.SetSrc(network.NewNetworkGroup())
	}

	if diffDst != nil {
		newIntent.SetDst(diffDst)
	} else {
		newIntent.SetDst(network.NewNetworkGroup())
	}

	if diffSrv != nil {
		newIntent.SetService(diffSrv)
	} else {
		newIntent.SetService(&service.Service{})
	}

	return newIntent
}

// handlePolicyReuse 处理策略复用
func (g *PolicyGenerator) handlePolicyReuse(intent *policy.Intent, fromZone, toZone string) (*ReuseResult, error) {
	// 检查复用模式
	reuseMode := g.config.ReusePolicyMode
	if reuseMode == "" {
		reuseMode = ReuseModeStandard // 默认使用标准模式
	}

	// 如果使用增强模式，调用增强复用逻辑
	if reuseMode == ReuseModeEnhanced {
		return g.handleEnhancedPolicyReuse(intent, fromZone, toZone)
	}

	// 否则使用标准复用逻辑
	return g.handleStandardPolicyReuse(intent, fromZone, toZone)
}

// handleStandardPolicyReuse 处理标准策略复用（原有逻辑）
func (g *PolicyGenerator) handleStandardPolicyReuse(intent *policy.Intent, fromZone, toZone string) (*ReuseResult, error) {
	result := &ReuseResult{
		IsReused:             false,
		ShouldGeneratePolicy: true, // 标准模式下总是生成策略
	}

	// 使用 common.FindPolicyByIntent 查找匹配的策略
	matchConfig := common.MatchConfig{
		MatchSrc:       true,
		MatchDst:       true,
		MatchService:   true,
		MatchThreshold: 2,
	}
	emptyZoneMatchesAny := g.config.EmptyZoneMatchesAny
	matchConfig.EmptyZoneMatchesAny = &emptyZoneMatchesAny

	matchedPolicies := common.FindPolicyByIntent(g.ctx.Node, intent, fromZone, toZone, matchConfig)
	if len(matchedPolicies) == 0 {
		return result, nil
	}

	matchedPolicy := matchedPolicies[0]
	result.IsReused = true
	result.ReusedPolicyName = matchedPolicy.Name()
	result.MatchedPolicy = matchedPolicy

	// 计算差异
	diffSrc, diffDst, diffSrv, err := intent.PolicyEntry.SubtractWithTwoSame(matchedPolicy.PolicyEntry())
	if err == nil {
		if diffSrc != nil || diffDst != nil || diffSrv != nil {
			// 创建只包含差异部分的 Intent，保留元数据字段
			result.UpdatedIntent = createDiffOnlyIntent(intent, diffSrc, diffDst, diffSrv)
		}
	}

	return result, nil
}

// handleEnhancedPolicyReuse 处理增强策略复用
func (g *PolicyGenerator) handleEnhancedPolicyReuse(intent *policy.Intent, fromZone, toZone string) (*ReuseResult, error) {
	result := &ReuseResult{
		IsReused:             false,
		ShouldGeneratePolicy: true, // 默认需要生成策略，除非所有差异都通过组更新处理
	}

	// 使用 common.FindPolicyByIntent 查找匹配的策略
	matchConfig := common.MatchConfig{
		MatchSrc:       true,
		MatchDst:       true,
		MatchService:   true,
		MatchThreshold: 2,
	}
	emptyZoneMatchesAny := g.config.EmptyZoneMatchesAny
	matchConfig.EmptyZoneMatchesAny = &emptyZoneMatchesAny

	matchedPolicies := common.FindPolicyByIntent(g.ctx.Node, intent, fromZone, toZone, matchConfig)
	if len(matchedPolicies) == 0 {
		return result, nil
	}

	matchedPolicy := matchedPolicies[0]
	result.IsReused = true
	result.ReusedPolicyName = matchedPolicy.Name()
	result.MatchedPolicy = matchedPolicy

	// 分析策略使用的对象类型
	srcObj, srcObjFound := matchedPolicy.GetSourceAddressObject()
	dstObj, dstObjFound := matchedPolicy.GetDestinationAddressObject()
	svcObj, svcObjFound := matchedPolicy.GetServiceObject()

	// 判断是否为组
	srcIsGroup := srcObjFound && srcObj.Type() == firewall.GROUP_NETWORK
	dstIsGroup := dstObjFound && dstObj.Type() == firewall.GROUP_NETWORK
	svcIsGroup := svcObjFound && svcObj.Type() == firewall.GROUP_SERVICE

	// 计算差异
	diffSrc, diffDst, diffSrv, err := intent.PolicyEntry.SubtractWithTwoSame(matchedPolicy.PolicyEntry())
	if err != nil {
		// 如果计算差异失败，回退到标准模式
		return g.handleStandardPolicyReuse(intent, fromZone, toZone)
	}

	var addressGroupUpdateCLIs []string
	var serviceGroupUpdateCLIs []string
	var remainingDiffSrc *network.NetworkGroup
	var remainingDiffDst *network.NetworkGroup
	var remainingDiffSrv *service.Service

	// 处理源地址差异
	if diffSrc != nil && !diffSrc.IsEmpty() {
		if srcIsGroup {
			// 源地址使用地址组，生成组更新CLI
			groupCli, err := g.generateAddressGroupUpdate(srcObj, diffSrc, true)
			if err == nil && groupCli != "" {
				addressGroupUpdateCLIs = append(addressGroupUpdateCLIs, groupCli)
				result.SourceGroupUpdated = true
			} else {
				// 如果生成失败，需要生成策略，记录差异
				remainingDiffSrc = diffSrc
			}
		} else {
			// 源地址不使用组，需要生成策略，记录差异
			remainingDiffSrc = diffSrc
		}
	}

	// 处理目标地址差异
	if diffDst != nil && !diffDst.IsEmpty() {
		if dstIsGroup {
			// 目标地址使用地址组，生成组更新CLI
			groupCli, err := g.generateAddressGroupUpdate(dstObj, diffDst, false)
			if err == nil && groupCli != "" {
				addressGroupUpdateCLIs = append(addressGroupUpdateCLIs, groupCli)
				result.DestinationGroupUpdated = true
			} else {
				// 如果生成失败，需要生成策略，记录差异
				remainingDiffDst = diffDst
			}
		} else {
			// 目标地址不使用组，需要生成策略，记录差异
			remainingDiffDst = diffDst
		}
	}

	// 处理服务差异
	if diffSrv != nil && !diffSrv.IsEmpty() {
		if svcIsGroup {
			// 服务使用服务组，生成组更新CLI
			groupCli, err := g.generateServiceGroupUpdate(svcObj, diffSrv)
			if err == nil && groupCli != "" {
				serviceGroupUpdateCLIs = append(serviceGroupUpdateCLIs, groupCli)
				result.ServiceGroupUpdated = true
			} else {
				// 如果生成失败，需要生成策略，记录差异
				remainingDiffSrv = diffSrv
			}
		} else {
			// 服务不使用组，需要生成策略，记录差异
			remainingDiffSrv = diffSrv
		}
	}

	// 合并组更新CLI（分别合并地址组和服务组）
	if len(addressGroupUpdateCLIs) > 0 {
		result.AddressGroupUpdateCLI = strings.Join(addressGroupUpdateCLIs, "\n"+g.getSectionSeparator()+"\n")
	}
	if len(serviceGroupUpdateCLIs) > 0 {
		result.ServiceGroupUpdateCLI = strings.Join(serviceGroupUpdateCLIs, "\n"+g.getSectionSeparator()+"\n")
	}
	// 为了兼容性，也保留 GroupUpdateCLI（包含所有组更新）
	allGroupUpdateCLIs := append(addressGroupUpdateCLIs, serviceGroupUpdateCLIs...)
	if len(allGroupUpdateCLIs) > 0 {
		result.GroupUpdateCLI = strings.Join(allGroupUpdateCLIs, "\n"+g.getSectionSeparator()+"\n")
	}

	// 增强模式的核心逻辑：只要生成了任何组更新CLI（地址组或服务组），就不应该再生成策略CLI
	// 因为组更新已经处理了差异，不需要生成新的策略
	if len(allGroupUpdateCLIs) > 0 {
		// 生成了组更新CLI，不生成策略
		result.ShouldGeneratePolicy = false
		// 如果有剩余差异但已经通过组更新处理了，不需要设置 UpdatedIntent
		// 因为策略已经存在，只需要更新组即可
	} else if remainingDiffSrc != nil || remainingDiffDst != nil || remainingDiffSrv != nil {
		// 没有生成组更新CLI，但有差异，需要生成包含差异的策略
		// 创建只包含差异部分的 Intent，保留元数据字段
		result.UpdatedIntent = createDiffOnlyIntent(intent, remainingDiffSrc, remainingDiffDst, remainingDiffSrv)
		result.ShouldGeneratePolicy = true
	} else {
		// 没有差异，不需要生成策略
		result.ShouldGeneratePolicy = false
	}

	return result, nil
}

// preparePolicyTemplateData 准备策略模板数据
func (g *PolicyGenerator) preparePolicyTemplateData(input *GeneratorInput, result *PolicyResult) map[string]interface{} {
	data := copyMap(g.ctx.MetaData)

	data["policy_name"] = result.PolicyName
	data["policy_id"] = result.PolicyId
	data["fromZone"] = input.FromZone
	data["toZone"] = input.ToZone
	data["fromArea"] = input.FromArea
	data["toArea"] = input.ToArea
	data["sourceArea"] = input.FromArea
	data["destinationArea"] = input.ToArea
	if input.IsSourceStubArea {
		data["isSourceStubArea"] = true
	} else {
		data["isSourceStubArea"] = false
	}
	if input.IsDestinationStubArea {
		data["isDestinationStubArea"] = true
	} else {
		data["isDestinationStubArea"] = false
	}

	if result.IsReused {
		data["sourceZones"] = []interface{}{}
		data["destinationZones"] = []interface{}{}
	} else {
		data["sourceZones"] = []interface{}{input.FromZone}
		data["destinationZones"] = []interface{}{input.ToZone}
	}

	if input.FromPort != nil {
		data["fromPort"] = input.FromPort.Name()
	}
	if input.ToPort != nil {
		data["toPort"] = input.ToPort.Name()
	}

	if len(result.SourceObjects) > 0 {
		srcObjs := make([]interface{}, len(result.SourceObjects))
		for i, obj := range result.SourceObjects {
			srcObjs[i] = obj
		}
		data["src_objects"] = srcObjs
		data["sourceObjects"] = srcObjs
		data["has_source_objects"] = true
	}

	if len(result.DestinationObjects) > 0 {
		dstObjs := make([]interface{}, len(result.DestinationObjects))
		for i, obj := range result.DestinationObjects {
			dstObjs[i] = obj
		}
		data["dst_objects"] = dstObjs
		data["destinationObjects"] = dstObjs
		data["has_destination_objects"] = true
	}

	if len(result.ServiceObjects) > 0 {
		svcObjs := make([]interface{}, len(result.ServiceObjects))
		for i, obj := range result.ServiceObjects {
			svcObjs[i] = obj
		}
		data["service_objects"] = svcObjs
		data["serviceObjects"] = svcObjs
		data["has_service_objects"] = true
	}
	// 设置IP协议标识供layout渲染使用（无论是否为IP协议都要设置，方便模板判断）
	if result.IsIPProtocol {
		data["is_ip_protocol"] = true
		data["has_ip_protocol"] = true
	} else {
		data["is_ip_protocol"] = false
	}

	if g.config.AddressObjectConfig.UseSourceObject {
		data["make_source"] = true
	}
	if g.config.AddressObjectConfig.UseDestinationObject {
		data["make_destination"] = true
	}
	if g.config.ServiceObjectConfig.UseServiceObject {
		data["make_service"] = true
	}

	data["enable"] = g.config.Enable
	data["action"] = getStringFromMeta(g.ctx.MetaData, "action", "")

	if g.config.Description != "" {
		data["description"] = g.config.Description
		data["has_description"] = true
	}

	return data
}

// normalizeAction 标准化action
// 根据防火墙类型转换action格式：
// - SecPath和DPTech使用 "pass"/"drop"
// - FortiGate使用 "accept"/"deny"
// - 其他设备使用 "permit"/"deny"
func (g *PolicyGenerator) normalizeAction(action string) string {
	if action == "" {
		action = "permit"
	}

	// 检查是否是 Starlark 模板适配器
	if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
		vendorName := adapter.GetVendorName()
		// SecPath和DPTech使用 "pass"/"drop"
		if vendorName == "secpath" || vendorName == "dptech" {
			if action == "permit" {
				return "pass"
			} else if action == "deny" {
				return "drop"
			}
			return action
		}

		// FortiGate使用 "accept"/"deny"
		if vendorName == "forti" {
			if action == "permit" {
				return "accept"
			}
			// "deny" 保持为 "deny"
			return action
		}
	}

	// 其他设备使用 "permit"/"deny"
	return action
}

// mergeObjectCLI 合并对象CLI
func (g *PolicyGenerator) mergeObjectCLI(result ObjectResultMerger, category string, newCLI string) {
	if newCLI == "" {
		return
	}

	sectionSeparator := g.getSectionSeparator()
	flyObject := result.GetFlyObject()

	if existing, exists := flyObject[category]; exists && existing != "" {
		existing = strings.TrimRight(existing, "\n\r")
		newCLI = strings.TrimLeft(newCLI, "\n\r")
		result.SetFlyObject(category, existing+"\n"+sectionSeparator+"\n"+newCLI)
	} else {
		result.SetFlyObject(category, newCLI)
	}

	currentCLI := result.GetCLIString()
	if currentCLI != "" {
		trimmedCurrentCLI := strings.TrimRight(currentCLI, "\n\r")
		trimmedNewCLI := strings.TrimLeft(newCLI, "\n\r")
		result.AppendCLIString("\n" + sectionSeparator + "\n" + trimmedCurrentCLI + "\n" + trimmedNewCLI + "\n")
	} else {
		result.AppendCLIString(newCLI + "\n")
	}
}

// getSectionSeparator 获取分隔符（使用通用的 getSectionSeparator 函数）
func (g *PolicyGenerator) getSectionSeparator() string {
	return getSectionSeparator(g.ctx)
}

// generateAddressGroupUpdate 生成地址组更新CLI（添加新地址到现有组）
func (g *PolicyGenerator) generateAddressGroupUpdate(groupObj firewall.FirewallNetworkObject, newAddresses *network.NetworkGroup, isSource bool) (string, error) {
	if groupObj == nil || newAddresses == nil || newAddresses.IsEmpty() {
		return "", fmt.Errorf("invalid parameters for address group update")
	}

	// 创建 intent，只包含新地址
	// 根据 isSource 决定放在 src 还是 dst
	intent := &policy.Intent{}
	if isSource {
		intent.SetSrc(newAddresses)
		intent.SetDst(network.NewNetworkGroupFromStringMust("0.0.0.0/0"))
	} else {
		intent.SetSrc(network.NewNetworkGroupFromStringMust("0.0.0.0/0"))
		intent.SetDst(newAddresses)
	}
	intent.SetService(&service.Service{})

	// 准备模板数据
	metaData := copyMap(g.ctx.MetaData)
	metaData["group_name"] = groupObj.Name()
	metaData["object_name"] = groupObj.Name()
	metaData["is_source"] = isSource

	// 检查配置：只有当 securitypolicy.address_group_member 为 true 时才生成成员对象
	addressGroupMember := getBoolFromMeta(g.ctx.MetaData, "securitypolicy.address_group_member", false)
	shouldGenerateMemberObjects := addressGroupMember

	var memberObjects []string
	var memberCLIs []string
	sectionSeparator := g.getSectionSeparator()

	// 获取地址对象命名模板
	networkObjectNameTemplate := getStringFromMeta(g.ctx.MetaData, "network_object_name_template", "")

	// 如果配置为生成成员对象，先为每个新地址生成成员对象
	if shouldGenerateMemberObjects {
		newAddresses.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
			memberNet := network.NewNetworkGroup()
			memberNet.Add(item)

			var key keys.Keys
			var isNew bool
			var err error

			// 如果启用复用，先尝试通过网络内容查找已有对象
			if g.config.AddressObjectConfig.ReuseAddressObject {
				existingObj, foundExisting := g.ctx.Node.GetObjectByNetworkGroup(memberNet, firewall.SEARCH_OBJECT_OR_GROUP, nil)
				if foundExisting {
					key = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
					isNew = false
				} else {
					key, isNew, err = g.addressGen.generateMemberObjectName(item, isSource, networkObjectNameTemplate)
					if err != nil {
						return false
					}
				}
			} else {
				key, isNew, err = g.addressGen.generateMemberObjectName(item, isSource, networkObjectNameTemplate)
				if err != nil {
					return false
				}
			}

			if isNew {
				// 生成成员对象CLI
				memberMeta := copyMap(g.ctx.MetaData)
				memberMeta["is_source"] = isSource
				memberMeta["object_name"] = key.String()

				// 创建一个新的 intent，确保源地址和目标地址信息正确
				// 对于源地址对象：memberNet 作为 src，0.0.0.0/0 作为 dst
				// 对于目标地址对象：0.0.0.0/0 作为 src，memberNet 作为 dst
				memberIntent := &policy.Intent{
					PolicyEntry: *policy.NewPolicyEntryWithAll(
						func() *network.NetworkGroup {
							if isSource {
								return memberNet
							}
							return network.NewNetworkGroupFromStringMust("0.0.0.0/0")
						}(),
						func() *network.NetworkGroup {
							if isSource {
								return network.NewNetworkGroupFromStringMust("0.0.0.0/0")
							}
							return memberNet
						}(),
						intent.Service(),
					),
				}

				memberCli := g.addressGen.renderAddressObject(memberIntent, memberMeta)
				if memberCli != "" {
					memberCLIs = append(memberCLIs, memberCli)
				}
			}

			memberObjects = append(memberObjects, key.String())
			return true
		})

		// 如果有成员对象，将成员对象名称传递给模板
		if len(memberObjects) > 0 {
			metaData["member_objects"] = memberObjects
		}
	}

	// 尝试使用 AddressGroupAddMember 模板
	if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
		groupCli, err := adapter.RenderStarlarkTemplate("AddressGroupAddMember", intent, metaData)
		if err == nil && groupCli != "" {
			// 合并成员对象CLI和地址组更新CLI
			var result strings.Builder
			if len(memberCLIs) > 0 {
				result.WriteString(strings.Join(memberCLIs, "\n"+sectionSeparator+"\n"))
				result.WriteString("\n" + sectionSeparator + "\n")
			}
			result.WriteString(groupCli)
			return result.String(), nil
		}
		// 如果模板不存在，尝试使用 AddressGroup 模板（但只生成添加成员的部分）
		// 这里可以进一步优化，但目前先返回错误
		return "", fmt.Errorf("AddressGroupAddMember template not found or failed: %v", err)
	}

	return "", fmt.Errorf("templates adapter is not StarlarkTemplatesAdapter")
}

// generateServiceGroupUpdate 生成服务组更新CLI（添加新服务到现有组）
func (g *PolicyGenerator) generateServiceGroupUpdate(groupObj firewall.FirewallServiceObject, newServices *service.Service) (string, error) {
	if groupObj == nil || newServices == nil || newServices.IsEmpty() {
		return "", fmt.Errorf("invalid parameters for service group update")
	}

	// 创建 intent，只包含新服务
	intent := &policy.Intent{
		PolicyEntry: *policy.NewPolicyEntryWithAll(
			network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
			network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
			newServices,
		),
	}

	// 准备模板数据
	metaData := copyMap(g.ctx.MetaData)
	metaData["group_name"] = groupObj.Name()
	metaData["object_name"] = groupObj.Name()

	// 检查配置：只有当 securitypolicy.service_group_member 为 true 时才生成成员对象
	serviceGroupMember := getBoolFromMeta(g.ctx.MetaData, "securitypolicy.service_group_member", false)
	shouldGenerateMemberObjects := serviceGroupMember

	var memberObjects []string
	var memberCLIs []string
	sectionSeparator := g.getSectionSeparator()

	// 获取服务对象命名模板和layout
	serviceObjectNameTemplate := getStringFromMeta(g.ctx.MetaData, "service_object_name_template", "")
	serviceObjectLayout := g.ctx.Templates.GetLayout(keys.NewKeyBuilder("ServiceObject", "OneLoop"))

	// 如果配置为生成成员对象，先为每个新服务生成成员对象
	if shouldGenerateMemberObjects {
		newServices.EachDetailed(func(item service.ServiceEntry) bool {
			memberSvc := &service.Service{}
			memberSvc.Add(item)

			var key keys.Keys
			var isNew bool
			var err error

			// 如果启用复用，先尝试通过服务内容查找已有对象
			if g.config.ServiceObjectConfig.ReuseServiceObject {
				existingObj, foundExisting := g.ctx.Node.GetObjectByService(memberSvc, firewall.SEARCH_OBJECT_OR_GROUP)
				if foundExisting {
					key = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
					isNew = false
				} else {
					key, isNew, err = g.serviceGen.generateMemberServiceName(item, serviceObjectNameTemplate, nil)
					if err != nil {
						return false
					}
				}
			} else {
				key, isNew, err = g.serviceGen.generateMemberServiceName(item, serviceObjectNameTemplate, nil)
				if err != nil {
					return false
				}
			}

			if isNew {
				// 生成成员对象CLI
				memberMeta := copyMap(g.ctx.MetaData)
				memberMeta["object_name"] = key.String()

				memberIntent := &policy.Intent{
					PolicyEntry: *policy.NewPolicyEntryWithAll(
						network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
						network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
						memberSvc,
					),
				}

				memberCli := renderLayout(g.ctx, memberIntent, serviceObjectLayout, memberMeta)
				if memberCli != "" {
					memberCLIs = append(memberCLIs, memberCli)
				}
			}

			memberObjects = append(memberObjects, key.String())
			return true
		})

		// 如果有成员对象，将成员对象名称传递给模板
		if len(memberObjects) > 0 {
			metaData["member_objects"] = memberObjects
		}
	}

	// 尝试使用 ServiceGroupAddMember 模板
	if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
		groupCli, err := adapter.RenderStarlarkTemplate("ServiceGroupAddMember", intent, metaData)
		if err == nil && groupCli != "" {
			// 合并成员对象CLI和服务组更新CLI
			var result strings.Builder
			if len(memberCLIs) > 0 {
				result.WriteString(strings.Join(memberCLIs, "\n"+sectionSeparator+"\n"))
				result.WriteString("\n" + sectionSeparator + "\n")
			}
			result.WriteString(groupCli)
			return result.String(), nil
		}
		// 如果模板不存在，尝试使用 ServiceGroup 模板（但只生成添加成员的部分）
		// 这里可以进一步优化，但目前先返回错误
		return "", fmt.Errorf("ServiceGroupAddMember template not found or failed: %v", err)
	}

	return "", fmt.Errorf("templates adapter is not StarlarkTemplatesAdapter")
}

// ReuseResult 策略复用结果
type ReuseResult struct {
	IsReused                bool
	ReusedPolicyName        string
	MatchedPolicy           firewall.FirewallPolicy
	UpdatedIntent           *policy.Intent
	SourceGroupUpdated      bool   // 源地址组是否更新
	DestinationGroupUpdated bool   // 目标地址组是否更新
	ServiceGroupUpdated     bool   // 服务组是否更新
	AddressGroupUpdateCLI   string // 地址组更新CLI（如果有）
	ServiceGroupUpdateCLI   string // 服务组更新CLI（如果有）
	GroupUpdateCLI          string // 组更新CLI（兼容性字段，包含所有组更新）
	ShouldGeneratePolicy    bool   // 是否需要生成策略CLI
}
