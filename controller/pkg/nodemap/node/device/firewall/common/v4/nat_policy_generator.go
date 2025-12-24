package v4

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/keys"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

// NatPolicyGenerator NAT策略生成器
type NatPolicyGenerator struct {
	ctx          *GeneratorContext
	config       NatPolicyGeneratorConfig
	addressGen   *AddressObjectGenerator
	serviceGen   *ServiceObjectGenerator
	natObjectGen *NatObjectGenerator
	natNameGen   *NatNameGenerator
}

// NewNatPolicyGenerator 创建NAT策略生成器
func NewNatPolicyGenerator(ctx *GeneratorContext, config NatPolicyGeneratorConfig) *NatPolicyGenerator {
	addressGen := NewAddressObjectGenerator(ctx, config.AddressObjectConfig)
	serviceGen := NewServiceObjectGenerator(ctx, config.ServiceObjectConfig)
	natObjectGen := NewNatObjectGenerator(ctx, config.NatObjectConfig)
	natNameGen := NewNatNameGenerator(ctx)

	return &NatPolicyGenerator{
		ctx:          ctx,
		config:       config,
		addressGen:   addressGen,
		serviceGen:   serviceGen,
		natObjectGen: natObjectGen,
		natNameGen:   natNameGen,
	}
}

// Generate 生成NAT策略
func (g *NatPolicyGenerator) Generate(input *GeneratorInput) (*NatPolicyResult, error) {
	result := &NatPolicyResult{
		NatType:            g.config.NatType,
		SourceObjects:      []string{},
		DestinationObjects: []string{},
		ServiceObjects:     []string{},
		Keys:               []string{},
		FlyObject:          make(map[string]string),
	}

	// 1. 生成NAT策略名称
	natName, natId, err := g.generateNatPolicyName(input.Intent, input.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to generate NAT policy name: %v", err)
	}
	result.NatName = natName
	if natId != "" {
		g.ctx.MetaData["nat_id"] = natId
		g.ctx.MetaData["policy_id"] = natId
	}

	// 2. 判断对象模式（简化实现，实际应该调用 determineObjectModeV3）
	useSourceObject := g.config.AddressObjectConfig.UseSourceObject
	useDestinationObject := g.config.AddressObjectConfig.UseDestinationObject
	useServiceObject := g.config.ServiceObjectConfig.UseServiceObject
	useRealPortServiceObject := g.config.RealPortServiceObject

	// 3. 生成地址对象
	if useSourceObject {
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

	if useDestinationObject {
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
	result.IsIPProtocol = input.Intent.Service() == nil
	if input.Intent.Service() != nil {
		input.Intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
			if l3, ok := item.(*service.L3Protocol); ok && l3.Protocol() == service.IP {
				result.IsIPProtocol = true
				return false
			}
			return true
		})
	}

	// 5. 生成服务对象
	if useServiceObject && !result.IsIPProtocol {
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

	// 6. 处理NAT对象（VIP/MIP或SNAT_POOL）
	vipMipResult, snatPoolResult, err := g.natObjectGen.Generate(input.Intent, input.FromZone, input.ToZone, input.FromPort, input.ToPort, input.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to process NAT object: %v", err)
	}

	fmt.Printf("[DEBUG] nat_policy_generator: vipMipResult=%v, snatPoolResult=%v\n", vipMipResult != nil, snatPoolResult != nil)
	if snatPoolResult != nil {
		fmt.Printf("[DEBUG] nat_policy_generator: snatPoolResult.PoolName=%q, snatPoolResult.Type=%q, snatPoolResult.PoolId=%q\n",
			snatPoolResult.PoolName, snatPoolResult.Type, snatPoolResult.PoolId)
	}

	if vipMipResult != nil {
		result.VipMipName = vipMipResult.ObjectName
		result.AppendKeys(vipMipResult.Keys)
		if vipMipResult.CLIString != "" {
			if vipMipResult.Type == "NETWORK_OBJECT" {
				// NETWORK_OBJECT 类型合并到 NETWORK
				g.mergeObjectCLI(result, "NETWORK", vipMipResult.CLIString)
			} else if vipMipResult.Type == "VIP" {
				g.mergeObjectCLI(result, "VIP", vipMipResult.CLIString)
			} else if vipMipResult.Type == "MIP" {
				g.mergeObjectCLI(result, "MIP", vipMipResult.CLIString)
			} else {
				// 默认合并到 NETWORK
				g.mergeObjectCLI(result, "NETWORK", vipMipResult.CLIString)
			}
		}
	}

	if snatPoolResult != nil {
		fmt.Printf("[DEBUG] nat_policy_generator: checking snatPoolResult, PoolName=%q, will set SnatPoolName=%v\n",
			snatPoolResult.PoolName, snatPoolResult.PoolName != "")
		if snatPoolResult.PoolName != "" {
			// 只有当 PoolName 不为空时才设置（INTERFACE 模式下 PoolName 为空）
			result.SnatPoolName = snatPoolResult.PoolName
			result.SnatPoolId = snatPoolResult.PoolId
			result.AppendKeys(snatPoolResult.Keys)
			if snatPoolResult.CLIString != "" {
				if snatPoolResult.Type == "NETWORK_OBJECT" {
					// NETWORK_OBJECT 类型合并到 NETWORK
					g.mergeObjectCLI(result, "NETWORK", snatPoolResult.CLIString)
				} else {
					// SNAT_POOL 类型合并到 POOL
					g.mergeObjectCLI(result, "POOL", snatPoolResult.CLIString)
				}
			}
			fmt.Printf("[DEBUG] nat_policy_generator: set result.SnatPoolName=%q\n", result.SnatPoolName)
		} else {
			fmt.Printf("[DEBUG] nat_policy_generator: PoolName is empty, NOT setting result.SnatPoolName\n")
		}
	} else {
		fmt.Printf("[DEBUG] nat_policy_generator: snatPoolResult is nil, NOT setting result.SnatPoolName\n")
	}
	fmt.Printf("[DEBUG] nat_policy_generator: final result.SnatPoolName=%q\n", result.SnatPoolName)

	// 7. 基于RealPort创建服务对象
	var realPortSvcResult *ServiceObjectResult
	var intentReverseSvcResult *ServiceObjectResult
	if input.Intent.RealPort != "" && useRealPortServiceObject {
		// 从原始服务获取协议（仅支持L4协议，因为需要端口）
		var protocol string
		if input.Intent.Service() != nil {
			input.Intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
				if l4, ok := item.(*service.L4Service); ok {
					protocol = strings.ToLower(l4.Protocol().String())
					return false
				}
				// L3协议不支持端口，跳过
				return true
			})
		}

		// 如果无法获取协议，默认使用TCP
		if protocol == "" {
			protocol = "tcp"
		}

		var realPortService *service.Service
		var intentReverseService *service.Service
		// 创建基于RealPort的服务对象
		if g.config.IsSourcePort {
			realPortService, err = service.NewServiceWithL4(protocol, input.Intent.RealPort, "")
			if err != nil {
				return nil, fmt.Errorf("failed to create real port service: %v", err)
			}

			s := input.Intent.Service().GenerateDestinationService()

			intentReverseService = &service.Service{}
			intentReverseService.Add(s.Reverse())
		} else {
			realPortService, err = service.NewServiceWithL4(protocol, "", input.Intent.RealPort)
			if err != nil {
				return nil, fmt.Errorf("failed to create real port service: %v", err)
			}
		}

		// 创建新的Intent，包含RealPort服务
		realPortIntent := &policy.Intent{
			PolicyEntry: *policy.NewPolicyEntryWithAll(
				input.Intent.Src(),
				input.Intent.Dst(),
				realPortService,
			),
			MetaData: map[string]string{
				"is_source_port": "true",
			},
		}

		// 使用ServiceObjectGenerator生成服务对象

		realPortSvcResult, err = g.serviceGen.Generate(realPortIntent, input.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to create real port service object: %v", err)
		}

		if intentReverseService != nil {
			intentReverseIntent := &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					input.Intent.Src(),
					input.Intent.Dst(),
					intentReverseService,
				),
				MetaData: map[string]string{
					"is_source_port": "true",
				},
			}
			intentReverseSvcResult, err = g.serviceGen.Generate(intentReverseIntent, input.Context)
			if err != nil {
				return nil, fmt.Errorf("failed to create intent reverse service object: %v", err)
			}
		}
		// 将生成的服务对象名称添加到结果中
		result.ServiceObjects = append(result.ServiceObjects, realPortSvcResult.ObjectNames...)
		result.AppendKeys(realPortSvcResult.Keys)
		if realPortSvcResult.CLIString != "" {
			g.mergeObjectCLI(result, "SERVICE", realPortSvcResult.CLIString)
		}

		if intentReverseSvcResult != nil {
			result.ServiceObjects = append(result.ServiceObjects, intentReverseSvcResult.ObjectNames...)
			result.AppendKeys(intentReverseSvcResult.Keys)
			if intentReverseSvcResult.CLIString != "" {
				g.mergeObjectCLI(result, "SERVICE", intentReverseSvcResult.CLIString)
			}
		}
	}

	// 8. 渲染NAT策略
	// 直接使用 Starlark 模板适配器渲染 "NatPolicy" 模板
	data := g.prepareNatPolicyTemplateData(input, result, vipMipResult, snatPoolResult, realPortSvcResult, intentReverseSvcResult)
	var natCli string
	if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
		var err error
		natCli, err = adapter.RenderStarlarkTemplate("NatPolicy", input.Intent, data)
		if err != nil {
			return nil, fmt.Errorf("failed to render Starlark template 'NatPolicy': %w", err)
		}
	} else {
		return nil, fmt.Errorf("templates adapter is not StarlarkTemplatesAdapter")
	}

	if natCli != "" {
		// if g.config.NatStyle == "object" {
		// 	// Object NAT: 追加到对象定义后
		// 	g.handleObjectNatSpecialCase(result, natCli, data)
		// } else {
		// Twice NAT: 使用独立的 NAT 配置
		result.FlyObject["NAT"] = natCli
		result.AppendCLIString(natCli)
		// }
	}

	return result, nil
}

// generateNatPolicyName 生成NAT策略名称
func (g *NatPolicyGenerator) generateNatPolicyName(intent *policy.Intent, ctx *firewall.PolicyContext) (string, string, error) {
	// 如果配置中直接指定了NAT名称，使用它
	if g.config.NatName != "" {
		natId := g.config.NatId
		if natId == "" {
			natId = g.config.PolicyId
		}
		if natId == "" {
			natId = "1"
		}
		return g.config.NatName, natId, nil
	}

	// 使用 NatNameGenerator 生成NAT策略名称（支持 IDTemplate 和 DSL）
	// 将配置中的 NatNameTemplate 设置到 metaData 中
	if g.config.NatNameTemplate != "" {
		g.ctx.MetaData["natpolicy.name_template"] = g.config.NatNameTemplate
	}
	if g.config.NatId != "" {
		g.ctx.MetaData["nat_id"] = g.config.NatId
	}
	if g.config.PolicyId != "" {
		g.ctx.MetaData["policy_id"] = g.config.PolicyId
	}

	mainID, natName, natId, err := g.natNameGen.Generate(intent, ctx, g.ctx.MetaData)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate NAT policy name: %w", err)
	}

	// 如果 mainID > 0，说明使用了 IDTemplate 的 MAIN 标记，更新 natId
	if mainID > 0 && natId == "" {
		natId = fmt.Sprintf("%d", mainID)
	}
	if natId == "" {
		natId = "1"
	}

	return natName, natId, nil
}

// selectNatPolicyLayout 选择NAT策略layout
func (g *NatPolicyGenerator) selectNatPolicyLayout() (string, error) {
	natStyle := g.config.NatStyle
	if natStyle == "" {
		natStyle = getStringFromMeta(g.ctx.MetaData, "natpolicy.asa.nat_style", "twice")
	}

	if natStyle == "object" {
		layout := g.ctx.Templates.GetLayout(keys.NewKeyBuilder("NatPolicy", "ObjectNat"))
		if layout == "" {
			return "", fmt.Errorf("NatPolicy.ObjectNat layout not found")
		}
		return layout, nil
	}

	layout := g.ctx.Templates.GetLayout(keys.NewKeyBuilder("NatPolicy", "OneLoop"))
	if layout == "" {
		return "", fmt.Errorf("NatPolicy.OneLoop layout not found")
	}
	return layout, nil
}

// prepareNatPolicyTemplateData 准备NAT策略模板数据
func (g *NatPolicyGenerator) prepareNatPolicyTemplateData(input *GeneratorInput, result *NatPolicyResult, vipMipResult *VipMipResult, snatPoolResult *SnatPoolResult, realPortSvcResult *ServiceObjectResult, intentReverseSvcResult *ServiceObjectResult) map[string]interface{} {
	data := copyMap(g.ctx.MetaData)

	if realPortSvcResult != nil {
		data["real_port_service_object"] = realPortSvcResult.ObjectNames
		data["real_port_service_object_keys"] = realPortSvcResult.Keys
		data["real_port_service_object_cli"] = realPortSvcResult.CLIString
	}

	if intentReverseSvcResult != nil {
		data["intent_reverse_service_object"] = intentReverseSvcResult.ObjectNames
		data["intent_reverse_service_object_keys"] = intentReverseSvcResult.Keys
		data["intent_reverse_service_object_cli"] = intentReverseSvcResult.CLIString
	}

	data["nat_type"] = result.NatType
	data["nat_style"] = g.config.NatStyle
	data["nat_name"] = result.NatName
	data["nat_rule_name"] = result.NatName

	enableValue := g.config.Enable
	data["enable"] = enableValue

	if input.FromZone != "" {
		data["fromZone"] = input.FromZone
		data["sourceZones"] = []interface{}{input.FromZone}
	}
	if input.ToZone != "" {
		data["toZone"] = input.ToZone
		data["destinationZones"] = []interface{}{input.ToZone}
	}

	if input.FromPort != nil {
		data["fromPort"] = input.FromPort.Name()
		data["has_fromPort"] = true
	}
	if input.ToPort != nil {
		data["toPort"] = input.ToPort.Name()
		data["has_toPort"] = true
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

	// DNAT相关
	if result.NatType == "DNAT" {
		if input.Intent.RealIp != "" {
			data["has_real_ip"] = true
		}
		if input.Intent.RealPort != "" {
			data["has_real_port"] = true
		}
		// INLINE模式下，vip_name和mip_name应该为空
		// 只有当vipMipResult存在且ObjectName不为空时才设置
		if vipMipResult != nil && vipMipResult.ObjectName != "" {
			data["vip_name"] = vipMipResult.ObjectName
			data["mip_name"] = vipMipResult.ObjectName
			data["has_vip_name"] = true
			data["has_mip_name"] = true
		} else {
			// INLINE模式：明确设置为空字符串，确保模板正确判断
			data["vip_name"] = ""
			data["mip_name"] = ""
		}
	}

	// SNAT相关
	if result.NatType == "SNAT" {
		// 检查 SNAT 对象类型
		snatPoolType := getStringFromMeta(g.ctx.MetaData, "snat_pool_type", "")
		snatObjectType := getStringFromMeta(g.ctx.MetaData, "snat_object_type", "")

		// INTERFACE 模式：使用 easy-ip，不生成 SNAT_POOL 对象
		if snatPoolType == "INTERFACE" || snatObjectType == "INTERFACE" {
			data["has_easy_ip"] = true
			// 明确不设置 has_pool_id，确保模板不会使用 pool_id
			// INTERFACE 模式下，snat 可以为空或 "interface"
			if input.Intent.Snat != "" && input.Intent.Snat != "interface" {
				data["has_snat"] = true
				data["snat"] = input.Intent.Snat
			}
		} else {
			// SNAT_POOL 或 INLINE 模式
			data["has_snat"] = true
			if input.Intent.Snat != "" {
				data["snat"] = input.Intent.Snat
			}
			// 只有当 snatPoolResult 存在且不是 INTERFACE 模式时才设置 pool_id
			if snatPoolResult != nil && snatPoolResult.PoolName != "" {
				data["pool_id"] = snatPoolResult.PoolId
				data["pool_name"] = snatPoolResult.PoolName
				data["use_pool"] = true
				data["has_pool_id"] = true
			}
		}
	}

	if g.config.Description != "" {
		data["description"] = g.config.Description
		data["has_description"] = true
	}

	return data
}

// handleObjectNatSpecialCase 处理Object NAT特殊情况
func (g *NatPolicyGenerator) handleObjectNatSpecialCase(result *NatPolicyResult, natCli string, data map[string]interface{}) {
	// 简化实现：追加到NETWORK类别
	if networkCli, exists := result.FlyObject["NETWORK"]; exists && networkCli != "" {
		result.FlyObject["NETWORK"] = networkCli + "\n" + natCli
	} else {
		result.FlyObject["NETWORK"] = natCli
	}
	result.AppendCLIString(natCli)
}

// mergeObjectCLI 合并对象CLI
func (g *NatPolicyGenerator) mergeObjectCLI(result ObjectResultMerger, category string, newCLI string) {
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
func (g *NatPolicyGenerator) getSectionSeparator() string {
	return getSectionSeparator(g.ctx)
}
