package v4

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/keys"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

// ServiceObjectGenerator 服务对象生成器
type ServiceObjectGenerator struct {
	ctx    *GeneratorContext
	config ServiceObjectGeneratorConfig
	om     *common.ObjectNameManager
}

// NewServiceObjectGenerator 创建服务对象生成器
func NewServiceObjectGenerator(ctx *GeneratorContext, config ServiceObjectGeneratorConfig) *ServiceObjectGenerator {
	return &ServiceObjectGenerator{
		ctx:    ctx,
		config: config,
		om:     common.NewObjectNameManager(),
	}
}

// Generate 生成服务对象
func (g *ServiceObjectGenerator) Generate(intent *policy.Intent, ctx *firewall.PolicyContext) (*ServiceObjectResult, error) {
	result := &ServiceObjectResult{
		ObjectNames: []string{},
		IsGroup:     false,
		Keys:        []string{},
	}

	// 检查 service 是否为 ip 协议
	isIPProtocol := false
	if intent.Service() != nil {
		intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
			if l3, ok := item.(*service.L3Protocol); ok && l3.Protocol() == service.IP {
				isIPProtocol = true
				return false
			}
			return true
		})
	}

	if isIPProtocol {
		// 如果 isIPProtocol 为 true，不生成 service 对象，模板会使用 service "any"
		result.IsIPProtocol = true
		return result, nil
	}

	// 获取命名模板
	serviceObjectNameTemplate := getStringFromMeta(g.ctx.MetaData, "service_object_name_template", "")
	serviceGroupNameTemplate := getStringFromMeta(g.ctx.MetaData, "service_group_name_template", "")

	// 获取layout
	serviceObjectLayout := g.ctx.Templates.GetLayout(keys.NewKeyBuilder("ServiceObject", "OneLoop"))
	serviceGroupLayout := g.ctx.Templates.GetLayout(keys.NewKeyBuilder("ServiceGroup", "OneLoop"))

	// 判断是否需要生成服务组
	serviceCount := 0
	intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
		serviceCount++
		return true
	})

	deviceSupportsServiceGroup := serviceGroupLayout != ""

	// 如果配置了优先使用多服务object，则优先使用多服务object而不是服务组
	// 多服务object会遍历服务，为每个条目创建独立的服务对象
	if g.config.PreferMultiServiceObject && serviceCount > 1 {
		return g.generateMultiServiceObjects(intent, serviceObjectNameTemplate, serviceObjectLayout, ctx, result)
	}

	shouldCreateGroup := serviceCount > 1 && deviceSupportsServiceGroup

	if shouldCreateGroup {
		return g.generateServiceGroup(intent, serviceObjectNameTemplate, serviceGroupNameTemplate, serviceObjectLayout, serviceGroupLayout, ctx, result)
	}

	return g.generateSingleServiceObject(intent, serviceObjectNameTemplate, serviceObjectLayout, ctx, result)
}

// generateServiceGroup 生成服务组
func (g *ServiceObjectGenerator) generateServiceGroup(
	intent *policy.Intent,
	serviceObjectNameTemplate, serviceGroupNameTemplate string,
	serviceObjectLayout, serviceGroupLayout string,
	ctx *firewall.PolicyContext,
	result *ServiceObjectResult,
) (*ServiceObjectResult, error) {
	sectionSeparator := g.getSectionSeparator()

	// 1. 先为每个成员生成服务对象
	// 检查配置：只有当 securitypolicy.service_group_member 为 true 时才生成成员对象
	serviceGroupMember := getBoolFromMeta(g.ctx.MetaData, "securitypolicy.service_group_member", false)
	shouldGenerateMemberObjects := serviceGroupMember

	memberObjects := []string{}
	intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
		memberSvc := &service.Service{}
		memberSvc.Add(item)

		var key keys.Keys
		var isNew bool
		var err error

		// 只有当配置为 true 时才生成成员对象
		if shouldGenerateMemberObjects {
			// 如果启用复用，先尝试通过服务内容查找已有对象
			if g.config.ReuseServiceObject {
				existingObj, foundExisting := g.ctx.Node.GetObjectByService(memberSvc, firewall.SEARCH_OBJECT_OR_GROUP)
				if foundExisting {
					key = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
					isNew = false
				} else {
					key, isNew, err = g.generateMemberServiceName(item, serviceObjectNameTemplate, nil)
					if err != nil {
						return false
					}
				}
			} else {
				key, isNew, err = g.generateMemberServiceName(item, serviceObjectNameTemplate, nil)
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
						intent.Src(),
						intent.Dst(),
						memberSvc,
					),
				}

				memberCli := g.renderLayout(memberIntent, serviceObjectLayout, memberMeta)
				if memberCli != "" {
					if result.CLIString != "" {
						result.CLIString += "\n" + sectionSeparator + "\n"
					}
					result.CLIString += memberCli
				}
			}

			memberObjects = append(memberObjects, key.String())
			result.Keys = append(result.Keys, key.String())
		}
		//  else {
		// 	// 如果不生成成员对象，直接使用服务字符串
		// 	// 使用 ServiceFormat 格式化服务，如果没有模板则使用默认格式
		// 	serviceString := g.formatServiceEntry(item)
		// 	memberObjects = append(memberObjects, serviceString)
		// }
		return true
	})

	// 2. 生成服务组
	groupName := g.generateGroupName(serviceGroupNameTemplate)
	groupKey := keys.NewKeyBuilder(groupName).Separator("_")
	groupKey, isNew, err := g.generateUniqueGroupName(groupKey, memberObjects)
	if err != nil {
		return nil, err
	}

	if isNew {
		groupMeta := copyMap(g.ctx.MetaData)
		groupMeta["object_name"] = groupKey.String()
		if shouldGenerateMemberObjects {
			groupMeta["member_objects"] = memberObjects
		}

		groupCli := g.renderLayout(intent, serviceGroupLayout, groupMeta)
		if groupCli != "" {
			if result.CLIString != "" {
				result.CLIString += "\n" + sectionSeparator + "\n"
			}
			result.CLIString += groupCli
		}
	}

	result.ObjectNames = []string{groupKey.String()}
	result.IsGroup = true
	result.Keys = append(result.Keys, groupKey.String())

	return result, nil
}

// generateSingleServiceObject 生成单个服务对象
func (g *ServiceObjectGenerator) generateSingleServiceObject(
	intent *policy.Intent,
	serviceObjectNameTemplate, serviceObjectLayout string,
	ctx *firewall.PolicyContext,
	result *ServiceObjectResult,
) (*ServiceObjectResult, error) {
	var key keys.Keys
	var isNew bool
	var err error

	var firstSvcEntry service.ServiceEntry
	intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
		firstSvcEntry = item
		return false // 只取第一个
	})

	// 如果启用复用，先尝试通过服务内容查找已有对象
	if g.config.ReuseServiceObject {
		existingObj, foundExisting := g.ctx.Node.GetObjectByService(intent.Service(), firewall.SEARCH_OBJECT_OR_GROUP)
		if foundExisting {
			key = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
			isNew = false
		} else {
			additionalMeta := map[string]interface{}{}
			if intent.MetaData != nil {
				if intent.MetaData["is_source_port"] == "true" {
					additionalMeta["is_source_port"] = true
				}
			}
			key, isNew, err = g.generateServiceName(firstSvcEntry, serviceObjectNameTemplate, additionalMeta)
			if err != nil {
				return nil, err
			}
		}
	} else {
		additionalMeta := map[string]interface{}{}
		if intent.MetaData != nil {
			if intent.MetaData["is_source_port"] == "true" {
				additionalMeta["is_source_port"] = true
			}
		}
		key, isNew, err = g.generateServiceName(firstSvcEntry, serviceObjectNameTemplate, additionalMeta)
		if err != nil {
			return nil, err
		}
	}

	if isNew {
		// 生成服务对象CLI - 直接通过 Starlark 渲染
		objectMeta := copyMap(g.ctx.MetaData)
		objectMeta["object_name"] = key.String()
		// 传递 is_source_port 标志，以便 Starlark 模板在生成命令行时使用源端口
		if intent.MetaData != nil {
			if intent.MetaData["is_source_port"] == "true" {
				objectMeta["is_source_port"] = true
			}
		}

		if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
			objectCli, err := adapter.RenderStarlarkTemplate("ServiceObject", intent, objectMeta)
			if err == nil && objectCli != "" {
				result.CLIString = objectCli
			}
		}

	}

	result.ObjectNames = []string{key.String()}
	result.IsGroup = false
	result.Keys = append(result.Keys, key.String())

	return result, nil
}

// generateMultiServiceObjects 生成多个服务对象（当PreferMultiServiceObject为true时使用）
// 遍历服务，为每个条目创建独立的服务对象，并将所有对象名称保存到ObjectNames中
func (g *ServiceObjectGenerator) generateMultiServiceObjects(
	intent *policy.Intent,
	serviceObjectNameTemplate, serviceObjectLayout string,
	ctx *firewall.PolicyContext,
	result *ServiceObjectResult,
) (*ServiceObjectResult, error) {
	sectionSeparator := g.getSectionSeparator()

	// 遍历服务，为每个条目创建独立的服务对象
	intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
		memberSvc := &service.Service{}
		memberSvc.Add(item)

		var key keys.Keys
		var isNew bool
		var err error

		// 如果启用复用，先尝试通过服务内容查找已有对象
		if g.config.ReuseServiceObject {
			existingObj, foundExisting := g.ctx.Node.GetObjectByService(memberSvc, firewall.SEARCH_OBJECT_OR_GROUP)
			if foundExisting {
				key = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
				isNew = false
			} else {
				additionalMeta := map[string]interface{}{}
				if intent.MetaData != nil {
					if intent.MetaData["is_source_port"] == "true" {
						additionalMeta["is_source_port"] = true
					}
				}
				key, isNew, err = g.generateMemberServiceName(item, serviceObjectNameTemplate, additionalMeta)
				if err != nil {
					return false
				}
			}
		} else {
			additionalMeta := map[string]interface{}{}
			if intent.MetaData != nil {
				if intent.MetaData["is_source_port"] == "true" {
					additionalMeta["is_source_port"] = true
				}
			}
			key, isNew, err = g.generateMemberServiceName(item, serviceObjectNameTemplate, additionalMeta)
			if err != nil {
				return false
			}
		}

		if isNew {
			// 生成服务对象CLI
			memberMeta := copyMap(g.ctx.MetaData)
			memberMeta["object_name"] = key.String()

			memberIntent := &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					intent.Src(),
					intent.Dst(),
					memberSvc,
				),
			}

			memberCli := g.renderLayout(memberIntent, serviceObjectLayout, memberMeta)
			if memberCli != "" {
				if result.CLIString != "" {
					result.CLIString += "\n" + sectionSeparator + "\n"
				}
				result.CLIString += memberCli
			}
		}

		// 将所有服务对象的名称保存到ObjectNames中
		result.ObjectNames = append(result.ObjectNames, key.String())
		result.Keys = append(result.Keys, key.String())
		return true
	})

	result.IsGroup = false
	return result, nil
}

// generateServiceName 生成服务对象名称
func (g *ServiceObjectGenerator) generateServiceName(firstSvcEntry service.ServiceEntry, template string, additionalMeta map[string]interface{}) (keys.Keys, bool, error) {
	// var firstSvcEntry service.ServiceEntry
	// intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
	// 	firstSvcEntry = item
	// 	return false // 只取第一个
	// })

	objectMetaForName := copyMap(g.ctx.MetaData)

	for k, v := range additionalMeta {
		objectMetaForName[k] = v
	}

	objectName := g.generateServiceNameFromTemplate(firstSvcEntry, template, objectMetaForName)
	if objectName == "" {
		objectName = "SERVICE_OBJECT"
	}

	svc := &service.Service{}
	svc.Add(firstSvcEntry)
	key := keys.NewKeyBuilder(objectName).Separator("_")
	return g.generateUniqueServiceName(keys.NewAutoIncrementKeys(key, 2), svc)
}

// generateMemberServiceName 生成成员服务对象名称
func (g *ServiceObjectGenerator) generateMemberServiceName(svcEntry service.ServiceEntry, template string, additionalMeta map[string]interface{}) (keys.Keys, bool, error) {
	memberMetaForName := copyMap(g.ctx.MetaData)
	for k, v := range additionalMeta {
		memberMetaForName[k] = v
	}
	memberName := g.generateServiceNameFromTemplate(svcEntry, template, memberMetaForName)
	if memberName == "" {
		memberName = fmt.Sprintf("MEMBER_%d", len(g.ctx.MetaData))
	}

	memberSvc := &service.Service{}
	memberSvc.Add(svcEntry)

	key := keys.NewKeyBuilder(memberName).Separator("_")
	return g.generateUniqueServiceName(keys.NewAutoIncrementKeys(key, 2), memberSvc)
}

// generateServiceNameFromTemplate 从模板生成服务对象名称
func (g *ServiceObjectGenerator) generateServiceNameFromTemplate(svcEntry service.ServiceEntry, template string, metaData map[string]interface{}) string {
	if template == "" {
		return ""
	}

	// 如果 is_source_port 为 true，提取源端口信息到 metaData 中
	// 这样模板可以根据 is_source_port 标志使用源端口或目标端口来生成名称
	if isSourcePort, ok := metaData["is_source_port"].(bool); ok && isSourcePort {
		if l4, ok := svcEntry.(*service.L4Service); ok {
			if !l4.SrcPort().IsFull() {
				metaData["src_port"] = l4.SrcPort().String()
				// 在 Starlark 模板中可以通过 item.src_port.compact 访问紧凑格式
				// 这里只提供 String() 格式，模板会自行处理
			}
		}
	} else {
		// 默认使用目标端口
		if l4, ok := svcEntry.(*service.L4Service); ok {
			if !l4.DstPort().IsFull() {
				metaData["dst_port"] = l4.DstPort().String()
				// 在 Starlark 模板中可以通过 item.dst_port.compact 访问紧凑格式
				// 这里只提供 String() 格式，模板会自行处理
			}
		}
	}

	svc := &service.Service{}
	svc.Add(svcEntry)

	return strings.TrimSpace(formatWithService(g.ctx, svc, template, metaData))
}

// generateGroupName 生成组名称
func (g *ServiceObjectGenerator) generateGroupName(template string) string {
	if template == "" {
		return "SRV_GROUP"
	}
	return formatWithMap(g.ctx, g.ctx.MetaData, template)
}

// generateUniqueServiceName 生成唯一的服务对象名称
func (g *ServiceObjectGenerator) generateUniqueServiceName(auto *keys.AutoIncrementKeys, svc *service.Service) (keys.Keys, bool, error) {
	var getIterator func() firewall.NamerIterator
	if iteratorNode, ok := g.ctx.Node.(firewall.IteratorFirewall); ok {
		getIterator = func() firewall.NamerIterator {
			return iteratorNode.ServiceIterator()
		}
	} else {
		getIterator = func() firewall.NamerIterator {
			return &emptyNamerIterator{}
		}
	}

	return common.GenerateObjectName(
		auto,
		svc,
		getIterator,
		g.ctx.Node,
		nil,
		common.RetryMethodNext,
		g.om,
		true,
	)
}

// generateUniqueGroupName 生成唯一的组名称
func (g *ServiceObjectGenerator) generateUniqueGroupName(auto keys.Keys, memberObjects []string) (keys.Keys, bool, error) {
	// 简化实现：直接返回，实际应该检查组名称是否已存在
	return auto, true, nil
}

// getSectionSeparator 获取分隔符（使用通用的 getSectionSeparator 函数）
func (g *ServiceObjectGenerator) getSectionSeparator() string {
	return getSectionSeparator(g.ctx)
}

// renderLayout 渲染layout（使用通用的 renderLayout 函数）
func (g *ServiceObjectGenerator) renderLayout(intent *policy.Intent, layout string, metaData map[string]interface{}) string {
	return renderLayout(g.ctx, intent, layout, metaData)
}
