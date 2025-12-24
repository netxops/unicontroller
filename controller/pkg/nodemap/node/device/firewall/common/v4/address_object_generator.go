package v4

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/keys"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
)

// AddressObjectGenerator 地址对象生成器
type AddressObjectGenerator struct {
	ctx    *GeneratorContext
	config AddressObjectGeneratorConfig
	om     *common.ObjectNameManager
}

// NewAddressObjectGenerator 创建地址对象生成器
func NewAddressObjectGenerator(ctx *GeneratorContext, config AddressObjectGeneratorConfig) *AddressObjectGenerator {
	return &AddressObjectGenerator{
		ctx:    ctx,
		config: config,
		om:     common.NewObjectNameManager(),
	}
}

// Generate 生成地址对象
// isSource: true 表示源地址对象，false 表示目标地址对象
func (g *AddressObjectGenerator) Generate(intent *policy.Intent, isSource bool, ctx *firewall.PolicyContext) (*AddressObjectResult, error) {
	result := &AddressObjectResult{
		ObjectNames: []string{},
		IsGroup:     false,
		Keys:        []string{},
	}
	g.ctx.MetaData["is_source"] = isSource

	// 获取命名模板
	networkObjectNameTemplate := getStringFromMeta(g.ctx.MetaData, "network_object_name_template", "")
	addressGroupNameTemplate := getStringFromMeta(g.ctx.MetaData, "address_group_name_template", "")

	// 确定要处理的网络组
	var targetNetworkGroup *network.NetworkGroup
	if isSource {
		targetNetworkGroup = intent.Src()
	} else {
		targetNetworkGroup = intent.Dst()
	}

	// 判断是否需要生成地址组
	networkCount := 0
	targetNetworkGroup.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
		networkCount++
		return true
	})

	// 检查是否支持地址组（通过尝试渲染模板来判断）
	deviceSupportsAddressGroup := g.checkAddressGroupSupport()

	// 如果配置了优先使用多地址object，则优先使用多地址object而不是地址组
	// 多地址object会遍历targetNetworkGroup，为每个条目创建独立的地址对象
	if (g.config.PreferMultiSourceAddressObject && isSource) || (g.config.PreferMultiDestinationAddressObject && !isSource) && networkCount > 1 {
		return g.generateMultiAddressObjects(intent, isSource, targetNetworkGroup, networkObjectNameTemplate, ctx, result)
	}

	shouldCreateGroup := networkCount > 1 && deviceSupportsAddressGroup

	if shouldCreateGroup {
		return g.generateAddressGroup(intent, isSource, targetNetworkGroup, networkObjectNameTemplate, addressGroupNameTemplate, ctx, result)
	}

	return g.generateSingleAddressObject(intent, isSource, targetNetworkGroup, networkObjectNameTemplate, ctx, result)
}

// generateAddressGroup 生成地址组
func (g *AddressObjectGenerator) generateAddressGroup(
	intent *policy.Intent,
	isSource bool,
	targetNetworkGroup *network.NetworkGroup,
	networkObjectNameTemplate, addressGroupNameTemplate string,
	ctx *firewall.PolicyContext,
	result *AddressObjectResult,
) (*AddressObjectResult, error) {
	sectionSeparator := g.getSectionSeparator()

	// 1. 先为每个成员生成地址对象
	// 检查配置：只有当 securitypolicy.address_group_member 为 "true" 时才生成成员对象
	// addressGroupMember := getBoolFromMeta(g.ctx.MetaData, "securitypolicy.address_group_member", false)
	var shouldGenerateMemberObjects bool
	if isSource {
		shouldGenerateMemberObjects = g.config.SourceAddressGroupStyle == "member"
	} else {
		shouldGenerateMemberObjects = g.config.DestinationAddressGroupStyle == "member"
	}
	memberObjects := []string{}
	targetNetworkGroup.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
		memberNet := network.NewNetworkGroup()
		memberNet.Add(item)

		var key keys.Keys
		var isNew bool
		var err error

		// 只有当配置为 "true" 时才生成成员对象
		if shouldGenerateMemberObjects {
			// 如果启用复用，先尝试通过网络内容查找已有对象
			if g.config.ReuseAddressObject {
				existingObj, foundExisting := g.ctx.Node.GetObjectByNetworkGroup(memberNet, firewall.SEARCH_OBJECT_OR_GROUP, nil)
				if foundExisting {
					key = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
					isNew = false
				} else {
					key, isNew, err = g.generateMemberObjectName(item, isSource, networkObjectNameTemplate)
					if err != nil {
						return false
					}
				}
			} else {
				key, isNew, err = g.generateMemberObjectName(item, isSource, networkObjectNameTemplate)
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

				memberCli := g.renderAddressObject(memberIntent, memberMeta)
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
		// else {
		// 	// 如果不生成成员对象，直接使用网络地址字符串
		// 	memberObjects = append(memberObjects, memberNet.String())
		// }
		return true
	})

	// 2. 生成地址组
	groupName := g.generateGroupName(addressGroupNameTemplate, isSource)
	groupKey := keys.NewKeyBuilder(groupName).Separator("_")

	var isNew bool
	var err error

	// 如果启用复用，先尝试通过网络内容查找已有地址组
	if g.config.ReuseAddressObject {
		existingObj, foundExisting := g.ctx.Node.GetObjectByNetworkGroup(targetNetworkGroup, firewall.SEARCH_GROUP, nil)
		if foundExisting {
			groupKey = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
			isNew = false
		} else {
			groupKey, isNew, err = g.generateUniqueGroupName(groupKey, memberObjects)
			if err != nil {
				return nil, err
			}
		}
	} else {
		groupKey, isNew, err = g.generateUniqueGroupName(groupKey, memberObjects)
		if err != nil {
			return nil, err
		}
	}

	if isNew {
		groupMeta := copyMap(g.ctx.MetaData)
		groupMeta["is_source"] = isSource
		groupMeta["object_name"] = groupKey.String()
		if shouldGenerateMemberObjects {
			groupMeta["member_objects"] = memberObjects
		}

		// groupIntent := &policy.Intent{
		// 	PolicyEntry: *policy.NewPolicyEntryWithAll(
		// 		targetNetworkGroup,
		// 		network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
		// 		intent.Service(),
		// 	),
		// }
		// groupIntent := policy.NewIntent()

		groupCli := g.renderAddressGroup(intent, groupMeta)
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

// generateSingleAddressObject 生成单个地址对象
func (g *AddressObjectGenerator) generateSingleAddressObject(
	intent *policy.Intent,
	isSource bool,
	targetNetworkGroup *network.NetworkGroup,
	networkObjectNameTemplate string,
	ctx *firewall.PolicyContext,
	result *AddressObjectResult,
) (*AddressObjectResult, error) {
	var key keys.Keys
	var isNew bool
	var err error

	// targetStr := targetNetworkGroup.String()
	// net, err := network.NewNetworkFromString(targetStr)
	// if err != nil {
	// 	return nil, err
	// }
	var net network.AbbrNet
	targetNetworkGroup.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
		net = item
		return false
	})

	// 如果启用复用，先尝试通过网络内容查找已有对象
	if g.config.ReuseAddressObject {
		existingObj, foundExisting := g.ctx.Node.GetObjectByNetworkGroup(targetNetworkGroup, firewall.SEARCH_OBJECT_OR_GROUP, nil)
		if foundExisting {
			key = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
			isNew = false
		} else {
			key, isNew, err = g.generateObjectName(net, isSource, networkObjectNameTemplate)
			if err != nil {
				return nil, err
			}
		}
	} else {
		key, isNew, err = g.generateObjectName(net, isSource, networkObjectNameTemplate)
		if err != nil {
			return nil, err
		}
	}

	if isNew {
		// 生成地址对象CLI
		objectMeta := copyMap(g.ctx.MetaData)
		objectMeta["is_source"] = isSource
		objectMeta["object_name"] = key.String()

		// 创建一个新的 intent，确保源地址和目标地址信息正确
		// 对于源地址对象：targetNetworkGroup 作为 src，0.0.0.0/0 作为 dst
		// 对于目标地址对象：0.0.0.0/0 作为 src，targetNetworkGroup 作为 dst
		objectIntent := &policy.Intent{
			PolicyEntry: *policy.NewPolicyEntryWithAll(
				func() *network.NetworkGroup {
					if isSource {
						return targetNetworkGroup
					}
					return network.NewNetworkGroupFromStringMust("0.0.0.0/0")
				}(),
				func() *network.NetworkGroup {
					if isSource {
						return network.NewNetworkGroupFromStringMust("0.0.0.0/0")
					}
					return targetNetworkGroup
				}(),
				intent.Service(),
			),
		}

		objectCli := g.renderAddressObject(objectIntent, objectMeta)
		if objectCli != "" {
			result.CLIString = objectCli
		}
	}

	result.ObjectNames = []string{key.String()}
	result.IsGroup = false
	result.Keys = append(result.Keys, key.String())

	return result, nil
}

// generateMultiAddressObjects 生成多个地址对象（当PreferMultiAddressObject为true时使用）
// 遍历targetNetworkGroup，为每个条目创建独立的地址对象，并将所有对象名称保存到ObjectNames中
func (g *AddressObjectGenerator) generateMultiAddressObjects(
	intent *policy.Intent,
	isSource bool,
	targetNetworkGroup *network.NetworkGroup,
	networkObjectNameTemplate string,
	ctx *firewall.PolicyContext,
	result *AddressObjectResult,
) (*AddressObjectResult, error) {
	sectionSeparator := g.getSectionSeparator()

	// 遍历targetNetworkGroup，为每个条目创建独立的地址对象
	targetNetworkGroup.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
		memberNet := network.NewNetworkGroup()
		memberNet.Add(item)

		var key keys.Keys
		var isNew bool
		var err error

		// 如果启用复用，先尝试通过网络内容查找已有对象
		if g.config.ReuseAddressObject {
			existingObj, foundExisting := g.ctx.Node.GetObjectByNetworkGroup(memberNet, firewall.SEARCH_OBJECT_OR_GROUP, nil)
			if foundExisting {
				key = keys.NewKeyBuilder(existingObj.Name()).Separator("_")
				isNew = false
			} else {
				key, isNew, err = g.generateObjectName(item, isSource, networkObjectNameTemplate)
				// key, isNew, err = g.generateMemberObjectName(memberNet, isSource, networkObjectNameTemplate)
				if err != nil {
					return false
				}
			}
		} else {
			key, isNew, err = g.generateObjectName(item, isSource, networkObjectNameTemplate)
			// key, isNew, err = g.generateMemberObjectName(memberNet, isSource, networkObjectNameTemplate)
			if err != nil {
				return false
			}
		}

		if isNew {
			// 生成地址对象CLI
			memberMeta := copyMap(g.ctx.MetaData)
			memberMeta["is_source"] = isSource
			memberMeta["object_name"] = key.String()

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

			memberCli := g.renderAddressObject(memberIntent, memberMeta)
			if memberCli != "" {
				if result.CLIString != "" {
					result.CLIString += "\n" + sectionSeparator + "\n"
				}
				result.CLIString += memberCli
			}
		}

		// 将所有地址对象的名称保存到ObjectNames中
		result.ObjectNames = append(result.ObjectNames, key.String())
		result.Keys = append(result.Keys, key.String())
		return true
	})

	result.IsGroup = false
	return result, nil
}

// generateObjectName 生成对象名称
func (g *AddressObjectGenerator) generateObjectName(net network.AbbrNet, isSource bool, template string) (keys.Keys, bool, error) {
	objectName := getStringFromMeta(g.ctx.MetaData, "object_name", "")
	if objectName == "" {
		objectMetaForName := copyMap(g.ctx.MetaData)
		objectMetaForName["is_source"] = isSource
		objectName = generateObjectNameFromTemplate(g.ctx, net, template, objectMetaForName)
	}
	if objectName == "" {
		objectName = "ADDRESS_OBJECT"
	}

	key := keys.NewKeyBuilder(objectName).Separator("_")
	return g.generateUniqueObjectName(keys.NewAutoIncrementKeys(key, 2), net)
}

// generateMemberObjectName 生成成员对象名称
func (g *AddressObjectGenerator) generateMemberObjectName(net network.AbbrNet, isSource bool, template string) (keys.Keys, bool, error) {
	memberMetaForName := copyMap(g.ctx.MetaData)
	memberMetaForName["is_source"] = isSource
	memberName := generateObjectNameFromTemplate(g.ctx, net, template, memberMetaForName)
	if memberName == "" {
		memberName = fmt.Sprintf("MEMBER_%d", len(memberMetaForName))
	}
	ng := &network.NetworkGroup{}
	ng.Add(net)
	key := keys.NewKeyBuilder(memberName).Separator("_")
	return g.generateUniqueObjectName(keys.NewAutoIncrementKeys(key, 2), ng)
}

// generateGroupName 生成组名称
func (g *AddressObjectGenerator) generateGroupName(template string, isSource bool) string {
	if template == "" {
		if isSource {
			return "SRC_group"
		}
		return "DST_group"
	}

	groupMeta := copyMap(g.ctx.MetaData)
	groupMeta["is_source"] = isSource

	// 使用 DSL 处理模板
	return formatWithMap(g.ctx, groupMeta, template)
}

// generateUniqueObjectName 生成唯一的对象名称
// net支持network.AbbrNet和network.NetworkGroup
func (g *AddressObjectGenerator) generateUniqueObjectName(auto *keys.AutoIncrementKeys, net interface{}) (keys.Keys, bool, error) {
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
		net,
		getIterator,
		g.ctx.Node,
		nil,
		common.RetryMethodNext,
		g.om,
		true,
	)
}

// generateUniqueGroupName 生成唯一的组名称
func (g *AddressObjectGenerator) generateUniqueGroupName(auto keys.Keys, memberObjects []string) (keys.Keys, bool, error) {
	// 简化实现：直接返回，实际应该检查组名称是否已存在
	return auto, true, nil
}

// getSectionSeparator 获取分隔符（使用通用的 getSectionSeparator 函数）
func (g *AddressObjectGenerator) getSectionSeparator() string {
	return getSectionSeparator(g.ctx)
}

// renderAddressObject 直接渲染地址对象模板
func (g *AddressObjectGenerator) renderAddressObject(intent *policy.Intent, metaData map[string]interface{}) string {
	if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
		result, err := adapter.RenderStarlarkTemplate("AddressObject", intent, metaData)
		if err != nil {
			return ""
		}
		return result
	}
	return ""
}

// renderAddressGroup 直接渲染地址组模板
func (g *AddressObjectGenerator) renderAddressGroup(intent *policy.Intent, metaData map[string]interface{}) string {
	if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
		result, err := adapter.RenderStarlarkTemplate("AddressGroup", intent, metaData)
		if err != nil {
			return ""
		}
		return result
	}
	return ""
}

// checkAddressGroupSupport 检查是否支持地址组（通过尝试渲染模板来判断）
func (g *AddressObjectGenerator) checkAddressGroupSupport() bool {
	if adapter, ok := g.ctx.Templates.(*StarlarkTemplatesAdapter); ok {
		// 创建一个空的 intent 和 meta 来测试模板是否存在
		emptyIntent := &policy.Intent{}
		emptyMeta := make(map[string]interface{})
		_, err := adapter.RenderStarlarkTemplate("AddressGroup", emptyIntent, emptyMeta)
		// 如果模板不存在，会返回包含 "not found" 的错误
		// 如果模板存在但渲染失败（例如缺少必要参数），也认为支持地址组
		return err == nil || !strings.Contains(err.Error(), "not found")
	}
	return false
}
