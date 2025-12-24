package v4

// import (
// 	"github.com/netxops/keys"
// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
// 	"github.com/netxops/utils/network"
// )

// // AddressNameGenerator 地址对象名称生成器
// type AddressNameGenerator struct {
// 	ctx *GeneratorContext
// 	om  *common.ObjectNameManager
// }

// // NewAddressNameGenerator 创建地址对象名称生成器
// func NewAddressNameGenerator(ctx *GeneratorContext) *AddressNameGenerator {
// 	return &AddressNameGenerator{
// 		ctx: ctx,
// 		om:  common.NewObjectNameManager(),
// 	}
// }

// // Generate 生成地址对象名称（唯一）
// // 返回：生成的名称、是否为新对象、错误
// func (g *AddressNameGenerator) Generate(ng *network.NetworkGroup, isSource bool, template string, metaData map[string]interface{}) (keys.Keys, bool, error) {
// 	// 优先使用metaData中直接指定的object_name
// 	objectName := getStringFromMeta(metaData, "object_name", "")
// 	if objectName == "" {
// 		// 使用模板生成名称
// 		objectMetaForName := copyMap(metaData)
// 		if isSource {
// 			objectMetaForName["is_source"] = "true"
// 		} else {
// 			objectMetaForName["is_source"] = "false"
// 		}
// 		objectName = generateObjectNameFromTemplate(g.ctx, ng, template, objectMetaForName)
// 	}

// 	if objectName == "" {
// 		objectName = "ADDRESS_OBJECT"
// 	}

// 	// 生成唯一名称
// 	key := keys.NewKeyBuilder(objectName).Separator("_")
// 	return g.generateUniqueName(keys.NewAutoIncrementKeys(key, 2), ng)
// }

// // GenerateGroupName 生成地址组名称（唯一）
// func (g *AddressNameGenerator) GenerateGroupName(template string, isSource bool, memberObjects []string, metaData map[string]interface{}) (keys.Keys, bool, error) {
// 	groupName := g.generateGroupNameFromTemplate(template, isSource, metaData)
// 	if groupName == "" {
// 		if isSource {
// 			groupName = "SRC_group"
// 		} else {
// 			groupName = "DST_group"
// 		}
// 	}

// 	key := keys.NewKeyBuilder(groupName).Separator("_")
// 	// 简化实现：直接返回，实际应该检查组名称是否已存在
// 	return key, true, nil
// }

// // generateGroupNameFromTemplate 从模板生成组名称
// func (g *AddressNameGenerator) generateGroupNameFromTemplate(template string, isSource bool, metaData map[string]interface{}) string {
// 	if template == "" {
// 		return ""
// 	}

// 	groupMeta := copyMap(metaData)
// 	if isSource {
// 		groupMeta["is_source"] = "true"
// 	} else {
// 		groupMeta["is_source"] = "false"
// 	}

// 	return formatWithMap(g.ctx, groupMeta, template)
// }

// // generateUniqueName 生成唯一的对象名称
// func (g *AddressNameGenerator) generateUniqueName(auto *keys.AutoIncrementKeys, ng *network.NetworkGroup) (keys.Keys, bool, error) {
// 	var getIterator func() firewall.NamerIterator
// 	if iteratorNode, ok := g.ctx.Node.(firewall.IteratorFirewall); ok {
// 		getIterator = func() firewall.NamerIterator {
// 			return iteratorNode.NetworkIterator()
// 		}
// 	} else {
// 		getIterator = func() firewall.NamerIterator {
// 			return &emptyNamerIterator{}
// 		}
// 	}

// 	return common.GenerateObjectName(
// 		auto,
// 		ng,
// 		getIterator,
// 		g.ctx.Node,
// 		nil,
// 		common.RetryMethodNext,
// 		g.om,
// 		true,
// 	)
// }
