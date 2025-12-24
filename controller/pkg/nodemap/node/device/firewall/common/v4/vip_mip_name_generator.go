package v4

import (
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/keys"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

// VipMipNameGenerator VIP/MIP对象名称生成器
type VipMipNameGenerator struct {
	ctx *GeneratorContext
	om  *common.ObjectNameManager
}

// NewVipMipNameGenerator 创建VIP/MIP对象名称生成器
func NewVipMipNameGenerator(ctx *GeneratorContext) *VipMipNameGenerator {
	return &VipMipNameGenerator{
		ctx: ctx,
		om:  common.NewObjectNameManager(),
	}
}

// Generate 生成VIP/MIP对象名称（唯一）
// 返回：生成的名称、是否为新对象、错误
func (g *VipMipNameGenerator) Generate(intent *policy.Intent, objType string, metaData map[string]interface{}) (keys.Keys, bool, error) {
	// 优先使用直接指定的对象名称
	objectName := getStringFromMeta(metaData, "object_name", "")
	if objectName == "" {
		// 使用配置的命名模板
		nameTemplate := getStringFromMeta(metaData, objType+"_name_template", "")
		if nameTemplate == "" {
			if objType == "VIP" {
				nameTemplate = getStringFromMeta(metaData, "vip_name_template", "")
			} else {
				nameTemplate = getStringFromMeta(metaData, "mip_name_template", "")
			}
		}

		if nameTemplate != "" {
			nameMeta := copyMap(metaData)
			if intent.Dst() != nil {
				intent.Dst().EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
					if ipNet, ok := item.(*network.IPNet); ok {
						nameMeta["dst_network"] = ipNet.IP.String()
					} else {
						nameMeta["dst_network"] = item.String()
					}
					return true
				})
			}
			if intent.RealPort != "" {
				nameMeta["dst_port"] = intent.RealPort
			} else if intent.Service() != nil {
				intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
					if l4, ok := item.(*service.L4Service); ok {
						if !l4.DstPort().IsFull() {
							nameMeta["dst_port"] = l4.DstPort().String()
						}
					}
					return true
				})
			}
			objectName = strings.TrimSpace(formatWithIntent(g.ctx, intent, nameTemplate, nameMeta))
		}
	}

	// 如果仍然为空，使用默认名称
	if objectName == "" {
		if intent.RealIp != "" {
			objectName = objType + "_" + strings.ReplaceAll(intent.RealIp, ".", "_")
		} else {
			objectName = objType + "_OBJECT"
		}
	}

	// 生成唯一名称
	key := keys.NewKeyBuilder(objectName).Separator("_")
	return g.generateUniqueName(keys.NewAutoIncrementKeys(key, 2), intent.Dst())
}

// generateUniqueName 生成唯一的对象名称
func (g *VipMipNameGenerator) generateUniqueName(auto *keys.AutoIncrementKeys, ng *network.NetworkGroup) (keys.Keys, bool, error) {
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
