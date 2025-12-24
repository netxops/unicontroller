package v4

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/keys"
	"github.com/netxops/utils/service"
)

// ServiceNameGenerator 服务对象名称生成器
type ServiceNameGenerator struct {
	ctx *GeneratorContext
	om  *common.ObjectNameManager
}

// NewServiceNameGenerator 创建服务对象名称生成器
func NewServiceNameGenerator(ctx *GeneratorContext) *ServiceNameGenerator {
	return &ServiceNameGenerator{
		ctx: ctx,
		om:  common.NewObjectNameManager(),
	}
}

// Generate 生成服务对象名称（唯一）
// 返回：生成的名称、是否为新对象、错误
func (g *ServiceNameGenerator) Generate(svc *service.Service, template string, metaData map[string]interface{}) (keys.Keys, bool, error) {
	// 获取第一个服务条目用于生成名称
	var firstSvcEntry service.ServiceEntry
	svc.EachDetailed(func(item service.ServiceEntry) bool {
		firstSvcEntry = item
		return false // 只取第一个
	})

	objectMetaForName := copyMap(metaData)
	objectName := g.generateServiceNameFromTemplate(firstSvcEntry, template, objectMetaForName)
	if objectName == "" {
		objectName = "SERVICE_OBJECT"
	}

	// 生成唯一名称
	key := keys.NewKeyBuilder(objectName).Separator("_")
	return g.generateUniqueName(keys.NewAutoIncrementKeys(key, 2), svc)
}

// GenerateFromEntry 从服务条目生成名称
func (g *ServiceNameGenerator) GenerateFromEntry(svcEntry service.ServiceEntry, template string, metaData map[string]interface{}) (keys.Keys, bool, error) {
	memberMetaForName := copyMap(metaData)
	memberName := g.generateServiceNameFromTemplate(svcEntry, template, memberMetaForName)
	if memberName == "" {
		memberName = fmt.Sprintf("MEMBER_%d", len(metaData))
	}

	memberSvc := &service.Service{}
	memberSvc.Add(svcEntry)

	key := keys.NewKeyBuilder(memberName).Separator("_")
	return g.generateUniqueName(keys.NewAutoIncrementKeys(key, 2), memberSvc)
}

// GenerateGroupName 生成服务组名称（唯一）
func (g *ServiceNameGenerator) GenerateGroupName(template string, metaData map[string]interface{}) (keys.Keys, bool, error) {
	groupName := g.generateGroupNameFromTemplate(template, metaData)
	if groupName == "" {
		groupName = "SRV_GROUP"
	}

	key := keys.NewKeyBuilder(groupName).Separator("_")
	// 简化实现：直接返回，实际应该检查组名称是否已存在
	return key, true, nil
}

// generateServiceNameFromTemplate 从模板生成服务对象名称
func (g *ServiceNameGenerator) generateServiceNameFromTemplate(svcEntry service.ServiceEntry, template string, metaData map[string]interface{}) string {
	if template == "" {
		return ""
	}

	svc := &service.Service{}
	svc.Add(svcEntry)

	return strings.TrimSpace(formatWithService(g.ctx, svc, template, metaData))
}

// generateGroupNameFromTemplate 从模板生成组名称
func (g *ServiceNameGenerator) generateGroupNameFromTemplate(template string, metaData map[string]interface{}) string {
	if template == "" {
		return ""
	}
	return formatWithMap(g.ctx, metaData, template)
}

// generateUniqueName 生成唯一的服务对象名称
func (g *ServiceNameGenerator) generateUniqueName(auto *keys.AutoIncrementKeys, svc *service.Service) (keys.Keys, bool, error) {
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
