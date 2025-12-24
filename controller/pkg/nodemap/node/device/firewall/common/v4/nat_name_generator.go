package v4

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

// NatNameGenerator NAT策略名称生成器
type NatNameGenerator struct {
	ctx             *GeneratorContext
	template        *common.IDTemplate
	currentTemplate string
}

// NewNatNameGenerator 创建NAT策略名称生成器
func NewNatNameGenerator(ctx *GeneratorContext) *NatNameGenerator {
	return &NatNameGenerator{
		ctx: ctx,
	}
}

// Generate 生成NAT策略名称和ID
func (g *NatNameGenerator) Generate(intent *policy.Intent, ctx *firewall.PolicyContext, metaData map[string]interface{}) (mainID int, name string, id string, err error) {
	// 优先使用metaData中直接指定的nat_name
	name = getStringFromMeta(metaData, "nat_name", "")

	// 如果metaData中没有nat_name，优先调用GetPolicyName（如果实现）
	if name == "" {
		if policyNameGetter, ok := g.ctx.Node.(interface {
			GetPolicyName(ctx *firewall.PolicyContext) (string, error)
		}); ok {
			generatedName, err := policyNameGetter.GetPolicyName(ctx)
			if err == nil && generatedName != "" {
				name = generatedName
			}
		}
	}

	// 如果GetPolicyName返回空，使用命名模板
	if name == "" {
		template := getStringFromMeta(metaData, "natpolicy.name_template", "")
		if template == "" {
			template = "NAT_POLICY"
		}

		mainID, name, err = g.generateFromTemplate(intent, template, metaData)
		if err != nil {
			return 0, "", "", fmt.Errorf("failed to generate NAT policy name from template: %v", err)
		}
	}

	// 如果还是没有名称，使用默认名称
	if name == "" {
		name = "NAT_POLICY"
		mainID = 0
	}

	// 生成ID
	id = getStringFromMeta(metaData, "nat_id", "")
	if id == "" {
		id = getStringFromMeta(metaData, "policy_id", "")
	}
	if id == "" && mainID > 0 {
		id = fmt.Sprintf("%d", mainID)
		metaData["nat_id"] = id
		metaData["policy_id"] = id
	}

	return mainID, strings.TrimSpace(name), id, nil
}

// generateFromTemplate 从模板生成名称
// 支持三种模板类型：
// 1. IDTemplate 语法：{VAR:...}, {DATE:...}, {SEQ:...}
// 2. DSL IntentFormat：包含 intent 字段（{dst_network}, {src_network}, {dst_port}）
// 3. DSL MapFormat：普通变量替换
func (g *NatNameGenerator) generateFromTemplate(intent *policy.Intent, template string, metaData map[string]interface{}) (int, string, error) {
	// 检查模板是否包含 IDTemplate 语法
	// 注意：需要检查 {VAR:}, {DATE:}, {SEQ:} 三种类型
	hasIDTemplateSyntax := strings.Contains(template, "{VAR:") ||
		strings.Contains(template, "{DATE:") ||
		strings.Contains(template, "{SEQ:")

	if hasIDTemplateSyntax {
		// 如果模板改变了，需要重新创建 IDTemplate
		if g.currentTemplate != template {
			var getIterator func() firewall.NamerIterator
			if iteratorNode, ok := g.ctx.Node.(firewall.IteratorFirewall); ok {
				// 优先使用 NatIterator，如果没有则使用 PolicyIterator
				if natIteratorNode, ok := iteratorNode.(interface {
					NatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator
				}); ok {
					getIterator = func() firewall.NamerIterator {
						return natIteratorNode.NatIterator()
					}
				} else {
					getIterator = func() firewall.NamerIterator {
						return iteratorNode.PolicyIterator()
					}
				}
			} else {
				getIterator = func() firewall.NamerIterator {
					return &emptyNamerIterator{}
				}
			}
			// 创建 IDTemplate 并初始化（从现有NAT策略中提取序列号和日期）
			g.template = common.NewPolicyTemplate(template, getIterator).WithMaxRetries(10).Initialize()
			g.currentTemplate = template
		}

		// 准备变量数据
		variables := make(map[string]interface{})
		for k, v := range metaData {
			variables[k] = v
		}
		// 添加 intent 相关的变量（用于 IDTemplate 中的 VAR 字段）
		g.addIntentVariables(intent, variables)

		// 使用 IDTemplate 生成 NAT 策略名称
		// IDTemplate 会处理 {VAR:}, {DATE:}, {SEQ:} 三种字段类型
		mainID, name := g.template.Generate(variables)
		return mainID, strings.TrimSpace(name), nil
	}

	// 检查是否包含 intent 字段（DSL 语法）
	if strings.Contains(template, "{dst_network}") || strings.Contains(template, "{src_network}") || strings.Contains(template, "{dst_port}") {
		// 使用 Starlark 模板处理包含 intent 字段的模板
		nameMeta := copyMap(metaData)
		g.addIntentVariables(intent, nameMeta)
		name := strings.TrimSpace(formatWithIntent(g.ctx, intent, template, nameMeta))
		return 0, name, nil
	}

	// 使用 Starlark 模板处理普通模板
	name := strings.TrimSpace(formatWithMap(g.ctx, metaData, template))
	return 0, name, nil
}

// addIntentVariables 添加 intent 相关的变量
func (g *NatNameGenerator) addIntentVariables(intent *policy.Intent, variables map[string]interface{}) {
	if intent.Dst() != nil {
		intent.Dst().EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
			if ipNet, ok := item.(*network.IPNet); ok {
				variables["dst_network"] = ipNet.IP.String()
			} else {
				variables["dst_network"] = item.String()
			}
			return true
		})
	}
	if intent.Src() != nil {
		intent.Src().EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
			if ipNet, ok := item.(*network.IPNet); ok {
				variables["src_network"] = ipNet.IP.String()
			} else {
				variables["src_network"] = item.String()
			}
			return true
		})
	}
	if intent.Service() != nil {
		intent.Service().EachDetailed(func(item service.ServiceEntry) bool {
			if l4, ok := item.(*service.L4Service); ok {
				if !l4.DstPort().IsFull() {
					variables["dst_port"] = l4.DstPort().String()
				}
			}
			return true
		})
	}
}
