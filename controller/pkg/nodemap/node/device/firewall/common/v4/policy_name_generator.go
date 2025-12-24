package v4

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
)

// PolicyNameGenerator 策略名称生成器
// 支持完整的 IDTemplate 语法：
// - {VAR:name} - 变量替换
// - {DATE:name:format} - 日期字段（支持 YYYYMMDD, YYYY-MM-DD 等）
// - {SEQ:name:width:start:step:MAIN:NORENDER} - 序列号字段
type PolicyNameGenerator struct {
	ctx             *GeneratorContext
	template        *common.IDTemplate
	currentTemplate string
}

// NewPolicyNameGenerator 创建策略名称生成器
func NewPolicyNameGenerator(ctx *GeneratorContext) *PolicyNameGenerator {
	return &PolicyNameGenerator{
		ctx: ctx,
	}
}

// Generate 生成策略名称和ID
// 优先级：
// 1. metaData 中直接指定的 policy_name
// 2. 节点实现的 GetPolicyName 方法
// 3. 使用命名模板生成（支持 IDTemplate 和 DSL）
func (g *PolicyNameGenerator) Generate(ctx *firewall.PolicyContext, metaData map[string]interface{}) (mainID int, name string, id string, err error) {
	// 优先使用metaData中直接指定的policy_name
	name = getStringFromMeta(metaData, "policy_name", "")

	// 如果metaData中没有policy_name，优先调用GetPolicyName（如果实现）
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
		template := getStringFromMeta(metaData, "securitypolicy.policy_name_template", "")
		if template == "" {
			template = getStringFromMeta(metaData, "policy_name_template", "")
		}
		if template == "" {
			template = "POLICY_{SEQ:id:5:1:1:MAIN}" // 默认模板
		}

		mainID, name, err = g.generateFromTemplate(template, metaData)
		if err != nil {
			return 0, "", "", fmt.Errorf("failed to generate policy name from template: %w", err)
		}
	}

	// 如果还是没有名称，使用默认名称
	if name == "" {
		name = "POLICY_OBJECT"
		mainID = 0
	}

	// 将 policyName 设置到 metaData 中，以便后续的对象名称生成可以使用
	metaData["policy_name"] = name

	// 生成策略ID
	id = getStringFromMeta(metaData, "policy_id", "")
	if id == "" && mainID > 0 {
		id = fmt.Sprintf("%d", mainID)
		metaData["policy_id"] = id
	}
	if id == "" {
		id = "1" // 默认ID
	}

	return mainID, strings.TrimSpace(name), id, nil
}

// generateFromTemplate 从模板生成名称
// 支持两种模板类型：
// 1. IDTemplate 语法：{VAR:...}, {DATE:...}, {SEQ:...}
// 2. DSL 语法：普通变量替换
func (g *PolicyNameGenerator) generateFromTemplate(template string, metaData map[string]interface{}) (int, string, error) {
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
				getIterator = func() firewall.NamerIterator {
					return iteratorNode.PolicyIterator()
				}
			} else {
				getIterator = func() firewall.NamerIterator {
					return &emptyNamerIterator{}
				}
			}
			// 创建 IDTemplate 并初始化（从现有策略中提取序列号和日期）
			g.template = common.NewPolicyTemplate(template, getIterator).WithMaxRetries(10).Initialize()
			g.currentTemplate = template
		}

		// 使用 IDTemplate 生成策略名称
		// IDTemplate 会处理 {VAR:}, {DATE:}, {SEQ:} 三种字段类型
		variables := make(map[string]interface{})
		for k, v := range metaData {
			variables[k] = v
		}
		mainID, name := g.template.Generate(variables)
		return mainID, strings.TrimSpace(name), nil
	}

	// 使用 Starlark 模板生成策略名称（不包含 IDTemplate 语法）
	name := strings.TrimSpace(formatWithMap(g.ctx, metaData, template))
	return 0, name, nil
}
