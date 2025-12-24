package v4

import (
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/keys"
	"github.com/netxops/utils/dsl"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

// getStringFromMeta 从 metaData 中获取字符串值
func getStringFromMeta(metaData map[string]interface{}, key, defaultValue string) string {
	if metaData == nil {
		return defaultValue
	}
	if v, ok := metaData[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultValue
}

// getBoolFromMeta 从 metaData 中获取布尔值
func getBoolFromMeta(metaData map[string]interface{}, key string, defaultValue bool) bool {
	if metaData == nil {
		return defaultValue
	}
	if v, ok := metaData[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
		if s, ok := v.(string); ok {
			return s == "true"
		}
	}
	return defaultValue
}

// copyMap 复制 map
func copyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return make(map[string]interface{})
	}
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}

// generateObjectNameFromTemplate 从模板生成对象名称（支持 Starlark 模板）
func generateObjectNameFromTemplate(ctx *GeneratorContext, net network.AbbrNet, template string, metaData map[string]interface{}) string {
	if template == "" || net == nil {
		return ""
	}

	// 检查模板是否包含 IDTemplate 语法（{SEQ:...} 或 {VAR:...}）
	hasIDTemplateSyntax := strings.Contains(template, "{SEQ:") || strings.Contains(template, "{VAR:")

	// 如果包含 IDTemplate 语法，先处理这些部分
	if hasIDTemplateSyntax {
		getIterator := func() firewall.NamerIterator {
			return &emptyNamerIterator{}
		}
		idTemplate := common.NewPolicyTemplate(template, getIterator).Initialize()

		idTemplateVars := make(map[string]interface{}, len(metaData))
		for k, v := range metaData {
			idTemplateVars[k] = v
		}

		_, intermediateResult := idTemplate.Generate(idTemplateVars)

		// 检查是否还有 DSL 语法或需要 Starlark 处理
		hasDSLSyntax := strings.Contains(intermediateResult, "{ip}") ||
			strings.Contains(intermediateResult, "{mask}") ||
			strings.Contains(intermediateResult, "{start}") ||
			strings.Contains(intermediateResult, "{end}") ||
			strings.Contains(intermediateResult, "{cidr}") ||
			strings.Contains(intermediateResult, "{type}")
		ng := &network.NetworkGroup{}
		ng.Add(net)
		if hasDSLSyntax {
			// 创建临时 intent 用于格式化
			tempIntent := &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					ng,
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					nil,
				),
			}
			return formatWithIntent(ctx, tempIntent, intermediateResult, metaData)
		}

		return strings.TrimSpace(intermediateResult)
	}

	// 不包含 IDTemplate 语法，使用 Starlark 处理
	// 检查模板中是否使用了 intent 对象
	// 如果使用了 intent，需要创建临时 Intent 并使用 formatWithIntent
	// 否则使用 StarlarkNetworkFormat（只提供 network 对象）
	hasIntentSyntax := strings.Contains(template, "intent.") || strings.Contains(template, "intent.src") || strings.Contains(template, "intent.dst")

	if hasIntentSyntax {
		// 创建临时 Intent，将 net 作为 src 或 dst
		ng := &network.NetworkGroup{}
		ng.Add(net)

		// 根据 is_source 决定将 net 放在 src 还是 dst
		isSource := false
		if isSourceStr, ok := metaData["is_source"].(string); ok {
			isSource = isSourceStr == "true"
		} else if isSourceBool, ok := metaData["is_source"].(bool); ok {
			isSource = isSourceBool
		}

		tempIntent := &policy.Intent{
			PolicyEntry: *policy.NewPolicyEntryWithAll(
				func() *network.NetworkGroup {
					if isSource {
						return ng
					}
					return network.NewNetworkGroupFromStringMust("0.0.0.0/0")
				}(),
				func() *network.NetworkGroup {
					if isSource {
						return network.NewNetworkGroupFromStringMust("0.0.0.0/0")
					}
					return ng
				}(),
				nil,
			),
		}
		return formatWithIntent(ctx, tempIntent, template, metaData)
	}

	// 没有使用 intent，直接使用 StarlarkNetworkFormat 进行渲染
	opts := dsl.NewDSLParserOptions()
	result := dsl.StarlarkNetworkFormat(net, template, opts, metaData)
	return strings.TrimSpace(result)
}

// formatWithIntent 使用 Intent 格式化模板（仅支持 Starlark）
func formatWithIntent(ctx *GeneratorContext, intent *policy.Intent, template string, metaData map[string]interface{}) string {
	if template == "" {
		return ""
	}

	// 检查是否是 Starlark 模板标记（格式：__STARLARK__:TemplateName）
	if IsStarlarkLayout(template) {
		templateName := ExtractStarlarkTemplateName(template)
		if templateName != "" {
			if adapter, ok := ctx.Templates.(*StarlarkTemplatesAdapter); ok {
				result, err := adapter.RenderStarlarkTemplate(templateName, intent, metaData)
				if err == nil {
					return strings.TrimSpace(result)
				}
			}
		}
		return ""
	}

	// 否则，直接作为 Starlark 代码字符串执行
	if adapter, ok := ctx.Templates.(*StarlarkTemplatesAdapter); ok {
		result, err := adapter.ExecuteStarlarkCode(template, intent, metaData)
		if err == nil {
			return strings.TrimSpace(result)
		}
	}

	return ""
}

// formatWithNetworkGroup 使用 NetworkGroup 格式化模板（支持 Starlark）
func formatWithNetworkGroup(ctx *GeneratorContext, ng *network.NetworkGroup, template string, metaData map[string]interface{}) string {
	if template == "" || ng == nil {
		return ""
	}

	return dsl.StarlarkNetworkGroupFormat(ng, template, dsl.NewDSLParserOptions(), metaData)
}

// formatWithService 使用 Service 格式化模板（支持 Starlark）
func formatWithService(ctx *GeneratorContext, svc *service.Service, template string, metaData map[string]interface{}) string {
	if template == "" || svc == nil {
		return ""
	}

	return dsl.StarlarkServiceFormat(svc, template, dsl.NewDSLParserOptions(), metaData)
}

// formatWithMap 使用 Map 格式化模板（仅支持 Starlark）
func formatWithMap(ctx *GeneratorContext, metaData map[string]interface{}, template string) string {
	if template == "" {
		return ""
	}

	// 否则，直接作为 Starlark 代码字符串执行
	// 直接使用 dsl.StarlarkIntentFormat 渲染
	opts := dsl.NewDSLParserOptions()
	result := dsl.StarlarkMapFormat(metaData, template, opts, metaData)
	return strings.TrimSpace(result)
}

// dslMapFormat 使用 Map 格式化模板（支持 Starlark，向后兼容函数）
func dslMapFormat(ctx *GeneratorContext, metaData map[string]interface{}, template string) string {
	return formatWithMap(ctx, metaData, template)
}

// emptyNamerIterator 实现一个空的 NamerIterator
type emptyNamerIterator struct{}

func (e *emptyNamerIterator) HasNext() bool {
	return false
}

func (e *emptyNamerIterator) Next() firewall.Namer {
	return nil
}

func (e *emptyNamerIterator) Reset() {
	// 空实现
}

// renderLayout 通用的 layout 渲染函数，仅支持 Starlark 模板
// ctx: 生成器上下文
// intent: 策略意图
// layout: layout 字符串（Starlark 标记，格式：__STARLARK__:TemplateName）
// metaData: 元数据
func renderLayout(ctx *GeneratorContext, intent *policy.Intent, layout string, metaData map[string]interface{}) string {
	if layout == "" {
		return ""
	}

	// 检查是否是 Starlark 模板
	if IsStarlarkLayout(layout) {
		templateName := ExtractStarlarkTemplateName(layout)
		if templateName == "" {
			return ""
		}

		// 尝试从 ctx.Templates 获取 Starlark 适配器
		if adapter, ok := ctx.Templates.(*StarlarkTemplatesAdapter); ok {
			result, err := adapter.RenderStarlarkTemplate(templateName, intent, metaData)
			if err != nil {
				// 如果渲染失败，返回空字符串
				// 注意：err 可能包含有用的错误信息，但这里不传播以避免影响调用者
				return ""
			}
			// 即使没有错误，结果也可能为空（例如模板函数返回空字符串）
			return result
		}

		// 如果不是 Starlark 适配器，返回空字符串
		return ""
	}

	// 使用 DSL 渲染
	// return dsl.IntentFormat(intent, layout, dsl.NewDSLParserOptions().WithIgnoreLeadingWhitespace(true), metaData)
	// 已移除 DSL 向后兼容支持，仅支持 Starlark 模板
	return ""
}

// getSectionSeparator 通用的分隔符获取函数，仅支持 Starlark 模板
// ctx: 生成器上下文
func getSectionSeparator(ctx *GeneratorContext) string {
	separator := ctx.Templates.GetLayout(keys.NewKeyBuilder("SectionSeparator"))
	if separator == "" {
		return "#" // 默认分隔符
	}

	// 检查是否是 Starlark 模板返回的分隔符
	if IsStarlarkLayout(separator) {
		templateName := ExtractStarlarkTemplateName(separator)
		if templateName == "SectionSeparator" {
			// 对于 SectionSeparator，Starlark 模板返回的是字符串值，不是函数
			// 直接调用 RenderStarlarkTemplate 会返回字符串
			if adapter, ok := ctx.Templates.(*StarlarkTemplatesAdapter); ok {
				// SectionSeparator 在 Starlark 模板中是字符串，不是函数
				// 创建一个空的 intent 和 meta 来获取分隔符
				emptyIntent := &policy.Intent{}
				emptyMeta := make(map[string]interface{})
				result, err := adapter.RenderStarlarkTemplate("SectionSeparator", emptyIntent, emptyMeta)
				if err == nil && result != "" {
					return result
				}
			}
		}
		// 如果获取失败，返回默认值
		return "#"
	}

	// DSL 模板直接返回分隔符字符串
	// return separator
	// 已移除 DSL 向后兼容支持，仅支持 Starlark 模板
	return "#"
}
