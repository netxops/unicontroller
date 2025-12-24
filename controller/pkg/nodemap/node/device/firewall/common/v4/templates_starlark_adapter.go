package v4

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/keys"
	"github.com/netxops/utils/dsl"
	"github.com/netxops/utils/policy"
)

// StarlarkTemplatesAdapter Starlark 模板适配器，实现 TemplatesV4 接口
type StarlarkTemplatesAdapter struct {
	registry   *dsl.TemplateRegistry
	vendorName string
}

// NewStarlarkTemplatesAdapter 创建 Starlark 模板适配器
// vendorName: 厂商名称，如 "secpath", "usg", "dptech" 等
// templateDir: Starlark 模板文件所在目录（可以是相对路径或绝对路径）
func NewStarlarkTemplatesAdapter(vendorName, templateDir string) (*StarlarkTemplatesAdapter, error) {
	registry := dsl.NewTemplateRegistry()

	// 如果路径不是绝对路径，尝试转换为绝对路径
	// 这对于测试环境很重要，因为测试的工作目录可能不同
	absTemplateDir := templateDir
	if !filepath.IsAbs(templateDir) {
		// 首先尝试从项目根目录查找（相对于项目根目录的路径）
		// 这对于测试很重要，因为测试可能在不同的目录运行
		cwd, _ := filepath.Abs(".")

		// 尝试从当前目录开始向上查找项目根目录
		// 检查路径是否以 "pkg/" 开头，如果是，说明是相对于项目根目录的路径

		// 如果路径以 "pkg/" 开头，说明是相对于项目根目录的路径
		// 需要从当前目录向上查找项目根目录
		if strings.HasPrefix(templateDir, "pkg/") {
			// 从当前目录向上查找，直到找到包含 "pkg/" 目录的路径
			currentDir := cwd
			for i := 0; i < 10; i++ { // 最多向上查找10层
				testPath := filepath.Join(currentDir, templateDir)
				if files, err := filepath.Glob(filepath.Join(testPath, "templates_*.star")); err == nil && len(files) > 0 {
					absTemplateDir = testPath
					break
				}
				parent := filepath.Dir(currentDir)
				if parent == currentDir {
					break // 已经到达根目录
				}
				currentDir = parent
			}
		} else {
			// 如果不是以 "pkg/" 开头，尝试从当前目录解析
			if absPath, err := filepath.Abs(templateDir); err == nil {
				absTemplateDir = absPath
			}
		}
	}

	// 从目录加载模板
	err := registry.LoadTemplatesFromDir(absTemplateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load Starlark templates from %s (resolved from %s): %w", absTemplateDir, templateDir, err)
	}

	return &StarlarkTemplatesAdapter{
		registry:   registry,
		vendorName: vendorName,
	}, nil
}

// NewStarlarkTemplatesAdapterFromNode 从 FirewallNode 创建 Starlark 模板适配器
// 自动检测厂商名称并加载对应的模板
func NewStarlarkTemplatesAdapterFromNode(node firewall.FirewallNode, templateDir string) (*StarlarkTemplatesAdapter, error) {
	// 从节点类型推断厂商名称
	vendorName := getVendorNameFromNode(node)
	if vendorName == "" {
		return nil, fmt.Errorf("cannot determine vendor name from node type: %T", node)
	}

	return NewStarlarkTemplatesAdapter(vendorName, templateDir)
}

// getVendorNameFromNode 从节点类型推断厂商名称
func getVendorNameFromNode(node firewall.FirewallNode) string {
	nodeType := fmt.Sprintf("%T", node)
	nodeType = strings.ToLower(nodeType)

	// 根据节点类型推断厂商名称
	if strings.Contains(nodeType, "secpath") {
		return "secpath"
	} else if strings.Contains(nodeType, "usg") {
		return "usg"
	} else if strings.Contains(nodeType, "dptech") {
		return "dptech"
	} else if strings.Contains(nodeType, "asa") {
		return "asa"
	} else if strings.Contains(nodeType, "forti") {
		return "forti"
	} else if strings.Contains(nodeType, "sangfor") {
		return "sangfor"
	}

	return ""
}

// GetLayout 实现 TemplatesV4 接口
// 返回特殊标记，表示使用 Starlark 模板
// key 的格式通常是 "TemplateType" 或 "TemplateType.SubType"
// 例如: "Policy", "Policy.OneLoop", "AddressObject", "ServiceGroup" 等
func (a *StarlarkTemplatesAdapter) GetLayout(key keys.Keys) string {
	// 将 keys.Keys 转换为模板名称
	templateName := a.keyToTemplateName(key)

	// 返回特殊标记，格式: "__STARLARK__:TemplateName"
	// 这样 renderLayout 可以识别并调用 Starlark 渲染
	return fmt.Sprintf("__STARLARK__:%s", templateName)
}

// keyToTemplateName 将 keys.Keys 转换为 Starlark 模板名称
func (a *StarlarkTemplatesAdapter) keyToTemplateName(key keys.Keys) string {
	// keys.Keys 的 String() 方法返回类似 "Policy.OneLoop" 的格式
	// 我们取第一部分作为模板名称
	keyStr := key.String()
	if keyStr == "" {
		return ""
	}

	// 按 "." 分割，取第一部分
	parts := strings.Split(keyStr, ".")
	if len(parts) == 0 {
		return ""
	}

	// 第一部分是模板类型
	templateType := parts[0]

	// 特殊处理：某些 key 可能需要映射
	// 例如 "Policy.OneLoop" -> "Policy"
	// "NatPolicy.ObjectNat" -> "NatPolicy"
	// "NatPolicy.OneLoop" -> "NatPolicy"
	return templateType
}

// RenderStarlarkTemplate 渲染 Starlark 模板
// templateName: 模板名称，如 "Policy", "AddressObject" 等
// intent: 策略意图
// meta: 元数据
func (a *StarlarkTemplatesAdapter) RenderStarlarkTemplate(templateName string, intent *policy.Intent, meta map[string]interface{}) (string, error) {
	return a.registry.RenderTemplate(a.vendorName, templateName, intent, meta)
}

// IsStarlarkLayout 检查 layout 是否是 Starlark 模板标记
func IsStarlarkLayout(layout string) bool {
	return strings.HasPrefix(layout, "__STARLARK__:")
}

// ExtractStarlarkTemplateName 从 Starlark 标记中提取模板名称
func ExtractStarlarkTemplateName(layout string) string {
	if !IsStarlarkLayout(layout) {
		return ""
	}
	return strings.TrimPrefix(layout, "__STARLARK__:")
}

// GetVendorName 获取厂商名称
func (a *StarlarkTemplatesAdapter) GetVendorName() string {
	return a.vendorName
}

// ExecuteStarlarkCode 直接执行 Starlark 代码字符串
// code: Starlark 代码字符串，应该是一个表达式或语句序列，最后需要返回结果
// intent: 策略意图
// meta: 元数据
//
// 支持的代码格式：
//
//  1. 顶层语句序列，最后需要有 result 变量：
//     result = meta.get("policy_name", "") + "_"
//     result += items[0].protocol.lower if len(items) > 0 else ""
//     result
//
//  2. 函数定义+调用形式：
//     def generate_name(intent, meta):
//     result = meta.get("policy_name", "")
//     return result
//     result = generate_name(intent, meta)
//
// 3. 可以使用以下全局变量：
//   - src, dst, service (直接访问，如 src.EachIPNet())
//   - intent.src, intent.dst, intent.service (通过 intent 访问)
//   - meta (元数据字典)
//   - intent (完整的 Intent 对象)
//
// 参考：github.com/netxops/utils/dsl 中的 StarlarkIntentFormat 函数
// 参考：starlark_intent_cartesian_example.md 中的示例
func (a *StarlarkTemplatesAdapter) ExecuteStarlarkCode(code string, intent *policy.Intent, meta map[string]interface{}) (string, error) {
	// 使用 dsl 包的 StarlarkIntentFormat 函数直接执行 Starlark 代码
	// StarlarkIntentFormat 会自动处理代码执行，并返回 result 变量的值
	opts := dsl.NewDSLParserOptions()
	result := dsl.StarlarkIntentFormat(intent, code, opts, meta)
	return result, nil
}
