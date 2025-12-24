package firewall

const (
	// DefaultFirewallTemplatePath 默认的防火墙模板路径
	DefaultFirewallTemplatePath = "pkg/nodemap/node/device/firewall/common/v4/templates"
)

// GetTemplatePath 获取模板路径
// 优先级：PolicyContext.TemplatePath > 默认路径
func GetTemplatePath(ctx *PolicyContext) string {
	if ctx != nil && ctx.TemplatePath != "" {
		return ctx.TemplatePath
	}
	return DefaultFirewallTemplatePath
}
