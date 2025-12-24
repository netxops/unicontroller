package forti

import (
	"fmt"
	"net"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
)

var _ firewall.BlacklistWhitelistHandler = &FortigateNode{}

// GetImplementationMethod 获取实现方式
func (fgn *FortigateNode) GetImplementationMethod() string {
	return "policy"
}

// AddIPsToGroup 添加IP到预设地址组（策略方式）
func (fgn *FortigateNode) AddIPsToGroup(
	listType string,
	groupName string,
	ips []string,
) (string, error) {
	if listType != "blacklist" && listType != "whitelist" {
		return "", fmt.Errorf("invalid list type: %s", listType)
	}

	if groupName == "" {
		return "", fmt.Errorf("group name is required")
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("ips list is empty")
	}

	var cliCommands []string

	// 为每个IP创建地址对象（如果不存在）并添加到地址组
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		// 解析IP地址
		ip, ipNet, err := parseIP(ipStr)
		if err != nil {
			return "", fmt.Errorf("invalid IP address %s: %w", ipStr, err)
		}

		// 生成地址对象名称
		objName := generateAddressObjectName(listType, ipStr)

		// 检查地址对象是否已存在
		exists := fgn.HasObjectName(objName)

		// 创建地址对象（如果不存在）
		if !exists {
			addrCLI := generateAddressObjectCLI(objName, ip, ipNet)
			cliCommands = append(cliCommands, addrCLI)
		}

		// 生成添加到地址组的CLI
		groupCLI := generateAddToGroupCLI(groupName, objName)
		cliCommands = append(cliCommands, groupCLI)
	}

	return strings.Join(cliCommands, "\n"), nil
}

// RemoveIPsFromGroup 从预设地址组移除IP（策略方式）
func (fgn *FortigateNode) RemoveIPsFromGroup(
	listType string,
	groupName string,
	ips []string,
) (string, error) {
	if listType != "blacklist" && listType != "whitelist" {
		return "", fmt.Errorf("invalid list type: %s", listType)
	}

	if groupName == "" {
		return "", fmt.Errorf("group name is required")
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("ips list is empty")
	}

	var cliCommands []string

	// 从地址组移除每个IP对应的地址对象
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		// 生成地址对象名称
		objName := generateAddressObjectName(listType, ipStr)

		// 生成从地址组移除的CLI
		groupCLI := generateRemoveFromGroupCLI(groupName, objName)
		cliCommands = append(cliCommands, groupCLI)
	}

	return strings.Join(cliCommands, "\n"), nil
}

// AddIPsViaAPI 通过API添加IP（专门功能方式）
func (fgn *FortigateNode) AddIPsViaAPI(
	listType string,
	ips []string,
) (map[string]interface{}, error) {
	// Fortinet 当前使用策略方式，暂不支持专门功能方式
	return nil, fmt.Errorf("Fortinet does not support API method, use policy method instead")
}

// RemoveIPsViaAPI 通过API移除IP（专门功能方式）
func (fgn *FortigateNode) RemoveIPsViaAPI(
	listType string,
	ips []string,
) (map[string]interface{}, error) {
	// Fortinet 当前使用策略方式，暂不支持专门功能方式
	return nil, fmt.Errorf("Fortinet does not support API method, use policy method instead")
}

// CheckPresetConfig 检查预设配置是否存在
func (fgn *FortigateNode) CheckPresetConfig(
	presetConfig *firewall.PresetConfig,
) (*firewall.PresetConfigCheckResult, error) {
	result := &firewall.PresetConfigCheckResult{
		Details: make(map[string]string),
	}

	// 检查黑名单策略
	if presetConfig.BlacklistPolicyName != "" {
		result.BlacklistPolicyOK = fgn.HasPolicyName(presetConfig.BlacklistPolicyName)
		if !result.BlacklistPolicyOK {
			result.Details["blacklist_policy"] = fmt.Sprintf("Policy '%s' not found", presetConfig.BlacklistPolicyName)
		} else {
			result.Details["blacklist_policy"] = fmt.Sprintf("Policy '%s' exists", presetConfig.BlacklistPolicyName)
		}
	}

	// 检查白名单策略
	if presetConfig.WhitelistPolicyName != "" {
		result.WhitelistPolicyOK = fgn.HasPolicyName(presetConfig.WhitelistPolicyName)
		if !result.WhitelistPolicyOK {
			result.Details["whitelist_policy"] = fmt.Sprintf("Policy '%s' not found", presetConfig.WhitelistPolicyName)
		} else {
			result.Details["whitelist_policy"] = fmt.Sprintf("Policy '%s' exists", presetConfig.WhitelistPolicyName)
		}
	}

	// 检查黑名单地址组
	if presetConfig.BlacklistGroupName != "" {
		result.BlacklistGroupOK = fgn.HasObjectName(presetConfig.BlacklistGroupName)
		if !result.BlacklistGroupOK {
			result.Details["blacklist_group"] = fmt.Sprintf("Address group '%s' not found", presetConfig.BlacklistGroupName)
		} else {
			result.Details["blacklist_group"] = fmt.Sprintf("Address group '%s' exists", presetConfig.BlacklistGroupName)
		}
	}

	// 检查白名单地址组
	if presetConfig.WhitelistGroupName != "" {
		result.WhitelistGroupOK = fgn.HasObjectName(presetConfig.WhitelistGroupName)
		if !result.WhitelistGroupOK {
			result.Details["whitelist_group"] = fmt.Sprintf("Address group '%s' not found", presetConfig.WhitelistGroupName)
		} else {
			result.Details["whitelist_group"] = fmt.Sprintf("Address group '%s' exists", presetConfig.WhitelistGroupName)
		}
	}

	return result, nil
}

// parseIP 解析IP地址（支持单个IP和CIDR）
func parseIP(ipStr string) (string, *net.IPNet, error) {
	// 尝试解析为CIDR
	if strings.Contains(ipStr, "/") {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return "", nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		return ipNet.IP.String(), ipNet, nil
	}

	// 尝试解析为单个IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// 单个IP转换为/32或/128
	if ip.To4() != nil {
		_, ipNet, _ := net.ParseCIDR(ipStr + "/32")
		return ip.String(), ipNet, nil
	} else {
		_, ipNet, _ := net.ParseCIDR(ipStr + "/128")
		return ip.String(), ipNet, nil
	}
}

// generateAddressObjectName 生成地址对象名称
func generateAddressObjectName(listType, ipStr string) string {
	// 简化IP字符串（替换.和/为_）
	ipSimplified := strings.ReplaceAll(ipStr, ".", "_")
	ipSimplified = strings.ReplaceAll(ipSimplified, "/", "_")
	ipSimplified = strings.ReplaceAll(ipSimplified, ":", "_")

	prefix := "BL"
	if listType == "whitelist" {
		prefix = "WL"
	}

	// 生成简短名称（限制长度）
	if len(ipSimplified) > 30 {
		ipSimplified = ipSimplified[:30]
	}

	return fmt.Sprintf("%s_%s", prefix, ipSimplified)
}

// generateAddressObjectCLI 生成创建地址对象的CLI
func generateAddressObjectCLI(objName string, ip string, ipNet *net.IPNet) string {
	var cli strings.Builder

	cli.WriteString("config firewall address\n")
	cli.WriteString(fmt.Sprintf("    edit \"%s\"\n", objName))

	// 判断是单个IP还是子网
	mask := ipNet.Mask
	ones, _ := mask.Size()

	if (ipNet.IP.To4() != nil && ones == 32) || (ipNet.IP.To4() == nil && ones == 128) {
		// 单个IP
		cli.WriteString(fmt.Sprintf("        set subnet %s 255.255.255.255\n", ip))
	} else {
		// 子网
		subnet := ipNet.String()
		cli.WriteString(fmt.Sprintf("        set subnet %s\n", subnet))
	}

	cli.WriteString("    next\n")
	cli.WriteString("end\n")

	return cli.String()
}

// generateAddToGroupCLI 生成添加到地址组的CLI
func generateAddToGroupCLI(groupName, objName string) string {
	var cli strings.Builder

	cli.WriteString("config firewall addrgrp\n")
	cli.WriteString(fmt.Sprintf("    edit \"%s\"\n", groupName))
	cli.WriteString(fmt.Sprintf("        append member \"%s\"\n", objName))
	cli.WriteString("    next\n")
	cli.WriteString("end\n")

	return cli.String()
}

// generateRemoveFromGroupCLI 生成从地址组移除的CLI
func generateRemoveFromGroupCLI(groupName, objName string) string {
	var cli strings.Builder

	cli.WriteString("config firewall addrgrp\n")
	cli.WriteString(fmt.Sprintf("    edit \"%s\"\n", groupName))
	cli.WriteString(fmt.Sprintf("        unselect member \"%s\"\n", objName))
	cli.WriteString("    next\n")
	cli.WriteString("end\n")

	return cli.String()
}
