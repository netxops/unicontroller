package service

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"go.uber.org/zap"
)

// PresetConfig 预设配置信息
type PresetConfig struct {
	BlacklistPolicyName string `json:"blacklist_policy_name"`         // 预设黑名单策略名称
	BlacklistPolicyID   string `json:"blacklist_policy_id,omitempty"` // 预设黑名单策略ID
	WhitelistPolicyName string `json:"whitelist_policy_name"`         // 预设白名单策略名称
	WhitelistPolicyID   string `json:"whitelist_policy_id,omitempty"` // 预设白名单策略ID
	BlacklistGroupName  string `json:"blacklist_group_name"`          // 预设黑名单地址组名称
	WhitelistGroupName  string `json:"whitelist_group_name"`          // 预设白名单地址组名称
}

// BlacklistWhitelistRequest 黑白名单请求
type BlacklistWhitelistRequest struct {
	DeviceName   string        `json:"device_name"`           // 设备名称
	Type         string        `json:"type"`                  // "blacklist" 或 "whitelist"
	IPs          []string      `json:"ips"`                   // IP 地址列表（支持 CIDR）
	PresetConfig *PresetConfig `json:"preset_config"`         // 预设配置信息
	Operation    string        `json:"operation"`             // "add" 或 "remove"
	Description  string        `json:"description,omitempty"` // 描述
}

// BlacklistWhitelistResponse 黑白名单响应
type BlacklistWhitelistResponse struct {
	Success      bool   `json:"success"`
	DeviceName   string `json:"device_name"`
	PolicyName   string `json:"policy_name"`
	AddressGroup string `json:"address_group"`
	CLI          string `json:"cli"`    // 生成的配置命令（策略方式）或 API 调用信息（专门功能方式）
	Method       string `json:"method"` // "policy" 或 "api"
	Message      string `json:"message,omitempty"`
}

// PresetConfigCheckRequest 预设配置检查请求
type PresetConfigCheckRequest struct {
	DeviceName   string        `json:"device_name"`
	PresetConfig *PresetConfig `json:"preset_config"`
}

// PresetConfigCheckResponse 预设配置检查响应
type PresetConfigCheckResponse struct {
	Success           bool              `json:"success"`
	DeviceName        string            `json:"device_name"`
	BlacklistPolicyOK bool              `json:"blacklist_policy_ok"` // 黑名单策略是否存在
	WhitelistPolicyOK bool              `json:"whitelist_policy_ok"` // 白名单策略是否存在
	BlacklistGroupOK  bool              `json:"blacklist_group_ok"`  // 黑名单地址组是否存在
	WhitelistGroupOK  bool              `json:"whitelist_group_ok"`  // 白名单地址组是否存在
	Message           string            `json:"message,omitempty"`
	Details           map[string]string `json:"details,omitempty"` // 详细信息
}

// ApplyBlacklistWhitelist 应用黑白名单（添加或移除IP）
func (mnm *NodemapService) ApplyBlacklistWhitelist(
	deviceConfigs []config.DeviceConfig,
	request *BlacklistWhitelistRequest,
	nm *nodemap.NodeMap,
) (*BlacklistWhitelistResponse, error) {
	Logger.Info("ApplyBlacklistWhitelist called",
		zap.String("device_name", request.DeviceName),
		zap.String("type", request.Type),
		zap.String("operation", request.Operation),
		zap.Strings("ips", request.IPs))

	// 验证请求参数
	if request.Type != "blacklist" && request.Type != "whitelist" {
		return nil, fmt.Errorf("invalid type: %s, must be 'blacklist' or 'whitelist'", request.Type)
	}

	if request.Operation != "add" && request.Operation != "remove" {
		return nil, fmt.Errorf("invalid operation: %s, must be 'add' or 'remove'", request.Operation)
	}

	if len(request.IPs) == 0 {
		return nil, fmt.Errorf("ips list is empty")
	}

	if request.PresetConfig == nil {
		return nil, fmt.Errorf("preset_config is required")
	}

	// 确定要使用的地址组名称和策略名称
	var groupName, policyName string
	if request.Type == "blacklist" {
		groupName = request.PresetConfig.BlacklistGroupName
		policyName = request.PresetConfig.BlacklistPolicyName
	} else {
		groupName = request.PresetConfig.WhitelistGroupName
		policyName = request.PresetConfig.WhitelistPolicyName
	}

	if groupName == "" {
		return nil, fmt.Errorf("preset %s group name is required", request.Type)
	}

	// 获取或创建 NodeMap
	if nm == nil {
		var nodemapId uint = 0
		nm, _ = nodemap.NewNodeMapFromNetwork(mnm.MNM.Name, deviceConfigs, true, 123456, &nodemapId)
		if nm == nil {
			return nil, fmt.Errorf("failed to create NodeMap")
		}
		nm.WithLogger(Logger)
	}

	// 获取防火墙节点
	node := nm.GetNode(request.DeviceName)
	if node == nil {
		return nil, fmt.Errorf("device node '%s' not found", request.DeviceName)
	}

	// 检查节点是否为防火墙节点并实现了 BlacklistWhitelistHandler 接口
	fwNode, ok := node.(firewall.FirewallNode)
	if !ok {
		return nil, fmt.Errorf("node '%s' is not a firewall node", request.DeviceName)
	}

	handler, ok := fwNode.(firewall.BlacklistWhitelistHandler)
	if !ok {
		return nil, fmt.Errorf("firewall node '%s' does not implement BlacklistWhitelistHandler", request.DeviceName)
	}

	// 获取实现方式
	method := handler.GetImplementationMethod()

	var cli string
	var err error

	// 根据操作类型和实现方式调用相应的方法
	if request.Operation == "add" {
		if method == "policy" {
			cli, err = handler.AddIPsToGroup(request.Type, groupName, request.IPs)
		} else {
			apiInfo, apiErr := handler.AddIPsViaAPI(request.Type, request.IPs)
			if apiErr != nil {
				return nil, fmt.Errorf("failed to add IPs via API: %w", apiErr)
			}
			// 将 API 信息转换为字符串（实际应该返回结构化数据）
			cli = fmt.Sprintf("API call: %v", apiInfo)
		}
	} else {
		if method == "policy" {
			cli, err = handler.RemoveIPsFromGroup(request.Type, groupName, request.IPs)
		} else {
			apiInfo, apiErr := handler.RemoveIPsViaAPI(request.Type, request.IPs)
			if apiErr != nil {
				return nil, fmt.Errorf("failed to remove IPs via API: %w", apiErr)
			}
			// 将 API 信息转换为字符串（实际应该返回结构化数据）
			cli = fmt.Sprintf("API call: %v", apiInfo)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to %s IPs: %w", request.Operation, err)
	}

	response := &BlacklistWhitelistResponse{
		Success:      true,
		DeviceName:   request.DeviceName,
		PolicyName:   policyName,
		AddressGroup: groupName,
		CLI:          cli,
		Method:       method,
		Message:      fmt.Sprintf("Successfully %sed %d IP(s) to %s", request.Operation, len(request.IPs), request.Type),
	}

	return response, nil
}

// CheckPresetConfig 检查预设配置是否准备就绪
func (mnm *NodemapService) CheckPresetConfig(
	deviceConfigs []config.DeviceConfig,
	request *PresetConfigCheckRequest,
	nm *nodemap.NodeMap,
) (*PresetConfigCheckResponse, error) {
	Logger.Info("CheckPresetConfig called",
		zap.String("device_name", request.DeviceName))

	if request.PresetConfig == nil {
		return nil, fmt.Errorf("preset_config is required")
	}

	// 获取或创建 NodeMap
	if nm == nil {
		var nodemapId uint = 0
		nm, _ = nodemap.NewNodeMapFromNetwork(mnm.MNM.Name, deviceConfigs, true, 123456, &nodemapId)
		if nm == nil {
			return nil, fmt.Errorf("failed to create NodeMap")
		}
		nm.WithLogger(Logger)
	}

	// 获取防火墙节点
	node := nm.GetNode(request.DeviceName)
	if node == nil {
		return nil, fmt.Errorf("device node '%s' not found", request.DeviceName)
	}

	// 检查节点是否为防火墙节点并实现了 BlacklistWhitelistHandler 接口
	fwNode, ok := node.(firewall.FirewallNode)
	if !ok {
		return nil, fmt.Errorf("node '%s' is not a firewall node", request.DeviceName)
	}

	handler, ok := fwNode.(firewall.BlacklistWhitelistHandler)
	if !ok {
		return nil, fmt.Errorf("firewall node '%s' does not implement BlacklistWhitelistHandler", request.DeviceName)
	}

	// 转换 PresetConfig 类型
	presetConfig := &firewall.PresetConfig{
		BlacklistPolicyName: request.PresetConfig.BlacklistPolicyName,
		BlacklistPolicyID:   request.PresetConfig.BlacklistPolicyID,
		WhitelistPolicyName: request.PresetConfig.WhitelistPolicyName,
		WhitelistPolicyID:   request.PresetConfig.WhitelistPolicyID,
		BlacklistGroupName:  request.PresetConfig.BlacklistGroupName,
		WhitelistGroupName:  request.PresetConfig.WhitelistGroupName,
	}

	// 调用 handler 检查预设配置
	checkResult, err := handler.CheckPresetConfig(presetConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to check preset config: %w", err)
	}

	// 构建响应
	response := &PresetConfigCheckResponse{
		Success: checkResult.BlacklistPolicyOK && checkResult.WhitelistPolicyOK &&
			checkResult.BlacklistGroupOK && checkResult.WhitelistGroupOK,
		DeviceName:        request.DeviceName,
		BlacklistPolicyOK: checkResult.BlacklistPolicyOK,
		WhitelistPolicyOK: checkResult.WhitelistPolicyOK,
		BlacklistGroupOK:  checkResult.BlacklistGroupOK,
		WhitelistGroupOK:  checkResult.WhitelistGroupOK,
		Details:           checkResult.Details,
	}

	// 生成消息
	if response.Success {
		response.Message = "All preset configurations are ready"
	} else {
		var missing []string
		if !checkResult.BlacklistPolicyOK {
			missing = append(missing, "blacklist policy")
		}
		if !checkResult.WhitelistPolicyOK {
			missing = append(missing, "whitelist policy")
		}
		if !checkResult.BlacklistGroupOK {
			missing = append(missing, "blacklist group")
		}
		if !checkResult.WhitelistGroupOK {
			missing = append(missing, "whitelist group")
		}
		response.Message = fmt.Sprintf("Missing preset configurations: %v", missing)
	}

	return response, nil
}
