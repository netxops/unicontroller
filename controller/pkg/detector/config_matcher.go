package detector

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	ps "github.com/netxops/netlink/service"
	"github.com/netxops/netlink/structs"
	"gopkg.in/yaml.v2"
)

// ConfigMatcher 配置匹配器
type ConfigMatcher struct {
	templatePath    string
	pipelineService *ps.PipelineService
	config          *ConfigMatcherConfig
}

// NewConfigMatcher 创建配置匹配器
func NewConfigMatcher(templatePath string, pipelineService *ps.PipelineService) (*ConfigMatcher, error) {
	matcher := &ConfigMatcher{
		templatePath:    templatePath,
		pipelineService: pipelineService,
	}

	// 加载配置匹配策略
	if err := matcher.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config matcher config: %w", err)
	}

	return matcher, nil
}

// loadConfig 加载配置匹配器配置
func (cm *ConfigMatcher) loadConfig() error {
	filePath := filepath.Join(cm.templatePath, "detect/config_matcher.yaml")
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		// 如果配置文件不存在，使用默认配置
		cm.config = cm.getDefaultConfig()
		return nil
	}

	var config ConfigMatcherConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config matcher config: %w", err)
	}

	cm.config = &config
	return nil
}

// getDefaultConfig 获取默认配置
func (cm *ConfigMatcher) getDefaultConfig() *ConfigMatcherConfig {
	return &ConfigMatcherConfig{
		Strategies: []MatchingStrategy{
			{
				Name:     "exactMatch",
				Priority: 1,
				Match: MatchConfig{
					Manufacturer: "exact",
					Platform:     "exact",
					Version:      "exact",
				},
				PathTemplate: "{manufacturer}/{platform}/v{version}/config.yaml",
				Fallback: []FallbackPath{
					{PathTemplate: "{manufacturer}/{platform}/base/config.yaml"},
					{PathTemplate: "{manufacturer}/{platform}/config.yaml"},
				},
			},
			{
				Name:     "platformMatch",
				Priority: 2,
				Match: MatchConfig{
					Manufacturer: "exact",
					Platform:     "exact",
					Version:      "any",
				},
				PathTemplate: "{manufacturer}/{platform}/config.yaml",
			},
			{
				Name:     "manufacturerMatch",
				Priority: 3,
				Match: MatchConfig{
					Manufacturer: "exact",
					Platform:     "default",
					Version:      "any",
				},
				DefaultPlatforms: map[string]string{
					"Cisco":   "IOS",
					"Huawei":  "VRP",
					"H3C":     "Comware",
					"Dell":    "Ubuntu",
					"Dptech":  "FWNFV",
					"Sangfor": "SangforOS",
					"Ruijie":  "Ruijie",
					"server":  "base_linux",
				},
			},
		},
		DefaultConfigs: map[string]string{
			"NETWORK":  "network/default/config.yaml",
			"SERVER":   "server/default/config.yaml",
			"FIREWALL": "firewall/default/config.yaml",
			"SWITCH":   "switch/default/config.yaml",
		},
	}
}

// Match 匹配设备配置
func (cm *ConfigMatcher) Match(manufacturer, platform, version, catalog string) (*structs.DeviceConfig, error) {
	attributes := make(map[string]string)

	// 按优先级尝试各个匹配策略
	for _, strategy := range cm.config.Strategies {
		config, err := cm.tryStrategy(strategy, manufacturer, platform, version, catalog, attributes)
		if err == nil && config != nil {
			return config, nil
		}
	}

	// 如果所有策略都失败，尝试使用分类默认配置
	if catalog != "" {
		if _, exists := cm.config.DefaultConfigs[catalog]; exists {
			// 这里可以尝试加载默认配置
			// 但通常应该返回错误，让调用者处理
		}
	}

	return nil, fmt.Errorf("no matching device config found for manufacturer=%s, platform=%s, version=%s", manufacturer, platform, version)
}

// tryStrategy 尝试匹配策略
func (cm *ConfigMatcher) tryStrategy(strategy MatchingStrategy, manufacturer, platform, version, catalog string, attributes map[string]string) (*structs.DeviceConfig, error) {
	var targetManufacturer, targetPlatform, targetVersion string

	// 根据策略确定目标值
	switch strategy.Match.Manufacturer {
	case "exact":
		targetManufacturer = manufacturer
	case "default":
		if catalog != "" {
			if catalogDefault, exists := strategy.CatalogDefaults[catalog]; exists {
				targetManufacturer = catalogDefault.Manufacturer
			}
		}
	}

	switch strategy.Match.Platform {
	case "exact":
		targetPlatform = platform
	case "default":
		if targetManufacturer != "" {
			if defaultPlatform, exists := strategy.DefaultPlatforms[targetManufacturer]; exists {
				targetPlatform = defaultPlatform
			}
		}
	}

	switch strategy.Match.Version {
	case "exact":
		targetVersion = version
	case "any":
		targetVersion = ""
	}

	// 如果目标值不完整，跳过此策略
	if targetManufacturer == "" || targetPlatform == "" {
		return nil, fmt.Errorf("incomplete target values")
	}

	// 尝试精确匹配
	config, err := cm.pipelineService.GetDeviceConfig(targetManufacturer, targetPlatform, targetVersion, attributes)
	if err == nil && config != nil {
		return config, nil
	}

	// 尝试fallback路径
	for range strategy.Fallback {
		// 这里可以尝试解析fallback路径并加载配置
		// 但通常PipelineService已经处理了版本匹配的fallback
	}

	return nil, fmt.Errorf("strategy %s failed", strategy.Name)
}
