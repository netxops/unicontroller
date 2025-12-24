package controller

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/pelletier/go-toml/v2"
)

type TelegrafConfigGenerator struct {
	TemplateService *PluginTemplateService
	BaseConfigPath  string
}

func ProvideTelegrafConfigGenerator(templateService *PluginTemplateService, config *Config) (*TelegrafConfigGenerator, error) {
	return &TelegrafConfigGenerator{
		TemplateService: templateService,
		BaseConfigPath:  "", // 可以从配置中读取
	}, nil
}

// TelegrafConfigStruct 表示 telegraf 配置结构（内部使用）
type TelegrafConfigStruct struct {
	GlobalTags map[string]string                   `toml:"global_tags,omitempty"`
	Agent      *AgentConfigStruct                  `toml:"agent,omitempty"`
	Inputs     map[string][]map[string]interface{} `toml:"inputs,omitempty"`
	Outputs    map[string][]map[string]interface{} `toml:"outputs,omitempty"`
}

// AgentConfigStruct 表示 agent 配置（内部使用）
type AgentConfigStruct struct {
	Interval          string `toml:"interval,omitempty"`
	RoundInterval     bool   `toml:"round_interval,omitempty"`
	MetricBatchSize   int    `toml:"metric_batch_size,omitempty"`
	MetricBufferLimit int    `toml:"metric_buffer_limit,omitempty"`
	CollectionJitter  string `toml:"collection_jitter,omitempty"`
	FlushInterval     string `toml:"flush_interval,omitempty"`
	FlushJitter       string `toml:"flush_jitter,omitempty"`
	Precision         string `toml:"precision,omitempty"`
	Hostname          string `toml:"hostname,omitempty"`
	OmitHostname      bool   `toml:"omit_hostname,omitempty"`
}

// GenerateConfig 生成完整的 telegraf 配置
func (tcg *TelegrafConfigGenerator) GenerateConfig(ctx context.Context, tasks []*models.MonitoringTask, standalonePlugins []*models.PluginConfig) (string, error) {
	// 1. 加载基础配置
	baseConfig, err := tcg.loadBaseConfig()
	if err != nil {
		return "", fmt.Errorf("failed to load base config: %w", err)
	}

	// 2. 合并任务配置
	for _, task := range tasks {
		if task.Status != models.TaskStatusActive {
			continue
		}

		for _, plugin := range task.Plugins {
			if !plugin.Enabled {
				continue
			}

			pluginConfig, err := tcg.generatePluginConfig(ctx, &plugin)
			if err != nil {
				return "", fmt.Errorf("failed to generate config for plugin %s: %w", plugin.ID, err)
			}

			baseConfig = tcg.mergePluginConfig(baseConfig, plugin.Type, pluginConfig, plugin.Priority)
		}
	}

	// 3. 合并独立插件配置
	for _, plugin := range standalonePlugins {
		if !plugin.Enabled {
			continue
		}

		pluginConfig, err := tcg.generatePluginConfig(ctx, plugin)
		if err != nil {
			return "", fmt.Errorf("failed to generate config for plugin %s: %w", plugin.ID, err)
		}

		baseConfig = tcg.mergePluginConfig(baseConfig, plugin.Type, pluginConfig, plugin.Priority)
	}

	// 4. 转换为 TOML 字符串
	tomlBytes, err := tcg.configToTOML(baseConfig)
	if err != nil {
		return "", fmt.Errorf("failed to convert config to TOML: %w", err)
	}

	return string(tomlBytes), nil
}

// loadBaseConfig 加载基础配置
func (tcg *TelegrafConfigGenerator) loadBaseConfig() (map[string]interface{}, error) {
	// 如果指定了基础配置文件路径，从文件加载
	if tcg.BaseConfigPath != "" {
		content, err := ioutil.ReadFile(tcg.BaseConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read base config file: %w", err)
		}

		var config map[string]interface{}
		if err := toml.Unmarshal(content, &config); err != nil {
			return nil, fmt.Errorf("failed to parse base config: %w", err)
		}

		return config, nil
	}

	// 否则返回默认配置
	return tcg.getDefaultBaseConfig(), nil
}

// getDefaultBaseConfig 获取默认基础配置
func (tcg *TelegrafConfigGenerator) getDefaultBaseConfig() map[string]interface{} {
	return map[string]interface{}{
		"agent": map[string]interface{}{
			"interval":            "10s",
			"round_interval":      true,
			"metric_batch_size":   1000,
			"metric_buffer_limit": 10000,
			"collection_jitter":   "0s",
			"flush_interval":      "10s",
			"flush_jitter":        "0s",
			"precision":           "0s",
			"hostname":            "",
			"omit_hostname":       false,
		},
		"outputs": map[string]interface{}{
			"prometheus_client": []map[string]interface{}{
				{
					"listen": ":9273",
				},
			},
		},
	}
}

// generatePluginConfig 生成插件配置
func (tcg *TelegrafConfigGenerator) generatePluginConfig(ctx context.Context, plugin *models.PluginConfig) (map[string]interface{}, error) {
	var configStr string
	var err error

	// 如果使用了模板，先渲染模板
	if plugin.TemplateID != "" {
		configStr, err = tcg.TemplateService.RenderTemplate(ctx, plugin.TemplateID, plugin.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to render template: %w", err)
		}
	} else {
		// 直接使用配置，转换为 TOML 字符串
		configStr, err = tcg.configMapToTOMLString(plugin.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to convert config to TOML: %w", err)
		}
	}

	// 解析 TOML 字符串为 map
	var config map[string]interface{}
	if err := toml.Unmarshal([]byte(configStr), &config); err != nil {
		return nil, fmt.Errorf("failed to parse plugin config: %w", err)
	}

	// 应用配置覆盖（plugin.Config 中的值覆盖模板渲染的结果）
	if plugin.Config != nil && len(plugin.Config) > 0 {
		config = tcg.mergeConfigMaps(config, plugin.Config)
	}

	return config, nil
}

// mergePluginConfig 合并插件配置到主配置
func (tcg *TelegrafConfigGenerator) mergePluginConfig(baseConfig map[string]interface{}, pluginType string, pluginConfig map[string]interface{}, priority int) map[string]interface{} {
	// 解析插件类型（如 "inputs.cpu" -> "inputs", "cpu"）
	parts := strings.SplitN(pluginType, ".", 2)
	if len(parts) != 2 {
		return baseConfig
	}

	section := parts[0]    // inputs 或 outputs
	pluginName := parts[1] // cpu, snmp 等

	// 确保 section 存在
	if baseConfig[section] == nil {
		baseConfig[section] = make(map[string]interface{})
	}

	sectionMap, ok := baseConfig[section].(map[string]interface{})
	if !ok {
		sectionMap = make(map[string]interface{})
		baseConfig[section] = sectionMap
	}

	// 确保插件数组存在
	if sectionMap[pluginName] == nil {
		sectionMap[pluginName] = []map[string]interface{}{}
	}

	pluginArray, ok := sectionMap[pluginName].([]map[string]interface{})
	if !ok {
		// 如果不是数组，尝试转换
		if singleConfig, ok := sectionMap[pluginName].(map[string]interface{}); ok {
			pluginArray = []map[string]interface{}{singleConfig}
		} else {
			pluginArray = []map[string]interface{}{}
		}
	}

	// 添加新配置（根据优先级决定是追加还是替换）
	if priority > 0 {
		// 高优先级：添加到数组开头
		pluginArray = append([]map[string]interface{}{pluginConfig}, pluginArray...)
	} else {
		// 普通优先级：追加到数组末尾
		pluginArray = append(pluginArray, pluginConfig)
	}

	sectionMap[pluginName] = pluginArray
	baseConfig[section] = sectionMap

	return baseConfig
}

// mergeConfigMaps 合并两个配置 map
func (tcg *TelegrafConfigGenerator) mergeConfigMaps(base, override map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// 复制 base
	for k, v := range base {
		result[k] = v
	}

	// 应用 override
	for k, v := range override {
		if existing, ok := result[k]; ok {
			// 如果都是 map，递归合并
			if baseMap, ok1 := existing.(map[string]interface{}); ok1 {
				if overrideMap, ok2 := v.(map[string]interface{}); ok2 {
					result[k] = tcg.mergeConfigMaps(baseMap, overrideMap)
					continue
				}
			}
		}
		// 否则直接覆盖
		result[k] = v
	}

	return result
}

// configToTOML 将配置转换为 TOML 格式
func (tcg *TelegrafConfigGenerator) configToTOML(config map[string]interface{}) ([]byte, error) {
	// 使用 go-toml 库进行转换
	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	encoder.SetIndentTables(true)
	encoder.SetArraysMultiline(true)

	if err := encoder.Encode(config); err != nil {
		return nil, fmt.Errorf("failed to encode config to TOML: %w", err)
	}

	return buf.Bytes(), nil
}

// configMapToTOMLString 将配置 map 转换为 TOML 字符串
func (tcg *TelegrafConfigGenerator) configMapToTOMLString(config map[string]interface{}) (string, error) {
	// 构建插件配置的 TOML 字符串
	// 这里我们假设配置是一个插件配置块
	var buf strings.Builder

	// 对于简单的配置，直接构建 TOML
	for key, value := range config {
		buf.WriteString(fmt.Sprintf("  %s = ", key))
		tcg.writeTOMLValue(&buf, value)
		buf.WriteString("\n")
	}

	return buf.String(), nil
}

// writeTOMLValue 写入 TOML 值
func (tcg *TelegrafConfigGenerator) writeTOMLValue(buf *strings.Builder, value interface{}) {
	switch v := value.(type) {
	case string:
		buf.WriteString(fmt.Sprintf(`"%s"`, strings.ReplaceAll(v, `"`, `\"`)))
	case int, int32, int64:
		buf.WriteString(fmt.Sprintf("%v", v))
	case float32, float64:
		buf.WriteString(fmt.Sprintf("%v", v))
	case bool:
		buf.WriteString(fmt.Sprintf("%v", v))
	case []interface{}:
		buf.WriteString("[")
		for i, item := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			tcg.writeTOMLValue(buf, item)
		}
		buf.WriteString("]")
	case map[string]interface{}:
		buf.WriteString("{\n")
		// 对键进行排序以保持一致性
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			buf.WriteString(fmt.Sprintf("    %s = ", k))
			tcg.writeTOMLValue(buf, v[k])
			buf.WriteString("\n")
		}
		buf.WriteString("  }")
	default:
		buf.WriteString(fmt.Sprintf("%v", v))
	}
}

// ValidateConfig 验证配置有效性
func (tcg *TelegrafConfigGenerator) ValidateConfig(configStr string) error {
	var config map[string]interface{}
	if err := toml.Unmarshal([]byte(configStr), &config); err != nil {
		return fmt.Errorf("invalid TOML format: %w", err)
	}

	// 这里可以添加更多的验证逻辑
	// 例如检查必需的字段、字段类型等

	return nil
}

// GeneratePluginConfigFromTemplate 从模板生成插件配置
func (tcg *TelegrafConfigGenerator) GeneratePluginConfigFromTemplate(ctx context.Context, templateID string, params map[string]interface{}) (string, error) {
	return tcg.TemplateService.RenderTemplate(ctx, templateID, params)
}

// GeneratePluginConfigFromRaw 从原始配置生成插件配置
func (tcg *TelegrafConfigGenerator) GeneratePluginConfigFromRaw(config map[string]interface{}) (string, error) {
	return tcg.configMapToTOMLString(config)
}
