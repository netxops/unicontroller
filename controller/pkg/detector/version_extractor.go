package detector

import (
	"log"
	"regexp"
)

// VersionExtractor 版本提取器
// MVP: 基于规则的版本提取模块
type VersionExtractor struct {
}

// NewVersionExtractor 创建版本提取器
func NewVersionExtractor() *VersionExtractor {
	return &VersionExtractor{}
}

// Extract 提取版本信息
// 基于规则中的versionExtract配置提取版本
func (ve *VersionExtractor) Extract(collectedData CollectedData, rule *DetectionRule) string {
	if rule.VersionExtract == nil {
		return ""
	}

	data, exists := collectedData[rule.VersionExtract.Source]
	if !exists || data == "" {
		return ""
	}

	// 使用正则表达式提取版本
	re, err := regexp.Compile(rule.VersionExtract.Regex)
	if err != nil {
		log.Printf("Failed to compile version extract regex: %v", err)
		return ""
	}

	matches := re.FindStringSubmatch(data)
	if len(matches) > 1 {
		// 优先返回完整版本格式（如 V500R005C00SPC100）
		// 正则表达式: V(\\d+R\\d+C\\d+S\\w+)|Version\\s+(\\S+)
		// matches[1] = 完整版本（不含V前缀），matches[2] = 简单版本
		if len(matches) > 1 && matches[1] != "" {
			// 返回完整版本，添加 "V" 前缀
			return "V" + matches[1]
		}
		// 如果没有完整版本，返回简单版本
		if len(matches) > 2 && matches[2] != "" {
			return matches[2]
		}
		// 如果只有第一个捕获组，直接返回
		if matches[1] != "" {
			return matches[1]
		}
	}

	return ""
}
