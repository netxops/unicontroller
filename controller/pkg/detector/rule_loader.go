package detector

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v2"
)

// RuleLoader 规则加载器
type RuleLoader struct {
	templatePath string
	rules        []DetectionRule
}

// NewRuleLoader 创建规则加载器
func NewRuleLoader(templatePath string) (*RuleLoader, error) {
	loader := &RuleLoader{
		templatePath: templatePath,
		rules:        []DetectionRule{},
	}

	if err := loader.LoadRules(); err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	return loader, nil
}

// LoadRules 加载所有规则
func (rl *RuleLoader) LoadRules() error {
	// 加载厂商规则
	manufacturerRules, err := rl.loadRuleFile("detect/rules/manufacturer_rules.yaml")
	if err != nil {
		return fmt.Errorf("failed to load manufacturer rules: %w", err)
	}

	// 加载平台规则
	platformRules, err := rl.loadRuleFile("detect/rules/platform_rules.yaml")
	if err != nil {
		return fmt.Errorf("failed to load platform rules: %w", err)
	}

	// 合并规则
	rl.rules = append(rl.rules, manufacturerRules...)
	rl.rules = append(rl.rules, platformRules...)

	// 按优先级排序
	sort.Slice(rl.rules, func(i, j int) bool {
		if rl.rules[i].Priority != rl.rules[j].Priority {
			return rl.rules[i].Priority > rl.rules[j].Priority
		}
		return rl.rules[i].Name < rl.rules[j].Name
	})

	return nil
}

// loadRuleFile 加载规则文件
func (rl *RuleLoader) loadRuleFile(relativePath string) ([]DetectionRule, error) {
	filePath := filepath.Join(rl.templatePath, relativePath)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file %s: %w", filePath, err)
	}

	var config struct {
		Rules []DetectionRule `yaml:"rules"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule file %s: %w", filePath, err)
	}

	return config.Rules, nil
}

// GetRules 获取所有规则
func (rl *RuleLoader) GetRules() []DetectionRule {
	return rl.rules
}

// MatchRules 匹配规则
func (rl *RuleLoader) MatchRules(collectedData CollectedData) (*DetectionResult, error) {
	var candidates []DetectionRule

	log.Printf("Matching rules against collected data. Available data fields: %v", getDataFields(collectedData))
	log.Printf("Total rules to check: %d", len(rl.rules))

	// 1. 初步匹配：找出所有可能匹配的规则
	for i, rule := range rl.rules {
		score := 0.0
		matched := true
		matchedPatterns := 0
		failedPatterns := []string{}

		for _, pattern := range rule.Patterns {
			data, exists := collectedData[pattern.Source]
			if !exists && pattern.Required {
				matched = false
				failedPatterns = append(failedPatterns, fmt.Sprintf("%s (required, not found)", pattern.Source))
				break
			}

			if exists && data != "" {
				// 正则匹配
				regexMatched, err := matchRegex(pattern.Regex, data)
				if err == nil && regexMatched {
					score += pattern.Confidence
					matchedPatterns++
					log.Printf("Rule %s: Pattern matched for source %s (regex: %s)", rule.Name, pattern.Source, pattern.Regex)
				} else {
					if pattern.Required {
						matched = false
						failedPatterns = append(failedPatterns, fmt.Sprintf("%s (required, regex not matched: %s)", pattern.Source, pattern.Regex))
						break
					} else {
						if err != nil {
							log.Printf("Rule %s: Regex error for source %s: %v", rule.Name, pattern.Source, err)
						}
					}
				}
			} else if exists && data == "" {
				log.Printf("Rule %s: Source %s exists but is empty", rule.Name, pattern.Source)
			}
		}

		if matched && matchedPatterns > 0 {
			rule.Score = score
			candidates = append(candidates, rule)
			log.Printf("Rule %s matched with score %.2f (matched %d patterns)", rule.Name, score, matchedPatterns)
		} else {
			if len(failedPatterns) > 0 {
				log.Printf("Rule %s did not match. Failed patterns: %v", rule.Name, failedPatterns)
			} else if matchedPatterns == 0 {
				log.Printf("Rule %s did not match. No patterns matched (checked %d patterns)", rule.Name, len(rule.Patterns))
			}
		}

		// 只检查前20个规则，避免日志过多
		if i >= 20 {
			break
		}
	}

	if len(candidates) == 0 {
		log.Printf("No matching rules found. Collected data summary:")
		for key, value := range collectedData {
			preview := value
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			log.Printf("  %s: %s", key, preview)
		}
		return nil, fmt.Errorf("no matching rule found")
	}

	// 2. 按优先级和置信度排序
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		return candidates[i].Score > candidates[j].Score
	})

	// 3. 返回最佳匹配
	best := candidates[0]
	result := &DetectionResult{
		Manufacturer: best.Manufacturer,
		Platform:     best.Platform,
		Catalog:      best.Catalog,
		Confidence:   best.Score,
		DetectedAt:   getCurrentTime(),
	}

	// 版本提取已移到detector.go中使用VersionExtractor模块
	// 这里保留空版本，由detector统一处理

	return result, nil
}

// GetMatchedRule 获取匹配的规则（用于版本提取）
func (rl *RuleLoader) GetMatchedRule(collectedData CollectedData) *DetectionRule {
	var candidates []DetectionRule

	// 1. 初步匹配：找出所有可能匹配的规则
	for _, rule := range rl.rules {
		score := 0.0
		matched := true
		matchedPatterns := 0

		for _, pattern := range rule.Patterns {
			data, exists := collectedData[pattern.Source]
			if !exists && pattern.Required {
				matched = false
				break
			}

			if exists && data != "" {
				// 正则匹配
				regexMatched, err := matchRegex(pattern.Regex, data)
				if err == nil && regexMatched {
					score += pattern.Confidence
					matchedPatterns++
				} else {
					if pattern.Required {
						matched = false
						break
					}
				}
			}
		}

		if matched && matchedPatterns > 0 {
			rule.Score = score
			candidates = append(candidates, rule)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// 2. 按优先级和置信度排序
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		return candidates[i].Score > candidates[j].Score
	})

	// 3. 返回最佳匹配
	return &candidates[0]
}

// matchRegex 正则匹配
func matchRegex(pattern, text string) (bool, error) {
	matched, err := regexp.MatchString(pattern, text)
	if err != nil {
		return false, err
	}
	return matched, nil
}

// getCurrentTime 获取当前时间
func getCurrentTime() time.Time {
	return time.Now()
}

// getDataFields 获取数据字段列表
func getDataFields(data CollectedData) []string {
	fields := make([]string, 0, len(data))
	for k := range data {
		fields = append(fields, k)
	}
	return fields
}
