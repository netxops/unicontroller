package srx

import (
	"github.com/netxops/utils/text"
	"strings"
)

func parseSection(config, regex, name string) string {
	sectionRegexMap := map[string]string{
		"regex": regex,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
	if err != nil {
		// 如果解析出错，返回空字符串而不是panic
		// 这样可以允许某些配置类型不存在（例如服务对象CLI中可能没有地址对象）
		return ""
	}

	// 如果没有匹配，返回空字符串
	if sectionResult == nil || sectionResult.Len() == 0 {
		return ""
	}

	var sections []string
	for it := sectionResult.Iterator(); it.HasNext(); {
		_, _, sectionMap := it.Next()
		if sectionMap != nil {
			if val, ok := sectionMap[name]; ok {
				sections = append(sections, val)
			}
		}
	}

	return strings.Join(sections, "\n")

}
