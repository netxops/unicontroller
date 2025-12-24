package parser

import (
	"regexp"
	"strings"
)

type Template struct {
	Name   string
	Fields []string
	Rules  []Rule
}

type Rule struct {
	Pattern *regexp.Regexp
	Actions []string
}

type ParseResult struct {
	Records []map[string]string
}

func ParseWithTemplate(input string, template Template) (ParseResult, error) {
	var result ParseResult
	lines := strings.Split(input, "\n")
	currentRecord := make(map[string]string)

	for _, line := range lines {
		for _, rule := range template.Rules {
			if matches := rule.Pattern.FindStringSubmatch(line); matches != nil {
				for i, action := range rule.Actions {
					if action == "Record" {
						if len(currentRecord) > 0 {
							result.Records = append(result.Records, currentRecord)
							currentRecord = make(map[string]string)
						}
					} else if i < len(matches)-1 {
						currentRecord[action] = matches[i+1]
					}
				}
				break
			}
		}
	}

	if len(currentRecord) > 0 {
		result.Records = append(result.Records, currentRecord)
	}

	return result, nil
}
