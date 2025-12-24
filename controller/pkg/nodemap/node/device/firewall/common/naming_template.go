package common

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
)

type IDTemplate struct {
	template          string
	fields            map[string]*Field
	sequence          map[string]int
	lastDates         map[string]time.Time // 新增：跟踪每个日期字段的最后日期
	maxRetries        int
	customValidator   func(string) bool
	customIDExtractor func(string) int
	getIterator       func() firewall.NamerIterator
	currentTime       time.Time
}

type Field struct {
	Type     string
	Format   string
	Width    int
	Start    int
	Step     int
	IsMainID bool
	NoRender bool
}

func NewPolicyTemplate(template string, getIterator func() firewall.NamerIterator) *IDTemplate {
	pt := &IDTemplate{
		template:    template,
		fields:      make(map[string]*Field),
		sequence:    make(map[string]int),
		lastDates:   make(map[string]time.Time),
		getIterator: getIterator,
	}
	pt.parseTemplate()
	return pt
}

func (pt *IDTemplate) WithCurrentTime(t time.Time) *IDTemplate {
	pt.currentTime = t
	return pt
}

func (pt *IDTemplate) WithLastDate(name string, t time.Time) *IDTemplate {
	// pt.currentTime = t
	pt.lastDates[name] = t
	return pt
}

func (pt *IDTemplate) Initialize() *IDTemplate {
	iterator := pt.getIterator()
	pt.sequence = make(map[string]int)
	pt.lastDates = make(map[string]time.Time)
	dateSeq := make(map[string]map[string]int)

	for iterator.HasNext() {
		policy := iterator.Next()
		info, err := pt.Extract(policy.Name())
		if err != nil {
			continue
		}

		for key, value := range info {
			if field, ok := pt.fields[key]; ok {
				switch field.Type {
				case "SEQ":
					if seq, err := strconv.Atoi(value); err == nil {
						dateKey := pt.getDateKeyForSeq(key, info)
						if dateKey != "" {
							if _, ok := dateSeq[dateKey]; !ok {
								dateSeq[dateKey] = make(map[string]int)
							}
							if seq > dateSeq[dateKey][key] {
								dateSeq[dateKey][key] = seq
							}
						}
					}
				case "DATE":
					if date, err := time.Parse(pt.convertDateFormat(field.Format), value); err == nil {
						if date.After(pt.lastDates[key]) {
							pt.lastDates[key] = date
						}
					}
				}
			}
		}
	}

	// 使用最新日期的序列号
	latestDateKey := pt.getLatestDateKey()
	for key, field := range pt.fields {
		if field.Type == "SEQ" {
			if latestDateKey != "" && dateSeq[latestDateKey] != nil {
				pt.sequence[key] = dateSeq[latestDateKey][key]
			}
			if pt.sequence[key] == 0 {
				pt.sequence[key] = field.Start - field.Step
			}
		}
	}

	return pt
}

func (pt *IDTemplate) getDateKeyForSeq(seqKey string, info map[string]string) string {
	for dateKey, field := range pt.fields {
		if field.Type == "DATE" {
			return info[dateKey]
		}
	}
	return ""
}

func (pt *IDTemplate) getLatestDateKey() string {
	var latestKey string
	var latestDate time.Time
	for key, date := range pt.lastDates {
		if date.After(latestDate) {
			latestDate = date
			latestKey = key
		}
	}
	return latestKey
}

func (pt *IDTemplate) WithMaxRetries(maxRetries int) *IDTemplate {
	pt.maxRetries = maxRetries
	return pt
}

func (pt *IDTemplate) WithCustomValidator(validator func(string) bool) *IDTemplate {
	pt.customValidator = validator
	return pt
}

func (pt *IDTemplate) WithCustomIDExtractor(extractor func(string) int) *IDTemplate {
	pt.customIDExtractor = extractor
	return pt
}

func (pt *IDTemplate) parseTemplate() {
	varRegex := regexp.MustCompile(`\{VAR:([^}]+)\}`)
	dateRegex := regexp.MustCompile(`\{DATE:([^:}]+):([^}]+)\}`)
	seqRegex := regexp.MustCompile(`\{SEQ:([^:}]+):(\d+):(\d+):(\d+)(:MAIN)?(:NORENDER)?\}`)

	for _, regex := range []*regexp.Regexp{varRegex, dateRegex, seqRegex} {
		matches := regex.FindAllStringSubmatch(pt.template, -1)
		for _, match := range matches {
			name := match[1]
			field := &Field{}

			switch regex {
			case varRegex:
				field.Type = "VAR"
			case dateRegex:
				field.Type = "DATE"
				field.Format = match[2]
			case seqRegex:
				field.Type = "SEQ"
				field.Width, _ = strconv.Atoi(match[2])
				field.Start, _ = strconv.Atoi(match[3])
				field.Step, _ = strconv.Atoi(match[4])
				field.IsMainID = len(match) > 5 && strings.Contains(match[0], ":MAIN")
				field.NoRender = len(match) > 6 && strings.Contains(match[0], ":NORENDER")
			}

			pt.fields[name] = field
		}
	}
}

func (pt *IDTemplate) Generate(variables map[string]interface{}) (int, string) {
	result := pt.template
	currentTime := pt.currentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	dateChanged := false
	var mainID int

	for name, field := range pt.fields {
		var value string
		switch field.Type {
		case "VAR":
			if v, ok := variables[name]; ok {
				value = fmt.Sprintf("%v", v)
			}
		case "DATE":
			value = currentTime.Format(pt.convertDateFormat(field.Format))
			lastDate, exists := pt.lastDates[name]
			if !exists || !isSameDate(currentTime, lastDate) {
				dateChanged = true
				pt.lastDates[name] = currentTime
			}
		case "SEQ":
			if dateChanged {
				pt.sequence[name] = field.Start
			} else if _, exists := pt.sequence[name]; !exists {
				pt.sequence[name] = field.Start
			} else {
				pt.sequence[name] += field.Step
			}
			value = fmt.Sprintf("%0*d", field.Width, pt.sequence[name])
			if field.IsMainID {
				mainID = pt.sequence[name]
			}
		}
		placeholder := pt.getFieldPlaceholder(name, field)
		result = strings.Replace(result, placeholder, value, 1)
	}

	// 移除所有未替换的占位符
	result = regexp.MustCompile(`\{(VAR|DATE|SEQ):[^}]+\}`).ReplaceAllString(result, "")

	// 清理可能产生的多余下划线
	result = strings.Trim(result, "_")
	result = strings.ReplaceAll(result, "__", "_")

	return mainID, result
}

func isSameDate(t1, t2 time.Time) bool {
	y1, m1, d1 := t1.Date()
	y2, m2, d2 := t2.Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

func (pt *IDTemplate) getFieldPlaceholder(name string, field *Field) string {
	switch field.Type {
	case "VAR":
		return fmt.Sprintf("{VAR:%s}", name)
	case "DATE":
		return fmt.Sprintf("{DATE:%s:%s}", name, field.Format)
	case "SEQ":
		mainTag := ""
		if field.IsMainID {
			mainTag = ":MAIN"
		}
		return fmt.Sprintf("{SEQ:%s:%d:%d:%d%s}", name, field.Width, field.Start, field.Step, mainTag)
	}
	return ""
}

func (pt *IDTemplate) convertDateFormat(format string) string {
	format = strings.Replace(format, "YYYY", "2006", 1)
	format = strings.Replace(format, "MM", "01", 1)
	format = strings.Replace(format, "DD", "02", 1)
	return format
}

func (pt *IDTemplate) Extract(policy string) (map[string]string, error) {
	regex := pt.templateToRegex()
	re := regexp.MustCompile(regex)
	match := re.FindStringSubmatch(policy)

	if len(match) < 2 {
		return nil, fmt.Errorf("policy does not match the template")
	}

	result := make(map[string]string)
	dateChanged := false

	for i, name := range re.SubexpNames()[1:] {
		if name == "" {
			continue
		}
		result[name] = match[i+1]

		if field, ok := pt.fields[name]; ok {
			switch field.Type {
			case "DATE":
				dateFormat := pt.convertDateFormat(field.Format)
				date, err := time.Parse(dateFormat, match[i+1])
				if err != nil {
					fmt.Printf("解析日期失败: %v\n", err)
				} else if !pt.lastDates[name].Equal(date) {
					dateChanged = true
					pt.lastDates[name] = date
					fmt.Printf("更新字段 %s 的最新日期为: %v\n", name, date)
				}
			case "SEQ":
				if !field.NoRender {
					var currentSeq int
					if pt.customIDExtractor != nil {
						currentSeq = pt.customIDExtractor(match[i+1])
					} else {
						currentSeq, _ = strconv.Atoi(match[i+1])
					}
					if dateChanged {
						pt.sequence[name] = field.Start
						fmt.Printf("日期变化，重置字段 %s 的序列号为起始值: %d\n", name, field.Start)
					}
					if currentSeq > pt.sequence[name] {
						pt.sequence[name] = currentSeq
						// fmt.Printf("更新字段 %s 的最大序列号为: %d\n", name, currentSeq)
					}
				}
			}
		}
	}

	return result, nil
}

func (pt *IDTemplate) SetLastSequence(name string, value int) {
	pt.sequence[name] = value
}

func (pt *IDTemplate) GetLastSequence(name string) int {
	return pt.sequence[name]
}

func (pt *IDTemplate) templateToRegex() string {
	regex := pt.template
	for name, field := range pt.fields {
		var placeholder string
		if field.Type == "SEQ" {
			mainTag := ""
			if field.IsMainID {
				mainTag = ":MAIN"
			}
			noRenderTag := ""
			if field.NoRender {
				noRenderTag = ":NORENDER"
			}
			placeholder = fmt.Sprintf("{SEQ:%s:%d:%d:%d%s%s}", name, field.Width, field.Start, field.Step, mainTag, noRenderTag)
		} else {
			placeholder = pt.getFieldPlaceholder(name, field)
		}

		var replacement string
		switch field.Type {
		case "VAR":
			replacement = fmt.Sprintf("(?P<%s>[^_]+)", name)
		case "DATE":
			replacement = fmt.Sprintf("(?P<%s>\\d+)", name)
		case "SEQ":
			if field.NoRender {
				// 对于 NORENDER 字段，我们直接从模板中移除整个占位符
				regex = strings.Replace(regex, placeholder, "", 1)
				continue // 跳过当前循环，不进行后续的替换
			} else {
				replacement = fmt.Sprintf("(?P<%s>\\d{%d})", name, field.Width)
			}
		}
		regex = strings.Replace(regex, placeholder, replacement, 1)
	}
	// 清理可能产生的多余下划线
	regex = strings.Trim(regex, "_")
	regex = strings.ReplaceAll(regex, "__", "_")
	return "^" + regex + "$"
}
