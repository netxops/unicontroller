package controller

import (
	"bytes"
	"fmt"
	"text/template"
)

// TemplateData 是一个通用的结构，用于存储模板数据
type TemplateData map[string]interface{}

// ConfigTemplate 是配置模板的主要结构
type ConfigTemplate struct {
	template *template.Template
}

// NewConfigTemplate 创建一个新的配置模板
func NewConfigTemplate(templateString string) (*ConfigTemplate, error) {
	tmpl, err := template.New("config").Parse(templateString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %v", err)
	}
	return &ConfigTemplate{template: tmpl}, nil
}

// Generate 根据提供的数据生成配置
func (ct *ConfigTemplate) Generate(data TemplateData) (string, error) {
	var buf bytes.Buffer
	err := ct.template.Execute(&buf, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %v", err)
	}
	return buf.String(), nil
}
