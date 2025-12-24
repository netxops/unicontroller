package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PluginTemplateService struct {
	mongoClient *mongo.Client
	database    string
}

func ProvidePluginTemplateService(mongoClient *mongo.Client, config *Config) (*PluginTemplateService, error) {
	return &PluginTemplateService{
		mongoClient: mongoClient,
		database:    "controller",
	}, nil
}

// GetTemplate 获取插件模板
func (pts *PluginTemplateService) GetTemplate(ctx context.Context, templateID string) (*models.PluginTemplate, error) {
	if pts.mongoClient == nil {
		return nil, fmt.Errorf("MongoDB client not available")
	}

	collection := pts.mongoClient.Database(pts.database).Collection("plugin_templates")

	var tmpl models.PluginTemplate
	err := collection.FindOne(ctx, bson.M{"_id": templateID}).Decode(&tmpl)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("template %s not found", templateID)
		}
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	return &tmpl, nil
}

// ListTemplates 列出所有插件模板
func (pts *PluginTemplateService) ListTemplates(ctx context.Context, filter map[string]interface{}) ([]*models.PluginTemplate, error) {
	if pts.mongoClient == nil {
		return nil, fmt.Errorf("MongoDB client not available")
	}

	collection := pts.mongoClient.Database(pts.database).Collection("plugin_templates")

	bsonFilter := bson.M{}
	if filter != nil {
		for k, v := range filter {
			bsonFilter[k] = v
		}
	}

	cursor, err := collection.Find(ctx, bsonFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}
	defer cursor.Close(ctx)

	var templates []*models.PluginTemplate
	if err := cursor.All(ctx, &templates); err != nil {
		return nil, fmt.Errorf("failed to decode templates: %w", err)
	}

	return templates, nil
}

// CreateTemplate 创建插件模板
func (pts *PluginTemplateService) CreateTemplate(ctx context.Context, tmpl *models.PluginTemplate) error {
	if pts.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := pts.mongoClient.Database(pts.database).Collection("plugin_templates")

	// 验证模板语法
	if err := pts.ValidateTemplate(ctx, tmpl.Template); err != nil {
		return fmt.Errorf("invalid template syntax: %w", err)
	}

	// 设置创建时间
	if tmpl.CreatedAt.IsZero() {
		tmpl.CreatedAt = time.Now()
	}
	tmpl.UpdatedAt = time.Now()

	_, err := collection.InsertOne(ctx, tmpl)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("template %s already exists", tmpl.ID)
		}
		return fmt.Errorf("failed to create template: %w", err)
	}

	return nil
}

// UpdateTemplate 更新插件模板
func (pts *PluginTemplateService) UpdateTemplate(ctx context.Context, templateID string, tmpl *models.PluginTemplate) error {
	if pts.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := pts.mongoClient.Database(pts.database).Collection("plugin_templates")

	// 验证模板语法
	if err := pts.ValidateTemplate(ctx, tmpl.Template); err != nil {
		return fmt.Errorf("invalid template syntax: %w", err)
	}

	tmpl.ID = templateID
	tmpl.UpdatedAt = time.Now()

	filter := bson.M{"_id": templateID}
	update := bson.M{"$set": tmpl}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update template: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("template %s not found", templateID)
	}

	return nil
}

// DeleteTemplate 删除插件模板
func (pts *PluginTemplateService) DeleteTemplate(ctx context.Context, templateID string) error {
	if pts.mongoClient == nil {
		return fmt.Errorf("MongoDB client not available")
	}

	collection := pts.mongoClient.Database(pts.database).Collection("plugin_templates")

	result, err := collection.DeleteOne(ctx, bson.M{"_id": templateID})
	if err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("template %s not found", templateID)
	}

	return nil
}

// ValidateTemplate 验证模板语法
func (pts *PluginTemplateService) ValidateTemplate(ctx context.Context, templateContent string) error {
	_, err := template.New("validator").Parse(templateContent)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}
	return nil
}

// ValidateTemplateParameters 验证模板参数
func (pts *PluginTemplateService) ValidateTemplateParameters(ctx context.Context, templateID string, params map[string]interface{}) error {
	tmpl, err := pts.GetTemplate(ctx, templateID)
	if err != nil {
		return err
	}

	// 检查必需参数
	for _, param := range tmpl.Parameters {
		if param.Required {
			if _, ok := params[param.Name]; !ok {
				return fmt.Errorf("required parameter %s is missing", param.Name)
			}
		}
	}

	return nil
}

// RenderTemplate 渲染模板
func (pts *PluginTemplateService) RenderTemplate(ctx context.Context, templateID string, params map[string]interface{}) (string, error) {
	tmpl, err := pts.GetTemplate(ctx, templateID)
	if err != nil {
		return "", err
	}

	// 验证参数
	if err := pts.ValidateTemplateParameters(ctx, templateID, params); err != nil {
		return "", err
	}

	// 设置默认值
	for _, param := range tmpl.Parameters {
		if _, ok := params[param.Name]; !ok && param.Default != nil {
			params[param.Name] = param.Default
		}
	}

	// 解析模板
	parsedTmpl, err := template.New(tmpl.ID).Parse(tmpl.Template)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// 渲染模板
	var buf strings.Builder
	if err := parsedTmpl.Execute(&buf, params); err != nil {
		return "", fmt.Errorf("failed to render template: %w", err)
	}

	return buf.String(), nil
}

// RenderTemplateFromContent 直接从模板内容渲染（不存储）
func (pts *PluginTemplateService) RenderTemplateFromContent(ctx context.Context, templateContent string, params map[string]interface{}) (string, error) {
	// 验证模板语法
	if err := pts.ValidateTemplate(ctx, templateContent); err != nil {
		return "", err
	}

	// 解析模板
	parsedTmpl, err := template.New("inline").Parse(templateContent)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// 渲染模板
	var buf strings.Builder
	if err := parsedTmpl.Execute(&buf, params); err != nil {
		return "", fmt.Errorf("failed to render template: %w", err)
	}

	return buf.String(), nil
}

// GetTemplatesByType 根据插件类型获取模板列表
func (pts *PluginTemplateService) GetTemplatesByType(ctx context.Context, pluginType string) ([]*models.PluginTemplate, error) {
	return pts.ListTemplates(ctx, map[string]interface{}{
		"type": pluginType,
	})
}

// EnsureIndexes 创建索引
func (pts *PluginTemplateService) EnsureIndexes(ctx context.Context) error {
	if pts.mongoClient == nil {
		return nil
	}

	collection := pts.mongoClient.Database(pts.database).Collection("plugin_templates")

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "type", Value: 1}},
			Options: options.Index().SetName("idx_type"),
		},
		{
			Keys:    bson.D{{Key: "name", Value: 1}},
			Options: options.Index().SetName("idx_name"),
		},
		{
			Keys: bson.D{
				{Key: "type", Value: 1},
				{Key: "name", Value: 1},
			},
			Options: options.Index().SetUnique(true).SetName("idx_type_name_unique"),
		},
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

// PresetTemplates 预置常用插件模板
func (pts *PluginTemplateService) PresetTemplates(ctx context.Context) error {
	templates := []*models.PluginTemplate{
		{
			ID:          "inputs.cpu.basic",
			Type:        "inputs.cpu",
			Name:        "Basic CPU Monitoring",
			Description: "基础 CPU 监控模板",
			Template: `[[inputs.cpu]]
  percpu = {{if .percpu}}{{.percpu}}{{else}}true{{end}}
  totalcpu = {{if .totalcpu}}{{.totalcpu}}{{else}}true{{end}}
  collect_cpu_time = {{if .collect_cpu_time}}{{.collect_cpu_time}}{{else}}false{{end}}
  report_active = {{if .report_active}}{{.report_active}}{{else}}false{{end}}`,
			Parameters: []models.TemplateParameter{
				{Name: "percpu", Type: "bool", Required: false, Default: true, Description: "是否收集每个 CPU 核心的指标"},
				{Name: "totalcpu", Type: "bool", Required: false, Default: true, Description: "是否收集总 CPU 指标"},
			},
			Version: "1.0.0",
		},
		{
			ID:          "inputs.mem.basic",
			Type:        "inputs.mem",
			Name:        "Basic Memory Monitoring",
			Description: "基础内存监控模板",
			Template:    `[[inputs.mem]]`,
			Parameters:  []models.TemplateParameter{},
			Version:     "1.0.0",
		},
		{
			ID:          "inputs.disk.basic",
			Type:        "inputs.disk",
			Name:        "Basic Disk Monitoring",
			Description: "基础磁盘监控模板",
			Template: `[[inputs.disk]]
  ignore_fs = {{if .ignore_fs}}[{{range $i, $fs := .ignore_fs}}{{if $i}}, {{end}}"{{$fs}}"{{end}}]{{else}}["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]{{end}}`,
			Parameters: []models.TemplateParameter{
				{Name: "ignore_fs", Type: "array", Required: false, Default: []string{"tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"}, Description: "忽略的文件系统列表"},
			},
			Version: "1.0.0",
		},
		{
			ID:          "inputs.snmp.basic",
			Type:        "inputs.snmp",
			Name:        "Basic SNMP Monitoring",
			Description: "基础 SNMP 监控模板",
			Template: `[[inputs.snmp]]
  agents = [{{range $i, $agent := .agents}}{{if $i}}, {{end}}"{{$agent}}"{{end}}]
  version = {{if .version}}{{.version}}{{else}}2{{end}}
  community = "{{.community}}"
  
  [[inputs.snmp.field]]
    oid = "1.3.6.1.2.1.1.3.0"
    name = "uptime"`,
			Parameters: []models.TemplateParameter{
				{Name: "agents", Type: "array", Required: true, Description: "SNMP 代理地址列表"},
				{Name: "version", Type: "int", Required: false, Default: 2, Description: "SNMP 版本"},
				{Name: "community", Type: "string", Required: true, Description: "SNMP 社区字符串"},
			},
			Version: "1.0.0",
		},
		{
			ID:          "inputs.ping.basic",
			Type:        "inputs.ping",
			Name:        "Basic Ping Monitoring",
			Description: "基础 Ping 监控模板",
			Template: `[[inputs.ping]]
  urls = [{{range $i, $url := .urls}}{{if $i}}, {{end}}"{{$url}}"{{end}}]
  method = "{{if .method}}{{.method}}{{else}}native{{end}}"
  count = {{if .count}}{{.count}}{{else}}1{{end}}
  ping_interval = {{if .ping_interval}}{{.ping_interval}}{{else}}1.0{{end}}`,
			Parameters: []models.TemplateParameter{
				{Name: "urls", Type: "array", Required: true, Description: "要 ping 的 URL 或 IP 地址列表"},
				{Name: "method", Type: "string", Required: false, Default: "native", Description: "ping 方法 (native 或 exec)"},
				{Name: "count", Type: "int", Required: false, Default: 1, Description: "每次 ping 的包数量"},
			},
			Version: "1.0.0",
		},
		{
			ID:          "inputs.net.basic",
			Type:        "inputs.net",
			Name:        "Basic Network Monitoring",
			Description: "基础网络监控模板",
			Template: `[[inputs.net]]
  interfaces = {{if .interfaces}}[{{range $i, $iface := .interfaces}}{{if $i}}, {{end}}"{{$iface}}"{{end}}]{{else}}[]{{end}}`,
			Parameters: []models.TemplateParameter{
				{Name: "interfaces", Type: "array", Required: false, Description: "要监控的网络接口列表，为空则监控所有接口"},
			},
			Version: "1.0.0",
		},
	}

	for _, tmpl := range templates {
		tmpl.CreatedAt = time.Now()
		tmpl.UpdatedAt = time.Now()

		// 检查模板是否已存在
		_, err := pts.GetTemplate(ctx, tmpl.ID)
		if err == nil {
			// 模板已存在，跳过
			continue
		}

		// 创建模板
		if err := pts.CreateTemplate(ctx, tmpl); err != nil {
			// 如果是因为已存在而失败，继续下一个
			if strings.Contains(err.Error(), "already exists") {
				continue
			}
			return fmt.Errorf("failed to create preset template %s: %w", tmpl.ID, err)
		}
	}

	return nil
}

// ConvertConfigToTOML 将配置 map 转换为 TOML 格式的字符串
func (pts *PluginTemplateService) ConvertConfigToTOML(config map[string]interface{}) (string, error) {
	// 这是一个简化的实现，实际应该使用专门的 TOML 库
	// 这里我们使用 JSON 作为中间格式，然后手动转换为 TOML
	jsonBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	// 简单的 JSON 到 TOML 转换（仅用于简单场景）
	// 对于复杂场景，应该使用专门的库如 github.com/pelletier/go-toml
	tomlStr := string(jsonBytes)
	// 这里只是占位，实际应该实现完整的转换逻辑
	// 或者直接使用 TOML 库

	return tomlStr, nil
}
