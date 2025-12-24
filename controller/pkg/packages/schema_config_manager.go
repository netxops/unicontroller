package packages

// import (
// 	"fmt"
// 	"path/filepath"

// 	"github.com/influxdata/telegraf/controller/model"
// )

// type SchemaConfigManager struct {
// 	Schema         *model.Schema
// 	ConfigPath     string
// 	RestartManager RestartManager
// }

// // 确保 SchemaConfigManager 实现了 ConfigManager 接口
// var _ ConfigManager = (*SchemaConfigManager)(nil)

// type RestartManager interface {
// 	Restart() error
// }

// func NewSchemaConfigManager(schema *model.Schema, configPath string, restartManager RestartManager) *SchemaConfigManager {
// 	return &SchemaConfigManager{
// 		Schema:         schema,
// 		ConfigPath:     configPath,
// 		RestartManager: restartManager,
// 	}
// }

// func (scm *SchemaConfigManager) Load() (*Config, error) {
// 	config := &Config{Data: make(map[string]interface{})}
// 	for _, configItem := range scm.Schema.Configs {
// 		path := filepath.Join(scm.ConfigPath, configItem.File)
// 		format := getFormatFromFilename(configItem.File)
// 		fileConfig := &FileConfig{Path: path, Format: format}
// 		c, err := fileConfig.Load()
// 		if err != nil {
// 			return nil, fmt.Errorf("error loading config for %s: %v", configItem.Arg, err)
// 		}
// 		config.Data[configItem.Arg] = c.Data
// 	}
// 	return config, nil
// }

// func (scm *SchemaConfigManager) Save(config *Config) error {
// 	for _, configItem := range scm.Schema.Configs {
// 		if subConfig, ok := config.Data[configItem.Arg]; ok {
// 			path := filepath.Join(scm.ConfigPath, configItem.File)
// 			format := getFormatFromFilename(configItem.File)
// 			fileConfig := &FileConfig{Path: path, Format: format}
// 			err := fileConfig.Save(&Config{Data: subConfig.(map[string]interface{})})
// 			if err != nil {
// 				return fmt.Errorf("error saving config for %s: %v", configItem.Arg, err)
// 			}
// 		}
// 	}
// 	return nil
// }

// func (scm *SchemaConfigManager) Apply() error {
// 	switch scm.Schema.RestartPolicy {
// 	case model.RestartAlways:
// 		return scm.RestartManager.Restart()
// 	case model.RestartOnChange:
// 		configChanged, err := scm.isConfigChanged()
// 		if err != nil {
// 			return fmt.Errorf("error checking config changes: %v", err)
// 		}
// 		if configChanged {
// 			return scm.RestartManager.Restart()
// 		}
// 	case model.RestartNever:
// 		// 不重启
// 	}
// 	return nil
// }
// func (scm *SchemaConfigManager) GetPath() string {
// 	return scm.ConfigPath
// }

// func (scm *SchemaConfigManager) GetFormat() string {
// 	return "schema"
// }

// func (scm *SchemaConfigManager) isConfigChanged() (bool, error) {

// 	return false, nil
// }

// func (scm *SchemaConfigManager) getLastAppliedConfig(arg string) (map[string]interface{}, error) {
// 	// 这里应该实现获取上次应用的配置的逻辑
// 	// 可以从文件、数据库或内存中获取，取决于你的具体实现
// 	// 这里我们简单返回一个空map作为示例
// 	return make(map[string]interface{}), nil
// }

// func getFormatFromFilename(filename string) string {
// 	ext := filepath.Ext(filename)
// 	switch ext {
// 	case ".json":
// 		return "json"
// 	case ".yaml", ".yml":
// 		return "yaml"
// 	case ".toml":
// 		return "toml"
// 	default:
// 		return "unknown"
// 	}
// }

// func createObserver(observerType string) ConfigObserver {
// 	// 根据类型创建观察者的逻辑
// 	// 这里需要实现具体的观察者创建逻辑
// 	return nil
// }

// // // 实现 ApplyStrategy 接口
// // func (scm *SchemaConfigManager) Apply(config ConfigManager) error {
// // 	return scm.Apply()
// // }
