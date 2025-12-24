// 自动生成模板Plugin
package model

// 如果含有time.Time 请自行import time包
type Plugin struct {
	GVA_MODEL `mapstructure:",squash"`
	Name      string  `json:"name" form:"name" gorm:"column:name;comment:" mapstructure:"name"`
	Version   string  `json:"version" form:"version" gorm:"column:version;comment:" mapstructure:"version"`
	FileSize  int     `json:"file_size" form:"file_size" gorm:"column:file_size;comment:" mapstructure:"file_size"`
	TarName   string  `json:"tar_name" form:"tar_name" gorm:"column:tar_name;comment:" mapstructure:"tar_name"`
	SavePath  string  `json:"save_path" form:"save_path" gorm:"column:save_path;comment:" mapstructure:"save_path"`
	EditionID int     `json:"edition_id" form:"edition_id" gorm:"column:edition_id;comment:;type:int;" mapstructure:"edition_id"`
	Edition   Edition `json:"edition" form:"edition"`
}

func (Plugin) TableName() string {
	return "plugin"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type PluginWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	Plugin   `json:"business"`
// }

// func (Plugin) TableName() string {
// 	return "plugin"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["plugin"] = func() model.GVA_Workflow {
//   return new(model.PluginWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["plugin"] = func() interface{} {
// 	return new(model.Plugin)
// }
