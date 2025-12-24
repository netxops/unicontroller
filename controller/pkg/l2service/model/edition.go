// 自动生成模板Edition
package model

// 如果含有time.Time 请自行import time包
type Edition struct {
	GVA_MODEL    `mapstructure:",squash"`
	Name         string `json:"name" form:"name" gorm:"column:name;comment:" mapstructure:"name"`
	TarName      string `json:"tar_name" form:"tar_name" gorm:"column:tar_name;comment:" mapstructure:"tar_name"`
	MainFileName string `json:"main_file_name" form:"main_file_name" gorm:"column:main_file_name;comment:" mapstructure:"main_file_name"`
	SavePath     string `json:"save_path" form:"save_path" gorm:"column:save_path;comment:" mapstructure:"save_path"`
	DeployPath   string `json:"deploy_path" form:"deploy_path" gorm:"column:deploy_path;comment:" mapstructure:"deploy_path"`
	Version      string `json:"version" form:"version" gorm:"column:version;comment:" mapstructure:"version"`
	Md5          string `json:"md5" form:"md5" gorm:"column:md5;comment:" mapstructure:"md5"`
	UpdateTime   string `json:"update_time" form:"update_time" gorm:"column:update_time;comment:" mapstructure:"update-time"`
	FileSize     int    `json:"file_size" form:"file_size" gorm:"column:file_size;comment:" mapstructure:"file-size"`
}

func (Edition) TableName() string {
	return "edition"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type EditionWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	Edition   `json:"business"`
// }

// func (Edition) TableName() string {
// 	return "edition"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["edition"] = func() model.GVA_Workflow {
//   return new(model.EditionWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["edition"] = func() interface{} {
// 	return new(model.Edition)
// }
