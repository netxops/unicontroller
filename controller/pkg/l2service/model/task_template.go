// 自动生成模板TaskTemplate
package model

// 如果含有time.Time 请自行import time包
type TaskTemplate struct {
	GVA_MODEL
	Name        string  `json:"name" form:"name" gorm:"column:name;comment:;type:varchar(64);size:64;"`
	Usage       string  `json:"usage" form:"usage" gorm:"column:usage;comment:;type:varchar(255);size:255;"`
	Version     string  `json:"version" form:"version" gorm:"column:usage;comment:;type:varchar(64);size:64;"`
	FileSize    int     `json:"file_size" form:"file_size" gorm:"column:file_size;comment:" mapstructure:"file-size"`
	Description string  `json:"description" form:"description" gorm:"column:description;comment:;type:varchar(255);size:255;"`
	EditionID   int     `json:"edition_id" form:"edition_id" gorm:"column:edition_id;comment:版本ID;type:int;"`
	Edition     Edition `json:"edition" form:"edition"`
}

func (TaskTemplate) TableName() string {
	return "task_template"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type TaskTemplateWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	TaskTemplate   `json:"business"`
// }

// func (TaskTemplate) TableName() string {
// 	return "task_template"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["task_template"] = func() model.GVA_Workflow {
//   return new(model.TaskTemplateWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["task_template"] = func() interface{} {
// 	return new(model.TaskTemplate)
// }
