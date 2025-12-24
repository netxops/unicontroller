// 自动生成模板TemplateArg
package model

// 如果含有time.Time 请自行import time包
type TemplateArg struct {
	GVA_MODEL
	Name           string       `json:"name" form:"name" gorm:"column:name;comment:;type:varchar(40);size:40;"`
	Type           string       `json:"type" form:"type" gorm:"column:type;comment:参数类型;type:varchar(191);size:191;"`
	Default        string       `json:"default" form:"default" gorm:"column:default;comment:参数默认值;type:varchar(191);size:191;"`
	TaskTemplateID int          `json:"task_template_id" form:"task_template_id" gorm:"column:task_template_id;comment:任务模板ID;type:int;"`
	TaskTemplate   TaskTemplate `json:"task_template" form:"task_template"`
}

func (TemplateArg) TableName() string {
	return "template_arg"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type TemplateArgWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	TemplateArg   `json:"business"`
// }

// func (TemplateArg) TableName() string {
// 	return "template_arg"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["template_arg"] = func() model.GVA_Workflow {
//   return new(model.TemplateArgWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["template_arg"] = func() interface{} {
// 	return new(model.TemplateArg)
// }
