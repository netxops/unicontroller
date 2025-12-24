// 自动生成模板TaskArgsValue
package model

// 如果含有time.Time 请自行import time包
type TaskArgsValue struct {
	GVA_MODEL
	ArgsValue     string      `json:"args_value" form:"args_value" gorm:"column:args_value;comment:参数值;type:varchar(191);size:191;" mapstructure:"args_value"`
	TaskID        int         `json:"task_id" form:"task_id" gorm:"column:task_id;comment:任务ID;type:int;" mapstructure:"task_id"`
	Task          Task        `json:"task" form:"task"`
	TemplateArgID int         `json:"template_arg_id" form:"template_arg_id" gorm:"column:template_arg_id;comment:;type:int;" mapstructure:"template_arg_id"`
	TemplateArg   TemplateArg `json:"template_arg" form:"template_arg"`
}

func (TaskArgsValue) TableName() string {
	return "task_args_value"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type TaskArgsValueWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	TaskArgsValue   `json:"business"`
// }

// func (TaskArgsValue) TableName() string {
// 	return "task_args_value"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["task_args_value"] = func() model.GVA_Workflow {
//   return new(model.TaskArgsValueWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["task_args_value"] = func() interface{} {
// 	return new(model.TaskArgsValue)
// }
