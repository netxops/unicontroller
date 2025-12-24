// 自动生成模板TaskResult
package model

// 如果含有time.Time 请自行import time包
type TaskResult struct {
	GVA_MODEL `mapstructure:",squash"`
	TaskID    int  `json:"task_id" form:"task_id" gorm:"column:task_id;comment:;type:int;" mapstructure:"task_id"`
	Task      Task `json:"task" form:"task"`

	Uuid   string `json:"uuid" form:"uuid" gorm:"column:uuid;comment:" mapstructure:"uuid"`
	Result string `json:"result" form:"result" gorm:"size:2020" mapstructure:"result"`
	Error  string `json:"error" form:"error" gorm:"column:error;comment:" mapstructure:"error"`
}

func (TaskResult) TableName() string {
	return "taskresult"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type TaskResultWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	TaskResult   `json:"business"`
// }

// func (TaskResult) TableName() string {
// 	return "taskresult"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["taskresult"] = func() model.GVA_Workflow {
//   return new(model.TaskResultWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["taskresult"] = func() interface{} {
// 	return new(model.TaskResult)
// }
