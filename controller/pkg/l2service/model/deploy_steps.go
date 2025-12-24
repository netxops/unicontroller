// 自动生成模板DeploySteps
package model

// 如果含有time.Time 请自行import time包
type DeploySteps struct {
	GVA_MODEL   `mapstructure:",squash"`
	Name        string `json:"name" form:"name" gorm:"column:name;comment:" mapstructure:"name"`
	StepStatus  int    `json:"step_status" form:"step_status" gorm:"column:step_status;comment:" mapstructure:"step_status"`
	StepResult  string `json:"step_result" form:"step_result" gorm:"column:step_result;comment:" mapstructure:"step_result"`
	StepCommand string `json:"step_command" form:"step_command" gorm:"column:step_command;comment:" mapstructure:"step_command"`
	ProbeID     int    `json:"probe_id" form:"probe_id" gorm:"column:probe_id;comment:;type:int;" mapstructure:"probe_id"`
	Probe       Probe  `json:"probe" form:"probe"`
	Step        int    `json:"step" form:"step" gorm:"column:step;comment:" mapstructure:"step"`
	StepType    int    `json:"step_type" form:"step_type" gorm:"column:step_type;comment:" mapstructure:"step_type"`
}

func (DeploySteps) TableName() string {
	return "deploy_steps"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type DeployStepsWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	DeploySteps   `json:"business"`
// }

// func (DeploySteps) TableName() string {
// 	return "deploy_steps"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["deploy_steps"] = func() model.GVA_Workflow {
//   return new(model.DeployStepsWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["deploy_steps"] = func() interface{} {
// 	return new(model.DeploySteps)
// }
