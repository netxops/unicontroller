// 自动生成模板Task
package model

import (
	"time"
)

// 如果含有time.Time 请自行import time包

type Task struct {
	GVA_MODEL
	Uuid           string           `json:"uuid" form:"uuid" gorm:"column:uuid;comment:任务ID;type:varchar(128);size:128;"`
	Name           string           `json:"name" form:"name" gorm:"column:name;comment:;type:varchar(64);size:64;"`
	TaskTemplateID int              `json:"task_template_id" form:"task_template_id" gorm:"column:task_template_id;comment:任务模板;type:int;"`
	TaskTemplate   TaskTemplate     `json:"task_template" form:"task_template"`
	Timeout        int              `json:"timeout" form:"timeout" gorm:"column:timeout;comment:任务超时时间;type:bigint;size:19;"`
	TaskCronExpr   string           `json:"task_cron_expr" form:"task_cron_expr" gorm:"column:task_cron_expr;comment:Cron表达式;type:varchar(128);size:128;"`
	TaskCronTime   time.Time        `json:"task_cron_time" form:"task_cron_time" gorm:"column:task_cron_time;comment:Cron时间;type:datetime;"`
	Description    string           `json:"description" form:"description" gorm:"column:description;comment:;type:varchar(255);size:255;"`
	TaskArgsValues []*TaskArgsValue `json:"task_args_values" form:"task_args_values"`
	ProbeGroupID   int              `json:"probe_group_id" form:"probe_group_id" gorm:"column:probe_group_id;comment:探针组;type:int;"`
	ProbeGroup     ProbeGroup       `json:"probe_group" form:"probe_group"`
	Probes         []*Probe         `json:"probes" form:"probes" gorm:"many2many:probe_task;"`
}

func (Task) TableName() string {
	return "task"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type TaskWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	Task   `json:"business"`
// }

// func (Task) TableName() string {
// 	return "task"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["task"] = func() model.GVA_Workflow {
//   return new(model.TaskWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["task"] = func() interface{} {
// 	return new(model.Task)
// }
