// 自动生成模板Probe
package model

// 如果含有time.Time 请自行import time包
type Probe struct {
	GVA_MODEL
	Name         string         `json:"name" form:"name" gorm:"column:name;comment:;type:varchar(20);size:20;"`
	Ip           string         `json:"ip" form:"ip" gorm:"column:ip;comment:;type:varchar(20);size:20;"`
	User         string         `json:"user" form:"user" gorm:"column:user;comment:;type:varchar(20);size:20;"`
	Password     string         `json:"password" form:"password" gorm:"column:password;comment:;type:varchar(20);size:20;"`
	Port         int            `json:"port" form:"port" gorm:"column:port;comment:;type:mediumint;"`
	Status       int            `json:"status" form:"status" gorm:"column:status;comment:连接状态;type:mediumint;"`
	Tasks        []*Task        `json:"tasks" form:"tasks" gorm:"many2many:probe_task;"`
	TaskIds      []int          `json:"task_ids" form:"task_ids" gorm:"-" mapstructure:"task_ids"`
	ProbeGroups  []*ProbeGroup  `json:"probe_groups" form:"probe_groups" gorm:"many2many:probe_probe_group;" mapstructure:"probe_groups"`
	EditionID    int            `json:"edition_id" form:"edition_id" gorm:"column:edition_id;commrnt:;type:int" mapstructure:"edition_id"`
	Edition      Edition        `json:"edition" form:"edition"`
	DeployStepss []*DeploySteps `json:"deploy_stepss" form:"deploy_stepss" gorm:"many2many:deploy_steps_probe;" mapstructure:"deploy_stepss"`
	Test         bool           `json:"test" form:"test" gorm:"column:test;" mapstructure:"test"`
	//DeployID    int           `json:"deploy_id" form:"deploy_id" gorm:"column:deploy_id;comment:;type:int;" mapstructure:"deploy_id"`
	//Deploy      Deploy        `json:"deploy" form:"deploy"`
}

func (Probe) TableName() string {
	return "probe"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type ProbeWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	Probe   `json:"business"`
// }

// func (Probe) TableName() string {
// 	return "probe"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["probe"] = func() model.GVA_Workflow {
//   return new(model.ProbeWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["probe"] = func() interface{} {
// 	return new(model.Probe)
// }
