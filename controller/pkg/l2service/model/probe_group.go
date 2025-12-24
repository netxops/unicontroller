// 自动生成模板ProbeGroup
package model

// 如果含有time.Time 请自行import time包
type ProbeGroup struct {
	GVA_MODEL   `mapstructure:",squash"`
	Name        string  `json:"name" form:"name" gorm:"column:name;comment:;type:varchar(191);size:191;" mapstructure:"name"`
	Description string  `json:"description" form:"description" gorm:"column:description;comment:;type:varchar(191);size:191;" mapstructure:"description"`
	TestGroup   bool    `json:"test_group" form:"test_group" gorm:"column:test_group;" mapstructure:"test_group"`
	EditionID   int     `json:"edition_id" form:"edition_id" gorm:"column:edition_id;commrnt:;type:int" mapstructure:"edition_id"`
	Edition     Edition `json:"edition" form:"edition"`

	Probes []*Probe `json:"probes" form:"probes" gorm:"many2many:probe_probe_group;" mapstructure:"probes"`
}

func (ProbeGroup) TableName() string {
	return "probe_group"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type ProbeGroupWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	ProbeGroup   `json:"business"`
// }

// func (ProbeGroup) TableName() string {
// 	return "probe_group"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["probe_group"] = func() model.GVA_Workflow {
//   return new(model.ProbeGroupWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["probe_group"] = func() interface{} {
// 	return new(model.ProbeGroup)
// }
