// 自动生成模板Deploy
package model

// 如果含有time.Time 请自行import time包
type Deploy struct {
	GVA_MODEL    `mapstructure:",squash"`
	Name         string   `json:"name" form:"name" gorm:"column:name;comment:" mapstructure:"name"`
	DeployStatus int      `json:"deploy_status" form:"deploy_status" gorm:"column:deploy_status;comment:" mapstructure:"deploy_status"`
	DeployRegion string   `json:"deploy_region" form:"deploy_region" gorm:"column:deploy_region;comment:" mapstructure:"deploy_region"`
	ProbeIds     []int    `json:"probe_ids" form:"probe_ids" gorm:"-" mapstructure:"probe_ids"`
	Probes       []*Probe `json:"probes" form:"probes" gorm:"many2many:deploy_probe;" mapstructure:"probes"`
	EditionID    int      `json:"edition_id" form:"edition_id" gorm:"column:edition_id;comment:" mapstructure:"edition_id"`
	Edition      Edition  `json:"edition" form:"edition"`
	PluginID     int      `json:"plugin_id" form:"plugin_id" gorm:"column:plugin_id;comment:" mapstructure:"plugin_id"`
	Plugin       Plugin   `json:"plugin" form:"plugin"`
}

func (Deploy) TableName() string {
	return "deploy"
}

// 如果使用工作流功能 需要打开下方注释 并到initialize的workflow中进行注册 且必须指定TableName
// type DeployWorkflow struct {
// 	// 工作流操作结构体
// 	WorkflowBase      `json:"wf"`
// 	Deploy   `json:"business"`
// }

// func (Deploy) TableName() string {
// 	return "deploy"
// }

// 工作流注册代码

// initWorkflowModel内部注册
// model.WorkflowBusinessStruct["deploy"] = func() model.GVA_Workflow {
//   return new(model.DeployWorkflow)
// }

// initWorkflowTable内部注册
// model.WorkflowBusinessTable["deploy"] = func() interface{} {
// 	return new(model.Deploy)
// }
