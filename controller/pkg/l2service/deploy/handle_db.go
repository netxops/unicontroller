package deploy

// func ProbesInitStepsByIds(ids []int, step_type int) (err error) {
// 	var probes []model.Probe
// 	err = global.GVA_DB.Where("id in ?", ids).Preload(clause.Associations).Find(&probes).Error
// 	if err != nil {
// 		return
// 	}
// 	var step_ids []int
// 	for _, probe := range probes {
// 		for _, step := range probe.DeployStepss {
// 			if step.StepType == step_type {
// 				step_ids = append(step_ids, int(step.ID))
// 			}
// 		}
// 	}
// 	if len(step_ids) > 0 {
// 		err = global.GVA_DB.Delete(&[]model.DeploySteps{}, "id in ?", step_ids).Error
// 		return
// 	}
// 	return
// }

// func GetDeployMoudle(id int) (err error, deploy model.Deploy) {
// 	err = global.GVA_DB.Where("id = ?", id).Preload(clause.Associations).First(&deploy).Error
// 	return
// }
