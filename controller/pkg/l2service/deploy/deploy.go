package deploy

type DeployFile interface {
	Source() string
	TargetPath() string
	TarName() string
	MainFileName() string
}

// type LocalDeployFile struct {
// 	source       string
// 	target       string
// 	tarName      string
// 	mainFileName string
// }

// func (ldf *LocalDeployFile) Source() string {
// 	return ldf.source
// }

// func (ldf *LocalDeployFile) MainFileName() string {
// 	return ldf.mainFileName
// }

// func (ldf *LocalDeployFile) TarName() string {
// 	return ldf.tarName
// }

// func (ldf *LocalDeployFile) TargetPath() string {
// 	return ldf.target
// }

// func (ldf *LocalDeployFile) File() []byte {
// 	return nil
// }

// func NewLocalDeployFile(source, target, tarName, mainFileName string) DeployFile {
// 	return &LocalDeployFile{
// 		source:       source,
// 		target:       target,
// 		tarName:      tarName,
// 		mainFileName: mainFileName,
// 	}
// }

// // func NewPluginFile(id int) DeployFile{
// // 	var plugin model.Plugin
// // 	global.GVA_DB.First(&plugin, id)
// // 	return &PluginDeployFile{
// // 		plugin: plugin
// // 	}
// // }

// // type EditionDeployFile struct {
// // 	plugin model.Plugin
// // }

// type EditionDeployFile struct {
// 	LocalDeployFile
// 	editionModel *model.Edition
// 	edition_id   int
// }

// func NewEditionDeployFile(edition_id int) DeployFile {
// 	df := &EditionDeployFile{
// 		edition_id:   edition_id,
// 		editionModel: &model.Edition{},
// 	}
// 	err_edit := global.GVA_DB.Where("id = ?", df.edition_id).First(df.editionModel).Error
// 	if err_edit != nil {
// 		fmt.Println("获取部署失败：", err_edit)
// 		panic(err_edit)
// 	}
// 	return df
// }

// func (edf *EditionDeployFile) Source() string {

// 	return edf.editionModel.SavePath + "/Deploy_test/"
// }

// func (edf *EditionDeployFile) MainFileName() string {
// 	return edf.editionModel.MainFileName
// }

// func (edf *EditionDeployFile) TarName() string {
// 	return edf.editionModel.TarName
// }

// func (edf *EditionDeployFile) TargetPath() string {
// 	return edf.editionModel.DeployPath
// }

// ////cmd命令执行
// //func execute_cmd(cmdStr string) ([]byte, error) {
// //// 执行命令超过5秒自动退出
// //ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1200)*time.Second)
// //defer cancel()
// //cmd := exec.CommandContext(ctx, "/bin/bash", "-c", cmdStr)
// //b, err := cmd.CombinedOutput()
// //return b, err
// //}

// //func KillRemoteProgress(cmd string) ([]byte, error) {
// //return execute_cmd(cmd)
// //}

// //func CheckAndMkdirEdition(cmd string) ([]byte, error) {
// //return execute_cmd(cmd)
// //}

// //func RemoteCopyEditionFile(cmd string) ([]byte, error) {
// //return execute_cmd(cmd)
// //}

// //func ExtractAndRun(cmd string) ([]byte, error) {
// //return execute_cmd(cmd)
// //}

// //func CheckAndMkdirPlugin(cmd string) ([]byte, error) {
// //return execute_cmd(cmd)
// //}

// //func RemoteCopyPluginFile(cmd string) ([]byte, error) {
// //return execute_cmd(cmd)
// //}

// //func UnzipAndRmTar(cmd string) ([]byte, error) {
// //return execute_cmd(cmd)
// //}

// ////func Mkdir(cmd string) ([]byte, error) {
// ////return executeCMD(cmd)
// ////}

// //func CreateDeployStep(probe *model.Probe, step model.DeploySteps) (err error) {
// //// for _, step := range steps {
// //// 	step.ProbeID = int(probe.ID)
// //// }
// //probe.DeployStepss = append(probe.DeployStepss, &step)
// //err = global.GVA_DB.Save(probe).Error
// //return
// //}
