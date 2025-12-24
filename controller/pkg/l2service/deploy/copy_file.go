package deploy

//
// type DeployFile interface {
// Source() string
// TargetPath() string
// TarName() string
// MainFileName() string
// }
//
// type LocalDeployFile struct {
// source       string
// target       string
// tarName      string
// mainFileName string
// }
//
// func (ldf *LocalDeployFile) Source() string {
// return ldf.source
// }
//
// func (ldf *LocalDeployFile) MainFileName() string {
// return ldf.mainFileName
// }
//
// func (ldf *LocalDeployFile) TarName() string {
// return ldf.tarName
// }
//
// func (ldf *LocalDeployFile) TargetPath() string {
// return ldf.target
// }
//
// func (ldf *LocalDeployFile) File() []byte {
// return nil
// }
//
// func NewLocalDeployFile(source, target, tarName, mainFileName string) DeployFile {
// return &LocalDeployFile{
// source:       source,
// target:       target,
// tarName:      tarName,
// mainFileName: mainFileName,
// }
// }
