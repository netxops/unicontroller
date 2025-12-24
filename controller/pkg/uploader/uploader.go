package uploader

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"
)

const (
	HuaWei  = "huawei"
	Cisco   = "cisco"
	ComWare = "comware"
	IOS     = "ios"
	Nexus   = "nexus"
)

type Uploader interface {
	Upload(src, dest structs.FileUrl, timeout int, overwrite bool) (error, map[string]string)
	// WithVrf(vrf string)
	// WithTerminalExecute(exec *terminal.Execute)
}

// type FileUpload struct {
// FileUp Uploader
// Vrf    string
// }
//
// func (md *FileUpload) Upload(src, dest structs.FileUrl, timeout int, overwrite bool) error {
// return md.FileUp.Upload(src, dest, timeout, overwrite)
// }
//
// func (md *FileUpload) WithVrf(vrf string) {
// if vrf == "" {
// vrf = "default"
// }
// md.FileUp.WithVrf(vrf)
// }
//
// func (md *FileUpload) WithTerminalExecute(exec *terminal.Execute) {
// md.FileUp.WithTerminalExecute(exec)
// }
// func NewUploader(d Uploader) *FileUpload {
// return &FileUpload{FileUp: d}
// }
//
// func NewFileUploaderSelect(manufacturer string) *FileUpload {
// if strings.ToLower(manufacturer) == HuaWei {
//
// } else if strings.ToLower(manufacturer) == Nexus {
// d := cisco.NewCiscoUploader()
// sd := NewUploader(d)
// return sd
// }
// return nil
// }
