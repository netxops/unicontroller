package uploader

//
// func TestUploadFile(t *testing.T) {
// src := structs.FileUrl{
// Protocol: structs.FTP,
// Host:     "192.168.100.40",
// Path:     "/os_images/cisco/nexus/old_config",
// User:     "dev",
// Pwd:      "dev",
// }
// dest := structs.FileUrl{
// Protocol: structs.BOOTFLASH,
// }
// d := NewFileUploaderSelect("Nexus")
// d.WithVrf("default")
// base := &terminal.BaseInfo{
// Host:       "172.16.188.3",
// Username:   "admin",
// Password:   "admin@123",
// PrivateKey: "",
// AuthPass:   "",
// }
// exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.Nexus, base)
// d.WithTerminalExecute(exec)
// d.Upload(src, dest, 300, true)
// }
