package cisco

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
)

type CiscoUploader struct {
	exec *terminal.Execute
	vrf  string
}

func (cu *CiscoUploader) WithTerminalExecute(exec *terminal.Execute) {
	cu.exec = exec
}

func (cu *CiscoUploader) WithVrf(vrf string) {
	cu.vrf = vrf
}

func (cu *CiscoUploader) Bootflash() structs.ProtocolModel {
	return structs.BOOTFLASH
}

func (cu *CiscoUploader) Flash() structs.ProtocolModel {
	return structs.FLASH
}

func (cu *CiscoUploader) DefaultDest(src structs.FileUrl, destMode structs.ProtocolModel) (err error, dest *structs.FileUrl) {
	dest = &structs.FileUrl{}
	fileName := filepath.Base(src.Path)
	if destMode == structs.BOOTFLASH || destMode == structs.FLASH {
		dest.Protocol = destMode
		dest.Path = fileName
		return nil, dest
	}

	err = fmt.Errorf("不支持的协议类型")
	return err, dest
}

func (cu *CiscoUploader) Upload(src, dest structs.FileUrl, timeout int, overwrite bool) (error, map[string]string) {
	var check, msg string
	cli := fmt.Sprintf("copy %s %s", src.Url(), dest.Url())
	if cu.vrf != "" {
		cli = fmt.Sprintf("%s vrf %s", cli, cu.vrf)
	}

	fmt.Println("UploadCmd cmd-----", cli)
	var errResult error
	var fileExistError error

	ia, _, _ := cu.exec.NewInteraction(func(output string, _ *terminalmode.Command) {
	}, func(err error, _ *terminalmode.Command) {
		errResult = err
	})

	if errResult != nil {
		return errResult, map[string]string{"check": check, "msg": msg}
	}

	cmdName := "upload_image"
	cmd := terminalmode.NewCommand(cli, "", timeout, cmdName, "")
	f := func(data string, cmd *terminalmode.Command) (bool, string) {
		if cmd.Name != cmdName {
			return false, ""
		}

		// 如果执行过程如果遇到提示overwrite
		p := regexp.MustCompile(`want\sto\soverwrite\s\(y\/n\)\?\[n\]\s`)
		if matched := p.FindString(data); matched != "" {
			if overwrite {
				pass := terminalmode.NewCommand("y", "", timeout, "send_Y", "")
				cmd.Sub_commands = append(cmd.Sub_commands, pass)
				return true, matched
			}

			pass := terminalmode.NewCommand("n", "", 1, "send_N", "")
			cmd.Sub_commands = append(cmd.Sub_commands, pass)
			fileExistError = fmt.Errorf("FileExist")

			return true, matched
		}

		return false, ""
	}

	cu.exec.AddOpts(f)
	ia.PushSyncCmd(*cmd, func(output string) {
		check, msg = uploaderCheck(output)
	}, func(_ error) {})
	ia.Close()

	return fileExistError, map[string]string{"checkline": check, "msg": msg}
}

func NewCiscoUploader() *CiscoUploader {
	d := &CiscoUploader{}
	return d
}

//
// func sshCheckImportReply(desc string, mode terminalmode.DeviceType) (result *clitask.Table, deviceType string, err error) {
// switch mode {
// case terminalmode.IOS:
// case terminalmode.Nexus:
// table := LinkCheckImport(desc)
// result = table
// return
// case terminalmode.Comware:
// case terminalmode.VRP:
// case terminalmode.HuaWei:
// default:
// err = fmt.Errorf("unsupport platform")
// }
//
// if err == nil {
// return
// }
// return
// }
//
// func tt() {
// var rs *clitask.Table
// var err error
// tb := clitask.NewEmptyTableWithKeys([]string{"checkline"})
// data := make(map[string]string)
// rs, err = SSHGetWithCmdPrompt(remote, deviceType, logger, options...)
//
// if err != nil {
// logger.Warn("SSHGetWithCmcPrompt  failed", zap.Error(err), log.Tag("remote", remote))
// } else {
// for _, v := range rs.Data {
// if v["output"] != "" {
// fmt.Println("------out", v["output"])
// mode := terminalmode.NewDeviceType(remote.Platform)
// result, _, err = sshCheckImportReply(v["output"], mode)
// if result != nil {
// for _, s := range result.Data {
// if s["check"] == "false" {
// data["checkline"] = s["msg"] + "/" + s["check"]
// } else {
// data["checkline"] = s["check"]
// }
// }
// }
//
// }
// }
// }
// }

func uploaderCheck(output string) (check string, msg string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fmt.Println("--a-aaa", line)
		if strings.Contains(line, "this image is not allowed") {
			check = "false"
			msg = line
			return
		}
		if strings.Contains(line, "Cannot overwrite") {
			check = "false"
			msg = line
			return
		}
		if strings.Contains(line, "Copy complete") {
			check = "true"
			msg = ""
			return
		}
	}

	check = "true"
	msg = ""
	return
}

//
// func LinkCheckImport(desc string) (result *clitask.Table) {
// tb := clitask.NewEmptyTableWithKeys([]string{"check", "msg"})
// var data map[string]string
// data = make(map[string]string)
// lines := strings.Split(desc, "\n")
//
// for _, line := range lines {
// if strings.Contains(line, "this image is not allowed") {
// fmt.Println("////", line)
// data["check"] = "false"
// data["msg"] = line
// tb.PushRow("", data, false, "")
// tb.Pretty()
// return tb
// }
// if strings.Contains(line, "Copy complete") {
// data["check"] = "true"
// data["msg"] = ""
// tb.PushRow("", data, false, "")
// tb.Pretty()
// return tb
// }
// }
// data["check"] = "true"
// data["msg"] = ""
// tb.PushRow("", data, false, "")
// tb.Pretty()
// return tb
// }
//
