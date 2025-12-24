package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/apenella/go-ansible/pkg/execute"
	"github.com/apenella/go-ansible/pkg/execute/measure"
	"github.com/apenella/go-ansible/pkg/options"
	"github.com/apenella/go-ansible/pkg/playbook"
	"github.com/apenella/go-ansible/pkg/stdoutcallback/results"
	"github.com/gofrs/uuid"
	too "github.com/influxdata/telegraf/controller/pkg/l2service/deploy"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/log"
	clitask "github.com/netxops/utils/task"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

type ANSIBLE struct{}

var ansibleLogger *zap.Logger

func init() {
	ansibleLogger, _ = zap.NewDevelopment(zap.AddCallerSkip(1))
}
func structToMapByJsonTag(data interface{}) (map[string]string, error) {
	m := map[string]string{}
	byteS, err := json.Marshal(data)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(byteS, &m)

	return m, err
}

func Exec(cmdStr string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.Command("bash", "-c", cmdStr)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", ctx.Err()
	}
	if err != nil {
		errMsg := ""
		if len(stderr.String()) != 0 {
			errMsg = fmt.Sprintf("stderr: %s", stderr.String())
		}
		if len(stdout.String()) != 0 {
			if len(errMsg) != 0 {
				errMsg = fmt.Sprintf("%s; stdout: %s", errMsg, stdout.String())
			} else {
				errMsg = fmt.Sprintf("stdout: %s", stdout.String())
			}
		}
		return errMsg, err
	}
	return stdout.String(), nil
}
func ansible_task(cmdlist []string, logger *log.Logger) (*clitask.Table, error) {
	table := &clitask.Table{}

	fmt.Println("33333333", cmdlist)
	for _, v := range cmdlist {
		_, err := Exec(v)
		if err != nil {
			return nil, err
		} else {
			fmt.Println("---- ansible_task ok")
		}
	}
	return table, nil
}

func WriteYaml(fileName string, info *structs.RepoResult, logger *log.Logger) {
	// 将结构体转换为 YAML 格式
	data, err := yaml.Marshal(&info.PlayBook)
	if err != nil {
		logger.Error("ansible_playbook yaml marshal error", zap.Error(err))
	}

	// 将 YAML 数据写入文件
	fmt.Println("-----start write yaml")
	err = ioutil.WriteFile(fileName, data, 0644)
	if err != nil {
		logger.Error("yml WriteFile error", zap.Error(err))
	}
}
func DeleteYaml(fileName string, logger *log.Logger) {

	err := os.Remove(fileName)
	if err != nil {
		fmt.Println(err)
		logger.Error("yml Delete error", zap.Error(err))
		return
	} else {
		logger.Debug("文件已删除")
	}
}

func WriteContent(filePath string, content []byte, logger *log.Logger) (err error) {
	dir := filepath.Dir(filePath)

	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		// 处理错误
		logger.Error("目录创建失败", zap.Error(err))
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		// 处理错误
		logger.Error("文件创建失败", zap.Error(err))
		return err
	}

	// 将内容写入目标文件
	_, err = file.Write(content)
	if err != nil {
		logger.Error("无法写入文件内容", zap.Error(err))
		return
	}
	defer file.Close()
	return
}
func Playbook_Task(file string, info *structs.RepoResult, logger *log.Logger) (error, *structs.AnsibleTaskResult) {
	var res *results.AnsiblePlaybookJSONResults
	var err error
	buff := new(bytes.Buffer)
	inventoryList := info.Inventory
	inventorys := strings.Join(inventoryList, ",")
	logger.Info("写配置中")
	for _, v := range info.FileContent {
		for fi, con := range v {
			err = WriteContent(fi, con, logger)
			if err != nil {
				logger.Error("write fileContent err", zap.Error(err))
			} else {
				logger.Info("写入完成", zap.Any("filePath", fi))
			}
		}
	}
	logger.Info("Playbook_Task inventorys====", zap.Any("inventorys", inventorys), zap.Any("user", info.AnsibleConnUser))
	ansiblePlaybookConnectionOptions := &options.AnsibleConnectionOptions{
		Connection:    "ssh",
		User:          info.AnsibleConnUser,
		PrivateKey:    info.AnsibleConnPrivateKey,
		Timeout:       info.AnsibleTimeOut,
		SSHCommonArgs: "-o StrictHostKeyChecking=no",
	}
	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions{
		Inventory: inventorys + ",",
		ExtraVars: info.ExtraVars,
	}

	executorTimeMeasurement := measure.NewExecutorTimeMeasurement(
		execute.NewDefaultExecute(
			execute.WithWrite(io.Writer(buff)),
		),
	)

	playbooksList := []string{file}
	playbook2 := &playbook.AnsiblePlaybookCmd{
		Playbooks:         playbooksList,
		Exec:              executorTimeMeasurement,
		ConnectionOptions: ansiblePlaybookConnectionOptions,
		Options:           ansiblePlaybookOptions,
		StdoutCallback:    "json",
	}

	err = playbook2.Run(context.TODO())
	if err != nil {
		fmt.Println(err.Error())
	}

	res, err = results.ParseJSONResultsStream(io.Reader(buff))

	if err != nil {
		logger.Error("Playbook_Task ParseJSONResultsStream err", zap.Error(err))
	}
	fmt.Println("result---", res.String())
	ansibleResult := structs.AnsibleTaskResult{}
	statsMap := make(map[string]*structs.AnsibleTaskStatus)
	for host, stats := range res.Stats {
		ansibleTaskStatus := structs.AnsibleTaskStatus{}
		ansibleTaskStatus.Changed = stats.Changed
		ansibleTaskStatus.Ok = stats.Ok
		ansibleTaskStatus.Failures = stats.Failures
		ansibleTaskStatus.Ignored = stats.Ignored
		ansibleTaskStatus.Unreachable = stats.Unreachable
		ansibleTaskStatus.Rescued = stats.Rescued
		ansibleTaskStatus.Skipped = stats.Skipped
		statsMap[host] = &ansibleTaskStatus
	}
	ansibleResult.Stats = statsMap
	// ansibleTaskList := []*structs.AnsibleTask{}
	// ansibleTasks := []*structs.AnsibleTask{}
	ansibleHosts := []*structs.AnsibleHost{}
	for _, v := range res.Plays {
		output, _ := json.Marshal(&v)
		start := v.Play.Duration.Start
		end := v.Play.Duration.End
		ansibleResult.Start = start
		ansibleResult.End = end
		fmt.Println("one result----", string(output))
		hostMap := make(map[string][]*structs.AnsibleTask)
		for _, task := range v.Tasks {
			for host, result := range task.Hosts {
				if _, ok := hostMap[host]; !ok {
					hostMap[host] = []*structs.AnsibleTask{}
				}
				eachHost := structs.AnsibleTask{}
				eachHost.Task = task.Task.Name
				if result.Msg == nil {
					eachHost.Msg = fmt.Sprintf("")
				} else {
					eachHost.Msg = fmt.Sprintf("%s", result.Msg)
				}

				if result.Stderr == nil {
					eachHost.StdErr = ""
				} else {
					eachHost.StdErr = fmt.Sprintf("%s", result.Stderr)
				}

				eachHost.Failed = result.Failed
				if result.Stdout == nil {
					eachHost.Stdout = ""
				} else {
					eachHost.Stdout = fmt.Sprintf("%s", result.Stdout)
				}
				hostMap[host] = append(hostMap[host], &eachHost)
			}
		}
		for k, g := range hostMap {
			eachansibleHost := structs.AnsibleHost{}
			eachansibleHost.Host = k
			eachansibleHost.Tasks = g
			ansibleHosts = append(ansibleHosts, &eachansibleHost)
		}
		// for _, task := range v.Tasks {
		//	eachansibleTask := structs.AnsibleTask{}
		//	eachHost := structs.AnsibleHost{}
		//	eachansibleTask.Task = task.Task.Name
		//	eachTaskHosts := []*structs.AnsibleTaskHost{}
		//	for host, result := range task.Hosts {
		//		eachHost := structs.AnsibleTaskHost{}
		//		eachHost.Host = host
		//		if result.Msg == nil {
		//			eachHost.Msg = fmt.Sprintf("")
		//		} else {
		//			eachHost.Msg = fmt.Sprintf("%s", result.Msg)
		//		}
		//		if result.Stdout == nil {
		//			eachHost.Stdout = ""
		//		} else {
		//			eachHost.Stdout = fmt.Sprintf("%s", result.Stdout)
		//		}
		//		eachTaskHosts = append(eachTaskHosts, &eachHost)
		//	}
		//	eachansibleTask.Hosts = eachTaskHosts
		//	ansibleTasks = append(ansibleTasks, &eachansibleTask)
		// }
	}

	// output, _ := json.Marshal(&ansibleResult)
	// fmt.Println("ansible result----", string(output))
	ansibleResult.Hosts = ansibleHosts
	fmt.Println("Duration: ", executorTimeMeasurement.Duration())
	return err, &ansibleResult
}

func ansible_playbook(info *structs.RepoResult, logger *log.Logger) (result structs.RepoResultTaskReplay, err error) {
	fileName := info.Config.File
	if fileName == "" {
		fileName = "temp_playbook.yml"
	}
	WriteYaml(fileName, info, logger) // 写入yaml
	err2, reply := Playbook_Task(fileName, info, logger)
	result.AnsibleTaskResult = reply
	// tb, err := redfish.TableBuilder(AnsibleTaskResult{})
	// if err != nil {
	//	logger.Warn("ansible_playbook", zap.String("TableBuilder", "获取Table失败"), zap.Error(err))
	//	return nil, err
	// }
	// p := AnsibleTaskResult{}
	// p = reply
	// m, err := structToMapByJsonTag(p)
	// err = tb.PushRow("", m, false, "")
	// if err != nil {
	//	return nil, err
	// }
	// tb.Pretty()
	DeleteYaml(fileName, logger)
	return result, err2
}

func (ts *ANSIBLE) AnsibleCMD(ctx context.Context, info *structs.RepoResult, reply *structs.RepoResultTaskReplay) error {
	fmt.Println("--------AnsibleCMD start")
	logger := log.NewLogger(nil, true)

	var err error
	// session := NewWorkContext(ts, args)

	// var result *clitask.Table
	// reply.Method = args.ServiceType
	// var cmdList []string
	// for _, ops := range args.Options {
	//	cmd := ops.(string)
	//	cmdList = append(cmdList, cmd)
	// }
	result, err := ansible_playbook(info, logger)
	// if result == nil {
	//	result = &clitask.Table{}
	// }
	reply.AnsibleTaskResult = result.AnsibleTaskResult
	logger.Debug("AnsibleCMD",
		// zap.Any("method", "TOPO"),
		// log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Error(err))
	return err
}

func ConfigPathCheck(filePath, mode string) (file string) {
	fileSplit := strings.Split(filePath, "/")
	switch strings.ToLower(fileSplit[len(fileSplit)-1]) {
	case "conf":
		if mode == "Snmp" {
			file = filePath + "/input.snmp"
		} else if mode == "Ping" {
			file = filePath + "/input.ping"
		} else if mode == "Tcp" {
			file = filePath + "/input.net_response"
		}

	case "":
		if strings.Contains(filePath, "conf/") {
			if mode == "Snmp" {
				file = filePath + "input.snmp"
			} else if mode == "Ping" {
				file = filePath + "input.ping"
			} else if mode == "Tcp" {
				file = filePath + "input.net_response"
			}

		}
	default:
		file = ""
	}
	return file
}

func (ts *ANSIBLE) CategrafSnmpConfig(ctx context.Context, args *structs.Args, reply *structs.RepoResultTaskReplay) error {
	return errors.New("categraf配置推送已经废弃")
	// fmt.Println("------- CategrafSnmpConfig start")
	// logger := log.NewLogger(nil, true)
	// path := ""
	// fileName := ""
	// for _, eachOption := range args.Options {
	//	p := structs.RepoResult{}
	//	err := json.Unmarshal(eachOption.([]byte), &p)
	//	if err != nil {
	//		logger.Error("Unmarshal  structs.RepoResult err", zap.Error(err))
	//		return err
	//	} else {
	//		if p.Config.Type == "Snmp" {
	//			path = "/tmp/snmp.toml"
	//			fileName = "snmp.toml"
	//		} else if p.Config.Type == "Tcp" {
	//			path = "/tmp/net_response.toml"
	//			fileName = "net_response.toml"
	//		} else if p.Config.Type == "Ping" {
	//			path = "/tmp/ping.toml"
	//			fileName = "ping.toml"
	//		}
	//		for _, content := range p.FileContent {
	//			for k, v := range content {
	//				err := WriteContent(path, v, logger)
	//				if err != nil {
	//					logger.Error("写入文件失败", zap.Error(err))
	//					continue
	//				} else {
	//					logger.Debug("写入文件成功", zap.Any("path", path))
	//				}
	//				sshCmd := fmt.Sprintf("sshpass -p '%s' ", args.Remote.Password)
	//				k2 := ConfigPathCheck(k, p.Config.Type)
	//				if k2 == "" {
	//					logger.Error("scp文件路径错误", zap.Any("path", k))
	//					continue
	//				}
	//				loc_path, tar_name, dir_path := "/tmp/", fileName, k2
	//				cmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -p %s%s %s@%s:%s", loc_path, tar_name, args.Remote.Username, args.Remote.Ip, dir_path)
	//				cmds := sshCmd + cmd
	//
	//				logger.Debug("copy指令:", zap.Any("cmds", cmds))
	//				_, err = too.BaseexecuteCMD(cmds, 25)
	//				if err != nil {
	//					logger.Error("BaseexecuteCMD失败", zap.Error(err))
	//				} else {
	//					DeleteYaml(path, logger)
	//					restart_cmd := "kill -HUP `pidof categraf`"
	//
	//					base := &terminal.BaseInfo{
	//						Host:       args.Remote.Ip,
	//						Username:   args.Remote.Username,
	//						Password:   args.Remote.Password,
	//						PrivateKey: args.Remote.PrivateKey,
	//					}
	//
	//					base.WithActionID(args.Remote.ActionID)
	//
	//					cmdList := []*terminalmode.Command{}
	//					new_exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	//					// exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	//					options2 := []interface{}{}
	//					options2 = append(options2, restart_cmd)
	//					for index, ops := range options2 {
	//						key := strings.Join(strings.Fields(ops.(string)), "_")
	//						key = fmt.Sprintf("%s_%d", key, index+1)
	//
	//						cmd := terminalmode.NewCommand(ops.(string), "", 5, key, "")
	//						new_exec.AddCommand(cmd)
	//						cmdList = append(cmdList, cmd)
	//					}
	//					new_exec.Id = uuid.Must(uuid.NewV4()).String()
	//					//result := clitask.NewEmptyTableWithKeys([]string{"command", "key", "output", "status"})
	//					r := new_exec.Run(false)
	//					if r.Error() != nil {
	//						err = r.Error()
	//						logger.Error("new_exec.Run失败", zap.Error(err))
	//					} else {
	//						logger.Debug("配置重新加载完成")
	//					}
	//				}
	//			}
	//		}
	//	}
	// }
	// var err error
	// logger.Debug("CategrafSnmpConfig",
	//	//zap.Any("mode", "TOPO"),
	//	//log.Tag("remote", args.Remote),
	//	zap.Any("completed", true),
	//	zap.Error(err))
	// return err
}

func (ts *ANSIBLE) TelegrafPushSetting(ctx context.Context, args *structs.Args, reply *structs.RepoResultTaskReplay) error {
	logger := log.NewLogger(nil, true)
	logger.Info("------- TelegrafPushSettings start-----")
	tmpFilePath := ""
	fileName := ""
	for _, eachOption := range args.Options {
		p := structs.RepoResult{}
		err := json.Unmarshal(eachOption.([]byte), &p)
		if err != nil {
			logger.Error("Unmarshal TelegrafPushSettings structs.RepoResult err", zap.Error(err))
			return err
		}

		snmpTmpPath := "/tmp/all_snmp.conf"
		pingTmpPath := "/tmp/all_ping.conf"
		snmpFileName := "all_snmp.conf"
		pingFileName := "all_ping.conf"

		for _, content := range p.FileContent {
			for k, v := range content {
				fmt.Println("当前临时配置文件信息", k, " 长度", len(v))
				switch k {
				case "Snmp":
					tmpFilePath = snmpTmpPath
					fileName = snmpFileName
				case "Ping":
					tmpFilePath = pingTmpPath
					fileName = pingFileName
				}

				fmt.Println("当前临时配置文件信息", k, "开始写入")
				if err = WriteContent(tmpFilePath, v, logger); err != nil {
					logger.Error("写入telegraf配置临时文件失败", zap.Error(err))
					return err
				}

				fmt.Println("当前临时配置文件信息", k, "写入完成")
				sshCmd := fmt.Sprintf("sshpass -p '%s' ", args.Remote.Password)

				file := strings.Join([]string{p.Config.File, fileName}, "/")
				locPath, tarName, dirPath := "/tmp/", fileName, file
				cmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -p %s%s %s@%s:%s", locPath, tarName, args.Remote.Username, args.Remote.Ip, dirPath)
				command := sshCmd + cmd

				fmt.Println("copy指令:", command)
				_, err = too.BaseexecuteCMD(command, 25)
				if err != nil {
					logger.Error("Base execute CMD失败", zap.Error(err))
					return err
				}
				DeleteYaml(tmpFilePath, logger)
			}
		}

		restartCmd := "kill -HUP `pidof oneops-telegraf`"

		base := &terminal.BaseInfo{
			Host:       args.Remote.Ip,
			Username:   args.Remote.Username,
			Password:   args.Remote.Password,
			PrivateKey: args.Remote.PrivateKey,
		}

		base.WithActionID(args.Remote.ActionID)

		var cmdList []*terminalmode.Command
		newExec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
		var options2 []interface{}
		options2 = append(options2, restartCmd)
		for index, ops := range options2 {
			key := strings.Join(strings.Fields(ops.(string)), "_")
			key = fmt.Sprintf("%s_%d", key, index+1)

			cmd := terminalmode.NewCommand(ops.(string), "", 5, key, "")
			newExec.AddCommand(cmd)
			cmdList = append(cmdList, cmd)
		}
		newExec.Id = uuid.Must(uuid.NewV4()).String()
		r := newExec.Run(false)
		if r.Error() != nil {
			err = r.Error()
			logger.Error("new_exec.Run失败", zap.Error(err))
			return err
		}
		logger.Debug("配置重新加载完成")
	}
	return nil
}

func (ts *ANSIBLE) TelegrafPushSetting2(ctx context.Context, args *structs.Args, reply *structs.RepoResultTaskReplay) error {
	logger := log.NewLogger(nil, true)
	logger.Info("------- TelegrafPushSettings start-----")
	for _, eachOption := range args.Options {
		p := structs.RepoResult{}
		err := json.Unmarshal(eachOption.([]byte), &p)
		if err != nil {
			logger.Error("Unmarshal TelegrafPushSettings structs.RepoResult err", zap.Error(err))
			return err
		}

		snmpTmpPath := "/tmp/all_snmp.conf"
		pingTmpPath := "/tmp/all_ping.conf"
		snmpFileName := "all_snmp.conf"
		pingFileName := "all_ping.conf"

		for _, content := range p.FileContent {
			for k, v := range content {
				fmt.Println("当前临时配置文件信息", k, " 长度", len(v))
				remoteInfo := strings.Split(k, ",")
				remoteIP := remoteInfo[0]
				remoteUsername := remoteInfo[1]
				remotePassword := remoteInfo[2]
				remotePrivateKey := remoteInfo[3]
				remoteDirPath := remoteInfo[4]

				contentArr := strings.Split(string(v), "====== =====")
				pingContent := contentArr[0]
				if err = WriteContent(pingTmpPath, []byte(pingContent), logger); err != nil {
					logger.Error("写入telegraf ping配置临时文件失败", zap.Error(err))
					return err
				}
				snmpContent := contentArr[1]
				if err = WriteContent(snmpTmpPath, []byte(snmpContent), logger); err != nil {
					logger.Error("写入telegraf snmp配置临时文件失败", zap.Error(err))
					return err
				}
				fmt.Println("当前临时配置文件信息", k, "写入完成")

				sshCmd := fmt.Sprintf("sshpass -p '%s' ", remotePassword)
				mkdirCmd := fmt.Sprintf("sshpass -p '%s' ssh -o StrictHostKeyChecking=no %s@%s \"mkdir -p %s\"", remotePassword, remoteUsername, remoteIP, remoteDirPath)
				pingCmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -p %s %s@%s:%s", pingTmpPath, remoteUsername, remoteIP, remoteDirPath+"/"+pingFileName)
				pingCommand := mkdirCmd + " &&\n" + sshCmd + pingCmd

				fmt.Println("copy指令:", pingCommand)
				_, err = too.BaseexecuteCMD(pingCommand, 25)
				if err != nil {
					logger.Error("Base execute CMD失败", zap.Error(err))
					return err
				}
				DeleteYaml(pingTmpPath, logger)

				snmpCmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -p %s %s@%s:%s", snmpTmpPath, remoteUsername, remoteIP, remoteDirPath+"/"+snmpFileName)
				snmpCommand := sshCmd + snmpCmd

				fmt.Println("copy指令:", snmpCommand)
				_, err = too.BaseexecuteCMD(snmpCommand, 25)
				if err != nil {
					logger.Error("Base execute CMD失败", zap.Error(err))
					return err
				}
				DeleteYaml(snmpTmpPath, logger)

				restartCmd := "kill -HUP `pidof oneops-telegraf`"

				base := &terminal.BaseInfo{
					Host:       remoteIP,
					Username:   remoteUsername,
					Password:   remotePassword,
					PrivateKey: remotePrivateKey,
				}

				base.WithActionID(args.Remote.ActionID)

				var cmdList []*terminalmode.Command
				newExec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
				var options2 []interface{}
				options2 = append(options2, restartCmd)
				for index, ops := range options2 {
					key := strings.Join(strings.Fields(ops.(string)), "_")
					key = fmt.Sprintf("%s_%d", key, index+1)

					cmd := terminalmode.NewCommand(ops.(string), "", 5, key, "")
					newExec.AddCommand(cmd)
					cmdList = append(cmdList, cmd)
				}
				newExec.Id = uuid.Must(uuid.NewV4()).String()
				r := newExec.Run(false)
				if r.Error() != nil {
					err = r.Error()
					logger.Error("new_exec.Run失败", zap.Error(err))
					return err
				}
				logger.Debug("配置重新加载完成")
			}
		}
	}
	return nil
}

func (ts *ANSIBLE) ActiveMonitorPushSetting(ctx context.Context, args *structs.Args, reply *structs.RepoResultTaskReplay) error {
	logger := log.NewLogger(nil, true)
	fmt.Println("------- ActiveMonitorPushSetting start-----")
	tmpFilePath := ""
	fileName := ""
	for _, eachOption := range args.Options {
		p := structs.RepoResult{}
		err := json.Unmarshal(eachOption.([]byte), &p)
		if err != nil {
			logger.Error("Unmarshal ActiveMonitorPushSetting structs.RepoResult err", zap.Error(err))
			return err
		}

		for _, content := range p.FileContent {
			for k, v := range content {
				fmt.Println("当前临时配置文件信息", k, " 长度", len(v))
				tmpFilePath = "/tmp/" + p.Config.FileName + ".conf"
				fileName = p.Config.FileName + ".conf"

				fmt.Println("当前临时配置文件信息", k, "开始写入")
				if err = WriteContent(tmpFilePath, v, logger); err != nil {
					logger.Error("写入telegraf配置临时文件失败", zap.Error(err))
					return err
				}

				fmt.Println("当前临时配置文件信息", k, "写入完成")
				sshCmd := fmt.Sprintf("sshpass -p '%s' ", args.Remote.Password)

				file := strings.Join([]string{p.Config.File, fileName}, "/")
				locPath, tarName, dirPath := "/tmp/", fileName, file
				cmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -p %s%s %s@%s:%s", locPath, tarName, args.Remote.Username, args.Remote.Ip, dirPath)
				command := sshCmd + cmd

				fmt.Println("copy指令:", command)
				_, err = too.BaseexecuteCMD(command, 25)
				if err != nil {
					logger.Error("Base execute CMD失败", zap.Error(err))
					return err
				}
				DeleteYaml(tmpFilePath, logger)
			}
		}

		restartCmd := "kill -HUP `pidof oneops-telegraf`"

		base := &terminal.BaseInfo{
			Host:       args.Remote.Ip,
			Username:   args.Remote.Username,
			Password:   args.Remote.Password,
			PrivateKey: args.Remote.PrivateKey,
		}

		base.WithActionID(args.Remote.ActionID)

		var cmdList []*terminalmode.Command
		newExec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
		var options2 []interface{}
		options2 = append(options2, restartCmd)
		for index, ops := range options2 {
			key := strings.Join(strings.Fields(ops.(string)), "_")
			key = fmt.Sprintf("%s_%d", key, index+1)

			cmd := terminalmode.NewCommand(ops.(string), "", 5, key, "")
			newExec.AddCommand(cmd)
			cmdList = append(cmdList, cmd)
		}
		newExec.Id = uuid.Must(uuid.NewV4()).String()
		r := newExec.Run(false)
		if r.Error() != nil {
			err = r.Error()
			logger.Error("new_exec.Run失败", zap.Error(err))
			return err
		}
		logger.Debug("配置重新加载完成")
	}
	return nil
}
