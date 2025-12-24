package linux

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/l2service/deploy"
	stackup "github.com/influxdata/telegraf/controller/pkg/l2service/sup"
	"github.com/influxdata/telegraf/controller/pkg/sshtool"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/structs/sup"

	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/tools"

	"strings"

	"github.com/gofrs/uuid"
)

type Linux struct {
	LocalDataPath string
}

func (l *Linux) batch(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	twa := deploy.NewTargetWithAuth(remote.Username, remote.Password, remote.Ip)
	var cmdList []string
	for _, ops := range options {
		cmd := ops.(string)
		cmdList = append(cmdList, cmd)
	}

	res, err := twa.ExecuteCmd(cmdList, 90)
	result = clitask.NewEmptyTableWithKeys([]string{"output"})
	if res != "" {
		data := map[string]string{
			"output": res,
		}
		result.PushRow("1", data, true, "")
	}
	if err != nil {
		return
	}
	return
}

// 单步执行，默认遇到错误不停止执行
func (l *Linux) step(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	return l._stepRun(remote, taskConfig, true, options...)
}

func (l *Linux) _stepRun(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, stopOnErr bool, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
	}
	base.WithActionID(remote.ActionID)
	//
	// if remote.CtxID != "" {
	// ctx := context.Background()
	// ctx = context.WithValue(ctx, "ctx_id", remote.CtxID)
	// base.WithContext(ctx)
	// }

	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	for index, ops := range options {
		// cmd := ops.(*terminalmode.Command)
		key := strings.Join(strings.Fields(ops.(string)), "_")
		key = fmt.Sprintf("%s_%d", key, index+1)

		cmd := terminalmode.NewCommand(ops.(string), "", 3, key, "")
		exec.AddCommand(cmd)
		cmdList = append(cmdList, cmd)
	}

	exec.Id = uuid.Must(uuid.NewV4()).String()

	result = clitask.NewEmptyTableWithKeys([]string{"command", "key", "output", "msg", "status"})

	r := exec.Run(stopOnErr)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	for index, cmd := range cmdList {
		ok, data := r.GetResult(cmd.Name)
		msg := r.GetMsg(cmd.Name)
		m := map[string]string{
			"command": cmd.Command,
			"key":     cmd.Name,
			"output":  strings.Join(data, "\n"),
			"msg":     msg,
			"status":  tools.Conditional(ok, "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}

	// result.Pretty()

	return
}

func (l *Linux) ibnetCommands(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	cmds := []interface{}{}
	for _, ops := range options {
		if cmd, ok := ops.(string); ok {
			cmds = append(cmds, cmd)
		}
	}

	return sshtool.ExecuteSSHCommands(remote, cmds)
	return
}

func (l *Linux) checkdevice(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	var ipList []string
	for _, ops := range options {
		ip := ops.(string)
		ipList = append(ipList, ip)
	}
	fmt.Println(ipList)
	t := true
	f := false
	community := []string{"69=u8tb=oo"}
	// var resultTable *clitask.Table
	for _, ip := range ipList {
		remoteInfo := structs.L2DeviceRemoteInfo{
			Ip:        ip,
			Username:  "admin.ro",
			Password:  "Dfzq@2019",
			AuthPass:  "Dfzq@2019",
			Community: community,
			Platform:  "Nexus",
			Catalog:   "SWITCH",
			MetaID:    274,
			IsRedfish: false,
		}
		remoteInfo.Meta.RestfullPort = 8443
		remoteInfo.Meta.NetconfPort = 830
		remoteInfo.Meta.TelnetPort = 23
		remoteInfo.Meta.SSHPort = 22
		remoteInfo.Meta.Enable = &t
		remoteInfo.Meta.EnableSSH = &t
		remoteInfo.Meta.EnableTelnet = &t
		remoteInfo.Meta.EnableNetconf = &t
		remoteInfo.Meta.EnableRestfull = &f
		remoteInfo.Meta.EnableSnmp = &t
		remoteInfo.Meta.Version = "9.3(3)"

		// deviceService := service.Config.Select(remoteInfo, "iftable")
		// resultTable, err = deviceService.Run(remoteInfo, options...)
		// return resultTable, err
	}
	return
}

func (l *Linux) stepWithCommand(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
	}

	// if remote.CtxID != "" {
	// ctx := context.Background()
	// ctx = context.WithValue(ctx, "ctx_id", remote.CtxID)
	// base.WithContext(ctx)
	// }
	base.WithActionID(remote.ActionID)

	cmdList := []*terminalmode.Command{}
	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	// exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	for index, ops := range options {
		var cmd terminalmode.Command
		err = json.Unmarshal(ops.([]byte), &cmd)
		if err != nil {
			return
		}

		if cmd.Name == "" {
			cmd.Name = strings.Join(strings.Fields(cmd.Command), "_")
			cmd.Name = fmt.Sprintf("%s_%d", cmd.Name, index+1)
		}

		if cmd.Timeout == 0 {
			cmd.Timeout = 3
		}
		exec.AddCommand(&cmd)
		cmdList = append(cmdList, &cmd)
	}
	exec.Id = uuid.Must(uuid.NewV4()).String()
	result = clitask.NewEmptyTableWithKeys([]string{"command", "key", "output", "msg", "status"})

	r := exec.Run(true)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	for index, cmd := range cmdList {
		ok, data := r.GetResult(cmd.Name)
		msg := r.GetMsg(cmd.Name)
		m := map[string]string{
			"command": cmd.Command,
			"key":     cmd.Name,
			"output":  strings.Join(data, "\n"),
			"msg":     msg,
			"status":  tools.Conditional(ok, "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}

	// result.Pretty()

	return
}

func (l *Linux) stackUp(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	result = clitask.NewEmptyTableWithKeys([]string{"command", "key", "output", "msg", "status"})
	if len(options) == 0 {
		err = errors.New("the 'options' parameter is empty")
		return
	}

	bs, ok := options[0].([]byte)
	if !ok {
		err = errors.New("the 'options' parameter type is incorrect. It should be of type []byte")
	}
	conf, err := sup.NewSupConfg(bs)
	if err != nil {
		err = fmt.Errorf("initialization failed, err: %s", err)
		return
	}
	s, _ := stackup.NewFromConfg(conf, l.LocalDataPath)

	exec, cmdList, err := s.BuildExecute(remote, conf.Env, nil, nil, conf.Commands...)
	if err != nil {
		return result, err
	}

	stopOnErr := false
	r := exec.Run(stopOnErr)

	for index, cmd := range cmdList {
		_, data := r.GetResult(cmd.Name)
		msg := r.GetMsg(cmd.Name)
		m := map[string]string{
			"command": cmd.Command,
			"key":     cmd.Name,
			"output":  strings.Join(data, "\n"),
			"msg":     msg,
			"status":  tools.Conditional(r.HasError(cmd.Name), "true", "false").(string),
		}
		result.PushRow(fmt.Sprint(index+1), m, true, "")
	}

	return
}

func (l *Linux) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "STACKUP":
		switch strings.ToUpper(remote.Platform) {
		case "UBUNTU":
			result, err = l.stackUp(remote, taskConfig, options...)
		case "CENTOS":
			result, err = l.stackUp(remote, taskConfig, options...)
		case "REDHAT":
			result, err = l.stackUp(remote, taskConfig, options...)
		case "LINUX":
			result, err = l.stackUp(remote, taskConfig, options...)
		case "DEBIAN":
			result, err = l.stackUp(remote, taskConfig, options...)
		case "ALMALINUX":
			result, err = l.stackUp(remote, taskConfig, options...)
		default:
			err = fmt.Errorf("task is not being executed, platform=%s, method=%s", remote.Platform, strings.ToUpper(taskConfig.GetMethod()))
		}
	case "BATCH":
		switch strings.ToUpper(remote.Platform) {
		case "UBUNTU":
			result, err = l.batch(remote, taskConfig, options...)
		case "CENTOS":
			result, err = l.batch(remote, taskConfig, options...)
		case "REDHAT":
			result, err = l.batch(remote, taskConfig, options...)
		case "LINUX":
			result, err = l.batch(remote, taskConfig, options...)
		case "DEBIAN":
			result, err = l.batch(remote, taskConfig, options...)
		case "ALMALINUX":
			result, err = l.batch(remote, taskConfig, options...)
		default:
			err = fmt.Errorf("task is not being executed, platform=%s, method=%s", remote.Platform, strings.ToUpper(taskConfig.GetMethod()))
		}
	case "STEP":
		switch strings.ToUpper(remote.Platform) {
		case "UBUNTU":
			result, err = l.step(remote, taskConfig, options...)
		case "DEBIAN":
			result, err = l.step(remote, taskConfig, options...)
		case "ALMALINUX":
			result, err = l.step(remote, taskConfig, options...)
		case "CENTOS":
			result, err = l.step(remote, taskConfig, options...)
		case "REDHAT":
			result, err = l.step(remote, taskConfig, options...)
		case "LINUX":
			result, err = l.step(remote, taskConfig, options...)
		default:
			err = fmt.Errorf("task is not being executed, platform=%s, method=%s", remote.Platform, strings.ToUpper(taskConfig.GetMethod()))
		}
	case "STEP_WITH_COMMAND":
		switch strings.ToUpper(remote.Platform) {
		case "UBUNTU":
			result, err = l.stepWithCommand(remote, taskConfig, options...)
		case "CENTOS":
			result, err = l.stepWithCommand(remote, taskConfig, options...)
		case "REDHAT":
			result, err = l.stepWithCommand(remote, taskConfig, options...)
		case "LINUX":
			result, err = l.stepWithCommand(remote, taskConfig, options...)
		case "DEBIAN":
			result, err = l.stepWithCommand(remote, taskConfig, options...)
		case "ALMALINUX":
			result, err = l.stepWithCommand(remote, taskConfig, options...)
		default:
			err = fmt.Errorf("task is not being executed, platform=%s, method=%s", remote.Platform, strings.ToUpper(taskConfig.GetMethod()))
		}
	case "IB_NET":
		switch strings.ToUpper(remote.Platform) {
		case "UBUNTU":
			result, err = l.ibnetCommands(remote, taskConfig, options...)
		case "CENTOS":
			result, err = l.ibnetCommands(remote, taskConfig, options...)
		default:
			err = fmt.Errorf("task is not being executed, platform=%s, method=%s", remote.Platform, strings.ToUpper(taskConfig.GetMethod()))
		}

	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}
	return
}
