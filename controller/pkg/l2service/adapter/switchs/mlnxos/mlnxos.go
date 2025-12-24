package mlnxos

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/tools"

	"github.com/influxdata/telegraf/controller/pkg/structs"

	clitask "github.com/netxops/utils/task"
	// "github.com/influxdata/telegraf/controller/pkg/l2service/temp/snmp"
)

type Mlnxos struct{}

func (s *Mlnxos) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {

	case "MLNXOS_IBNET_COMMAND":
		result, err = s.ibnet_command(remote, taskConfig, options...)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))

	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}
	return
}

func (s *Mlnxos) ibnet_command(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
	}

	base.WithActionID(remote.ActionID)

	var cmdList []*terminalmode.Command
	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.MLMNOS, base)
	fmt.Println("sssssss", options)
	for _, ops := range options {
		var cmd terminalmode.Command
		cmd.Command = ops.(string)
		cmd.Name = cmd.Command
		if cmd.Timeout == 0 {
			cmd.Timeout = 10
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
