package fw

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	clitask "github.com/netxops/utils/task"
)

type Dptech struct{}

func (a Dptech) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	fmt.Printf("--------remoteInfo-------%#v\n", remote)

	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "DPTECH_CONFIG":
		result, err = a.config(remote, taskConfig, options)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}

func (a Dptech) config(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	cmds := []string{}
	for _, option := range options {
		for _, op := range option.([]interface{}) {
			if opVal, ok := op.(string); ok {
				cmds = append(cmds, opVal)
			}
		}
	}

	if len(cmds) == 0 {
		return nil, errors.New("dptech commands not received, command is empty")
	}
	return dptechTerminalConfig(remote, taskConfig, cmds)
}

func dptechTerminalConfig(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, params []string) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		AuthPass:   remote.AuthPass,
		Port:       remote.Meta.SSHPort,
		Telnet:     remote.Meta.EnableTelnet != nil && *remote.Meta.EnableTelnet,
	}

	exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.Dptech, base)

	fmt.Println("dptech method params======>", params)
	var cmds []*terminalmode.Command
	for index, op := range params {
		key := fmt.Sprintf("%s_%d", op, index+1)
		cmd := terminalmode.NewCommand(op, "", 15, key, "")
		exec.AddCommand(cmd)
		cmds = append(cmds, cmd)
	}

	fmt.Println("cmd======>", cmds)
	exec.Id = uuid.Must(uuid.NewV4()).String()

	result = clitask.NewEmptyTableWithKeys([]string{"firewallConfigResult"})
	exec.Prepare(false)
	r := exec.Run(true)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	fmt.Printf("final result ---- %#v\n", r)

	dataBytes, err := json.Marshal(r)
	if err != nil {
		err = errors.New("dptech config result trans err")
		return
	}

	err = result.PushRow("0", map[string]string{"firewallConfigResult": string(dataBytes)}, false, "")
	return
}
