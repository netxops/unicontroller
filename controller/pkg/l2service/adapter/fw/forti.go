package fw

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	fortiEnum "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/mitchellh/mapstructure"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	clitask "github.com/netxops/utils/task"
)

type Forti struct{}

func (a Forti) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	fmt.Printf("--------remoteInfo-------%#v\n", remote)

	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "FORTI_CONFIG":
		result, err = a.config(remote, taskConfig, options)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}

func (a Forti) config(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*clitask.Table, error) {
	cmds := []string{}
	for _, option := range options {
		for _, op := range option.([]interface{}) {
			if opVal, ok := op.(string); ok {
				cmds = append(cmds, opVal)
			}
		}
	}

	if len(cmds) == 0 {
		return nil, errors.New("asa commands not received, command is empty")
	}
	return fortiConfig(terminalmode.FortiGate, remote, taskConfig, cmds)
}

func fortiConfig(deviceType terminalmode.DeviceType, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, params []string) (result *clitask.Table, err error) {
	base := &terminal.BaseInfo{
		Host:     remote.Ip,
		Username: remote.Username,
		Password: remote.Password,
		//PrivateKey: remote.PrivateKey,
		Telnet:   false,
		AuthPass: remote.AuthPass,
		Port:     remote.Meta.SSHPort,
	}
	exec := terminal.NewExecute(terminalmode.CONFIG, deviceType, base)
	fmt.Println("forti method params======>", params)
	var cmds []*terminalmode.Command
	//params = []string{`config firewall vip`, `edit "VIP_9.1.1.12_IP_port1"`, `set extip 9.1.1.12`, `set mappedip "89.1.1.9"`, `set extintf "port1"`, `next`, `end`}
	policyMap, maxId, err := processPolicyId(base, remote.Token)
	if err != nil {
		return
	}
	var policyId int64
	var hasGetId bool
	for index, op := range params {
		if strings.Contains(op, "${ID}") {
			if hasGetId {
				op = strings.ReplaceAll(op, "${ID}", fmt.Sprintf("%d", policyId))
			} else {
				policyId, maxId, err = calcPolicyId(params[index+1], policyMap, maxId)
				if err != nil {
					return
				}
				hasGetId = true
				op = strings.ReplaceAll(op, "${ID}", fmt.Sprintf("%d", policyId))
			}
		}
		key := fmt.Sprintf("%s_%d", op, index+1)
		cmd := terminalmode.NewCommand(op, "", 15, key, "")
		exec.AddCommand(cmd)
		cmds = append(cmds, cmd)
	}

	for index, cmd := range cmds {
		fmt.Println(fmt.Sprintf("cmd[%d]======>%s", index, cmd.Command))
	}

	exec.Id = uuid.Must(uuid.NewV4()).String()

	result = clitask.NewEmptyTableWithKeys([]string{"firewallConfigResult"})
	exec.Prepare(false)
	r := exec.Run(true)
	if r.Error() != nil {
		err = r.Error()
		return
	}

	fmt.Println("=====final result ==========")

	dataBytes, err := json.Marshal(r)
	if err != nil {
		err = errors.New("forti config result trans err")
		return
	}

	err = result.PushRow("0", map[string]string{"firewallConfigResult": string(dataBytes)}, false, "")
	return
}

func processPolicyId(baseInfo *terminal.BaseInfo, token string) (mp map[string]int64, maxIdInt int64, err error) {
	fortiInfo := session.NewDeviceBaseInfo(baseInfo.Host, baseInfo.Username, baseInfo.Password, terminalmode.FortiGate.String(), "", 22)
	fortiInfo.WithToken(token)
	fortiAdapter := forti.NewFortiAdapter(fortiInfo, "")
	client, _ := fortiAdapter.CreateClient()
	mp = make(map[string]int64)
	policies, err := fortiAdapter.GetResponseByApi(client, fortiEnum.FirewallPolicy)
	if err != nil {
		return
	}
	rs := policies["results"]
	if _, ok := rs.([]any); ok {
		resArr := rs.([]any)
		for _, res := range resArr {
			result := &dto.ForiRespResult{}
			err = mapstructure.Decode(res, result)
			if err != nil {
				return
			}
			if maxIdInt <= *result.PolicyId {
				maxIdInt = *result.PolicyId
			}
			mp[result.Name] = *result.PolicyId
		}
		return
	} else {
		return mp, maxIdInt, errors.New("forti policy remote http result not to transform")
	}
}

func calcPolicyId(policyName string, policyMap map[string]int64, maxId int64) (policyId int64, newMaxId int64, err error) {

	for name := range policyMap {

		if fmt.Sprintf("set name \"%s\"", name) == policyName {
			return policyMap[name], maxId, nil
		}
	}

	policyNameArr := strings.Split(policyName, " ")
	newPolicyName := strings.ReplaceAll(policyNameArr[2], "\"", "")
	policyMap[newPolicyName] = maxId + 1
	return policyMap[newPolicyName], policyMap[newPolicyName], nil
}
