package firewall

import (
	"encoding/json"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/netxops/utils/policy"
)

type ProcessStep struct {
	// need   bool
	phaseAction PhaseProcessAction
	phase       FirewallPhase
	result      processor.AbstractMatchResult
	cli         string
	cmdList     interface{}
}

func (step *ProcessStep) MarshalJSON() ([]byte, error) {
	var result processor.AbstractMatchResult
	if step.cli == "" {
		result = step.result
	}
	return json.Marshal(&struct {
		PhaseAction string
		Phase       string
		MatchResult processor.AbstractMatchResult
		Cli         string
	}{
		PhaseAction: step.phaseAction.String(),
		Phase:       step.phase.String(),
		MatchResult: result,
		Cli:         step.cli,
	})
}

func (step *ProcessStep) UnmarshalJSON(b []byte) error {
	//var result FirewallMatchResult
	//if step.cli == "" {
	//	result = step.result
	//}

	type ts struct {
		PhaseAction string
		Phase       string
		MatchResult processor.AbstractMatchResult
		Cli         string
	}

	tsMod := &ts{}
	if err := json.Unmarshal(b, &tsMod); err != nil {
		return err
	}

	step.phaseAction = NewPhaseProcessAction(tsMod.PhaseAction)
	step.phase = NewFirewallPhase(tsMod.Phase)
	step.cli = tsMod.Cli
	step.result = tsMod.MatchResult
	return nil
}

func (step *ProcessStep) WithCmdList(cmdList interface{}) *ProcessStep {
	step.cmdList = cmdList

	return step
}

func (step *ProcessStep) CmdList() interface{} {
	return step.cmdList
}

func (step *ProcessStep) WithPhaseAction(action PhaseProcessAction) *ProcessStep {
	step.phaseAction = action
	return step
}

func (step *ProcessStep) PhaseAction() PhaseProcessAction {
	return step.phaseAction
}

func (step *ProcessStep) WithMatchResult(result processor.AbstractMatchResult) *ProcessStep {
	step.result = result
	return step
}

func (step *ProcessStep) MatchResult() processor.AbstractMatchResult {
	return step.result
}

func (step *ProcessStep) WithCli(cli string) *ProcessStep {
	step.cli = cli
	return step
}

func (step *ProcessStep) Cli() string {
	return step.cli
}

func (step *ProcessStep) Phase() FirewallPhase {
	return step.phase
}

// POLICY_DENY Action = iota + 1
// POLICY_PERMIT
// POLICY_IMPLICIT_PERMIT
// POLICY_IMPLICIT_DENY
func (step *ProcessStep) IsMeetIntent(intent *policy.Intent) bool {
	if step.result == nil {
		return false
	}
	if step.phase == INPUT_POLICY || step.phase == OUTPUT_POLICY {
		if step.result.Action() == int(POLICY_IMPLICIT_PERMIT) || step.result.Action() == int(POLICY_PERMIT) {
			return true
		}
		return false
	} else if step.phase == INPUT_NAT {
		// translated := step.result.(*NatMatchResult).translate
		// tranDst := translated.Dst()
		// s := translated.Service()
		// tranService := s.NewServiceWithEmptyL4Port(true)
		//
		// if intent.RealIp == "" {
		// panic(fmt.Sprintf("snat is empty: %+v", intent))
		// }
		//
		// realService := &service.Service{}
		// if intent.RealPort == "" {
		// port, err := strconv.Atoi(intent.RealPort)
		// if err != nil {
		// panic(err)
		// }
		//
		// l4port, err := service.NewL4Port(service.EQ, port, -1, 0)
		// if err != nil {
		// panic(err)
		// }
		//
		// l4service, err := service.NewL4Service(tranService.Protocol(), l4port, nil)
		// if err != nil {
		// panic(err)
		// }
		// realService.Add(l4service)
		// } else {
		// ipL3, _ := service.NewL3Protocol(service.IP)
		// realService.Add(ipL3)
		// }
		//
		// realIp := network.NewNetworkGroup()
		// net, err := network.NewNetworkFromString(intent.RealIp)
		// if err != nil {
		// panic(err)
		// }
		// realIp.Add(net)
		//
		// if !tranDst.Same(realIp) {
		// return false
		// }

		return false
	}

	return false
}
