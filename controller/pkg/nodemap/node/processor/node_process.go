package processor

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/tools"
	"go.uber.org/zap"
)

//
// const (
// INPUT_NAT = iota
// INPUT_POLICY
// OUTPUT_POLICY
// OUTPUT_NAT
// )

type NodeProcessor struct {
	inEntry  policy.PolicyEntryInf
	node     api.Node
	stepList []string
	steps    map[string]*ProcessStep
	logger   zap.Logger
}

func (np *NodeProcessor) SetStepList(list []string) error {
	if len(np.stepList) > 0 {
		return fmt.Errorf("stepList is not empty")
	}

	np.stepList = append(np.stepList, list...)
	return nil
}

func (np *NodeProcessor) GetInEntry() policy.PolicyEntryInf {
	return np.inEntry
}

func (np *NodeProcessor) GetNode() api.Node {
	return np.node
}

func (np *NodeProcessor) GetSteps() map[string]*ProcessStep {
	return np.steps
}

func (np *NodeProcessor) GetLogger() zap.Logger {
	return np.logger
}

func (np *NodeProcessor) SetInEntry(inEntry policy.PolicyEntryInf) {
	np.inEntry = inEntry
}

func (np *NodeProcessor) SetNode(node api.Node) {
	np.node = node
}

func (np *NodeProcessor) SetSteps(steps map[string]*ProcessStep) {
	for k, _ := range steps {
		if !tools.Contains(np.stepList, k) {
			panic(fmt.Errorf("k '%q' is not in '%q'", k, np.stepList))
		}
	}

	np.steps = steps
}

func (np *NodeProcessor) SetLogger(logger zap.Logger) {
	np.logger = logger
}

func (np *NodeProcessor) Iterator() *StepIterator {
	iterator := StepIterator{
		index:   0,
		process: np,
	}

	// var phaseRange []int
	// switch np.node.NodeType() {
	// case api.FIREWALL:
	// phaseRange = []int{INPUT_NAT, INPUT_POLICY, OUTPUT_POLICY, OUTPUT_NAT}
	// case api.LB:
	// case api.ROUTER:
	//
	// }
	for _, stepName := range np.stepList {
		if np.steps[stepName] != nil {
			iterator.phaseS = append(iterator.phaseS, stepName)
		}
	}

	return &iterator
}

//func MakeFirewallTemplates(processor firewall.FirewallProcess, ctx context.Context, intent *policy.Intent, inPort api.Port, vrf api.Vrf, force bool) (translateTo *policy.Intent, cmdList []interface{}, additionCli []string) {
//	return processor.MakeTemplates(ctx, intent, inPort, vrf, force)
//}
//
//func MakeLBTemplates(processor lb.LBProcessor, ctx context.Context, intent *policy.Intent, inPort api.Port, vrf api.Vrf, force bool) (translateTo *policy.Intent, cmdList []interface{}, additionCli []string) {
//	return processor.MakeTemplates(ctx, intent, inPort, vrf, force)
//}
