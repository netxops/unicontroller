package processor

type ProcessStep struct {
	phaseAction PhaseProcessAction
	phase       int
	result      AbstractMatchResult
	cli         string
	cmdList     interface{}
	rule        string
}

type PhaseProcessAction int

const (
	_ PhaseProcessAction = iota
	PHASE_MATCHED
	PHASE_GENERATED
)

type StepIterator struct {
	phaseS  []string
	process *NodeProcessor
	index   int
}

func NewProcessStep(phase int) *ProcessStep {
	return &ProcessStep{
		phase: phase,
	}
}

func (step ProcessStep) GetPhaseAction() PhaseProcessAction {
	return step.phaseAction
}

func (step ProcessStep) GetPhase() int {
	return step.phase
}

func (step ProcessStep) GetResult() AbstractMatchResult {
	return step.result
}

func (step ProcessStep) GetCli() string {
	return step.cli
}

func (step ProcessStep) GetRule() string {
	return step.rule
}

func (step ProcessStep) GetCmdList() interface{} {
	return step.cmdList
}

func (step *ProcessStep) WithMatchResult(result AbstractMatchResult) *ProcessStep {
	step.result = result
	return step
}

func (step *ProcessStep) WithPhaseAction(action PhaseProcessAction) *ProcessStep {
	step.phaseAction = action
	return step
}

func (step *ProcessStep) WithCmdList(cmdList interface{}) *ProcessStep {
	step.cmdList = cmdList
	return step
}

func (step *ProcessStep) WithCli(cli string) *ProcessStep {
	step.cli = cli
	return step
}

func (step *ProcessStep) WithRule(rule string) *ProcessStep {
	step.rule = rule
	return step
}

func (it *StepIterator) HasNext() bool {
	if it.index < len(it.phaseS) {
		return true
	}

	return false
}

func (it *StepIterator) Next() (string, *ProcessStep) {
	stepName := it.phaseS[it.index]
	it.index++

	return stepName, it.process.steps[stepName]
}
