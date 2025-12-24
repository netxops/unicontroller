package processor

import "github.com/influxdata/telegraf/controller/pkg/nodemap/api"

type AbstractMatchResult interface {
	FromPort() api.Port
	OutPort() api.Port
	Action() int
	Name() string
	Cli() string
}

type MatchResult struct {
	fromPort api.Port
	outPort  api.Port
	action   int
	name     string
	cli      string
}

func (r *MatchResult) SetFromPort(fromPort api.Port) {
	r.fromPort = fromPort
}

func (r *MatchResult) SetOutPort(outPort api.Port) {
	r.outPort = outPort
}

func (r *MatchResult) SetAction(action int) {
	r.action = action
}

func (r *MatchResult) SetName(name string) {
	r.name = name
}

func (r *MatchResult) SetCli(cli string) {
	r.cli = cli
}

func (r *MatchResult) FromPort() api.Port {
	return r.fromPort
}

func (r *MatchResult) OutPort() api.Port {
	return r.outPort
}

func (r *MatchResult) Action() int {
	return r.action
}

func (r *MatchResult) Name() string {
	return r.name
}

func (r *MatchResult) Cli() string {
	return r.cli
}
