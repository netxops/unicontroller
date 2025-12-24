package firewall

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/tools"
)

const (
	DEFAULT_VRF = "default"
)

type MeetIntentStatus int

const (
	MEET_INIENT_UNKNOWN MeetIntentStatus = iota
	MEET_INTENT_NO
	MEET_INTENT_OK
	MEET_INTENT_MAYBE
)

func (m MeetIntentStatus) String() string {
	return []string{"MEET_INIENT_UNKNOWN", "MEET_INTENT_NO", "MEET_INTENT_OK", "MEET_INTENT_MAYBE"}[m]
}

type Action int

const (
	_ Action = iota
	POLICY_DENY
	POLICY_PERMIT
	POLICY_REJECT
	POLICY_IMPLICIT_PERMIT
	POLICY_IMPLICIT_DENY
	NAT_MATCHED
	NAT_NOMATCHED
)

func (ac Action) String() string {
	return []string{"POLICY_DENY", "POLICY_PERMIT", "POLICY_REJECT", "POLICY_IMPLICIT_PERMIT", "POLICY_IMPLICIT_DENY", "NAT_MATCHED", "NAT_NOMATCHED"}[ac-1]
	// return []string{"策略禁止", "策略允许", "策略拒绝", "默认运行", "默认禁止", "NAT匹配", "NAT未匹配"}[ac-1]
}

func LocateAction(index int) Action {
	switch index {
	case int(POLICY_DENY):
		return POLICY_DENY
	case int(POLICY_PERMIT):
		return POLICY_PERMIT
	case int(POLICY_REJECT):
		return POLICY_REJECT
	case int(POLICY_IMPLICIT_PERMIT):
		return POLICY_IMPLICIT_PERMIT
	case int(POLICY_IMPLICIT_DENY):
		return POLICY_IMPLICIT_DENY
	case int(NAT_MATCHED):
		return NAT_MATCHED
	case int(NAT_NOMATCHED):
		return NAT_NOMATCHED
	}
	return 0
}

type PolicyStatus int

const (
	POLICY_ACTIVE PolicyStatus = iota + 1
	POLICY_INACTIVE
	POLICY_INCOMPLETE
)

func (ps PolicyStatus) String() string {
	return []string{"POLICY_ACTIVE", "POLICY_INACTIVE"}[ps-1]
}

type PhaseProcessAction int

const (
	_ PhaseProcessAction = iota
	PHASE_MATCHED
	PHASE_GENERATED
)

var (
	phaseProcessActionList = []string{"", "PHASE_MATCHED", "PHASE_GENERATED"}
)

func NewPhaseProcessAction(action string) PhaseProcessAction {
	for index, t := range phaseProcessActionList {
		if strings.ToUpper(t) == strings.ToUpper(action) {
			return PhaseProcessAction(index)
		}
	}
	panic(fmt.Sprintf("unsupport PhaseProcessAction type: %s", action))
}

func (pa PhaseProcessAction) String() string {
	return []string{"PHASE_MATCHED", "PHASE_GENERATED"}[pa-1]
	// return []string{"已有配置", "生成配置"}[pa-1]
}

type FirewallPhase int

const (
	INPUT_NAT FirewallPhase = iota
	INPUT_POLICY
	OUTPUT_POLICY
	OUTPUT_NAT
)

var (
	firewallPhaseList = []string{"INPUT_NAT", "INPUT_POLICY", "OUTPUT_POLICY", "OUTPUT_NAT"}
)

func (fp FirewallPhase) String() string {
	return []string{"INPUT_NAT", "INPUT_POLICY", "OUTPUT_POLICY", "OUTPUT_NAT"}[fp]
	// return []string{"DNAT", "安全策略", "出向策略", "SNAT"}[fp]
}

func NewFirewallPhase(phase string) FirewallPhase {
	for index, t := range firewallPhaseList {
		if strings.ToUpper(t) == strings.ToUpper(phase) {
			return FirewallPhase(index)
		}
	}
	panic(fmt.Sprintf("unsupport FirewallPhase type: %s", phase))
}

type NatMatchResult struct {
	policy.Intent
	processor.MatchResult
	//fromPort   api.Port
	//outPort    api.Port
	translate *policy.Intent
	//action     Action
	meetStatus MeetIntentStatus
	rule       FirewallNatRule
}

func (nr NatMatchResult) MarshalJSON() ([]byte, error) {
	var from, out string
	if _, ok := nr.FromPort().(ZoneFirewall); ok {
		from = nr.FromPort().(ZoneFirewall).Zone()
	} else {
		from = nr.FromPort().Name()
	}

	if !tools.IsNil(nr.OutPort()) {
		if _, ok := nr.OutPort().(ZoneFirewall); ok {
			out = nr.OutPort().(ZoneFirewall).Zone()
		} else {
			out = nr.OutPort().Name()
		}
	}

	return json.Marshal(&struct {
		Intent    string
		From      string
		Out       string
		Translate string
		Action    string
		Status    string
		Rule      FirewallNatRule
	}{
		Intent:    nr.Intent.String(),
		From:      from,
		Out:       out,
		Translate: nr.translate.String(),
		Status:    nr.meetStatus.String(),
		Action:    tools.Conditional(nr.Action() != 0, NAT_MATCHED, NAT_NOMATCHED).(Action).String(),
		Rule:      nr.rule,
	},
	)
}

type PolicyMatchResult struct {
	policy.Intent
	processor.MatchResult
	rule FirewallPolicy
}

func (pr PolicyMatchResult) MarshalJSON() ([]byte, error) {
	var from, out string
	if _, ok := pr.FromPort().(ZoneFirewall); ok {
		from = pr.FromPort().(ZoneFirewall).Zone()
	} else {
		from = pr.FromPort().Name()
	}

	if _, ok := pr.OutPort().(ZoneFirewall); ok {
		out = pr.OutPort().(ZoneFirewall).Zone()
	} else {
		out = pr.OutPort().Name()
	}

	return json.Marshal(&struct {
		Intent string
		From   string
		Out    string
		Action Action
		Rule   FirewallPolicy
	}{
		Intent: pr.Intent.String(),
		From:   from,
		Out:    out,
		Action: LocateAction(pr.Action()),
		Rule:   pr.rule,
	})
}

func NewNatResultIntent(intent *policy.Intent) *NatMatchResult {
	result := &NatMatchResult{}
	bs, err := json.Marshal(intent)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(bs, &result.Intent)
	if err != nil {
		panic(err)
	}

	return result
}

func (mr *NatMatchResult) WithFromPort(port api.Port) policy.PolicyEntryInf {
	mr.SetFromPort(port)
	return mr
}

//func (mr *NatMatchResult) FromPort() api.Port {
//	return mr.fromPort
//}

func (mr *NatMatchResult) WithOutPort(port api.Port) policy.PolicyEntryInf {
	mr.SetOutPort(port)
	return mr
}

//func (mr *NatMatchResult) OutPort() api.Port {
//	return mr.outPort
//}

func (mr *NatMatchResult) WithRule(rule FirewallNatRule) policy.PolicyEntryInf {
	mr.rule = rule
	return mr
}

func (mr *NatMatchResult) WithTranslate(intent *policy.Intent) policy.PolicyEntryInf {
	mr.translate = intent
	return mr
}

func (mr *NatMatchResult) WithAction(action Action) policy.PolicyEntryInf {
	mr.SetAction(int(action))
	return mr
}

func (mr *NatMatchResult) WithMeetIntentStatus(status MeetIntentStatus) policy.PolicyEntryInf {
	mr.meetStatus = status
	return mr
}

//func (mr *NatMatchResult) Action() Action {
//	return mr.action
//}

func (mr *NatMatchResult) MeetStatus() MeetIntentStatus {
	return mr.meetStatus
}

func (mr *NatMatchResult) Rule() FirewallNatRule {
	if mr.isNilish(mr.rule) {
		return nil
	}
	return mr.rule
}

//func (mr *NatMatchResult) Cli() string {
//	return mr.rule.Cli()
//}

func (mr *NatMatchResult) RuleCli() string {
	if mr.rule != nil {
		return mr.rule.Cli()
	}

	return ""
}

//func (mr *NatMatchResult) Name() string {
//	return mr.rule.Name()
//}

func (mr *NatMatchResult) TranslateTo() *policy.Intent {
	return mr.translate
}

// policy.Intent
// fromPort   api.Port
// outPort    api.Port
// translate  *policy.Intent
// action     Action
// meetStatus MeetIntentStatus
// rule       FirewallNatRule

func (mr *NatMatchResult) Analysis() {
	if mr.Action() == int(NAT_NOMATCHED) {
		mr.meetStatus = MEET_INTENT_NO
		return
	}

	if mr.Intent.Snat == "" && mr.Intent.RealIp == "" {
		mr.meetStatus = MEET_INTENT_OK
		return
	}

	if mr.Intent.Snat != "" {
		snat := network.NewNetworkGroup()
		if strings.ToLower(mr.Intent.Snat) == "interface" {
			var ip string
			if mr.Intent.Src().IsIPv4() {
				ip = mr.OutPort().(FirewallPort).MainIpv4()
				if ip == "" {
					panic("can not get main ipv4 address")
				}
				ng, _ := network.NewNetworkGroupFromString(ip)
				snat.AddGroup(ng)
			}

			if mr.Intent.Src().IsIPv6() {
				ip = mr.OutPort().(FirewallPort).MainIpv6()
				if ip == "" {
					panic("can not get main ipv6 address")
				}
				ng, _ := network.NewNetworkGroupFromString(ip)
				snat.AddGroup(ng)
			}
		} else {
			ng, _ := network.NewNetworkGroupFromString(mr.Intent.Snat)
			snat.AddGroup(ng)
		}

		tranSrc := mr.translate.Src()
		if tranSrc.MatchNetworkGroup(snat) {
			if !snat.MatchNetworkGroup(tranSrc) {
				mr.meetStatus = MEET_INTENT_MAYBE
			} else {
				mr.meetStatus = MEET_INTENT_OK
			}
		} else {
			mr.meetStatus = MEET_INTENT_NO
		}

	} else if mr.Intent.RealIp != "" {
		intentGen := mr.Intent.GenerateIntentPolicyEntry()
		fmt.Println("intentGen:", intentGen)
		translateGen := mr.translate.GenerateDestinationPolicyEntry()
		fmt.Println("translateGen:", translateGen)

		if translateGen.Match(intentGen) {
			if intentGen.Match(translateGen) {
				mr.meetStatus = MEET_INTENT_OK
			} else {
				mr.meetStatus = MEET_INTENT_MAYBE
			}
		} else {
			mr.meetStatus = MEET_INTENT_NO
		}
	}
}

func NewPolicyResultIntent(intent *policy.Intent) *PolicyMatchResult {
	result := &PolicyMatchResult{}

	pe := intent.Copy().(*policy.Intent)
	result.Intent = *pe

	return result
}

func (mr *PolicyMatchResult) WithFromPort(port api.Port) policy.PolicyEntryInf {
	mr.SetFromPort(port)
	return mr
}

//func (mr *PolicyMatchResult) FromPort() api.Port {
//	return mr.fromPort
//}

func (mr *PolicyMatchResult) WithOutPort(port api.Port) policy.PolicyEntryInf {
	mr.SetOutPort(port)
	return mr
}

//func (mr *PolicyMatchResult) OutPort() api.Port {
//	return mr.outPort
//}

func (mr *PolicyMatchResult) WithRule(rule FirewallPolicy) policy.PolicyEntryInf {
	mr.rule = rule
	return mr
}

func (mr *PolicyMatchResult) WithAction(action Action) policy.PolicyEntryInf {
	mr.SetAction(int(action))
	return mr
}

//func (mr *PolicyMatchResult) Action() Action {
//	return mr.action
//}

func (mr *PolicyMatchResult) Rule() FirewallPolicy {
	return mr.rule
}

//func (mr *PolicyMatchResult) Cli() string {
//	return mr.rule.Cli()
//}
//
//func (mr *PolicyMatchResult) Name() string {
//	return mr.rule.Name()
//}

func (mr *NatMatchResult) isNilish(val any) bool {
	if val == nil {
		return true
	}

	v := reflect.ValueOf(val)
	k := v.Kind()
	switch k {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer,
		reflect.UnsafePointer, reflect.Interface, reflect.Slice:
		return v.IsNil()
	}

	return false
}
