package sangfor

import (
	"fmt"
	"reflect"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
)

var _ firewall.ZoneFirewall = &SangforPort{}

type SangforPort struct {
	node.NodePort
}

func (sp *SangforPort) TypeName() string {
	return "SangforPort"
}

func (sp *SangforPort) Zone() string {
	return sp.NodePort.ZoneName
}

func (sp *SangforPort) WithZone(name string) *SangforPort {
	sp.NodePort.ZoneName = name
	return sp
}

func NewSangforPortFromNodePort(p *node.NodePort) *SangforPort {
	return &SangforPort{
		NodePort: *p,
	}
}

func NewSangforPort(name, tenant string, ip_list map[network.IPFamily][]string, members []api.Member) *SangforPort {
	p := node.NewPort(name, tenant, ip_list, members)
	return &SangforPort{
		NodePort: *p,
	}
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Port)(nil)).Elem(), "SangforPort", reflect.TypeOf(SangforPort{}))
}

func (sangfor *SangforNode) InPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {
	// 打印匹配请求的详细信息
	fmt.Printf("[DEBUG InPacket] 开始策略匹配\n")
	fmt.Printf("  源接口: %s, 目标接口: %s\n", from.Name(), to.Name())
	if entry != nil {
		if src := entry.Src(); src != nil {
			fmt.Printf("  源网络: %s\n", src.String())
		}
		if dst := entry.Dst(); dst != nil {
			fmt.Printf("  目标网络: %s\n", dst.String())
		}
		if svc := entry.Service(); svc != nil {
			fmt.Printf("  服务: %s\n", svc.String())
		}
	}

	// 打印策略总数
	if sangfor.policySet != nil {
		fmt.Printf("[DEBUG InPacket] 策略总数: %d\n", len(sangfor.policySet.policySet))
	} else {
		fmt.Printf("[DEBUG InPacket] 警告: policySet 为 nil\n")
		return firewall.POLICY_IMPLICIT_DENY, nil
	}

	// 调用 PolicySet 的 Match 方法进行策略匹配
	ok, rule := sangfor.policySet.Match(from.Name(), to.Name(), entry)
	if !ok {
		fmt.Printf("[DEBUG InPacket] 未找到匹配的策略，返回 IMPLICIT_DENY\n")
		return firewall.POLICY_IMPLICIT_DENY, nil
	}

	matchedPolicy := rule.(*Policy)
	action := matchedPolicy.Action()
	fmt.Printf("[DEBUG InPacket] 匹配到策略: %s, Action: %d (1=PERMIT, 2=DENY, 3=IMPLICIT_DENY)\n",
		matchedPolicy.Name(), action)
	return action, rule
}

func (sangfor *SangforNode) OutPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {
	// 调用 PolicySet 的 Match 方法进行策略匹配
	ok, rule := sangfor.policySet.Match(from.Name(), to.Name(), entry)
	if !ok {
		return firewall.POLICY_IMPLICIT_DENY, nil
	}
	return rule.(*Policy).Action(), rule
}
