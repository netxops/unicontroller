package lb

import (
	"context"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/lb"
	F5 "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/lb/f5"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/netxops/utils/flexrange"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/tools"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/netxops/utils/policy"
)

type LBProcessor struct {
	inInterfaces []lb.Interface
	state        string
	nodeType     api.NodeType
	processor.NodeProcessor
}

type LBProcessResult struct {
	Virtual     string   `json:"virtual" mapstructure:"virtual"`
	Partition   string   `json:"partition" mapstructure:"partition"`
	Dst         string   `json:"dst" mapstructure:"dst"`
	Dport       string   `json:"dport" mapstructure:"dport"`
	Pool        string   `json:"pool" mapstructure:"pool"`
	AutoMap     bool     `json:"autoMap" mapstructure:"autoMap"`
	State       []string `json:"state" mapstructure:"state"`
	Nodes       []string `json:"nodes" mapstructure:"nodes"`
	RouteDomain string   `json:"routeDomain" mapstructure:"routeDomain"`
	NodePort    string   `json:"nodePort" mapstructure:"nodePort"`
	ErrMsg      string   `json:"errMsg" mapstructure:"errMsg"`
}

type LBPhase int

const (
	INPUT_NAT LBPhase = iota
	INPUT_POLICY
	OUTPUT_POLICY
	OUTPUT_NAT
)

var (
	lpPhaseList = []string{"INPUT_NAT", "INPUT_POLICY", "OUTPUT_POLICY", "OUTPUT_NAT"}
)

func (lp LBPhase) String() string {
	return []string{"INPUT_NAT", "INPUT_POLICY", "OUTPUT_POLICY", "OUTPUT_NAT"}[lp]
	// return []string{"DNAT", "安全策略", "出向策略", "SNAT"}[fp]
}

func NewLBPhase(phase string) LBPhase {
	for index, t := range lpPhaseList {
		if strings.ToUpper(t) == strings.ToUpper(phase) {
			return LBPhase(index)
		}
	}
	panic(fmt.Sprintf("unsupport LBPhase type: %s", phase))
}

func NewF5Processor(node api.Node, inEntry policy.PolicyEntryInf) *LBProcessor {
	lp := LBProcessor{}
	lp.SetStepList(lpPhaseList)

	lp.SetInEntry(inEntry)
	lp.SetNode(node)
	lp.SetSteps(map[string]*processor.ProcessStep{})
	if inEntry.(*policy.Intent).RealIp != "" {
		lp.WithInputNat()
	} else if inEntry.(*policy.Intent).Snat != "" {
		lp.WithOutputNat()
	}
	return &lp
}

func (lp *LBProcessor) WithInputNat() *LBProcessor {
	lp.GetSteps()[INPUT_NAT.String()] = processor.NewProcessStep(int(INPUT_NAT))
	return lp
}

func (lp *LBProcessor) WithOutputNat() *LBProcessor {
	lp.GetSteps()[OUTPUT_NAT.String()] = processor.NewProcessStep(int(OUTPUT_NAT))
	return lp
}

func (lp *LBProcessor) MakeTemplates(ctx context.Context, intent *policy.Intent, inPort api.Port, vrf api.Vrf, force bool) (result LBProcessResult) {
	logger := lp.GetLogger()
	//vrfs := lp.GetNode().Vrfs()
	nodeHost := lp.GetNode().CmdIp()
	//node := lp.GetNode().(LBNode)
	dst := intent.Dst()
	var cidrs []*network.IPNet
	if dst.HasIPv4() {
		ipv4s := dst.IPv4()
		drInfo := ipv4s.DataRange()
		l := drInfo.List()
		ip1 := network.NewIPFromInt(tools.CopyInt(l[0].(flexrange.EntryInt).Low()), network.IPv4)
		ip2 := network.NewIPFromInt(tools.CopyInt(l[0].(flexrange.EntryInt).High()), network.IPv4)
		rg := network.NewIPRangeFromInt(ip1.Int(), ip2.Int(), network.IPv4)
		cidrs = rg.CIDRs()
	}

	if dst.HasIPv6() {
		ipv6s := dst.IPv6()
		drInfo := ipv6s.DataRange()
		l := drInfo.List()
		ip1 := network.NewIPFromInt(tools.CopyInt(l[0].(flexrange.EntryInt).Low()), network.IPv6)
		ip2 := network.NewIPFromInt(tools.CopyInt(l[0].(flexrange.EntryInt).High()), network.IPv6)
		rg := network.NewIPRangeFromInt(ip1.Int(), ip2.Int(), network.IPv6)
		cidrs = rg.CIDRs()
	}
	if len(cidrs) != 1 {
		result.ErrMsg = "=====****  F5 not support multiple cidr network  ****====="
		logger.Error(result.ErrMsg)
		return
	}

	intent.Service().MustOneServiceEntry()

	formater, _ := tools.NewPairFormatter("%s %s")
	ports := intent.Service().DstPortList(formater)
	if len(ports) != 1 {
		result.ErrMsg = "=====****  F5 can only support one port  ****====="
		logger.Error(result.ErrMsg)
		return
	}

	adapter := ctx.Value(nodeHost).(*F5.F5Adapter)
	virtuals := adapter.Virtuals
	pools := adapter.Pools
	routeDomains := adapter.RouteDomains

	vs, pool, _, nomatchs := matchVsPolicyentry(*intent, vrf.Name(), virtuals, routeDomains, pools)
	var routeDomain *lb.RouteDomain
	var partition string
	for _, r := range routeDomains {
		if r.Vrf == vrf.Name() {
			routeDomain = &r
			partition = r.Partition
			break
		}
	}
	if routeDomain == nil {
		result.ErrMsg = fmt.Sprintf("通过vrf:%s获取route domain失败", vrf.Name())
		logger.Error(result.ErrMsg)
		return
	}
	if partition == "" {
		result.ErrMsg = fmt.Sprintf("通过vrf:%s获取route domain -- parttion失败", vrf.Name())
		logger.Error(result.ErrMsg)
		return
	}

	vsName := ""
	if vs == nil {
		vsName = strings.Join([]string{intent.TicketNumber, intent.Service().String()}, "_")
		if pool.Name == "" {
			pool.Name = strings.Join([]string{vsName}, "_POOL")
		}
		result.State = append(result.State, lb.CREATE_POOL.String(), lb.CREATE_VS.String(), lb.ADD_NODE.String())
	} else {
		vsName = vs.Name
		if pool.Name == "" {
			pool.Name = strings.Join([]string{vsName}, "_POOL")
			result.State = append(result.State, lb.CREATE_POOL.String(), lb.ADD_NODE.String())
		} else {
			result.State = append(result.State, lb.ADD_NODE.String())
		}
	}

	result.Virtual = vsName
	result.Partition = partition
	result.Dst = intent.Dst().String()
	result.Dport = ports[0]
	result.Pool = pool.Name

	if intent.Snat == "" || strings.ToUpper(intent.Snat) == strings.ToUpper("autoMap") {
		result.AutoMap = true
	} else {
		result.AutoMap = false
	}

	if len(result.State) == 1 && result.State[0] == lb.ADD_NODE.String() {
		result.Nodes = nomatchs
	} else {
		result.Nodes = intent.Nodes
	}

	result.RouteDomain = routeDomain.ID
	result.NodePort = intent.NodePort
	return
}

func matchVsPolicyentry(intent policy.Intent, vrf string, virtuals map[int]map[string]lb.Virtual, routeDomains map[string]lb.RouteDomain,
	pools map[string]lb.Pool) (vs *lb.Virtual, pool lb.Pool, members []string, nomatch []string) {
	if len(routeDomains) == 0 || len(virtuals) == 0 {
		return
	}
	//rds := []lb.RouteDomain{}
	//partitions := []string{}
	var partition string
	for _, rd := range routeDomains {
		if rd.Vrf == vrf {
			//partitions = append(partitions, rd.Partition)
			//rds = append(rds, rd)
			partition = rd.Partition
			break
		}
	}

	if partition == "" {
		return
	}

	for index := 0; index < len(lb.MATRIX); index++ {
		vsList := virtuals[index+1]
		if vsList == nil || len(vsList) == 0 {
			continue
		}

		for _, vsValue := range vsList {
			if !vsValue.Enabled || vsValue.Vrf != vrf || vsValue.Partition.Name != partition {
				continue
			}
			members = []string{}
			nomatch = []string{}
			if vsValue.Match(intent, true) {
				if vsValue.TranslateAddress == "disabled" {
					continue
				}
				var p *lb.Pool
				for _, poolValue := range pools {
					if poolValue.Name == vsValue.Pool.Name {
						p = &poolValue
						break
					}
				}
				if p != nil {
					if len(intent.Nodes) > 0 {
						for _, n := range intent.Nodes {
							memMatch := false
							for _, mem := range p.PoolMembers {
								if mem.PoolName == n {
									memMatch = true
									break
								}
							}
							if memMatch {
								members = append(members, n)
							} else {
								nomatch = append(nomatch, n)
							}
						}
					} else {
						for _, m := range p.PoolMembers {
							members = append(members, m.FullPath)
						}
					}
				}

				if p == nil {
					p = &lb.Pool{}
				}
				return &vsValue, *p, members, nomatch
			}
		}
	}
	return
}
