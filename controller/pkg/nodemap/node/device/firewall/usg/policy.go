package usg

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
)

type Policy struct {
	cli         string
	name        string
	policyEntry policy.PolicyEntryInf
	node        *UsgNode
	// from         api.Port
	// to           api.Port
	srcZone      []string
	dstZone      []string
	srcAddr      []string
	srcObject    []string
	srcObjectCli []string
	dstAddr      []string
	dstObject    []string
	dstObjectCli []string
	srv          []string
	srvObject    []string
	srvObjectCli []string
	action       firewall.Action
	status       firewall.PolicyStatus
	objects      *UsgObjectSet
	description  string
}

// TypeName 实现 TypeInterface 接口
func (p *Policy) TypeName() string {
	return "UsgPolicy"
}

// policyJSON 用于序列化和反序列化
type policyJSON struct {
	CLI          string                `json:"cli"`
	Name         string                `json:"name"`
	PolicyEntry  json.RawMessage       `json:"policy_entry"`
	SrcZone      []string              `json:"src_zone"`
	DstZone      []string              `json:"dst_zone"`
	SrcAddr      []string              `json:"src_addr"`
	SrcObject    []string              `json:"src_object"`
	SrcObjectCli []string              `json:"src_object_cli"`
	DstAddr      []string              `json:"dst_addr"`
	DstObject    []string              `json:"dst_object"`
	DstObjectCli []string              `json:"dst_object_cli"`
	Srv          []string              `json:"srv"`
	SrvObject    []string              `json:"srv_object"`
	SrvObjectCli []string              `json:"srv_object_cli"`
	Action       firewall.Action       `json:"action"`
	Status       firewall.PolicyStatus `json:"status"`
	Description  string                `json:"description"`
}

// MarshalJSON 实现 JSON 序列化
func (p *Policy) MarshalJSON() ([]byte, error) {
	policyEntryRaw, err := registry.InterfaceToRawMessage[policy.PolicyEntryInf](p.policyEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy entry: %v", err)
	}

	return json.Marshal(policyJSON{
		CLI:          p.cli,
		Name:         p.name,
		PolicyEntry:  policyEntryRaw,
		SrcZone:      p.srcZone,
		DstZone:      p.dstZone,
		SrcAddr:      p.srcAddr,
		SrcObject:    p.srcObject,
		SrcObjectCli: p.srcObjectCli,
		DstAddr:      p.dstAddr,
		DstObject:    p.dstObject,
		DstObjectCli: p.dstObjectCli,
		Srv:          p.srv,
		SrvObject:    p.srvObject,
		SrvObjectCli: p.srvObjectCli,
		Action:       p.action,
		Status:       p.status,
		Description:  p.description,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (p *Policy) UnmarshalJSON(data []byte) error {
	var pj policyJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return err
	}

	p.cli = pj.CLI
	p.name = pj.Name
	p.srcZone = pj.SrcZone
	p.dstZone = pj.DstZone
	p.srcAddr = pj.SrcAddr
	p.srcObject = pj.SrcObject
	p.srcObjectCli = pj.SrcObjectCli
	p.dstAddr = pj.DstAddr
	p.dstObject = pj.DstObject
	p.dstObjectCli = pj.DstObjectCli
	p.srv = pj.Srv
	p.srvObject = pj.SrvObject
	p.srvObjectCli = pj.SrvObjectCli
	p.action = pj.Action
	p.status = pj.Status
	p.description = pj.Description
	// 特殊处理 policyEntry
	policyEntry, err := registry.RawMessageToInterface[policy.PolicyEntryInf](pj.PolicyEntry)
	if err != nil {
		return fmt.Errorf("failed to unmarshal policy entry: %v", err)
	}
	p.policyEntry = policyEntry

	return nil
}

func (plc *Policy) Action() firewall.Action {
	return plc.action
}

func (plc *Policy) Name() string {
	return plc.name
}

func (plc *Policy) ID() string {
	return ""
}

func (plc *Policy) Cli() string {
	return plc.cli
}

func (plc *Policy) Description() string {
	return plc.description
}

func (plc *Policy) PolicyEntry() policy.PolicyEntryInf {
	return plc.policyEntry
}

func (plc *Policy) Match(pe policy.PolicyEntryInf) bool {
	if plc.status == firewall.POLICY_INACTIVE {
		return false
	}

	// 如果策略引用了地址、服务对象，先重新加载这些对象
	if len(plc.srcObject) > 0 || len(plc.dstObject) > 0 || len(plc.srvObject) > 0 {
		// 重新加载源地址对象
		for _, objName := range plc.srcObject {
			_, ng, ok := plc.objects.Network("", objName)
			if ok {
				plc.policyEntry.AddSrc(ng)
			}
		}

		// 重新加载目标地址对象
		for _, objName := range plc.dstObject {
			_, ng, ok := plc.objects.Network("", objName)
			if ok {
				plc.policyEntry.AddDst(ng)
			}
		}

		// 重新加载服务对象
		for _, objName := range plc.srvObject {
			_, srv, ok := plc.objects.Service(objName)
			if ok {
				plc.policyEntry.AddService(srv)
			}
		}
	}

	return plc.policyEntry.Match(pe)
}

func (plc *Policy) FromZones() []string {
	return plc.srcZone
}

func (plc *Policy) ToZones() []string {
	return plc.dstZone
}

func (plc *Policy) FromPorts() []api.Port {
	var ports []api.Port
	for _, port := range plc.node.PortList() {
		portZone := port.(firewall.ZoneFirewall).Zone()
		for _, zone := range plc.srcZone {
			if zone == "any" || zone == portZone {
				ports = append(ports, port)
				break
			}
		}
	}
	return ports
}

func (plc *Policy) ToPorts() []api.Port {
	var ports []api.Port
	for _, port := range plc.node.PortList() {
		portZone := port.(firewall.ZoneFirewall).Zone()
		for _, zone := range plc.dstZone {
			if zone == "any" || zone == portZone {
				ports = append(ports, port)
				break
			}
		}
	}
	return ports
}

func (plc *Policy) Extended() map[string]interface{} {
	return map[string]interface{}{
		"SrcObjectCli": plc.srcObjectCli,
		"DstObjectCli": plc.dstObjectCli,
		"SrvObjectCli": plc.srvObjectCli,
		"SrcZone":      plc.srcZone,
		"DstZone":      plc.dstZone,
		"SrcAddr":      plc.srcAddr,
		"SrcObject":    plc.srcObject,
		"DstAddr":      plc.dstAddr,
		"DstObject":    plc.dstObject,
		"Srv":          plc.srv,
		"SrvObject":    plc.srvObject,
		// "IPType":       plc.ipType,
		// "ID":           plc.id,
	}
}

// GetSourceAddressObject 获取源地址对象
func (plc *Policy) GetSourceAddressObject() (firewall.FirewallNetworkObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有源地址对象名称，尝试查找
	if len(plc.srcObject) > 0 {
		objName := plc.srcObject[0]
		// 尝试从源端口查找
		fromPorts := plc.FromPorts()
		for _, port := range fromPorts {
			if port != nil {
				// 通过对象名称查找
				_, _, found := plc.objects.Network("", objName)
				if found {
					// 在 addressObjectSet 和 addressGroupSet 中查找对象
					for _, obj := range plc.objects.addressObjectSet {
						if obj.Name() == objName {
							return obj, true
						}
					}
					for _, obj := range plc.objects.addressGroupSet {
						if obj.Name() == objName {
							return obj, true
						}
					}
				}
			}
		}
	}

	return nil, false
}

// GetDestinationAddressObject 获取目标地址对象
func (plc *Policy) GetDestinationAddressObject() (firewall.FirewallNetworkObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有目标地址对象名称，尝试查找
	if len(plc.dstObject) > 0 {
		objName := plc.dstObject[0]
		// 尝试从目标端口查找
		toPorts := plc.ToPorts()
		for _, port := range toPorts {
			if port != nil {
				// 通过对象名称查找
				_, _, found := plc.objects.Network("", objName)
				if found {
					// 在 addressObjectSet 和 addressGroupSet 中查找对象
					for _, obj := range plc.objects.addressObjectSet {
						if obj.Name() == objName {
							return obj, true
						}
					}
					for _, obj := range plc.objects.addressGroupSet {
						if obj.Name() == objName {
							return obj, true
						}
					}
				}
			}
		}
	}

	return nil, false
}

// GetServiceObject 获取服务对象
func (plc *Policy) GetServiceObject() (firewall.FirewallServiceObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有服务对象名称，尝试查找
	if len(plc.srvObject) > 0 {
		objName := plc.srvObject[0]
		// 在 serviceMap 和 serviceGroup 中查找对象
		for _, obj := range plc.objects.serviceMap {
			if obj.Name() == objName {
				return obj, true
			}
		}
		for _, obj := range plc.objects.serviceGroup {
			if obj.Name() == objName {
				return obj, true
			}
		}
	}

	return nil, false
}

// func (plc *Policy) parsePolicy(config string) error {
// 	regex := `
//         security-policy\s+(?P<name>\S+)\s+
//         (
//             src-zone\s+(?P<from>\S+)\s+dst-zone\s+(?P<to>\S+)\s+
//             (
//                 (src-address\s+
// 					(
//                         (?P<src_any>any) |
//                         (address-object\s+(?P<src_addr>\S+)) |
//                         (address-group\s+(?P<src_group>\S+)) |
//                         (domain\s+(?P<src_domain>\S+)) |
//                         (domain-group\s+(?P<src_domain_group>\S+)) |
//                         ((?P<src_ip>\S+)\s+mask\s+(?P<src_mask>\S+))
// 					)
//                 ) |
//                 (dst-address\s+
// 					(
//                         (?P<dst_any>any) |
//                         (address-object\s+(?P<dst_addr>\S+)) |
//                         (address-group\s+(?P<dst_group>\S+)) |
//                         (domain\s+(?P<dst_domain>\S+)) |
//                         (domain-group\s+(?P<dst_domain_group>\S+)) |
//                         ((?P<dst_ip>\S+)\s+mask\s+(?P<dst_mask>\S+))
// 					)
//                 ) |
//                 (service\s+
// 					(
//                         (?P<service_any>any) |
//                         (service-object\s+(?P<service>\S+)) |
//                         (service-group\s+(?P<service_group>\S+))
// 					)
//                 ) |
//                 (action\s+(?P<action>\S+)) |
//                 (state\s+(?P<state>disable))
//             )
// 		)
//     `
// 	policyRegexMap := map[string]string{
// 		"regex": regex,
// 		"name":  "policy",
// 		"flags": "mx",
// 		"pcre":  "true",
// 	}

// 	policyResult, err := text.SplitterProcessOneTime(policyRegexMap, config)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse policy: %v", err)
// 	}

// 	projectionMap, err := policyResult.Projection([]string{"from", "to", "src_addr", "src_group", "src_domain", "src_domain_group", "src_ip", "dst_addr", "dst_group", "dst_domain", "dst_domain_group", "dst_ip", "service", "service_group"}, ",", [][]string{{"src_ip", "src_mask"}, {"dst_ip", "dst_mask"}})
// 	if err != nil {
// 		return fmt.Errorf("failed to project policy result: %v", err)
// 	}

// 	// plc.from = &UsgPort{node.NodePort{ZoneName: projectionMap["from"]}}
// 	plc.srcZone = strings.Split(projectionMap["from"], ",")
// 	if len(plc.srcZone) == 0 {
// 		plc.srcZone = []string{"any"}
// 		// plc.from = &UsgPort{node.NodePort{ZoneName: "any"}}
// 	}

// 	plc.dstZone = strings.Split(projectionMap["to"], ",")
// 	if len(plc.dstZone) == 0 {
// 		plc.dstZone = []string{"any"}
// 	}

// 	// Parse source address
// 	src := network.NewNetworkGroup()
// 	if projectionMap["src_addr"] != "" {
// 		for _, addr := range strings.Split(projectionMap["src_addr"], ",") {
// 			_, ng, ok := plc.objects.Network("", addr)
// 			if !ok {
// 				return fmt.Errorf("get network failed, zone:%v, network:%s", plc.srcZone, addr)
// 			}
// 			src.AddGroup(ng)
// 		}
// 	}
// 	if projectionMap["src_group"] != "" {
// 		for _, group := range strings.Split(projectionMap["src_group"], ",") {
// 			_, ng, ok := plc.objects.Network("", group)
// 			if !ok {
// 				return fmt.Errorf("get network group failed, zone:%v, group:%s", plc.srcZone, group)
// 			}
// 			src.AddGroup(ng)
// 		}
// 	}
// 	if projectionMap["src_ip"] != "" {
// 		for _, ip := range strings.Split(projectionMap["src_ip"], ",") {
// 			src.AddGroup(mustNetworkGroup(strings.Replace(ip, "-", "/", 1)))
// 		}
// 	}

// 	// Parse destination address
// 	dst := network.NewNetworkGroup()
// 	if projectionMap["dst_addr"] != "" {
// 		for _, addr := range strings.Split(projectionMap["dst_addr"], ",") {
// 			_, ng, ok := plc.objects.Network("", addr)
// 			if !ok {
// 				return fmt.Errorf("get network failed, zone:%v, network:%s", plc.dstZone, addr)
// 			}
// 			dst.AddGroup(ng)
// 		}
// 	}
// 	if projectionMap["dst_group"] != "" {
// 		for _, group := range strings.Split(projectionMap["dst_group"], ",") {
// 			_, ng, ok := plc.objects.Network("", group)
// 			if !ok {
// 				return fmt.Errorf("get network group failed, zone:%v, group:%s", plc.dstZone, group)
// 			}
// 			dst.AddGroup(ng)
// 		}
// 	}
// 	if projectionMap["dst_ip"] != "" {
// 		for _, ip := range strings.Split(projectionMap["dst_ip"], ",") {
// 			dst.AddGroup(mustNetworkGroup(strings.Replace(ip, "-", "/", 1)))
// 		}
// 	}

// 	// Parse service
// 	var svc *service.Service
// 	if projectionMap["service"] != "" {
// 		for _, s := range strings.Split(projectionMap["service"], ",") {
// 			_, srv, ok := plc.objects.Service(s)
// 			if !ok {
// 				return fmt.Errorf("get service failed, service:%s", s)
// 			}
// 			if svc == nil {
// 				svc = srv
// 			} else {
// 				svc.Add(srv)
// 			}
// 		}
// 	}
// 	if projectionMap["service_group"] != "" {
// 		for _, group := range strings.Split(projectionMap["service_group"], ",") {
// 			_, srv, ok := plc.objects.Service(group)
// 			if !ok {
// 				return fmt.Errorf("get service group failed, group:%s", group)
// 			}
// 			if svc == nil {
// 				svc = srv
// 			} else {
// 				svc.Add(srv)
// 			}
// 		}
// 	}

// 	// Parse action
// 	if action, ok := projectionMap["action"]; ok && action != "" {
// 		switch action {
// 		case "permit":
// 			plc.action = firewall.POLICY_PERMIT
// 		case "deny":
// 			plc.action = firewall.POLICY_DENY
// 		default:
// 			return fmt.Errorf("unknown action: %s", action)
// 		}
// 	} else {
// 		// 如果没有指定action，可以设置一个默认值或返回错误
// 		return fmt.Errorf("action not specified in policy")
// 	}

// 	// Parse state
// 	if state, ok := projectionMap["state"]; ok && state == "disable" {
// 		plc.status = firewall.POLICY_INACTIVE
// 	} else {
// 		plc.status = firewall.POLICY_ACTIVE
// 	}

// 	if src == nil || dst == nil || svc == nil {
// 		plc.status = firewall.POLICY_INACTIVE
// 	}

// 	pe := policy.NewPolicyEntry()
// 	pe.AddSrc(src)
// 	pe.AddDst(dst)
// 	pe.AddService(svc)

// 	plc.policyEntry = pe
// 	plc.cli = config
// 	plc.name = projectionMap["name"]

// 	return nil
// }

type PolicySet struct {
	objects *UsgObjectSet
	node    *UsgNode
	// 第一key为from，第二个key为to
	// policySet map[string]map[string][]*Policy
	policySet []*Policy
}

// TypeName 实现 TypeInterface 接口
func (ps *PolicySet) TypeName() string {
	return "UsgPolicySet"
}

// policySetJSON 用于序列化和反序列化
type policySetJSON struct {
	PolicySet []*Policy `json:"policy_set"`
}

// MarshalJSON 实现 JSON 序列化
func (ps *PolicySet) MarshalJSON() ([]byte, error) {
	return json.Marshal(policySetJSON{
		PolicySet: ps.policySet,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ps *PolicySet) UnmarshalJSON(data []byte) error {
	var psj policySetJSON
	if err := json.Unmarshal(data, &psj); err != nil {
		return err
	}

	ps.policySet = psj.PolicySet

	return nil
}

// func (ps *PolicySet) Match(from, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
// 	if _, ok := ps.policySet[from]; ok {
// 		if _, ok = ps.policySet[from][to]; ok {
// 			plcList := ps.policySet[from][to]
// 			for _, plc := range plcList {
// 				if plc.Match(pe) {
// 					return true, plc
// 				}
// 			}
// 		}
// 	}

// 	return false, nil
// }

func (ps *PolicySet) Match(from, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	for _, plc := range ps.policySet {
		// 检查策略的源区域和目标区域是否匹配
		srcMatch := false
		dstMatch := false

		for _, src := range plc.srcZone {
			if src == from || src == "any" {
				srcMatch = true
				break
			}
		}

		for _, dst := range plc.dstZone {
			if dst == to || dst == "any" {
				dstMatch = true
				break
			}
		}

		// 如果源和目标都匹配，并且策略条目匹配，则返回该策略
		if srcMatch && dstMatch && plc.Match(pe) {
			return true, plc
		}
	}

	// 如果没有找到匹配的策略，返回 false 和 nil
	return false, nil
}

// func (ps *PolicySet) addPolicy(plc *Policy) {
// 	// 确保policySet已初始化
// 	if ps.policySet == nil {
// 		ps.policySet = make(map[string]map[string][]*Policy)
// 	}

// 	// 遍历所有源区域
// 	for _, from := range plc.srcZone {
// 		// 如果源区域不存在，创建一个新的map
// 		if _, ok := ps.policySet[from]; !ok {
// 			ps.policySet[from] = make(map[string][]*Policy)
// 		}

// 		// 遍历所有目标区域
// 		for _, out := range plc.dstZone {
// 			// 将策略添加到对应的源-目标区域组合中
// 			ps.policySet[from][out] = append(ps.policySet[from][out], plc)
// 		}
// 	}
// }

// func (ps *PolicySet) addPolicy(plc *Policy) {
// 	// 确保policySet已初始化
// 	if ps.policySet == nil {
// 		ps.policySet = []*Policy{}
// 	}

// 	// 直接将策略添加到切片中
// 	ps.policySet = append(ps.policySet, plc)
// }

func (ps *PolicySet) addPolicy(plc *Policy) {
	// 确保policySet已初始化
	if ps.policySet == nil {
		ps.policySet = []*Policy{}
	}

	// 查找是否存在同名策略
	for i, existingPlc := range ps.policySet {
		if existingPlc.name == plc.name {
			// 找到同名策略，进行叠加
			mergePolicy(ps.policySet[i], plc)
			return
		}
	}

	// 如果没有找到同名策略，直接添加新策略
	ps.policySet = append(ps.policySet, plc)
}

func mergePolicy(existing *Policy, new *Policy) {
	// 合并源地址
	if new.policyEntry.Src() != nil && !new.policyEntry.Src().IsAny(true) {
		existing.policyEntry.AddSrc(new.policyEntry.Src())
	}

	// 合并目标地址
	if new.policyEntry.Dst() != nil && !new.policyEntry.Dst().IsAny(true) {
		existing.policyEntry.AddDst(new.policyEntry.Dst())
	}

	// 合并服务
	if new.policyEntry.Service() != nil && !new.policyEntry.Service().IsAny(true) {
		existing.policyEntry.AddService(new.policyEntry.Service())
	}
}

func (ps *PolicySet) parseConfig(config string) error {
	// 步骤 1: 提取 security-policy 开头到 # 之间的内容
	securityPolicyRegex := `(?s)security-policy.*?(?:#|$)`
	re := regexp.MustCompile(securityPolicyRegex)
	securityPolicyContent := re.FindString(config)

	if securityPolicyContent == "" {
		return fmt.Errorf("no security-policy content found")
	}

	if !strings.Contains(securityPolicyContent, "rule name") {
		return fmt.Errorf("no rule name found in security-policy")
	}

	sections := text.MustSectionsByRegex(`\s{1}rule name[^\n]+(\s{3}[^\n]+)+`, securityPolicyContent)

	// 步骤 2: 将内容按 rule 进行分组
	// ruleRegex := `(?m)^\s*rule\s+name\s+(\S+)(?:\s*\n(?:(?!rule\s+name).)*)*`
	// ruleRe := regexp.MustCompile(ruleRegex)
	// ruleMatches := ruleRe.FindAllStringSubmatch(securityPolicyContent, -1)

	// if len(ruleMatches) == 0 {
	// 	return fmt.Errorf("no rules found in security-policy")
	// }

	// 步骤 3: 处理每个分组的内容
	for _, ruleContent := range sections.Texts {
		ruleContent = strings.TrimSpace(ruleContent)
		// ruleName := match[1]
		// ruleContent := match[0]
		ruleName := strings.TrimSpace(strings.Replace(strings.Split(ruleContent, "\n")[0], "rule name", "", 1))

		plc := &Policy{
			objects:     ps.objects,
			node:        ps.node,
			name:        ruleName,
			policyEntry: policy.NewPolicyEntry(),
		}

		err := plc.parseRule(ruleContent)
		if err != nil {
			return fmt.Errorf("failed to parse rule %s: %v", ruleName, err)
		}

		if plc.PolicyEntry().Src() == nil && plc.PolicyEntry().Dst() == nil && plc.PolicyEntry().Service() == nil {
			plc.status = firewall.POLICY_INACTIVE
			continue
		}
		if plc.PolicyEntry().Src() == nil {
			plc.PolicyEntry().AddSrc(network.NewAny4Group())
		}
		if plc.PolicyEntry().Dst() == nil {
			plc.PolicyEntry().AddDst(network.NewAny4Group())
		}
		if plc.PolicyEntry().Service() == nil {
			plc.PolicyEntry().AddService(service.NewServiceMust("ip"))
		}

		ps.addPolicy(plc)
	}

	return nil
}

func (plc *Policy) parseRule(ruleContent string) error {
	lines := strings.Split(ruleContent, "\n")

	plc.status = firewall.POLICY_ACTIVE
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "disable" {
			plc.status = firewall.POLICY_INACTIVE
			continue
		}

		if strings.HasPrefix(line, "description") {
			plc.description = strings.TrimSpace(strings.Replace(line, "description", "", 1))
			continue
		}

		parts := strings.Fields(line)
		switch parts[0] {
		case "source-zone":
			plc.srcZone = append(plc.srcZone, parts[1])
		case "destination-zone":
			plc.dstZone = append(plc.dstZone, parts[1])
		case "source-address":
			ng, err := parseAddress(parts, plc.objects)
			if err != nil {
				return err
			}
			plc.policyEntry.AddSrc(ng)
			if parts[1] == "any" {
				plc.srcAddr = append(plc.srcAddr, "any")
			} else if parts[1] == "address-set" {
				plc.srcObject = append(plc.srcObject, parts[2])
				if cli, _, ok := plc.objects.Network("", parts[2]); ok {
					plc.srcObjectCli = append(plc.srcObjectCli, cli)
				}
			} else {
				plc.srcAddr = append(plc.srcAddr, strings.Join(parts[1:], " "))
			}

		case "destination-address":
			ng, err := parseAddress(parts, plc.objects)
			if err != nil {
				return err
			}
			plc.policyEntry.AddDst(ng)

			if parts[1] == "any" {
				plc.dstAddr = append(plc.dstAddr, "any")
			} else if parts[1] == "address-set" {
				plc.dstObject = append(plc.dstObject, parts[2])
				if cli, _, ok := plc.objects.Network("", parts[2]); ok {
					plc.dstObjectCli = append(plc.dstObjectCli, cli)
				}
			} else {
				plc.dstAddr = append(plc.dstAddr, strings.Join(parts[1:], " "))
			}
		case "service":
			srv, err := parsePolicyServiceLine(line, plc.objects)
			if err != nil {
				return err
			}
			plc.policyEntry.AddService(srv)
			if parts[1] == "any" {
				plc.srv = append(plc.srv, "any")
			} else {
				for i := 1; i < len(parts); i++ {
					if parts[i] != "service-set" {
						plc.srv = append(plc.srv, parts[i])
					} else {
						i++
						if i < len(parts) {
							plc.srvObject = append(plc.srvObject, parts[i])
							if cli, _, ok := plc.objects.Service(parts[i]); ok {
								plc.srvObjectCli = append(plc.srvObjectCli, cli)
							}
						}
					}
				}
			}
		case "action":
			switch parts[1] {
			case "permit":
				plc.action = firewall.POLICY_PERMIT
			case "deny":
				plc.action = firewall.POLICY_DENY
			default:
				return fmt.Errorf("unknown action: %s", parts[1])
			}
		}
	}

	if len(plc.srcZone) == 0 {
		plc.srcZone = []string{"any"}
	}
	if len(plc.dstZone) == 0 {
		plc.dstZone = []string{"any"}
	}

	plc.cli = ruleContent
	return nil
}

// func (plc *Policy) parseAddress(parts []string) (*network.NetworkGroup, error) {
// 	isSource := parts[0] == "source-address"
// 	var ng *network.NetworkGroup

// 	// // Initialize policy entry if not already done
// 	// if plc.policyEntry == nil {
// 	// 	plc.policyEntry = policy.NewPolicyEntry()
// 	// }
// 	ng, err := parseAddress(parts, plc.objects)

// 	return nil
// }

// Helper function to check if a string is numeric
func isNumeric(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(s) > 0
}

// Helper function to validate IPv4 prefix length (1-32)
func isValidIPv4PrefixLength(s string) bool {
	if !isNumeric(s) {
		return false
	}

	// Convert to int and check range
	var prefixLen int
	for _, char := range s {
		prefixLen = prefixLen*10 + int(char-'0')
	}

	return prefixLen >= 1 && prefixLen <= 32
}

// Helper function to validate IPv6 prefix length (1-128)
func isValidIPv6PrefixLength(s string) bool {
	if !isNumeric(s) {
		return false
	}

	// Convert to int and check range
	var prefixLen int
	for _, char := range s {
		prefixLen = prefixLen*10 + int(char-'0')
	}

	return prefixLen >= 1 && prefixLen <= 128
}

// func (ps *PolicySet) parseDeactive(config string) {
// 	deactiveRegexMap := map[string]string{
// 		"regex": `deactivate security policies from-zone (?P<from>\S+) to-zone (?P<to>\S+) policy (?P<name>\S+)`,
// 		"name":  "deactive",
// 		"flags": "m",
// 		"pcre":  "true",
// 	}

// 	deactiveResult, err := text.SplitterProcessOneTime(deactiveRegexMap, config)
// 	if err != nil {
// 		panic(err)
// 	}

// 	for it := deactiveResult.Iterator(); it.HasNext(); {
// 		_, _, deactiveMap := it.Next()

// 		if _, ok := ps.policySet[deactiveMap["from"]]; !ok {
// 			panic(fmt.Sprintf("can not get policy: %+v", deactiveMap))
// 		}

// 		if _, ok := ps.policySet[deactiveMap["from"]][deactiveMap["to"]]; !ok {
// 			panic(fmt.Sprintf("can not get policy: %+v", deactiveMap))
// 		}
// 		plcList := ps.policySet[deactiveMap["from"]][deactiveMap["to"]]

// 		for _, plc := range plcList {
// 			if plc.name == deactiveMap["name"] {
// 				plc.status = firewall.POLICY_INACTIVE
// 			}
// 		}
// 	}
// }

func (ps *PolicySet) parseSectionWithGroup(config string) ([]string, error) {
	sectionRegex := `(?P<all>security-policy\s+(?P<name>\S+)\s+[^\n]+)`

	sectionRegexMap := map[string]string{
		"regex": sectionRegex,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
	if err != nil {
		return nil, fmt.Errorf("failed to process section regex: %v", err)
	}

	clis, err := sectionResult.CombinKey([]string{"name"})
	if err != nil {
		return nil, fmt.Errorf("failed to combine keys: %v", err)
	}

	return clis, nil
}

func mustNetworkGroup(s string) *network.NetworkGroup {
	ng, err := network.NewNetworkGroupFromString(s)
	if err != nil {
		panic(err)
	}
	return ng
}

func mustService(port, protocol string) *service.Service {
	s, err := service.NewServiceWithL4(protocol, port, "")
	if err != nil {
		panic(err)
	}
	return s
}

func parseAddress(parts []string, objects *UsgObjectSet) (*network.NetworkGroup, error) {
	var ng *network.NetworkGroup

	switch {
	case len(parts) == 2 && parts[1] == "any":
		// any - Indicate any conditions of ip address set
		ng = network.NewAny4Group()

	case len(parts) == 2 && parts[1] == "address-set":
		// address-set without name - invalid
		return nil, fmt.Errorf("address-set requires a name")

	case len(parts) == 3 && parts[1] == "address-set":
		// address-set <name> - Indicate the address-set
		var ok bool
		_, ng, ok = objects.Network("", parts[2])
		if !ok {
			return nil, fmt.Errorf("address-set not found: %s", parts[2])
		}

	case len(parts) == 2 && parts[1] == "range":
		// range without parameters - invalid
		return nil, fmt.Errorf("range requires start and end IP addresses")

	case len(parts) == 4 && parts[1] == "range":
		var err error
		ng, err = network.NewNetworkGroupFromString(parts[2] + "-" + parts[3])
		if err != nil {
			return nil, fmt.Errorf("invalid IP address range: %s - %s", parts[2], parts[3])
		}

	case len(parts) == 3 && net.ParseIP(parts[1]) != nil && !strings.Contains(parts[1], ":") && isNumeric(parts[2]):
		// X.X.X.X <1-32> - IPv4 address with netmask length
		prefixLen := parts[2]
		if !isValidIPv4PrefixLength(prefixLen) {
			return nil, fmt.Errorf("invalid IPv4 prefix length: %s (must be 1-32)", prefixLen)
		}
		return network.NewNetworkGroupFromString(parts[1] + "/" + prefixLen)

	case len(parts) == 3 && strings.Contains(parts[1], ":") && isNumeric(parts[2]):
		// X:X::X:X <1-128> - IPv6 address with prefix length
		prefixLen := parts[2]
		if !isValidIPv6PrefixLength(prefixLen) {
			return nil, fmt.Errorf("invalid IPv6 prefix length: %s (must be 1-128)", prefixLen)
		}
		return network.NewNetworkGroupFromString(parts[1] + "/" + prefixLen)

	case len(parts) == 3 && net.ParseIP(parts[1]) != nil && net.ParseIP(parts[2]) != nil && !strings.Contains(parts[1], ":"):
		// X.X.X.X X.X.X.X - IPv4 address with wildcard mask
		// Example: 0.0.0.255 represents 24-bit mask
		ip := net.ParseIP(parts[1])
		wildcard := net.ParseIP(parts[2])
		if ip == nil || wildcard == nil {
			return nil, fmt.Errorf("invalid IP address or wildcard mask: %s %s", parts[1], parts[2])
		}

		// Convert wildcard mask to subnet mask
		wildcardBytes := wildcard.To4()
		if wildcardBytes == nil {
			return nil, fmt.Errorf("invalid wildcard mask format: %s", parts[2])
		}

		// Invert wildcard mask to get subnet mask
		subnetMask := make(net.IPMask, 4)
		for i := 0; i < 4; i++ {
			subnetMask[i] = ^wildcardBytes[i]
		}

		// Get CIDR prefix length
		// prefixLen, _ := subnetMask.Size()
		return network.NewNetworkGroupFromString(fmt.Sprintf("%s/%s", parts[1], net.IP(subnetMask).String()))

	case len(parts) == 4 && net.ParseIP(parts[1]) != nil && parts[2] == "mask" && net.ParseIP(parts[3]) != nil:
		// X.X.X.X mask X.X.X.X - IPv4 address with subnet mask
		ip := net.ParseIP(parts[1])
		mask := net.ParseIP(parts[3])
		if ip == nil || mask == nil {
			return nil, fmt.Errorf("invalid IP address or mask: %s %s", parts[1], parts[3])
		}

		return network.NewNetworkGroupFromString(fmt.Sprintf("%s/%s", parts[1], parts[3]))

	default:
		return nil, fmt.Errorf("unrecognized address format: %s", strings.Join(parts, " "))
	}

	return ng, nil
}

func init() {
	// registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallPolicy)(nil)).Elem(), "UsgPolicy", reflect.TypeOf(Policy{}))
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNatRule)(nil)).Elem(), "UsgNatPool", reflect.TypeOf(NatRule{}))
}
