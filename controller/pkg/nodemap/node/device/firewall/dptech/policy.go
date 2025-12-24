package dptech

import (
	"encoding/json"
	"fmt"
	"reflect"
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
	cli          string
	name         string
	id           string
	ipType       network.IPFamily
	policyEntry  policy.PolicyEntryInf
	node         *DptechNode
	srcZone      []string
	dstZone      []string
	action       firewall.Action
	status       firewall.PolicyStatus
	objects      *DptechObjectSet
	srcAddr      []string
	srcObject    []string
	srcObjectCli []string
	dstAddr      []string
	dstObject    []string
	dstObjectCli []string
	srv          []string
	srvObject    []string
	srvObjectCli []string
	description  string
}

// TypeName 实现 TypeInterface 接口
func (p *Policy) TypeName() string {
	return "DptechPolicy"
}

// policyJSON 用于序列化和反序列化
type policyJSON struct {
	CLI          string                `json:"cli"`
	Name         string                `json:"name"`
	ID           string                `json:"id"`
	IPType       network.IPFamily      `json:"ip_type"`
	PolicyEntry  json.RawMessage       `json:"policy_entry"`
	SrcZone      []string              `json:"src_zone"`
	DstZone      []string              `json:"dst_zone"`
	Action       firewall.Action       `json:"action"`
	Status       firewall.PolicyStatus `json:"status"`
	SrcAddr      []string              `json:"src_addr"`
	SrcObject    []string              `json:"src_object"`
	SrcObjectCli []string              `json:"src_object_cli"`
	DstAddr      []string              `json:"dst_addr"`
	DstObject    []string              `json:"dst_object"`
	DstObjectCli []string              `json:"dst_object_cli"`
	Srv          []string              `json:"srv"`
	SrvObject    []string              `json:"srv_object"`
	SrvObjectCli []string              `json:"srv_object_cli"`
}

// MarshalJSON 实现 JSON 序列化
func (p *Policy) MarshalJSON() ([]byte, error) {
	policyEntryRaw, err := registry.InterfaceToRawMessage(p.policyEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy entry: %v", err)
	}

	return json.Marshal(policyJSON{
		CLI:          p.cli,
		Name:         p.name,
		ID:           p.id,
		IPType:       p.ipType,
		PolicyEntry:  policyEntryRaw,
		SrcZone:      p.srcZone,
		DstZone:      p.dstZone,
		Action:       p.action,
		Status:       p.status,
		SrcAddr:      p.srcAddr,
		SrcObject:    p.srcObject,
		SrcObjectCli: p.srcObjectCli,
		DstAddr:      p.dstAddr,
		DstObject:    p.dstObject,
		DstObjectCli: p.dstObjectCli,
		Srv:          p.srv,
		SrvObject:    p.srvObject,
		SrvObjectCli: p.srvObjectCli,
	})
}

func (plc *Policy) Description() string {
	return plc.description
}

// UnmarshalJSON 实现 JSON 反序列化
func (p *Policy) UnmarshalJSON(data []byte) error {
	var pj policyJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return err
	}

	p.cli = pj.CLI
	p.name = pj.Name
	p.id = pj.ID
	p.ipType = pj.IPType
	p.srcZone = pj.SrcZone
	p.dstZone = pj.DstZone
	p.action = pj.Action
	p.status = pj.Status
	p.srcAddr = pj.SrcAddr
	p.srcObject = pj.SrcObject
	p.srcObjectCli = pj.SrcObjectCli
	p.dstAddr = pj.DstAddr
	p.dstObject = pj.DstObject
	p.dstObjectCli = pj.DstObjectCli
	p.srv = pj.Srv
	p.srvObject = pj.SrvObject
	p.srvObjectCli = pj.SrcObjectCli

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
	return plc.id
}

func (plc *Policy) Cli() string {
	return plc.cli
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
		"IPType":       plc.ipType,
		"ID":           plc.id,
	}
}

func (plc *Policy) parsePolicy(config string, update bool) error {
	regex := `
        security-policy\s+(?P<name>\S+)\s+
        (
            src-zone\s+(?P<from>\S+)\s+dst-zone\s+(?P<to>\S+)\s+
            (
                (src-address\s+
					(
                        (?P<src_any>any) |
                        (address-object\s+(?P<src_addr>\S+)) |
                        (address-group\s+(?P<src_group>\S+)) |
                        (domain\s+(?P<src_domain>\S+)) |
                        (domain-group\s+(?P<src_domain_group>\S+)) |
                        ((?P<src_ip>\S+)\s+mask\s+(?P<src_mask>\S+))
					)
                ) |
                (dst-address\s+
					(
                        (?P<dst_any>any) |
                        (address-object\s+(?P<dst_addr>\S+)) |
                        (address-group\s+(?P<dst_group>\S+)) |
                        (domain\s+(?P<dst_domain>\S+)) |
                        (domain-group\s+(?P<dst_domain_group>\S+)) |
                        ((?P<dst_ip>\S+)\s+mask\s+(?P<dst_mask>\S+))
					)
                ) |
                (service\s+
					(
                        (?P<service_any>any) |
                        (service-object\s+(?P<service>\S+)) |
                        (service-group\s+(?P<service_group>\S+)) |
						(user-define-service\s+(?P<user_define_service>[^\n]+)) 
					)
                ) |
                (action\s+(?P<action>\S+)) |
                (state\s+(?P<state>disable)) |
				(description\s(?P<description>\S+))
            )
		)
    `
	policyRegexMap := map[string]string{
		"regex": regex,
		"name":  "policy",
		"flags": "mx",
		"pcre":  "true",
	}

	policyResult, err := text.SplitterProcessOneTime(policyRegexMap, config)
	if err != nil {
		return fmt.Errorf("failed to parse policy: %v", err)
	}

	projectionMap, err := policyResult.Projection([]string{"from", "to", "src_addr", "src_group", "src_domain", "src_domain_group", "src_ip", "dst_addr", "dst_group", "dst_domain", "dst_domain_group", "dst_ip", "service", "service_group", "user_define_service"}, ",", [][]string{{"src_ip", "src_mask"}, {"dst_ip", "dst_mask"}})
	if err != nil {
		return fmt.Errorf("failed to project policy result: %v", err)
	}

	// 如果 update 为 true，保留现有的策略条目和字段
	var pe policy.PolicyEntryInf
	var src, dst *network.NetworkGroup
	var svc *service.Service

	if update && plc.policyEntry != nil {
		// 更新模式：使用现有的策略条目
		pe = plc.policyEntry
		if pe.Src() != nil {
			src = pe.Src().Copy().(*network.NetworkGroup)
		} else {
			src = network.NewNetworkGroup()
		}
		if pe.Dst() != nil {
			dst = pe.Dst().Copy().(*network.NetworkGroup)
		} else {
			dst = network.NewNetworkGroup()
		}
		if pe.Service() != nil {
			svc = pe.Service().Copy().(*service.Service)
		}
	} else {
		// 创建模式：创建新的策略条目
		pe = policy.NewPolicyEntry()
		src = network.NewNetworkGroup()
		dst = network.NewNetworkGroup()
		// 设置 zone 信息
		plc.srcZone = strings.Split(projectionMap["from"], ",")
		if len(plc.srcZone) == 0 {
			plc.srcZone = []string{"any"}
		}
		plc.dstZone = strings.Split(projectionMap["to"], ",")
		if len(plc.dstZone) == 0 {
			plc.dstZone = []string{"any"}
		}
	}

	// 更新模式下，如果配置中有新的 zone 信息，则合并
	if update && projectionMap["from"] != "" {
		newSrcZones := strings.Split(projectionMap["from"], ",")
		// 合并 zone，避免重复
		zoneMap := make(map[string]bool)
		for _, z := range plc.srcZone {
			zoneMap[z] = true
		}
		for _, z := range newSrcZones {
			if !zoneMap[z] {
				plc.srcZone = append(plc.srcZone, z)
			}
		}
	}
	if update && projectionMap["to"] != "" {
		newDstZones := strings.Split(projectionMap["to"], ",")
		// 合并 zone，避免重复
		zoneMap := make(map[string]bool)
		for _, z := range plc.dstZone {
			zoneMap[z] = true
		}
		for _, z := range newDstZones {
			if !zoneMap[z] {
				plc.dstZone = append(plc.dstZone, z)
			}
		}
	}

	// Parse source address
	if projectionMap["src_addr"] != "" {
		for _, addr := range strings.Split(projectionMap["src_addr"], ",") {
			cli, ng, ok := plc.objects.Network("", addr)
			if !ok {
				return fmt.Errorf("get network failed, zone:%v, network:%s", plc.srcZone, addr)
			}
			src.AddGroup(ng)
			plc.srcObject = append(plc.srcObject, addr)
			plc.srcObjectCli = append(plc.srcObjectCli, cli)
		}
	}
	if projectionMap["src_group"] != "" {
		for _, group := range strings.Split(projectionMap["src_group"], ",") {
			cli, ng, ok := plc.objects.Network("", group)
			if !ok {
				return fmt.Errorf("get network group failed, zone:%v, group:%s", plc.srcZone, group)
			}
			src.AddGroup(ng)
			plc.srcObject = append(plc.srcObject, group)
			plc.srcObjectCli = append(plc.srcObjectCli, cli)
		}
	}
	if projectionMap["src_ip"] != "" {
		for _, ip := range strings.Split(projectionMap["src_ip"], ",") {
			src.AddGroup(mustNetworkGroup(strings.Replace(ip, "-", "/", 1)))
			plc.srcAddr = append(plc.srcAddr, ip)
		}
	}

	// Parse destination address
	// dst 已在前面声明，这里只需要确保不为 nil
	if dst == nil {
		dst = network.NewNetworkGroup()
	}
	if projectionMap["dst_addr"] != "" {
		for _, addr := range strings.Split(projectionMap["dst_addr"], ",") {
			cli, ng, ok := plc.objects.Network("", addr)
			if !ok {
				return fmt.Errorf("get network failed, zone:%v, network:%s", plc.dstZone, addr)
			}
			dst.AddGroup(ng)
			plc.dstObject = append(plc.dstObject, addr)
			plc.dstObjectCli = append(plc.dstObjectCli, cli)
		}
	}
	if projectionMap["dst_group"] != "" {
		for _, group := range strings.Split(projectionMap["dst_group"], ",") {
			cli, ng, ok := plc.objects.Network("", group)
			if !ok {
				return fmt.Errorf("get network group failed, zone:%v, group:%s", plc.dstZone, group)
			}
			dst.AddGroup(ng)
			plc.dstObject = append(plc.dstObject, group)
			plc.dstObjectCli = append(plc.dstObjectCli, cli)
		}
	}
	if projectionMap["dst_ip"] != "" {
		for _, ip := range strings.Split(projectionMap["dst_ip"], ",") {
			dst.AddGroup(mustNetworkGroup(strings.Replace(ip, "-", "/", 1)))
			plc.dstAddr = append(plc.dstAddr, ip)
		}
	}

	// Parse service
	// svc 已在前面声明，这里直接使用
	if projectionMap["service"] != "" {
		for _, s := range strings.Split(projectionMap["service"], ",") {
			cli, srv, ok := plc.objects.Service(s)
			if !ok {
				return fmt.Errorf("get service failed, service:%s", s)
			}
			if svc == nil {
				svc = srv
			} else {
				svc.Add(srv)
			}
			plc.srvObject = append(plc.srvObject, s)
			plc.srvObjectCli = append(plc.srvObjectCli, cli)
		}
	}
	if projectionMap["service_group"] != "" {
		for _, group := range strings.Split(projectionMap["service_group"], ",") {
			cli, srv, ok := plc.objects.Service(group)
			if !ok {
				return fmt.Errorf("get service group failed, group:%s", group)
			}
			if svc == nil {
				svc = srv
			} else {
				svc.Add(srv)
			}
			plc.srvObject = append(plc.srvObject, group)
			plc.srvObjectCli = append(plc.srvObjectCli, cli)
		}
	}

	if projectionMap["user_define_service"] != "" {
		for _, uds := range strings.Split(projectionMap["user_define_service"], ",") {
			fields := strings.Fields(strings.ToLower(uds))
			srv, err := parseProtocolService(fields)
			if err != nil {
				return fmt.Errorf("parse user-define service failed: %v", err)
			}
			if svc == nil {
				svc = srv
			} else {
				svc.Add(srv)
			}
		}
	}

	if projectionMap["service_any"] != "" {
		svc, _ = service.NewServiceFromString("ip")
	}

	// Parse action - 更新模式下，如果配置中没有指定 action，保留现有的
	if action, ok := projectionMap["action"]; ok && action != "" {
		switch action {
		case "permit":
			plc.action = firewall.POLICY_PERMIT
		case "deny":
			plc.action = firewall.POLICY_DENY
		default:
			return fmt.Errorf("unknown action: %s", action)
		}
	} else if !update {
		// 创建模式下，如果没有指定action，返回错误
		return fmt.Errorf("action not specified in policy")
	}

	// Parse state - 更新模式下，如果配置中没有指定 state，保留现有的
	if state, ok := projectionMap["state"]; ok && state == "disable" {
		plc.status = firewall.POLICY_INACTIVE
	} else if !update {
		// 创建模式下，默认设置为激活状态
		plc.status = firewall.POLICY_ACTIVE
	}

	// 更新策略条目
	if src != nil && !src.IsEmpty() {
		pe.AddSrc(src)
	}
	if dst != nil && !dst.IsEmpty() {
		pe.AddDst(dst)
	}
	if svc != nil {
		pe.AddService(svc)
	}

	// 如果所有字段都为空，设置为非激活状态
	if (src == nil || src.IsEmpty()) && (dst == nil || dst.IsEmpty()) && svc == nil {
		plc.status = firewall.POLICY_INACTIVE
	}

	if projectionMap["description"] != "" {
		plc.description = projectionMap["description"]
	}

	plc.policyEntry = pe
	// 更新模式下，追加 CLI 而不是替换
	if update && plc.cli != "" {
		plc.cli = plc.cli + "\n" + config
	} else {
		plc.cli = config
	}
	plc.name = projectionMap["name"]

	return nil
}

type PolicySet struct {
	objects *DptechObjectSet
	node    *DptechNode
	// 第一key为from，第二个key为to
	policySet []*Policy
}

// TypeName 实现 TypeInterface 接口
func (ps *PolicySet) TypeName() string {
	return "DptechPolicySet"
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

func (ps *PolicySet) Match(in, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	for _, plc := range ps.policySet {
		if plc.name == "DMZ_XXB_policy12" {
			fmt.Println("plc.name", plc.name)
		}
		// 检查源区域是否匹配
		srcMatch := false
		for _, src := range plc.srcZone {
			if src == "any" || src == in {
				srcMatch = true
				break
			}
		}
		if !srcMatch {
			continue
		}

		// 检查目标区域是否匹配
		dstMatch := false
		for _, dst := range plc.dstZone {
			if dst == "any" || dst == to {
				dstMatch = true
				break
			}
		}
		if !dstMatch {
			continue
		}

		// 如果源和目标区域都匹配，检查策略是否匹配
		if plc.Match(pe) {
			return true, plc
		}
	}

	return false, nil
}

// GetSourceAddressObject 获取策略使用的源地址对象
func (plc *Policy) GetSourceAddressObject() (firewall.FirewallNetworkObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有源地址对象名称，尝试查找
	if len(plc.srcObject) > 0 {
		objName := plc.srcObject[0]
		// 先尝试从地址对象中查找
		if obj, found := plc.objects.addressObjectSet[objName]; found {
			return obj, true
		}
		// 再尝试从地址组中查找
		if obj, found := plc.objects.addressGroupSet[objName]; found {
			return obj, true
		}
	}

	return nil, false
}

// GetDestinationAddressObject 获取策略使用的目标地址对象
func (plc *Policy) GetDestinationAddressObject() (firewall.FirewallNetworkObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有目标地址对象名称，尝试查找
	if len(plc.dstObject) > 0 {
		objName := plc.dstObject[0]
		// 先尝试从地址对象中查找
		if obj, found := plc.objects.addressObjectSet[objName]; found {
			return obj, true
		}
		// 再尝试从地址组中查找
		if obj, found := plc.objects.addressGroupSet[objName]; found {
			return obj, true
		}
	}

	return nil, false
}

// GetServiceObject 获取策略使用的服务对象
func (plc *Policy) GetServiceObject() (firewall.FirewallServiceObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有服务对象名称，尝试查找
	if len(plc.srvObject) > 0 {
		objName := plc.srvObject[0]
		// 先尝试从服务对象中查找
		if obj, found := plc.objects.serviceMap[objName]; found {
			return obj, true
		}
		// 再尝试从服务组中查找
		if obj, found := plc.objects.serviceGroup[objName]; found {
			return obj, true
		}
	}

	return nil, false
}

// func (ps *PolicySet) addPolicy(plc *Policy) {
// 	// 确保policySet已初始化
// 	// if ps.policySet == nil {
// 	// 	ps.policySet = []*Policy{}
// 	// }

// 	// // 遍历所有源区域
// 	// for _, from := range plc.srcZone {
// 	// 	// 如果源区域不存在，创建一个新的map
// 	// 	if _, ok := ps.policySet[from]; !ok {
// 	// 		ps.policySet[from] = make(map[string][]*Policy)
// 	// 	}

// 	// 	// 遍历所有目标区域
// 	// 	for _, out := range plc.dstZone {
// 	// 		// 将策略添加到对应的源-目标区域组合中
// 	// 		ps.policySet[from][out] = append(ps.policySet[from][out], plc)
// 	// 	}
// 	// }
// 	ps.policySet = append(ps.policySet, plc)
// }

func (ps *PolicySet) addPolicy(plc *Policy) {
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
	sections, err := ps.parseSectionWithGroup(config)
	if err != nil {
		if strings.Contains(err.Error(), "no match") {
			return nil
		}
		return fmt.Errorf("failed to parse sections: %v", err)
	}

	for _, section := range sections {
		if !strings.Contains(section.cli, "src-") {
			continue
		}

		update := false
		for _, plc := range ps.policySet {
			if plc.name == section.name {
				update = true
				err := plc.parsePolicy(section.cli, update)
				if err != nil {
					return fmt.Errorf("failed to parse policy: %v", err)
				}
				break
			}
		}
		if update {
			continue
		}

		plc := &Policy{
			objects: ps.objects,
			node:    ps.node,
		}
		err := plc.parsePolicy(section.cli, false)
		if err != nil {
			return fmt.Errorf("failed to parse policy: %v", err)
		}
		if plc.PolicyEntry() == nil || (plc.PolicyEntry().Src() == nil && plc.PolicyEntry().Dst() == nil && plc.PolicyEntry().Service() == nil) {
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

	// Uncomment the following line if you want to parse deactive policies
	// err = ps.parseDeactive(config)
	// if err != nil {
	//     return fmt.Errorf("failed to parse deactive policies: %v", err)
	// }

	return nil
}

func (ps *PolicySet) parseDeactive(config string) {
	deactiveRegexMap := map[string]string{
		"regex": `deactivate security policies from-zone (?P<from>\S+) to-zone (?P<to>\S+) policy (?P<name>\S+)`,
		"name":  "deactive",
		"flags": "m",
		"pcre":  "true",
	}

	deactiveResult, err := text.SplitterProcessOneTime(deactiveRegexMap, config)
	if err != nil {
		panic(err)
	}

	for it := deactiveResult.Iterator(); it.HasNext(); {
		_, _, deactiveMap := it.Next()

		for _, plc := range ps.policySet {
			// 检查策略的源区域和目标区域是否匹配
			srcMatch := false
			for _, src := range plc.srcZone {
				if src == "any" || src == deactiveMap["from"] {
					srcMatch = true
					break
				}
			}

			dstMatch := false
			for _, dst := range plc.dstZone {
				if dst == "any" || dst == deactiveMap["to"] {
					dstMatch = true
					break
				}
			}

			// 如果源区域、目标区域和名称都匹配，将策略设置为非活动状态
			if srcMatch && dstMatch && plc.name == deactiveMap["name"] {
				plc.status = firewall.POLICY_INACTIVE
				break // 找到匹配的策略后可以退出循环
			}
		}
	}
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

type sectionWithGroup struct {
	name string
	cli  string
}

func (ps *PolicySet) parseSectionWithGroup(config string) ([]sectionWithGroup, error) {
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

	sectionWithGroupList := make([]sectionWithGroup, 0)
	for _, cli := range clis {
		lines := strings.Split(cli, "\n")
		for _, line := range lines {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) < 2 {
				continue
			}
			if parts[0] != "security-policy" {
				continue
			}
			name := parts[1]
			sectionWithGroupList = append(sectionWithGroupList, sectionWithGroup{
				name: name,
				cli:  cli,
			})
			break
		}
	}

	return sectionWithGroupList, nil
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

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallPolicy)(nil)).Elem(), "DptechPolicy", reflect.TypeOf(Policy{}))
}
