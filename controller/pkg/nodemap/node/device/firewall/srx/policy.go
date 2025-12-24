package srx

import (
	"encoding/json"
	"fmt"
	"reflect"

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
	policyEntry  policy.PolicyEntryInf
	node         *SRXNode
	from         api.Port
	out          api.Port
	action       firewall.Action
	status       firewall.PolicyStatus
	objects      *SRXObjectSet
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
	description  string
}

// TypeName 实现 TypeInterface 接口
func (p *Policy) TypeName() string {
	return "SRXPolicy"
}

// policyJSON 用于序列化和反序列化
type policyJSON struct {
	CLI          string                `json:"cli"`
	Name         string                `json:"name"`
	PolicyEntry  policy.PolicyEntryInf `json:"policy_entry"`
	From         api.Port              `json:"from"`
	Out          api.Port              `json:"out"`
	Action       firewall.Action       `json:"action"`
	Status       firewall.PolicyStatus `json:"status"`
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
	Description  string                `json:"description"`
}

// MarshalJSON 实现 JSON 序列化
func (p *Policy) MarshalJSON() ([]byte, error) {
	return json.Marshal(policyJSON{
		CLI:          p.cli,
		Name:         p.name,
		PolicyEntry:  p.policyEntry,
		From:         p.from,
		Out:          p.out,
		Action:       p.action,
		Status:       p.status,
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
	p.policyEntry = pj.PolicyEntry
	p.from = pj.From
	p.out = pj.Out
	p.action = pj.Action
	p.status = pj.Status
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
	p.description = pj.Description
	return nil
}

func (plc *Policy) Description() string {
	return plc.description
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
			// 尝试从各个zone查找
			found := false
			for _, zone := range plc.srcZone {
				ng, ok := plc.objects.Network(zone, objName)
				if ok {
					plc.policyEntry.AddSrc(ng)
					found = true
					break
				}
			}
			// 如果zone中找不到，尝试从global zone查找
			if !found {
				ng, ok := plc.objects.Network("global", objName)
				if ok {
					plc.policyEntry.AddSrc(ng)
				}
			}
		}

		// 重新加载目标地址对象
		for _, objName := range plc.dstObject {
			// 尝试从各个zone查找
			found := false
			for _, zone := range plc.dstZone {
				ng, ok := plc.objects.Network(zone, objName)
				if ok {
					plc.policyEntry.AddDst(ng)
					found = true
					break
				}
			}
			// 如果zone中找不到，尝试从global zone查找
			if !found {
				ng, ok := plc.objects.Network("global", objName)
				if ok {
					plc.policyEntry.AddDst(ng)
				}
			}
		}

		// 重新加载服务对象
		for _, objName := range plc.srvObject {
			srv, ok := plc.objects.Service(objName)
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

// GetSourceAddressObject 获取策略使用的源地址对象
func (plc *Policy) GetSourceAddressObject() (firewall.FirewallNetworkObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有源地址对象名称，尝试查找
	if len(plc.srcObject) > 0 {
		objName := plc.srcObject[0]
		// 尝试从各个zone查找
		for _, zone := range plc.srcZone {
			if networkMap, ok := plc.objects.zoneAddressBook[zone]; ok {
				if obj, found := networkMap[objName]; found {
					return obj, true
				}
			}
		}
		// 如果zone中找不到，尝试从global zone查找
		if networkMap, ok := plc.objects.zoneAddressBook["global"]; ok {
			if obj, found := networkMap[objName]; found {
				return obj, true
			}
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
		// 尝试从各个zone查找
		for _, zone := range plc.dstZone {
			if networkMap, ok := plc.objects.zoneAddressBook[zone]; ok {
				if obj, found := networkMap[objName]; found {
					return obj, true
				}
			}
		}
		// 如果zone中找不到，尝试从global zone查找
		if networkMap, ok := plc.objects.zoneAddressBook["global"]; ok {
			if obj, found := networkMap[objName]; found {
				return obj, true
			}
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
		if obj, found := plc.objects.serviceMap[objName]; found {
			return obj, true
		}
	}

	return nil, false
}

// func (plc *Policy) parsePolicy(config string) {
// 	regex := `
// 		set\ssecurity\spolicies\s((from-zone\s(?P<from>\S+)\sto-zone\s(?P<to>\S+)\s)|(global\s))policy\s(?P<name>\S+)\s
// 		(
// 			(match\s
// 				(
// 					(source-address\s(?P<src_addr>\S+)) |
// 					(destination-address\s(?P<dst_addr>\S+)) |
// 					(application\s(?P<app>\S+)) |
// 					(?P<src_excluded>source-address-excluded) |
// 					(?P<dst_excluded>destination-address-excluded)
// 				)
// 			) |
// 			((then\s
// 				(
// 					(?P<permit>permit) |
// 					(?P<deny>deny) |
// 					(?P<reject>reject) |
// 					(?P<log>log\s\S+) |
// 				)
// 			) |
// 			( description\s\S+) |
// 			( scheduler-name\s\S+)
// 			)
// 		)
// 	`
// 	policyRegexMap := map[string]string{
// 		"regex": regex,
// 		"name":  "policy",
// 		"flags": "mx",
// 		"pcre":  "true",
// 	}

// 	policyResult, err := text.SplitterProcessOneTime(policyRegexMap, config)
// 	if err != nil {
// 		panic(err)
// 	}

// 	var src, dst *network.NetworkGroup
// 	var service *service.Service

// 	for it := policyResult.Iterator(); it.HasNext(); {
// 		_, _, policyMap := it.Next()
// 		plc.name = policyMap["name"]

// 		if policyMap["src_addr"] != "" {
// 			ng, ok := plc.objects.Network(policyMap["from"], policyMap["src_addr"])
// 			if !ok {
// 				panic(fmt.Sprintf("get network failed, zone:%s, network:%s", policyMap["from"], policyMap["src_addr"]))
// 			}
// 			if src == nil {
// 				src = ng
// 			} else {
// 				src.AddGroup(ng)
// 			}
// 		}
// 		if policyMap["dst_addr"] != "" {
// 			ng, ok := plc.objects.Network(policyMap["to"], policyMap["dst_addr"])
// 			if !ok {
// 				panic(fmt.Sprintf("get network failed, zone:%s, network:%s", policyMap["to"], policyMap["dst_addr"]))
// 			}
// 			if dst == nil {
// 				dst = ng
// 			} else {
// 				dst.AddGroup(ng)
// 			}
// 		}

// 		if policyMap["app"] != "" {
// 			srv, ok := plc.objects.Service(policyMap["app"])

// 			if !ok {
// 				panic(fmt.Sprintf("get application failed, application:%s", policyMap["app"]))
// 			}
// 			if service == nil {
// 				service = srv
// 			} else {
// 				service.Add(srv)
// 			}
// 		}

// 		if policyMap["from"] != "" {
// 			plc.from = plc.node.GetPort(policyMap["from"])
// 		}

// 		if policyMap["to"] != "" {
// 			plc.out = plc.node.GetPort(policyMap["to"])
// 		}

// 		if policyMap["reject"] != "" {
// 			plc.action = firewall.POLICY_REJECT
// 		}

// 		if policyMap["permit"] != "" {
// 			plc.action = firewall.POLICY_PERMIT
// 		}

// 		if policyMap["deny"] != "" {
// 			plc.action = firewall.POLICY_DENY
// 		}

// 		pe := policy.NewPolicyEntry()
// 		pe.AddSrc(src)
// 		pe.AddDst(dst)
// 		pe.AddService(service)

// 		plc.policyEntry = pe

// 	}

// }

func (plc *Policy) parsePolicy(config string) {
	regex := `
        set\ssecurity\spolicies\s((from-zone\s(?P<from>\S+)\sto-zone\s(?P<to>\S+)\s)|(global\s))policy\s(?P<name>\S+)\s
        (
            (match\s
                (
                    (source-address\s(?P<src_addr>\S+)) |
                    (destination-address\s(?P<dst_addr>\S+)) |
                    (application\s(?P<app>\S+)) |
                    (?P<src_excluded>source-address-excluded) |
                    (?P<dst_excluded>destination-address-excluded)
                )
            ) |
            ((then\s
                (
                    (?P<permit>permit) |
                    (?P<deny>deny) |
                    (?P<reject>reject) |
                    (?P<log>log\s\S+) |
                )
            ) | 
            ( description\s(?P<description>\S+) |
            ( scheduler-name\s\S+)
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
		panic(err)
	}

	var src, dst *network.NetworkGroup
	var service *service.Service

	for it := policyResult.Iterator(); it.HasNext(); {
		_, _, policyMap := it.Next()
		plc.name = policyMap["name"]

		if policyMap["from"] != "" {
			plc.srcZone = append(plc.srcZone, policyMap["from"])
			plc.from = plc.node.GetPortByNameOrAlias(policyMap["from"])
		}

		if policyMap["to"] != "" {
			plc.dstZone = append(plc.dstZone, policyMap["to"])
			plc.out = plc.node.GetPortByNameOrAlias(policyMap["to"])
		}

		if policyMap["src_addr"] != "" {
			ng, ok := plc.objects.Network(policyMap["from"], policyMap["src_addr"])
			if !ok {
				panic(fmt.Sprintf("get network failed, zone:%s, network:%s", policyMap["from"], policyMap["src_addr"]))
			}
			if src == nil {
				src = ng
			} else {
				src.AddGroup(ng)
			}
			plc.srcAddr = append(plc.srcAddr, policyMap["src_addr"])
			plc.srcObject = append(plc.srcObject, policyMap["src_addr"])
			// Note: You might need to implement a method to get the CLI representation of the object
			// plc.srcObjectCli = append(plc.srcObjectCli, getObjectCli(policyMap["from"], policyMap["src_addr"]))
		}

		if policyMap["dst_addr"] != "" {
			ng, ok := plc.objects.Network(policyMap["to"], policyMap["dst_addr"])
			if !ok {
				panic(fmt.Sprintf("get network failed, zone:%s, network:%s", policyMap["to"], policyMap["dst_addr"]))
			}
			if dst == nil {
				dst = ng
			} else {
				dst.AddGroup(ng)
			}
			plc.dstAddr = append(plc.dstAddr, policyMap["dst_addr"])
			plc.dstObject = append(plc.dstObject, policyMap["dst_addr"])
			// Note: You might need to implement a method to get the CLI representation of the object
			// plc.dstObjectCli = append(plc.dstObjectCli, getObjectCli(policyMap["to"], policyMap["dst_addr"]))
		}

		if policyMap["app"] != "" {
			srv, ok := plc.objects.Service(policyMap["app"])
			if !ok {
				panic(fmt.Sprintf("get application failed, application:%s", policyMap["app"]))
			}
			if service == nil {
				service = srv
			} else {
				service.Add(srv)
			}
			plc.srv = append(plc.srv, policyMap["app"])
			plc.srvObject = append(plc.srvObject, policyMap["app"])
			// Note: You might need to implement a method to get the CLI representation of the service object
			// plc.srvObjectCli = append(plc.srvObjectCli, getServiceObjectCli(policyMap["app"]))
		}

		if policyMap["reject"] != "" {
			plc.action = firewall.POLICY_REJECT
		}

		if policyMap["permit"] != "" {
			plc.action = firewall.POLICY_PERMIT
		}

		if policyMap["deny"] != "" {
			plc.action = firewall.POLICY_DENY
		}
		if policyMap["description"] != "" {
			plc.description = policyMap["description"]
		}

		pe := policy.NewPolicyEntry()
		pe.AddSrc(src)
		pe.AddDst(dst)
		pe.AddService(service)

		plc.policyEntry = pe
	}

	plc.cli = config
}

type PolicySet struct {
	objects *SRXObjectSet
	node    *SRXNode
	// 第一key为from，第二个key为to
	policySet map[string]map[string][]*Policy
}

// TypeName 实现 TypeInterface 接口
func (ps *PolicySet) TypeName() string {
	return "SRXPolicySet"
}

// policySetJSON 用于序列化和反序列化
type policySetJSON struct {
	PolicySet map[string]map[string][]*Policy `json:"policy_set"`
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

func (ps *PolicySet) Match(from, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	if _, ok := ps.policySet[from]; ok {
		if _, ok = ps.policySet[from][to]; ok {
			plcList := ps.policySet[from][to]
			for _, plc := range plcList {
				if plc.Match(pe) {
					return true, plc
				}
			}
		}
	}

	return false, nil
}

func (ps *PolicySet) addPolicy(plc *Policy) {
	from := plc.from.(*SRXPort).Zone()
	out := plc.out.(*SRXPort).Zone()

	if _, ok := ps.policySet[from]; !ok {
		ps.policySet = map[string]map[string][]*Policy{}
		if _, ok = ps.policySet[from]; !ok {
			ps.policySet[from] = map[string][]*Policy{}
		}
	}

	ps.policySet[from][out] = append(ps.policySet[from][out], plc)
}

func (ps *PolicySet) parseConfig(config string) {
	// parseSection(config, sectionRegex, "all")
	sections := ps.parseSectionWithGroup(config)

	for _, section := range sections {
		plc := &Policy{
			objects: ps.objects,
			node:    ps.node,
		}
		plc.parsePolicy(section)
		ps.addPolicy(plc)
	}
	ps.parseDeactive(config)
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
		// 如果解析出错（例如没有匹配），直接返回
		return
	}

	// 如果没有匹配，直接返回
	if deactiveResult == nil || deactiveResult.Len() == 0 {
		return
	}

	for it := deactiveResult.Iterator(); it.HasNext(); {
		_, _, deactiveMap := it.Next()

		if _, ok := ps.policySet[deactiveMap["from"]]; !ok {
			panic(fmt.Sprintf("can not get policy: %+v", deactiveMap))
		}

		if _, ok := ps.policySet[deactiveMap["from"]][deactiveMap["to"]]; !ok {
			panic(fmt.Sprintf("can not get policy: %+v", deactiveMap))
		}
		plcList := ps.policySet[deactiveMap["from"]][deactiveMap["to"]]

		for _, plc := range plcList {
			if plc.name == deactiveMap["name"] {
				plc.status = firewall.POLICY_INACTIVE
			}
		}
	}
}

func (ps *PolicySet) parseSectionWithGroup(config string) []string {
	sectionRegex := `(?P<all>set security policies ((from-zone (?P<from>\S+) to-zone (?P<to>\S+))|(?P<global>global)) policy (?P<name>\S+) [^\n]+)`

	sectionRegexMap := map[string]string{
		"regex": sectionRegex,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
	if err != nil {
		// 如果解析出错（例如没有匹配），返回空切片
		return []string{}
	}

	// 如果没有匹配，返回空切片
	if sectionResult == nil || sectionResult.Len() == 0 {
		return []string{}
	}

	clis, err := sectionResult.CombinKey([]string{"from", "to", "name"})
	if err != nil {
		// 如果组合键出错，返回空切片
		return []string{}
	}
	return clis
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallPolicy)(nil)).Elem(), "SrxPolicy", reflect.TypeOf(Policy{}))
}
