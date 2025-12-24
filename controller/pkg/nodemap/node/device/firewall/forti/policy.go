package forti

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/forti/templates"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/tools"
)

type Policy struct {
	objMap       dto.ForiRespResult
	name         string
	policyEntry  policy.PolicyEntryInf
	node         *FortigateNode
	action       firewall.Action
	cli          string
	status       firewall.PolicyStatus
	objects      *FortiObjectSet
	srcIntf      []string
	dstIntf      []string
	useNat       bool
	usePool      bool
	poolNames    []string
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
	return "FortiPolicy"
}

// policyJSON 用于序列化和反序列化
type policyJSON struct {
	ObjMap       dto.ForiRespResult    `json:"obj_map"`
	Name         string                `json:"name"`
	PolicyEntry  policy.PolicyEntryInf `json:"policy_entry"`
	Action       firewall.Action       `json:"action"`
	Cli          string                `json:"cli"`
	Status       firewall.PolicyStatus `json:"status"`
	SrcIntf      []string              `json:"src_intf"`
	DstIntf      []string              `json:"dst_intf"`
	UseNat       bool                  `json:"use_nat"`
	UsePool      bool                  `json:"use_pool"`
	PoolNames    []string              `json:"pool_names"`
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
		ObjMap:       p.objMap,
		Name:         p.name,
		PolicyEntry:  p.policyEntry,
		Action:       p.action,
		Cli:          p.cli,
		Status:       p.status,
		SrcIntf:      p.srcIntf,
		DstIntf:      p.dstIntf,
		UseNat:       p.useNat,
		UsePool:      p.usePool,
		PoolNames:    p.poolNames,
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

	p.objMap = pj.ObjMap
	p.name = pj.Name
	p.policyEntry = pj.PolicyEntry
	p.action = pj.Action
	p.cli = pj.Cli
	p.status = pj.Status
	p.srcIntf = pj.SrcIntf
	p.dstIntf = pj.DstIntf
	p.useNat = pj.UseNat
	p.usePool = pj.UsePool
	p.poolNames = pj.PoolNames
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
	// objects 和 node 字段被忽略，需要在其他地方设置

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

func (plc *Policy) FromZones() []string {
	return plc.srcZone
}

func (plc *Policy) ToZones() []string {
	return plc.dstZone
}

func (plc *Policy) FromPorts() []api.Port {
	var ports []api.Port
	for _, intfName := range plc.srcIntf {
		if port := plc.node.GetPortByNameOrAlias(intfName); port != nil {
			ports = append(ports, port)
		}
	}
	return ports
}

func (plc *Policy) ToPorts() []api.Port {
	var ports []api.Port
	for _, intfName := range plc.dstIntf {
		if port := plc.node.GetPortByNameOrAlias(intfName); port != nil {
			ports = append(ports, port)
		}
	}
	return ports
}

func (plc *Policy) PolicyEntry() policy.PolicyEntryInf {
	return plc.policyEntry
}

func (plc *Policy) SetUseNat(useNat bool) {
	plc.useNat = useNat
}

func (plc *Policy) SetUsePool(usePool bool) {
	plc.usePool = usePool
}

func (plc *Policy) SetPoolNames(poolNames []string) {
	plc.poolNames = poolNames
}

func (plc *Policy) Extended() map[string]interface{} {
	return map[string]interface{}{
		"action":     plc.action,
		"src_intf":   plc.srcIntf,
		"dst_intf":   plc.dstIntf,
		"use_nat":    plc.useNat,
		"use_pool":   plc.usePool,
		"pool_names": plc.poolNames,
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
		// 从 networkMap 中查找
		if obj, found := plc.objects.networkMap[objName]; found {
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
		// 从 networkMap 中查找
		if obj, found := plc.objects.networkMap[objName]; found {
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
		// 从 serviceMap 中查找
		if obj, found := plc.objects.serviceMap[objName]; found {
			return obj, true
		}
	}

	return nil, false
}

func (plc *Policy) Match(pe policy.PolicyEntryInf) bool {
	if plc.status == firewall.POLICY_INACTIVE {
		return false
	}

	// 如果策略引用了地址、服务对象，先重新加载这些对象
	if len(plc.srcObject) > 0 || len(plc.dstObject) > 0 || len(plc.srvObject) > 0 {
		// 重新加载源地址对象
		for _, objName := range plc.srcObject {
			ng, ok := plc.objects.Network("", objName)
			if ok {
				plc.policyEntry.AddSrc(ng)
			}
		}

		// 重新加载目标地址对象
		for _, objName := range plc.dstObject {
			ng, ok := plc.objects.Network("", objName)
			if ok {
				plc.policyEntry.AddDst(ng)
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

type PolicySet struct {
	parent    *FortigateNode
	objects   *FortiObjectSet
	node      *FortigateNode
	policySet map[string]*Policy
}

// TypeName 实现 TypeInterface 接口
func (ps *PolicySet) TypeName() string {
	return "FortiPolicySet"
}

// policySetJSON 用于序列化和反序列化
type policySetJSON struct {
	Parent    *FortigateNode     `json:"parent"`
	PolicySet map[string]*Policy `json:"policy_set"`
}

// MarshalJSON 实现 JSON 序列化
func (ps *PolicySet) MarshalJSON() ([]byte, error) {
	return json.Marshal(policySetJSON{
		Parent:    ps.parent,
		PolicySet: ps.policySet,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ps *PolicySet) UnmarshalJSON(data []byte) error {
	var psj policySetJSON
	if err := json.Unmarshal(data, &psj); err != nil {
		return err
	}

	ps.parent = psj.Parent
	ps.policySet = psj.PolicySet

	// objects 和 node 字段被忽略，需要在其他地方设置

	return nil
}

func (ps *PolicySet) addPolicy(name string, plc *Policy) {
	ps.policySet[name] = plc
}

func (ps *PolicySet) parseRespResultForPolicy(result []dto.ForiRespResult) {
	for _, res := range result {
		var plc *Policy
		plc = &Policy{
			node:    ps.node,
			objects: ps.objects,
			srcIntf: []string{},
			dstIntf: []string{},
		}
		if py, ok := ps.policySet[res.Name]; ok {
			plc = py
		}

		plc.parse(ps, res, ps.parent)
		ps.addPolicy(plc.name, plc)
	}
}

// func (plc *Policy) parse(ps *PolicySet, respResult dto.ForiRespResult, node *FortigateNode) {
// 	pe := policy.NewPolicyEntry()
// 	for _, srcIntf := range respResult.SrcIntf {
// 		plc.srcIntf = append(plc.srcIntf, srcIntf.Name)
// 	}
// 	for _, dstIntf := range respResult.DstIntf {
// 		plc.dstIntf = append(plc.dstIntf, dstIntf.Name)
// 	}

// 	var srcAddrArr []string
// 	var dstAddrArr []string
// 	for _, srcAddr := range respResult.SrcAddr {
// 		objNetwork := ps.node.objectSet.networkMap[srcAddr.Name]
// 		if objNetwork == nil || objNetwork.Name() == "" {
// 			continue
// 		}
// 		objNetworkGroup := objNetwork.Network(ps.node)
// 		if objNetworkGroup == nil {
// 			continue
// 		}
// 		pe.AddSrc(objNetworkGroup)
// 		srcAddrArr = append(srcAddrArr, srcAddr.Name)
// 	}

// 	for _, dstAddr := range respResult.DstAddr {
// 		var objNetworkGroup *network.NetworkGroup
// 		objNetwork := ps.node.objectSet.networkMap[dstAddr.Name]

// 		if objNetwork == nil {
// 			vip := node.nats.getVipByName(dstAddr.Name)
// 			objNetworkGroup = vip.orignal.Src()
// 		} else {
// 			if objNetwork.Name() != "" {
// 				objNetworkGroup = objNetwork.Network(ps.node)
// 			}
// 		}

// 		if objNetworkGroup == nil {
// 			continue
// 		}

// 		pe.AddDst(objNetworkGroup)
// 		dstAddrArr = append(dstAddrArr, dstAddr.Name)
// 	}

// 	for _, srcAddr := range respResult.SrcAddr6 {
// 		objNetwork := ps.node.objectSet.networkMap[srcAddr.Name]
// 		if objNetwork == nil || objNetwork.Name() == "" {
// 			continue
// 		}
// 		objNetworkGroup := objNetwork.Network(ps.node)
// 		if objNetworkGroup == nil {
// 			continue
// 		}
// 		pe.AddSrc(objNetworkGroup)
// 		srcAddrArr = append(srcAddrArr, srcAddr.Name)
// 	}

// 	for _, dstAddr := range respResult.DstAddr6 {
// 		objNetwork := ps.node.objectSet.networkMap[dstAddr.Name]
// 		if objNetwork == nil || objNetwork.Name() == "" {
// 			continue
// 		}
// 		objNetworkGroup := objNetwork.Network(ps.node)
// 		if objNetworkGroup == nil {
// 			continue
// 		}
// 		pe.AddDst(objNetworkGroup)
// 		dstAddrArr = append(dstAddrArr, dstAddr.Name)
// 	}

// 	var serviceArr []string
// 	for _, srv := range respResult.Service {
// 		objService := ps.node.objectSet.serviceMap[srv.Name]
// 		if objService == nil || objService.Name() == "" {
// 			continue
// 		}
// 		objServiceGroup := objService.Service(ps.node)
// 		if objServiceGroup == nil {
// 			continue
// 		}
// 		pe.AddService(objServiceGroup)
// 		serviceArr = append(serviceArr, objService.Name())
// 	}

// 	plc.name = respResult.Name
// 	switch respResult.Action {
// 	case "accept":
// 		plc.action = firewall.POLICY_PERMIT
// 	case "deny":
// 		plc.action = firewall.POLICY_DENY
// 	}
// 	plc.objMap = respResult
// 	plc.policyEntry = pe

// 	if respResult.Nat == "enable" {
// 		plc.useNat = true
// 	}
// 	if respResult.IsPool == "enable" {
// 		plc.usePool = true
// 		if len(respResult.PoolName) == 0 {
// 			panic("policy pool name is empty")
// 		}
// 		for _, m := range respResult.PoolName {
// 			plc.poolNames = append(plc.poolNames, m.Name)
// 		}
// 	}
// 	if respResult.Status == "enable" {
// 		plc.status = firewall.POLICY_ACTIVE
// 	} else {
// 		plc.status = firewall.POLICY_INACTIVE
// 	}

// 	pairs := []templates.ParamPair{
// 		{S: "PolicyName", V: plc.Name()},
// 		//{S: "ID", V: int(*respResult.PolicyId)},
// 		{S: "SrcIntf", V: strings.Join(plc.srcIntf, " ")},
// 		{S: "DstIntf", V: strings.Join(plc.dstIntf, " ")},
// 		{S: "SrcAddrArray", V: srcAddrArr},
// 		{S: "DstAddrArray", V: dstAddrArr},
// 		{S: "ServiceArray", V: serviceArr},
// 	}
// 	if respResult.PolicyId != nil {
// 		pairs = append(pairs, templates.ParamPair{S: "ID", V: int(*respResult.PolicyId)})
// 	}

// 	var template *templates.CliTemplate

// 	if respResult.Nat == "enable" {
// 		if respResult.IsPool == "enable" {
// 			pairs = append(pairs, templates.ParamPair{S: "PoolName", V: respResult.PoolName})
// 			template = templates.CliTemplates["ConfigFirewallPolicyForPool"]
// 		}
// 	}
// 	if template == nil {
// 		template = templates.CliTemplates["ConfigFirewallPolicyForVip"]
// 	}
// 	plc.cli = template.Formatter(pairs)
// 	fmt.Println("plc--->", plc.PolicyEntry().String())
// }

func (plc *Policy) parse(ps *PolicySet, respResult dto.ForiRespResult, node *FortigateNode) {
	pe := policy.NewPolicyEntry()

	// 处理源接口和目标接口
	for _, srcIntf := range respResult.SrcIntf {
		plc.srcIntf = append(plc.srcIntf, srcIntf.Name)
		plc.srcZone = append(plc.srcZone, srcIntf.Name) // 假设接口名称等同于区域名称
	}
	for _, dstIntf := range respResult.DstIntf {
		plc.dstIntf = append(plc.dstIntf, dstIntf.Name)
		plc.dstZone = append(plc.dstZone, dstIntf.Name) // 假设接口名称等同于区域名称
	}

	var srcAddrArr []string
	var dstAddrArr []string

	// 处理源地址
	for _, srcAddr := range respResult.SrcAddr {
		objNetwork := ps.node.objectSet.networkMap[srcAddr.Name]
		if objNetwork == nil || objNetwork.Name() == "" {
			continue
		}
		objNetworkGroup := objNetwork.Network(ps.node)
		if objNetworkGroup == nil {
			continue
		}
		pe.AddSrc(objNetworkGroup)
		srcAddrArr = append(srcAddrArr, srcAddr.Name)
		plc.srcAddr = append(plc.srcAddr, srcAddr.Name)
		plc.srcObject = append(plc.srcObject, srcAddr.Name)
		plc.srcObjectCli = append(plc.srcObjectCli, objNetwork.Cli()) // 假设 Network 对象有 Cli() 方法
	}

	// 处理目标地址
	for _, dstAddr := range respResult.DstAddr {
		var objNetworkGroup *network.NetworkGroup
		objNetwork := ps.node.objectSet.networkMap[dstAddr.Name]

		if objNetwork == nil {
			vip := node.nats.getVipByName(dstAddr.Name)
			objNetworkGroup = vip.orignal.Src()
		} else {
			if objNetwork.Name() != "" {
				objNetworkGroup = objNetwork.Network(ps.node)
			}
		}

		if objNetworkGroup == nil {
			continue
		}

		pe.AddDst(objNetworkGroup)
		dstAddrArr = append(dstAddrArr, dstAddr.Name)
		plc.dstAddr = append(plc.dstAddr, dstAddr.Name)
		plc.dstObject = append(plc.dstObject, dstAddr.Name)
		plc.dstObjectCli = append(plc.dstObjectCli, objNetwork.Cli()) // 假设 Network 对象有 Cli() 方法
	}

	// 处理 IPv6 源地址
	for _, srcAddr := range respResult.SrcAddr6 {
		objNetwork := ps.node.objectSet.networkMap[srcAddr.Name]
		if objNetwork == nil || objNetwork.Name() == "" {
			continue
		}
		objNetworkGroup := objNetwork.Network(ps.node)
		if objNetworkGroup == nil {
			continue
		}
		pe.AddSrc(objNetworkGroup)
		srcAddrArr = append(srcAddrArr, srcAddr.Name)
		plc.srcAddr = append(plc.srcAddr, srcAddr.Name)
		plc.srcObject = append(plc.srcObject, srcAddr.Name)
		plc.srcObjectCli = append(plc.srcObjectCli, objNetwork.Cli()) // 假设 Network 对象有 Cli() 方法
	}

	// 处理 IPv6 目标地址
	for _, dstAddr := range respResult.DstAddr6 {
		objNetwork := ps.node.objectSet.networkMap[dstAddr.Name]
		if objNetwork == nil || objNetwork.Name() == "" {
			continue
		}
		objNetworkGroup := objNetwork.Network(ps.node)
		if objNetworkGroup == nil {
			continue
		}
		pe.AddDst(objNetworkGroup)
		dstAddrArr = append(dstAddrArr, dstAddr.Name)
		plc.dstAddr = append(plc.dstAddr, dstAddr.Name)
		plc.dstObject = append(plc.dstObject, dstAddr.Name)
		plc.dstObjectCli = append(plc.dstObjectCli, objNetwork.Cli()) // 假设 Network 对象有 Cli() 方法
	}

	var serviceArr []string
	// 处理服务
	for _, srv := range respResult.Service {
		objService := ps.node.objectSet.serviceMap[srv.Name]
		if objService == nil || objService.Name() == "" {
			continue
		}
		objServiceGroup := objService.Service(ps.node)
		if objServiceGroup == nil {
			continue
		}
		pe.AddService(objServiceGroup)
		serviceArr = append(serviceArr, objService.Name())
		plc.srv = append(plc.srv, srv.Name)
		plc.srvObject = append(plc.srvObject, srv.Name)
		plc.srvObjectCli = append(plc.srvObjectCli, objService.Cli()) // 假设 Service 对象有 Cli() 方法
	}

	plc.name = respResult.Name
	switch respResult.Action {
	case "accept":
		plc.action = firewall.POLICY_PERMIT
	case "deny":
		plc.action = firewall.POLICY_DENY
	}
	plc.objMap = respResult
	plc.policyEntry = pe

	if respResult.Nat == "enable" {
		plc.useNat = true
	}
	if respResult.IsPool == "enable" {
		plc.usePool = true
		if len(respResult.PoolName) == 0 {
			panic("policy pool name is empty")
		}
		for _, m := range respResult.PoolName {
			plc.poolNames = append(plc.poolNames, m.Name)
		}
	}
	if respResult.Status == "enable" {
		plc.status = firewall.POLICY_ACTIVE
	} else {
		plc.status = firewall.POLICY_INACTIVE
	}

	pairs := []templates.ParamPair{
		{S: "PolicyName", V: plc.Name()},
		{S: "SrcIntf", V: strings.Join(plc.srcIntf, " ")},
		{S: "DstIntf", V: strings.Join(plc.dstIntf, " ")},
		{S: "SrcAddrArray", V: srcAddrArr},
		{S: "DstAddrArray", V: dstAddrArr},
		{S: "ServiceArray", V: serviceArr},
	}
	if respResult.PolicyId != nil {
		pairs = append(pairs, templates.ParamPair{S: "ID", V: int(*respResult.PolicyId)})
	}

	var template *templates.CliTemplate

	if respResult.Nat == "enable" {
		if respResult.IsPool == "enable" {
			pairs = append(pairs, templates.ParamPair{S: "PoolName", V: respResult.PoolName})
			template = templates.CliTemplates["ConfigFirewallPolicyForPool"]
		}
	}
	if template == nil {
		template = templates.CliTemplates["ConfigFirewallPolicyForVip"]
	}
	plc.cli = template.Formatter(pairs)
	fmt.Println("plc--->", plc.PolicyEntry().String())
}

func (ps *PolicySet) InPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {
	ok, rule := ps.Match(from.Name(), to.Name(), entry)
	if !ok {
		return firewall.POLICY_IMPLICIT_DENY, nil
	} else {
		return rule.(*Policy).Action(), rule
	}
}

func (ps *PolicySet) OutPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {
	ok, rule := ps.Match(from.Name(), to.Name(), entry)
	if !ok {
		return firewall.POLICY_IMPLICIT_DENY, nil
	} else {
		return rule.(*Policy).Action(), rule
	}
}

func (ps *PolicySet) Match(from, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	for _, rule := range ps.policySet {
		if rule.status == firewall.POLICY_INACTIVE {
			continue
		}
		if (tools.Contains(rule.srcIntf, "any") || tools.Contains(rule.srcIntf, from)) &&
			(tools.Contains(rule.dstIntf, "any") || tools.Contains(rule.dstIntf, to)) {
			if rule.policyEntry.Match(pe) {
				return true, rule
			}
		}
	}
	return false, nil
}

//func (ps *PolicySet) Match(name string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
//	if policyList, ok := ps.policySet[name]; !ok {
//		return false, nil
//	} else {
//		for _, p := range policyList {
//			if p.Match(pe) {
//				return true, p
//			}
//		}
//	}
//
//	return false, nil
//}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallPolicy)(nil)).Elem(), "FortiPolicy", reflect.TypeOf(Policy{}))
}
