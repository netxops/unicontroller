package secpath

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/secpath/model"

	//"github.com/netxops/unify/global"
	//M "github.com/netxops/unify/model"
	"regexp"
	"strconv"
	"strings"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cast"
)

func XmlAddrGroupMemberStructToAddressGroup(xag *model.XmlAddrGroupMemberStruct) *model.AddressGroup {
	net, err := network.NewNetworkGroupFromString(fmt.Sprintf("%s-%s", xag.StartIpv4Address, xag.EndIpv4Address))
	if err != nil {
		panic(err)
	}

	byteS, err := json.Marshal(xag)
	if err != nil {
		panic(err)
	}
	return &model.AddressGroup{GroupNumber: xag.GroupNumber, C: string(byteS), N: net}
}

func XmlOutboundDynamicStructToNatRule(xos *model.XmlOutboundDynamicStruct, node *SecPathNode, objects *SecPathObjectSet, nats *Nats) *NatRule {
	basePolicyEntry := policy.NewPolicyEntry()
	basePolicyEntry.AddSrc(network.NewAny4Group())
	basePolicyEntry.AddDst(network.NewAny4Group())
	s, _ := service.NewServiceWithProto("ip")
	basePolicyEntry.AddService(s)

	nat := NatRule{
		method: model.SECPATH_NAT_OUTBOUNT_DYNAMIC,
		node:   node,
		status: tools.Conditional(xos.Disable, firewall.NAT_INACTIVE, firewall.NAT_ACTIVE).(firewall.NatStatus),
		// name: xos.RuleName,
	}

	if xos.ACLNumber != "" {
		policyGroup := node.PolicySet.getPolicyGroup(xos.ACLNumber)
		if policyGroup == nil {
			panic(fmt.Sprintf("find acl rule failed, aclnumber: %s", xos.ACLNumber))
		}

		pe := policy.NewPolicyEntry()
		for _, rule := range policyGroup.rules {
			pe.AddSrc(rule.policyEntry.Src())
			pe.AddDst(rule.policyEntry.Dst())
			pe.AddService(rule.policyEntry.Service())
		}
		nat.orignal = pe

		// 添加aclName
		nat.aclName = xos.ACLNumber
		// nat.aclPolicyEntry = pe
	} else {
		panic("current not support acl number is nil")
	}

	var mappedSrc *network.NetworkGroup
	if xos.AddrGroupNumber > 0 {
		ag := nats.addressGroup(xos.AddrGroupNumber)
		mappedSrc = ag.N

		// 添加natPool
		nat.natPool = xos.AddrGroupNumber
	} else if xos.IfIndex != "" {
		ifIndex := cast.ToInt(xos.IfIndex)
		port := node.GetPortByIfIndex(ifIndex)
		if port == nil {
			panic(fmt.Sprintf("can not find port by ifindex: %s", xos.IfIndex))
		}
		mappedSrc = port.V4NetworkGroup()

		// 添加 outboundPort
		nat.outboundPort = int64(ifIndex)
	} else {
		panic("unknown error")
	}

	translate := policy.NewPolicyEntry()
	translate.AddSrc(mappedSrc)

	nat.translate = translate
	nat.orignal.AutoFill(basePolicyEntry)
	nat.translate.AutoFill(basePolicyEntry)

	return &nat
}

// 1. A single public address with no or a single public port
// 2. A single public address with consecutive public ports
// 3. Consecutive public addresses with no public port
// 4. Consecutive public addresses with one single public port
// 5. Load sharing NAT server mapping
// 6. ACL-based NAT server mapping
func XmlServerOnInterfaceStructToNatRule(xso *model.XmlServerOnInterfaceStruct, node *SecPathNode, objects *SecPathObjectSet, nats *Nats) *NatRule {
	basePolicyEntry := policy.NewPolicyEntry()
	basePolicyEntry.AddSrc(network.NewAny4Group())
	basePolicyEntry.AddDst(network.NewAny4Group())
	s, _ := service.NewServiceWithProto("ip")
	basePolicyEntry.AddService(s)

	var err error
	nat := NatRule{
		name:         xso.RuleName,
		node:         node,
		method:       model.SECPATH_NAT_SERVER_ON_INTERFACE,
		natType:      firewall.STATIC_NAT,
		outboundPort: int64(xso.IfIndex),
		srcVrf:       tools.OR(xso.LocalInfo.LocalVRF, firewall.DEFAULT_VRF).(string),
		dstVrf:       tools.OR(xso.GlobalInfo.GlobalVRF, firewall.DEFAULT_VRF).(string),
		reversible:   xso.Reversible,
		status:       tools.Conditional(xso.Disable, firewall.NAT_INACTIVE, firewall.NAT_ACTIVE).(firewall.NatStatus),
	}

	protocol := service.IPProto(xso.ProtocolType)
	realService := &service.Service{}
	mappedService := &service.Service{}

	var realSrc *network.NetworkGroup
	realSrc, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s-%s", xso.LocalInfo.LocalStartIpv4Address,
		tools.OR(xso.LocalInfo.LocalEndIpv4Address, xso.LocalInfo.LocalStartIpv4Address).(string)))
	// 添加realSrc，最终用于数据入库
	nat.realSrc = fmt.Sprintf("%s-%s", xso.LocalInfo.LocalStartIpv4Address,
		tools.OR(xso.LocalInfo.LocalEndIpv4Address, xso.LocalInfo.LocalStartIpv4Address).(string))

	if err != nil {
		panic(err)
	}

	var mappedSrc *network.NetworkGroup
	if xso.GlobalInfo.GlobalStartIpv4Address != "" {
		mappedSrc, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s-%s", xso.GlobalInfo.GlobalStartIpv4Address,
			tools.OR(xso.GlobalInfo.GlobalEndIpv4Address, xso.GlobalInfo.GlobalStartIpv4Address)))

		// 添加mappedSrc，最终用于数据入库
		nat.mappedSrc = fmt.Sprintf("%s-%s", xso.GlobalInfo.GlobalStartIpv4Address,
			tools.OR(xso.GlobalInfo.GlobalEndIpv4Address, xso.GlobalInfo.GlobalStartIpv4Address))
	} else if xso.GlobalInfo.GlobalIfIndex != "" {
		ifIndex := cast.ToInt(xso.GlobalInfo.GlobalIfIndex)
		port := node.GetPortByIfIndex(ifIndex)
		if port == nil {
			panic(fmt.Sprintf("can not find port by ifindex: %s", xso.GlobalInfo.GlobalIfIndex))
		}
		mappedSrc = port.V4NetworkGroup()

		// 添加outboundPort,最终用于数据入库
		nat.outboundPort = int64(ifIndex)
	} else {
		panic("unknown error")
	}

	if xso.LocalInfo.LocalStartPortNumber != "" {
		port, err := service.NewL4PortFromString(fmt.Sprintf("%s-%s", xso.LocalInfo.LocalStartPortNumber, tools.OR(xso.LocalInfo.LocalEndPortNumber, xso.LocalInfo.LocalStartPortNumber)), 0)
		if err != nil {
			panic(err)
		}

		realService, err = service.NewService(protocol, port, nil, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
		if err != nil {
			panic(err)
		}

		// 添加realSrv，最终用于数据入库
		nat.realSrv = realService.String()
	}

	if xso.GlobalInfo.GlobalStartPortNumber != "" {
		port, err := service.NewL4PortFromString(fmt.Sprintf("%s-%s", xso.GlobalInfo.GlobalStartPortNumber, tools.OR(xso.GlobalInfo.GlobalEndPortNumber, xso.GlobalInfo.GlobalStartPortNumber)), 0)
		if err != nil {
			panic(err)
		}

		mappedService, err = service.NewService(protocol, port, nil, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
		if err != nil {
			panic(err)
		}

		// 添加mappedSrc，最终用于数据入库
		nat.mappedSrv = mappedService.String()
	}

	if xso.ACLNumber != "" {
		policyGroup := node.PolicySet.getPolicyGroup(xso.ACLNumber)
		if policyGroup == nil {
			panic(fmt.Sprintf("find acl rule failed, aclnumber: %s", xso.ACLNumber))
		}

		pe := policy.NewPolicyEntry()
		for _, rule := range policyGroup.rules {
			pe.AddSrc(rule.policyEntry.Src())
			pe.AddDst(rule.policyEntry.Dst())
			pe.AddService(rule.policyEntry.Service())
		}
		nat.aclPolicyEntry = pe
	}

	orignal := policy.NewPolicyEntry()
	orignal.AddSrc(realSrc)
	orignal.AddService(realService)
	nat.orignal = orignal

	translate := policy.NewPolicyEntry()
	translate.AddSrc(mappedSrc)
	translate.AddService(mappedService)
	nat.translate = translate

	nat.orignal.AutoFill(basePolicyEntry)
	nat.translate.AutoFill(basePolicyEntry)

	return &nat
}

func XmlOutboundStaticStructToNatRule(xos *model.XmlOutboundStaticStruct, node *SecPathNode, objects *SecPathObjectSet, nats *Nats) *NatRule {
	basePolicyEntry := policy.NewPolicyEntry()
	basePolicyEntry.AddSrc(network.NewAny4Group())
	basePolicyEntry.AddDst(network.NewAny4Group())
	s, _ := service.NewServiceWithProto("ip")
	basePolicyEntry.AddService(s)

	var err error
	nat := NatRule{
		objects:    objects,
		node:       node,
		method:     model.SECPATH_NAT_OUTBOUND_STATIC,
		srcVrf:     tools.OR(xos.LocalInfo.LocalVRF, firewall.DEFAULT_VRF).(string),
		dstVrf:     tools.OR(xos.GlobalInfo.GlobalVRF, firewall.DEFAULT_VRF).(string),
		reversible: xos.Reversible,
		status:     tools.Conditional(xos.Disable, firewall.NAT_INACTIVE, firewall.NAT_ACTIVE).(firewall.NatStatus),
	}

	var realSrc *network.NetworkGroup
	var mappedSrc *network.NetworkGroup
	realSrc, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s-%s", xos.LocalInfo.StartIpv4Address,
		tools.OR(xos.LocalInfo.EndIpv4Address, xos.LocalInfo.StartIpv4Address).(string)))

	// 添加realSrc，最终用于数据入库
	nat.realSrc = fmt.Sprintf("%s-%s", xos.LocalInfo.StartIpv4Address,
		tools.OR(xos.LocalInfo.EndIpv4Address, xos.LocalInfo.StartIpv4Address).(string))

	if err != nil {
		panic(err)
	}

	mappedSrc, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s/%d", xos.GlobalInfo.Ipv4Address, xos.GlobalInfo.Ipv4PrefixLength))

	// 添加mappedSrc，最终用于数据入库
	nat.mappedSrc = fmt.Sprintf("%s/%d", xos.GlobalInfo.Ipv4Address, xos.GlobalInfo.Ipv4PrefixLength)

	if xos.ACLNumber != "" {
		policyGroup := node.PolicySet.getPolicyGroup(xos.ACLNumber)
		if policyGroup == nil {
			panic(fmt.Sprintf("find acl rule failed, aclnumber: %s", xos.ACLNumber))
		}

		pe := policy.NewPolicyEntry()
		for _, rule := range policyGroup.rules {
			pe.AddSrc(rule.policyEntry.Src())
			pe.AddDst(rule.policyEntry.Dst())
			pe.AddService(rule.policyEntry.Service())
		}
		nat.aclPolicyEntry = pe

		// 添加aclName
		nat.aclName = xos.ACLNumber
	}

	orignal := policy.NewPolicyEntry()
	orignal.AddSrc(realSrc)
	// orignal.AddService(realService)
	nat.orignal = orignal

	translate := policy.NewPolicyEntry()
	translate.AddSrc(mappedSrc)
	nat.translate = translate

	nat.orignal.AutoFill(basePolicyEntry)
	nat.translate.AutoFill(basePolicyEntry)

	return &nat
}

func XmlNatPolicyStructToNatRule(xps *model.XmlNatPolicyStruct, node *SecPathNode, objects *SecPathObjectSet, nats *Nats) *NatRule {
	basePolicyEntry := policy.NewPolicyEntry()
	basePolicyEntry.AddSrc(network.NewAny4Group())
	basePolicyEntry.AddDst(network.NewAny4Group())
	s, _ := service.NewServiceWithProto("ip")
	basePolicyEntry.AddService(s)

	nat := NatRule{
		method:  model.SECPATH_NAT_POLICY,
		node:    node,
		name:    xps.RuleName,
		natType: firewall.DYNAMIC_NAT,
		status:  tools.Conditional(xps.Disable, firewall.NAT_INACTIVE, firewall.NAT_ACTIVE).(firewall.NatStatus),
	}
	var src, dst *network.NetworkGroup

	if len(xps.SrvObjGrpList.ServiceObjGroup) > 0 {
		if src == nil {
			src = network.NewNetworkGroup()
		}
		for _, objName := range xps.SrcObjGrpList.SrcIPObjGroup {
			ng, _, ok := objects.Network("", objName)
			if !ok {
				panic(fmt.Sprintf("can not find object network, name:%s", objName))
			}
			src.AddGroup(ng)

			// 添加realSrcObject，最终用于数据入库
			nat.realSrcObject = append(nat.realSrcObject, objName)
		}
	}

	if len(xps.DstObjGrpList.DstIPObjGroup) > 0 {
		if dst == nil {
			dst = network.NewNetworkGroup()
		}
		for _, objName := range xps.DstObjGrpList.DstIPObjGroup {
			ng, _, ok := objects.Network("", objName)
			if !ok {
				panic(fmt.Sprintf("can not find object network, name:%s", objName))
			}
			dst.AddGroup(ng)

			// 添加realDstObject，最终用于数据入库
			nat.realDstObject = append(nat.realDstObject, objName)
		}
	}

	var srv *service.Service
	if len(xps.SrvObjGrpList.ServiceObjGroup) > 0 {
		if srv == nil {
			srv = &service.Service{}
		}

		for _, objName := range xps.SrvObjGrpList.ServiceObjGroup {
			s, _, ok := objects.Service(objName)
			if !ok {
				panic(fmt.Sprintf("can not find object service, name:%s", objName))
			}

			srv.Add(s)

			// 添加realSrvObject，最终用于数据入库
			nat.realSrvObject = append(nat.realSrvObject, objName)
		}
	}

	orignal := policy.NewPolicyEntry()
	if src != nil {
		orignal.AddSrc(src)
	}
	if dst != nil {
		orignal.AddDst(dst)
	}
	if srv != nil {
		orignal.AddService(srv)
	}

	translate := policy.NewPolicyEntry()
	if xps.AddrGroupNumber != 0 {
		ng := nats.addressGroup(int(xps.AddrGroupNumber)).N
		translate.AddSrc(ng)

		// 添加natPool，最终用于数据入库
		nat.natPool = int(xps.AddrGroupNumber)
	} else if *xps.Action == model.EASYIP {
		outPort := node.GetPortByIfIndex(int(xps.OutboundInterface)).(*SecPathPort)
		ng := network.NewNetworkGroup()
		for _, ip := range outPort.Ipv4List() {
			i, err := network.ParseIPNet(ip)
			if err != nil {
				panic(err)
			}
			g, err := network.NewNetworkFromString(i.IP.String())
			if err != nil {
				panic(err)
			}
			ng.Add(g)
		}
		translate.AddSrc(ng)

		// 添加outboundPort, 最终用于数据入库
		nat.outboundPort = int64(outPort.IfIndex())
	} else if *xps.Action == model.NONAT {
		translate = orignal.Copy().(*policy.PolicyEntry)
	}

	nat.orignal = orignal
	nat.translate = translate
	if xps.OutboundInterface != 0 {
		nat.outboundPort = xps.OutboundInterface
	}
	if xps.Reversible {
		nat.reversible = true
	} else {
		nat.reversible = false
	}

	nat.orignal.AutoFill(basePolicyEntry)
	nat.translate.AutoFill(basePolicyEntry)

	return &nat
}

type NatRule struct {
	method     model.ApiNatRuleMethod
	objects    *SecPathObjectSet
	name       string
	node       *SecPathNode
	from       string
	srcVrf     string
	dstVrf     string
	to         string
	natType    firewall.NatType
	afterAuto  bool
	cli        string
	status     firewall.NatStatus
	natPool    int
	reversible bool
	noNat      bool
	noPat      bool
	orignal    policy.PolicyEntryInf
	translate  policy.PolicyEntryInf

	realSrc          string
	realSrcObject    []string
	realSrcObjectCli []string
	realDst          string
	realDstObject    []string
	realDstObjectCli []string
	realSrv          string
	realSrvObject    []string
	realSrvObjectCli []string

	mappedSrc          string
	mappedSrcObject    []string
	mappedSrcObjectCli []string
	mappedDst          string
	mappedDstObject    []string
	mappedDstObjectCli []string
	mappedSrv          string
	mappedSrvObject    []string
	mappedSrvObjectCli []string

	aclName              string
	acl                  *ACL
	aclPolicyEntry       policy.PolicyEntryInf
	outboundPort         int64
	outboundPortName     string
	natServerOnInterface string
}

// TypeName 实现 TypeInterface 接口
func (nr *NatRule) TypeName() string {
	return "SecPathNatRule"
}

// natRuleJSON 用于序列化和反序列化
type natRuleJSON struct {
	Method               model.ApiNatRuleMethod `json:"method"`
	Name                 string                 `json:"name"`
	From                 string                 `json:"from"`
	SrcVrf               string                 `json:"src_vrf"`
	DstVrf               string                 `json:"dst_vrf"`
	To                   string                 `json:"to"`
	NatType              firewall.NatType       `json:"nat_type"`
	AfterAuto            bool                   `json:"after_auto"`
	Cli                  string                 `json:"cli"`
	Status               firewall.NatStatus     `json:"status"`
	NatPool              int                    `json:"nat_pool"`
	Reversible           bool                   `json:"reversible"`
	NoNat                bool                   `json:"no_nat"`
	NoPat                bool                   `json:"no_pat"`
	Orignal              json.RawMessage        `json:"orignal"`
	Translate            json.RawMessage        `json:"translate"`
	RealSrc              string                 `json:"real_src"`
	RealSrcObject        []string               `json:"real_src_object"`
	RealSrcObjectCli     []string               `json:"real_src_object_cli"`
	RealDst              string                 `json:"real_dst"`
	RealDstObject        []string               `json:"real_dst_object"`
	RealDstObjectCli     []string               `json:"real_dst_object_cli"`
	RealSrv              string                 `json:"real_srv"`
	RealSrvObject        []string               `json:"real_srv_object"`
	RealSrvObjectCli     []string               `json:"real_srv_object_cli"`
	MappedSrc            string                 `json:"mapped_src"`
	MappedSrcObject      []string               `json:"mapped_src_object"`
	MappedSrcObjectCli   []string               `json:"mapped_src_object_cli"`
	MappedDst            string                 `json:"mapped_dst"`
	MappedDstObject      []string               `json:"mapped_dst_object"`
	MappedDstObjectCli   []string               `json:"mapped_dst_object_cli"`
	MappedSrv            string                 `json:"mapped_srv"`
	MappedSrvObject      []string               `json:"mapped_srv_object"`
	MappedSrvObjectCli   []string               `json:"mapped_srv_object_cli"`
	AclName              string                 `json:"acl_name"`
	AclPolicyEntry       json.RawMessage        `json:"acl_policy_entry"`
	OutboundPort         int64                  `json:"outbound_port"`
	OutboundPortName     string                 `json:"outbound_port_name"`
	NatServerOnInterface string                 `json:"nat_server_on_interface"`
}

// MarshalJSON 实现 JSON 序列化
func (nr *NatRule) MarshalJSON() ([]byte, error) {

	orignalRaw, err := registry.InterfaceToRawMessage(nr.orignal)
	if err != nil {
		return nil, fmt.Errorf("error marshaling orignal: %w", err)
	}

	translateRaw, err := registry.InterfaceToRawMessage(nr.translate)
	if err != nil {
		return nil, fmt.Errorf("error marshaling translate: %w", err)
	}

	var aclPolicyEntryRaw json.RawMessage
	if nr.aclPolicyEntry != nil {
		aclPolicyEntryRaw, err = registry.InterfaceToRawMessage(nr.aclPolicyEntry)
		if err != nil {
			return nil, fmt.Errorf("error marshaling aclPolicyEntry: %w", err)
		}
	}

	return json.Marshal(natRuleJSON{
		Method:               nr.method,
		Name:                 nr.name,
		From:                 nr.from,
		SrcVrf:               nr.srcVrf,
		DstVrf:               nr.dstVrf,
		To:                   nr.to,
		NatType:              nr.natType,
		AfterAuto:            nr.afterAuto,
		Cli:                  nr.cli,
		Status:               nr.status,
		NatPool:              nr.natPool,
		Reversible:           nr.reversible,
		NoNat:                nr.noNat,
		NoPat:                nr.noPat,
		Orignal:              orignalRaw,
		Translate:            translateRaw,
		RealSrc:              nr.realSrc,
		RealSrcObject:        nr.realSrcObject,
		RealSrcObjectCli:     nr.realSrcObjectCli,
		RealDst:              nr.realDst,
		RealDstObject:        nr.realDstObject,
		RealDstObjectCli:     nr.realDstObjectCli,
		RealSrv:              nr.realSrv,
		RealSrvObject:        nr.realSrvObject,
		RealSrvObjectCli:     nr.realSrvObjectCli,
		MappedSrc:            nr.mappedSrc,
		MappedSrcObject:      nr.mappedSrcObject,
		MappedSrcObjectCli:   nr.mappedSrcObjectCli,
		MappedDst:            nr.mappedDst,
		MappedDstObject:      nr.mappedDstObject,
		MappedDstObjectCli:   nr.mappedDstObjectCli,
		MappedSrv:            nr.mappedSrv,
		MappedSrvObject:      nr.mappedSrvObject,
		MappedSrvObjectCli:   nr.mappedSrvObjectCli,
		AclName:              nr.aclName,
		AclPolicyEntry:       aclPolicyEntryRaw,
		OutboundPort:         nr.outboundPort,
		OutboundPortName:     nr.outboundPortName,
		NatServerOnInterface: nr.natServerOnInterface,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (nr *NatRule) UnmarshalJSON(data []byte) error {
	var nrj natRuleJSON
	if err := json.Unmarshal(data, &nrj); err != nil {
		return err
	}

	nr.method = nrj.Method
	nr.name = nrj.Name
	nr.from = nrj.From
	nr.srcVrf = nrj.SrcVrf
	nr.dstVrf = nrj.DstVrf
	nr.to = nrj.To
	nr.natType = nrj.NatType
	nr.afterAuto = nrj.AfterAuto
	nr.cli = nrj.Cli
	nr.status = nrj.Status
	nr.natPool = nrj.NatPool
	nr.reversible = nrj.Reversible
	nr.noNat = nrj.NoNat
	nr.noPat = nrj.NoPat
	nr.realSrc = nrj.RealSrc
	nr.realSrcObject = nrj.RealSrcObject
	nr.realSrcObjectCli = nrj.RealSrcObjectCli
	nr.realDst = nrj.RealDst
	nr.realDstObject = nrj.RealDstObject
	nr.realDstObjectCli = nrj.RealDstObjectCli
	nr.realSrv = nrj.RealSrv
	nr.realSrvObject = nrj.RealSrvObject
	nr.realSrvObjectCli = nrj.RealSrvObjectCli
	nr.mappedSrc = nrj.MappedSrc
	nr.mappedSrcObject = nrj.MappedSrcObject
	nr.mappedSrcObjectCli = nrj.MappedSrcObjectCli
	nr.mappedDst = nrj.MappedDst
	nr.mappedDstObject = nrj.MappedDstObject
	nr.mappedDstObjectCli = nrj.MappedDstObjectCli
	nr.mappedSrv = nrj.MappedSrv
	nr.mappedSrvObject = nrj.MappedSrvObject
	nr.mappedSrvObjectCli = nrj.MappedSrvObjectCli
	nr.aclName = nrj.AclName
	nr.outboundPort = nrj.OutboundPort
	nr.outboundPortName = nrj.OutboundPortName
	nr.natServerOnInterface = nrj.NatServerOnInterface

	var err error
	if string(nrj.Orignal) != "null" {
		nr.orignal, err = registry.RawMessageToInterface[policy.PolicyEntryInf](nrj.Orignal)
		if err != nil {
			return fmt.Errorf("error unmarshaling orignal: %w", err)
		}
	}

	if string(nrj.Translate) != "null" {
		nr.translate, err = registry.RawMessageToInterface[policy.PolicyEntryInf](nrj.Translate)
		if err != nil {
			return fmt.Errorf("error unmarshaling translate: %w", err)
		}
	}

	if string(nrj.AclPolicyEntry) != "null" {
		nr.aclPolicyEntry, err = registry.RawMessageToInterface[policy.PolicyEntryInf](nrj.AclPolicyEntry)
		if err != nil {
			return fmt.Errorf("error unmarshaling aclPolicyEntry: %w", err)
		}
	}

	return nil
}

func (rule *NatRule) Name() string {
	return rule.name
}

func (rule *NatRule) Cli() string {
	return rule.cli
}

func (rule *NatRule) Extended() map[string]interface{} {
	return map[string]interface{}{
		"Method":             rule.method,
		"Name":               rule.name,
		"From":               rule.from,
		"To":                 rule.to,
		"SrcVrf":             rule.srcVrf,
		"DstVrf":             rule.dstVrf,
		"NatType":            rule.natType,
		"Status":             rule.status,
		"NatPool":            rule.natPool,
		"Reversible":         rule.reversible,
		"NoNat":              rule.noNat,
		"NoPat":              rule.noPat,
		"RealSrc":            rule.realSrc,
		"RealSrcObject":      rule.realSrcObject,
		"RealSrcObjectCli":   rule.realSrcObjectCli,
		"RealDst":            rule.realDst,
		"RealDstObject":      rule.realDstObject,
		"RealDstObjectCli":   rule.realDstObjectCli,
		"RealSrv":            rule.realSrv,
		"RealSrvObject":      rule.realSrvObject,
		"RealSrvObjectCli":   rule.realSrvObjectCli,
		"MappedSrc":          rule.mappedSrc,
		"MappedSrcObject":    rule.mappedSrcObject,
		"MappedSrcObjectCli": rule.mappedSrcObjectCli,
		"MappedDst":          rule.mappedDst,
		"MappedDstObject":    rule.mappedDstObject,
		"MappedDstObjectCli": rule.mappedDstObjectCli,
		"MappedSrv":          rule.mappedSrv,
		"MappedSrvObject":    rule.mappedSrvObject,
		"MappedSrvObjectCli": rule.mappedSrvObjectCli,
		"AclName":            rule.aclName,
		"OutboundPort":       rule.outboundPort,
	}
}

func (rule *NatRule) Original() policy.PolicyEntryInf {
	return rule.orignal
}

func (rule *NatRule) Translate() policy.PolicyEntryInf {
	return rule.translate
}

func (rule *NatRule) matchDnatTarget(entry policy.PolicyEntryInf) bool {
	if rule.method == model.SECPATH_NAT_GLOBAL_POLICY {
		return rule.orignal.Match(entry)
	}

	// 为了理解方便，其实就是Intent的RealIp+RealPort，能匹配已有的STATIC_NAT策略
	if rule.natType == firewall.DYNAMIC_NAT {
		return false
	}

	reverse := entry.Reverse()
	if rule.orignal.Match(reverse) {
		return true
	}

	return false
}

//func (rule *NatRule) ToDbStruct(db *gorm.DB, task_id uint) *M.NatObject {
//	no := M.NatObject{
//		Method:               rule.method.String(),
//		Name:                 rule.name,
//		ExtractTaskID:        task_id,
//		Cli:                  rule.cli,
//		From:                 rule.from,
//		To:                   rule.to,
//		SrcVrf:               rule.srcVrf,
//		DstVrf:               rule.dstVrf,
//		NatType:              rule.natType,
//		Status:               int(rule.status),
//		RealSrc:              rule.realSrc,
//		RealDst:              rule.realDst,
//		RealSrv:              rule.realSrv,
//		MappedSrc:            rule.mappedSrc,
//		MappedDst:            rule.mappedDst,
//		MappedSrv:            rule.mappedSrv,
//		RealSrcAddress:       rule.orignal.Src(),
//		RealDstAddress:       rule.orignal.Dst(),
//		RealService:          rule.orignal.Service(),
//		MappedSrcAddress:     rule.translate.Src(),
//		MappedDstAddress:     rule.translate.Dst(),
//		MappedService:        rule.translate.Service(),
//		RealSrcAddressString: rule.orignal.Src().String(),
//		RealDstAddressString: rule.orignal.Dst().String(),
//		RealServiceString:    rule.orignal.Service().String(),
//	}
//
//	if rule.natType == firewall.DYNAMIC_NAT || rule.natType == firewall.TWICE_NAT {
//		no.MappedSrcAddressString = rule.translate.Src().String()
//	}
//
//	if rule.natType == firewall.STATIC_NAT || rule.natType == firewall.TWICE_NAT {
//		no.MappedDstAddressString = rule.translate.Dst().String()
//		no.MappedServiceString = rule.translate.Service().String()
//	}
//
//	for _, objName := range rule.realSrcObject {
//		obj := M.NetworkObject{}
//		result := db.Where("extract_task_id = ?", task_id).Where("name = ?", objName).Find(&obj)
//		if result.RowsAffected == 0 {
//			panic(fmt.Sprintf("extract_task_id = %d, name = %s", task_id, objName))
//		}
//
//		no.RealSrcObject = append(no.RealSrcObject, &obj)
//	}
//
//	for _, objName := range rule.realDstObject {
//		obj := M.NetworkObject{}
//		result := db.Where("extract_task_id = ?", task_id).Where("name = ?", objName).Find(&obj)
//		if result.RowsAffected == 0 {
//			panic(fmt.Sprintf("extract_task_id = %d, name = %s", task_id, objName))
//		}
//		no.RealDstObject = append(no.RealDstObject, &obj)
//	}
//
//	for _, objName := range rule.realSrvObject {
//		obj := M.ServiceObject{}
//		result := db.Where("extract_task_id = ?", task_id).Where("name = ?", objName).Find(&obj)
//		if result.RowsAffected == 0 {
//			panic(fmt.Sprintf("extract_task_id = %d, name = %s", task_id, objName))
//		}
//		no.RealSrvObject = append(no.RealSrvObject, &obj)
//	}
//
//	for _, objName := range rule.mappedSrcObject {
//		obj := M.NetworkObject{}
//		result := db.Where("extract_task_id = ?", task_id).Where("name = ?", objName).Find(&obj)
//		if result.RowsAffected == 0 {
//			panic(fmt.Sprintf("extract_task_id = %d, name = %s", task_id, objName))
//		}
//
//		no.MappedSrcObject = append(no.MappedSrcObject, &obj)
//
//	}
//
//	for _, objName := range rule.mappedDstObject {
//		obj := M.NetworkObject{}
//		result := db.Where("extract_task_id = ?", task_id).Where("name = ?", objName).Find(&obj)
//		if result.RowsAffected == 0 {
//			panic(fmt.Sprintf("extract_task_id = %d, name = %s", task_id, objName))
//		}
//		no.MappedDstObject = append(no.MappedDstObject, &obj)
//	}
//
//	for _, objName := range rule.mappedSrvObject {
//		obj := M.ServiceObject{}
//		result := db.Where("extract_task_id = ?", task_id).Where("name = ?", objName).Find(&obj)
//		if result.RowsAffected == 0 {
//			panic(fmt.Sprintf("extract_task_id = %d, name = %s", task_id, objName))
//		}
//		no.MappedSrvObject = append(no.MappedSrvObject, &obj)
//	}
//
//	if rule.aclName != "" {
//		acl := M.PolicyGroup{}
//		result := db.Where("extract_task_id = ?", task_id).Where("name = ?", rule.aclName).Find(&acl)
//		if result.RowsAffected == 0 {
//			panic(fmt.Sprintf("extract_task_id = %d, name = %s", task_id, rule.aclName))
//		}
//		no.PolicyGroup = &acl
//	}
//
//	if rule.natPool != 0 {
//		pool := M.NatPool{}
//		result := db.Where("extract_task_id = ?", task_id).Where("name = ?", fmt.Sprintf("%d", rule.natPool)).Find(&pool)
//		if result.RowsAffected == 0 {
//			panic(fmt.Sprintf("extract_task_id = %d, name = %d", task_id, rule.natPool))
//		}
//		no.NatPool = &pool
//	}
//
//	// Method           string           `gorm:"method"`
//	// Name             string           `gorm:"name"`
//	// ExtractTaskID    uint             `gorm:"extract_task_id"`
//	// Cli              string           `gorm:"cli"`
//	// From             string           `gorm:"from"`
//	// To               string           `gorm:"to"`
//	// SrvVrf           string           `gorm:"srv_vrf"`
//	// DstVrf           string           `gorm:"dst_vrf"`
//	// NatType          string           `gorm:"nat_type"`
//	// Status           string           `gorm:"status"`
//	// RealSrc          string           `gorm:"real_src"`
//	// RealSrcObject    []*NetworkObject `gorm:"many2many:nat_real_src_network"`
//	// RealDst          string           `gorm:"real_dst"`
//	// RealDstObject    []*NetworkObject `gorm:"many2many:nat_real_dst_network"`
//	// RealSrv          string           `gorm:"real_srv"`
//	// RealSrvObject    []*ServiceObject `gorm:"many2many:nat_real_srv"`
//	// MappedSrc        string           `gorm:"mapped_src"`
//	// MappedSrcObject  []*NetworkObject `gorm:"many2many:nat_mapped_src_network"`
//	// MappedDst        string           `gorm:"mapped_dst"`
//	// MappedDstObject  []*NetworkObject `gorm:"many2many:nat_mapped_dst_network"`
//	// MappedSrv        string           `gorm:"mapped_srv"`
//	// MappedSrvObject  []*NetworkObject `gorm:"many2many:nat_mapped_srv"`
//	// Pool             *NatPool
//	// NatPoolID        uint `gorm:"column:nat_pool_id"`
//
//	return &no
//}

type Nats struct {
	objects *SecPathObjectSet
	node    *SecPathNode
	// 都是以ruleSet的名称为key
	natGlobalPolicy   []*NatRule
	natPolicy         []*NatRule
	natServer         []*NatRule
	outboundStatic    []*NatRule
	outboundDynamic   []*NatRule
	inboundStatic     []*NatRule
	addrGroups        []*model.AddressGroup
	staticOnInterface []int
}

//
// {
// "RuleName": "Trust_to_Untrust_YWJS-123488-198316",
// "OutboundInterface": 49,
// "SrcObjGrpList": {
// "SrcIpObjGroup": [
// "YWJS-123488-198316_Trust_src"
// ]
// },
// "DstObjGrpList": {
// "DstIpObjGroup": [
// "YWJS-123488-198316_Untrust_dst"
// ]
// },
// "SrvObjGrpList": {
// "ServiceObjGroup": [
// "YWJS-123488-198316_service"
// ]
// },
// "Action": 0,
// "AddrGroupNumber": 1,
// "Reversible": false,
// "PortPreserved": false,
// "Disable": false,
// "Counting": false,
// "MatchingCount": 0
// }

// TypeName 实现 TypeInterface 接口
func (n *Nats) TypeName() string {
	return "SecPathNats"
}

// natsJSON 用于序列化和反序列化
type natsJSON struct {
	NatGlobalPolicy   []*NatRule            `json:"nat_global_policy"`
	NatPolicy         []*NatRule            `json:"nat_policy"`
	NatServer         []*NatRule            `json:"nat_server"`
	OutboundStatic    []*NatRule            `json:"outbound_static"`
	OutboundDynamic   []*NatRule            `json:"outbound_dynamic"`
	InboundStatic     []*NatRule            `json:"inbound_static"`
	AddrGroups        []*model.AddressGroup `json:"addr_groups"`
	StaticOnInterface []int                 `json:"static_on_interface"`
}

// MarshalJSON 实现 JSON 序列化
func (n *Nats) MarshalJSON() ([]byte, error) {
	return json.Marshal(natsJSON{
		NatGlobalPolicy:   n.natGlobalPolicy,
		NatPolicy:         n.natPolicy,
		NatServer:         n.natServer,
		OutboundStatic:    n.outboundStatic,
		OutboundDynamic:   n.outboundDynamic,
		InboundStatic:     n.inboundStatic,
		AddrGroups:        n.addrGroups,
		StaticOnInterface: n.staticOnInterface,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (n *Nats) UnmarshalJSON(data []byte) error {
	var nj natsJSON
	if err := json.Unmarshal(data, &nj); err != nil {
		return err
	}

	n.natGlobalPolicy = nj.NatGlobalPolicy
	n.natPolicy = nj.NatPolicy
	n.natServer = nj.NatServer
	n.outboundStatic = nj.OutboundStatic
	n.outboundDynamic = nj.OutboundDynamic
	n.inboundStatic = nj.InboundStatic
	n.addrGroups = nj.AddrGroups
	n.staticOnInterface = nj.StaticOnInterface

	return nil
}

func (nats *Nats) parseNatGlobalPolicy(config string) {
	sections := strings.Split(config, "#")

	natClis := ""
	for _, section := range sections {
		if strings.Index(section, "nat global-policy") >= 0 {
			// 去除第一行nat global-policy
			// lines := strings.Split(section, "\n")
			lines := strings.Split(strings.TrimSpace(section), "\n")
			natClis = strings.Join(lines[1:], "\n")
		}
	}

	if natClis == "" {
		return
	}

	ruleRegexMap := map[string]string{
		"regex": `
			(rule\sname\s(?P<rule_name>\S+))|
			(source-zone\s(?P<src_zone>\S+))|
			(destination-zone\s(?P<dst_zone>\S+))|
			(service
				(
					(\s(?P<srv>\S+))|
					(-port\s(?P<sp>[ \w]+))
				)
			)|
			(source-ip\s((host\s(?P<src_host>\S+))|
						 (subnet\s(?P<src_subnet>\S+)\s(?P<src_prefix>\S+))|
						 (?P<src_obj>\S+)
						)
			)|
			(destination-ip\s((host\s(?P<dst_host>\S+))|
			                  (subnet\s(?P<dst_subnet>\S+)\s(?P<dst_prefix>\S+))|
							  (?P<dst_obj>\S+)
							 )
			)|
			(action\s
				(
					(snat\s
							(
							   (static\s
								   (ip-address\s(?P<snat_ip>\S+))|
								   (object-group\s(?P<snat_obj>\S+))|
								   (subnet\s(?P<snat_subnet>\S+)\s(?P<snat_subnet_prefix>\S+))
							   )|
							   (address-group\s(?P<addr_grp>\S+))|
							   (?P<easy_ip>easy-ip)|
							   (?P<src_nonat>no-nat)
							)
					)|
					(dnat\s( ((ip-address\s(?P<dnat_ip>\S+))  | (object-group\s(?P<dnat_obj>\S+)))  (\slocal-port\s(?P<mapped_port>\S+))?) |
						   (?P<dnat_nonat>no-nat) 
					)
				)
			)|
			(?P<disable>disable)
		`,
		"name":  "rule",
		"flags": "mx",
		"pcre":  "true",
	}

	// action dnat object-group obj_172.32.110.55 local-port 80

	natSectionResult := text.IndentSection2(natClis)
	for _, clis := range natSectionResult {
		ruleRgexResult, err := text.SplitterProcessOneTime(ruleRegexMap, clis)
		if err != nil {
			panic(err)
		}
		//
		// (source-zone\s(?P<src_zone>\S+))|
		// (destination-zone\s(?P<dst_zone>\S+))|
		// (service\s(?P<srv>\S+))|
		// (source-ip\s((host\s(?P<src_host>\S+))|
		// (subnet\s(?P<src_subnet>\S+)\s(?P<src_prefix>\S+))|
		// (?P<src_obj>\S+)
		// )
		// )|
		// (destination-ip\s((host\s(?P<dst_host>\S+))|
		// (subnet\s(?P<dst_subnet>\S+)\s(?P<dst_prefix>\S+))|
		// (?P<dst_obj>\S+)
		// )
		// )|
		// (action\s
		// (
		// (snat\s
		// (
		// (static\s
		// (ip-address\s(?P<snat_ip>\S+))|
		// (object-group\s(?P<snat_obj>\S+))|
		// (subnet\s(?P<snat_subnet>\S+)\s(?P<snat_subnet_prefix>\S+))
		// )|
		// (address-group\s(?P<addr_grp>\S+))|
		// (?P<easy_ip>easy-ip)|
		// (?P<src_nonat>no-nat)
		// )
		// )|
		// (dnat\s(ip-address\s(?P<dnat_ip>\S+)(\slocal-port\s(?P<mapped_port>\S+))?)|
		// (?P<dnat_nonat>no-nat)
		// )
		// )
		// )|

		natMap, err := ruleRgexResult.Projection([]string{"srv", "sp", "src_host", "src_subnet", "src_obj", "dst_host", "dst_subnet", "dst_obj", "mapped_port"},
			",", [][]string{
				[]string{"src_subnet", "src_prefix"},
				[]string{"dst_subnet", "dst_prefix"},
			})
		if err != nil {
			panic(err)
		}

		nat := &NatRule{
			objects: nats.objects,
			node:    nats.node,
			method:  model.SECPATH_NAT_GLOBAL_POLICY,
			cli:     clis,
			from:    tools.Conditional(natMap["src_zone"] == "", "Any", natMap["src_zone"]).(string),
			to:      tools.Conditional(natMap["dst_zone"] == "", "Any", natMap["dst_zone"]).(string),

			name: natMap["rule_name"],
		}

		basePolicyEntry := policy.NewPolicyEntry()
		basePolicyEntry.AddSrc(network.NewAny4Group())
		basePolicyEntry.AddDst(network.NewAny4Group())
		s, _ := service.NewServiceWithProto("ip")
		basePolicyEntry.AddService(s)

		var realSrc *network.NetworkGroup
		var ok bool
		if natMap["src_host"] != "" {
			realSrc, _ = network.NewNetworkGroupFromString(natMap["src_host"])
			nat.realSrc = natMap["src_host"]
		} else if natMap["src_subnet"] != "" {
			realSrc, _ = network.NewNetworkGroupFromString(natMap["src_subnet"] + "/" + natMap["src_prefix"])
			nat.realSrc = natMap["src_subnet"] + "/" + natMap["src_prefix"]
		} else if natMap["src_obj"] != "" {
			for _, part := range strings.Split(natMap["src_obj"], ",") {
				tmp, _, ok := nats.objects.Network(natMap["src_zone"], part)
				if !ok {
					panic(fmt.Sprintf("find network object failed, name: %s", part))
				}
				if realSrc == nil {
					realSrc = tmp
				} else {
					realSrc.AddGroup(tmp)
				}
				nat.realSrcObject = append(nat.realSrcObject, part)
			}
		} else {
			realSrc = network.NewAny4Group()
			nat.realSrc = "0.0.0.0/0"
		}

		var realDst *network.NetworkGroup
		if natMap["dst_host"] != "" {
			realDst, _ = network.NewNetworkGroupFromString(natMap["dst_host"])
			nat.realDst = natMap["dst_host"]
		} else if natMap["dst_subnet"] != "" {
			realDst, _ = network.NewNetworkGroupFromString(natMap["dst_subnet"] + "/" + natMap["dst_prefix"])
			nat.realDst = natMap["dst_subnet"] + "/" + natMap["dst_prefix"]
		} else if natMap["dst_obj"] != "" {
			for _, part := range strings.Split(natMap["dst_obj"], ",") {
				tmp, _, ok := nats.objects.Network(natMap["dst_zone"], part)
				if !ok {
					panic(fmt.Sprintf("find network object failed, name: %s", part))
				}
				if realDst == nil {
					realDst = tmp
				} else {
					realDst.AddGroup(tmp)
				}
				nat.realDstObject = append(nat.realDstObject, part)
			}

		} else {
			// panic("nat global policy parse error")
			realDst = network.NewAny4Group()
			nat.realDst = "0.0.0.0/0"
		}

		var realService *service.Service
		if natMap["srv"] != "" {
			for _, srvName := range strings.Split(natMap["srv"], ",") {
				s, objCli, ok := nats.objects.Service(srvName)
				if !ok {
					panic(fmt.Sprintf("find service object failed, name: %s", natMap["srv"]))
				}
				if realService == nil {
					realService = s
				} else {
					realService.Add(s)
				}
				if objCli != "" {
					nat.realDstObjectCli = append(nat.realDstObjectCli, objCli)
				}
				nat.realSrvObject = append(nat.realSrvObject, srvName)
			}
		} else if natMap["sp"] != "" {
			// 解析 service-port，类似于 parseOnePolicyCli 中的处理
			for _, cli := range strings.Split(natMap["sp"], ",") {
				if cli == "" {
					continue
				}
				cli = strings.Trim(cli, " ")
				s := PolicySorucePortParser(cli)
				if realService == nil {
					realService = s.Service()
				} else {
					realService.Add(s.Service())
				}
			}
			if realService != nil {
				nat.realSrv = realService.String()
			}
		} else {
			realService, _ = service.NewServiceFromString("ip")
			nat.realSrv = realService.String()
		}

		var mappedSrc *network.NetworkGroup
		if natMap["snat_ip"] != "" {
			mappedSrc, _ = network.NewNetworkGroupFromString(natMap["snat_ip"])
			nat.mappedSrc = natMap["snat_ip"]
		} else if natMap["snat_subnet"] != "" {
			mappedSrc, _ = network.NewNetworkGroupFromString(natMap["snat_subnet"] + "/" + natMap["snat_subnet_prefix"])
			nat.mappedSrc = natMap["snat_subnet"] + "/" + natMap["snat_subnet_prefix"]
		} else if natMap["snat_obj"] != "" {
			var objCli string
			mappedSrc, objCli, ok = nats.objects.Network("", natMap["snat_obj"])
			if !ok {
				panic(fmt.Sprintf("find network object failed, name: %s", natMap["snat_obj"]))
			}
			nat.mappedSrcObject = append(nat.mappedSrcObject, natMap["snat_obj"])
			if objCli != "" {
				nat.mappedSrcObjectCli = append(nat.mappedSrcObjectCli, objCli)
			}
		} else if natMap["addr_grp"] != "" {
			num, err := strconv.Atoi(natMap["addr_grp"])
			if err != nil {
				panic(err)
			}
			addrGrp := nats.addressGroup(num)
			mappedSrc = addrGrp.Network(nil)
			nat.mappedSrc = mappedSrc.String()
		} else if natMap["easy_ip"] != "" {
			// easy-ip 模式：使用 output 接口的 IP 作为 mappedSrc
			// 根据 dst_zone 找到对应的 output 接口
			dstZone := natMap["dst_zone"]
			if dstZone == "" {
				panic("easy-ip requires destination-zone to determine output interface")
			}

			// 检查 node 是否已初始化
			if nats.node == nil {
				panic("nats.node is nil, cannot determine output interface for easy-ip")
			}

			// 从 node 的端口列表中查找属于该 zone 的端口
			var outPort *SecPathPort
			portList := nats.node.PortList()
			for _, port := range portList {
				if port == nil {
					continue
				}
				if secPathPort, ok := port.(*SecPathPort); ok {
					if secPathPort.Zone() == dstZone {
						outPort = secPathPort
						break
					}
				}
			}

			if outPort == nil {
				panic(fmt.Sprintf("can not find output port by zone: %s", dstZone))
			}

			// 获取 output 接口的 IP 地址
			mappedSrc = network.NewNetworkGroup()
			ipv4List := outPort.Ipv4List()
			for _, ip := range ipv4List {
				i, err := network.ParseIPNet(ip)
				if err != nil {
					panic(fmt.Sprintf("failed to parse IP: %s, error: %v", ip, err))
				}
				g, err := network.NewNetworkFromString(i.IP.String())
				if err != nil {
					panic(fmt.Sprintf("failed to create network from IP: %s, error: %v", i.IP.String(), err))
				}
				mappedSrc.Add(g)
			}

			if mappedSrc.IsEmpty() {
				panic(fmt.Sprintf("output port %s (zone: %s) has no IPv4 address", outPort.Name(), dstZone))
			}

			nat.mappedSrc = mappedSrc.String()
			if outPort.IfIndex() > 0 {
				nat.outboundPort = int64(outPort.IfIndex())
			}
		} else if natMap["src_nonat"] != "" {
			mappedSrc = realSrc.Copy().(*network.NetworkGroup)
			nat.mappedSrc = mappedSrc.String()
		}
		// else {
		// fmt.Println(natMap)
		// fmt.Println(clis)
		// panic("unknown error")
		// }

		var mappedDst *network.NetworkGroup
		if natMap["dnat_ip"] != "" {
			mappedDst, _ = network.NewNetworkGroupFromString(natMap["dnat_ip"])
			nat.mappedDst = natMap["dnat_ip"]
		} else if natMap["dnat_nonat"] != "" {
			mappedDst = realDst.Copy().(*network.NetworkGroup)
			if nat.realDst != "" {
				nat.mappedDst = nat.realDst
			} else {
				for _, m := range nat.realDstObject {
					nat.mappedDstObject = append(nat.mappedDstObject, m)
				}
			}
		} else if natMap["dnat_obj"] != "" {
			var objCli string
			mappedDst, objCli, ok = nats.objects.Network("", natMap["dnat_obj"])
			if !ok {
				panic(fmt.Sprintf("find network object failed, name: %s", natMap["dnat_obj"]))
			}
			nat.mappedDstObject = append(nat.mappedDstObject, natMap["dnat_obj"])
			if objCli != "" {
				nat.mappedDstObjectCli = append(nat.mappedDstObjectCli, objCli)
			}
		}

		var mappedService *service.Service
		if natMap["mapped_port"] != "" {
			one := realService.MustOneServiceEntry()
			if one.Protocol() != service.TCP && one.Protocol() != service.UDP && one.Protocol() != service.TCP_UDP {
				panic("current only support TCP or UDP")
			}

			s, err := service.NewServiceWithL4(one.Protocol().String(), "", natMap["mapped_port"])
			if err != nil {
				panic(err)
			}
			mappedService = s
			nat.mappedSrv = s.String()
		} else {
			mappedService = realService.Copy().(*service.Service)
		}

		if mappedSrc == nil && mappedDst == nil {
			fmt.Println(natMap)
			panic(fmt.Sprintf("unknown parse error, cli: %s", clis))
		}
		if mappedSrc != nil && mappedDst != nil {
			nat.natType = firewall.TWICE_NAT
		} else if mappedSrc != nil {
			nat.natType = firewall.DYNAMIC_NAT
		} else if mappedDst != nil {
			nat.natType = firewall.STATIC_NAT
		} else {
			panic("unknow error")
		}

		orignal := policy.NewPolicyEntry()
		orignal.AddSrc(realSrc)
		orignal.AddDst(realDst)
		orignal.AddService(realService)

		translate := policy.NewPolicyEntry()
		translate.AddSrc(mappedSrc)
		translate.AddDst(mappedDst)
		translate.AddService(mappedService)

		orignal.AutoFill(basePolicyEntry)
		translate.AutoFill(basePolicyEntry)

		nat.orignal = orignal
		nat.translate = translate

		if natMap["disable"] != "" {
			nat.status = firewall.NAT_INACTIVE
		} else {
			nat.status = firewall.NAT_ACTIVE
		}

		nats.natGlobalPolicy = append(nats.natGlobalPolicy, nat)
	}

}

func (nats *Nats) parseStaticOnInterface(objList []interface{}) {
	for _, obj := range objList {
		var xmlObj model.XmlStaticOnInterfaceStruct
		mapstructure.WeakDecode(obj, &xmlObj)
		if xmlObj.EnableStatic {
			nats.staticOnInterface = append(nats.staticOnInterface, cast.ToInt(xmlObj.IfIndex))
		}
	}
}

func (nats *Nats) parseAddressGroupCli(config string) {
	sections := strings.Split(config, "#")

	objectSections := []string{}
	for _, section := range sections {
		ok, _ := regexp.MatchString(`^nat address-group\s`, strings.TrimSpace(section))
		if ok {
			objectSections = append(objectSections, strings.TrimSpace(section))
		}
	}

	addressRegexMap := map[string]string{
		"regex": `
			(nat\saddress-group\s(?P<name>\S+))|
			(address\s(?P<range>\S+)\s(?P<end>\S+))
		`,
		"name":  "name",
		"flags": "mx",
		"pcre":  "true",
	}

	for _, s := range objectSections {
		addressResult, err := text.SplitterProcessOneTime(addressRegexMap, s)
		if err != nil {
			panic(err)
		}
		netMap, err := addressResult.Projection([]string{"range"}, ",", [][]string{
			[]string{"range", "end"},
		})

		if err != nil {
			fmt.Println(s)
			panic(err)
		}

		// var net *network.NetworkGroup
		ag := &model.AddressGroup{
			GroupNumber: cast.ToInt(netMap["name"]),
			C:           s,
		}
		if netMap["range"] != "" {
			var err error
			// Projection 的 pairData 会将 range 和 end 用 "-" 连接
			// 所以 netMap["range"] 的格式是 "192.168.1.1-192.168.1.10,192.168.2.1-192.168.2.10"
			for _, r := range strings.Split(netMap["range"], ",") {
				r = strings.TrimSpace(r)
				if r == "" {
					continue
				}
				if ag.N == nil {
					ag.N, err = network.NewNetworkGroupFromString(r)
					if err != nil {
						fmt.Printf("Failed to parse range: %s, error: %v\n", r, err)
						fmt.Println(s)
						panic(err)
					}
				} else {
					net, err := network.NewNetworkGroupFromString(r)
					if err != nil {
						fmt.Printf("Failed to parse range: %s, error: %v\n", r, err)
						panic(err)
					}
					ag.N.AddGroup(net)
				}
			}
		}

		nats.addrGroups = append(nats.addrGroups, ag)

		// return &model.AddressGroup{GroupNumber: xag.GroupNumber, C: string(byteS), N: net}
	}

}

func (nats *Nats) parseAddressGroup(objList []interface{}) {
	for _, obj := range objList {
		var xmlObj model.XmlAddrGroupMemberStruct
		mapstructure.Decode(obj, &xmlObj)
		ag := XmlAddrGroupMemberStructToAddressGroup(&xmlObj)

		nats.addrGroups = append(nats.addrGroups, ag)
	}
}

func (nats *Nats) parseNatPolicy(objList []interface{}) {
	for _, obj := range objList {
		var xmlObj model.XmlNatPolicyStruct
		mapstructure.WeakDecode(obj, &xmlObj)
		byteS, err := json.Marshal(&xmlObj)
		if err != nil {
			panic(err)
		}
		rule := XmlNatPolicyStructToNatRule(&xmlObj, nats.node, nats.objects, nats)
		rule.cli = string(byteS)

		nats.natPolicy = append(nats.natPolicy, rule)
	}
}

func (nats *Nats) parseOutboundStaticRules(objList []interface{}) {
	for _, obj := range objList {
		var xmlObj model.XmlOutboundStaticStruct
		mapstructure.WeakDecode(obj, &xmlObj)
		byteS, err := json.Marshal(&xmlObj)
		if err != nil {
			panic(err)
		}
		rule := XmlOutboundStaticStructToNatRule(&xmlObj, nats.node, nats.objects, nats)
		rule.cli = string(byteS)

		nats.outboundStatic = append(nats.outboundStatic, rule)
	}
}

func (nats *Nats) parseOutboundDynamicRules(objList []interface{}) {
	for _, obj := range objList {
		var xmlObj model.XmlOutboundDynamicStruct
		mapstructure.WeakDecode(obj, &xmlObj)
		byteS, err := json.Marshal(&xmlObj)
		if err != nil {
			panic(err)
		}
		rule := XmlOutboundDynamicStructToNatRule(&xmlObj, nats.node, nats.objects, nats)
		rule.cli = string(byteS)

		nats.outboundDynamic = append(nats.outboundDynamic, rule)
	}
}

func (nats *Nats) parseNatServer(objList []interface{}) {
	for _, obj := range objList {
		var xmlObj model.XmlServerOnInterfaceStruct
		mapstructure.WeakDecode(obj, &xmlObj)
		byteS, err := json.Marshal(&xmlObj)
		if err != nil {
			panic(err)
		}
		rule := XmlServerOnInterfaceStructToNatRule(&xmlObj, nats.node, nats.objects, nats)
		rule.cli = string(byteS)

		nats.natServer = append(nats.natServer, rule)
	}
}

// interface Reth3
//
//	nat server protocol icmp global 192.168.0.136 inside 192.168.24.19 rule ServerRule_1 description For_FaYuan_PING
func (nats *Nats) parseNatServerCli(config string) error {
	sections := strings.Split(config, "#")

	for _, section := range sections {
		if !strings.Contains(section, "nat server") {
			return nil
		}

		portName, err := extractInterfaceName(section)
		if err != nil {
			return fmt.Errorf("failed to extract interface name from: %s", section)
		}

		regexMap := map[string]string{
			"regex": `
				nat\sserver
				(
					\sprotocol\s(?P<protocol>\S+)
				)?
				(
					\sglobal\s
					(
					(?P<current_interface>current-interface) |
					(interface\s(?P<interface>\S+)) |
					((?P<global_ip>[\d.]+)(\s(?P<global_ip_end>\d+\.\d+\.\d+\.\d+))?)
					)
				)
				(
					\s(?P<global_port>\d+)
				)?
				(
					\slocal\s(?P<inside_ip>[.\d]+)(\s(?P<inside_ip_end>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?
				)
				(
				    \s(?P<inside_port>\d+)
				)?
				(
					\svpn-instance\s(?P<vpn_instance>\S+)
				)?
				(
					\sacl\s(?P<acl>\S+)
				)?
				(
					\srule\s(?P<rule>\S+)
				)?
				(
					\sdescription\s(?P<description>.+)
				)?
	`,
			"name":  "natserver",
			"flags": "mx",
			"pcre":  "true",
		}

		result, err := text.SplitterProcessOneTime(regexMap, config)
		if err != nil {
			return fmt.Errorf("failed to process nat server regex: %v", err)
		}

		for it := result.Iterator(); it.HasNext(); {
			_, _, match := it.Next()

			nat := &NatRule{
				method:               model.SECPATH_NAT_SERVER_ON_INTERFACE,
				node:                 nats.node,
				natServerOnInterface: portName,
				cli:                  match["0"], // Full matched string
			}

			protocol := match["protocol"]
			if protocol == "" {
				protocol = "ip"
			}

			// if protocol, ok := match["protocol"]; ok {
			// 	nat.realSrv = protocol
			// }

			if globalIP, ok := match["global_ip"]; ok {
				if globalIPEnd, ok := match["global_ip_end"]; ok {
					nat.mappedSrc = fmt.Sprintf("%s-%s", globalIP, globalIPEnd)
				} else {
					nat.mappedSrc = globalIP
				}
			}

			if globalPort, ok := match["global_port"]; ok {
				nat.mappedSrv = globalPort
			}

			if insideIP, ok := match["inside_ip"]; ok {
				if insideIPEnd, ok := match["inside_ip_end"]; ok {
					nat.realSrc = fmt.Sprintf("%s-%s", insideIP, insideIPEnd)
				} else {
					nat.realSrc = insideIP
				}
			}

			if insidePort, ok := match["inside_port"]; ok {
				nat.realSrv = insidePort
			}

			if vpnInstance, ok := match["vpn_instance"]; ok {
				nat.srcVrf = vpnInstance
			}

			if acl, ok := match["acl"]; ok {
				nat.aclName = acl
			}

			if rule, ok := match["rule"]; ok {
				nat.name = rule
			}

			if description, ok := match["description"]; ok {
				// You might want to store the description in a field of NatRule
				// For now, we'll just print it
				fmt.Printf("NAT rule description: %s\n", description)
			}

			// 创建基础策略条目
			basePolicyEntry := policy.NewPolicyEntry()
			basePolicyEntry.AddSrc(network.NewAny4Group())
			basePolicyEntry.AddDst(network.NewAny4Group())
			s, _ := service.NewServiceWithProto("ip")
			basePolicyEntry.AddService(s)

			// 设置原始策略 (original)
			nat.orignal = basePolicyEntry.Copy().(policy.PolicyEntryInf)
			if nat.realSrc != "" {
				realSrcGroup, _ := network.NewNetworkGroupFromString(nat.realSrc)
				nat.orignal.(*policy.PolicyEntry).SetSrc(realSrcGroup)
			}
			// 设置转换后的策略 (translate)
			nat.translate = basePolicyEntry.Copy().(policy.PolicyEntryInf)
			if nat.mappedSrc != "" {
				mappedSrcGroup, _ := network.NewNetworkGroupFromString(nat.mappedSrc)
				nat.translate.(*policy.PolicyEntry).SetSrc(mappedSrcGroup)
			}

			if strings.ToLower(protocol) == "tcp" || strings.ToLower(protocol) == "udp" {
				// 设置原始服务，使用realSrv作为协议，不设置目标端口
				if nat.realSrv != "" {
					s := fmt.Sprintf("%s:%s|--", protocol, nat.realSrv)
					realService, err := service.NewServiceFromString(s)
					if err != nil {
						return fmt.Errorf("failed to create real service: %v", err)
					}
					nat.orignal.(*policy.PolicyEntry).SetService(realService)
				} else {
					realService, err := service.NewServiceFromString(protocol)
					if err != nil {
						return fmt.Errorf("failed to create real service: %v", err)
					}
					nat.orignal.(*policy.PolicyEntry).SetService(realService)
				}

				// 设置转换后的服务，使用realSrv作为协议，mappedSrv作为源端口
				if nat.realSrv != "" && nat.mappedSrv != "" {
					s := fmt.Sprintf("%s:%s|--", protocol, nat.mappedSrv)
					mappedService, err := service.NewServiceFromString(s)
					if err != nil {
						return fmt.Errorf("failed to create mapped service: %v", err)
					}
					nat.translate.(*policy.PolicyEntry).SetService(mappedService)
				}
			} else {
				s, err := service.NewServiceFromString(protocol)
				if err != nil {
					return fmt.Errorf("failed to create service: %v", err)
				}
				nat.orignal.(*policy.PolicyEntry).SetService(s.Copy().(*service.Service))
				nat.translate.(*policy.PolicyEntry).SetService(s.Copy().(*service.Service))
			}

			// Set the NAT type
			nat.natType = firewall.STATIC_NAT

			// Set the status (assuming it's active by default)
			nat.status = firewall.NAT_ACTIVE

			// Add the parsed NAT rule to the list
			nats.natServer = append(nats.natServer, nat)
		}

	}

	return nil
}

func extractInterfaceName(config string) (string, error) {
	// 定义正则表达式
	re := regexp.MustCompile(`(?m)^interface\s+(\S+)`)

	// 查找匹配
	match := re.FindStringSubmatch(config)

	// 检查是否找到匹配
	if len(match) < 2 {
		return "", fmt.Errorf("no interface name found in the configuration")
	}

	// 返回接口名称
	return match[1], nil
}

// func (nats *Nats) parseOutboundDynamicCli(config string) {
// 	sections := strings.Split(config, "#")

// 	regexMap := map[string]string{
// 		"regex": `
//             nat\soutbound\s(?P<acl_id>\d+)
//             \saddress-group\s(?P<address_group>\d+)
//             (
//                 \srule\s(?P<rule>\S+)
//             )?
//             (
//                 \sdescription\s(?P<description>.+)
//             )?
//         `,
// 		"flags": "mx",
// 		"pcre":  "true",
// 		"name":  "outbound_dynamic",
// 	}

// 	for _, section := range sections {
// 		if !strings.Contains(section, "nat outbound") {
// 			return
// 		}

// 		// for itSection := sectionResult.Iterator(); itSection.HasNext(); {
// 		// _, _, sectionMap := itSection.Next()
// 		if strings.Contains(sectionMap["section"], "interface") {
// 			cfgText := sectionMap["section"]
// 			result, err := text.SplitterProcessOneTime(regexMap, cfgText)
// 			if err != nil {
// 				if err == text.ErrNoMatched {
// 					continue
// 				}

// 				panic(fmt.Errorf("failed to process outbound dynamic NAT regex: %v", err))
// 			}

// 			interfaceRegex := `interface\s(?P<port>\S+)`
// 			portResult, err := text.GetFieldByRegex(interfaceRegex, cfgText, []string{"port"})
// 			if err != nil {
// 				panic(fmt.Errorf("failed to extract port from interface: %v", err))
// 			}

// 			for it := result.Iterator(); it.HasNext(); {
// 				_, _, match := it.Next()

// 				nat := &NatRule{
// 					// method:  model.SECPATH_NAT_OUTBOUND_DYNAMIC,
// 					outboundPortName: portResult["port"],
// 					node:             nats.node,
// 					cli:              match["0"], // Full matched string
// 					natType:          firewall.DYNAMIC_NAT,
// 					status:           firewall.NAT_ACTIVE, // Assuming active by default
// 				}

// 				if aclId, ok := match["acl_id"]; ok {
// 					nat.aclName = aclId
// 				}

// 				if addressGroup, ok := match["address_group"]; ok {
// 					nat.natPool, _ = strconv.Atoi(addressGroup)
// 					ag := nats.addressGroup(nat.natPool)
// 					if ag != nil {
// 						nat.mappedSrc = ag.N.String()
// 					}
// 				}

// 				if rule, ok := match["rule"]; ok {
// 					nat.name = rule
// 				}

// 				if description, ok := match["description"]; ok {
// 					// You might want to store the description in a field of NatRule
// 					// For now, we'll just print it
// 					fmt.Printf("Outbound dynamic NAT rule description: %s\n", description)
// 				}

// 				// Set up the original and translate PolicyEntry
// 				basePolicyEntry := policy.NewPolicyEntry()
// 				basePolicyEntry.AddSrc(network.NewAny4Group())
// 				basePolicyEntry.AddDst(network.NewAny4Group())
// 				s, _ := service.NewServiceWithProto("ip")
// 				basePolicyEntry.AddService(s)

// 				nat.orignal = basePolicyEntry.Copy().(policy.PolicyEntryInf)
// 				nat.translate = basePolicyEntry.Copy().(policy.PolicyEntryInf)

// 				// If we have a mapped source from the address group, set it in the translate PolicyEntry
// 				if nat.mappedSrc != "" {
// 					mappedSrcGroup, _ := network.NewNetworkGroupFromString(nat.mappedSrc)
// 					nat.translate.(*policy.PolicyEntry).AddSrc(mappedSrcGroup)
// 				}

// 				// Add the parsed NAT rule to the list
// 				nats.outboundDynamic = append(nats.outboundDynamic, nat)
// 			}
// 		}

// 		// }

// 	}

// }

func (nats *Nats) parseOutboundDynamicCli(config string) error {
	sections := strings.Split(config, "#")

	for _, section := range sections {
		if !strings.Contains(section, "nat outbound") {
			continue
		}

		portName, err := extractInterfaceName(section)
		if err != nil {
			return fmt.Errorf("failed to extract interface name from: %s", section)
		}

		regexMap := map[string]string{
			"regex": `
            nat\soutbound\s(?P<acl_id>\d+)
            \saddress-group\s(?P<address_group>\d+)
            (
                \srule\s(?P<rule>\S+)
            )?
            (
                \sdescription\s(?P<description>.+)
            )?
        `,
			"flags": "mx",
			"pcre":  "true",
			"name":  "outbound_dynamic",
		}

		result, err := text.SplitterProcessOneTime(regexMap, section)
		if err != nil {
			return fmt.Errorf("failed to process outbound dynamic NAT regex: %v", err)
		}

		for it := result.Iterator(); it.HasNext(); {
			_, _, match := it.Next()

			nat := &NatRule{
				method:           model.SECPATH_NAT_OUTBOUNT_DYNAMIC,
				node:             nats.node,
				outboundPortName: portName,
				cli:              match["0"], // Full matched string
				natType:          firewall.DYNAMIC_NAT,
				status:           firewall.NAT_ACTIVE, // Assuming active by default
			}

			if aclId, ok := match["acl_id"]; ok {
				nat.aclName = aclId
				acl := nats.node.AclSet.GetACL(nat.aclName)
				if acl == nil {
					return fmt.Errorf("ACL %s not found", nat.aclName)
				}
				nat.acl = acl
			}

			if addressGroup, ok := match["address_group"]; ok {
				natPool, err := strconv.Atoi(addressGroup)
				if err != nil {
					return fmt.Errorf("failed to convert address group to int: %v", err)
				}
				nat.natPool = natPool
				ag := nats.addressGroup(nat.natPool)
				if ag != nil {
					nat.mappedSrc = ag.N.String()
				}
			}

			if rule, ok := match["rule"]; ok {
				nat.name = rule
			}

			// Set up the original and translate PolicyEntry
			basePolicyEntry := policy.NewPolicyEntry()
			basePolicyEntry.AddSrc(network.NewAny4Group())
			basePolicyEntry.AddDst(network.NewAny4Group())
			s, _ := service.NewServiceWithProto("ip")
			basePolicyEntry.AddService(s)

			nat.orignal = basePolicyEntry.Copy().(policy.PolicyEntryInf)
			nat.translate = basePolicyEntry.Copy().(policy.PolicyEntryInf)

			// If we have a mapped source from the address group, set it in the translate PolicyEntry
			if nat.mappedSrc != "" {
				mappedSrcGroup, _ := network.NewNetworkGroupFromString(nat.mappedSrc)
				nat.translate.(*policy.PolicyEntry).SetSrc(mappedSrcGroup)
			}

			// Add the parsed NAT rule to the list
			nats.outboundDynamic = append(nats.outboundDynamic, nat)
		}
	}

	return nil
}

func (nats *Nats) parseOutboundStaticCli(config string) {
	if !strings.Contains(config, "static outbound") {
		return
	}

	regexMap := map[string]string{
		"regex": `
            nat\sstatic\soutbound
            (
                \s
                (
                (net-to-net\s(?P<local_start>\S+)\s(?P<local_end>\S+)\sglobal\s(?P<global_ip>\S+)\s(?P<global_prefix>\S+)) |
                ((?P<local_ip>[\d.]+)\s(?P<global_ip2>[\d.]+)) |
                (object-group\s(?P<local_obj>\S+)\sobject-group\s(?P<global_obj>\S+))
                )
            )
            (
                \svpn-instance\s(?P<vpn_instance>\S+)
            )?
            (
                \sacl\s(?P<acl>\S+)
            )?
            (
                \srule\s(?P<rule>\S+)
            )?
            (
                \sdescription\s(?P<description>.+)
            )?
        `,
		"pcre":  "true",
		"flags": "mx",
		"name":  "outbound_static",
	}

	result, err := text.SplitterProcessOneTime(regexMap, config)
	if err != nil {
		panic(fmt.Errorf("failed to process outbound static NAT regex: %v", err))
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, match := it.Next()
		nat := &NatRule{
			method:  model.SECPATH_NAT_OUTBOUND_STATIC,
			node:    nats.node,
			cli:     match["__match__"], // Full matched string
			natType: firewall.STATIC_NAT,
			status:  firewall.NAT_ACTIVE, // Assuming active by default
		}

		if localStart, ok := match["local_start"]; ok {
			nat.realSrc = fmt.Sprintf("%s-%s", localStart, match["local_end"])
		} else if localIP, ok := match["local_ip"]; ok {
			nat.realSrc = localIP
		} else if localObj, ok := match["local_obj"]; ok {
			nat.realSrcObject = append(nat.realSrcObject, localObj)
		}

		if globalIP, ok := match["global_ip"]; ok {
			nat.mappedSrc = fmt.Sprintf("%s/%s", globalIP, match["global_prefix"])
		} else if globalIP2, ok := match["global_ip2"]; ok {
			nat.mappedSrc = globalIP2
		} else if globalObj, ok := match["global_obj"]; ok {
			nat.mappedSrcObject = append(nat.mappedSrcObject, globalObj)
		}

		if vpnInstance, ok := match["vpn_instance"]; ok {
			nat.srcVrf = vpnInstance
		}

		if acl, ok := match["acl"]; ok {
			nat.aclName = acl
		}

		if rule, ok := match["rule"]; ok {
			nat.name = rule
		}

		if description, ok := match["description"]; ok {
			// You might want to store the description in a field of NatRule
			// For now, we'll just print it
			fmt.Printf("Outbound static NAT rule description: %s\n", description)
		}

		// Set up the original and translate PolicyEntry
		basePolicyEntry := policy.NewPolicyEntry()
		basePolicyEntry.AddSrc(network.NewAny4Group())
		basePolicyEntry.AddDst(network.NewAny4Group())
		s, _ := service.NewServiceWithProto("ip")
		basePolicyEntry.AddService(s)

		nat.orignal = basePolicyEntry.Copy().(policy.PolicyEntryInf)
		nat.translate = basePolicyEntry.Copy().(policy.PolicyEntryInf)

		// Set the real and mapped sources in the PolicyEntries
		if nat.realSrc != "" {
			realSrcGroup, _ := network.NewNetworkGroupFromString(nat.realSrc)
			nat.orignal.(*policy.PolicyEntry).SetSrc(realSrcGroup)
		}

		if nat.mappedSrc != "" {
			mappedSrcGroup, _ := network.NewNetworkGroupFromString(nat.mappedSrc)
			nat.translate.(*policy.PolicyEntry).SetSrc(mappedSrcGroup)
		}

		// Add the parsed NAT rule to the list
		nats.outboundStatic = append(nats.outboundStatic, nat)
	}
}

func (nats *Nats) parseInboundStaticCli(config string) {
	if !strings.Contains(config, "static inbound") {
		return
	}

	regexMap := map[string]string{
		"regex": `
            nat\sstatic\sinbound
            (
                \s
                (
                (net-to-net\s(?P<global_start>\S+)\s(?P<global_end>\S+)\slocal\s(?P<local_start>\S+)\s(?P<local_end>\S+)) |
                ((?P<global_ip>[\d.]+)\s(?P<local_ip>[\d.]+)) |
                (object-group\s(?P<global_obj>\S+)\sobject-group\s(?P<local_obj>\S+))
                )
            )
            (
                \svpn-instance\s(?P<vpn_instance>\S+)
            )?
            (
                \sacl\s(?P<acl>\S+)
            )?
            (
                \srule\s(?P<rule>\S+)
            )?
            (
                \sdescription\s(?P<description>.+)
            )?
        `,
		"pcre":  "true",
		"flags": "mx",
		"name":  "inbound_static",
	}

	result, err := text.SplitterProcessOneTime(regexMap, config)
	if err != nil {
		panic(fmt.Errorf("failed to process inbound static NAT regex: %v", err))
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, match := it.Next()
		nat := &NatRule{
			// method:  model.SECPATH_NAT_INBOUND_STATIC,
			node:    nats.node,
			cli:     match["0"], // Full matched string
			natType: firewall.STATIC_NAT,
			status:  firewall.NAT_ACTIVE, // Assuming active by default
		}

		if globalStart, ok := match["global_start"]; ok {
			nat.mappedSrc = fmt.Sprintf("%s-%s", globalStart, match["global_end"])
			nat.realSrc = fmt.Sprintf("%s-%s", match["local_start"], match["local_end"])
		} else if globalIP, ok := match["global_ip"]; ok {
			nat.mappedSrc = globalIP
			nat.realSrc = match["local_ip"]
		} else if globalObj, ok := match["global_obj"]; ok {
			nat.mappedSrcObject = append(nat.mappedSrcObject, globalObj)
			nat.realSrcObject = append(nat.realSrcObject, match["local_obj"])
		}

		if vpnInstance, ok := match["vpn_instance"]; ok {
			nat.srcVrf = vpnInstance
		}

		if acl, ok := match["acl"]; ok {
			nat.aclName = acl
		}

		if rule, ok := match["rule"]; ok {
			nat.name = rule
		}

		if description, ok := match["description"]; ok {
			// You might want to store the description in a field of NatRule
			// For now, we'll just print it
			fmt.Printf("Inbound static NAT rule description: %s\n", description)
		}

		// Set up the original and translate PolicyEntry
		basePolicyEntry := policy.NewPolicyEntry()
		basePolicyEntry.AddSrc(network.NewAny4Group())
		basePolicyEntry.AddDst(network.NewAny4Group())
		s, _ := service.NewServiceWithProto("ip")
		basePolicyEntry.AddService(s)

		nat.orignal = basePolicyEntry.Copy().(policy.PolicyEntryInf)
		nat.translate = basePolicyEntry.Copy().(policy.PolicyEntryInf)

		// Set the real and mapped sources in the PolicyEntries
		if nat.realSrc != "" {
			realSrcGroup, _ := network.NewNetworkGroupFromString(nat.realSrc)
			nat.orignal.(*policy.PolicyEntry).SetSrc(realSrcGroup)
		}

		if nat.mappedSrc != "" {
			mappedSrcGroup, _ := network.NewNetworkGroupFromString(nat.mappedSrc)
			nat.translate.(*policy.PolicyEntry).SetSrc(mappedSrcGroup)
		}

		// Add the parsed NAT rule to the list (you might need to create this list if it doesn't exist)
		nats.inboundStatic = append(nats.inboundStatic, nat)
	}
}

func (nats *Nats) addressGroup(number int) *model.AddressGroup {
	for _, ag := range nats.addrGroups {
		if ag.GroupNumber == number {
			return ag
		}
	}

	panic(fmt.Sprintf("unknown address group number: %d", number))
}

//func (nats *Nats) NatsToDb(db *gorm.DB, task_id uint) {
//	// natPolicy         []*NatRule
//	// natServer         []*NatRule
//	// outboundStatic    []*NatRule
//	// outboundDynamic   []*NatRule
//	// addrGroups        []*model.AddressGroup
//	//
//
//	natObjList := []*M.NatObject{}
//	for _, rule := range nats.natGlobalPolicy {
//		no := rule.ToDbStruct(db, task_id)
//
//		natObjList = append(natObjList, no)
//	}
//
//	for _, rule := range nats.natPolicy {
//		no := rule.ToDbStruct(db, task_id)
//
//		natObjList = append(natObjList, no)
//	}
//
//	for _, rule := range nats.natServer {
//		no := rule.ToDbStruct(db, task_id)
//
//		natObjList = append(natObjList, no)
//	}
//
//	for _, rule := range nats.outboundStatic {
//		no := rule.ToDbStruct(db, task_id)
//
//		natObjList = append(natObjList, no)
//	}
//
//	for _, rule := range nats.outboundDynamic {
//		no := rule.ToDbStruct(db, task_id)
//
//		natObjList = append(natObjList, no)
//	}
//
//	if len(natObjList) > 0 {
//		result := db.Save(natObjList)
//		global.GVA_LOG.Info("NatObject对象数量大于1,保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(natObjList)), zap.Any("RowsAffected", result.RowsAffected))
//		if result.Error != nil {
//			panic(result.Error)
//		}
//	} else {
//		global.GVA_LOG.Info("ServiceObject对象数量为0,保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(natObjList)))
//	}
//}

func (nats *Nats) outputNat(from, to api.Port, intent *policy.Intent) (bool, *policy.Intent, *NatRule) {

	// 检查 natServer
	for _, rule := range nats.natServer {
		if rule.status == firewall.NAT_INACTIVE {
			continue
		}
		fmt.Printf("output natServer rule.orignal: %s\n", rule.orignal.String())
		fmt.Printf("output natServer intent: %s\n", intent.String())
		if to.Name() == rule.natServerOnInterface && rule.orignal.Match(intent) {
			_, translate, _ := intent.Translate(rule.translate)
			fmt.Printf("output natServer translate: %s\n", translate.String())
			return true, intent.NewIntentWithTicket(translate), rule
		}
	}

	// 检查 outboundStatic
	for _, rule := range nats.outboundStatic {
		if rule.status == firewall.NAT_INACTIVE {
			continue
		}
		if rule.orignal.Match(intent) {
			_, translate, _ := intent.Translate(rule.translate)
			return true, intent.NewIntentWithTicket(translate), rule
		}
	}

	// 检查 outboundDynamic
	for _, rule := range nats.outboundDynamic {
		if rule.status == firewall.NAT_INACTIVE {
			continue
		}
		if to.IfIndex() == int(rule.outboundPort) || to.Name() == rule.outboundPortName {
			if rule.acl == nil && rule.orignal == nil {
				continue
			}

			if rule.acl != nil {
				if !rule.acl.IsPermit(intent) {
					continue
				}
			}

			if rule.orignal != nil && !rule.orignal.Match(intent) {
				continue
			}

			_, translate, _ := intent.Translate(rule.translate)
			return true, intent.NewIntentWithTicket(translate), rule
		}
	}

	for _, rule := range nats.natGlobalPolicy {
		if rule.status == firewall.NAT_INACTIVE {
			continue
		}

		if rule.natType == firewall.STATIC_NAT {
			continue
		}

		if rule.orignal.Match(intent) {
			_, translate, _ := intent.Translate(rule.translate)
			return true, intent.NewIntentWithTicket(translate), rule
		}
	}

	for _, rule := range nats.natPolicy {
		if rule.status == firewall.NAT_INACTIVE {
			continue
		}

		if to.IfIndex() == int(rule.outboundPort) {
			if rule.orignal.Match(intent) {
				_, translate, _ := intent.Translate(rule.translate)
				return true, intent.NewIntentWithTicket(translate), rule
			}
		}
	}

	for _, rule := range nats.outboundDynamic {
		if rule.status == firewall.NAT_INACTIVE {
			continue
		}

		if to.IfIndex() == int(rule.outboundPort) {
			if rule.orignal.Match(intent) {
				_, translate, _ := intent.Translate(rule.translate)
				return true, intent.NewIntentWithTicket(translate), rule
			}
		}
	}

	return false, nil, nil
}

func (nats *Nats) inputNat(from api.Port, intent *policy.Intent) (bool, *policy.Intent, *NatRule) {
	for _, rule := range nats.natGlobalPolicy {
		if rule.status == firewall.NAT_INACTIVE {
			continue
		}
		if rule.natType == firewall.STATIC_NAT || rule.natType == firewall.DESTINATION_NAT {
			if from.(firewall.ZoneFirewall).Zone() == rule.from || rule.from == "Any" {
				r := rule.orignal
				fmt.Printf("Global NAT rule match: %s\n", rule.orignal)
				if r.Match(intent) {
					t := rule.translate
					_, translate, _ := intent.Translate(t)
					fmt.Printf("Input NAT rule match: %s\n", translate)

					return true, intent.NewIntentWithTicket(translate), rule
					// if rule.aclPolicyEntry != nil {
					// if rule.aclPolicyEntry.Match(translate) {
					// return true, intent.NewIntentWithTicket(translate), rule
					// }
					// } else {
					// return true, intent.NewIntentWithTicket(translate), rule
					// }
				}

			}

		}
	}

	// for _, rule := range nats.natServer {
	// 	if rule.status == firewall.NAT_INACTIVE {
	// 		continue
	// 	}

	// 	fmt.Println("intent: ", intent.String())
	// 	if from.Name() == rule.natServerOnInterface || from.IfIndex() == int(rule.outboundPort) {
	// 		r := rule.translate.Reverse()
	// 		fmt.Println("reverse rule: ", r.String())
	// 		if r.Match(intent) {

	// 			t := rule.orignal.Reverse()
	// 			fmt.Println("original reverse: ", t.String())
	// 			ok, translate, msg := intent.Translate(t)
	// 			if !ok {
	// 				fmt.Println(msg)
	//                 return false, nil, nil
	// 			}

	// 			if rule.aclPolicyEntry != nil {
	// 				if rule.aclPolicyEntry.Match(translate) {
	// 					return true, intent.NewIntentWithTicket(translate), rule
	// 				}
	// 			} else {
	// 				return true, intent.NewIntentWithTicket(translate), rule
	// 			}
	// 		}
	// 	}
	// }

	for _, ruleList := range [][]*NatRule{nats.natServer, nats.inboundStatic} {
		for _, rule := range ruleList {
			if rule.status == firewall.NAT_INACTIVE {
				continue
			}

			fmt.Println("intent: ", intent.String())
			if from.Name() == rule.natServerOnInterface || from.IfIndex() == int(rule.outboundPort) {
				r := rule.translate.Reverse()
				fmt.Println("reverse rule: ", r.String())
				if r.Match(intent) {
					t := rule.orignal.Reverse()
					fmt.Println("original reverse: ", t.String())
					ok, translate, msg := intent.Translate(t)
					if !ok {
						fmt.Println(msg)
						return false, nil, nil
					}

					if rule.aclPolicyEntry != nil {
						if rule.aclPolicyEntry.Match(translate) {
							return true, intent.NewIntentWithTicket(translate), rule
						}
					} else {
						return true, intent.NewIntentWithTicket(translate), rule
					}
				}
			}
		}
	}

	for _, rule := range nats.outboundStatic {
		if rule.status == firewall.NAT_INACTIVE {
			continue
		}

		// outPort := nats.node.GetPortByIfIndex(int(rule.outboundPort))
		// if tools.IsIn(nats.staticOnInterface, outPort.(*SecPathPort).IfIndex) && outPort.Vrf() == rule.dstVrf {
		// fmt.Println(rule.translate)
		r := rule.translate.Reverse()
		if r.Match(intent) {
			t := rule.orignal.Reverse()
			_, translate, _ := intent.Translate(t)

			if rule.aclPolicyEntry != nil {
				racl := rule.aclPolicyEntry.Reverse()
				if racl.Match(translate) {
					return true, intent.NewIntentWithTicket(translate), rule
				}
			}
		}

		// }

	}
	return false, nil, nil
}

func (nats *Nats) inputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, *NatRule) {
	// 利用intent的realIp生成新的PolicyEntry，该PolicyEntry的源地址为realIp地址
	target := intent.GenerateIntentPolicyEntry()
	for _, ruleList := range [][]*NatRule{nats.natGlobalPolicy, nats.natServer, nats.outboundStatic} {
		for _, rule := range ruleList {
			ok := rule.matchDnatTarget(target)
			if ok {
				return true, rule
			}
		}
	}

	return false, nil
}

func (nats *Nats) matchAddressGroupByNetworkGroup(ng *network.NetworkGroup) (*model.AddressGroup, bool) {
	for _, ag := range nats.addrGroups {
		if ag.N.Same(ng) {
			return ag, true
		}
	}

	return nil, false
}

func (nats *Nats) hasAddressGroup(name string) bool {
	for _, ag := range nats.addrGroups {
		if ag.Name() == name {
			return true
		}
	}

	return false
}

func (nats *Nats) hasRuleName(name string) bool {
	for _, ruleList := range [][]*NatRule{nats.natPolicy, nats.natServer, nats.outboundStatic, nats.outboundDynamic} {
		for _, rule := range ruleList {
			if rule.name == name {
				return true
			}
		}
	}

	return false
}

//func (nats *Nats) AddressGroupToDb(db *gorm.DB, task_id uint) {
//	var count int64
//	for _, ag := range nats.addrGroups {
//		pool := M.NatPool{
//			ExtractTaskID: task_id,
//			Name:          ag.Name(),
//			Cli:           ag.Cli(),
//			Network:       ag.Network(nil),
//		}
//
//		result := db.Save(&pool)
//		if result.Error != nil {
//			panic(result.Error)
//		}
//		count += result.RowsAffected
//	}
//
//	if len(nats.addrGroups) > 0 {
//		global.GVA_LOG.Info("保存AddressGroup信息到数据库", zap.Any("Total", len(nats.addrGroups)), zap.Any("RowsAffected", count))
//	}
//}
// func init() {
// 	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.)(nil)).Elem(), "SecPathNode", reflect.TypeOf(SecPathNode{}))
// }

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNatRule)(nil)).Elem(), "SecPathNatRule", reflect.TypeOf(NatRule{}))
}
