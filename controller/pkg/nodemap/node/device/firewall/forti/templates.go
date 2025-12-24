package forti

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/forti/templates"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/name"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/validator"
)

type FortigateTemplates struct {
	*firewall.Naming
}

func NewFortigateTemplates(node firewall.FirewallNode) *FortigateTemplates {
	return &FortigateTemplates{
		firewall.NewNaming(node),
	}
}

func (fot *FortigateTemplates) MakeNetworkObj(intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string, port api.Port, ctx *firewall.PolicyContext) (objectName string, cmdList *command.CliCmdList, flyObjectsMap map[string][]interface{}) {
	fot.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("ADDRESS_{{SIMPLE}}", "_", map[string]func(interface{}) string{"SIMPLE": templates.Simple}))
	cmdList = command.NewCliCmdList(fot.Node().(api.Node).CmdIp(), true)
	flyObjectsMap = map[string][]interface{}{}

	input := name.NewNetworkNamingInput(intent, ng)
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	var reuse string
	objectName, reuse, err = fot.NameNetwork(input, port)
	if err != nil {
		panic(err)
	}
	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	if objectName == "" {
		objectName = reuse
		return
	}

	netList := ng.MustOne()
	var addressNameList []string
	var nameList []string
	nl, err := netList.IPNetList()
	if err != nil {
		panic(err)
	}

	objGrp := dto.ForiRespResult{
		Name: objectName,
	}
	var count int
	for _, net := range nl {
		count++
		objName := fmt.Sprintf("NET_%s", net.String())
		objName = strings.ReplaceAll(objName, "/", "_")
		nameList = append(nameList, objName)
		subnet := fmt.Sprintf("%s %s", net.IP.String(), net.Mask.String())

		addressObjTwo := dto.ForiRespResult{
			StructType:          enum.ADDRESS,
			Name:                objName,
			Subnet:              subnet,
			AssociatedInterface: port.Name(),
			Type:                "ipmask",
		}

		objGrp.Member = append(objGrp.Member, dto.ResultMember{
			Name: objName,
		})

		pairs := []templates.ParamPair{
			{S: "AddressName", V: addressObjTwo.Name},
			{S: "Port", V: addressObjTwo.AssociatedInterface},
			{S: "Subnet", V: addressObjTwo.Subnet},
		}
		template := templates.CliTemplates["ConfigFirewallAddress"]
		cli := template.Formatter(pairs)
		cmdList.Add(cli, fmt.Sprintf("%s_%d", objName, count), 2, true)
		flyObjectsMap["NETWORK_OBJECT"] = append(flyObjectsMap["NETWORK_OBJECT"], &addressObjTwo)
		flyObjectsMap["CLIS"] = append(flyObjectsMap["CLIS"], cli)
		addressNameList = append(addressNameList, objName)
	}
	pairs := []templates.ParamPair{
		{S: "AddressGroupName", V: objectName},
		{S: "AddressNameArray", V: addressNameList},
	}
	template := templates.CliTemplates["ConfigFirewallAddressGroup"]
	cli := template.Formatter(pairs)
	cmdList.Add(cli, objectName, 2, true)
	flyObjectsMap["NETWORK_OBJECT_GROUP"] = append(flyObjectsMap["NETWORK_OBJECT_GROUP"], &objGrp)
	flyObjectsMap["CLIS"] = append(flyObjectsMap["CLIS"], cli)
	return
}

func (fot *FortigateTemplates) MakeServiceObject(intent *policy.Intent, sg *service.Service, rule name.NamingRuleType, additionName string, ctx *firewall.PolicyContext) (serviceName string, cmdList *command.CliCmdList, flyObjectsMap map[string][]interface{}) {
	fot.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SERVICE_{{SIMPLE}}", "_", map[string]func(interface{}) string{"SIMPLE": templates.Simple}))
	cmdList = command.NewCliCmdList(fot.Node().(api.Node).CmdIp(), true)
	flyObjectsMap = map[string][]interface{}{}
	input := name.NewServiceNamingInput(intent, sg)
	input.WithRule(rule)
	input.WithAddition(additionName)

	serviceName, reuse, err := fot.NameService(input)
	if err != nil {
		panic(err)
	}

	if serviceName == "" && reuse == "" {
		panic("unknown error")
	}
	if reuse != "" {
		serviceName = reuse
		return
	}
	if serviceName == "" {
		serviceName = reuse
	}
	s := sg.MustOneServiceEntry()
	serviceObj := dto.ForiRespResult{
		Name: serviceName,
	}

	var flyObjects []interface{}
	switch s.Protocol() {
	case service.TCP, service.UDP:
		s.WithStrFunc(func() string {
			var strList []string
			l4SrcPort := s.(*service.L4Service).SrcPort()
			l4DstPort := s.(*service.L4Service).DstPort()
			if l4SrcPort != nil {
				if len(l4SrcPort.L) != 1 {
					panic(fmt.Sprintf("current not support multiple src port range, %+v", l4SrcPort.L))
				}
				strList = append(strList, fmt.Sprintf("%d-%d", l4SrcPort.L[0].Low(), l4SrcPort.L[0].High()))
			}

			if l4DstPort != nil {
				if len(l4DstPort.L) != 1 {
					panic(fmt.Sprintf("current not support multiple dst port range, %+v", l4DstPort.L))
				}
				strList = append(strList, fmt.Sprintf("%d-%d", l4DstPort.L[0].Low(), l4DstPort.L[0].High()))
			}
			return strings.Join(strList, ":")
		})

		portRange := s.String()
		if s.Protocol() == service.TCP {
			serviceObj.TcpPortRange = portRange
		}
		if s.Protocol() == service.UDP {
			serviceObj.UdpPortRange = portRange
		}

		var template *templates.CliTemplate
		if strings.ToLower(s.Protocol().String()) == "tcp" {
			template = templates.CliTemplates["ConfigFirewallServiceTCP"]
		} else {
			template = templates.CliTemplates["ConfigFirewallServiceUDP"]
		}

		pairs := []templates.ParamPair{
			{S: "ServiceName", V: serviceName},
			{S: "PortRange", V: portRange},
		}
		cli := template.Formatter(pairs)
		cmdList.Add(cli, serviceName, 2, true)
		flyObjects = append(flyObjects, &serviceObj)
		flyObjectsMap["CLIS"] = append(flyObjectsMap["CLIS"], cli)
	case service.IP:
		serviceObj.Protocol = "IP"
		template := templates.CliTemplates["ConfigFirewallServiceIP"]
		pairs := []templates.ParamPair{
			{S: "ServiceName", V: serviceName},
		}
		cli := template.Formatter(pairs)
		cmdList.Add(cli, serviceName, 2, true)
		flyObjects = append(flyObjects, &serviceObj)
		flyObjectsMap["CLIS"] = append(flyObjectsMap["CLIS"], cli)
	}

	flyObjectsMap["SERVICE"] = flyObjects
	return
}

func (fot *FortigateTemplates) MakeVip(from, out api.Port, intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string, ctx *firewall.PolicyContext) (vipName string, cmdList *command.CliCmdList, flyObjectsMap map[string][]interface{}) {
	fot.WithFormatter(name.SIMPLE_VIP, name.NewFormatter("VIP_{{SIMPLE}}", "_", map[string]func(interface{}) string{"SIMPLE": templates.Simple}))
	cmdList = command.NewCliCmdList(fot.Node().(api.Node).CmdIp(), true)
	flyObjectsMap = map[string][]interface{}{}

	input := name.NewVipNamingInput(intent, from.Name())
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	vipName, err = fot.NewName(input, rule)
	if err != nil {
		panic(err)
	}

	if vipName == "" {
		panic(errors.New("vip name not be nil"))
	}

	netList := ng.MustOne()
	vip := dto.ForiRespResult{
		Name: vipName,
	}

	var template *templates.CliTemplate
	vip.Name = vipName
	vip.Type = "static-nat"
	mappedMem := dto.ResultMember{
		Range: intent.RealIp,
	}
	vip.MappedIp = []dto.ResultMember{mappedMem}
	if !intent.Service().IsEmpty() {
		srv := intent.Service().MustOneServiceEntry()
		if srv.Protocol() == service.TCP || srv.Protocol() == service.UDP {
			dport := srv.(*service.L4Service).DstPort()
			if !dport.IsFull() {
				for it := dport.Iterator(); it.HasNext(); {
					_, e := it.Next()
					if e.Low().Cmp(e.High()) == 0 {
						vip.ExtPort = e.Low().String()
					} else {
						vip.ExtPort = fmt.Sprintf("%s-%s", e.Low().String(), e.High().String())
					}
				}
			}
		}
	}
	vip.MappedPort = intent.RealPort
	vip.Protocol = intent.Service().Protocol().String()
	vip.ExtIntf = from.Name()
	if len(netList.List()) != 1 {
		panic("vip net not single address")
	}
	for _, net := range netList.List() {
		if net.Type() == network.IPv6 {
			panic(errors.New("vip no support ipv6"))
		}
		ip, _ := net.IPNet()
		if net.Count().Cmp(big.NewInt(1)) == 0 {
			vip.ExtIp = ip.IP.String()
		} else {
			vip.ExtIp = fmt.Sprintf("%s-%s", ip.First().String(), ip.Last().String())
		}
	}
	vip.Status = "enable"
	var mappedIpNameArray []string
	for _, m := range vip.MappedIp {
		mappedIpNameArray = append(mappedIpNameArray, m.Range)
	}

	pairs := []templates.ParamPair{
		{S: "VipName", V: vip.Name},
		{S: "ExtIp", V: vip.ExtIp},
		{S: "MappedIp", V: mappedIpNameArray},
		{S: "ExtIntf", V: vip.ExtIntf},
	}
	if strings.ToLower(vip.Protocol) == "ip" {
		vip.PortForward = "disable"
		template = templates.CliTemplates["ConfigFirewallVipIp"]
	} else {
		vip.PortForward = "enable"
		pairs = append(pairs, templates.ParamPair{S: "ExtPort", V: vip.ExtPort}, templates.ParamPair{S: "MappedPort", V: vip.MappedPort})
		template = templates.CliTemplates["ConfigFirewallVipTcpUdp"]
	}
	cli := template.Formatter(pairs)
	cmdList.Add(cli, vipName, 2, true)
	flyObjectsMap["CLIS"] = append(flyObjectsMap["CLIS"], cli)
	flyObjectsMap["STATIC_NAT"] = append(flyObjectsMap["STATIC_NAT"], &vip)
	return
}

func (fot *FortigateTemplates) MakeIpPool(intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string, ctx *firewall.PolicyContext) (poolName string, cmdList *command.CliCmdList, flyObjectsMap map[string][]interface{}) {
	// pool_first_end
	fot.WithFormatter(name.SIMPLE_POOL, name.NewFormatter("POOL_{{SIMPLE}}", "_", map[string]func(interface{}) string{"SIMPLE": templates.Simple}))
	cmdList = command.NewCliCmdList(fot.Node().(api.Node).CmdIp(), true)
	flyObjectsMap = map[string][]interface{}{}

	input := name.NewPoolNamingInput(intent, ng, intent.Service())
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	createName, reuseName, err := fot.NamePool(input, firewall.DYNAMIC_NAT)
	if err != nil {
		panic(err)
	}
	if createName == "" && reuseName == "" {
		panic(fmt.Errorf("pool name not be nil"))
	}

	if createName != "" {
		poolName = createName
	}

	if createName == "" && reuseName != "" {
		return reuseName, cmdList, flyObjectsMap
	}

	if poolName == "" {
		panic(errors.New("pool name not be nil"))
	}

	netList := ng.MustOne()
	pool := dto.ForiRespResult{
		Name: poolName,
	}
	for _, net := range netList.List() {
		if net.Type() == network.IPv6 {
			panic(errors.New("pool no support ipv6"))
		}
		pool.Name = poolName
		ipv4 := ng.IPv4()
		pool.Type = "overload"
		pool.StartIpPool = ipv4.First().String()
		pool.EndIpPool = ipv4.Last().String()

		pairs := []templates.ParamPair{
			{S: "PoolName", V: pool.Name},
			{S: "StartIp", V: pool.StartIpPool},
			{S: "EndIp", V: pool.EndIpPool},
		}
		template := templates.CliTemplates["ConfigFirewallIpPool"]
		cli := template.Formatter(pairs)
		cmdList.Add(cli, pool.Name, 2, true)
		flyObjectsMap["POOL"] = append(flyObjectsMap["POOL"], &pool)
		flyObjectsMap["CLIS"] = append(flyObjectsMap["CLIS"], cli)
	}
	return
}

func (fot *FortigateTemplates) MakePolicy(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObjectsMap map[string][]interface{}, cmdList *command.CliCmdList) {
	// from = 18.1.1.8/24(port1)  to = 89.1.1.8/24(port2)
	// intent src = 18.1.1.0  dst = 9.1.1.1  realIP = 89.1.1.9   natType = static dynamic
	flyObjectsMap = make(map[string][]interface{})
	cmdList = command.NewCliCmdList(fot.Node().(api.Node).CmdIp(), true)
	policyName := intent.TicketNumber
	policyName, err := firewall.GetName(policyName, "_", fot.Node().HasPolicyName)
	if err != nil {
		panic(err)
	}
	if policyName == "" {
		panic(errors.New("policy name not be nil"))
	}

	thePolicy := dto.ForiRespResult{}
	thePolicy.Name = policyName
	thePolicy.Action = "accept"
	thePolicy.Status = "enable"
	var srcNetworkObjNames []string
	if intent.Src() != nil && !intent.Src().IsEmpty() {
		srcArr := strings.Split(intent.Src().String(), ",")
		for _, srcAddr := range srcArr {
			srcGroup, err := network.NewNetworkGroupFromString(srcAddr)
			if err != nil {
				panic(err)
			}
			objName, cmds, objMaps := fot.MakeNetworkObj(intent, srcGroup, name.REUSE_OR_NEW, "", from, ctx)
			if objName != "" {
				srcNetworkObjNames = append(srcNetworkObjNames, objName)
			}
			for _, cmd := range cmds.Cmds {
				cmdList.AddCmd(cmd)
			}
			for k, v := range objMaps {
				flyObjectsMap[k] = append(flyObjectsMap[k], v...)
			}
		}
	}

	var dstNetworkObjNames []string
	if intent.Dst() != nil && !intent.Dst().IsEmpty() {
		objName, cmds, objMaps := fot.MakeNetworkObj(intent, intent.Dst(), name.REUSE_OR_NEW, "", out, ctx)
		if objName != "" {
			dstNetworkObjNames = append(dstNetworkObjNames, objName)
		}
		for _, cmd := range cmds.Cmds {
			cmdList.AddCmd(cmd)
		}
		for k, v := range objMaps {
			flyObjectsMap[k] = append(flyObjectsMap[k], v...)
		}
	}

	var serviceNames []string
	if !intent.Service().IsEmpty() {
		serviceName, cmds, objMaps := fot.MakeServiceObject(intent, intent.Service(), name.REUSE_OR_NEW, "", ctx)
		if serviceName != "" {
			serviceNames = append(serviceNames, serviceName)
		}
		for _, cmd := range cmds.Cmds {
			cmdList.AddCmd(cmd)
		}
		for k, v := range objMaps {
			flyObjectsMap[k] = append(flyObjectsMap[k], v...)
		}
	}

	thePolicy.SrcIntf = []dto.ResultMember{{Name: from.Name()}}
	thePolicy.DstIntf = []dto.ResultMember{{Name: out.Name()}}
	var srcMems []dto.ResultMember
	for _, ads := range srcNetworkObjNames {
		srcMems = append(srcMems, dto.ResultMember{
			Name: ads,
		})
	}
	thePolicy.SrcAddr = srcMems
	vipNameObj, _ := ctx.GetValue("STATIC_NAT_NAME")
	var vipName string
	if vipNameObj != nil {
		if str, ok := vipNameObj.(string); ok && str != "" {
			vipName = str
		}
	}

	var dstMems []dto.ResultMember
	if vipName != "" {
		dstMems = append(dstMems, dto.ResultMember{
			Name: vipName,
		})
	} else {
		for _, ads := range dstNetworkObjNames {
			dstMems = append(dstMems, dto.ResultMember{
				Name: ads,
			})
		}
	}
	thePolicy.DstAddr = dstMems
	var serviceMems []dto.ResultMember
	for _, srvName := range serviceNames {
		serviceMems = append(serviceMems, dto.ResultMember{
			Name: srvName,
		})
	}
	thePolicy.Service = serviceMems
	pairs := []templates.ParamPair{
		{S: "PolicyName", V: thePolicy.Name},
		{S: "SrcIntf", V: from.Name()},
		{S: "DstIntf", V: out.Name()},
		{S: "SrcAddrArray", V: srcNetworkObjNames},
		{S: "ServiceArray", V: serviceNames},
		{S: "UseNat", V: "disable"},
	}

	// output nat templates的生成再这里完成
	var poolClis []string
	var template *templates.CliTemplate
	if intent.Snat != "" {
		ng, err := network.NewNetworkGroupFromString(intent.Snat)
		if err != nil {
			panic(err)
		}
		var poolName string
		poolObj, ok := fot.Node().GetPoolByNetworkGroup(ng, firewall.DYNAMIC_NAT)
		if !ok {
			flyPoolObj, cmds := fot.Node().(*FortigateNode).MakeDynamicNatCli(from, out, intent, ctx)
			fmt.Println(flyPoolObj, cmds)
			flyPoolObjMap := flyPoolObj.(map[string][]interface{})
			// 如果有pool对象生成，则追加pool的cli到flyObjectsMap
			if _, ok = flyPoolObjMap["POOL"]; ok {
				for _, cmd := range flyPoolObjMap["CLIS"] {
					cmdVal := cmd.(string)
					if strings.Contains(cmdVal, "policy") {
						break
					}
					poolClis = append(poolClis, cmdVal)
				}
				if len(poolClis) == 0 {
					panic("pool has create, but create cli is not found")
				}
			}

			if _, ok = flyPoolObjMap["PoolName"]; ok {
				for _, names := range flyPoolObjMap["PoolName"] {
					theNames := names.([]string)
					poolName = theNames[0]
					break
				}
			}
		}

		if poolObj != nil && poolObj.Name() != "" {
			poolName = poolObj.Name()
		}
		if poolName == "" {
			panic("MakeDynamicNatCli not find pool info")
		}
		pairs = append(pairs, templates.ParamPair{S: "DstAddrArray", V: dstNetworkObjNames})
		pairs = append(pairs, templates.ParamPair{S: "PoolName", V: poolName})

		template = templates.CliTemplates["ConfigFirewallPolicyForPool"]
	} else {
		if vipName != "" {
			pairs = append(pairs, templates.ParamPair{S: "DstAddrArray", V: []string{vipName}})
		} else {
			pairs = append(pairs, templates.ParamPair{S: "DstAddrArray", V: dstNetworkObjNames})
		}
		template = templates.CliTemplates["ConfigFirewallPolicyForVip"]
	}

	cli := template.Formatter(pairs)
	cmdList.Add(cli, thePolicy.Name, 2, true)
	for _, poolCli := range poolClis {
		flyObjectsMap["CLIS"] = append(flyObjectsMap["CLIS"], poolCli)
	}
	flyObjectsMap["CLIS"] = append(flyObjectsMap["CLIS"], cli)
	flyObjectsMap["POLICY"] = append(flyObjectsMap["POLICY"], &thePolicy)
	return
}

type FortiGateDNatTargetServiceValidator struct{}

func (dp FortiGateDNatTargetServiceValidator) Validate(data map[string]interface{}) validator.Result {
	var intent *policy.Intent
	var genPe policy.PolicyEntryInf
	var result validator.Result
	func() {
		defer func() {
			if r := recover(); r != nil {
				result = validator.NewValidateResult(false, fmt.Sprint(r))
			}
		}()

		intent = data["intent"].(*policy.Intent)
		genPe = intent.GenerateIntentPolicyEntry()
	}()

	if result != nil {
		return result
	}

	s := genPe.Service().MustSimpleServiceEntry()
	if !(s.Protocol() == service.IP || s.Protocol() == service.TCP || s.Protocol() == service.UDP) {
		return validator.NewValidateResult(false, fmt.Sprint("static nat not support portocol: ", s.Protocol()))
	}

	switch s.(type) {
	case *service.L3Protocol:
		if s.Protocol() != service.IP {
			return validator.NewValidateResult(false, fmt.Sprint("static nat not support L3 portocol: ", s.Protocol()))
		}
	case *service.L4Service:
		e := s.(*service.L4Service).DstPort().List()[0]
		if e.Count().Cmp(big.NewInt(1)) != 0 {
			return validator.NewValidateResult(false, fmt.Sprint("static nat not support multiple port: ", s.(*service.L4Service).DstPort()))
		}
	}

	return validator.NewValidateResult(true, "")
}

type FortiGateDNatTargetIsExistValidator struct{}

func (dv FortiGateDNatTargetIsExistValidator) Validate(data map[string]interface{}) validator.Result {
	node := data["node"].(firewall.FirewallNode)
	intent := data["intent"].(*policy.Intent)
	inPort := data["inPort"].(api.Port)
	outPort := data["outPort"].(api.Port)
	ok, rule := node.InputNatTargetCheck(intent, inPort, outPort)
	if ok {
		return validator.NewValidateResult(false, fmt.Sprint("target server nat is exist. ", rule))
	}

	return validator.NewValidateResult(true, "")
}

type FortiGateDNatMappedAddressValidator struct{}

func (dv FortiGateDNatMappedAddressValidator) Validate(data map[string]interface{}) validator.Result {
	intent := data["intent"].(*policy.Intent)
	dst := intent.Dst()

	if !(dst.AddressType() == network.HOST || dst.AddressType() == network.SUBNET) {
		return validator.NewValidateResult(false, fmt.Sprint("dnat only support host and subnet, dst: ", dst))
	}

	return validator.NewValidateResult(true, "")
}
