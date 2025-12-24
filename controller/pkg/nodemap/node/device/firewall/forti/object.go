package forti

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/forti/templates"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
)

//
// type firewall.FirewallServiceObject interface {
// Cli() string
// Name() string
// Service(map[string]firewall.FirewallServiceObject) *service.Service
// NeedProcessRefs() bool
// }

//
// type firewall.FirewallNetworkObject interface {
// Cli() string
// Name() string
// Network(map[string]firewall.FirewallNetworkObject) *network.NetworkGroup
// NeedProcessRefs() bool
// }

type Pool struct{}

type FortiPoolSet struct{}

type fortiGateService struct {
	catagory firewall.FirewallObjectType
	objMap   dto.ForiRespResult
	name     string
	service  *service.Service
	// refs     []firewall.FirewallServiceObject
	refNames []string
}

// fortiGateServiceJSON 用于序列化和反序列化
type fortiGateServiceJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	ObjMap   json.RawMessage             `json:"obj_map"`
	Name     string                      `json:"name"`
	Service  json.RawMessage             `json:"service"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (fgs *fortiGateService) MarshalJSON() ([]byte, error) {
	objMap, err := json.Marshal(fgs.objMap)
	if err != nil {
		return nil, fmt.Errorf("error marshaling objMap: %w", err)
	}

	serviceRaw, err := json.Marshal(fgs.service)
	if err != nil {
		return nil, fmt.Errorf("error marshaling service: %w", err)
	}

	return json.Marshal(fortiGateServiceJSON{
		Catagory: fgs.catagory,
		ObjMap:   objMap,
		Name:     fgs.name,
		Service:  serviceRaw,
		RefNames: fgs.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (fgs *fortiGateService) UnmarshalJSON(data []byte) error {
	var fgsj fortiGateServiceJSON
	if err := json.Unmarshal(data, &fgsj); err != nil {
		return err
	}

	fgs.catagory = fgsj.Catagory
	fgs.name = fgsj.Name
	fgs.refNames = fgsj.RefNames

	if err := json.Unmarshal(fgsj.ObjMap, &fgs.objMap); err != nil {
		return fmt.Errorf("error unmarshaling objMap: %w", err)
	}

	fgs.service = &service.Service{}
	if err := json.Unmarshal(fgsj.Service, fgs.service); err != nil {
		return fmt.Errorf("error unmarshaling service: %w", err)
	}

	return nil
}

func (fortiGate *fortiGateService) Name() string {
	return fortiGate.name
}

func (fortiGate *fortiGateService) TypeName() string {
	return "FortiGateService"
}

func (fortiGate *fortiGateService) Cli() string {
	return ""
}

func (fortiGate *fortiGateService) Type() firewall.FirewallObjectType {
	return fortiGate.catagory
}

// func (fortiGate *fortiGateService) Service(serviceMap map[string]firewall.FirewallServiceObject) *service.Service {
func (fortiGate *fortiGateService) Service(node firewall.FirewallNode) *service.Service {
	if fortiGate.service == nil {
		return nil
	}
	s := fortiGate.service.Copy().(*service.Service)
	ft := node.(*FortigateNode)
	serviceMap := ft.objectSet.serviceMap

	for _, ref := range fortiGate.refNames {
		if refObj, ok := serviceMap[ref]; !ok {
			panic(fmt.Sprintf("can not find ref object: %s", ref))
		} else {
			s.Add(refObj.Service(node))
		}
	}

	return s
}

//type fortiGateL4Port struct {
//	catagory  firewall.FirewallObjectType
//	cli       string
//	name      string
//	l4port    *service.L4Port
//	protocols []service.IPProto
//	refNames  []string
//}
//
//func (fortiGate *fortiGateL4Port) Name() string {
//	return fortiGate.name
//}
//
//func (fortiGate *fortiGateL4Port) Cli() string {
//	return fortiGate.cli
//}
//
//func (fortiGate *fortiGateL4Port) Type() firewall.FirewallObjectType {
//	return fortiGate.catagory
//}
//
//func (fortiGate *fortiGateL4Port) L4Port(l4portMap map[string]firewall.FirewallL4PortObject) *service.L4Port {
//	dr := fortiGate.l4port.Copy().(*flexrange.DataRange)
//	s := &service.L4Port{
//		DataRange: *dr,
//	}
//	// s := fortiGate.l4port.Copy().(*service.L4Port)
//
//	for _, ref := range fortiGate.refNames {
//		if refObj, ok := l4portMap[ref]; !ok {
//			panic(fmt.Sprintf("can not find ref object: %s", ref))
//		} else {
//			s.Add(refObj.L4Port(l4portMap))
//		}
//	}
//
//	return s
//}

//
// func (fortiGate *fortiGateService) NeedProcessRefs() bool {
// if len(fortiGate.refNames) > 0 && len(fortiGate.refs) == 0 {
// return true
// }
//
// return false
// }

type fortiGateNetwork struct {
	catagory firewall.FirewallObjectType
	objMap   dto.ForiRespResult
	name     string
	hasNat   bool
	cli      string
	network  *network.NetworkGroup
	refs     []firewall.FirewallNetworkObject
	refNames []string
}

// 实现 TypeInterface 接口
func (fgn *fortiGateNetwork) TypeName() string {
	return "FortiGateNetwork"
}

// fortiGateNetworkJSON 用于序列化和反序列化
type fortiGateNetworkJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	ObjMap   json.RawMessage             `json:"obj_map"`
	Name     string                      `json:"name"`
	HasNat   bool                        `json:"has_nat"`
	Cli      string                      `json:"cli"`
	Network  json.RawMessage             `json:"network"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (fgn *fortiGateNetwork) MarshalJSON() ([]byte, error) {
	objMap, err := json.Marshal(fgn.objMap)
	if err != nil {
		return nil, fmt.Errorf("error marshaling objMap: %w", err)
	}

	networkRaw, err := json.Marshal(fgn.network)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	return json.Marshal(fortiGateNetworkJSON{
		Catagory: fgn.catagory,
		ObjMap:   objMap,
		Name:     fgn.name,
		HasNat:   fgn.hasNat,
		Cli:      fgn.cli,
		Network:  networkRaw,
		RefNames: fgn.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (fgn *fortiGateNetwork) UnmarshalJSON(data []byte) error {
	var fgnj fortiGateNetworkJSON
	if err := json.Unmarshal(data, &fgnj); err != nil {
		return err
	}

	fgn.catagory = fgnj.Catagory
	fgn.name = fgnj.Name
	fgn.hasNat = fgnj.HasNat
	fgn.cli = fgnj.Cli
	fgn.refNames = fgnj.RefNames

	if err := json.Unmarshal(fgnj.ObjMap, &fgn.objMap); err != nil {
		return fmt.Errorf("error unmarshaling objMap: %w", err)
	}

	fgn.network = &network.NetworkGroup{}
	if err := json.Unmarshal(fgnj.Network, fgn.network); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}

	// 注意：refs 字段没有被序列化，因此在反序列化时它将保持为空切片
	fgn.refs = []firewall.FirewallNetworkObject{}

	return nil
}

func (an *fortiGateNetwork) Name() string {
	return an.name
}

func (an *fortiGateNetwork) Cli() string {
	return an.cli
}

func (an *fortiGateNetwork) Type() firewall.FirewallObjectType {
	return an.catagory
}

func (an *fortiGateNetwork) WithNat() {
	an.hasNat = true
}

func (an *fortiGateNetwork) HasNat() bool {
	return an.hasNat
}

func (an *fortiGateNetwork) NeedProcessRefs() bool {
	if len(an.refNames) > 0 && len(an.refs) == 0 {
		return true
	}

	return false
}
func (an *fortiGateNetwork) Network(node firewall.FirewallNode) *network.NetworkGroup {
	forti := node.(*FortigateNode)
	networkMap := forti.objectSet.networkMap
	ng := an.network.Copy().(*network.NetworkGroup)
	for _, ref := range an.refNames {
		if refObj, ok := networkMap[ref]; !ok {
			panic(fmt.Sprintf("can not find ref object: %s", ref))
		} else {
			ng.AddGroup(refObj.Network(node))
		}
	}
	return ng
}

type FortiObjectSet struct {
	node       *FortigateNode
	serviceMap map[string]firewall.FirewallServiceObject
	networkMap map[string]firewall.FirewallNetworkObject
	//l4portMap  map[string]firewall.FirewallL4PortObject
}

func NewFortiObjectSet(node *FortigateNode) *FortiObjectSet {
	return &FortiObjectSet{
		node:       node,
		serviceMap: map[string]firewall.FirewallServiceObject{},
		networkMap: map[string]firewall.FirewallNetworkObject{},
		//l4portMap:  map[string]firewall.FirewallL4PortObject{},
	}
}

func parseObjectNetwork(foriRespResult dto.ForiRespResult) firewall.FirewallNetworkObject {
	obj := &fortiGateNetwork{
		catagory: firewall.OBJECT_NETWORK,
		objMap:   foriRespResult,
		name:     foriRespResult.Name,
	}
	obj.network = &network.NetworkGroup{}
	switch foriRespResult.Type {
	case "ipmask":
		pairs := []templates.ParamPair{
			{S: "AddressName", V: foriRespResult.Name},
			{S: "Port", V: foriRespResult.AssociatedInterface},
		}
		if foriRespResult.Subnet != "" {
			netArr := strings.Split(foriRespResult.Subnet, " ")
			if len(netArr) < 2 {
				panic(fmt.Errorf("invalid subnet format: %s (expected 'IP Mask')", foriRespResult.Subnet))
			}
			net, err := network.ParseIPNet(netArr[0] + "/" + netArr[1])
			if err != nil {
				panic(fmt.Errorf("failed to parse subnet %s: %v", foriRespResult.Subnet, err))
			}
			pairs = append(pairs, templates.ParamPair{S: "Subnet", V: foriRespResult.Subnet})
			obj.network.Add(net)
		}

		if foriRespResult.Ip6 != "" {
			net, err := network.ParseIPNet(foriRespResult.Ip6)
			if err != nil {
				panic(err)
			}
			pairs = append(pairs, templates.ParamPair{S: "Subnet", V: foriRespResult.Ip6})
			obj.network.Add(net)
		}
		template := templates.CliTemplates["ConfigFirewallAddress"]
		obj.cli = template.Formatter(pairs)
	case "iprange":
		if foriRespResult.StartIp == "" || foriRespResult.EndIp == "" {
			panic(fmt.Errorf("invalid IP range: StartIp=%s, EndIp=%s", foriRespResult.StartIp, foriRespResult.EndIp))
		}
		net, err := network.NewNetworkFromString(foriRespResult.StartIp + "-" + foriRespResult.EndIp)
		if err != nil {
			panic(fmt.Errorf("failed to parse IP range %s-%s: %v", foriRespResult.StartIp, foriRespResult.EndIp, err))
		}
		obj.network.Add(net)
		pairs := []templates.ParamPair{
			{S: "AddressName", V: foriRespResult.Name},
			{S: "Port", V: foriRespResult.AssociatedInterface},
			{S: "StartIp", V: foriRespResult.StartIp},
			{S: "EndIp", V: foriRespResult.EndIp},
		}
		template := templates.CliTemplates["ConfigFirewallAddressWithIpRange"]
		obj.cli = template.Formatter(pairs)
	}
	return obj
}

func parseObjectNetworkGroup(forti *FortiObjectSet, foriRespResult dto.ForiRespResult) firewall.FirewallNetworkObject {
	obj := &fortiGateNetwork{
		catagory: firewall.GROUP_NETWORK,
		objMap:   foriRespResult,
		name:     foriRespResult.Name,
	}
	obj.network = &network.NetworkGroup{}
	for _, member := range foriRespResult.Member {
		objNetwork := forti.networkMap[member.Name]
		if objNetwork.Name() == "" {
			continue
		}
		obj.refNames = append(obj.refNames, member.Name)
	}

	return obj
}

func parseObjectService(foriRespResult dto.ForiRespResult) firewall.FirewallServiceObject {
	obj := &fortiGateService{
		catagory: firewall.OBJECT_SERVICE,
		objMap:   foriRespResult,
		name:     foriRespResult.Name,
	}
	if foriRespResult.SctpPortRange != "" {
		panic(fmt.Errorf("stcp no supported"))
	}
	var sport, dport string
	var srv *service.Service
	var err error
	if foriRespResult.TcpPortRange != "" {
		sport, dport = splitPortRange(foriRespResult.TcpPortRange, ":")
		srv, err = service.NewServiceWithL4("tcp", sport, dport)
		if err != nil {
			panic(err)
		}
	}
	if foriRespResult.UdpPortRange != "" {
		sport, dport = splitPortRange(foriRespResult.UdpPortRange, ":")
		tmpSrv, err := service.NewServiceWithL4("udp", sport, dport)
		if err != nil {
			panic(err)
		}

		if srv == nil {
			srv = tmpSrv
		} else {
			srv.Add(tmpSrv)
		}
	}

	if foriRespResult.Protocol == "IP" {
		if foriRespResult.ProtocolNumber == 0 {
			srv, err = service.NewServiceFromString("ip")
		} else {
			srv, err = service.NewService(service.IPProto(foriRespResult.ProtocolNumber), nil, nil, 0, 0)
		}
		if err != nil {
			panic(err)
		}
	}

	if foriRespResult.Protocol == "ICMP" {
		// ICMP 服务处理
		icmpType := foriRespResult.ProtocolNumber
		icmpCode := 0 // 默认 code 为 0，如果需要可以从其他字段获取
		srv, err = service.NewService(service.ICMP, nil, nil, icmpType, icmpCode)
		if err != nil {
			panic(err)
		}
	}

	obj.service = srv
	return obj
}

func splitPortRange(portRange string, splitStr string) (sport string, dport string) {
	if portRange != "" {
		portRange = strings.ReplaceAll(portRange, " ", ",")
	}

	arr := strings.Split(portRange, splitStr)
	if len(arr) > 1 {
		return arr[0], arr[1]
	} else {
		return "0-65535", portRange
	}
}

func parseObjectServiceGroup(forti *FortiObjectSet, foriRespResult dto.ForiRespResult) firewall.FirewallServiceObject {
	obj := &fortiGateService{
		catagory: firewall.GROUP_SERVICE,
		objMap:   foriRespResult,
		name:     foriRespResult.Name,
	}
	obj.service = &service.Service{}
	for _, member := range foriRespResult.Member {
		objService := forti.serviceMap[member.Name]
		if objService.Name() == "" {
			continue
		}
		obj.refNames = append(obj.refNames, member.Name)
	}

	return obj
}

func (forti *FortiObjectSet) parseRespResultForNetwork(result []dto.ForiRespResult) {
	for _, res := range result {
		objNetwork := parseObjectNetwork(res)
		if objNetwork.Name() == "" {
			continue
		}
		forti.networkMap[objNetwork.Name()] = objNetwork
	}
}

func (forti *FortiObjectSet) parseRespResultForNetworkGroup(result []dto.ForiRespResult) {
	for _, res := range result {
		if len(res.Member) == 0 {
			continue
		}
		objNetworkGroup := parseObjectNetworkGroup(forti, res)
		if objNetworkGroup.Name() == "" {
			continue
		}
		forti.networkMap[objNetworkGroup.Name()] = objNetworkGroup
	}
}

func (forti *FortiObjectSet) parseRespResultForService(result []dto.ForiRespResult) {
	for _, res := range result {
		objService := parseObjectService(res)
		if objService.Name() == "" {
			continue
		}
		forti.serviceMap[objService.Name()] = objService
	}
}

func (forti *FortiObjectSet) parseRespResultForServiceGroup(result []dto.ForiRespResult) {
	for _, res := range result {
		if len(res.Member) == 0 {
			continue
		}
		objServicekGroup := parseObjectServiceGroup(forti, res)
		if objServicekGroup.Name() == "" {
			continue
		}
		forti.serviceMap[objServicekGroup.Name()] = objServicekGroup
	}
}

func (fortiGate *FortiObjectSet) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType) (firewall.FirewallNetworkObject, bool) {
	for _, object := range fortiGate.networkMap {
		if object.Network(fortiGate.node).Same(ng) {
			switch searchType {
			case firewall.SEARCH_OBJECT_OR_GROUP:
				return object, true
			case firewall.SEARCH_OBJECT:
				if object.Type() == firewall.OBJECT_NETWORK {
					return object, true
				}
			case firewall.SEARCH_GROUP:
				if object.Type() == firewall.GROUP_NETWORK {
					return object, true
				}
			}
		}
	}
	return nil, false
}

func (fortiGate *FortiObjectSet) GetObjectByService(ng *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	for _, object := range fortiGate.serviceMap {
		srv := object.Service(fortiGate.node)
		if srv == nil {
			continue
		}
		if srv.Same(ng) {
			switch searchType {
			case firewall.SEARCH_OBJECT_OR_GROUP:
				return object, true
			case firewall.SEARCH_OBJECT:
				if object.Type() == firewall.OBJECT_SERVICE {
					return object, true
				}

			case firewall.SEARCH_GROUP:
				if object.Type() == firewall.GROUP_SERVICE {
					return object, true
				}
			}
		}
	}
	return nil, false
}

func (fortiGate *FortiObjectSet) Network(zone, name string) (*network.NetworkGroup, bool) {
	if obj, ok := fortiGate.networkMap[name]; !ok {
		return nil, ok
	} else {
		ng := obj.Network(fortiGate.node)
		return ng, true
	}
}

func (fortiGate *FortiObjectSet) Service(name string) (*service.Service, bool) {
	if obj, ok := fortiGate.serviceMap[name]; !ok {
		return nil, ok
	} else {
		ng := obj.Service(fortiGate.node)
		return ng, true
	}
}

// parseCLIToForiRespResult 解析 FortiGate CLI 命令并转换为 dto.ForiRespResult 对象
// 支持解析 network objects, service objects, policies, VIP, 和 Pool
// 返回解析结果和对应的类型键（如 "NETWORK", "SERVICE", "STATIC_NAT", "POOL" 等）
func parseCLIToForiRespResult(cli string) (map[string][]*dto.ForiRespResult, error) {
	resultMap := make(map[string][]*dto.ForiRespResult)
	var results []*dto.ForiRespResult
	lines := strings.Split(cli, "\n")

	var currentObj *dto.ForiRespResult
	var inBlock bool
	var blockType string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 检测配置块开始
		if strings.HasPrefix(line, "config firewall address") {
			blockType = "NETWORK"
			inBlock = true
			continue
		} else if strings.HasPrefix(line, "config firewall service custom") {
			blockType = "SERVICE"
			inBlock = true
			continue
		} else if strings.HasPrefix(line, "config firewall policy") {
			blockType = "SECURITY_POLICY"
			inBlock = true
			continue
		} else if strings.HasPrefix(line, "config firewall vip") {
			blockType = "STATIC_NAT"
			inBlock = true
			continue
		} else if strings.HasPrefix(line, "config firewall ippool") {
			blockType = "POOL"
			inBlock = true
			continue
		}

		// 检测配置块结束
		if line == "end" {
			if currentObj != nil {
				results = append(results, currentObj)
				currentObj = nil
			}
			// 将当前块的结果添加到 resultMap
			if blockType != "" && len(results) > 0 {
				resultMap[blockType] = append(resultMap[blockType], results...)
				results = []*dto.ForiRespResult{} // 重置 results
			}
			inBlock = false
			blockType = ""
			continue
		}

		// 在配置块内解析
		if inBlock {
			// 检测 edit 命令，开始新对象
			if strings.HasPrefix(line, "edit ") {
				if currentObj != nil {
					results = append(results, currentObj)
				}
				currentObj = &dto.ForiRespResult{}
				// 提取对象名称，支持带引号的名称
				name := strings.TrimPrefix(line, "edit ")
				name = strings.Trim(name, `"`)
				currentObj.Name = name
				if blockType == "NETWORK" {
					currentObj.Type = "ipmask" // 默认类型
				}
				continue
			}

			// 解析 set 命令
			if strings.HasPrefix(line, "set ") && currentObj != nil {
				setLine := strings.TrimPrefix(line, "set ")
				// 检查是否包含 "next" 命令（不应该出现在 set 命令的值中）
				if strings.Contains(setLine, "next") {
					// 移除 "next" 及其后面的内容
					nextIndex := strings.Index(setLine, "next")
					setLine = strings.TrimSpace(setLine[:nextIndex])
				}
				parts := strings.Fields(setLine)
				if len(parts) < 2 {
					continue
				}

				key := parts[0]
				value := strings.Join(parts[1:], " ")
				// 对于 mappedip，需要保留引号以便 parseQuotedStrings 正确解析
				// 其他字段移除引号
				rawValue := value
				if key != "mappedip" {
					value = strings.Trim(value, `"`)
				}

				switch key {
				case "subnet":
					// subnet 格式: "IP Mask" 或 "IP/Mask"
					currentObj.Subnet = value
					currentObj.Type = "ipmask"
				case "start-ip":
					currentObj.StartIp = value
					currentObj.Type = "iprange"
				case "end-ip":
					currentObj.EndIp = value
					currentObj.Type = "iprange"
				case "associated-interface":
					currentObj.AssociatedInterface = value
				case "tcp-portrange":
					currentObj.TcpPortRange = value
					currentObj.Protocol = "TCP"
				case "udp-portrange":
					currentObj.UdpPortRange = value
					currentObj.Protocol = "UDP"
				case "icmptype":
					// ICMP type
					if typeVal, err := parseInt(value); err == nil {
						currentObj.ProtocolNumber = typeVal
						currentObj.Protocol = "ICMP"
					}
				case "icmpcode":
					// ICMP code (如果需要，可以存储在 ProtocolNumber 或其他字段)
					// 当前实现中，ICMP code 默认是 0
				case "protocol-number":
					// 其他协议号
					if protoNum, err := parseInt(value); err == nil {
						currentObj.ProtocolNumber = protoNum
						currentObj.Protocol = "IP"
					}
				case "name":
					currentObj.Name = value
				case "srcintf":
					// 源接口
					currentObj.SrcIntf = []dto.ResultMember{{Name: value}}
				case "dstintf":
					// 目标接口
					currentObj.DstIntf = []dto.ResultMember{{Name: value}}
				case "srcaddr":
					// 源地址对象列表，可能包含多个对象
					objNames := parseQuotedStrings(value)
					for _, objName := range objNames {
						currentObj.SrcAddr = append(currentObj.SrcAddr, dto.ResultMember{Name: objName})
					}
				case "dstaddr":
					// 目标地址对象列表
					objNames := parseQuotedStrings(value)
					for _, objName := range objNames {
						currentObj.DstAddr = append(currentObj.DstAddr, dto.ResultMember{Name: objName})
					}
				case "service":
					// 服务对象列表
					objNames := parseQuotedStrings(value)
					for _, objName := range objNames {
						currentObj.Service = append(currentObj.Service, dto.ResultMember{Name: objName})
					}
				case "action":
					currentObj.Action = value
				case "status":
					currentObj.Status = value
				// VIP 相关字段
				case "extip":
					currentObj.ExtIp = value
				case "mappedip":
					// mappedip 可能是多个 IP，用引号分隔
					// 使用原始值（带引号）以便 parseQuotedStrings 正确解析
					ipNames := parseQuotedStrings(rawValue)
					for _, ipName := range ipNames {
						// 使用 Range 字段存储 IP 地址（parseRespResultForVip 期望 Range 字段）
						currentObj.MappedIp = append(currentObj.MappedIp, dto.ResultMember{Range: ipName})
					}
				case "extintf":
					currentObj.ExtIntf = value
				case "portforward":
					currentObj.PortForward = value
				case "extport":
					currentObj.ExtPort = value
					// 如果 extport 存在且 portforward 是 enable，推断协议为 TCP（默认）
					// 注意：FortiGate VIP 通常使用 TCP，除非明确指定为 UDP
					if currentObj.PortForward == "enable" && currentObj.Protocol == "" {
						currentObj.Protocol = "TCP"
					}
				case "mappedport":
					currentObj.MappedPort = value
					// 如果 mappedport 存在且 portforward 是 enable，推断协议为 TCP（默认）
					if currentObj.PortForward == "enable" && currentObj.Protocol == "" {
						currentObj.Protocol = "TCP"
					}
				// Pool 相关字段
				case "type":
					// Pool 的 type: overload, fixed-port-range
					currentObj.Type = value
				case "startip":
					currentObj.StartIpPool = value
				case "endip":
					currentObj.EndIpPool = value
				case "source-startip":
					currentObj.SourceStartIpPool = value
				case "source-endip":
					currentObj.SourceEndIpPool = value
				case "startport":
					if portVal, err := parseInt(value); err == nil {
						currentObj.StartPortPool = portVal
					}
				case "endport":
					if portVal, err := parseInt(value); err == nil {
						currentObj.EndPortPool = portVal
					}
				}
			}

			// 检测 next 命令，结束当前对象
			if line == "next" && currentObj != nil {
				results = append(results, currentObj)
				currentObj = nil
			}
		}
	}

	// 处理最后一个对象（如果没有 next 命令）
	if currentObj != nil {
		results = append(results, currentObj)
	}

	// 将剩余的结果添加到 resultMap
	if blockType != "" && len(results) > 0 {
		resultMap[blockType] = append(resultMap[blockType], results...)
	}

	return resultMap, nil
}

// parseInt 解析字符串为整数
func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

// parseQuotedStrings 解析带引号的字符串列表
// 例如: "obj1" "obj2" "obj3" -> ["obj1", "obj2", "obj3"]
func parseQuotedStrings(s string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false

	for _, char := range s {
		if char == '"' {
			if inQuotes {
				// 结束引号
				if current.Len() > 0 {
					result = append(result, current.String())
					current.Reset()
				}
				inQuotes = false
			} else {
				// 开始引号
				inQuotes = true
			}
		} else if inQuotes {
			current.WriteRune(char)
		}
	}

	// 处理最后一个未闭合的引号
	if inQuotes && current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}
