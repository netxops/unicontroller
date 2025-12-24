package sangfor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
)

type SangforObjectSet struct {
	node       *SangforNode
	networkMap map[string]*SangforNetworkObject
	serviceMap map[string]*SangforServiceObject
}

type SangforNetworkObject struct {
	name     string
	network  *network.NetworkGroup
	refNames []string // 引用的网络对象名称列表（用于地址组）
	objType  firewall.FirewallObjectType
}

// TypeName 实现 TypedInterface 接口
func (sno *SangforNetworkObject) TypeName() string {
	return "SangforNetworkObject"
}

// sangforNetworkObjectJSON 用于序列化和反序列化
type sangforNetworkObjectJSON struct {
	Name     string                      `json:"name"`
	Network  json.RawMessage             `json:"network"`
	RefNames []string                    `json:"ref_names"`
	ObjType  firewall.FirewallObjectType `json:"obj_type"`
}

// MarshalJSON 实现 JSON 序列化
func (sno *SangforNetworkObject) MarshalJSON() ([]byte, error) {
	networkRaw, err := json.Marshal(sno.network)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	return json.Marshal(sangforNetworkObjectJSON{
		Name:     sno.name,
		Network:  networkRaw,
		RefNames: sno.refNames,
		ObjType:  sno.objType,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (sno *SangforNetworkObject) UnmarshalJSON(data []byte) error {
	var snoj sangforNetworkObjectJSON
	if err := json.Unmarshal(data, &snoj); err != nil {
		return err
	}

	sno.name = snoj.Name
	sno.refNames = snoj.RefNames
	sno.objType = snoj.ObjType
	sno.network = &network.NetworkGroup{}
	if err := json.Unmarshal(snoj.Network, sno.network); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}

	return nil
}

func (sno *SangforNetworkObject) Name() string {
	return sno.name
}

func (sno *SangforNetworkObject) Network(node firewall.FirewallNode) *network.NetworkGroup {
	// 如果有引用，需要递归解析引用的对象
	if len(sno.refNames) > 0 {
		ng := network.NewNetworkGroup()
		if sno.network != nil {
			ng.AddGroup(sno.network)
		}
		sangforNode := node.(*SangforNode)
		for _, refName := range sno.refNames {
			if refObj, ok := sangforNode.objectSet.networkMap[refName]; ok {
				refNg := refObj.Network(node)
				if refNg != nil {
					ng.AddGroup(refNg)
				}
			}
		}
		return ng
	}
	return sno.network
}

func (sno *SangforNetworkObject) Cli() string {
	if sno.network == nil {
		return ""
	}

	var builder strings.Builder
	builder.WriteString("config\n")
	builder.WriteString(fmt.Sprintf(`ipgroup "%s" ipv4`, sno.name))
	builder.WriteString("\n")

	// 如果有引用，生成地址组格式
	if len(sno.refNames) > 0 {
		builder.WriteString("type addrgroup\n")
		builder.WriteString("importance ordinary\n")
		for _, refName := range sno.refNames {
			builder.WriteString(fmt.Sprintf(`member "%s"`, refName))
			builder.WriteString("\n")
		}
	} else {
		// 生成单个地址对象格式
		builder.WriteString("type ip\n")
		builder.WriteString("importance ordinary\n")
		// 生成 ipentry
		sno.network.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
			if ipNet, ok := item.(*network.IPNet); ok {
				// CIDR 格式
				builder.WriteString(fmt.Sprintf("ipentry %s/%d\n", ipNet.IP.String(), ipNet.Mask.Prefix()))
			} else if ipRange, ok := item.(*network.IPRange); ok {
				// IP 范围格式
				builder.WriteString(fmt.Sprintf("ipentry %s-%s\n", ipRange.Start.String(), ipRange.End.String()))
			}
			return true
		})
	}

	builder.WriteString("end\n")
	return builder.String()
}

func (sno *SangforNetworkObject) Type() firewall.FirewallObjectType {
	return sno.objType
}

type SangforServiceObject struct {
	name     string
	service  *service.Service
	refNames []string // 引用的服务对象名称列表（用于服务组）
	objType  firewall.FirewallObjectType
}

// TypeName 实现 TypedInterface 接口
func (sso *SangforServiceObject) TypeName() string {
	return "SangforServiceObject"
}

// sangforServiceObjectJSON 用于序列化和反序列化
type sangforServiceObjectJSON struct {
	Name     string                      `json:"name"`
	Service  json.RawMessage             `json:"service"`
	RefNames []string                    `json:"ref_names"`
	ObjType  firewall.FirewallObjectType `json:"obj_type"`
}

// MarshalJSON 实现 JSON 序列化
func (sso *SangforServiceObject) MarshalJSON() ([]byte, error) {
	serviceRaw, err := json.Marshal(sso.service)
	if err != nil {
		return nil, fmt.Errorf("error marshaling service: %w", err)
	}

	return json.Marshal(sangforServiceObjectJSON{
		Name:     sso.name,
		Service:  serviceRaw,
		RefNames: sso.refNames,
		ObjType:  sso.objType,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (sso *SangforServiceObject) UnmarshalJSON(data []byte) error {
	var ssoj sangforServiceObjectJSON
	if err := json.Unmarshal(data, &ssoj); err != nil {
		return err
	}

	sso.name = ssoj.Name
	sso.refNames = ssoj.RefNames
	sso.objType = ssoj.ObjType
	sso.service = &service.Service{}
	if err := json.Unmarshal(ssoj.Service, sso.service); err != nil {
		return fmt.Errorf("error unmarshaling service: %w", err)
	}

	return nil
}

func (sso *SangforServiceObject) Name() string {
	return sso.name
}

func (sso *SangforServiceObject) Service(node firewall.FirewallNode) *service.Service {
	// 如果有引用，需要递归解析引用的服务
	if len(sso.refNames) > 0 {
		svc := sso.service.Copy().(*service.Service)
		sangforNode := node.(*SangforNode)
		for _, refName := range sso.refNames {
			if refObj, ok := sangforNode.objectSet.serviceMap[refName]; ok {
				refSvc := refObj.Service(node)
				if refSvc != nil {
					svc.Add(refSvc)
				}
			}
		}
		return svc
	}
	return sso.service
}

func (sso *SangforServiceObject) Cli() string {
	if sso.service == nil {
		return ""
	}

	var builder strings.Builder
	builder.WriteString("config\n")
	builder.WriteString(fmt.Sprintf(`service "%s"`, sso.name))
	builder.WriteString("\n")

	// 如果有引用，生成引用
	if len(sso.refNames) > 0 {
		for _, refName := range sso.refNames {
			builder.WriteString(fmt.Sprintf(`servsInfo "%s"`, refName))
			builder.WriteString("\n")
		}
	} else {
		// 生成服务条目
		sso.service.EachDetailed(func(entry service.ServiceEntry) bool {
			switch e := entry.(type) {
			case *service.L4Service:
				protocol := strings.ToLower(e.Protocol().String())
				if e.Protocol() == service.TCP {
					dstPort := e.DstPort()
					if dstPort != nil && len(dstPort.L) > 0 {
						portRange := dstPort.L[0]
						if portRange.Low() == portRange.High() {
							builder.WriteString(fmt.Sprintf("tcp-entry destination-port %d\n", portRange.Low()))
						} else {
							builder.WriteString(fmt.Sprintf("tcp-entry destination-port %d-%d\n", portRange.Low(), portRange.High()))
						}
					}
				} else if e.Protocol() == service.UDP {
					dstPort := e.DstPort()
					if dstPort != nil && len(dstPort.L) > 0 {
						portRange := dstPort.L[0]
						if portRange.Low() == portRange.High() {
							builder.WriteString(fmt.Sprintf("udp-entry destination-port %d\n", portRange.Low()))
						} else {
							builder.WriteString(fmt.Sprintf("udp-entry destination-port %d-%d\n", portRange.Low(), portRange.High()))
						}
					}
				} else {
					builder.WriteString(fmt.Sprintf("other-entry protocol %s\n", protocol))
				}
			case *service.ICMPProto:
				if e.Protocol() == service.ICMP {
					builder.WriteString("icmp-entry\n")
				} else if e.Protocol() == service.ICMP6 {
					builder.WriteString("icmpv6-entry\n")
				}
			case *service.L3Protocol:
				protocol := strings.ToLower(e.Protocol().String())
				builder.WriteString(fmt.Sprintf("other-entry protocol %s\n", protocol))
			}
			return true
		})
	}

	builder.WriteString("end\n")
	return builder.String()
}

func (sso *SangforServiceObject) Type() firewall.FirewallObjectType {
	return sso.objType
}

func NewSangforObjectSet(node *SangforNode) *SangforObjectSet {
	return &SangforObjectSet{
		node:       node,
		networkMap: make(map[string]*SangforNetworkObject),
		serviceMap: make(map[string]*SangforServiceObject),
	}
}

// parseRespResultForNetwork 解析网络对象响应
func (sos *SangforObjectSet) parseRespResultForNetwork(resp map[string]interface{}) {
	// 检查响应码
	if code, ok := resp["code"].(float64); !ok || code != 0 {
		return
	}

	// 解析 data.items 数组
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if items, ok := data["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					sos.parseNetworkItem(itemMap)
				}
			}
		}
	}
}

// parseNetworkItem 解析单个网络对象项
func (sos *SangforObjectSet) parseNetworkItem(itemMap map[string]interface{}) {
	name, _ := itemMap["name"].(string)
	if name == "" {
		return
	}

	ng := network.NewNetworkGroup()
	var refNames []string
	objType := firewall.OBJECT_NETWORK

	// 首先检查 objType 字段（用于 POOL 等特殊类型）
	if objTypeStr, ok := itemMap["objType"].(string); ok {
		switch objTypeStr {
		case "POOL":
			objType = firewall.OBJECT_POOL
		case "GROUP_NETWORK", "ADDRGROUP":
			objType = firewall.GROUP_NETWORK
		case "NETWORK":
			objType = firewall.OBJECT_NETWORK
		}
	}

	// 解析 businessType 判断对象类型（如果 objType 未设置）
	if objType == firewall.OBJECT_NETWORK {
		businessType, _ := itemMap["businessType"].(string)
		if businessType == "ADDRGROUP" {
			objType = firewall.GROUP_NETWORK
		}
	}

	// 解析 ipRanges 数组
	if ipRanges, ok := itemMap["ipRanges"].([]interface{}); ok {
		fmt.Printf("[parseNetworkItem] %s: ipRanges 数量: %d\n", name, len(ipRanges))
		for i, ipRange := range ipRanges {
			if ipRangeMap, ok := ipRange.(map[string]interface{}); ok {
				start, _ := ipRangeMap["start"].(string)
				end, _ := ipRangeMap["end"].(string)
				bits, hasBits := ipRangeMap["bits"].(float64)
				fmt.Printf("[parseNetworkItem] %s: ipRange[%d] start=%s, end=%s, bits=%v (hasBits=%v)\n", name, i, start, end, bits, hasBits)

				if start != "" {
					var net *network.Network
					var err error

					if hasBits && bits > 0 {
						// 有 bits 字段，解析为 CIDR
						cidr := fmt.Sprintf("%s/%d", start, int(bits))
						fmt.Printf("[parseNetworkItem] %s: 解析 CIDR: %s\n", name, cidr)
						net, err = network.NewNetworkFromString(cidr)
					} else if end != "" {
						// 有 end 字段，解析为 IP 范围
						rangeStr := start + "-" + end
						fmt.Printf("[parseNetworkItem] %s: 解析 IP 范围: %s\n", name, rangeStr)
						net, err = network.NewNetworkFromString(rangeStr)
					} else {
						// 只有 start，尝试解析为单个 IP
						fmt.Printf("[parseNetworkItem] %s: 解析单个 IP: %s\n", name, start)
						net, err = network.NewNetworkFromString(start)
					}

					if err == nil && net != nil {
						fmt.Printf("[parseNetworkItem] %s: 成功解析网络: %s\n", name, net.String())
						ng.Add(net)
					} else if err != nil {
						fmt.Printf("[parseNetworkItem] %s: 解析网络失败: %v\n", name, err)
					}
				}
			}
		}
		fmt.Printf("[parseNetworkItem] %s: 最终 NetworkGroup: %s\n", name, ng.String())
	}

	// 解析 member 数组（地址组成员，新格式）
	if members, ok := itemMap["member"].([]interface{}); ok && len(members) > 0 {
		objType = firewall.GROUP_NETWORK
		for _, member := range members {
			if memberName, ok := member.(string); ok && memberName != "" {
				refNames = append(refNames, memberName)
			}
		}
	}

	// 解析 refIpGroup 数组（地址组引用，兼容旧格式）
	if len(refNames) == 0 {
		if refIpGroup, ok := itemMap["refIpGroup"].([]interface{}); ok && len(refIpGroup) > 0 {
			objType = firewall.GROUP_NETWORK
			for _, ref := range refIpGroup {
				if refName, ok := ref.(string); ok && refName != "" {
					refNames = append(refNames, refName)
				}
			}
		}
	}

	// 解析 domains 数组（域名对象，暂时跳过或记录到扩展字段）
	// domains 暂时不处理，因为 network.NetworkGroup 不支持域名

	// 创建网络对象（即使没有网络内容，如果是地址组也要创建）
	if ng.Count().Int64() > 0 || len(refNames) > 0 {
		sos.networkMap[name] = &SangforNetworkObject{
			name:     name,
			network:  ng,
			refNames: refNames,
			objType:  objType,
		}
	}
}

// parseRespResultForService 解析服务对象响应
func (sos *SangforObjectSet) parseRespResultForService(resp map[string]interface{}) {
	// 检查响应码
	if code, ok := resp["code"].(float64); !ok || code != 0 {
		return
	}

	// 解析 data.items 数组
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if items, ok := data["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					sos.parseServiceItem(itemMap)
				}
			}
		}
	}
}

// parseServiceItem 解析单个服务对象项
func (sos *SangforObjectSet) parseServiceItem(itemMap map[string]interface{}) {
	name, _ := itemMap["name"].(string)
	if name == "" {
		return
	}

	svc := &service.Service{}
	var refNames []string
	objType := firewall.OBJECT_SERVICE
	hasServiceContent := false

	// 调试：检查输入数据
	// fmt.Printf("parseServiceItem: name=%s, tcpEntrys=%v\n", name, itemMap["tcpEntrys"])

	// 解析 servType 判断对象类型
	servType, _ := itemMap["servType"].(string)
	if servType == "SERV_GRP" {
		objType = firewall.GROUP_SERVICE
	}

	// 解析 tcpEntrys 数组
	if tcpEntrysRaw, ok := itemMap["tcpEntrys"]; ok && tcpEntrysRaw != nil {
		// 支持两种类型：[]interface{} 和 []map[string]interface{}
		var tcpEntrys []interface{}
		if tcpEntrysInterface, ok := tcpEntrysRaw.([]interface{}); ok {
			tcpEntrys = tcpEntrysInterface
		} else if tcpEntrysMap, ok := tcpEntrysRaw.([]map[string]interface{}); ok {
			// 将 []map[string]interface{} 转换为 []interface{}
			tcpEntrys = make([]interface{}, len(tcpEntrysMap))
			for i, entry := range tcpEntrysMap {
				tcpEntrys[i] = entry
			}
		}

		if len(tcpEntrys) > 0 {
			for _, tcpEntry := range tcpEntrys {
				if tcpEntryMap, ok := tcpEntry.(map[string]interface{}); ok {
					sportStr := parsePortRanges(tcpEntryMap["srcPorts"])
					dportStr := parsePortRanges(tcpEntryMap["dstPorts"])
					if dportStr == "" {
						dportStr = "0-65535"
					}
					if sportStr == "" {
						sportStr = "0-65535"
					}
					tmpSrv, err := service.NewServiceWithL4("tcp", sportStr, dportStr)
					if err == nil {
						svc.Add(tmpSrv)
						hasServiceContent = true
					}
				}
			}
		}
	}

	// 解析 udpEntrys 数组
	if udpEntrysRaw, ok := itemMap["udpEntrys"]; ok && udpEntrysRaw != nil {
		var udpEntrys []interface{}
		if udpEntrysInterface, ok := udpEntrysRaw.([]interface{}); ok {
			udpEntrys = udpEntrysInterface
		} else if udpEntrysMap, ok := udpEntrysRaw.([]map[string]interface{}); ok {
			udpEntrys = make([]interface{}, len(udpEntrysMap))
			for i, entry := range udpEntrysMap {
				udpEntrys[i] = entry
			}
		}

		if len(udpEntrys) > 0 {
			for _, udpEntry := range udpEntrys {
				if udpEntryMap, ok := udpEntry.(map[string]interface{}); ok {
					sportStr := parsePortRanges(udpEntryMap["srcPorts"])
					dportStr := parsePortRanges(udpEntryMap["dstPorts"])
					if dportStr == "" {
						dportStr = "0-65535"
					}
					if sportStr == "" {
						sportStr = "0-65535"
					}
					tmpSrv, err := service.NewServiceWithL4("udp", sportStr, dportStr)
					if err == nil {
						svc.Add(tmpSrv)
						hasServiceContent = true
					}
				}
			}
		}
	}

	// 解析 icmpEntrys 数组
	if icmpEntrysRaw, ok := itemMap["icmpEntrys"]; ok && icmpEntrysRaw != nil {
		// 支持两种类型：[]interface{} 和 []map[string]interface{}
		var icmpEntrys []interface{}
		if icmpEntrysInterface, ok := icmpEntrysRaw.([]interface{}); ok {
			icmpEntrys = icmpEntrysInterface
		} else if icmpEntrysMap, ok := icmpEntrysRaw.([]map[string]interface{}); ok {
			// 将 []map[string]interface{} 转换为 []interface{}
			icmpEntrys = make([]interface{}, len(icmpEntrysMap))
			for i, entry := range icmpEntrysMap {
				icmpEntrys[i] = entry
			}
		}

		if len(icmpEntrys) > 0 {
			for _, icmpEntry := range icmpEntrys {
				if icmpEntryMap, ok := icmpEntry.(map[string]interface{}); ok {
					icmpType := uint8(0)
					icmpCode := uint8(0)
					if t, ok := icmpEntryMap["type"].(float64); ok {
						icmpType = uint8(t)
					}
					if c, ok := icmpEntryMap["code"].(float64); ok {
						icmpCode = uint8(c)
					}
					// 255 表示全部
					if icmpType == 255 {
						icmpType = 0
					}
					if icmpCode == 255 {
						icmpCode = 0
					}
					tmpSrv, err := service.NewService(service.ICMP, nil, nil, int(icmpType), int(icmpCode))
					if err == nil {
						svc.Add(tmpSrv)
						hasServiceContent = true
					}
				}
			}
		}
	}

	// 解析 icmpv6Entrys 数组
	if icmpv6EntrysRaw, ok := itemMap["icmpv6Entrys"]; ok && icmpv6EntrysRaw != nil {
		// 支持两种类型：[]interface{} 和 []map[string]interface{}
		var icmpv6Entrys []interface{}
		if icmpv6EntrysInterface, ok := icmpv6EntrysRaw.([]interface{}); ok {
			icmpv6Entrys = icmpv6EntrysInterface
		} else if icmpv6EntrysMap, ok := icmpv6EntrysRaw.([]map[string]interface{}); ok {
			// 将 []map[string]interface{} 转换为 []interface{}
			icmpv6Entrys = make([]interface{}, len(icmpv6EntrysMap))
			for i, entry := range icmpv6EntrysMap {
				icmpv6Entrys[i] = entry
			}
		}

		if len(icmpv6Entrys) > 0 {
			for _, icmpv6Entry := range icmpv6Entrys {
				if icmpv6EntryMap, ok := icmpv6Entry.(map[string]interface{}); ok {
					icmpType := uint8(0)
					icmpCode := uint8(0)
					if t, ok := icmpv6EntryMap["type"].(float64); ok {
						icmpType = uint8(t)
					}
					if c, ok := icmpv6EntryMap["code"].(float64); ok {
						icmpCode = uint8(c)
					}
					// 255 表示全部
					if icmpType == 255 {
						icmpType = 0
					}
					if icmpCode == 255 {
						icmpCode = 0
					}
					tmpSrv, err := service.NewService(service.ICMP6, nil, nil, int(icmpType), int(icmpCode))
					if err == nil {
						svc.Add(tmpSrv)
						hasServiceContent = true
					}
				}
			}
		}
	}

	// 解析 other 数组（其他协议号）
	if other, ok := itemMap["other"].([]interface{}); ok {
		for _, protoNum := range other {
			if protoNumFloat, ok := protoNum.(float64); ok {
				protoNumInt := uint16(protoNumFloat)
				// 256 表示除 tcp,udp,icmp,icmpv6 之外的所有其他协议号
				if protoNumInt == 256 {
					tmpSrv, err := service.NewServiceFromString("ip")
					if err == nil {
						svc.Add(tmpSrv)
						hasServiceContent = true
					}
				} else {
					tmpSrv, err := service.NewService(service.IPProto(protoNumInt), nil, nil, 0, 0)
					if err == nil {
						svc.Add(tmpSrv)
						hasServiceContent = true
					}
				}
			}
		}
	}

	// 解析 servsInfo 数组（服务组引用）
	if servsInfo, ok := itemMap["servsInfo"].([]interface{}); ok && len(servsInfo) > 0 {
		objType = firewall.GROUP_SERVICE
		for _, serv := range servsInfo {
			if servName, ok := serv.(string); ok && servName != "" {
				refNames = append(refNames, servName)
			}
		}
		hasServiceContent = true
	}

	// 创建服务对象（即使没有服务内容，如果是服务组也要创建）
	if hasServiceContent || len(refNames) > 0 {
		sos.serviceMap[name] = &SangforServiceObject{
			name:     name,
			service:  svc,
			refNames: refNames,
			objType:  objType,
		}
	}
}

// parsePortRanges 解析端口范围数组，返回端口字符串（如 "80" 或 "80-8080" 或 "80,443,8080-8090"）
func parsePortRanges(portRanges interface{}) string {
	if portRanges == nil {
		return ""
	}

	// 支持两种类型：[]interface{} 和 []map[string]interface{}
	var portRangeList []interface{}
	if portRangeListInterface, ok := portRanges.([]interface{}); ok {
		portRangeList = portRangeListInterface
	} else if portRangeListMap, ok := portRanges.([]map[string]interface{}); ok {
		// 将 []map[string]interface{} 转换为 []interface{}
		portRangeList = make([]interface{}, len(portRangeListMap))
		for i, entry := range portRangeListMap {
			portRangeList[i] = entry
		}
	} else {
		return ""
	}

	if len(portRangeList) == 0 {
		return ""
	}

	var portStrs []string
	for _, portRange := range portRangeList {
		if portRangeMap, ok := portRange.(map[string]interface{}); ok {
			start, _ := portRangeMap["start"].(float64)
			end, hasEnd := portRangeMap["end"].(float64)

			startInt := int32(start)
			if hasEnd {
				endInt := int32(end)
				if startInt == endInt {
					portStrs = append(portStrs, fmt.Sprintf("%d", startInt))
				} else {
					portStrs = append(portStrs, fmt.Sprintf("%d-%d", startInt, endInt))
				}
			} else {
				portStrs = append(portStrs, fmt.Sprintf("%d", startInt))
			}
		}
	}

	if len(portStrs) == 0 {
		return ""
	}
	if len(portStrs) == 1 {
		return portStrs[0]
	}
	// 多个端口范围用逗号连接
	return strings.Join(portStrs, ",")
}

func (sos *SangforObjectSet) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	// 遍历所有网络对象，查找匹配的网络组
	for _, object := range sos.networkMap {
		if object.network == nil {
			continue
		}

		objv4, _ := object.network.Split()

		if objv4 != nil && objv4.Same(ng) {
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

func (sos *SangforObjectSet) GetObjectByService(sg *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	// 遍历所有服务对象，查找匹配的服务
	for _, object := range sos.serviceMap {
		if object.service == nil {
			continue
		}
		if object.service.Same(sg) {
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

func (sos *SangforObjectSet) Network(zone, name string) (*network.NetworkGroup, bool) {
	if obj, ok := sos.networkMap[name]; ok {
		return obj.network, true
	}
	return nil, false
}

func (sos *SangforObjectSet) Service(name string) (*service.Service, bool) {
	if obj, ok := sos.serviceMap[name]; ok {
		return obj.service, true
	}
	return nil, false
}

func (sos *SangforObjectSet) L4Port(name string) (*service.L4Port, bool) {
	// TODO: 实现 L4 端口查找
	return nil, false
}

func (sos *SangforObjectSet) HasObjectName(name string) bool {
	if _, ok := sos.networkMap[name]; ok {
		return true
	}
	if _, ok := sos.serviceMap[name]; ok {
		return true
	}
	return false
}
