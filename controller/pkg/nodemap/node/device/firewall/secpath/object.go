package secpath

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/secpath/model"

	//"github.com/netxops/unify/global"
	//M "github.com/netxops/unify/model"
	"strings"

	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/tools"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"

	"github.com/mitchellh/mapstructure"
)

type ZoneName string

type SecPathObjectSet struct {
	node *SecPathNode
	// services       []firewall.FirewallServiceObject
	ServiceMap     map[string]firewall.FirewallServiceObject
	ZoneNetworkMap map[ZoneName]map[string]firewall.FirewallNetworkObject
	// networks []firewall.FirewallNetworkObject
	// ipv6Networks []firewall.FirewallServiceObject
	// zoneNetworkMap map[string]map[string]firewall.FirewallNetworkObject
	// serviceMap map[string]firewall.FirewallServiceObject
	// poolMap    map[firewall.NatType]map[string]firewall.FirewallNetworkObject
	PortObjectMap map[string]*secpathPortObject
}

// 实现 TypeInterface 接口
func (spos *SecPathObjectSet) TypeName() string {
	return "SecPathObjectSet"
}

// MarshalJSON 实现 JSON 序列化
func (spos *SecPathObjectSet) MarshalJSON() ([]byte, error) {
	serviceMapRaw, err := registry.MapToRawMessage(spos.ServiceMap)
	if err != nil {
		return nil, fmt.Errorf("error marshaling serviceMap: %w", err)
	}

	zoneNetworkMapRaw := make(map[ZoneName]json.RawMessage)
	for zone, networkMap := range spos.ZoneNetworkMap {
		networkMapRaw, err := registry.MapToRawMessage(networkMap)
		if err != nil {
			return nil, fmt.Errorf("error marshaling zoneNetworkMap for zone %s: %w", zone, err)
		}
		zoneNetworkMapRaw[zone] = networkMapRaw
	}

	return json.Marshal(secPathObjectSetJSON{
		ServiceMap:     serviceMapRaw,
		ZoneNetworkMap: zoneNetworkMapRaw,
		PortObjectMap:  spos.PortObjectMap,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (spos *SecPathObjectSet) UnmarshalJSON(data []byte) error {
	var sposj secPathObjectSetJSON
	if err := json.Unmarshal(data, &sposj); err != nil {
		return err
	}

	var err error
	spos.ServiceMap, err = registry.RawMessageToMap[firewall.FirewallServiceObject](sposj.ServiceMap)
	if err != nil {
		return fmt.Errorf("error unmarshaling serviceMap: %w", err)
	}

	spos.ZoneNetworkMap = make(map[ZoneName]map[string]firewall.FirewallNetworkObject)
	for zone, rawNetworkMap := range sposj.ZoneNetworkMap {
		networkMap, err := registry.RawMessageToMap[firewall.FirewallNetworkObject](rawNetworkMap)
		if err != nil {
			return fmt.Errorf("error unmarshaling zoneNetworkMap for zone %s: %w", zone, err)
		}
		spos.ZoneNetworkMap[zone] = networkMap
	}

	spos.PortObjectMap = sposj.PortObjectMap

	// 注意：node 字段被忽略，需要在其他地方设置

	return nil
}

// secPathObjectSetJSON 用于序列化和反序列化
type secPathObjectSetJSON struct {
	ServiceMap     json.RawMessage               `json:"service_map"`
	ZoneNetworkMap map[ZoneName]json.RawMessage  `json:"zone_network_map"`
	PortObjectMap  map[string]*secpathPortObject `json:"port_object_map"`
}

func NewSecPathObjectSet(node *SecPathNode) *SecPathObjectSet {
	return &SecPathObjectSet{
		node:           node,
		ZoneNetworkMap: map[ZoneName]map[string]firewall.FirewallNetworkObject{},
		ServiceMap:     map[string]firewall.FirewallServiceObject{},
		PortObjectMap:  map[string]*secpathPortObject{},
	}
}

type secpathService struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	service  *service.Service
	refNames []string
}

// 实现 TypeInterface 接口
func (ss *secpathService) TypeName() string {
	return "SecpathService"
}

// secpathServiceJSON 用于序列化和反序列化
type secpathServiceJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	Service  json.RawMessage             `json:"service"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (ss *secpathService) MarshalJSON() ([]byte, error) {
	serviceRaw, err := json.Marshal(ss.service)
	if err != nil {
		return nil, fmt.Errorf("error marshaling service: %w", err)
	}

	return json.Marshal(secpathServiceJSON{
		Catagory: ss.catagory,
		Cli:      ss.cli,
		Name:     ss.name,
		Service:  serviceRaw,
		RefNames: ss.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ss *secpathService) UnmarshalJSON(data []byte) error {
	var ssj secpathServiceJSON
	if err := json.Unmarshal(data, &ssj); err != nil {
		return err
	}

	ss.catagory = ssj.Catagory
	ss.cli = ssj.Cli
	ss.name = ssj.Name
	ss.refNames = ssj.RefNames

	ss.service = &service.Service{}
	if err := json.Unmarshal(ssj.Service, ss.service); err != nil {
		return fmt.Errorf("error unmarshaling service: %w", err)
	}

	return nil
}

type secpathPortObject struct {
	name     string
	l4port   *service.L4Port
	refNames []string
}

// 实现 TypeInterface 接口
func (spo *secpathPortObject) TypeName() string {
	return "SecpathPortObject"
}

// secpathPortObjectJSON 用于序列化和反序列化
type secpathPortObjectJSON struct {
	Name     string          `json:"name"`
	L4Port   json.RawMessage `json:"l4port"`
	RefNames []string        `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (spo *secpathPortObject) MarshalJSON() ([]byte, error) {
	var l4portRaw json.RawMessage
	var err error
	if spo.l4port != nil {
		l4portRaw, err = json.Marshal(spo.l4port)
		if err != nil {
			return nil, fmt.Errorf("error marshaling l4port: %w", err)
		}
	}

	return json.Marshal(secpathPortObjectJSON{
		Name:     spo.name,
		L4Port:   l4portRaw,
		RefNames: spo.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (spo *secpathPortObject) UnmarshalJSON(data []byte) error {
	var spoj secpathPortObjectJSON
	if err := json.Unmarshal(data, &spoj); err != nil {
		return err
	}

	spo.name = spoj.Name
	spo.refNames = spoj.RefNames

	if len(spoj.L4Port) > 0 {
		spo.l4port = &service.L4Port{}
		if err := json.Unmarshal(spoj.L4Port, spo.l4port); err != nil {
			return fmt.Errorf("error unmarshaling l4port: %w", err)
		}
	}

	return nil
}

func (portObj *secpathPortObject) L4Port(objects *SecPathObjectSet) (*service.L4Port, bool) {
	var l4port *service.L4Port

	if portObj.l4port != nil {
		l4port = portObj.l4port.Copy().(*service.L4Port)
	}

	for _, ref := range portObj.refNames {
		if refObj, ok := objects.PortObjectMap[ref]; !ok {
			return nil, false
		} else {
			p4, ok := refObj.L4Port(objects)
			if !ok {
				return nil, false
			}
			if l4port == nil {
				l4port = p4
			} else {
				l4port.Add(p4)
			}
		}
	}

	return l4port, true
}

func (srvObj *secpathService) Name() string {
	return srvObj.name
}

func (srvObj *secpathService) Cli() string {
	return srvObj.cli
}

func (srvObj *secpathService) Type() firewall.FirewallObjectType {
	return srvObj.catagory
}

func (srvObj *secpathService) Service(node firewall.FirewallNode) *service.Service {
	s := srvObj.service.Copy().(*service.Service)
	secpath := node.(*SecPathNode)
	serviceMap := secpath.ObjectSet.ServiceMap

	for _, ref := range srvObj.refNames {
		if refObj, ok := serviceMap[ref]; !ok {
			panic(fmt.Sprintf("can not find ref object: %s", ref))
		} else {
			s.Add(refObj.Service(node))
		}
	}

	return s
}

func (sec *SecPathObjectSet) parseNetworkCli(config string) {
	sections := strings.Split(config, "#")

	objectSections := []string{}
	for _, section := range sections {
		if strings.Index(strings.TrimSpace(section), "object-group ip") == 0 {
			objectSections = append(objectSections, strings.TrimSpace(section))
		}
	}

	networkRegexMap := map[string]string{
		"regex": `
		    (^object-group\sip(v6)?\saddress\s(?P<name>\S+))|
			(security-zone\s(?P<zone>\S+))|
			(network\sgroup-object\s(?P<obj>\S+))|
			(network\shost\saddress\s(?P<host>\S+))|
			(network\ssubnet\s(?P<subnet>\S+)\s(?P<prefix>\S+))|
			(network\srange\s(?P<range>\S+)\s(?P<end>\S+))
		`,
		"name":  "name",
		"flags": "mx",
		"pcre":  "true",
	}

	for _, s := range objectSections {
		networkResult, err := text.SplitterProcessOneTime(networkRegexMap, s)
		if err != nil {
			panic(err)
		}
		netMap, err := networkResult.Projection([]string{"obj", "host", "subnet", "range"}, ",", [][]string{
			[]string{"subnet", "prefix"},
			[]string{"range", "end"},
		})

		if err != nil {
			fmt.Println(s)
			panic(err)
		}

		secpathNetworkObject := &secpathNetwork{
			ObjName:      netMap["name"],
			CLI:          s,
			NetworkGroup: network.NewNetworkGroup(),
			ZoneName:     tools.OR(netMap["zone"], model.SECPATH_NIL_ZONE).(string),
		}

		bGroup := false
		if netMap["obj"] != "" {
			bGroup = true
			for _, objName := range strings.Split(netMap["obj"], ",") {
				secpathNetworkObject.RefNames = append(secpathNetworkObject.RefNames, objName)
			}
		}

		addrList := []string{}
		if netMap["host"] != "" {
			secpathNetworkObject.NetworkGroup, err = network.NewNetworkGroupFromString(netMap["host"])
			if err != nil {
				panic(err)
			}
			for _, host := range strings.Split(netMap["host"], ",") {
				addrList = append(addrList, host)
			}
		}

		if netMap["subnet"] != "" {

			net, err := network.NewNetworkGroupFromString(strings.ReplaceAll(netMap["subnet"], "-", "/"))
			if err != nil {
				panic(err)
			}
			if secpathNetworkObject.NetworkGroup == nil {
				secpathNetworkObject.NetworkGroup = net
			} else {
				secpathNetworkObject.NetworkGroup.AddGroup(net)
			}

			for _, host := range strings.Split(netMap["subnet"], ",") {
				addrList = append(addrList, host)
			}
		}

		if netMap["range"] != "" {
			net, err := network.NewNetworkGroupFromString(netMap["range"])
			if err != nil {
				panic(err)
			}
			if secpathNetworkObject.NetworkGroup == nil {
				secpathNetworkObject.NetworkGroup = net
			} else {
				secpathNetworkObject.NetworkGroup.AddGroup(net)
			}

			for _, host := range strings.Split(netMap["range"], ",") {
				addrList = append(addrList, host)
			}
		}

		if !bGroup {
			if len(addrList) > 1 {
				bGroup = true
			}
		}

		if bGroup {
			secpathNetworkObject.Catagory = firewall.GROUP_NETWORK
		} else {
			secpathNetworkObject.Catagory = firewall.OBJECT_NETWORK
		}

		// var ok bool
		// for zone := range sec.zoneNetworkMap {
		// for _, netObj := range sec.zoneNetworkMap[zone] {
		// if netObj.Name() == secpathNetworkObject.name {
		// net1 := netObj.Network(sec.zoneNetworkMap[ZoneName(netObj.(*secpathNetwork).zone)])
		// net2 := secpathNetworkObject.Network(sec.zoneNetworkMap[ZoneName(netObj.(*secpathNetwork).zone)])
		// if net1.Same(net2) {
		// ok = true
		// } else {
		// fmt.Println("netObj: ", netObj)
		// fmt.Println("secpathNetworkObject:", secpathNetworkObject)
		// fmt.Println(s)
		// panic("unknown error")
		// }
		// }
		// }
		// }
		//
		// if !ok {
		// panic("unknown error")
		// }

		if _, ok := sec.ZoneNetworkMap[ZoneName(secpathNetworkObject.ZoneName)]; !ok {
			sec.ZoneNetworkMap[ZoneName(secpathNetworkObject.ZoneName)] = map[string]firewall.FirewallNetworkObject{}
		}

		if existingObj, ok := sec.ZoneNetworkMap[ZoneName(secpathNetworkObject.ZoneName)][secpathNetworkObject.ObjName]; !ok {
			sec.ZoneNetworkMap[ZoneName(secpathNetworkObject.ZoneName)][secpathNetworkObject.ObjName] = secpathNetworkObject
		} else {
			// merge the network group
			if existingSecpathObj, ok := existingObj.(*secpathNetwork); ok {
				// 如果是组类型，合并网络组
				if existingSecpathObj.Catagory == firewall.GROUP_NETWORK {
					// 合并网络组
					if secpathNetworkObject.NetworkGroup != nil && !secpathNetworkObject.NetworkGroup.IsEmpty() {
						if existingSecpathObj.NetworkGroup == nil {
							existingSecpathObj.NetworkGroup = network.NewNetworkGroup()
						}
						existingSecpathObj.NetworkGroup.AddGroup(secpathNetworkObject.NetworkGroup)
					}
					// 合并引用对象名称（去重）
					for _, newRef := range secpathNetworkObject.RefNames {
						found := false
						for _, existingRef := range existingSecpathObj.RefNames {
							if existingRef == newRef {
								found = true
								break
							}
						}
						if !found {
							existingSecpathObj.RefNames = append(existingSecpathObj.RefNames, newRef)
						}
					}
					// 更新CLI（追加新的CLI内容）
					if secpathNetworkObject.CLI != "" {
						if existingSecpathObj.CLI != "" {
							existingSecpathObj.CLI += "\n" + secpathNetworkObject.CLI
						} else {
							existingSecpathObj.CLI = secpathNetworkObject.CLI
						}
					}
				} else {
					// 如果不是组类型，覆盖对象
					sec.ZoneNetworkMap[ZoneName(secpathNetworkObject.ZoneName)][secpathNetworkObject.ObjName] = secpathNetworkObject
				}
			}
		}

	}
}

func (sec *SecPathObjectSet) parseNetwork(ipv4DataList, ipv6DataList, ipv4GroupInfo, ipv6GroupInfo []interface{}) {
	groupMap := map[string][]interface{}{}

	for _, obj := range ipv4DataList {
		var xmlObj model.XmlNetworkObject
		mapstructure.Decode(obj, &xmlObj)
		if xmlObj.Type != model.ADDRESS_NESTED {
			// fmt.Println(xmlObj.Network())
		}

		groupMap[xmlObj.Group] = append(groupMap[xmlObj.Group], &xmlObj)
		for _, info := range ipv4GroupInfo {
			if _, ok := info.(map[string]interface{}); ok {
				if info.(map[string]interface{})["Name"].(string) == xmlObj.Group {
					xmlObj.Zone = info.(map[string]interface{})["SecurityZone"].(string)
				}
			} else {
				if xmlObj.Group == info.(*model.XmlGroupStruct).Name {
					xmlObj.Zone = info.(*model.XmlGroupStruct).SecurityZone
				}
			}
		}
	}

	for _, obj := range ipv6DataList {
		var xmlObj model.XmlNetworkObject
		mapstructure.Decode(obj, &xmlObj)

		if xmlObj.Type != model.ADDRESS_NESTED {
			// fmt.Println(xmlObj.Network())
		}
		groupMap[xmlObj.Group] = append(groupMap[xmlObj.Group], &xmlObj)
		for _, info := range ipv6GroupInfo {
			if _, ok := info.(map[string]interface{}); ok {
				if info.(map[string]interface{})["Name"].(string) == xmlObj.Group {
					xmlObj.Zone = info.(map[string]interface{})["SecurityZone"].(string)
				}
			} else {
				xmlObj.Zone = info.(*model.XmlGroupStruct).SecurityZone
			}
		}
	}

	for name, xmlObjList := range groupMap {
		secpathNetworkObject := &secpathNetwork{
			ObjName:      name,
			NetworkGroup: network.NewNetworkGroup(),
			ZoneName:     tools.OR(xmlObjList[0].(*model.XmlNetworkObject).Zone, model.SECPATH_NIL_ZONE).(string),
		}
		if len(xmlObjList) > 1 {
			secpathNetworkObject.Catagory = firewall.GROUP_NETWORK
			byteS, err := json.Marshal(xmlObjList)
			if err != nil {
				panic(err)
			}
			secpathNetworkObject.CLI = string(byteS)
			for _, obj := range xmlObjList {
				if obj.(*model.XmlNetworkObject).NestedGroup == "" {
					ss, err := obj.(*model.XmlNetworkObject).Network()
					if err != nil {
						panic(err)
					}
					secpathNetworkObject.NetworkGroup.AddGroup(ss)
				} else {
					secpathNetworkObject.RefNames = append(secpathNetworkObject.RefNames, obj.(*model.XmlNetworkObject).NestedGroup)
				}
			}
		} else {
			secpathNetworkObject.Catagory = firewall.OBJECT_NETWORK
			byteS, err := json.Marshal(xmlObjList[0])
			if err != nil {
				panic(err)
			}

			obj := xmlObjList[0]
			if obj.(*model.XmlNetworkObject).NestedGroup == "" {
				ss, err := obj.(*model.XmlNetworkObject).Network()
				if err != nil {
					panic(err)
				}
				secpathNetworkObject.NetworkGroup.AddGroup(ss)
			} else {
				secpathNetworkObject.RefNames = append(secpathNetworkObject.RefNames, obj.(*model.XmlNetworkObject).NestedGroup)
			}

			secpathNetworkObject.CLI = string(byteS)
		}

		// fmt.Println(secpathNetworkObject)
		if _, ok := sec.ZoneNetworkMap[ZoneName(secpathNetworkObject.ZoneName)]; !ok {
			sec.ZoneNetworkMap[ZoneName(secpathNetworkObject.ZoneName)] = map[string]firewall.FirewallNetworkObject{}
		}
		sec.ZoneNetworkMap[ZoneName(secpathNetworkObject.ZoneName)][secpathNetworkObject.ObjName] = secpathNetworkObject

	}

}

func (sec *SecPathObjectSet) parsePortObjectCli(config string) error {
	sections := strings.Split(config, "#")

	objectSections := []string{}
	for _, section := range sections {
		if strings.Index(section, "object-group port") >= 0 {
			objectSections = append(objectSections, strings.TrimSpace(section))
		}
	}

	portRegexMap := map[string]string{
		"regex": `
            (port\s
				(
					(eq\s(?P<eq>\S+)) |
					(gt\s(?P<gt>\S+)) |
					(lt\s(?P<lt>\S+)) |
					(neq\s(?P<neq>\S+)) |
					(range\s(?P<start>\S+)\s(?P<end>\S+)) |
					(group-object\s(?P<obj>\S+))
				)
			)
        `,
		"name":  "service-port",
		"flags": "mx",
		"pcre":  "true",
	}

	for _, s := range objectSections {
		var l4PortResult *service.L4Port
		var refNames []string
		var err error
		var objectName string

		// 提取对象名称
		nameRegex := regexp.MustCompile(`object-group port (\S+)`)
		matches := nameRegex.FindStringSubmatch(s)
		if len(matches) > 1 {
			objectName = matches[1]
		} else {
			return fmt.Errorf("unable to extract object name from: %s", s)
		}

		portResult, err := text.SplitterProcessOneTime(portRegexMap, s)
		if err != nil {
			sec.PortObjectMap[objectName] = &secpathPortObject{
				name: objectName,
			}
			// return fmt.Errorf("parse port object cli error: %v", err)
		}

		for it := portResult.Iterator(); it.HasNext(); {
			_, _, portMap := it.Next()
			var l4port *service.L4Port
			var ref string
			var port int
			var err error

			switch {
			case portMap["eq"] != "":
				port, err = strconv.Atoi(portMap["eq"])
				if err != nil {
					return fmt.Errorf("parse port object cli error: %v", err)
				}
				l4port, err = service.NewL4Port(service.EQ, port, -1, 0)
			case portMap["lt"] != "":
				port, err = strconv.Atoi(portMap["lt"])
				if err != nil {
					return fmt.Errorf("parse port object cli error: %v", err)
				}
				l4port, err = service.NewL4Port(service.LT, port, -1, 0)
			case portMap["gt"] != "":
				port, err = strconv.Atoi(portMap["gt"])
				if err != nil {
					return fmt.Errorf("parse port object cli error: %v", err)
				}
				l4port, err = service.NewL4Port(service.GT, port, -1, 0)
			case portMap["neq"] != "":
				port, err = strconv.Atoi(portMap["neq"])
				if err != nil {
					return fmt.Errorf("parse port object cli error: %v", err)
				}
				l4port, err = service.NewL4Port(service.NEQ, port, -1, 0)
			case portMap["start"] != "":
				port1, err := strconv.Atoi(portMap["start"])
				if err != nil {
					return fmt.Errorf("parse port object cli error: %v", err)
				}
				port2, err := strconv.Atoi(portMap["end"])
				if err != nil {
					return fmt.Errorf("parse port object cli error: %v", err)
				}
				l4port, err = service.NewL4Port(service.RANGE, port1, port2, 0)
				if err != nil {
					return fmt.Errorf("parse port object cli error: %v", err)
				}
			case portMap["obj"] != "":
				ref = portMap["obj"]
				refNames = append(refNames, portMap["obj"])

			default:
				return fmt.Errorf("unknown service in port object cli: %s", s)
			}

			if err != nil {
				return fmt.Errorf("parse port object cli error: %v", err)
			}

			if ref == "" && l4port == nil {
				return fmt.Errorf("no service or port defined in port object cli: %s", s)
			}

			if l4PortResult == nil {
				l4PortResult = l4port
			} else {
				if l4port != nil {
					l4PortResult.Add(l4port)
				}
			}
		}

		// 将解析结果保存到 sec.portObjectMap
		// if l4PortResult != nil {
		// 	if sec.portObjectMap == nil {
		// 		sec.portObjectMap = make(map[string]*service.L4Port)
		// 	}
		// 	sec.portObjectMap[objectName] = l4PortResult
		// }
		sec.PortObjectMap[objectName] = &secpathPortObject{
			name:     objectName,
			l4port:   l4PortResult,
			refNames: refNames,
		}
	}

	return nil
}

func (sec *SecPathObjectSet) parseServiceCli(config string) {
	sections := strings.Split(config, "#")

	objectSections := []string{}
	for _, section := range sections {
		if strings.Index(section, "object-group service") >= 0 {
			objectSections = append(objectSections, strings.TrimSpace(section))
		}
	}

	serviceRegexMap := map[string]string{
		"regex": `
		    (object-group\sservice\s(?P<name>\S+))|
			(service\s((group-object\s(?P<obj>\S+))|(?P<srvCli>[ \w]+)))
		`,
		"name":  "service",
		"flags": "mx",
		"pcre":  "true",
	}

	for _, s := range objectSections {
		serviceResult, err := text.SplitterProcessOneTime(serviceRegexMap, s)
		if err != nil {
			panic(err)
		}

		srvMap, err := serviceResult.Projection([]string{"obj", "srvCli"}, ",", [][]string{})
		if err != nil {
			panic(err)
		}

		secpathServiceObject := &secpathService{
			name:    srvMap["name"],
			service: &service.Service{},
			cli:     s,
		}

		bGroup := false

		if srvMap["obj"] != "" {
			bGroup = true
			for _, objName := range strings.Split(srvMap["obj"], ",") {
				secpathServiceObject.refNames = append(secpathServiceObject.refNames, objName)
			}
		}

		srvList := []string{}
		if srvMap["srvCli"] != "" {
			for _, srvCli := range strings.Split(srvMap["srvCli"], ",") {
				srv := PolicySorucePortParser(srvCli).Service()
				if secpathServiceObject.service == nil {
					secpathServiceObject.service = srv
				} else {
					secpathServiceObject.service.Add(srv)
				}
				srvList = append(srvList, srvCli)
			}
		}

		// var ok bool
		// for _, srvObj := range sec.serviceMap {
		// if srvObj.Name() == secpathServiceObject.name {
		// if srvObj.Service(sec.serviceMap).Same(secpathServiceObject.Service(sec.serviceMap)) {
		// ok = true
		// } else {
		// fmt.Println(s)
		// fmt.Println("srvObj:", srvObj)
		// fmt.Println("secpathServiceObject: ", secpathServiceObject)
		// panic("unknown error")
		// }
		// }
		// }
		//
		// if !ok {
		// panic("unknown error")
		// }

		if !bGroup {
			if len(srvList) > 1 {
				bGroup = true
			}
		}

		if bGroup {
			secpathServiceObject.catagory = firewall.GROUP_SERVICE
		} else {
			secpathServiceObject.catagory = firewall.OBJECT_SERVICE
		}

		if existingObj, ok := sec.ServiceMap[secpathServiceObject.name]; !ok {
			sec.ServiceMap[secpathServiceObject.name] = secpathServiceObject
		} else {
			// merge the service
			if existingSecpathSvc, ok := existingObj.(*secpathService); ok {
				// 如果是组类型，合并服务
				if existingSecpathSvc.catagory == firewall.GROUP_SERVICE {
					// 合并服务
					if secpathServiceObject.service != nil && !secpathServiceObject.service.IsEmpty() {
						if existingSecpathSvc.service == nil {
							existingSecpathSvc.service = &service.Service{}
						}
						existingSecpathSvc.service.Add(secpathServiceObject.service)
					}
					// 合并引用对象名称（去重）
					for _, newRef := range secpathServiceObject.refNames {
						found := false
						for _, existingRef := range existingSecpathSvc.refNames {
							if existingRef == newRef {
								found = true
								break
							}
						}
						if !found {
							existingSecpathSvc.refNames = append(existingSecpathSvc.refNames, newRef)
						}
					}
					// 更新CLI（追加新的CLI内容）
					if secpathServiceObject.cli != "" {
						if existingSecpathSvc.cli != "" {
							existingSecpathSvc.cli += "\n" + secpathServiceObject.cli
						} else {
							existingSecpathSvc.cli = secpathServiceObject.cli
						}
					}
				} else {
					// 如果不是组类型，覆盖对象
					sec.ServiceMap[secpathServiceObject.name] = secpathServiceObject
				}
			}
		}
	}
}

func (sec *SecPathObjectSet) parseService(objList []interface{}) {
	groupMap := map[string][]interface{}{}
	for _, obj := range objList {
		var xmlObj model.XmlServiceObject
		mapstructure.Decode(obj, &xmlObj)
		// if *xmlObj.EndSrcPort < *xmlObj.StartSrcPort {
		// *xmlObj.EndSrcPort = *xmlObj.StartSrcPort
		// }
		//
		// fmt.Println(*xmlObj.EndSrcPort, *xmlObj.StartSrcPort, *xmlObj.StartDestPort, *xmlObj.EndDestPort)
		// if *xmlObj.EndDestPort < *xmlObj.StartDestPort {
		// *xmlObj.EndDestPort = *xmlObj.StartDestPort
		// }

		groupMap[xmlObj.Group] = append(groupMap[xmlObj.Group], &xmlObj)
	}

	for name, xmlObjList := range groupMap {
		secpathServiceObject := &secpathService{
			name:    name,
			service: &service.Service{},
		}
		if len(xmlObjList) > 1 {
			secpathServiceObject.catagory = firewall.GROUP_SERVICE
			byteS, err := json.Marshal(xmlObjList)
			if err != nil {
				panic(err)
			}
			secpathServiceObject.cli = string(byteS)
			for _, obj := range xmlObjList {
				if obj.(*model.XmlServiceObject).NestedGroup == "" {
					ss, err := obj.(*model.XmlServiceObject).Service()
					if err != nil {
						panic(err)
					}
					secpathServiceObject.service.Add(ss)
				} else {
					secpathServiceObject.refNames = append(secpathServiceObject.refNames, obj.(*model.XmlServiceObject).NestedGroup)
				}
			}
		} else {
			secpathServiceObject.catagory = firewall.OBJECT_SERVICE
			byteS, err := json.Marshal(xmlObjList[0])
			if err != nil {
				panic(err)
			}

			obj := xmlObjList[0]
			if obj.(*model.XmlServiceObject).NestedGroup == "" {
				ss, err := obj.(*model.XmlServiceObject).Service()
				if err != nil {
					panic(err)
				}
				secpathServiceObject.service.Add(ss)
			} else {
				secpathServiceObject.refNames = append(secpathServiceObject.refNames, obj.(*model.XmlServiceObject).NestedGroup)
			}

			secpathServiceObject.cli = string(byteS)
		}

		sec.ServiceMap[secpathServiceObject.name] = secpathServiceObject
	}
}

var _ firewall.FirewallNetworkObject = &secpathNetwork{}
var _ firewall.FirewallServiceObject = &secpathService{}

type secpathNetwork struct {
	Catagory     firewall.FirewallObjectType
	CLI          string
	ObjName      string
	HasNat       bool
	ZoneName     string
	NetworkGroup *network.NetworkGroup
	RefNames     []string
}

// 实现 TypeInterface 接口
func (sn *secpathNetwork) TypeName() string {
	return "SecpathNetwork"
}

// secpathNetworkJSON 用于序列化和反序列化
type secpathNetworkJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	HasNat   bool                        `json:"has_nat"`
	Zone     string                      `json:"zone"`
	Network  json.RawMessage             `json:"network"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (sn *secpathNetwork) MarshalJSON() ([]byte, error) {
	networkRaw, err := json.Marshal(sn.NetworkGroup)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	return json.Marshal(secpathNetworkJSON{
		Catagory: sn.Catagory,
		Cli:      sn.CLI,
		Name:     sn.ObjName,
		HasNat:   sn.HasNat,
		Zone:     sn.ZoneName,
		Network:  networkRaw,
		RefNames: sn.RefNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (sn *secpathNetwork) UnmarshalJSON(data []byte) error {
	var snj secpathNetworkJSON
	if err := json.Unmarshal(data, &snj); err != nil {
		return err
	}

	sn.Catagory = snj.Catagory
	sn.CLI = snj.Cli
	sn.ObjName = snj.Name
	sn.HasNat = snj.HasNat
	sn.ZoneName = snj.Zone
	sn.RefNames = snj.RefNames

	sn.NetworkGroup = &network.NetworkGroup{}
	if err := json.Unmarshal(snj.Network, sn.NetworkGroup); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}

	// 注意：refs 字段没有被序列化，因为它包含了对其他对象的引用
	// 如果需要，你可能需要在反序列化后重新构建这些引用

	return nil
}

func (netObj *secpathNetwork) Name() string {
	return netObj.ObjName
}

func (netObj *secpathNetwork) Cli() string {
	return netObj.CLI
}

func (netObj *secpathNetwork) WithZone(zone string) {
	netObj.ZoneName = zone
}

func (netObj *secpathNetwork) Zone() string {
	return netObj.ZoneName
}

func (netObj *secpathNetwork) Type() firewall.FirewallObjectType {
	return netObj.Catagory
}

func (netObj *secpathNetwork) Network(node firewall.FirewallNode) *network.NetworkGroup {
	secpath := node.(*SecPathNode)
	zoneNetworkMap := secpath.ObjectSet.ZoneNetworkMap
	ng := &network.NetworkGroup{}
	if netObj.NetworkGroup != nil {
		ng = netObj.NetworkGroup.Copy().(*network.NetworkGroup)
	}

	if len(netObj.RefNames) > 0 {
		zone := netObj.ZoneName
		networkMap := zoneNetworkMap[ZoneName(zone)]
		for _, ref := range netObj.RefNames {
			if refObj, ok := networkMap[ref]; !ok {
				panic(fmt.Sprintf("can not find ref object: %s", ref))
			} else {
				ng.AddGroup(refObj.Network(node))
			}
		}
	}

	return ng
}

//func (secpath *SecPathObjectSet) NetworkObjectToDb(db *gorm.DB, task_id uint) {
//	global.GVA_LOG.Info("开始保存NetworkObject到数据库", zap.Any("TaskId", task_id))
//	networkObjectMap := map[ZoneName]map[string]*M.NetworkObject{}
//	for zone := range secpath.zoneNetworkMap {
//		/* zones = append(zones, zone) */
//		networkObjectMap[zone] = map[string]*M.NetworkObject{}
//
//		for name, obj := range secpath.zoneNetworkMap[zone] {
//			ol := []string{
//				"[" + obj.(*secpathNetwork).network.String() + "]",
//			}
//
//			for _, objName := range obj.(*secpathNetwork).refNames {
//				ol = append(ol, "["+objName+"]")
//			}
//
//			no := &M.NetworkObject{
//				Cli:           obj.Cli(),
//				Name:          obj.Name(),
//				ExtractTaskID: task_id,
//				Zone:          string(zone),
//				Simple:        obj.(*secpathNetwork).network,
//				// Object1:       obj.(*secpathNetwork).network.String() + ";" + strings.Join(obj.(*secpathNetwork).refNames, ","),
//				Object1: strings.Join(ol, ","),
//				Network: obj.Network(secpath.zoneNetworkMap[zone]),
//			}
//			networkObjectMap[zone][name] = no
//		}
//	}
//
//	for zone := range secpath.zoneNetworkMap {
//		for name, obj := range secpath.zoneNetworkMap[zone] {
//			networkObj := networkObjectMap[zone][name]
//			for _, ref := range obj.(*secpathNetwork).refNames {
//				if _, ok := networkObjectMap[zone][ref]; !ok {
//					panic("unknown error")
//				}
//				networkObj.Childs = append(networkObj.Childs, networkObjectMap[zone][ref])
//			}
//		}
//	}
//	objList := []*M.NetworkObject{}
//
//	for zone := range networkObjectMap {
//		for _, obj := range networkObjectMap[zone] {
//			objList = append(objList, obj)
//		}
//	}
//
//	if len(objList) > 0 {
//		result := db.Save(objList)
//		global.GVA_LOG.Info("NetworkObject对象数量大于1,保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(objList)), zap.Any("RowsAffected", result.RowsAffected))
//		if result.Error != nil {
//			panic(result.Error)
//		}
//	} else {
//		global.GVA_LOG.Info("NetworkObject对象数量为0,保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(objList)))
//	}
//}

//func (secpath *SecPathObjectSet) ServiceObjectToDb(db *gorm.DB, task_id uint) {
//	keys := []string{}
//	for key := range secpath.serviceMap {
//		keys = append(keys, key)
//	}
//	sort.Strings(keys)
//
//	keyMap := map[string]*M.ServiceObject{}
//
//	serviceObjectMap := map[string]*M.ServiceObject{}
//	for _, key := range keys {
//		obj := secpath.serviceMap[key]
//
//		if _, ok := keyMap[obj.Name()]; !ok {
//			ol := []string{
//				"[" + obj.(*secpathService).service.String() + "]",
//			}
//
//			for _, objName := range obj.(*secpathService).refNames {
//				ol = append(ol, "["+objName+"]")
//			}
//
//			so := &M.ServiceObject{
//				Cli:           obj.Cli(),
//				Name:          obj.Name(),
//				ExtractTaskID: task_id,
//				Simple:        obj.(*secpathService).service,
//				Object1:       strings.Join(ol, ","),
//				Service:       obj.Service(secpath.serviceMap),
//				// Object1:       obj.(*secpathService).service.String() + ";" + strings.Join(obj.(*secpathService).refNames, ","),
//			}
//			serviceObjectMap[obj.Name()] = so
//		}
//	}
//
//	for _, key := range keys {
//		obj := secpath.serviceMap[key]
//		for _, ref := range obj.(*secpathService).refNames {
//			so := serviceObjectMap[obj.Name()]
//			refObj := serviceObjectMap[ref]
//			so.Childs = append(so.Childs, refObj)
//		}
//	}
//
//	objList := []*M.ServiceObject{}
//
//	for _, key := range keys {
//		objList = append(objList, serviceObjectMap[key])
//	}
//
//	if len(objList) > 0 {
//		result := db.Save(objList)
//		global.GVA_LOG.Info("ServiceObject对象数量大于1,保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(objList)), zap.Any("RowsAffected", result.RowsAffected))
//		if result.Error != nil {
//			panic(result.Error)
//		}
//	} else {
//		global.GVA_LOG.Info("ServiceObject对象数量为0,保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(objList)))
//	}
//}

func (secpath *SecPathObjectSet) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	var zone string
	if port == nil {
		zone = model.SECPATH_NIL_ZONE
	} else {
		zone = port.(*SecPathPort).Zone()
	}
	if zone == "" {
		panic(fmt.Sprint("unknown error:", port))
	}

	objectMap, exists := secpath.ZoneNetworkMap[ZoneName(zone)]
	if !exists || objectMap == nil {
		return nil, false
	}

	for _, obj := range objectMap {
		objNet := obj.Network(secpath.node)
		if objNet.Same(ng) {
			switch searchType {
			case firewall.SEARCH_OBJECT:
				if obj.Type() == firewall.OBJECT_NETWORK {
					return obj, true
				}
			case firewall.SEARCH_GROUP:
				if obj.Type() == firewall.GROUP_NETWORK {
					return obj, true
				}
			case firewall.SEARCH_OBJECT_OR_GROUP:
				if obj.Type() == firewall.OBJECT_NETWORK || obj.Type() == firewall.GROUP_NETWORK {
					return obj, true
				}
			}

		}
	}

	return nil, false

}

func (secpath *SecPathObjectSet) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	for _, obj := range secpath.ServiceMap {
		srv := obj.Service(secpath.node)
		if srv.Same(s) {
			switch searchType {
			case firewall.SEARCH_OBJECT:
				if obj.Type() == firewall.OBJECT_SERVICE {
					return obj, true
				}
			case firewall.SEARCH_GROUP:
				if obj.Type() == firewall.GROUP_SERVICE {
					return obj, true
				}
			case firewall.SEARCH_OBJECT_OR_GROUP:
				if obj.Type() == firewall.OBJECT_SERVICE || obj.Type() == firewall.GROUP_SERVICE {
					return obj, true
				}
			}
		}
	}

	return nil, false

}

// func (sec *SecPathObjectSet) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
// }
func (sec *SecPathObjectSet) Network(zone, name string) (*network.NetworkGroup, string, bool) {
	// if name == "any" {
	// ng := network.NewAny46Group()
	// return ng, true
	// } else if name == "any-ipv4" {
	// ng := network.NewAny4Group()
	// return ng, true
	// } else if name == "any-ipv6" {
	// ng := network.NewAny6Group()
	// return ng, true
	// }

	// fmt.Println("zone:", zone, sec)
	// fmt.Println(sec.zoneNetworkMap)
	// var m map[string]firewall.FirewallNetworkObject
	// if _, ok := sec.zoneNetworkMap[zone]; ok {
	// m = sec.zoneNetworkMap[zone]
	// } else {
	// m = sec.zoneNetworkMap[SECPATH_NIL_ZONE]
	// }

	for _, networkMap := range sec.ZoneNetworkMap {
		for _, obj := range networkMap {
			if obj.Name() == name {
				return obj.Network(sec.node), obj.Cli(), true
			}
		}
	}

	return nil, "", false
}

func (sec *SecPathObjectSet) Service(name string) (*service.Service, string, bool) {
	if obj, ok := sec.ServiceMap[name]; !ok {
		s, err := SECPATHNameToService(name)
		if err == nil {
			return s, "", true
		}
		return nil, "", false
	} else {
		ng := obj.Service(sec.node)
		return ng, obj.Cli(), true
	}
}

func (sec *SecPathObjectSet) hasObjectName(name string) bool {
	for _, objMap := range sec.ZoneNetworkMap {
		for _, obj := range objMap {
			if obj.Name() == name {
				return true
			}
		}
	}

	for _, obj := range sec.ServiceMap {
		if obj.Name() == name {
			return true
		}
	}

	return false

}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallServiceObject)(nil)).Elem(), "SecpathService", reflect.TypeOf(secpathService{}))
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNetworkObject)(nil)).Elem(), "SecpathNetwork", reflect.TypeOf(secpathNetwork{}))
}
