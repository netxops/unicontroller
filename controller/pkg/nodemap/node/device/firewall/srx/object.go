package srx

import (
	"encoding/json"
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
)

// type PoolDirection int
//
// const (
// _ PoolDirection = iota
// SOURCE
// DESTINATION
// )
//
// func (p PoolDirection) String() string {
// return []string{"SOURCE", "DESTINATION"}[p-1]
// }

type AddressBook struct {
	networkMap map[string]firewall.FirewallNetworkObject
}

func (ab *AddressBook) Count() int {
	return len(ab.networkMap)
}

type SRXObjectSet struct {
	node *SRXNode
	//地址的第一级索引为zone，或为"global"
	zoneAddressBook map[string]map[string]firewall.FirewallNetworkObject
	// zoneAddressBook map[string]*AddressBook
	serviceMap map[string]firewall.FirewallServiceObject
	poolMap    map[firewall.NatType]map[string]firewall.FirewallNetworkObject
}

func NewSRXObjectSet(node *SRXNode) *SRXObjectSet {
	return &SRXObjectSet{
		node:            node,
		zoneAddressBook: map[string]map[string]firewall.FirewallNetworkObject{},
		serviceMap:      map[string]firewall.FirewallServiceObject{},
		poolMap:         map[firewall.NatType]map[string]firewall.FirewallNetworkObject{},
	}
}

type srxService struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	service  *service.Service
	refNames []string
}

// 实现 TypeInterface 接口
func (rs *srxService) TypeName() string {
	return "SRXService"
}

// srxServiceJSON 用于序列化和反序列化
type srxServiceJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	Service  json.RawMessage             `json:"service"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (rs *srxService) MarshalJSON() ([]byte, error) {
	serviceRaw, err := json.Marshal(rs.service)
	if err != nil {
		return nil, fmt.Errorf("error marshaling service: %w", err)
	}

	return json.Marshal(srxServiceJSON{
		Catagory: rs.catagory,
		Cli:      rs.cli,
		Name:     rs.name,
		Service:  serviceRaw,
		RefNames: rs.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (rs *srxService) UnmarshalJSON(data []byte) error {
	var rsj srxServiceJSON
	if err := json.Unmarshal(data, &rsj); err != nil {
		return err
	}

	rs.catagory = rsj.Catagory
	rs.cli = rsj.Cli
	rs.name = rsj.Name
	rs.refNames = rsj.RefNames

	rs.service = &service.Service{}
	if err := json.Unmarshal(rsj.Service, rs.service); err != nil {
		return fmt.Errorf("error unmarshaling service: %w", err)
	}

	return nil
}

func (rs *srxService) Name() string {
	return rs.name
}

func (rs *srxService) Cli() string {
	return rs.cli
}

func (rs *srxService) Type() firewall.FirewallObjectType {
	return rs.catagory
}

// func (rs *srxService) Service(serviceMap map[string]firewall.FirewallServiceObject) *service.Service {
func (rs *srxService) Service(node firewall.FirewallNode) *service.Service {
	var s *service.Service
	if rs.service != nil {
		s = rs.service.Copy().(*service.Service)
	}
	srx := node.(*SRXNode)
	serviceMap := srx.objectSet.serviceMap
	// s := rs.service.Copy().(*service.Service)

	for _, ref := range rs.refNames {
		if refObj, ok := serviceMap[ref]; !ok {
			panic(fmt.Sprintf("can not find ref object: %s", ref))
		} else {
			if s == nil {
				s = refObj.Service(node).Copy().(*service.Service)
			} else {
				s.Add(refObj.Service(node))
			}
		}
	}

	return s
}

type srxNetwork struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	hasNat   bool
	network  *network.NetworkGroup
	refs     []firewall.FirewallNetworkObject
	refNames []string
}

// 实现 TypeInterface 接口
func (sn *srxNetwork) TypeName() string {
	return "SRXNetwork"
}

// srxNetworkJSON 用于序列化和反序列化
type srxNetworkJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	HasNat   bool                        `json:"has_nat"`
	Network  json.RawMessage             `json:"network"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (sn *srxNetwork) MarshalJSON() ([]byte, error) {
	networkRaw, err := json.Marshal(sn.network)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	return json.Marshal(srxNetworkJSON{
		Catagory: sn.catagory,
		Cli:      sn.cli,
		Name:     sn.name,
		HasNat:   sn.hasNat,
		Network:  networkRaw,
		RefNames: sn.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (sn *srxNetwork) UnmarshalJSON(data []byte) error {
	var snj srxNetworkJSON
	if err := json.Unmarshal(data, &snj); err != nil {
		return err
	}

	sn.catagory = snj.Catagory
	sn.cli = snj.Cli
	sn.name = snj.Name
	sn.hasNat = snj.HasNat
	sn.refNames = snj.RefNames

	sn.network = &network.NetworkGroup{}
	if err := json.Unmarshal(snj.Network, sn.network); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}

	// 注意：refs 字段不会被序列化和反序列化，因为它包含接口类型
	// 如果需要，你可能需要在反序列化后手动重建这个字段

	return nil
}

func (sn *srxNetwork) Name() string {
	return sn.name
}

func (sn *srxNetwork) Cli() string {
	return sn.cli
}

func (sn *srxNetwork) Type() firewall.FirewallObjectType {
	return sn.catagory
}

func (sn *srxNetwork) Network(node firewall.FirewallNode) *network.NetworkGroup {
	var ng *network.NetworkGroup
	if sn.network != nil {
		ng = sn.network.Copy().(*network.NetworkGroup)
	}
	srx := node.(*SRXNode)
	zonesNetworkMap := srx.objectSet.zoneAddressBook
	for _, networkMap := range zonesNetworkMap {
		for _, ref := range sn.refNames {
			if refObj, ok := networkMap[ref]; !ok {
				panic(fmt.Sprintf("can not find ref object: %s", ref))
			} else {
				if ng == nil {
					ng = refObj.Network(node).Copy().(*network.NetworkGroup)
				} else {
					ng.AddGroup(refObj.Network(node))
				}
			}
		}
	}

	return ng
}

func (srx *SRXObjectSet) push(zone, name string, obj *srxNetwork) {
	if zone == "" {
		// 如何没有给出zone，将object保存到global地址中
		zone = "global"
	}
	// 如果给出zone，则将object保持到zone相关的地址中，注意
	if _, ok := srx.zoneAddressBook[zone]; !ok {
		srx.zoneAddressBook[zone] = map[string]firewall.FirewallNetworkObject{}
	}
	srx.zoneAddressBook[zone][name] = obj
}

func (srx *SRXObjectSet) parseConfig(config string) {
	// srx.parseZoneAddress(config)
	srx.parseAddress(config)
	srx.parseAddressSet(config)
	srx.parseApplication(config)
	srx.parseApplicationSet(config)
	srx.parsePools(config)

}

type NatPool struct {
	// direction  PoolDirection
	natType    firewall.NatType
	cli        string
	name       string
	objectType firewall.FirewallObjectType
	// natType    firewall.NatType
	network *network.NetworkGroup
	port    *service.L4Port
}

// 实现 TypeInterface 接口
func (np *NatPool) TypeName() string {
	return "NatPool"
}

// natPoolJSON 用于序列化和反序列化
type natPoolJSON struct {
	NatType    firewall.NatType            `json:"nat_type"`
	Cli        string                      `json:"cli"`
	Name       string                      `json:"name"`
	ObjectType firewall.FirewallObjectType `json:"object_type"`
	Network    json.RawMessage             `json:"network"`
	Port       json.RawMessage             `json:"port"`
}

// MarshalJSON 实现 JSON 序列化
func (np *NatPool) MarshalJSON() ([]byte, error) {
	networkRaw, err := json.Marshal(np.network)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	portRaw, err := json.Marshal(np.port)
	if err != nil {
		return nil, fmt.Errorf("error marshaling port: %w", err)
	}

	return json.Marshal(natPoolJSON{
		NatType:    np.natType,
		Cli:        np.cli,
		Name:       np.name,
		ObjectType: np.objectType,
		Network:    networkRaw,
		Port:       portRaw,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (np *NatPool) UnmarshalJSON(data []byte) error {
	var npj natPoolJSON
	if err := json.Unmarshal(data, &npj); err != nil {
		return err
	}

	np.natType = npj.NatType
	np.cli = npj.Cli
	np.name = npj.Name
	np.objectType = npj.ObjectType

	np.network = &network.NetworkGroup{}
	if err := json.Unmarshal(npj.Network, np.network); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}

	np.port = &service.L4Port{}
	if err := json.Unmarshal(npj.Port, np.port); err != nil {
		return fmt.Errorf("error unmarshaling port: %w", err)
	}

	return nil
}

// Cli() string
// Name() string
// Network(map[string]FirewallNetworkObject) *network.NetworkGroup
// Type() FirewallObjectType
func (pool *NatPool) Cli() string {
	return pool.cli
}

func (pool *NatPool) Name() string {
	return pool.name
}

func (pool *NatPool) ID() string {
	return pool.name
}

func (pool *NatPool) Type() firewall.FirewallObjectType {
	return pool.objectType
}

func (pool *NatPool) NatType() firewall.NatType {
	return pool.natType
}

func (pool *NatPool) Network(_ firewall.FirewallNode) *network.NetworkGroup {
	return pool.network
}

func (pool *NatPool) MatchNetworkGroup(ng *network.NetworkGroup) bool {
	if pool.network == nil || ng == nil {
		return false
	}
	return pool.network.Same(ng)
}

func (pool *NatPool) L4Port() *service.L4Port {
	return pool.port
}

func (pool *NatPool) parsePool(config string) {
	poolRegexMap := map[string]string{
		"regex": `
			set\ssecurity\snat\s(?P<direct>\S+)\spool\s(?P<name>\S+)\s
			(
				(
					address\s(?P<address>\d+\.\d+\.\d+\.\d+)(/(?P<addr_prefix>\d+))?\s*
					(to\s(?P<address2>\d+\.\d+\.\d+\.\d+)(/(?P<addr2_prefix>\d+))?)?
				) |
				((address\s)?port\s(range\s)?to\s(?P<port_to>\d+)) |
				((address\s)?port\s(range\s)?(?P<port_from>\d+))
			)
		`,
		"name":  "pool",
		"flags": "mx",
		"pcre":  "true",
	}

	// for _, section := range sections {
	poolResult, err := text.SplitterProcessOneTime(poolRegexMap, config)
	if err != nil {
		panic(err)
	}

	poolMap, err := poolResult.Projection([]string{}, ",", [][]string{})
	if err != nil {
		panic(err)
	}

	if poolMap["direct"] == "source" {
		pool.natType = firewall.DYNAMIC_NAT
	} else if poolMap["direct"] == "destination" {
		pool.natType = firewall.DESTINATION_NAT
	} else {
		panic(fmt.Sprint("unkonw error: ", poolMap))
	}

	pool.name = poolMap["name"]
	pool.cli = config
	pool.objectType = firewall.OBJECT_POOL

	// poolMap["address"] + "/" + poolMap["addr_prefix"]
	var ng *network.NetworkGroup
	if poolMap["address2"] != "" {
		ng, err = network.NewNetworkGroupFromString(poolMap["address"] + "-" + poolMap["address2"])
	} else {
		addressStr := poolMap["address"]
		if addrPrefix := poolMap["addr_prefix"]; addrPrefix != "" {
			addressStr = addressStr + "/" + addrPrefix
		}
		ng, err = network.NewNetworkGroupFromString(addressStr)
	}
	if err != nil {
		panic(err)
	}

	pool.network = ng

	var l4port *service.L4Port
	if poolMap["port_to"] != "" {
		l4port, err = service.NewL4PortFromString(poolMap["port_from"]+"-"+poolMap["port_to"], 0)
	} else if poolMap["port_from"] != "" {
		l4port, err = service.NewL4PortFromString(poolMap["port_from"], 0)
	}

	pool.port = l4port
}

func (srx *SRXObjectSet) parsePools(config string) {
	poolSectionRegexMap := map[string]string{
		"regex": `set security nat (?P<direct>\S+) pool (?P<name>\S+) [^\n]*`,
		"name":  "pool",
		"flags": "m",
		"pcre":  "true",
	}

	poolResult, err := text.SplitterProcessOneTime(poolSectionRegexMap, config)
	if err != nil {
		// 如果解析出错（例如没有匹配），直接返回
		return
	}

	// 如果没有匹配，直接返回
	if poolResult == nil || poolResult.Len() == 0 {
		return
	}

	sections, err := poolResult.CombinKey([]string{"name"})
	if err != nil {
		// 如果组合键出错，直接返回
		return
	}

	for _, section := range sections {
		pool := &NatPool{}
		pool.parsePool(section)
		if _, ok := srx.poolMap[pool.NatType()]; !ok {
			srx.poolMap[pool.NatType()] = map[string]firewall.FirewallNetworkObject{}
		}
		srx.poolMap[pool.NatType()][pool.Name()] = pool

	}
}

func (srx *SRXObjectSet) parseApplicationSet(config string) {
	regex := `(?P<all>set (groups junos-defaults )?applications application-set [^\n]*)`
	sections := parseSection(config, regex, "all")

	// 如果没有匹配的服务组配置，直接返回
	if sections == "" {
		return
	}

	serviceRegexMap := map[string]string{
		"regex": `
			(?P<cli>
				set\s
				(groups\sjunos-defaults\s)?
				applications\sapplication-set\s(?P<name>\S+)\s
				(
					(application-set\s(?P<applicationSet>\S+)) |
					(application\s(?P<application>\S+))
				)
			)
		`,
		"name":  "service",
		"flags": "mx",
		"pcre":  "true",
	}

	serviceResult, err := text.SplitterProcessOneTime(serviceRegexMap, sections)
	if err != nil {
		// 如果解析出错（例如没有匹配），直接返回
		return
	}

	// 如果没有匹配，直接返回
	if serviceResult == nil || serviceResult.Len() == 0 {
		return
	}

	// sm := map[string]map[string]map[string]string{}
	for it := serviceResult.Iterator(); it.HasNext(); {
		_, _, serviceMap := it.Next()
		if _, ok := srx.serviceMap[serviceMap["name"]]; !ok {
			srx.serviceMap[serviceMap["name"]] = &srxService{
				catagory: firewall.GROUP_SERVICE,
				name:     serviceMap["name"],
			}
		}
		obj := srx.serviceMap[serviceMap["name"]].(*srxService)
		if serviceMap["applicationSet"] != "" {
			obj.refNames = append(obj.refNames, serviceMap["applicationSet"])
		} else {
			obj.refNames = append(obj.refNames, serviceMap["application"])
		}

		if obj.cli == "" {
			obj.cli = serviceMap["cli"]
		} else {
			obj.cli += serviceMap["cli"]
		}
	}

	// for _, s := range srx.serviceMap {
	// fmt.Println(s)
	// }
}

func (srx *SRXObjectSet) parseApplication(config string) {
	regex := `(?P<all>set (groups junos-defaults )?applications application [^\n]*)`
	sections := parseSection(config, regex, "all")

	// 如果没有匹配的服务对象配置，直接返回
	if sections == "" {
		return
	}

	serviceRegexMap := map[string]string{
		"regex": `
			(?P<cli>
				set\s
				(groups\sjunos-defaults\s)?
				applications\sapplication\s(?P<name>\S+)\s
				(term\s(?P<term>\S+)\s)?
				(
					(destination-port\s((?P<dport>\d+)(-(?P<dend>\d+))?)) |
					(protocol\s(?P<protocol>\S+)) |
					(source-port\s  ((?P<sport>\d+)-(?P<send>\d+))) |
					(icmp6-type\s(?P<icmp6_type>\d+)) |
					(icmp6-code\s(?P<icmp6_code>\d+)) |
					(icmp-type\s(?P<icmp_type>\d+))
				)
			)
		`,
		"name":  "service",
		"flags": "mx",
		"pcre":  "true",
	}

	serviceResult, err := text.SplitterProcessOneTime(serviceRegexMap, sections)
	if err != nil {
		// 如果解析出错（例如没有匹配），直接返回
		return
	}

	// 如果没有匹配，直接返回
	if serviceResult == nil || serviceResult.Len() == 0 {
		return
	}

	sm := map[string]map[string]map[string]string{}
	for it := serviceResult.Iterator(); it.HasNext(); {
		_, _, serviceMap := it.Next()
		term := "t0"
		if serviceMap["term"] != "" {
			term = serviceMap["term"]
		}

		if _, ok := sm[serviceMap["name"]][term]; !ok {
			sm[serviceMap["name"]] = map[string]map[string]string{}
			sm[serviceMap["name"]][term] = map[string]string{}
		}

		m := sm[serviceMap["name"]][term]
		if serviceMap["protocol"] != "" {
			m["protocol"] = serviceMap["protocol"]
		}

		if serviceMap["icmp_type"] != "" {
			m["icmp_type"] = serviceMap["icmp_type"]
		}

		if serviceMap["icmp_code"] != "" {
			m["icmp_code"] = serviceMap["icmp_code"]
		}

		if serviceMap["icmp6_type"] != "" {
			m["icmp6_type"] = serviceMap["icmp6_type"]
		}

		if serviceMap["icmp6_code"] != "" {
			m["icmp6_code"] = serviceMap["icmp6_code"]
		}

		if serviceMap["dport"] != "" {
			m["dport"] = serviceMap["dport"]
			m["dport2"] = serviceMap["dend"]
		}

		if serviceMap["sport"] != "" {
			m["sport"] = serviceMap["sport"]
			m["sport2"] = serviceMap["send"]
		}
	}

	for serviceName, s := range sm {
		obj := &srxService{
			catagory: firewall.OBJECT_SERVICE,
			name:     serviceName,
		}

		var newService *service.Service
		for _, m := range s {
			var srv *service.Service
			pp, err := SRXParseProtocol(m["protocol"])
			if err != nil {
				panic(err)
			}
			protocol := service.NewL3ProtocolFromString(fmt.Sprintf("%d", pp))
			// if m[]

			// fmt.Println(serviceName, term, protocol)
			switch protocol.Protocol() {
			case service.ICMP:
				if m["icmp_type"] != "" {
					p, err := SRXIcmpParse(m["icmp_type"])
					if err != nil {
						panic(err)
					}
					srv, err = service.NewServiceWithIcmp("icmp", p, service.ICMP_DEFAULT_CODE)
				} else {
					srv, err = service.NewServiceWithIcmp("icmp", service.ICMP_DEFAULT_TYPE, service.ICMP_DEFAULT_CODE)
				}
			case service.ICMP6:
				if m["icmp6_type"] != "" {
					p, err := SRXIcmp6Parse(m["icmp6_type"])
					if err != nil {
						panic(err)
					}
					srv, err = service.NewServiceWithIcmp("icmp6", p, service.ICMP_DEFAULT_CODE)
				} else {
					srv, err = service.NewServiceWithIcmp("icmp6", service.ICMP_DEFAULT_TYPE, service.ICMP_DEFAULT_CODE)
				}

			case service.TCP, service.UDP:
				var p int
				p, err = SRXParseProtocol(m["protocol"])
				if err != nil {
					panic(err)
				}

				var sport string
				if m["sport"] != "" {
					if m["sport2"] != "" {
						sport2, err := SRXTcpPortParse(m["sport2"])
						if err != nil {
							panic(err)
						}
						sport1, err := SRXTcpPortParse(m["sport"])
						if err != nil {
							panic(err)
						}
						sport = fmt.Sprintf("%d-%d", sport1, sport2)
					} else {
						sport1, err := SRXTcpPortParse(m["sport"])
						if err != nil {
							panic(err)
						}
						sport = fmt.Sprintf("%d", sport1)
					}
				} else {
					sport = "0-65535"
				}

				var dport string
				if m["dport"] != "" {
					if m["dport2"] != "" {
						dport2, err := SRXTcpPortParse(m["dport2"])
						if err != nil {
							panic(err)
						}
						dport1, err := SRXTcpPortParse(m["dport"])
						if err != nil {
							panic(err)
						}
						dport = fmt.Sprintf("%d-%d", dport1, dport2)
					} else {
						dport1, err := SRXTcpPortParse(m["dport"])
						if err != nil {
							panic(err)
						}
						dport = fmt.Sprintf("%d", dport1)
					}
				} else {
					dport = "0-65535"
				}

				srv, err = service.NewServiceWithL4(fmt.Sprintf("%d", p), sport, dport)
				if err != nil {
					panic(err)
				}
			case service.IP:
				srv, _ = service.NewServiceWithProto("ip")
			default:
				p, err := SRXParseProtocol(m["protocol"])
				if err != nil {
					panic(err)
				}
				srv, err = service.NewServiceWithProto(fmt.Sprintf("%d", p))
				if err != nil {
					panic(err)
				}
			}
			if newService == nil {
				newService = srv
			} else {
				newService.Add(srv)
			}
		}
		obj.service = newService

		srx.serviceMap[serviceName] = obj
	}

	for it := serviceResult.Iterator(); it.HasNext(); {
		_, _, serviceMap := it.Next()
		if srx.serviceMap[serviceMap["name"]].(*srxService).cli == "" {
			srx.serviceMap[serviceMap["name"]].(*srxService).cli = serviceMap["cli"]
		} else {
			srx.serviceMap[serviceMap["name"]].(*srxService).cli += serviceMap["cli"]
		}
	}

	// for _, s := range srx.serviceMap {
	// fmt.Println(s)
	// }
}

func (srx *SRXObjectSet) parseAttachZone(config string) map[string]string {
	azRegexMap := map[string]string{
		"regex": `(?P<all>set security address-book (?P<book_name>\S+) attach zone (?P<zone>\S+))`,
		"flags": "m",
		"name":  "az",
		"pcre":  "true",
	}

	azResult, err := text.SplitterProcessOneTime(azRegexMap, config)
	if err != nil {
		// 如果解析出错或没有匹配，返回空map
		return map[string]string{}
	}

	// 如果没有匹配，返回空map
	if azResult == nil || azResult.Len() == 0 {
		return map[string]string{}
	}

	azZoneMap := map[string]string{}
	for it := azResult.Iterator(); it.HasNext(); {
		_, _, azMap := it.Next()
		if azMap != nil {
			if bookName, ok := azMap["book_name"]; ok {
				if zone, ok := azMap["zone"]; ok {
					azZoneMap[bookName] = zone
				}
			}
		}
	}

	return azZoneMap
}

func (srx *SRXObjectSet) parseAddressSet(config string) string {
	regex := `(?P<all>set security (zones security-zone \S+ )?address-book ((?P<name>\S+) )?address-set [^\n]*)`
	sections := parseSection(config, regex, "all")

	// 如果没有匹配的地址组配置，直接返回
	if sections == "" {
		return ""
	}

	azZoneMap := srx.parseAttachZone(config)

	regexMap := map[string]string{
		"regex": `
			(?P<cli>
			set\ssecurity\s(zones\ssecurity-zone\s(?P<zone>\S+)\s)?address-book\s((?P<book_name>\S+)\s)?address-set\s(?P<name>\S+)\s
			(
				(address-set\s(?P<address_set>\S+)) |
				(address\s(?P<address>\S+)) |

			)$
			)
		`,
		"name":  "address",
		"flags": "mx",
		"pcre":  "true",
	}

	addressResult, err := text.SplitterProcessOneTime(regexMap, sections)
	if err != nil {
		// 如果解析出错（例如没有匹配），返回空字符串而不是panic
		return ""
	}

	// 如果没有匹配，直接返回
	if addressResult == nil || addressResult.Len() == 0 {
		return ""
	}

	setMap := map[string]*srxNetwork{}
	for it := addressResult.Iterator(); it.HasNext(); {
		_, _, addressMap := it.Next()
		if _, ok := setMap[addressMap["name"]]; !ok {
			obj := &srxNetwork{
				catagory: firewall.GROUP_NETWORK,
				// cli:      addressMap["cli"],
				name:    addressMap["name"],
				network: network.NewNetworkGroup(),
			}
			setMap[addressMap["name"]] = obj
			if addressMap["book_name"] == "global" {
				srx.push("global", addressMap["name"], obj)
			} else if addressMap[addressMap["book_name"]] != "" {
				// address_book的名称主要用于选择对应的zone
				zone := azZoneMap[addressMap["book_name"]]
				srx.push(zone, addressMap["name"], obj)
			} else {
				zone := addressMap["zone"]
				srx.push(zone, addressMap["name"], obj)
			}
		}

		obj := setMap[addressMap["name"]]
		obj.cli = obj.cli + addressMap["cli"]

		// var net *network.NetworkGroup
		// var err error
		if addressMap["address"] != "" {
			// net, err = network.NewNetworkGroupFromString(addressMap["address"])
			// if err != nil {
			// panic(err)
			// }

			obj.refNames = append(obj.refNames, addressMap["address"])
		}
		if addressMap["address_set"] != "" {
			obj.refNames = append(obj.refNames, addressMap["address_set"])
		}
		//
		// if net != nil {
		// obj.network.AddGroup(net)
		// } else if addressMap["address_set"] != "" {
		// obj.refNames = append(obj.refNames, addressMap["address_set"])
		// } else {
		// panic(fmt.Sprint("unknown error: ", addressMap))
		// }
	}

	return ""

}

func (srx *SRXObjectSet) parseAddress(config string) string {
	regex := `(?P<all>set security (zones security-zone \S+ )?address-book ((?P<name>\S+) )?address [^\n]*)`
	sections := parseSection(config, regex, "all")

	// 如果没有匹配的地址对象配置，直接返回
	if sections == "" {
		return ""
	}

	azZoneMap := srx.parseAttachZone(config)

	regexMap := map[string]string{
		"regex": `
			(?P<cli>
			set\ssecurity\s(zones\ssecurity-zone\s(?P<zone>\S+)\s)?address-book\s((?P<book_name>\S+)\s)?address\s(?P<name>\S+)\s
			(
				(range-address\s(?P<start>\S+)\sto\s(?P<end>\S+)) |
				(?P<address>\S+) |

			)$
			)
		`,
		"name":  "address",
		"flags": "mx",
		"pcre":  "true",
	}

	addressResult, err := text.SplitterProcessOneTime(regexMap, sections)
	if err != nil {
		// 如果解析出错（例如没有匹配），返回空字符串而不是panic
		// 这样可以允许某些配置类型不存在（例如服务对象CLI中可能没有地址对象）
		return ""
	}

	// 如果没有匹配，直接返回
	if addressResult == nil || addressResult.Len() == 0 {
		return ""
	}

	for it := addressResult.Iterator(); it.HasNext(); {
		_, _, addressMap := it.Next()
		obj := &srxNetwork{
			catagory: firewall.OBJECT_NETWORK,
			cli:      addressMap["cli"],
			name:     addressMap["name"],
		}
		obj.network = &network.NetworkGroup{}
		var net *network.Network
		if addressMap["start"] != "" {
			net, err = network.NewNetworkFromString(addressMap["start"] + "-" + addressMap["end"])
			obj.network.Add(net)
		} else {
			net, err = network.NewNetworkFromString(addressMap["address"])
			obj.network.Add(net)
		}

		if addressMap["book_name"] == "global" {
			srx.push("global", addressMap["name"], obj)
		} else if addressMap["book_name"] != "" {
			zone := azZoneMap[addressMap["book_name"]]
			srx.push(zone, addressMap["name"], obj)
		} else {
			zone := addressMap["zone"]
			srx.push(zone, addressMap["name"], obj)
		}
	}

	return ""
}

// func (srx *SRXObjectSet) parseZoneAddress(config string) string {
// regex := `(?P<all>set security address-book global address [^\n]*)`
// sections := srx.parseSection(config, regex, "all")
//
// regexMap := map[string]string{
// "regex": `
// (?P<cli>
// set\ssecurity\saddress-book\s(?P<book_name>\S+)\saddress\s(?P<name>\S+)\s
// (
// (range-address\s(?P<start>\S+)\sto\s(?P<end>\S+)) |
// (?P<address>\S+) |
//
// )$
// )
// `,
// "name":  "address",
// "flags": "mx",
// "pcre":  "true",
// }
//
// addressResult, err := text.SplitterProcessOneTime(regexMap, sections)
// if err != nil {
// panic(err)
// }
//
// for it := addressResult.Iterator(); it.HasNext(); {
// _, _, addressMap := it.Next()
// obj := &srxNetwork{
// catagory: firewall.OBJECT_NETWORK,
// cli:      addressMap["cli"],
// name:     addressMap["name"],
// }
// obj.network = &network.NetworkGroup{}
// var net *network.Network
// if addressMap["start"] != "" {
// net, err = network.NewNetworkFromString(addressMap["start"] + "-" + addressMap["end"])
// obj.network.Add(net)
// } else {
// net, err = network.NewNetworkFromString(addressMap["address"])
// obj.network.Add(net)
// }
//
// fmt.Println(obj.network)
// }
//
// return ""
// }
//
// func (srx *SRXObjectSet) parseSection(config, regex, name string) string {
// sectionRegexMap := map[string]string{
// "regex": regex,
// "name":  "section",
// "flags": "m",
// "pcre":  "true",
// }
//
// sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
// if err != nil {
// panic(err)
// }
//
// var sections []string
// for it := sectionResult.Iterator(); it.HasNext(); {
// _, _, sectionMap := it.Next()
// sections = append(sections, sectionMap[name])
// }
//
// return strings.Join(sections, "\n")
//
// }
//
//
// func (srx *SRXObjectSet) parseZoneAddress(config string) {
// sectionRgexMap := map[string]string{
// "regex": `set security zones security-zone \S+ address-book address [^\n]*`,
// "name":  "section",
// "flags": "m",
// "pcre":  "true",
// }
// }

//
// func (srx *SRXObjectSet) parseObjectSecion(config string) []string {
// var sections []string
// sectionRegexMap := map[string]string{
// "regex": `(?P<all>^object[^\n]+(?!\n nat)(\n [^\n]+)+)`,
// "name":  "section",
// "flags": "m",
// "pcre":  "true",
// }
//
// sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
// if err != nil {
// panic(err)
// }
//
// for it := sectionResult.Iterator(); it.HasNext(); {
// _, _, sectionMap := it.Next()
// sections = append(sections, sectionMap["all"])
// srx.prepare(sectionMap["all"])
// }
//
// return sections
// }

func (srx *SRXObjectSet) Network(zone, name string) (*network.NetworkGroup, bool) {
	if name == "any" {
		ng := network.NewAny46Group()
		return ng, true
	} else if name == "any-ipv4" {
		ng := network.NewAny4Group()
		return ng, true
	} else if name == "any-ipv6" {
		ng := network.NewAny6Group()
		return ng, true
	}

	var m map[string]firewall.FirewallNetworkObject
	if _, ok := srx.zoneAddressBook[zone]; ok {
		m = srx.zoneAddressBook[zone]
	} else {
		m = srx.zoneAddressBook["global"]
	}

	if m == nil || len(m) == 0 {
		return nil, false
	}

	obj, ok := m[name]
	if !ok {
		return nil, false
	}

	ng := obj.Network(srx.node)
	if ok && ng == nil {
		panic(fmt.Sprint("unknown error", zone, name))
	}
	return ng, ok
}

func (srx *SRXObjectSet) Service(name string) (*service.Service, bool) {
	if obj, ok := srx.serviceMap[name]; !ok {
		return nil, ok
	} else {
		ng := obj.Service(srx.node)
		return ng, true
	}
}

func (srx *SRXObjectSet) Pool(name string, objectType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	if _, ok := srx.poolMap[objectType]; ok {
		return srx.poolMap[objectType][name], true
	}

	return nil, false
}

func (srx *SRXObjectSet) L4Port(name string) (*service.L4Port, bool) {
	return nil, false
}

func (srx *SRXObjectSet) GetPoolByeNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	// poolMap    map[firewall.NatType]map[string]firewall.FirewallNetworkObject
	if _, ok := srx.poolMap[natType]; !ok {
		return nil, false
	} else {
		poolMap := srx.poolMap[natType]
		for _, obj := range poolMap {
			net := obj.Network(nil)
			if net.Same(ng) {
				return obj, true
			}
		}
	}

	return nil, false
}

func (srx *SRXObjectSet) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	// zoneAddressBook map[string]map[string]firewall.FirewallNetworkObject
	var zone string
	if port == nil {
		zone = "global"
	} else {
		zone = port.(*SRXPort).Zone()
	}
	if zone == "" {
		panic(fmt.Sprint("unknown error:", port))
	}

	objectMap := srx.zoneAddressBook[zone]

	for _, obj := range objectMap {
		objNet := obj.Network(srx.node)
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

func (srx *SRXObjectSet) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	// serviceMap map[string]firewall.FirewallServiceObject

	for _, obj := range srx.serviceMap {
		srv := obj.Service(srx.node)
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

func (srx *SRXObjectSet) hasObjectName(name string) bool {

	for _, objMap := range srx.zoneAddressBook {
		for _, obj := range objMap {
			if obj.Name() == name {
				return true
			}
		}
	}

	for _, obj := range srx.serviceMap {
		if obj.Name() == name {
			return true
		}
	}

	return false
}
