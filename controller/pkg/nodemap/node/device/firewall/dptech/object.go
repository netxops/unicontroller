package dptech

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/errors"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/parse"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/registry"
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

type DptechObjectSet struct {
	node *DptechNode
	//地址的第一级索引为zone，或为"global"
	// zoneAddressBook  map[string]map[string]firewall.FirewallNetworkObject
	addressObjectSet map[string]firewall.FirewallNetworkObject
	addressGroupSet  map[string]firewall.FirewallNetworkObject
	// zoneAddressBook map[string]*AddressBook
	serviceMap   map[string]firewall.FirewallServiceObject
	serviceGroup map[string]firewall.FirewallServiceObject
	poolMap      map[string]firewall.FirewallNetworkObject
}

// MarshalJSON 实现 JSON 序列化
func (dos *DptechObjectSet) MarshalJSON() ([]byte, error) {
	addressObjectSet, err := registry.MapToRawMessage(dos.addressObjectSet)
	if err != nil {
		return nil, fmt.Errorf("error marshaling addressObjectSet: %w", err)
	}

	addressGroupSet, err := registry.MapToRawMessage(dos.addressGroupSet)
	if err != nil {
		return nil, fmt.Errorf("error marshaling addressGroupSet: %w", err)
	}

	serviceMap, err := registry.MapToRawMessage(dos.serviceMap)
	if err != nil {
		return nil, fmt.Errorf("error marshaling serviceMap: %w", err)
	}

	serviceGroup, err := registry.MapToRawMessage(dos.serviceGroup)
	if err != nil {
		return nil, fmt.Errorf("error marshaling serviceGroup: %w", err)
	}

	poolMap, err := registry.MapToRawMessage(dos.poolMap)
	if err != nil {
		return nil, fmt.Errorf("error marshaling pool map: %w", err)
	}

	return json.Marshal(dptechObjectSetJSON{
		AddressObjectSet: addressObjectSet,
		AddressGroupSet:  addressGroupSet,
		ServiceMap:       serviceMap,
		ServiceGroup:     serviceGroup,
		PoolMap:          poolMap,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (dos *DptechObjectSet) UnmarshalJSON(data []byte) error {
	var dosj dptechObjectSetJSON
	if err := json.Unmarshal(data, &dosj); err != nil {
		return err
	}

	addressObjectSet, err := registry.RawMessageToMap[firewall.FirewallNetworkObject](dosj.AddressObjectSet)
	if err != nil {
		return fmt.Errorf("error unmarshaling addressObjectSet: %w", err)
	}
	dos.addressObjectSet = addressObjectSet

	addressGroupSet, err := registry.RawMessageToMap[firewall.FirewallNetworkObject](dosj.AddressGroupSet)
	if err != nil {
		return fmt.Errorf("error unmarshaling addressGroupSet: %w", err)
	}
	dos.addressGroupSet = addressGroupSet

	serviceMap, err := registry.RawMessageToMap[firewall.FirewallServiceObject](dosj.ServiceMap)
	if err != nil {
		return fmt.Errorf("error unmarshaling serviceMap: %w", err)
	}
	dos.serviceMap = serviceMap

	serviceGroup, err := registry.RawMessageToMap[firewall.FirewallServiceObject](dosj.ServiceGroup)
	if err != nil {
		return fmt.Errorf("error unmarshaling serviceGroup: %w", err)
	}
	dos.serviceGroup = serviceGroup

	poolMap, err := registry.RawMessageToMap[firewall.FirewallNetworkObject](dosj.PoolMap)
	if err != nil {
		return fmt.Errorf("error unmarshaling pool map: %w", err)
	}
	dos.poolMap = poolMap

	return nil
}

// 更新 dptechObjectSetJSON 结构
type dptechObjectSetJSON struct {
	AddressObjectSet json.RawMessage `json:"address_object_set"`
	AddressGroupSet  json.RawMessage `json:"address_group_set"`
	ServiceMap       json.RawMessage `json:"service_map"`
	ServiceGroup     json.RawMessage `json:"service_group"`
	PoolMap          json.RawMessage `json:"pool_map"`
}

func NewDptechObjectSet(node *DptechNode) *DptechObjectSet {

	dos := &DptechObjectSet{
		node: node,
		// zoneAddressBook: map[string]map[string]firewall.FirewallNetworkObject{},
		addressObjectSet: map[string]firewall.FirewallNetworkObject{},
		addressGroupSet:  map[string]firewall.FirewallNetworkObject{},
		serviceGroup:     map[string]firewall.FirewallServiceObject{},
		serviceMap:       map[string]firewall.FirewallServiceObject{},
		poolMap:          map[string]firewall.FirewallNetworkObject{},
	}
	node.ObjectSet = dos
	return dos
}

var _ firewall.FirewallServiceObject = &DptechService{}

type DptechService struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	service  *service.Service
	refNames []string
}

// dptechServiceJSON 用于序列化和反序列化
type dptechServiceJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	Service  *service.Service            `json:"service"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (ds *DptechService) MarshalJSON() ([]byte, error) {
	return json.Marshal(dptechServiceJSON{
		Catagory: ds.catagory,
		Cli:      ds.cli,
		Name:     ds.name,
		Service:  ds.service,
		RefNames: ds.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ds *DptechService) UnmarshalJSON(data []byte) error {
	var dsj dptechServiceJSON
	if err := json.Unmarshal(data, &dsj); err != nil {
		return err
	}

	ds.catagory = dsj.Catagory
	ds.cli = dsj.Cli
	ds.name = dsj.Name
	ds.service = dsj.Service
	ds.refNames = dsj.RefNames

	return nil
}

func (rs *DptechService) TypeName() string {
	return "DptechService"
}

func (rs *DptechService) Name() string {
	return rs.name
}

func (rs *DptechService) Cli() string {
	return rs.cli
}

func (rs *DptechService) Type() firewall.FirewallObjectType {
	return rs.catagory
}

// func (rs *DptechService) Service(serviceMap map[string]firewall.FirewallServiceObject) *service.Service {
func (rs *DptechService) Service(node firewall.FirewallNode) *service.Service {
	var s *service.Service

	if rs.service != nil {
		s = rs.service.Copy().(*service.Service)
	}
	dp := node.(*DptechNode)
	serviceMap := dp.ObjectSet.serviceMap
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

type DptechNetwork struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	hasNat   bool
	network  *network.NetworkGroup
	refs     []firewall.FirewallNetworkObject
	refNames []string
}

// dptechNetworkJSON 用于序列化和反序列化
type dptechNetworkJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	HasNat   bool                        `json:"has_nat"`
	Network  *network.NetworkGroup       `json:"network"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (dn *DptechNetwork) MarshalJSON() ([]byte, error) {
	return json.Marshal(dptechNetworkJSON{
		Catagory: dn.catagory,
		Cli:      dn.cli,
		Name:     dn.name,
		HasNat:   dn.hasNat,
		Network:  dn.network,
		RefNames: dn.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (dn *DptechNetwork) UnmarshalJSON(data []byte) error {
	var dnj dptechNetworkJSON
	if err := json.Unmarshal(data, &dnj); err != nil {
		return err
	}

	dn.catagory = dnj.Catagory
	dn.cli = dnj.Cli
	dn.name = dnj.Name
	dn.hasNat = dnj.HasNat
	dn.network = dnj.Network
	dn.refNames = dnj.RefNames

	return nil
}

func (sn *DptechNetwork) Name() string {
	return sn.name
}

func (sn *DptechNetwork) TypeName() string {
	return "DptechNetwork"
}

func (sn *DptechNetwork) Cli() string {
	return sn.cli
}

func (sn *DptechNetwork) Type() firewall.FirewallObjectType {
	return sn.catagory
}

func (sn *DptechNetwork) Network(node firewall.FirewallNode) *network.NetworkGroup {
	var ng *network.NetworkGroup
	if sn.network != nil {
		ng = sn.network.Copy().(*network.NetworkGroup)
	}
	dp := node.(*DptechNode)
	networkMap := dp.ObjectSet.addressObjectSet
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

	return ng
}

// func (dos *DptechObjectSet) push(zone, name string, obj *DptechNetwork) {
// 	if zone == "" {
// 		// 如何没有给出zone，将object保存到global地址中
// 		zone = "global"
// 	}
// 	// 如果给出zone，则将object保持到zone相关的地址中，注意
// 	if _, ok := dos.zoneAddressBook[zone]; !ok {
// 		dos.zoneAddressBook[zone] = map[string]firewall.FirewallNetworkObject{}
// 	}
// 	dos.zoneAddressBook[zone][name] = obj
// }

func (dos *DptechObjectSet) parseSectionWithGroup(config string, regex string, groups ...string) ([]string, error) {
	sectionRegexMap := map[string]string{
		"regex": regex,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
	if err != nil {
		return nil, fmt.Errorf("failed to process section: %w", err)
	}

	clis, err := sectionResult.CombinKey(groups)
	if err != nil {
		return nil, fmt.Errorf("failed to combine keys: %w", err)
	}

	return clis, nil
}

// func (dos *DptechObjectSet) parseConfig(config string) {
// 	// Dptech.parseZoneAddress(config)
// 	dos.parseAddress(config)
// 	dos.parseAddressSet(config)
// 	dos.parseApplication(config)
// 	dos.parseApplicationSet(config)
// 	dos.parsePools(config)

// }

func (adapter *DptechObjectSet) ParseConfig(config string) *parse.ParseResult {
	result := parse.NewParseResult()

	// 解析地址对象
	adapter.parseAddress(config, result)

	// 解析地址集
	adapter.parseAddressGroup(config, result)

	// 解析服务对象
	adapter.parseService(config, result)

	// 解析服务集
	adapter.parseServiceGroup(config, result)

	adapter.parsePools(config, result)

	return result
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
				(port\srange\sto\s(?P<port_to>\d+)) |
				(port\srange\s(?P<port_from>\d+))
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
		ng, err = network.NewNetworkGroupFromString(poolMap["address"])
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

func (dos *DptechObjectSet) parsePools(config string, result *parse.ParseResult) {
	poolRegexMap := map[string]string{
		"regex": `address-pool\s+(?P<name>\S+)\s+address\s+(?P<start>\S+)(\s+to\s+(?P<end>\S+))?`,
		"name":  "pool",
		"flags": "m",
		"pcre":  "true",
	}

	poolResult, err := text.SplitterProcessOneTime(poolRegexMap, config)
	if err != nil {
		result.AddError(errors.NewError(
			errors.ParseError,
			"Failed to parse address pools",
			errors.SeverityError,
			"Address Pools",
			0,
			config,
			map[string]interface{}{"error": err.Error()},
		))
		return
	}

	for it := poolResult.Iterator(); it.HasNext(); {
		_, _, poolMap := it.Next()
		pool := &NatPool{
			natType:    firewall.DYNAMIC_NAT, // Assuming DYNAMIC_NAT for all pools
			cli:        fmt.Sprintf("address-pool %s address %s", poolMap["name"], poolMap["start"]),
			name:       poolMap["name"],
			objectType: firewall.OBJECT_POOL,
		}

		var ng *network.NetworkGroup
		var err error
		if poolMap["end"] != "" {
			ng, err = network.NewNetworkGroupFromString(poolMap["start"] + "-" + poolMap["end"])
			pool.cli += " to " + poolMap["end"]
		} else {
			ng, err = network.NewNetworkGroupFromString(poolMap["start"])
		}

		if err != nil {
			result.AddError(errors.NewError(
				errors.ExecutionError,
				"Failed to create network group for address pool",
				errors.SeverityError,
				"Address Pools",
				0,
				pool.cli,
				map[string]interface{}{"error": err.Error()},
			))
			continue
		}

		pool.network = ng

		dos.poolMap[pool.Name()] = pool
	}
}

func (dos *DptechObjectSet) parseServiceGroup(config string, result *parse.ParseResult) {
	regex := `(?P<all>service-group (?P<name>\S+) [^\n]+)`
	clis, err := dos.parseSectionWithGroup(config, regex, "name")
	if err != nil {
		result.AddError(errors.NewError(
			errors.ParseError,
			"Failed to parse service group sections",
			errors.SeverityError,
			"Service Groups",
			0,
			config,
			map[string]interface{}{"error": err.Error()},
		))
		return
	}

	serviceGroupRegexMap := map[string]string{
		"regex": `
            (?P<cli>
                service-group\s+(?P<name>\S+)\s+
					(
                		(service-object\s+(?P<service>\S+)) |
						(predefined-service\s(?P<builtin_service>\S+))
					)
            )
        `,
		"name":  "serviceGroup",
		"flags": "mx",
		"pcre":  "true",
	}

	for _, cli := range clis {
		serviceGroupResult, err := text.SplitterProcessOneTime(serviceGroupRegexMap, cli)
		if err != nil {
			result.AddError(errors.NewError(
				errors.ParseError,
				"Failed to parse service group",
				errors.SeverityWarning,
				"Service Groups",
				0,
				cli,
				map[string]interface{}{"error": err.Error()},
			))
			continue
		}

		for it := serviceGroupResult.Iterator(); it.HasNext(); {
			_, _, serviceGroupMap := it.Next()
			groupName := serviceGroupMap["name"]
			serviceName := serviceGroupMap["service"]
			builtin := serviceGroupMap["builtin_service"]

			if _, ok := dos.serviceGroup[groupName]; !ok {
				dos.serviceGroup[groupName] = &DptechService{
					catagory: firewall.GROUP_SERVICE,
					name:     groupName,
					cli:      "",
					refNames: []string{},
				}
			}

			var obj *DptechService
			group := dos.serviceGroup[groupName].(*DptechService)
			if serviceName != "" {
				obj = dos.serviceMap[serviceName].(*DptechService)
				group.refNames = append(group.refNames, serviceName)
			}

			if builtin != "" {
				srv, ok := DptechBuiltinService(builtin)
				if !ok {
					result.AddError(errors.NewError(
						errors.ParseError,
						fmt.Sprintf("Built-in service '%s' not found", builtin),
						errors.SeverityWarning,
						"Service Groups",
						0,
						serviceGroupMap["cli"],
						map[string]interface{}{"builtin_service": builtin},
					))
					continue
				} else {
					group.refNames = append(group.refNames, builtin)
				}
				obj = &DptechService{
					catagory: firewall.OBJECT_SERVICE,
					name:     builtin,
					cli:      "",
					refNames: []string{},
					service:  srv,
				}
			}

			if group.cli == "" {
				group.cli = serviceGroupMap["cli"]
			} else {
				group.cli += "\n" + serviceGroupMap["cli"]
			}
			if group.service == nil {
				group.service = obj.service.Copy().(*service.Service)
			} else {
				group.service.Add(obj.service)
			}
		}
	}
}

func (dos *DptechObjectSet) parseService(config string, result *parse.ParseResult) {
	regex := `(?P<all>service-object (?P<name>\S+) [^\n]*)`
	clis, err := dos.parseSectionWithGroup(config, regex, "name")
	if err != nil {
		result.AddError(errors.NewError(
			errors.ParseError,
			"Failed to parse service sections",
			errors.SeverityError,
			"Service Objects",
			0,
			config,
			map[string]interface{}{"error": err.Error()},
		))
		return
	}
	serviceRegexMap := map[string]string{
		"regex": `(?P<cli>service-object\s(?P<name>\S+)\s(?P<params>.+))`,
		"name":  "service",
		"flags": "mx",
		"pcre":  "true",
	}

	for _, cli := range clis {
		serviceResult, err := text.SplitterProcessOneTime(serviceRegexMap, cli)
		if err != nil {
			result.AddError(errors.NewError(errors.ParseError, "Failed to parse service object", errors.SeverityWarning, "Service Objects", 0, cli, map[string]interface{}{"error": err.Error()}))
			continue
		}

		serviceMap, ok := serviceResult.One()
		if !ok {
			result.AddError(errors.NewError(errors.ParseError, "No match found for service object", errors.SeverityWarning, "Service Objects", 0, cli, nil))
			continue
		}

		name := serviceMap["name"]
		params := serviceMap["params"]

		var obj *DptechService
		var existingObj bool

		// 检查是否已存在同名对象
		if existingService, exists := dos.serviceMap[name]; exists {
			obj = existingService.(*DptechService)
			existingObj = true
		} else {
			obj = &DptechService{
				catagory: firewall.OBJECT_SERVICE,
				name:     name,
			}
		}

		// 解析新的服务参数
		newSrv, errParse := parseServiceParams(params)
		if errParse != nil {
			result.AddError(errors.NewError(errors.ExecutionError, "Failed to create service object", errors.SeverityError, "Service Objects", 0, cli, map[string]interface{}{"error": errParse.Error()}))
			continue
		}

		// 如果对象已存在，合并服务；否则，直接赋值
		if existingObj {
			obj.service.Add(newSrv)
			obj.cli += "\n" + cli // 添加新的CLI到现有的CLI
		} else {
			obj.service = newSrv
			obj.cli = cli
		}

		// 更新或添加到serviceMap
		dos.serviceMap[name] = obj
	}
}

func parseServiceParams(params string) (*service.Service, error) {
	fields := strings.Fields(params)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty service-object params")
	}

	proto := fields[0]
	fields = fields[1:]

	switch proto {
	case "protocol":
		return parseProtocolService(fields)
	// case "tcp", "udp":
	// 	return parseTCPUDPService(proto, fields)
	default:
		return nil, fmt.Errorf("unsupported service protocol: %s", proto)
		// return parseOtherProtocolService(proto)
	}
}

func parseProtocolService(fields []string) (*service.Service, error) {
	if len(fields) > 0 && fields[0] == "icmp" {
		return parseICMPService(fields[1:])
	}

	if len(fields) > 0 && (fields[0] == "tcp" || fields[0] == "udp") {
		return parseTCPUDPService(fields[0], fields[1:])
	}

	if len(fields) > 0 {
		protoNum, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("invalid protocol number: %s", fields[0])
		}
		return service.NewServiceWithProto(strconv.Itoa(protoNum))
	}
	return nil, fmt.Errorf("invalid protocol service definition")
}

func parseICMPService(fields []string) (*service.Service, error) {
	var icmpTypes, icmpCodes []int
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "type":
			_, types := parseICMPRange(fields, i+1)
			icmpTypes = append(icmpTypes, types...)
		case "code":
			_, codes := parseICMPRange(fields, i+1)
			icmpCodes = append(icmpCodes, codes...)
		}
	}

	if len(icmpTypes) == 0 {
		icmpTypes = []int{service.ICMP_DEFAULT_TYPE}
	}
	if len(icmpCodes) == 0 {
		icmpCodes = []int{service.ICMP_DEFAULT_CODE}
	}

	srv := &service.Service{}
	for _, t := range icmpTypes {
		for _, c := range icmpCodes {
			tmpSrv, err := service.NewServiceWithIcmp("icmp", t, c)
			if err == nil {
				srv.Add(tmpSrv)
			}
		}
	}
	return srv, nil
}

func parseICMPRange(fields []string, start int) (int, []int) {
	var result []int
	if start+1 < len(fields) && fields[start+1] == "to" && start+2 < len(fields) {
		begin, _ := strconv.Atoi(fields[start])
		end, _ := strconv.Atoi(fields[start+2])
		for i := begin; i <= end; i++ {
			result = append(result, i)
		}
		return start + 2, result
	}
	val, _ := strconv.Atoi(fields[start])
	return start, []int{val}
}

func parseTCPUDPService(proto string, fields []string) (*service.Service, error) {
	srcPorts, dstPorts := parsePortRanges(fields)
	if len(srcPorts) == 0 {
		srcPorts = []string{"0-65535"}
	}
	if len(dstPorts) == 0 {
		dstPorts = []string{"0-65535"}
	}

	srv := &service.Service{}
	for _, sp := range srcPorts {
		for _, dp := range dstPorts {
			tmpSrv, err := service.NewServiceWithL4(proto, sp, dp)
			if err == nil {
				srv.Add(tmpSrv)
			}
		}
	}
	return srv, nil
}

func parsePortRanges(fields []string) ([]string, []string) {
	var srcPorts, dstPorts []string
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "src-port":
			_, ports := parsePortRange(fields, i+1)
			srcPorts = append(srcPorts, ports...)
		case "dst-port":
			_, ports := parsePortRange(fields, i+1)
			dstPorts = append(dstPorts, ports...)
		}
	}
	return srcPorts, dstPorts
}

func parsePortRange(fields []string, start int) (int, []string) {
	if start+1 < len(fields) && fields[start+1] == "to" && start+2 < len(fields) {
		return start + 2, []string{fields[start] + "-" + fields[start+2]}
	}
	return start, []string{fields[start]}
}

func parseOtherProtocolService(proto string) (*service.Service, error) {
	if n, err := strconv.Atoi(proto); err == nil {
		return service.NewServiceWithProto(strconv.Itoa(n))
	}
	return service.NewServiceWithProto(proto)
}

func (dos *DptechObjectSet) parseAttachZone(config string) map[string]string {
	azRegexMap := map[string]string{
		"regex": `(?P<all>set security address-book (?P<book_name>\S+) attach zone (?P<zone>\S+))`,
		"flags": "m",
		"name":  "az",
		"pcre":  "true",
	}

	azResult, err := text.SplitterProcessOneTime(azRegexMap, config)
	if err != nil {
		panic(err)
	}

	azZoneMap := map[string]string{}
	for it := azResult.Iterator(); it.HasNext(); {
		_, _, azMap := it.Next()
		azZoneMap[azMap["book_name"]] = azMap["zone"]
	}

	return azZoneMap
}

func (dos *DptechObjectSet) parseAddressGroup(config string, result *parse.ParseResult) {
	regex := `(?P<all>address-group (?P<name>\S+) [^\n]+)`
	clis, err := dos.parseSectionWithGroup(config, regex, "name")
	if err != nil {
		result.AddError(errors.NewError(
			errors.ParseError,
			"Failed to parse address group sections",
			errors.SeverityError,
			"Address Groups",
			0,
			config,
			map[string]interface{}{"error": err.Error()},
		))
		return
	}

	regexMap := map[string]string{
		"regex": `
			(?P<cli>
			address-group\s+(?P<name>\S+)\s+
			(
				(address-object\s+(?P<obj_name>\S+)\s*) |
				(description\s+(?P<description>\S+)\s*) 

			)$
			)
		`,
		"name":  "address",
		"flags": "mx",
		"pcre":  "true",
	}

	for _, cli := range clis {
		cli = strings.TrimSpace(cli)
		addressResult, err := text.SplitterProcessOneTime(regexMap, cli)
		if err != nil {
			result.AddError(errors.NewError(
				errors.ParseError,
				"Failed to parse address object",
				errors.SeverityWarning,
				"Address Objects",
				0,
				cli,
				map[string]interface{}{"error": err.Error()},
			))
			continue
		}

		hasMatch := false
		for it := addressResult.Iterator(); it.HasNext(); {
			hasMatch = true
			_, _, addressMap := it.Next()

			if _, ok := dos.addressGroupSet[addressMap["name"]]; !ok {
				dos.addressGroupSet[addressMap["name"]] = &DptechNetwork{
					catagory: firewall.OBJECT_NETWORK,
					cli:      cli,
					name:     addressMap["name"],
					network:  network.NewNetworkGroup(),
				}
			}
			obj := dos.addressGroupSet[addressMap["name"]].(*DptechNetwork)
			if addressMap["obj_name"] != "" {
				_, netObj, ok := dos.Network("", addressMap["obj_name"])
				if !ok {
					result.AddError(errors.NewError(
						errors.ParseError,
						"Address object not found",
						errors.SeverityWarning,
						"Address Objects",
						0,
						cli,
						map[string]interface{}{"name": addressMap["obj_name"]},
					))
					continue
				}
				obj.network.AddGroup(netObj)
				obj.refNames = append(obj.refNames, addressMap["obj_name"])
			} else if addressMap["description"] != "" {
				// Handle description if needed
			} else {
				result.AddError(errors.NewError(
					errors.ParseError,
					"Unknown cli in address object",
					errors.SeverityWarning,
					"Address Objects",
					0,
					cli,
					map[string]interface{}{"cli": cli},
				))
				continue
			}
		}

		if !hasMatch {
			result.AddError(errors.NewError(
				errors.ParseError,
				"No match found for address object",
				errors.SeverityWarning,
				"Address Objects",
				0,
				cli,
				nil,
			))
		}
	}

}

func (dos *DptechObjectSet) parseAddress(config string, result *parse.ParseResult) {
	regex := `(?P<all>address-object (?P<name>\S+) [^\n]+)`
	clis, err := dos.parseSectionWithGroup(config, regex, "name")
	if err != nil {
		result.AddError(errors.NewError(
			errors.ParseError,
			"Failed to parse address sections",
			errors.SeverityError,
			"Address Objects",
			0,
			config,
			map[string]interface{}{"error": err.Error()},
		))
		return
	}

	regexMap := map[string]string{
		"regex": `
            (?P<cli>
                address-object\s+(?P<name>\S+)\s+
                (
                    (range\s+(?P<start>\S+)\s+(?P<end>\S+)) |
                    (exclude\s+(?P<exclude>\S+)) |
                    (wildcard\s+(?P<wildcard>\S+)) |
                    (?P<address>\S+) |
                    (description\s+(?P<description>\S+))  
                )\s*$
            )
        `,
		"name":  "address",
		"flags": "mx",
		"pcre":  "true",
	}

	for _, cli := range clis {

		cli = strings.TrimSpace(cli)
		addressResult, err := text.SplitterProcessOneTime(regexMap, cli)
		if err != nil {
			result.AddError(errors.NewError(errors.ParseError, "Failed to parse address object", errors.SeverityWarning, "Address Objects", 0, cli, map[string]interface{}{"error": err.Error()}))
			continue
		}

		for it := addressResult.Iterator(); it.HasNext(); {
			_, _, addressMap := it.Next()
			if len(addressMap) == 0 {
				continue
			}
			var obj *DptechNetwork
			var ok bool
			if _, ok = dos.addressObjectSet[addressMap["name"]]; ok {
				obj = dos.addressObjectSet[addressMap["name"]].(*DptechNetwork)
				obj.cli += "\n" + cli
			} else {
				obj = &DptechNetwork{
					catagory: firewall.OBJECT_NETWORK,
					cli:      cli,
					name:     addressMap["name"],
					network:  network.NewNetworkGroup(),
				}
			}

			if obj.name == "" {
				obj.name = addressMap["name"]
			}

			if addressMap["start"] != "" {
				net, err := network.NewNetworkFromString(addressMap["start"] + "-" + addressMap["end"])
				if err != nil {
					result.AddError(errors.NewError(errors.ExecutionError, "Failed to create network from range", errors.SeverityError, "Address Objects", 0, cli, map[string]interface{}{"error": err.Error(), "start": addressMap["start"], "end": addressMap["end"]}))
					continue
				}
				obj.network.Add(net)
			} else if addressMap["address"] != "" {
				if !isValidIPWithPrefix(addressMap["address"]) {
					result.AddError(errors.NewError(errors.ParseError, "Invalid IP address format", errors.SeverityError, "Address Objects", 0, cli, map[string]interface{}{"address": addressMap["address"]}))
					continue
				}

				net, err := network.NewNetworkFromString(addressMap["address"])
				if err != nil {
					result.AddError(errors.NewError(errors.ExecutionError, "Failed to create network from address", errors.SeverityError, "Address Objects", 0, cli, map[string]interface{}{"error": err.Error(), "address": addressMap["address"]}))
					continue
				}
				obj.network.Add(net)
			} else {
				result.AddError(errors.NewError(errors.ParseError, "Unknown address type", errors.SeverityWarning, "Address Objects", 0, cli, map[string]interface{}{"cli": cli}))
				continue
			}

			dos.addressObjectSet[addressMap["name"]] = obj
		}

	}
}

func isValidIPWithPrefix(address string) bool {
	parts := strings.Split(address, "/")
	if len(parts) != 2 {
		return false
	}

	ip := net.ParseIP(parts[0])
	if ip == nil {
		return false
	}

	prefix, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	if ip.To4() != nil {
		return prefix >= 0 && prefix <= 32
	} else {
		return prefix >= 0 && prefix <= 128
	}
}

// func (Dptech *DptechObjectSet) parseZoneAddress(config string) string {
// regex := `(?P<all>set security address-book global address [^\n]*)`
// sections := Dptech.parseSection(config, regex, "all")
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
// obj := &DptechNetwork{
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
// func (Dptech *DptechObjectSet) parseSection(config, regex, name string) string {
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
// func (Dptech *DptechObjectSet) parseZoneAddress(config string) {
// sectionRgexMap := map[string]string{
// "regex": `set security zones security-zone \S+ address-book address [^\n]*`,
// "name":  "section",
// "flags": "m",
// "pcre":  "true",
// }
// }

//
// func (Dptech *DptechObjectSet) parseObjectSecion(config string) []string {
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
// Dptech.prepare(sectionMap["all"])
// }
//
// return sections
// }

func (dos *DptechObjectSet) Network(_, name string) (string, *network.NetworkGroup, bool) {
	// 处理特殊的网络组
	switch name {
	case "any":
		return "any", network.NewAny46Group(), true
	case "any-ipv4":
		return "any-ipv4", network.NewAny4Group(), true
	case "any-ipv6":
		return "any-ipv6", network.NewAny6Group(), true
	}

	// 首先检查 addressObjectSet
	if obj, ok := dos.addressObjectSet[name]; ok {
		return obj.Cli(), obj.Network(dos.node), true
	}

	// 然后检查 addressGroupSet
	if obj, ok := dos.addressGroupSet[name]; ok {
		return obj.Cli(), obj.Network(dos.node), true
	}

	// 如果在两个集合中都没有找到，则返回 nil 和 false
	// 在测试环境中，地址对象可能尚未创建，这是正常的，使用调试级别日志
	// log.Printf("Warning: Network object '%s' not found", name)
	return "", nil, false
}

// func (dos *DptechObjectSet) Service(name string) (*service.Service, bool) {
// 	if strings.ToLower(name) == "any" {
// 		ip, _ := service.NewServiceFromString("ip")
// 		return ip, true
// 	}

//		if obj, ok := dos.serviceMap[name]; !ok {
//			return nil, ok
//		} else {
//			ng := obj.Service(dos.serviceMap)
//			return ng, true
//		}
//	}
func (dos *DptechObjectSet) Service(name string) (string, *service.Service, bool) {
	// Handle "any" service
	if strings.ToLower(name) == "any" {
		ip, _ := service.NewServiceFromString("ip")
		return "any", ip, true
	}

	// Check in serviceMap
	if obj, ok := dos.serviceMap[name]; ok {
		return obj.Cli(), obj.Service(dos.node), true
	}

	// Check in serviceGroup
	if obj, ok := dos.serviceGroup[name]; ok {
		return obj.Cli(), obj.Service(dos.node), true
	}

	// Check for built-in services
	if builtinService, ok := DptechBuiltinService(name); ok {
		return name, builtinService, true
	}

	// Service not found
	return "", nil, false
}

func (dos *DptechObjectSet) Pool(name string) (firewall.FirewallNetworkObject, bool) {
	pool, ok := dos.poolMap[name]
	return pool, ok
}

func (dos *DptechObjectSet) L4Port(name string) (*service.L4Port, bool) {
	return nil, false
}

func (dos *DptechObjectSet) GetPoolByeNetworkGroup(ng *network.NetworkGroup) (firewall.FirewallNetworkObject, bool) {
	for _, obj := range dos.poolMap {
		net := obj.Network(nil)
		if net.Same(ng) {
			return obj, true
		}
	}
	return nil, false
}

func (dos *DptechObjectSet) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	// 首先检查 addressObjectSet
	for _, obj := range dos.addressObjectSet {
		if obj.Network(dos.node).Same(ng) {
			if searchType == firewall.SEARCH_OBJECT || searchType == firewall.SEARCH_OBJECT_OR_GROUP {
				return obj, true
			}
		}
	}

	// 然后检查 addressGroupSet
	for _, obj := range dos.addressGroupSet {
		if obj.Network(dos.node).Same(ng) {
			if searchType == firewall.SEARCH_GROUP || searchType == firewall.SEARCH_OBJECT_OR_GROUP {
				return obj, true
			}
		}
	}

	// 注意：DptechObjectSet 结构中没有 zoneAddressBook 字段，所以我们不需要检查它
	// 如果需要基于端口或区域进行额外的检查，可能需要修改 DptechObjectSet 结构或调整此方法的逻辑

	return nil, false
}

func (dos *DptechObjectSet) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	// serviceMap map[string]firewall.FirewallServiceObject

	for _, obj := range dos.serviceMap {
		srv := obj.Service(dos.node)
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

func (dos *DptechObjectSet) hasObjectName(name string) bool {
	// 检查 addressObjectSet
	if _, ok := dos.addressObjectSet[name]; ok {
		return true
	}

	// 检查 addressGroupSet
	if _, ok := dos.addressGroupSet[name]; ok {
		return true
	}

	// 检查 serviceMap
	if _, ok := dos.serviceMap[name]; ok {
		return true
	}

	// 检查 serviceGroup
	if _, ok := dos.serviceGroup[name]; ok {
		return true
	}

	// 检查 poolMap
	if _, ok := dos.poolMap[name]; ok {
		return true
	}

	// 如果在所有集合中都没有找到，则返回 false
	return false
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNetworkObject)(nil)).Elem(), "DptechNetwork", reflect.TypeOf(DptechNetwork{}))
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallServiceObject)(nil)).Elem(), "DptechService", reflect.TypeOf(DptechService{}))
}
