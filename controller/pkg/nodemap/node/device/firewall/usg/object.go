package usg

import (
	"encoding/json"
	"fmt"
	"log"
	"math/bits"
	"net"
	"reflect"
	"regexp"
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
	"github.com/netxops/utils/tools"
)

const DefaultVrf = "default"

type AddressBook struct {
	networkMap map[string]firewall.FirewallNetworkObject
}

func (ab *AddressBook) Count() int {
	return len(ab.networkMap)
}

type UsgObjectSet struct {
	node *UsgNode
	//地址的第一级索引为zone，或为"global"
	// zoneAddressBook  map[string]map[string]firewall.FirewallNetworkObject
	addressObjectSet []firewall.FirewallNetworkObject
	addressGroupSet  []firewall.FirewallNetworkObject
	// zoneAddressBook map[string]*AddressBook
	serviceMap   []firewall.FirewallServiceObject
	serviceGroup []firewall.FirewallServiceObject
	// poolMap      map[firewall.NatType]map[string]firewall.FirewallNetworkObject
}

func NewUsgObjectSet(node *UsgNode) *UsgObjectSet {
	return &UsgObjectSet{
		node: node,
		// zoneAddressBook: map[string]map[string]firewall.FirewallNetworkObject{},
		addressObjectSet: []firewall.FirewallNetworkObject{},
		addressGroupSet:  []firewall.FirewallNetworkObject{},
		serviceGroup:     []firewall.FirewallServiceObject{},
		serviceMap:       []firewall.FirewallServiceObject{},
		// poolMap:          map[firewall.NatType]map[string]firewall.FirewallNetworkObject{},
	}
}

var _ firewall.FirewallServiceObject = &UsgService{}

type UsgService struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	service  *service.Service
	refNames []string
	vrf      string
}

// 实现 TypeInterface 接口
func (us *UsgService) TypeName() string {
	return "UsgService"
}

// usgServiceJSON 用于序列化和反序列化
type usgServiceJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	Service  *service.Service            `json:"service"`
	RefNames []string                    `json:"ref_names"`
	Vrf      string                      `json:"vrf"`
}

// MarshalJSON 实现 JSON 序列化
func (us *UsgService) MarshalJSON() ([]byte, error) {
	// var serviceRaw json.RawMessage
	// var err error
	// if us.service != nil {
	// 	serviceRaw, err = registry.InterfaceToRawMessage(us.service)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("error marshaling service: %w", err)
	// 	}
	// }

	return json.Marshal(usgServiceJSON{
		Catagory: us.catagory,
		Cli:      us.cli,
		Name:     us.name,
		Service:  us.service,
		RefNames: us.refNames,
		Vrf:      us.vrf,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (us *UsgService) UnmarshalJSON(data []byte) error {
	var usj usgServiceJSON
	if err := json.Unmarshal(data, &usj); err != nil {
		return err
	}

	us.catagory = usj.Catagory
	us.cli = usj.Cli
	us.name = usj.Name
	us.refNames = usj.RefNames
	us.vrf = usj.Vrf
	us.service = usj.Service

	return nil
}

// usgObjectSetJSON 用于序列化和反序列化
type usgObjectSetJSON struct {
	AddressObjectSet []json.RawMessage                               `json:"address_object_set"`
	AddressGroupSet  []json.RawMessage                               `json:"address_group_set"`
	ServiceMap       []json.RawMessage                               `json:"service_map"`
	ServiceGroup     []json.RawMessage                               `json:"service_group"`
	PoolMap          map[firewall.NatType]map[string]json.RawMessage `json:"pool_map"`
}

// MarshalJSON 实现 JSON 序列化
func (uos *UsgObjectSet) MarshalJSON() ([]byte, error) {
	addressObjectSetRaw, err := registry.InterfacesToRawMessages(uos.addressObjectSet)
	if err != nil {
		return nil, fmt.Errorf("error marshaling addressObjectSet: %w", err)
	}

	addressGroupSetRaw, err := registry.InterfacesToRawMessages(uos.addressGroupSet)
	if err != nil {
		return nil, fmt.Errorf("error marshaling addressGroupSet: %w", err)
	}

	serviceMapRaw, err := registry.InterfacesToRawMessages(uos.serviceMap)
	if err != nil {
		return nil, fmt.Errorf("error marshaling serviceMap: %w", err)
	}

	serviceGroupRaw, err := registry.InterfacesToRawMessages(uos.serviceGroup)
	if err != nil {
		return nil, fmt.Errorf("error marshaling serviceGroup: %w", err)
	}

	// poolMapRaw := make(map[firewall.NatType]map[string]json.RawMessage)
	// for natType, natMap := range uos.poolMap {
	// 	poolMapRaw[natType], err = registry.MapToRawMessage(natMap)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("error marshaling poolMap for NatType %v: %w", natType, err)
	// 	}
	// }

	return json.Marshal(usgObjectSetJSON{
		AddressObjectSet: addressObjectSetRaw,
		AddressGroupSet:  addressGroupSetRaw,
		ServiceMap:       serviceMapRaw,
		ServiceGroup:     serviceGroupRaw,
		// PoolMap:          poolMapRaw,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (uos *UsgObjectSet) UnmarshalJSON(data []byte) error {
	var uosj usgObjectSetJSON
	if err := json.Unmarshal(data, &uosj); err != nil {
		return err
	}

	var err error

	uos.addressObjectSet, err = registry.RawMessagesToInterfaces[firewall.FirewallNetworkObject](uosj.AddressObjectSet)
	if err != nil {
		return fmt.Errorf("error unmarshaling addressObjectSet: %w", err)
	}

	uos.addressGroupSet, err = registry.RawMessagesToInterfaces[firewall.FirewallNetworkObject](uosj.AddressGroupSet)
	if err != nil {
		return fmt.Errorf("error unmarshaling addressGroupSet: %w", err)
	}

	uos.serviceMap, err = registry.RawMessagesToInterfaces[firewall.FirewallServiceObject](uosj.ServiceMap)
	if err != nil {
		return fmt.Errorf("error unmarshaling serviceMap: %w", err)
	}

	uos.serviceGroup, err = registry.RawMessagesToInterfaces[firewall.FirewallServiceObject](uosj.ServiceGroup)
	if err != nil {
		return fmt.Errorf("error unmarshaling serviceGroup: %w", err)
	}

	// uos.poolMap = make(map[firewall.NatType]map[string]firewall.FirewallNetworkObject)
	// for natType, rawMap := range uosj.PoolMap {
	// 	uos.poolMap[natType], err = registry.RawMessageToMap[firewall.FirewallNetworkObject](rawMap)
	// 	if err != nil {
	// 		return fmt.Errorf("error unmarshaling poolMap for NatType %v: %w", natType, err)
	// 	}
	// }

	return nil
}

func (rs *UsgService) Name() string {
	return rs.name
}

func (rs *UsgService) Cli() string {
	return rs.cli
}

func (rs *UsgService) Type() firewall.FirewallObjectType {
	return rs.catagory
}

func (rs *UsgService) Service(node firewall.FirewallNode) *service.Service {
	var s *service.Service
	usg := node.(*UsgNode)

	if rs.service != nil {
		s = rs.service.Copy().(*service.Service)
	}
	// s := rs.service.Copy().(*service.Service)

	// serviceMap := usg.objectSet.serviceMap
	for _, ref := range rs.refNames {
		for _, obj := range usg.objectSet.serviceMap {
			if obj.Name() == ref {
				if s == nil {
					s = obj.Service(node).Copy().(*service.Service)
				} else {
					s.Add(obj.Service(node))
				}
				break
			}
		}
		// refObj, ok := serviceMap[ref]
		// if !ok {
		// 	return nil
		// }
		// if s == nil {
		// 	s = refObj.Service(node).Copy().(*service.Service)
		// } else {
		// 	s.Add(refObj.Service(node))
		// }

		// if refObj, ok := serviceMap[ref]; !ok {
		// 	panic(fmt.Sprintf("can not find ref object: %s", ref))
		// } else {
		// 	if s == nil {
		// 		s = refObj.Service(serviceMap).Copy().(*service.Service)
		// 	} else {
		// 		s.Add(refObj.Service(serviceMap))
		// 	}
		// }
	}

	return s
}

type UsgNetwork struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	hasNat   bool
	network  *network.NetworkGroup
	// refs     []firewall.FirewallNetworkObject
	refNames []string
	vrf      string
}

// 实现 TypeInterface 接口
func (un *UsgNetwork) TypeName() string {
	return "UsgNetwork"
}

// usgNetworkJSON 用于序列化和反序列化
type usgNetworkJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	HasNat   bool                        `json:"has_nat"`
	Network  json.RawMessage             `json:"network"`
	RefNames []string                    `json:"ref_names"`
	Vrf      string                      `json:"vrf"`
}

// MarshalJSON 实现 JSON 序列化
func (un *UsgNetwork) MarshalJSON() ([]byte, error) {
	networkRaw, err := json.Marshal(un.network)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	return json.Marshal(usgNetworkJSON{
		Catagory: un.catagory,
		Cli:      un.cli,
		Name:     un.name,
		HasNat:   un.hasNat,
		Network:  networkRaw,
		RefNames: un.refNames,
		Vrf:      un.vrf,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (un *UsgNetwork) UnmarshalJSON(data []byte) error {
	var unj usgNetworkJSON
	if err := json.Unmarshal(data, &unj); err != nil {
		return err
	}

	un.catagory = unj.Catagory
	un.cli = unj.Cli
	un.name = unj.Name
	un.hasNat = unj.HasNat
	un.refNames = unj.RefNames
	un.vrf = unj.Vrf

	un.network = &network.NetworkGroup{}
	if err := json.Unmarshal(unj.Network, un.network); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}

	// Note: We're not unmarshaling the 'refs' field here because it's a slice of interfaces.
	// You might need to handle this separately if needed.

	return nil
}

func (sn *UsgNetwork) Name() string {
	return sn.name
}

func (sn *UsgNetwork) Cli() string {
	return sn.cli
}

func (sn *UsgNetwork) Type() firewall.FirewallObjectType {
	return sn.catagory
}

func (sn *UsgNetwork) Network(node firewall.FirewallNode) *network.NetworkGroup {
	var ng *network.NetworkGroup
	if sn.network != nil {
		ng = sn.network.Copy().(*network.NetworkGroup)
	}
	usg := node.(*UsgNode)
	// networkMap := usg.objectSet.addressObjectSet
	for _, ref := range sn.refNames {
		for _, obj := range usg.objectSet.addressObjectSet {
			if obj.Name() == ref {
				if ng == nil {
					ng = obj.Network(node).Copy().(*network.NetworkGroup)
				} else {
					ng.AddGroup(obj.Network(node))
				}
				break
			}
		}

		// if refObj, ok := networkMap[ref]; !ok {
		// 	panic(fmt.Sprintf("can not find ref object: %s", ref))
		// } else {
		// 	if ng == nil {
		// 		ng = refObj.Network(node).Copy().(*network.NetworkGroup)
		// 	} else {
		// 		ng.AddGroup(refObj.Network(node))
		// 	}
		// }

	}

	return ng
}

// func (dos *UsgObjectSet) push(zone, name string, obj *UsgNetwork) {
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

func (dos *UsgObjectSet) parseSectionWithGroup(config string, regex string, groups ...string) ([]string, error) {
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

// func (dos *UsgObjectSet) parseConfig(config string) {
// 	// Usg.parseZoneAddress(config)
// 	dos.parseAddress(config)
// 	dos.parseAddressSet(config)
// 	dos.parseApplication(config)
// 	dos.parseApplicationSet(config)
// 	dos.parsePools(config)

// }

func (adapter *UsgObjectSet) ParseConfig(config string) *parse.ParseResult {
	result := parse.NewParseResult()

	// 解析地址对象
	adapter.parseAddress(config, result)

	// // 解析地址集
	// adapter.parseAddressGroup(config, result)

	// // 解析服务对象
	adapter.parseService(config, result)

	// // 解析服务集
	// adapter.parseServiceGroup(config, result)

	// adapter.parsePools(config, result)

	return result
}

// type NatPool struct {
// 	// direction  PoolDirection
// 	natType    firewall.NatType
// 	cli        string
// 	name       string
// 	objectType firewall.FirewallObjectType
// 	// natType    firewall.NatType
// 	network *network.NetworkGroup
// 	port    *service.L4Port
// }

// // Cli() string
// // Name() string
// // Network(map[string]FirewallNetworkObject) *network.NetworkGroup
// // Type() FirewallObjectType
// func (pool *NatPool) Cli() string {
// 	return pool.cli
// }

// func (pool *NatPool) Name() string {
// 	return pool.name
// }

// func (pool *NatPool) Type() firewall.FirewallObjectType {
// 	return pool.objectType
// }

// func (pool *NatPool) NatType() firewall.NatType {
// 	return pool.natType
// }

// func (pool *NatPool) Network(_ map[string]firewall.FirewallNetworkObject) *network.NetworkGroup {
// 	return pool.network
// }

// func (pool *NatPool) L4Port() *service.L4Port {
// 	return pool.port
// }

// func (pool *NatPool) parsePool(config string) {
// 	poolRegexMap := map[string]string{
// 		"regex": `
// 			set\ssecurity\snat\s(?P<direct>\S+)\spool\s(?P<name>\S+)\s
// 			(
// 				(
// 					address\s(?P<address>\d+\.\d+\.\d+\.\d+)(/(?P<addr_prefix>\d+))?\s*
// 					(to\s(?P<address2>\d+\.\d+\.\d+\.\d+)(/(?P<addr2_prefix>\d+))?)?
// 				) |
// 				(port\srange\sto\s(?P<port_to>\d+)) |
// 				(port\srange\s(?P<port_from>\d+))
// 			)
// 		`,
// 		"name":  "pool",
// 		"flags": "mx",
// 		"pcre":  "true",
// 	}

// 	// for _, section := range sections {
// 	poolResult, err := text.SplitterProcessOneTime(poolRegexMap, config)
// 	if err != nil {
// 		panic(err)
// 	}

// 	poolMap, err := poolResult.Projection([]string{}, ",", [][]string{})
// 	if err != nil {
// 		panic(err)
// 	}

// 	if poolMap["direct"] == "source" {
// 		pool.natType = firewall.DYNAMIC_NAT
// 	} else if poolMap["direct"] == "destination" {
// 		pool.natType = firewall.DESTINATION_NAT
// 	} else {
// 		panic(fmt.Sprint("unkonw error: ", poolMap))
// 	}

// 	pool.name = poolMap["name"]
// 	pool.cli = config
// 	pool.objectType = firewall.OBJECT_POOL

// 	// poolMap["address"] + "/" + poolMap["addr_prefix"]
// 	var ng *network.NetworkGroup
// 	if poolMap["address2"] != "" {
// 		ng, err = network.NewNetworkGroupFromString(poolMap["address"] + "-" + poolMap["address2"])
// 	} else {
// 		ng, err = network.NewNetworkGroupFromString(poolMap["address"])
// 	}
// 	if err != nil {
// 		panic(err)
// 	}

// 	pool.network = ng

// 	var l4port *service.L4Port
// 	if poolMap["port_to"] != "" {
// 		l4port, err = service.NewL4PortFromString(poolMap["port_from"]+"-"+poolMap["port_to"], 0)
// 	} else if poolMap["port_from"] != "" {
// 		l4port, err = service.NewL4PortFromString(poolMap["port_from"], 0)
// 	}

// 	pool.port = l4port
// }

// func (dos *UsgObjectSet) parsePools(config string, result *parse.ParseResult) {
// 	poolRegexMap := map[string]string{
// 		"regex": `address-pool\s+(?P<name>\S+)\s+address\s+(?P<start>\S+)(\s+to\s+(?P<end>\S+))?`,
// 		"name":  "pool",
// 		"flags": "m",
// 		"pcre":  "true",
// 	}

// 	poolResult, err := text.SplitterProcessOneTime(poolRegexMap, config)
// 	if err != nil {
// 		result.AddError(errors.NewError(
// 			errors.ParseError,
// 			"Failed to parse address pools",
// 			errors.SeverityError,
// 			"Address Pools",
// 			0,
// 			config,
// 			map[string]interface{}{"error": err.Error()},
// 		))
// 		return
// 	}

// 	for it := poolResult.Iterator(); it.HasNext(); {
// 		_, _, poolMap := it.Next()
// 		pool := &NatPool{
// 			natType:    firewall.DYNAMIC_NAT, // Assuming DYNAMIC_NAT for all pools
// 			cli:        fmt.Sprintf("address-pool %s address %s", poolMap["name"], poolMap["start"]),
// 			name:       poolMap["name"],
// 			objectType: firewall.OBJECT_POOL,
// 		}

// 		var ng *network.NetworkGroup
// 		var err error
// 		if poolMap["end"] != "" {
// 			ng, err = network.NewNetworkGroupFromString(poolMap["start"] + "-" + poolMap["end"])
// 			pool.cli += " to " + poolMap["end"]
// 		} else {
// 			ng, err = network.NewNetworkGroupFromString(poolMap["start"])
// 		}

// 		if err != nil {
// 			result.AddError(errors.NewError(
// 				errors.ExecutionError,
// 				"Failed to create network group for address pool",
// 				errors.SeverityError,
// 				"Address Pools",
// 				0,
// 				pool.cli,
// 				map[string]interface{}{"error": err.Error()},
// 			))
// 			continue
// 		}

// 		pool.network = ng

// 		if _, ok := dos.poolMap[pool.NatType()]; !ok {
// 			dos.poolMap[pool.NatType()] = make(map[string]firewall.FirewallNetworkObject)
// 		}
// 		dos.poolMap[pool.NatType()][pool.Name()] = pool
// 	}
// }

func (dos *UsgObjectSet) parseServiceGroup(config string, result *parse.ParseResult) {
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

			var group *UsgService
			for _, existingGroup := range dos.serviceGroup {
				if existingGroup.Name() == groupName {
					group = existingGroup.(*UsgService)
					break
				}
			}

			if group == nil {
				group = &UsgService{
					catagory: firewall.GROUP_SERVICE,
					name:     groupName,
					cli:      "",
					refNames: []string{},
				}
				dos.serviceGroup = append(dos.serviceGroup, group)
			}

			if serviceName != "" {
				for _, svc := range dos.serviceMap {
					if svc.Name() == serviceName {
						group.refNames = append(group.refNames, serviceName)
						break
					}
				}
			}

			if builtin != "" {
				srv, ok := UsgBuiltinService(builtin)
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
				builtinService := &UsgService{
					catagory: firewall.OBJECT_SERVICE,
					name:     builtin,
					cli:      "",
					refNames: []string{},
					service:  srv,
				}
				dos.serviceMap = append(dos.serviceMap, builtinService)
			}

			if group.cli == "" {
				group.cli = serviceGroupMap["cli"]
			} else {
				group.cli += "\n" + serviceGroupMap["cli"]
			}

			// 更新 group 的 service
			if group.service == nil {
				group.service = &service.Service{}
			}
			for _, refName := range group.refNames {
				for _, svc := range dos.serviceMap {
					if svc.Name() == refName {
						group.service.Add(svc.Service(dos.node))
						break
					}
				}
			}
		}
	}

	// for _, cli := range clis {
	// 	serviceGroupResult, err := text.SplitterProcessOneTime(serviceGroupRegexMap, cli)
	// 	if err != nil {
	// 		result.AddError(errors.NewError(
	// 			errors.ParseError,
	// 			"Failed to parse service group",
	// 			errors.SeverityWarning,
	// 			"Service Groups",
	// 			0,
	// 			cli,
	// 			map[string]interface{}{"error": err.Error()},
	// 		))
	// 		continue
	// 	}

	// 	for it := serviceGroupResult.Iterator(); it.HasNext(); {
	// 		_, _, serviceGroupMap := it.Next()
	// 		groupName := serviceGroupMap["name"]
	// 		serviceName := serviceGroupMap["service"]
	// 		builtin := serviceGroupMap["builtin_service"]

	// 		if _, ok := dos.serviceGroup[groupName]; !ok {
	// 			dos.serviceGroup[groupName] = &UsgService{
	// 				catagory: firewall.GROUP_SERVICE,
	// 				name:     groupName,
	// 				cli:      "",
	// 				refNames: []string{},
	// 			}
	// 		}

	// 		var obj *UsgService
	// 		group := dos.serviceGroup[groupName].(*UsgService)
	// 		if serviceName != "" {
	// 			obj = dos.serviceMap[serviceName].(*UsgService)
	// 			group.refNames = append(group.refNames, serviceName)
	// 		}

	// 		if builtin != "" {
	// 			srv, ok := UsgBuiltinService(builtin)
	// 			if !ok {
	// 				result.AddError(errors.NewError(
	// 					errors.ParseError,
	// 					fmt.Sprintf("Built-in service '%s' not found", builtin),
	// 					errors.SeverityWarning,
	// 					"Service Groups",
	// 					0,
	// 					serviceGroupMap["cli"],
	// 					map[string]interface{}{"builtin_service": builtin},
	// 				))
	// 				continue
	// 			} else {
	// 				group.refNames = append(group.refNames, builtin)
	// 			}
	// 			obj = &UsgService{
	// 				catagory: firewall.OBJECT_SERVICE,
	// 				name:     builtin,
	// 				cli:      "",
	// 				refNames: []string{},
	// 				service:  srv,
	// 			}
	// 		}

	// 		if group.cli == "" {
	// 			group.cli = serviceGroupMap["cli"]
	// 		} else {
	// 			group.cli += "\n" + serviceGroupMap["cli"]
	// 		}
	// 		if group.service == nil {
	// 			group.service = obj.service.Copy().(*service.Service)
	// 		} else {
	// 			group.service.Add(obj.service)
	// 		}
	// 	}
	// }
}

func (dos *UsgObjectSet) parseService(config string, result *parse.ParseResult) {
	// 使用正则表达式匹配 ip service-set 开头到 # 结束的多行文本
	regex := `(?ms)ip service-set\s+\S+(?:(?:.|\n)*?(?:\n#|\z))`

	// 使用正则表达式查找所有匹配的组
	re := regexp.MustCompile(regex)
	matches := re.FindAllString(config, -1)

	if len(matches) == 0 {
		result.AddError(errors.NewError(
			errors.ParseError,
			"No service-set sections found",
			errors.SeverityWarning,
			"Service Objects",
			0,
			config,
			nil,
		))
		return
	}

	// 处理每个匹配的组
	for _, match := range matches {
		// 去除开头和结尾的空白字符
		match = strings.TrimSpace(match)

		// 解析每个服务组
		dos.parseServiceSet(match, result)
	}
}

func (dos *UsgObjectSet) parseServiceSet(serviceSet string, result *parse.ParseResult) {
	// 提取服务组的名称、VRF 和类型
	nameRegex := `ip service-set\s+(?P<name>\S+)(\s+vpn-instance\s+(?P<vrf>\S+))?\s+type\s+(?P<type>\S+)(?:\s+(?P<id>\d+))?`
	matched, err := text.GetFieldByRegex(nameRegex, serviceSet, []string{"name", "vrf", "type", "id"})
	if err != nil {
		result.AddError(errors.NewError(
			errors.ParseError,
			"Failed to extract service-set name, vrf and type",
			errors.SeverityWarning,
			"Service Objects",
			0,
			serviceSet,
			nil,
		))
		return
	}
	name := matched["name"]
	vrf := matched["vrf"]
	typ := matched["type"]

	// 创建新的 UsgService 对象
	obj := &UsgService{
		catagory: firewall.OBJECT_SERVICE,
		cli:      serviceSet,
		name:     name,
		service:  &service.Service{},
		refNames: []string{},
		vrf:      vrf,
	}

	if typ == "group" {
		// 对于 group 类型，解析 service service-set 引用
		// 格式：service service-set <service_name>
		serviceSetRefRegex := `(?m)^\s*service\s+service-set\s+(?P<ref_name>\S+)`
		refMatches := regexp.MustCompile(serviceSetRefRegex).FindAllStringSubmatch(serviceSet, -1)

		for _, refMatch := range refMatches {
			if len(refMatch) < 2 {
				continue
			}
			refName := refMatch[1]
			if refName != "" {
				obj.refNames = append(obj.refNames, refName)
			}
		}
	} else if typ == "object" {
		// 对于 object 类型，解析 service protocol 定义
		// 解析服务组中的每个服务
		serviceRegex := `(?m)^\s*(service\s+(?:\d+\+)?protocol\s+.+)`
		serviceMatches := regexp.MustCompile(serviceRegex).FindAllStringSubmatch(serviceSet, -1)

		for _, serviceMatch := range serviceMatches {
			if len(serviceMatch) < 2 {
				continue
			}
			serviceLine := serviceMatch[1]

			srv, err := parseServiceLine(serviceLine)
			if err != nil {
				result.AddError(errors.NewError(
					errors.ExecutionError,
					"Failed to parse service line",
					errors.SeverityWarning,
					"Service Objects",
					0,
					serviceLine,
					map[string]interface{}{"error": err.Error()},
				))
				continue
			}
			obj.service.Add(srv)
		}
	}

	// 检查是否已存在同名对象，如果存在则更新，否则添加新对象
	if typ == "object" {
		// 查找已存在的服务对象
		found := false
		for _, existingObj := range dos.serviceMap {
			if existingObj.Name() == name {
				// 更新已存在的对象：合并服务
				existingUsgObj := existingObj.(*UsgService)
				if existingUsgObj.service != nil && obj.service != nil {
					existingUsgObj.service.Add(obj.service)
				}
				// 合并引用名称
				existingUsgObj.refNames = append(existingUsgObj.refNames, obj.refNames...)
				// 更新CLI（追加）
				if existingUsgObj.cli != "" && obj.cli != "" {
					existingUsgObj.cli += "\n" + obj.cli
				}
				found = true
				break
			}
		}
		if !found {
			dos.serviceMap = append(dos.serviceMap, obj)
		}
	} else if typ == "group" {
		// 查找已存在的服务组
		found := false
		for _, existingObj := range dos.serviceGroup {
			if existingObj.Name() == name {
				// 更新已存在的对象：合并服务
				existingUsgObj := existingObj.(*UsgService)
				if existingUsgObj.service != nil && obj.service != nil {
					existingUsgObj.service.Add(obj.service)
				}
				// 合并引用名称
				existingUsgObj.refNames = append(existingUsgObj.refNames, obj.refNames...)
				// 更新CLI（追加）
				if existingUsgObj.cli != "" && obj.cli != "" {
					existingUsgObj.cli += "\n" + obj.cli
				}
				found = true
				break
			}
		}
		if !found {
			dos.serviceGroup = append(dos.serviceGroup, obj)
		}
	} else {
		result.AddError(errors.NewError(
			errors.ParseError,
			"Unknown service-set type",
			errors.SeverityWarning,
			"Service Objects",
			0,
			serviceSet,
			map[string]interface{}{"type": typ},
		))
	}
}

func parseServiceLine(line string) (*service.Service, error) {
	regexMap := map[string]string{
		"regex": `
        service\s+((?P<id>\d+)\s+)?
        protocol\s+
        (
            (?P<icmp>(1|icmp)(\s+icmp-type\s+(?P<icmp_type>\d+|\S+)(\s+(?P<icmp_code>\d+))?)?) |
            (?P<icmp6>58|icmpv6) (\s+icmp6-type\s+(?P<icmp6_type>\d+|\S+))? |
            ((?P<l3_proto>(6|tcp) | (17|udp) | (132|stcp))
                ((\s+source-port(?P<src_ports>(\s+(\d+|to))+))?
                 (\s+destination-port(?P<dst_ports>(\s+(\d+|to))+))?
            )) |
            (?P<protocol_num>\d+) 
        )
        `,
		"name":  "service",
		"pcre":  "true",
		"flags": "mx",
	}

	result, err := text.SplitterProcessOneTime(regexMap, line)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service line: %v", err)
	}

	match, ok := result.One()
	if !ok {
		return nil, fmt.Errorf("no match found for service line")
	}

	// 使用新的独立方法解析服务协议
	srv, err := parseServiceProtocol(match)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("Parsed service: %+v\n", srv.String())
	return srv, nil
}

func parsePolicyServiceLine(line string, objects *UsgObjectSet) (*service.Service, error) {
	regexMap := map[string]string{
		"regex": `
        service\s+
		(
			(?P<srv_name>\S+)$ |
			(protocol\s+
				(
					(?P<icmp>(1|icmp)(\s+icmp-type\s+(?P<icmp_type>\d+|\S+)(\s+(?P<icmp_code>\d+))?)?) |
					(?P<icmp6>58|icmpv6) (\s+icmp6-type\s+(?P<icmp6_type>\d+|\S+))? |
					((?P<l3_proto>(6|tcp) | (17|udp) | (132|stcp))
						((\s+source-port(?P<src_ports>(\s+(\d+|to))+))?
						(\s+destination-port(?P<dst_ports>(\s+(\d+|to))+))?
					)) |
					(?P<protocol_num>\d+) 
				)
			)$
		)
        `,
		"name":  "service",
		"pcre":  "true",
		"flags": "mx",
	}

	result, err := text.SplitterProcessOneTime(regexMap, strings.TrimSpace(line))
	if err != nil {
		return nil, fmt.Errorf("failed to parse service line: %v", err)
	}

	match, ok := result.One()
	if !ok {
		return nil, fmt.Errorf("no match found for service line")
	}

	if match["srv_name"] != "" {
		name := match["srv_name"]
		_, srv, ok := objects.Service(name)
		if !ok {
			return nil, fmt.Errorf("service not found: %s", name)
		}
		// fmt.Printf("Parsed service: %+v\n", srv.String())
		return srv, nil
	}

	// 使用新的独立方法解析服务协议
	srv, err := parseServiceProtocol(match)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("Parsed service: %+v\n", srv.String())
	return srv, nil
}

// func parseServiceLine(line string) (*service.Service, error) {
// 	regexMap := map[string]string{
// 		"regex": `
//         service\s+(?P<id>\d+)\s+
//         protocol\s+
//         (
//             (?<icmp>(1|icmp)(\s+icmp-type\s+(?P<icmp_type>\d+|\S+))?) |
//             (?P<icmp6>58|icmpv6) (\s+icmp6-type\s+(?P<icmp6_type>\d+|\S+))? |
//             ((?P<l3_proto>(6|tcp) | (17|udp) | (132|stcp))
//                 ((\s+source-port(?P<src_ports>(\s+(\d+|to))+))?
//                  (\s+destination-port(?P<dst_ports>(\s+(\d+|to))+))?
//             )) |
//             (?P<protocol_num>\d+)
//         )
//         `,
// 		"name":  "service",
// 		"pcre":  "true",
// 		"flags": "mx",
// 	}

// 	result, err := text.SplitterProcessOneTime(regexMap, line)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse service line: %v", err)
// 	}

// 	match, ok := result.One()
// 	if !ok {
// 		return nil, fmt.Errorf("no match found for service line")
// 	}

// 	srv := &service.Service{}

// 	// 处理 ICMP
// 	if match["icmp_type"] != "" {
// 		icmpType, err := parseICMPType(match["icmp_type"])
// 		if err != nil {
// 			return nil, err
// 		}
// 		icmp, err := service.NewICMPProto(service.ICMP, icmpType, service.ICMP_DEFAULT_CODE)
// 		if err != nil {
// 			return nil, err
// 		}
// 		srv.Add(icmp)
// 	} else if match["icmp6_type"] != "" {
// 		icmp6Type, err := parseICMPType(match["icmp6_type"])
// 		if err != nil {
// 			return nil, err
// 		}
// 		icmp6, err := service.NewICMPProto(service.ICMP6, icmp6Type, service.ICMP_DEFAULT_CODE)
// 		if err != nil {
// 			return nil, err
// 		}
// 		srv.Add(icmp6)
// 	} else if match["protocol_num"] != "" {
// 		// 处理其他协议
// 		protocolNum, err := strconv.Atoi(match["protocol_num"])
// 		if err != nil {
// 			return nil, fmt.Errorf("invalid protocol number: %s", match["protocol_num"])
// 		}
// 		proto, err := service.NewL3Protocol(service.IPProto(protocolNum))
// 		if err != nil {
// 			return nil, err
// 		}
// 		srv.Add(proto)
// 	} else if match["l3_proto"] != "" {
// 		// 处理 TCP, UDP, STCP
// 		// protocol := getProtocol(match["l3_proto"])
// 		protocol := service.NewIPProtoFromString(match["l3_proto"])

// 		srcPorts, err := parsePorts(match["src_ports"])
// 		if err != nil {
// 			return nil, fmt.Errorf("error parsing source ports: %v", err)
// 		}

// 		dstPorts, err := parsePorts(match["dst_ports"])
// 		if err != nil {
// 			return nil, fmt.Errorf("error parsing destination ports: %v", err)
// 		}

// 		l4srv, err := service.NewL4Service(protocol, srcPorts, dstPorts)
// 		if err != nil {
// 			return nil, err
// 		}
// 		srv.Add(l4srv)
// 	}

// 	fmt.Println("Parsed service: %+v", srv.String())
// 	return srv, nil
// }

// parseServiceProtocol 解析服务协议配置，支持ICMP、ICMPv6、TCP、UDP、SCTP等协议
func parseServiceProtocol(match map[string]string) (*service.Service, error) {
	srv := &service.Service{}

	// 处理 ICMP
	// 检查 icmp 组是否匹配（protocol icmp 或 protocol 1）
	if match["icmp"] != "" {
		// 如果指定了 icmp-type，使用指定的类型和代码
		if match["icmp_type"] != "" {
			icmpType, err := parseICMPType(match["icmp_type"])
			if err != nil {
				return nil, err
			}
			icmp_code := service.ICMP_DEFAULT_CODE
			if match["icmp_code"] != "" {
				icmp_code, err = strconv.Atoi(match["icmp_code"])
				if err != nil {
					return nil, fmt.Errorf("invalid ICMP code: %s", match["icmp_code"])
				}
			}
			icmp, err := service.NewICMPProto(service.ICMP, icmpType, icmp_code)
			if err != nil {
				return nil, err
			}
			srv.Add(icmp)
		} else {
			// 没有指定 icmp-type，使用默认的 ICMP 服务（所有 ICMP 类型）
			icmp, err := service.NewServiceFromString("icmp")
			if err != nil {
				return nil, err
			}
			srv.Add(icmp)
		}
	} else if match["icmp6"] != "" {
		// 处理 ICMPv6
		// 如果指定了 icmp6-type，使用指定的类型
		if match["icmp6_type"] != "" {
			icmp6Type, err := parseICMPType(match["icmp6_type"])
			if err != nil {
				return nil, err
			}
			icmp6, err := service.NewICMPProto(service.ICMP6, icmp6Type, service.ICMP_DEFAULT_CODE)
			if err != nil {
				return nil, err
			}
			srv.Add(icmp6)
		} else {
			// 没有指定 icmp6-type，使用默认的 ICMPv6 服务（所有 ICMPv6 类型）
			icmp6, err := service.NewServiceWithProto("icmpv6")
			if err != nil {
				return nil, err
			}
			srv.Add(icmp6)
		}
	} else if match["icmp_type"] != "" {
		// 兼容旧的正则表达式匹配（直接匹配 icmp_type，没有 icmp 组）
		icmpType, err := parseICMPType(match["icmp_type"])
		if err != nil {
			return nil, err
		}
		icmp_code := service.ICMP_DEFAULT_CODE
		if match["icmp_code"] != "" {
			icmp_code, err = strconv.Atoi(match["icmp_code"])
			if err != nil {
				return nil, fmt.Errorf("invalid ICMP code: %s", match["icmp_code"])
			}
		}
		icmp, err := service.NewICMPProto(service.ICMP, icmpType, icmp_code)
		if err != nil {
			return nil, err
		}
		srv.Add(icmp)
	} else if match["icmp6_type"] != "" {
		icmp6Type, err := parseICMPType(match["icmp6_type"])
		if err != nil {
			return nil, err
		}
		icmp6, err := service.NewICMPProto(service.ICMP6, icmp6Type, service.ICMP_DEFAULT_CODE)
		if err != nil {
			return nil, err
		}
		srv.Add(icmp6)
	} else if match["protocol_num"] != "" {
		// 处理其他协议
		protocolNum, err := strconv.Atoi(match["protocol_num"])
		if err != nil {
			return nil, fmt.Errorf("invalid protocol number: %s", match["protocol_num"])
		}
		proto, err := service.NewL3Protocol(service.IPProto(protocolNum))
		if err != nil {
			return nil, err
		}
		srv.Add(proto)
	} else if match["l3_proto"] != "" {
		// 处理 TCP, UDP, STCP
		protocol := service.NewIPProtoFromString(match["l3_proto"])

		srcPorts, err := parsePorts(match["src_ports"])
		if err != nil {
			return nil, fmt.Errorf("error parsing source ports: %v", err)
		}

		dstPorts, err := parsePorts(match["dst_ports"])
		if err != nil {
			return nil, fmt.Errorf("error parsing destination ports: %v", err)
		}

		if match["src_ports"] == "" && match["dst_ports"] == "" {
			s, err := service.NewServiceFromString(match["l3_proto"])
			if err != nil {
				return nil, err
			}
			srv.Add(s)
		} else {
			l4srv, err := service.NewL4Service(protocol, srcPorts, dstPorts)
			if err != nil {
				return nil, err
			}
			srv.Add(l4srv)
		}

	}

	return srv, nil
}

func parsePorts(portsStr string) (*service.L4Port, error) {
	if portsStr == "" {
		return nil, nil
	}

	ports := strings.Fields(portsStr)
	var ranges [][]int

	for i := 0; i < len(ports); i++ {
		if ports[i] == "to" {
			continue
		}
		start, err := strconv.Atoi(ports[i])
		if err != nil {
			return nil, fmt.Errorf("invalid port number: %s", ports[i])
		}
		if i+2 < len(ports) && ports[i+1] == "to" {
			end, err := strconv.Atoi(ports[i+2])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", ports[i+2])
			}
			ranges = append(ranges, []int{start, end})
			i += 2
		} else {
			ranges = append(ranges, []int{start, start})
		}
	}

	var l4port *service.L4Port
	for _, r := range ranges {
		port, err := service.NewL4Port(service.RANGE, r[0], r[1], 0)
		if err != nil {
			return nil, fmt.Errorf("error creating L4Port: %v", err)
		}
		if l4port == nil {
			l4port = port
		} else {
			l4port.Add(port)
		}
	}

	return l4port, nil
}

func getrPotocol(match map[string]string) service.IPProto {
	if strings.Contains(match["0"], "6") || strings.Contains(match["0"], "tcp") {
		return service.TCP
	} else if strings.Contains(match["0"], "17") || strings.Contains(match["0"], "udp") {
		return service.UDP
	} else if strings.Contains(match["0"], "132") || strings.Contains(match["0"], "stcp") {
		return service.SCTP
	}
	return service.IP // 默认返回 IP
}

func parseICMPType(typeStr string) (int, error) {
	if typeStr == "" {
		return service.ICMP_DEFAULT_TYPE, nil
	}

	// 尝试将typeStr转换为整数
	icmpType, err := strconv.Atoi(typeStr)
	if err == nil {
		// 如果成功转换为整数，直接返回
		return icmpType, nil
	}

	// 如果不是数字，查找预定义的ICMP类型名称
	typeCode, ok := Usg_ICMP_Types[strings.ToLower(typeStr)]
	if !ok {
		return 0, fmt.Errorf("unsupported ICMP type name: %s", typeStr)
	}

	// 从typeCode中提取ICMP类型（第一个数字）
	parts := strings.Split(typeCode, ",")
	if len(parts) < 1 {
		return 0, fmt.Errorf("invalid ICMP type definition for: %s", typeStr)
	}

	return strconv.Atoi(parts[0])
}

func parseServiceInfo(info string) (*service.Service, error) {
	fields := strings.Fields(info)
	if len(fields) < 4 {
		return nil, fmt.Errorf("invalid service info format")
	}

	protocol := fields[1]
	srv := &service.Service{}

	srcPorts := []string{}
	dstPorts := []string{}
	isSource := true

	for i := 2; i < len(fields); i++ {
		if fields[i] == "source-port" {
			isSource = true
			continue
		}
		if fields[i] == "destination-port" {
			isSource = false
			continue
		}
		if fields[i] == "to" {
			continue
		}

		if isSource {
			srcPorts = append(srcPorts, fields[i])
		} else {
			dstPorts = append(dstPorts, fields[i])
		}
	}

	// 处理源端口
	if len(srcPorts) > 0 {
		srcL4, err := parsePortRange(srcPorts)
		if err != nil {
			return nil, fmt.Errorf("error parsing source ports: %v", err)
		}
		s, err := service.NewL4Service(service.NewIPProtoFromString(protocol), srcL4, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating L4Service: %v", err)
		}
		srv.Add(s)
	}

	// 处理目标端口
	if len(dstPorts) > 0 {
		dstL4, err := parsePortRange(dstPorts)
		if err != nil {
			return nil, fmt.Errorf("error parsing destination ports: %v", err)
		}
		s, err := service.NewL4Service(service.NewIPProtoFromString(protocol), nil, dstL4)
		if err != nil {
			return nil, fmt.Errorf("error creating L4Service: %v", err)
		}
		srv.Add(s)
	}

	return srv, nil
}

func parsePortRange(ports []string) (*service.L4Port, error) {
	var ranges [][]int
	for i := 0; i < len(ports); i++ {
		start, err := strconv.Atoi(ports[i])
		if err != nil {
			return nil, fmt.Errorf("invalid port number: %s", ports[i])
		}
		if i+2 < len(ports) && ports[i+1] == "to" {
			end, err := strconv.Atoi(ports[i+2])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", ports[i+2])
			}
			ranges = append(ranges, []int{start, end})
			i += 2
		} else {
			ranges = append(ranges, []int{start, start})
		}
	}
	var l4port *service.L4Port
	for _, r := range ranges {
		l4, err := service.NewL4Port(service.RANGE, r[0], r[1], 0)
		if err != nil {
			return nil, fmt.Errorf("error creating L4Port: %v", err)
		}
		if l4port == nil {
			l4port = l4
		} else {
			l4port.Add(l4)
		}
	}

	return l4port, nil
}

func (dos *UsgObjectSet) parseAttachZone(config string) map[string]string {
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

// func (dos *UsgObjectSet) parseAddressGroup(config string, result *parse.ParseResult) {
// 	regex := `(?P<all>address-group (?P<name>\S+) [^\n]+)`
// 	clis, err := dos.parseSectionWithGroup(config, regex, "name")
// 	if err != nil {
// 		result.AddError(errors.NewError(
// 			errors.ParseError,
// 			"Failed to parse address group sections",
// 			errors.SeverityError,
// 			"Address Groups",
// 			0,
// 			config,
// 			map[string]interface{}{"error": err.Error()},
// 		))
// 		return
// 	}

// 	regexMap := map[string]string{
// 		"regex": `
// 			(?P<cli>
// 			address-group\s+(?P<name>\S+)\s+
// 			(
// 				(address-object\s+(?P<obj_name>\S+)) |
// 				(description\s+(?P<description>\S+))

// 			)$
// 			)
// 		`,
// 		"name":  "address",
// 		"flags": "mx",
// 		"pcre":  "true",
// 	}

// 	for _, cli := range clis {
// 		cli = strings.TrimSpace(cli)
// 		addressResult, err := text.SplitterProcessOneTime(regexMap, cli)
// 		if err != nil {
// 			result.AddError(errors.NewError(
// 				errors.ParseError,
// 				"Failed to parse address object",
// 				errors.SeverityWarning,
// 				"Address Objects",
// 				0,
// 				cli,
// 				map[string]interface{}{"error": err.Error()},
// 			))
// 			continue
// 		}

// 		hasMatch := false
// 		for it := addressResult.Iterator(); it.HasNext(); {
// 			hasMatch = true
// 			_, _, addressMap := it.Next()

// 			if _, ok := dos.addressGroupSet[addressMap["name"]]; !ok {
// 				dos.addressGroupSet[addressMap["name"]] = &UsgNetwork{
// 					catagory: firewall.OBJECT_NETWORK,
// 					cli:      cli,
// 					name:     addressMap["name"],
// 					network:  network.NewNetworkGroup(),
// 				}
// 			}
// 			obj := dos.addressGroupSet[addressMap["name"]].(*UsgNetwork)
// 			if addressMap["obj_name"] != "" {
// 				netObj, ok := dos.Network("", addressMap["obj_name"])
// 				if !ok {
// 					result.AddError(errors.NewError(
// 						errors.ParseError,
// 						"Address object not found",
// 						errors.SeverityWarning,
// 						"Address Objects",
// 						0,
// 						cli,
// 						map[string]interface{}{"name": addressMap["obj_name"]},
// 					))
// 					continue
// 				}
// 				obj.network.AddGroup(netObj)
// 				obj.refNames = append(obj.refNames, addressMap["obj_name"])
// 			} else if addressMap["description"] != "" {
// 				// Handle description if needed
// 			} else {
// 				result.AddError(errors.NewError(
// 					errors.ParseError,
// 					"Unknown cli in address object",
// 					errors.SeverityWarning,
// 					"Address Objects",
// 					0,
// 					cli,
// 					map[string]interface{}{"cli": cli},
// 				))
// 				continue
// 			}
// 		}

// 		if !hasMatch {
// 			result.AddError(errors.NewError(
// 				errors.ParseError,
// 				"No match found for address object",
// 				errors.SeverityWarning,
// 				"Address Objects",
// 				0,
// 				cli,
// 				nil,
// 			))
// 		}
// 	}

// }

// func (dos *UsgObjectSet) parseAddress(config string, result *parse.ParseResult) {
// 	regex := `(?P<all>ip address-set (?P<name>\S+) [^\n]+(\s{2,}[^\n]+)*)`

// 	clis := []string{}
// 	sectionMap, err := text.GetFieldByRegex(regex, config, []string{"all"})
// 	if err != nil {
// 		result.AddError(errors.NewError(
// 			errors.ParseError,
// 			"Failed to parse address sections",
// 			errors.SeverityError,
// 			"Address Objects",
// 			0,
// 			config,
// 			map[string]interface{}{"error": err.Error()},
// 		))
// 		return
// 	}
// 	fmt.Println("sectionMap: ", sectionMap)

// 	// clis, err := dos.parseSectionWithGroup(config, regex, "name")
// 	// if err != nil {
// 	// 	result.AddError(errors.NewError(
// 	// 		errors.ParseError,
// 	// 		"Failed to parse address sections",
// 	// 		errors.SeverityError,
// 	// 		"Address Objects",
// 	// 		0,
// 	// 		config,
// 	// 		map[string]interface{}{"error": err.Error()},
// 	// 	))
// 	// 	return
// 	// }

// 	regexMap := map[string]string{
// 		"regex": `
//             (?P<cli>
//                 address-object\s+(?P<name>\S+)\s+
//                 (
//                     (range\s+(?P<start>\S+)\s+(?P<end>\S+)) |
//                     (exclude\s+(?P<exclude>\S+)) |
//                     (wildcard\s+(?P<wildcard>\S+)) |
//                     (?P<address>\S+) |
//                     (description\s+(?P<description>\S+))
//                 )$
//             )
//         `,
// 		"name":  "address",
// 		"flags": "mx",
// 		"pcre":  "true",
// 	}

// 	for _, cli := range clis {
// 		cli = strings.TrimSpace(cli)
// 		addressResult, err := text.SplitterProcessOneTime(regexMap, cli)
// 		if err != nil {
// 			result.AddError(errors.NewError(errors.ParseError, "Failed to parse address object", errors.SeverityWarning, "Address Objects", 0, cli, map[string]interface{}{"error": err.Error()}))
// 			continue
// 		}

// 		addressMap, ok := addressResult.One()
// 		if !ok {
// 			result.AddError(errors.NewError(errors.ParseError, "No match found for address object", errors.SeverityWarning, "Address Objects", 0, cli, nil))
// 			continue
// 		}

// 		obj := &UsgNetwork{
// 			catagory: firewall.OBJECT_NETWORK,
// 			cli:      cli,
// 			name:     addressMap["name"],
// 			network:  network.NewNetworkGroup(),
// 		}

// 		if addressMap["start"] != "" {
// 			net, err := network.NewNetworkFromString(addressMap["start"] + "-" + addressMap["end"])
// 			if err != nil {
// 				result.AddError(errors.NewError(errors.ExecutionError, "Failed to create network from range", errors.SeverityError, "Address Objects", 0, cli, map[string]interface{}{"error": err.Error(), "start": addressMap["start"], "end": addressMap["end"]}))
// 				continue
// 			}
// 			obj.network.Add(net)
// 		} else if addressMap["address"] != "" {
// 			if !isValidIPWithPrefix(addressMap["address"]) {
// 				result.AddError(errors.NewError(errors.ParseError, "Invalid IP address format", errors.SeverityError, "Address Objects", 0, cli, map[string]interface{}{"address": addressMap["address"]}))
// 				continue
// 			}

// 			net, err := network.NewNetworkFromString(addressMap["address"])
// 			if err != nil {
// 				result.AddError(errors.NewError(errors.ExecutionError, "Failed to create network from address", errors.SeverityError, "Address Objects", 0, cli, map[string]interface{}{"error": err.Error(), "address": addressMap["address"]}))
// 				continue
// 			}
// 			obj.network.Add(net)
// 		} else {
// 			result.AddError(errors.NewError(errors.ParseError, "Unknown address type", errors.SeverityWarning, "Address Objects", 0, cli, map[string]interface{}{"cli": cli}))
// 			continue
// 		}

// 		dos.addressObjectSet[addressMap["name"]] = obj
// 	}
// }

func (dos *UsgObjectSet) parseAddress(config string, result *parse.ParseResult) {
	// 使用正则表达式匹配 ip address-set 开头到 # 结束的多行文本
	regex := `(?ms)ip address-set\s+\S+(?:(?:.|\n)*?(?:\n#|\z))`

	// 使用正则表达式查找所有匹配的组
	re := regexp.MustCompile(regex)
	matches := re.FindAllString(config, -1)

	if len(matches) == 0 {
		result.AddError(errors.NewError(
			errors.ParseError,
			"No address-set sections found",
			errors.SeverityWarning,
			"Address Objects",
			0,
			config,
			nil,
		))
		return
	}

	// 处理每个匹配的组
	for _, match := range matches {
		// 去除开头和结尾的空白字符
		match = strings.TrimSpace(match)

		// 解析每个地址组
		dos.parseAddressSet(match, result)
	}
}

func (dos *UsgObjectSet) parseAddressSet(addressSet string, result *parse.ParseResult) {
	// 提取地址组的名称、VRF 和类型
	nameRegex := `ip address-set\s+(?P<name>\S+)(\s+vpn-instance\s+(?P<vrf>\S+))?(\s+type\s+(?P<type>\S+))?`
	matched, err := text.GetFieldByRegex(nameRegex, addressSet, []string{"name", "vrf", "type"})
	if err != nil {
		result.AddError(errors.NewError(
			errors.ParseError,
			"Failed to extract address-set name, vrf and type",
			errors.SeverityWarning,
			"Address Objects",
			0,
			addressSet,
			nil,
		))
		return
	}
	name := matched["name"]
	vrf := matched["vrf"]
	typ := matched["type"]

	// 创建新的 UsgNetwork 对象
	obj := &UsgNetwork{
		catagory: firewall.OBJECT_NETWORK,
		cli:      addressSet,
		name:     name,
		network:  network.NewNetworkGroup(),
		vrf:      tools.ConditionalT(vrf != "", vrf, string(DefaultVrf)),
	}

	// 解析地址组中的每个地址
	addressRegex := `(?m)^\s*address\s+(\d+\s+)?(.+)`
	addressMatches := regexp.MustCompile(addressRegex).FindAllStringSubmatch(addressSet, -1)

	for _, addrMatch := range addressMatches {
		if len(addrMatch) < 3 {
			continue
		}
		addressID := strings.TrimSpace(addrMatch[1])
		addressInfo := addrMatch[2]

		if strings.HasPrefix(addressInfo, "range") {
			// 处理地址范围
			rangeRegex := `range\s+(\S+)\s+(\S+)`
			rangeMatch := regexp.MustCompile(rangeRegex).FindStringSubmatch(addressInfo)
			if len(rangeMatch) == 3 {
				start, end := rangeMatch[1], rangeMatch[2]
				net, err := network.NewNetworkFromString(start + "-" + end)
				if err != nil {
					result.AddError(errors.NewError(
						errors.ExecutionError,
						"Failed to create network from range",
						errors.SeverityWarning,
						"Address Objects",
						0,
						addressInfo,
						map[string]interface{}{"error": err.Error(), "start": start, "end": end, "id": addressID},
					))
					continue
				}
				obj.network.Add(net)
			}
		} else if strings.HasPrefix(addressInfo, "address-set") {
			// 处理 address address-set xxxx 形式
			addressSetName := strings.TrimSpace(strings.TrimPrefix(addressInfo, "address-set"))
			var refObj firewall.FirewallNetworkObject
			var found bool

			for _, addrObj := range dos.addressObjectSet {
				if addrObj.Name() == addressSetName {
					refObj = addrObj
					found = true
					break
				}
			}

			if found {
				obj.network.AddGroup(refObj.Network(dos.node))
				obj.refNames = append(obj.refNames, addressSetName)
			} else {
				result.AddError(errors.NewError(
					errors.ParseError,
					"Referenced address-set not found",
					errors.SeverityWarning,
					"Address Objects",
					0,
					addressInfo,
					map[string]interface{}{"addressSet": addressSetName, "id": addressID},
				))
			}

		} else {
			// 处理单个 IP 地址（IPv4 或 IPv6）
			parts := strings.Fields(addressInfo)
			if len(parts) >= 1 {
				address := parts[0]
				var netStr string

				if strings.Contains(address, ":") {
					// IPv6 地址
					if len(parts) >= 2 && parts[1] == "mask" {
						netStr = address + "/" + parts[2]
					} else {
						netStr = address + "/128" // 默认单个 IPv6 地址
					}
				} else {
					// IPv4 地址
					if len(parts) >= 2 {
						if parts[1] == "0" {
							netStr = address + "/32" // 单个主机
						} else if parts[1] == "mask" {
							netStr = address + "/" + parts[2]
						} else {
							// 使用通配符掩码
							wildcard := parts[1]
							mask := wildcardToMask(wildcard)
							if mask == "" {
								result.AddError(errors.NewError(
									errors.ParseError,
									"Invalid wildcard mask",
									errors.SeverityWarning,
									"Address Objects",
									0,
									addressInfo,
									map[string]interface{}{"wildcard": wildcard, "id": addressID},
								))
								continue
							}
							netStr = address + "/" + mask
						}
					} else {
						netStr = address + "/32" // 默认单个 IPv4 地址
					}
				}

				net, err := network.NewNetworkFromString(netStr)
				if err != nil {
					result.AddError(errors.NewError(
						errors.ExecutionError,
						"Failed to create network from address",
						errors.SeverityWarning,
						"Address Objects",
						0,
						addressInfo,
						map[string]interface{}{"error": err.Error(), "address": netStr, "id": addressID},
					))
					continue
				}
				obj.network.Add(net)
			}
		}
	}

	// 根据类型将解析后的对象添加到相应的集合中
	// 检查是否已存在同名对象，如果存在则更新，否则添加新对象
	if typ == "group" {
		// 查找已存在的地址组
		found := false
		for _, existingObj := range dos.addressGroupSet {
			if existingObj.Name() == name {
				// 更新已存在的对象：合并网络
				existingUsgObj := existingObj.(*UsgNetwork)
				if existingUsgObj.network != nil && obj.network != nil {
					existingUsgObj.network.AddGroup(obj.network)
				}
				// 更新CLI（追加）
				if existingUsgObj.cli != "" && obj.cli != "" {
					existingUsgObj.cli += "\n" + obj.cli
				}
				found = true
				break
			}
		}
		if !found {
			dos.addressGroupSet = append(dos.addressGroupSet, obj)
		}
	} else {
		// 查找已存在的地址对象
		found := false
		for _, existingObj := range dos.addressObjectSet {
			if existingObj.Name() == name {
				// 更新已存在的对象：合并网络
				existingUsgObj := existingObj.(*UsgNetwork)
				if existingUsgObj.network != nil && obj.network != nil {
					existingUsgObj.network.AddGroup(obj.network)
				}
				// 更新CLI（追加）
				if existingUsgObj.cli != "" && obj.cli != "" {
					existingUsgObj.cli += "\n" + obj.cli
				}
				found = true
				break
			}
		}
		if !found {
			dos.addressObjectSet = append(dos.addressObjectSet, obj)
		}
	}
}

// 辅助函数：将通配符掩码转换为 CIDR 掩码
func wildcardToMask(wildcard string) string {
	parts := strings.Split(wildcard, ".")
	if len(parts) != 4 {
		return ""
	}
	var maskBits int
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return ""
		}
		maskBits += bits.OnesCount8(uint8(^num))
	}
	return strconv.Itoa(maskBits)
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

// func (Usg *UsgObjectSet) parseZoneAddress(config string) string {
// regex := `(?P<all>set security address-book global address [^\n]*)`
// sections := Usg.parseSection(config, regex, "all")
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
// obj := &UsgNetwork{
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
// func (Usg *UsgObjectSet) parseSection(config, regex, name string) string {
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
// func (Usg *UsgObjectSet) parseZoneAddress(config string) {
// sectionRgexMap := map[string]string{
// "regex": `set security zones security-zone \S+ address-book address [^\n]*`,
// "name":  "section",
// "flags": "m",
// "pcre":  "true",
// }
// }

//
// func (Usg *UsgObjectSet) parseObjectSecion(config string) []string {
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
// Usg.prepare(sectionMap["all"])
// }
//
// return sections
// }

func (dos *UsgObjectSet) Network(_, name string) (string, *network.NetworkGroup, bool) {
	// 处理特殊的网络组
	switch name {
	case "any":
		return "any", network.NewAny46Group(), true
	}

	// 首先检查 addressObjectSet
	for _, obj := range dos.addressObjectSet {
		if obj.Name() == name {
			return obj.Cli(), obj.Network(dos.node), true
		}
	}

	// 然后检查 addressGroupSet
	for _, obj := range dos.addressGroupSet {
		if obj.Name() == name {
			return obj.Cli(), obj.Network(dos.node), true
		}
	}

	// 如果在两个集合中都没有找到，则返回 nil 和 false
	log.Printf("Warning: Network object '%s' not found", name)
	return "", nil, false
}

// func (dos *UsgObjectSet) Service(name string) (*service.Service, bool) {
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
func (dos *UsgObjectSet) Service(name string) (string, *service.Service, bool) {
	// Handle "any" service
	if strings.ToLower(name) == "any" {
		ip, _ := service.NewServiceFromString("ip")
		return "any", ip, true
	}
	// Check in serviceMap
	for _, obj := range dos.serviceMap {
		if obj.Name() == name {
			return obj.Cli(), obj.Service(dos.node), true
		}
	}

	// Check in serviceGroup
	for _, obj := range dos.serviceGroup {
		if obj.Name() == name {
			return obj.Cli(), obj.Service(dos.node), true
		}
	}

	// Check for built-in services
	if builtinService, ok := UsgBuiltinService(name); ok {
		return name, builtinService, true
	}

	// Service not found
	return "", nil, false
}

func (dos *UsgObjectSet) Pool(name string, objectType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	// if _, ok := dos.poolMap[objectType]; ok {
	// 	return dos.poolMap[objectType][name], true
	// }
	if _, ok := dos.node.nats.addressGroups[name]; ok {
		return dos.node.nats.addressGroups[name], true
	}

	return nil, false
}

func (dos *UsgObjectSet) L4Port(name string) (*service.L4Port, bool) {
	return nil, false
}

func (dos *UsgObjectSet) GetPoolByeNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	// // poolMap    map[firewall.NatType]map[string]firewall.FirewallNetworkObject
	// if _, ok := dos.poolMap[natType]; !ok {
	// 	return nil, false
	// } else {
	// 	poolMap := dos.poolMap[natType]
	// 	for _, obj := range poolMap {
	// 		net := obj.Network(nil)
	// 		if net.Same(ng) {
	// 			return obj, true
	// 		}
	// 	}
	// }

	for _, pool := range dos.node.nats.addressGroups {
		if pool.N != nil && pool.N.Same(ng) {
			return pool, true
		}
	}

	return nil, false
}

func (dos *UsgObjectSet) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	// 检查 addressObjectSet
	for _, obj := range dos.addressObjectSet {
		objNet := obj.Network(dos.node)
		if objNet != nil && objNet.Same(ng) {
			switch searchType {
			case firewall.SEARCH_OBJECT:
				if obj.Type() == firewall.OBJECT_NETWORK {
					return obj, true
				}
			case firewall.SEARCH_GROUP:
				// 跳过，因为这是对象，不是组
			case firewall.SEARCH_OBJECT_OR_GROUP:
				if obj.Type() == firewall.OBJECT_NETWORK {
					return obj, true
				}
			}
		}
	}

	// 检查 addressGroupSet
	for _, obj := range dos.addressGroupSet {
		objNet := obj.Network(dos.node)
		if objNet != nil && objNet.Same(ng) {
			switch searchType {
			case firewall.SEARCH_OBJECT:
				// 跳过，因为这是组，不是对象
			case firewall.SEARCH_GROUP:
				if obj.Type() == firewall.GROUP_NETWORK {
					return obj, true
				}
			case firewall.SEARCH_OBJECT_OR_GROUP:
				if obj.Type() == firewall.GROUP_NETWORK {
					return obj, true
				}
			}
		}
	}

	return nil, false
}

func (dos *UsgObjectSet) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	// 检查 serviceMap
	for _, obj := range dos.serviceMap {
		srv := obj.Service(dos.node)
		if srv != nil && srv.Same(s) {
			switch searchType {
			case firewall.SEARCH_OBJECT:
				if obj.Type() == firewall.OBJECT_SERVICE {
					return obj, true
				}
			case firewall.SEARCH_GROUP:
				// 跳过，因为这是对象，不是组
			case firewall.SEARCH_OBJECT_OR_GROUP:
				if obj.Type() == firewall.OBJECT_SERVICE {
					return obj, true
				}
			}
		}
	}

	// 检查 serviceGroup
	for _, obj := range dos.serviceGroup {
		srv := obj.Service(dos.node)
		if srv != nil && srv.Same(s) {
			switch searchType {
			case firewall.SEARCH_OBJECT:
				// 跳过，因为这是组，不是对象
			case firewall.SEARCH_GROUP:
				if obj.Type() == firewall.GROUP_SERVICE {
					return obj, true
				}
			case firewall.SEARCH_OBJECT_OR_GROUP:
				if obj.Type() == firewall.GROUP_SERVICE {
					return obj, true
				}
			}
		}
	}

	return nil, false
}

func (dos *UsgObjectSet) hasObjectName(name string) bool {
	// 检查地址对象
	for _, obj := range dos.addressObjectSet {
		if obj.Name() == name {
			return true
		}
	}

	// 检查地址组
	for _, obj := range dos.addressGroupSet {
		if obj.Name() == name {
			return true
		}
	}

	// 检查服务对象
	for _, obj := range dos.serviceMap {
		if obj.Name() == name {
			return true
		}
	}

	// 检查服务组
	for _, obj := range dos.serviceGroup {
		if obj.Name() == name {
			return true
		}
	}

	// // 检查 NAT 池
	// for _, poolMap := range dos.poolMap {
	// 	if _, ok := poolMap[name]; ok {
	// 		return true
	// 	}
	// }

	return false
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNetworkObject)(nil)).Elem(), "UsgNetwork", reflect.TypeOf(UsgNetwork{}))
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallServiceObject)(nil)).Elem(), "UsgService", reflect.TypeOf(UsgService{}))
}
