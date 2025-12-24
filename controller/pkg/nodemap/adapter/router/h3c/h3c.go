package h3c

import (
	"encoding/json"
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"

	//"github.com/netxops/unify/global"
	//"github.com/netxops/unify/model"
	"strings"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"

	"github.com/gofrs/uuid"
	"github.com/mitchellh/mapstructure"
)

type H3CAdapter struct {
	Type       api.AdapterType
	Session    *session.HttpSession
	DeviceType terminalmode.DeviceType
	api        map[string]string
	portList   []api.Port
	//Task        *model.ExtractTask
	// DevTablesID *uint
	// DumpDb      bool
}

type xmlIpv4Struct struct {
	Ipv4Address      string  `mapstructure:"Ipv4Address"`
	Ipv4PrefixLength float64 `mapstructure:"Ipv4PrefixLength"`
}

type xmlIpv6Struct struct {
	Ipv6Address      string  `mapstructure:"Ipv6Address"`
	Ipv6PrefixLength float64 `mapstructure:"Ipv6PrefixLength"`
}

type xmlRouteStruct struct {
	VRF        string         `mapstructure:"VRF"`
	Ipv4       *xmlIpv4Struct `mapstructure:"Ipv4"`
	Ipv6Prefix *xmlIpv6Struct `mapstructure:"Ipv6Prefix"`
	Nexthop    string         `mapstructure:"Nexthop"`
	IfIndex    float64        `mapstructure:"IfIndex"`
	PortName   string
	Connected  bool
}

func (xr *xmlRouteStruct) key() string {
	if xr.Ipv4 != nil {
		return fmt.Sprintf("%s_%s_%d", xr.VRF, xr.Ipv4.Ipv4Address, int(xr.Ipv4.Ipv4PrefixLength))
	} else {
		return fmt.Sprintf("%s_%s_%d", xr.VRF, xr.Ipv6Prefix.Ipv6Address, int(xr.Ipv6Prefix.Ipv6PrefixLength))
	}
}

func (xr *xmlRouteStruct) net() string {
	if xr.Ipv4 != nil {
		return fmt.Sprintf("%s/%d", xr.Ipv4.Ipv4Address, int(xr.Ipv4.Ipv4PrefixLength))
	} else {
		return fmt.Sprintf("%s/%d", xr.Ipv6Prefix.Ipv6Address, int(xr.Ipv6Prefix.Ipv6PrefixLength))
	}
}
func NewH3CAdapter(info *session.DeviceBaseInfo, config string) *H3CAdapter {
	auth_url := "api/v1/tokens"
	hs := session.NewHttpSession(info, auth_url)
	hs.EnableBasicAuth()
	hs.WithTokenField("X-Auth-Token")

	//task := model.ExtractTask{
	//	NodeMapTaskID: task_id,
	//}

	//result := global.GVA_DB.Where("node_ip = ?", info.Host).Where("node_map_task_id = ?", task_id).Find(&task)
	//if result.RowsAffected == 0 {
	//	task.NodeIp = info.Host
	//
	//	result = global.GVA_DB.Save(&task)
	//	if result.RowsAffected != 1 {
	//		panic(result.Error)
	//	}
	//}

	apiMap := map[string]string{
		"Zones":                         "api/v1/SecurityZone/Zones",
		"ZoneInterfaces":                "api/v1/SecurityZone/Interfaces",
		"Ipv4Routes":                    "api/v1/Route/Ipv4Routes",
		"Ipv6Routes":                    "api/v1/Route/Ipv6Routes",
		"IPv4Groups":                    "api/v1/OMS/IPv4Groups",
		"IPv4Objs":                      "api/v1/OMS/IPv4Objs",
		"SysIPv4Groups":                 "api/v1/OMS/SysIPv4Groups",
		"IPv6Groups":                    "api/v1/OMS/IPv6Groups",
		"IPv6Objs":                      "api/v1/OMS/IPv6Objs",
		"SysIPv6Groups":                 "api/v1/OMS/SysIPv6Groups",
		"ServGroups":                    "api/v1/OMS/ServGroups",
		"ServObjs":                      "api/v1/OMS/ServObjs",
		"SysServGroups":                 "api/v1/OMS/SysServGroups",
		"PortGroups":                    "api/v1/OMS/PortGroups",
		"PortObjs":                      "api/v1/OMS/PortObjs",
		"SysPortGroups":                 "api/v1/OMS/SysPortGroups",
		"IPv4Exclude":                   "api/v1/OMS/IPv4Exclude",
		"IPv6Exclude":                   "api/v1/OMS/IPv6Exclude",
		"OmsCapability":                 "api/v1/OMS/Capability",
		"IPv4Paging":                    "api/v1/OMS/IPv4Paging",
		"IPv6Paging":                    "api/v1/OMS/IPv6Paging",
		"ServicePaging":                 "api/v1/OMS/ServicePaging",
		"GetIPv4ObjData":                "api/v1/OMS/GetIPv4ObjData",
		"GetIPv6ObjData":                "api/v1/OMS/GetIPv6ObjData",
		"MACGroups":                     "api/v1/OMS/MACGroups",
		"MACObjs":                       "api/v1/OMS/MACObjs",
		"MACPaging":                     "api/v1/OMS/MACPaging",
		"AddrGroups":                    "api/v1/NAT/AddrGroups",
		"AddrGroupMembers":              "api/v1/NAT/AddrGroupMembers",
		"InboundDynamicRules":           "api/v1/NAT/InboundDynamicRules",
		"OutboundDynamicRules":          "api/v1/NAT/OutboundDynamicRules",
		"InboundStaticMappings":         "api/v1/NAT/InboundStaticMappings",
		"OutboundStaticMappings":        "api/v1/NAT/OutboundStaticMappings",
		"StaticOnInterfaces":            "api/v1/NAT/StaticOnInterfaces",
		"ServerGroups":                  "api/v1/NAT/ServerGroups",
		"ServerGroupMembers":            "api/v1/NAT/ServerGroupMembers",
		"ServerOnInterfaces":            "api/v1/NAT/ServerOnInterfaces",
		"PortBlockGroups":               "api/v1/NAT/PortBlockGroups",
		"PortBlockGroupLocalMembers":    "api/v1/NAT/PortBlockGroupLocalMembers",
		"PortBlockGroupGlobalMembers":   "api/v1/NAT/PortBlockGroupGlobalMembers",
		"OutboundPortBlockOnInterfaces": "api/v1/NAT/OutboundPortBlockOnInterfaces",
		"DNSMappings":                   "api/v1/NAT/DNSMappings",
		"ALG":                           "api/v1/NAT/ALG",
		"EIM":                           "api/v1/NAT/EIM",
		"HairpinOnInterfaces":           "api/v1/NAT/HairpinOnInterfaces",
		"LogRule":                       "api/v1/NAT/LogRule",
		"HotBackup":                     "api/v1/NAT/HotBackup",
		"StaticLoadBalance":             "api/v1/NAT/StaticLoadBalance",
		"ReplyRedirectOnInterfaces":     "api/v1/NAT/ReplyRedirectOnInterfaces",
		"AddrPoolAlloc":                 "api/v1/NAT/ReplyRedirectOnInterfaces",
		"Capabilities":                  "api/v1/NAT/ReplyRedirectOnInterfaces",
		"NatPolicy":                     "api/v1/NAT/NatPolicy",
		"PolicyRules":                   "api/v1/NAT/PolicyRules",
		"PolicyRuleMembers":             "api/v1/NAT/PolicyRuleMembers",
		"PolicyRuleMemberSrcObj":        "api/v1/NAT/PolicyRuleMemberSrcObj",
		"PolicyRuleMemberDstObj":        "api/v1/NAT/PolicyRuleMemberDstObj",
		"PolicyRuleMemberSrvObj":        "api/v1/NAT/PolicyRuleMemberSrvObj",
		"DestinationNatOnInterfaces":    "api/v1/NAT/DestinationNatOnInterfaces",
		"ObjServer":                     "api/v1/NAT/ObjServer",
		"Statistics":                    "api/v1/NAT/ReplyRedirectOnInterfaces",
		"Groups":                        "api/v1/ACL/Groups",
		"NamedGroups":                   "api/v1/ACL/NamedGroups",
		"Intervals":                     "api/v1/ACL/Intervals",
		"IPv4BasicRules":                "api/v1/ACL/IPv4BasicRules",
		"IPv4NamedBasicRules":           "api/v1/ACL/IPv4NamedBasicRules",
		"IPv6BasicRules":                "api/v1/ACL/IPv6BasicRules",
		"IPv6NamedBasicRules":           "api/v1/ACL/IPv6NamedBasicRules",
		"IPv4AdvanceRules":              "api/v1/ACL/IPv4AdvanceRules",
		"IPv4NamedAdvanceRules":         "api/v1/ACL/IPv4NamedAdvanceRules",
		"IPv6AdvanceRules":              "api/v1/ACL/IPv6AdvanceRules",
		"IPv6NamedAdvanceRules":         "api/v1/ACL/IPv6NamedAdvanceRules",
		"MACRules":                      "api/v1/ACL/MACRules",
		"MACNamedRules":                 "api/v1/ACL/MACNamedRules",
		"PfilterDefAction":              "api/v1/ACL/PfilterDefAction",
		"PfilterIgnoreAction":           "api/v1/ACL/PfilterIgnoreAction",
		"PfilterApply":                  "api/v1/ACL/PfilterApply",
		"PfilterGroupRunInfo":           "api/v1/ACL/PfilterGroupRunInfo",
		"PfilterRuleRunInfo":            "api/v1/ACL/PfilterRuleRunInfo",
		"PfilterStatisticSum":           "api/v1/ACL/PfilterStatisticSum",
		"UserRules":                     "api/v1/ACL/UserRules",
		"UserNamedRules":                "api/v1/ACL/UserNamedRules",
		"ZonePairPfilterApply":          "api/v1/ACL/ZonePairPfilterApply",
		"ZonePairPfilterRules":          "api/v1/ACL/ZonePairPfilterRules",
		"Base":                          "api/v1/ACL/Base",
		"AclCapability":                 "api/v1/ACL/Capability",
		"Ipv4Addresses":                 "api/v1/IPV4ADDRESS/Ipv4Addresses",
		"IPv4AddressPPPNegotiate":       "api/v1/IPV4ADDRESS/IPv4AddressPPPNegotiate",
		"IPv4AddressCellular":           "api/v1/IPV4ADDRESS/IPv4AddressCellular",
		"Ipv4AddressSpecification":      "api/v1/IPV4ADDRESS/Ipv4AddressSpecification",
		"IPv4AddressUnnumbered":         "api/v1/IPV4ADDRESS/IPv4AddressUnnumbered",
		"Ipv4AddressInterfaceRelation":  "api/v1/IPV4ADDRESS/Ipv4AddressInterfaceRelation",
		"Ipv6AddressesConfig":           "api/v1/IPV6ADDRESS/Ipv6AddressesConfig",
		"Ipv6AddressesAuto":             "api/v1/IPV6ADDRESS/Ipv6AddressesAuto",
		"Ipv6Addresses":                 "api/v1/IPV6ADDRESS/Ipv6Addresses",
		"Ipv6AddressSpecification":      "api/v1/IPV6ADDRESS/Ipv6AddressSpecification",
		"Interfaces":                    "api/v1/Ifmgr/Interfaces",
		"IfmgrStatistics":               "api/v1/Ifmgr/Statistics",
		"Ports ":                        "api/v1/Ifmgr/Ports ",
		"InterfaceCapabilities":         "api/v1/Ifmgr/InterfaceCapabilities",
		"TypeCapabilities":              "api/v1/Ifmgr/TypeCapabilities",
		"EthInterfaces":                 "api/v1/Ifmgr/EthInterfaces",
		"EthInterfaceCapabilities":      "api/v1/Ifmgr/EthInterfaceCapabilities",
		"DeviceCapabilities":            "api/v1/Ifmgr/DeviceCapabilities",
		"TrafficStatisticsInterfaces":   "api/v1/Ifmgr/TrafficStatistics/Interfaces",
		"Interval":                      "api/v1/Ifmgr/TrafficStatistics/Interval",
		"StormConstrainInterfaces":      "api/v1/Ifmgr/StormConstrain/Interfaces",
		"StormConstrainInterval":        "api/v1/Ifmgr/StormConstrain/Interval",
		"PortIsolationGroups":           "api/v1/Ifmgr/PortIsolation/Groups",
		"PortIsolationInterfaces":       "api/v1/Ifmgr/PortIsolation/Interfaces",
		"PortIsolationCapabilities":     "api/v1/Ifmgr/PortIsolation/Capabilities",
		"ReserveVlanInterface":          "api/v1/Ifmgr/ReserveVlanInterface",
		"SubChannel":                    "api/v1/Ifmgr/SubChannel",
		"CellularChannel":               "api/v1/Ifmgr/CellularChannel",
		"NewSubInterfaces":              "api/v1/Ifmgr/NewSubInterfaces",
		"L3vpnVRF":                      "api/v1/L3vpn/L3vpnVRF",
		"L3vpnIf":                       "api/v1/L3vpn/L3vpnIf",
		"L3vpnRT":                       "api/v1/L3vpn/L3vpnRT",
		"L3vpnPeer":                     "api/v1/L3vpn/L3vpnPeer",
		"MacUnicastTable":               "api/v1/MAC/MacUnicastTable",
		"MacGroupTable":                 "api/v1/MAC/MacGroupTable",
		"MacAging":                      "api/v1/MAC/MacAging",
		"MacPort":                       "api/v1/MAC/MacPort",
		"MacVLAN":                       "api/v1/MAC/MacVLAN",
		"MacSpecification":              "api/v1/MAC/MacSpecification",
		"MacFwdSrcCheck":                "api/v1/MAC/MacFwdSrcCheck",
		"MacPortConfig":                 "api/v1/MAC/MacPortConfig",
		"SRVs":                          "api/v1/MAC/SRVs",
		"DeviceBase":                    "api/v1/Device/Base",
		"PhysicalEntities":              "api/v1/Device/PhysicalEntities",
		"ExtPhysicalEntities":           "api/v1/Device/ExtPhysicalEntities",
		"Transceivers":                  "api/v1/Device/Transceivers",
		"TransceiversChannels":          "api/v1/Device/TransceiversChannels",
		"TransceiversITUChannels":       "api/v1/Device/TransceiversITUChannels",
		"CPUs":                          "api/v1/Device/CPUs",
		"SummerTime":                    "api/v1/Device/SummerTime",
		"Boards":                        "api/v1/Device/Boards",
		"Blades":                        "api/v1/Device/Blades",
		"PEXes":                         "api/v1/Device/PEXes",
		"BladeCapabilities":             "api/v1/Device/BladeCapabilities",
		"PEXCapabilities":               "api/v1/Device/PEXCapabilities",
		"FailoverGroupCapabilities":     "api/v1/Device/FailoverGroupCapabilities",
		"Subcards":                      "api/v1/Device/Subcards",
		"TemperatureSensors":            "api/v1/Device/TemperatureSensors",
		"SystemStableStatus":            "api/v1/Device/SystemStableStatus",
		"BoardStableStatus":             "api/v1/Device/BoardStableStatus",
		"IPv4Rules":                     "api/v1/SecurityPolicies/IPv4Rules",
		"IPv6Rules":                     "api/v1/SecurityPolicies/IPv6Rules",
		"GetRules":                      "api/v1/SecurityPolicies/GetRules",
		"QueryRules":                    "api/v1/SecurityPolicies/QueryRules",
		"IPv4SrcSecZone":                "api/v1/SecurityPolicies/IPv4SrcSecZone",
		"IPv6SrcSecZone":                "api/v1/SecurityPolicies/IPv6SrcSecZone",
		"IPv4DestSecZone":               "api/v1/SecurityPolicies/IPv4DestSecZone",
		"IPv6DestSecZone":               "api/v1/SecurityPolicies/IPv6DestSecZone",
		"IPv4SrcAddr":                   "api/v1/SecurityPolicies/IPv4SrcAddr",
		"IPv6SrcAddr":                   "api/v1/SecurityPolicies/IPv6SrcAddr",
		"IPv4DestAddr":                  "api/v1/SecurityPolicies/IPv4DestAddr",
		"IPv6DestAddr":                  "api/v1/SecurityPolicies/IPv6DestAddr",
		"IPv4SrcMacAddr":                "api/v1/SecurityPolicies/IPv4IPv4SrcMacAddr",
		"IPv4ServGrp":                   "api/v1/SecurityPolicies/IPv4ServGrp",
		"IPv6ServGrp":                   "api/v1/SecurityPolicies/IPv6ServGrp",
		"IPv4App":                       "api/v1/SecurityPolicies/IPv4App",
		"IPv6App":                       "api/v1/SecurityPolicies/IPv6App",
		"IPv4AppGrp":                    "api/v1/SecurityPolicies/IPv4AppGrp",
		"IPv6AppGrp":                    "api/v1/SecurityPolicies/IPv6AppGrp",
		"IPv4User":                      "api/v1/SecurityPolicies/IPv4User",
		"IPv6User":                      "api/v1/SecurityPolicies/IPv6User",
		"IPv4UserGrp":                   "api/v1/SecurityPolicies/IPv4UserGrp",
		"IPv6UserGrp":                   "api/v1/SecurityPolicies/IPv6UserGrp",
		"AllocRuleID":                   "api/v1/SecurityPolicies/AllocRuleID",
		"AccelerateCommit":              "api/v1/SecurityPolicies/AccelerateCommit",
		"Accelerate":                    "api/v1/SecurityPolicies/Accelerate",
		"BaseProtocols":                 "api/v1/SecurityPolicies/BaseProtocols",
		"RedundancyCheckStatus":         "api/v1/SecurityPolicies/RedundancyCheckStatus",
		"ContainRedundancyRules":        "api/v1/SecurityPolicies/ContainRedundancyRules",
		"ConfirmedRedundancyRules":      "api/v1/SecurityPolicies/ConfirmedRedundancyRules",
		"IPv4SrcSecZoneInfo":            "api/v1/SecurityPolicies/IPv4SrcSecZoneInfo",
		"IPv6SrcSecZoneInfo":            "api/v1/SecurityPolicies/IPv6SrcSecZoneInfo",
		"IPv4DestSecZoneInfo":           "api/v1/SecurityPolicies/IPv4DestSecZoneInfo",
		"IPv6DestSecZoneInfo":           "api/v1/SecurityPolicies/IPv6DestSecZoneInfo",
		"IPv4SrcMacAddrGrpInfo":         "api/v1/SecurityPolicies/IPv4SrcMacAddrGrpInfo",
		"IPv4SrcAddrGrpInfo":            "api/v1/SecurityPolicies/IPv4SrcAddrGrpInfo",
		"IPv6SrcAddrGrpInfo":            "api/v1/SecurityPolicies/IPv6SrcAddrGrpInfo",
		"IPv4DestAddrGrpInfo":           "api/v1/SecurityPolicies/IPv4DestAddrGrpInfo",
		"IPv6DestAddrGrpInfo":           "api/v1/SecurityPolicies/IPv6DestAddrGrpInfo",
		"IPv4ServGrpInfo":               "api/v1/SecurityPolicies/IPv4ServGrpInfo",
		"IPv6ServGrpInfo":               "api/v1/SecurityPolicies/IPv6ServGrpInfo",
		"IPv4AppInfo":                   "api/v1/SecurityPolicies/IPv4AppInfo",
		"IPv6AppInfo":                   "api/v1/SecurityPolicies/IPv6AppInfo",
		"IPv4AppGrpInfo":                "api/v1/SecurityPolicies/IPv4AppGrpInfo",
		"IPv6AppGrpInfo":                "api/v1/SecurityPolicies/IPv6AppGrpInfo",
		"IPv4UserInfo":                  "api/v1/SecurityPolicies/IPv4UserInfo",
		"IPv6UserInfo":                  "api/v1/SecurityPolicies/IPv6UserInfo",
		"IPv4UserGrpInfo":               "api/v1/SecurityPolicies/IPv4UserGrpInfo",
		"IPv6UserGrpInfo":               "api/v1/SecurityPolicies/IPv6UserGrpInfo",
		"IPv4RuleGroup":                 "api/v1/SecurityPolicies/IPv4RuleGroup",
		"IPv6RuleGroup":                 "api/v1/SecurityPolicies/IPv6RuleGroup",
		"IPv4SrcSimpleAddr":             "api/v1/SecurityPolicies/IPv4SrcSimpleAddr",
		"IPv4DestimpleAddr":             "api/v1/SecurityPolicies/IPv4DestSimpleAddr",
	}

	sec := &H3CAdapter{
		DeviceType: terminalmode.SecPath,
		Session:    hs,
		Type:       tools.ConditionalT(info == nil || info.Host == "", api.StringAdapter, api.LiveAdapter),
	}

	sec.api = apiMap
	return sec

}

func (adapter *H3CAdapter) TaskId() uint {
	//return adapter.Task.ID
	return 1
}

// func (adapter *H3CAdapter) getAPI(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
// 	url := adapter.api[apiKey]

// 	tokens := strings.Split(url, "/")
// 	if key == "" {
// 		key = "get_" + strings.Join(tokens, "_")
// 	}

// 	//db := global.GVA_DB
// 	//entity := model.ConfigExtractEntity{}
// 	//
// 	//result := db.Where("extract_task_id = ?", adapter.Task.ID).Where("cmd_key = ?", key).Find(&entity)
// 	//if result.RowsAffected == 0 {
// 	//	return adapter.get(apiKey, key, timeout, force, nested)
// 	//} else {
// 	//	m := map[string]interface{}{}
// 	//	if entity.Data == "" {
// 	//		return m, nil
// 	//	}
// 	//	err := json.Unmarshal([]byte(entity.Data), &m)
// 	//	return m, err
// 	//}
// 	return nil, nil
// }

func (adapter *H3CAdapter) getAPI(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
	url := adapter.api[apiKey]

	tokens := strings.Split(url, "/")
	if key == "" {
		key = "get_" + strings.Join(tokens, "_")
	}
	item := tokens[len(tokens)-1]

	cmd := command.NewHttpCmd("GET", url, key, timeout, force)
	cd, err := adapter.Session.Request(cmd)
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{}
	if string(cd.Data) == "" {
		return data, nil
	} else {

		err = json.Unmarshal(cd.Data, &data)
		if err != nil {
			return nil, err
		}
		if nested {
			d := data[item].(map[string]interface{})
			return d, nil
		} else {
			return data, nil
		}
	}
}

func (adapter *H3CAdapter) get(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
	url := adapter.api[apiKey]

	tokens := strings.Split(url, "/")
	if key == "" {
		key = "get_" + strings.Join(tokens, "_")
	}
	//item := tokens[len(tokens)-1]

	//cmd := command.NewHttpCmd("GET", url, key, timeout, force)
	//cd, err := adapter.Session.Request(cmd)
	//if err != nil {
	//	return nil, err
	//}

	//enitiy := model.ConfigExtractEntity{
	//	ExtractTaskID: &adapter.Task.ID,
	//	Cmd:           cmd.Cmd(),
	//	CmdKey:        cmd.Key(),
	//	Timeout:       cmd.Timeout(),
	//	Data:          cmd.Msg(),
	//	Md5:           tools.Md5(cmd.Msg()),
	//	DevTablesID:   adapter.DevTablesID,
	//}
	//
	//result := global.GVA_DB.Save(&enitiy)
	//if result.Error != nil {
	//	panic(result.Error)
	//}
	//global.GVA_LOG.Info("dump data to db", zap.Any("cmd", cmd.Cmd()), zap.Any("key", cmd.Key()))
	//
	//data := map[string]interface{}{}
	//if string(cd.Data) == "" {
	//	return data, nil
	//} else {
	//
	//	err = json.Unmarshal(cd.Data, &data)
	//	if err != nil {
	//		return nil, err
	//	}
	//	if nested {
	//		d := data[item].(map[string]interface{})
	//		return d, nil
	//	} else {
	//		return data, nil
	//	}
	//}
	return nil, nil
}

func (adapter *H3CAdapter) getDataList(apiKey string, force bool) (objList []interface{}) {
	m, err := adapter.getAPI(apiKey, "", 5, force, false)
	if err != nil {
		panic(err)
	}

	url := adapter.api[apiKey]
	tokens := strings.Split(url, "/")
	item := tokens[len(tokens)-1]

	if len(m) > 0 {
		objList = m[item].([]interface{})
	}
	return
}

//
// func (adapter *H3CAdapter) vrfs(force bool) (map[string]interface{}, error) {
//
// adapter.getDataMap()
// }

func (adapter *H3CAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	cmd := command.NewHttpCmd("GET", "api/v1/Device/Base", "info", 5, false)
	cd, err := adapter.Session.Request(cmd)
	if err != nil {
		// fmt.Println("error:", err)
		return nil, err
	}

	data := map[string]interface{}{}
	err = json.Unmarshal(cd.Data, &data)
	if err != nil {
		// panic(err)
		return nil, err
	}

	result, err := text.GetFieldByRegex(`Software Version (?P<ver>[\d\.]+), (ESS|Ess|Release) (?P<ver2>\w+)`, data["HostDescription"].(string), []string{"ver", "ver2"})
	if err != nil {
		// panic(err)
		return nil, err
	}
	modelResult, err := text.GetFieldByRegex(`H3C (?P<model>\S+)`, data["HostDescription"].(string), []string{"model"})
	if err != nil {
		// panic(err)
		return nil, err
	}

	version := result["ver"] + "." + result["ver2"]

	info := &device.DeviceBaseInfo{
		Hostname: data["HostName"].(string),
		Version:  version,
		Model:    modelResult["model"],
		SN:       data["BridgeMAC"].(string),
	}

	// adapter.getCliConfig()

	return info, nil
}

func (adapter *H3CAdapter) vrfs(force bool) (map[string]interface{}, error) {
	apiKey := "L3vpnIf"
	// func (adapter *H3CAdapter) getAPI(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
	return adapter.getAPI(apiKey, "get_vrfs", 5, force, false)
}

func (adapter *H3CAdapter) parsePort(portMap interface{}) api.Port {
	m := portMap.(map[string]interface{})
	// func NewSRXPort(name, tenant string, ip_list map[string][]string, members []*api.Member) *SecPathPort {
	// port := SECPATH.NewSecPathPort(m["Name"].(string), "", map[string][]string{}, []*api.Member{})
	// func NewPort(name, tenant string, ip_list map[string][]string, members []*api.Member) *NodePort {
	port := node.NewPort(m["Name"].(string), "", map[network.IPFamily][]string{}, []api.Member{})
	port.WithAliasName(m["AbbreviatedName"].(string))
	port.WithIfIndex(int(m["IfIndex"].(float64)))
	// if m["OperStatus"].(int) ==

	return port
}

func (adapter *H3CAdapter) PortList(force bool) []api.Port {
	interfaceMap, err := adapter.getAPI("Interfaces", "get_interfaces", 5, force, false)
	if err != nil {
		panic(err)
	}

	portList := []api.Port{}
	for _, intf := range interfaceMap["Interfaces"].([]interface{}) {
		portList = append(portList, adapter.parsePort(intf))
	}

	vrfMap, err := adapter.vrfs(force)
	if err != nil {
		panic(err)
	}

	if len(vrfMap) > 0 {
		for _, vrf := range vrfMap["L3vpnIf"].([]interface{}) {
			fmt.Println("vrf:", vrf)
			m := vrf.(map[string]interface{})
			for _, port := range portList {
				if port.IfIndex() == int(m["IfIndex"].(float64)) {
					port.WithVrf(m["VRF"].(string))
				}
			}
		}
	}
	// else {
	for _, port := range portList {
		if port.Vrf() == "" {
			port.WithVrf(enum.DefaultVrf)
		}
	}
	// }

	ip4Map, err := adapter.getAPI("Ipv4Addresses", "get_ipv4", 5, force, false)
	if err != nil {
		panic(err)
	}

	if len(ip4Map) > 0 {
		for _, ip4 := range ip4Map["Ipv4Addresses"].([]interface{}) {
			m := ip4.(map[string]interface{})
			net, err := network.ParseIPNet(m["Ipv4Address"].(string) + "/" + m["Ipv4Mask"].(string))
			if err != nil {
				panic(err)
			}

			for _, port := range portList {
				if port.IfIndex() == int(m["IfIndex"].(float64)) {
					port.AddIpv4(net.String())
				}
			}
		}
	}

	ip6Map, err := adapter.getAPI("Ipv6Addresses", "get_ipv6", 5, force, false)
	if err != nil {
		panic(err)
	}

	if len(ip6Map) > 0 {
		for _, ip6 := range ip6Map["Ipv6Addresses"].([]interface{}) {
			m := ip6.(map[string]interface{})
			net, err := network.ParseIPNet(fmt.Sprintf("%s/%d", m["Ipv6Address"].(string), int(m["Ipv6PrefixLength"].(float64))))
			if err != nil {
				panic(err)
			}

			for _, port := range portList {
				if port.IfIndex() == int(m["IfIndex"].(float64)) {
					port.AddIpv6(net.String())
				}
			}

		}
	}

	adapter.portList = portList

	// zones := adapter.Zones(force)
	// for _, zone := range zones {
	// ifIndex := int(zone.(map[string]interface{})["IfIndex"].(float64))
	// for _, port := range portList {
	// if ifIndex == port.IfIndex() {
	// port.(*SECPATH.SecPathPort).WithZone(zone.(map[string]interface{})["ZoneName"].(string))
	// }
	// }
	// }

	return portList

}

func (adapter *H3CAdapter) parseRouteTable(v4, force bool) map[string]*network.AddressTable {
	var apiKey = "Ipv4Routes"
	if !v4 {
		apiKey = "Ipv6Routes"
	}

	type routeEntry struct {
		net     string
		vrf     string
		nextHop *network.NextHop
	}

	resultTableMap := map[string]*network.AddressTable{}
	// func (adapter *H3CAdapter) getAPI(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
	rMap, err := adapter.getAPI(apiKey, "", 5, force, false)
	if err != nil {
		panic(err)
	}
	var table *network.AddressTable

	if len(rMap) > 0 {
		routeMapList := rMap[apiKey].([]interface{})
		xmlRouteEntryMap := map[string][]*xmlRouteStruct{}
		for _, r := range routeMapList {
			var routeEntry xmlRouteStruct
			err := mapstructure.Decode(r, &routeEntry)
			if err != nil {
				panic(err)
			}
			key := routeEntry.key()
			skip := false
			for _, port := range adapter.portList {
				if port.IfIndex() == int(routeEntry.IfIndex) {
					if port.Name() == "NULL0" {
						skip = true
						break
					}
					routeEntry.PortName = port.Name()
					addressList := []string{}
					addressList = append(addressList, port.Ipv4List()...)
					addressList = append(addressList, port.Ipv6List()...)

					net, _ := network.NewNetworkFromString(routeEntry.net())
					for _, addr := range addressList {
						n, _ := network.NewNetworkFromString(addr)
						// if net.Match(n) {
						if net.Same(n) {
							routeEntry.Connected = true
						}
					}
				}
			}
			if !skip {
				xmlRouteEntryMap[key] = append(xmlRouteEntryMap[key], &routeEntry)
				if routeEntry.Nexthop == "" {
					routeEntry.Connected = true
				}

			}

		}

		for _, routeList := range xmlRouteEntryMap {
			r := routeList[0]
			if _, ok := resultTableMap[r.VRF]; !ok {
				if v4 {
					resultTableMap[r.VRF] = network.NewAddressTable(network.IPv4)
				} else {
					resultTableMap[r.VRF] = network.NewAddressTable(network.IPv6)
				}
			}
			table = resultTableMap[r.VRF]
			net, err := network.ParseIPNet(r.net())
			if err != nil {
				panic(err)
			}
			nextHop := &network.NextHop{}
			for _, hopMap := range routeList {
				nextHop.AddHop(hopMap.PortName, hopMap.Nexthop, hopMap.Connected, false, nil)
			}

			err = table.PushRoute(net, nextHop)
		}
	}
	return resultTableMap
}

func (adapter *H3CAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {

	ipv4routeTableMap := adapter.parseRouteTable(true, force)
	ipv6routeTableMap := adapter.parseRouteTable(false, force)

	ipv4TableMap = map[string]*network.AddressTable{
		// H3C_DEFAULT_VRF: ipv4routeTable,
	}

	for vrf, table := range ipv4routeTableMap {
		if vrf == "" {
			ipv4TableMap[enum.DefaultVrf] = table
		} else {
			ipv4TableMap[vrf] = table
		}
	}

	ipv6TableMap = map[string]*network.AddressTable{}
	for vrf, table := range ipv6routeTableMap {
		if vrf == "" {
			ipv6TableMap[enum.DefaultVrf] = table
		} else {
			ipv6TableMap[vrf] = table
		}
	}

	return ipv4TableMap, ipv6TableMap

}

func (adapter *H3CAdapter) serviceGroupObject(force bool) (groups []interface{}) {
	return adapter.getDataList("ServObjs", force)
}

func (adapter *H3CAdapter) ipv4ObjectGroup(force bool) (groups []interface{}) {
	return adapter.getDataList("IPv4Groups", force)
}

func (adapter *H3CAdapter) ipv4Objects(force bool) (objs []interface{}) {
	return adapter.getDataList("IPv4Objs", force)
}

func (adapter *H3CAdapter) ipv6ObjectGroup(force bool) (groups []interface{}) {
	return adapter.getDataList("IPv6Groups", force)
}

func (adapter *H3CAdapter) ipv6Objects(force bool) (objs []interface{}) {
	return adapter.getDataList("IPv6Objs", force)
}

func (adapter *H3CAdapter) natPolicyRules(force bool) (rules []interface{}) {
	return adapter.getDataList("PolicyRuleMembers", force)
}

func (adapter *H3CAdapter) outboundDynamicRules(force bool) (rules []interface{}) {
	return adapter.getDataList("OutboundDynamicRules", force)
}

func (adapter *H3CAdapter) staticOnInterface(force bool) (rules []interface{}) {
	return adapter.getDataList("StaticOnInterfaces", force)
}

func (adapter *H3CAdapter) serverOnInterface(force bool) (rules []interface{}) {
	return adapter.getDataList("ServerOnInterfaces", force)
}

func (adapter *H3CAdapter) natAddrGroups(force bool) (rules []interface{}) {
	return adapter.getDataList("AddrGroupMembers", force)
}

func (adapter *H3CAdapter) outboundStaticRules(force bool) (rules []interface{}) {
	return adapter.getDataList("OutboundStaticMappings", force)
}

func (adapter *H3CAdapter) ipv4NamedBasicAcl(force bool) (rules []interface{}) {
	return adapter.getDataList("IPv4NamedBasicRules", force)
}

func (adapter *H3CAdapter) ipv4NamedAdvanceAcl(force bool) (rules []interface{}) {
	return adapter.getDataList("IPv4NamedAdvanceRules", force)
}

func (adapter *H3CAdapter) ipv6NamedBasicAcl(force bool) (rules []interface{}) {
	return adapter.getDataList("IPv6NamedBasicRules", force)
}

func (adapter *H3CAdapter) ipv6NamedAdvanceAcl(force bool) (rules []interface{}) {
	return adapter.getDataList("IPv6NamedAdvanceRules", force)
}

func (adapter *H3CAdapter) securityPolicyRules(force bool) (rules []interface{}) {
	return adapter.getDataList("GetRules", force)
}

func (adapter *H3CAdapter) Zones(force bool) (zones []interface{}) {
	a := adapter.getDataList("ZoneInterfaces", force)
	return a
}

func (adapter *H3CAdapter) getCliConfig() {
	//key := "sh_run"
	//db := global.GVA_DB
	//entity := model.ConfigExtractEntity{}
	//
	//result := db.Where("extract_task_id = ?", adapter.Task.ID).Where("cmd_key = ?", key).Find(&entity)
	//if result.RowsAffected == 0 {
	//	// return adapter.get(apiKey, key, timeout, force, nested)
	//	info := adapter.Session.Info.BaseInfo
	//
	//	base := terminal.BaseInfo{
	//		Host:     info.Host,
	//		Username: info.Username,
	//		Password: info.Password,
	//		Telnet:   false,
	//	}
	//
	//	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.SecPath, &base)
	//	exec.Add("display current", "", 2, "sh_run", "")
	//	exec.Prepare(false)
	//	result := exec.Run(false)
	//
	//	if result.Error() != nil {
	//		panic(result.Error())
	//	}
	//
	//	ok, sh_run := result.GetResult("sh_run")
	//
	//	if !ok {
	//		panic(fmt.Sprintf("node: %+v, get result failed", info.Host))
	//	}
	//
	//	enitiy := model.ConfigExtractEntity{
	//		ExtractTaskID: &adapter.Task.ID,
	//		Cmd:           "display current",
	//		CmdKey:        "sh_run",
	//		Timeout:       2,
	//		Data:          strings.Join(sh_run, "\n"),
	//		Md5:           tools.Md5(strings.Join(sh_run, "\n")),
	//		DevTablesID:   adapter.DevTablesID,
	//	}
	//
	//	result2 := global.GVA_DB.Save(&enitiy)
	//	if result2.Error != nil {
	//		panic(result2.Error)
	//	}
	//	global.GVA_LOG.Info("dump data to db", zap.Any("cmd", "display current"), zap.Any("key", "sh_run"))
	//
	//}
}

func (adapter *H3CAdapter) GetConfig(force bool) interface{} {
	data := map[string]interface{}{}
	data["ServiceGroupObject"] = adapter.serviceGroupObject(force)
	data["IPv4Objs"] = adapter.ipv4Objects(force)
	data["IPv4Groups"] = adapter.ipv4ObjectGroup(force)
	data["IPv6Objs"] = adapter.ipv6Objects(force)
	data["IPv6Groups"] = adapter.ipv6ObjectGroup(force)
	data["OutboundDynamicRules"] = adapter.outboundDynamicRules(force)
	data["StaticOnInterfaces"] = adapter.staticOnInterface(force)
	data["ServerOnInterfaces"] = adapter.serverOnInterface(force)
	data["AddrGroupMembers"] = adapter.natAddrGroups(force)
	data["OutboundStaticMappings"] = adapter.outboundStaticRules(force)
	data["PolicyRuleMembers"] = adapter.natPolicyRules(force)
	data["IPv4NamedBasicRules"] = adapter.ipv4NamedBasicAcl(force)
	data["IPv4NamedAdvanceRules"] = adapter.ipv4NamedAdvanceAcl(force)
	data["IPv6NamedBasicRules"] = adapter.ipv6NamedBasicAcl(force)
	data["IPv6NamedAdvanceRules"] = adapter.ipv6NamedAdvanceAcl(force)
	data["GetRules"] = adapter.securityPolicyRules(force)

	return data
}

func (adapter *H3CAdapter) ParseName(force bool) string {
	info, err := adapter.Info(force)
	if err != nil {
		panic(err)
	}
	adapter.getCliConfig()

	//if adapter.DumpDb {
	//	dev := model.DcimDevice{}
	//	//result := global.GVA_DB.Where("system_ip = ?", adapter.Session.Info.Host).Where("system_name = ?", info.Hostname).Find(&dev)
	//	var ipaddress model.IpamIpaddress
	//	ipResult := global.GVA_DB.Where("address = ?", adapter.Session.Info.Host).First(&ipaddress)
	//	if ipResult.RowsAffected > 0 {
	//		result := global.GVA_DB.Where("primary_ip4_id = ?", adapter.Session.Info.Host).Where("name = ?", info.Hostname).Find(&dev)
	//		if result.Error != nil {
	//			panic(result.Error)
	//		}
	//		global.GVA_DB.Model(&model.ExtractTask{}).Where("id = ?", adapter.Task.ID).Update("dev_tables_id", dev.ID)
	//	} else {
	//		fmt.Println("ParseName err not found,address :", adapter.Session.Info.Host)
	//	}
	//}

	return info.Hostname
}

func (adapter *H3CAdapter) Post(url, data string) (interface{}, error) {
	// func NewHttpCmd(method, url, key string, timeout int, force bool) *HttpCmd {
	key := strings.ReplaceAll(url, "/", "_")
	cmd := command.NewHttpCmd("POST", url, key, 2, true)
	cmd.WithData([]byte(data))
	cd, err := adapter.Session.Request(cmd)
	if err != nil {
		return nil, err
	}

	return cd.Data, nil
}

// p是[]*HttpCmdList
func (adapter *H3CAdapter) BatchRun(p interface{}) (interface{}, error) {
	cmds := p.([]interface{})
	var err error

	var mustStop bool
	for _, cmdList := range cmds {
		if !mustStop {
			for _, cmd := range cmdList.(*command.HttpCmdList).Cmds {
				cmd.(*command.HttpCmd).Force = true
			}

			err = adapter.Session.BatchRun(cmdList.(*command.HttpCmdList), true)
			if err != nil {
				return nil, err
			}
			for _, c := range cmdList.(*command.HttpCmdList).Cmds {
				if c.Level() == command.MUST && !c.Ok() {
					mustStop = true
				}
			}
		}
	}

	return p, err
}

func (adapter *H3CAdapter) BatchConfig(p ...interface{}) (interface{}, error) {
	info := adapter.Session.Info.BaseInfo

	base := terminal.BaseInfo{
		Host:     info.Host,
		Username: info.Username,
		Password: info.Password,
		Telnet:   false,
	}

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.SecPath, &base)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	cmdList := []command.Command{}

	cb := command.NewCliCmd("display current", "before", 10, true)
	cb.WithLevel(command.OPTION)

	exec.Add("display current", "", 2, "before", "")
	exec.Prepare(false)
	resultBefore := exec.Run(false)
	_, beforeList := resultBefore.GetResult("before")
	if resultBefore.Error() != nil {
		cb.WithOk(false)
		cb.WithMsg(fmt.Sprint(resultBefore.Error()))
		// panic(resultBefore.Error())
		// fmt.Println("error: ", resultBefore.Error())
	} else {
		before := strings.Join(beforeList, "\n")
		cb.WithOk(true)
		cb.WithMsg(before)
	}

	cmdList = append(cmdList, cb)

	var hasError bool

	for _, cl := range p {
		switch cl.(type) {
		case []interface{}:
			resetResult, err := adapter.BatchRun(cl)
			if err != nil {
				panic(err)
			}

			cmds := resetResult.([]interface{})

			for _, cl := range cmds {
				for _, cmd := range cl.(*command.HttpCmdList).Cmds {
					cmdList = append(cmdList, cmd)
				}
			}

			for _, c := range cmdList {
				if c.Level() == command.MUST && !c.Ok() {
					hasError = true
				}
			}
		case []string:
			if !hasError {
				exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.SecPath, &base)
				exec.Id = uuid.Must(uuid.NewV4()).String()
				subCmdList := []command.Command{}

				for _, c := range cl.([]string) {
					cb := command.NewCliCmd(c, "", 1, true)
					// cb.WithLevel(command.OPTION)
					cb.WithLevel(command.MUST)
					key := strings.ReplaceAll(c, " ", "_")
					exec.Add(c, "", 2, key, "")
					subCmdList = append(subCmdList, cb)
				}

				exec.Prepare(true)
				additionResult := exec.Run(true)
				if additionResult.Error() == nil {
					for _, c := range subCmdList {
						c.WithOk(true)
						cmdList = append(cmdList, c)

					}
				} else {
					for _, c := range subCmdList {
						c.WithOk(false)
						for _, errMsgPair := range additionResult.ErrMsg {
							if errMsgPair.Key == c.Cmd() {
								c.WithMsg(strings.Join(errMsgPair.Value, "\n"))
							}
						}
						cmdList = append(cmdList, c)
					}
				}

			}
		}

	}

	if !hasError {
		ca := command.NewCliCmd("display current", "after", 10, true)
		ca.WithLevel(command.OPTION)

		exec = terminal.NewExecute(terminalmode.VIEW, terminalmode.SecPath, &base)
		exec.Add("display current", "", 2, "after", "")
		exec.Prepare(false)
		resultAfter := exec.Run(false)

		_, afterList := resultAfter.GetResult("after")
		if resultAfter.Error() != nil {
			cb.WithOk(false)
			cb.WithMsg(fmt.Sprint(resultAfter.Error()))
		} else {
			after := strings.Join(afterList, "\n")
			ca.WithMsg(after)
			ca.WithOk(true)
		}

		cmdList = append(cmdList, ca)
	}

	httpCmdList := command.NewHttpCmdList(base.Host, true)
	for _, cmd := range cmdList {
		httpCmdList.AddCmd(cmd)
	}

	return httpCmdList, nil
}

func (bia *H3CAdapter) AttachChannel(out chan string) bool {
	return false
}

func (bia *H3CAdapter) GetRawConfig(_ string, force bool) (any, error) {
	return bia.GetConfig(force), nil
}
