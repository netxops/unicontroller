package secpath

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/axgle/mahonia"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	SECPATH "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/secpath"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/gotextfsm"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/text"

	"github.com/gofrs/uuid"
	"github.com/mitchellh/mapstructure"
)

var _ api.Adapter = &SecPathAdapter{}

type SecPathAdapter struct {
	Type       api.AdapterType
	Session    *session.HttpSession
	DeviceType terminalmode.DeviceType
	api        map[string]string
	portList   []api.Port
	// screenOut chan string
	current string
	// DumpDb      bool
	// DevTablesID *uint
}

// type Adapter interface {
// 	ParseName(force bool) string
// 	PortList(force bool) []Port
// 	RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable)
// 	GetConfig(force bool) interface{}
// 	BatchRun(interface{}) (interface{}, error)
// 	BatchConfig(p ...interface{}) (interface{}, error)
// 	TaskId() uint
// 	AttachChannel(out chan string) bool
// 	Info(bool) (*device.DeviceBaseInfo, error)
// 	GetRawConfig(string, bool) (any, error)
// }

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

func NewSecPathAdapter(info *session.DeviceBaseInfo, config string) *SecPathAdapter {
	if info == nil || info.Host == "" {
		adapter := &SecPathAdapter{
			Type:       api.StringAdapter,
			DeviceType: terminalmode.SecPath,
			current:    config,
		}
		return adapter
	}

	auth_url := "api/v1/tokens"
	hs := session.NewHttpSession(info, auth_url)
	hs.EnableBasicAuth()
	hs.WithTokenField("X-Auth-Token")

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

	sec := &SecPathAdapter{
		Type:       api.LiveAdapter,
		DeviceType: terminalmode.SecPath,
		Session:    hs,
	}
	sec.api = apiMap

	return sec
}

func (adapter *SecPathAdapter) TaskId() uint {
	//return adapter.Task.ID
	return 1
}

func (adapter *SecPathAdapter) getAPI(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
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

func (adapter *SecPathAdapter) get(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
	url := adapter.api[apiKey]

	tokens := strings.Split(url, "/")
	if key == "" {
		key = "get_" + strings.Join(tokens, "_")
	}

	return nil, nil
}

func (adapter *SecPathAdapter) getDataList(apiKey string, force bool) (objList []interface{}) {
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

func (adapter *SecPathAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	if adapter.Type == api.LiveAdapter {
		return adapter.liveAdapterInfo(force)
	} else if adapter.Type == api.StringAdapter {
		return adapter.stringAdapterInfo()
	}
	return nil, fmt.Errorf("unsupported adapter type")
}

func (adapter *SecPathAdapter) liveAdapterInfo(force bool) (*device.DeviceBaseInfo, error) {
	cmd := command.NewHttpCmd("GET", "api/v1/Device/Base", "info", 5, force)
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

	return info, nil

}

func (adapter *SecPathAdapter) stringAdapterInfo() (*device.DeviceBaseInfo, error) {
	// Define the TextFSM template
	template := `Value VERSION (\S+)
Value RELEASE (\S+)
Value HOSTNAME (\S+)
Value MODEL (\S+)

Start
  ^\s*version\s+${VERSION},\s*Release\s+${RELEASE}
  ^\s*sysname\s+${HOSTNAME}
  ^\s*H3C\s+${MODEL}\s+
`

	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(template)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TextFSM template: %v", err)
	}

	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(adapter.current, fsm, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %v", err)
	}

	if len(parser.Dict) == 0 {
		return nil, fmt.Errorf("no matching records found in the configuration")
	}

	// Extract the information from the first record
	record := parser.Dict[0]

	info := &device.DeviceBaseInfo{
		Hostname: getString(record, "HOSTNAME"),
		Version:  getString(record, "VERSION") + "." + getString(record, "RELEASE"),
		Model:    getString(record, "MODEL"),
		SN:       "Unknown", // Serial number is not available in the given configuration
	}

	return info, nil
}

func getString(record map[string]interface{}, key string) string {
	if value, ok := record[key]; ok {
		if strValue, ok := value.(string); ok {
			return strings.TrimSpace(strValue)
		}
	}
	return ""
}

func (adapter *SecPathAdapter) vrfs(force bool) (map[string]interface{}, error) {
	apiKey := "L3vpnIf"
	// func (adapter *SecPathAdapter) getAPI(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
	return adapter.getAPI(apiKey, "get_vrfs", 5, force, false)
}

func (adapter *SecPathAdapter) parsePort(portMap interface{}) api.Port {
	m := portMap.(map[string]interface{})
	// func NewSRXPort(name, tenant string, ip_list map[string][]string, members []*api.Member) *SecPathPort {
	port := SECPATH.NewSecPathPort(m["Name"].(string), "", map[network.IPFamily][]string{}, []api.Member{})
	port.WithAliasName(m["AbbreviatedName"].(string))
	port.WithIfIndex(int(m["IfIndex"].(float64)))
	// if m["OperStatus"].(int) ==

	return port
}

func (adapter *SecPathAdapter) PortList(force bool) []api.Port {
	if adapter.Type == api.LiveAdapter {
		return adapter.liveAdapterPortList(force)
	} else if adapter.Type == api.StringAdapter {
		return adapter.stringAdapterPortList()
	}
	// return nil, fmt.Errorf("unsupported adapter type")
	panic(fmt.Errorf("unsupported adapter type"))
}

func (adapter *SecPathAdapter) hitByIpWithoutPrefix(ip, vrf string) (api.Port, bool) {
	var portList []api.Port

	if adapter.portList == nil {
		portList = adapter.PortList(true)
	}
	for _, port := range portList {
		if port.HitByIpWithoutPrefix(ip, vrf) {
			return port, true
		}
	}

	return nil, false
}

func (adapter *SecPathAdapter) liveAdapterPortList(force bool) []api.Port {
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

	for _, port := range portList {
		if port.Vrf() == "" {
			port.WithVrf(enum.DefaultVrf)
		}
	}

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

	zones, err := adapter.Zones(force)
	if err != nil {
		panic(err)
	}
	// map[IfIndex:49 ZoneName:Trust]
	for _, zone := range zones {
		ifIndex := int(zone.(map[string]interface{})["IfIndex"].(float64))
		for _, port := range portList {
			if ifIndex == port.IfIndex() {
				port.(*SECPATH.SecPathPort).WithZone(zone.(map[string]interface{})["ZoneName"].(string))
			}
		}
	}

	return portList
}

// func (adapter *SecPathAdapter) stringAdapterPortList() []api.Port {
// 	// 使用 TextFSM 解析配置文件中的端口信息
// 	template := `Value Required NAME (\S+)
// Value DESCRIPTION (.*)
// Value IP_ADDRESS (\S+)
// Value IP_MASK (\S+)
// Value VRF (\S+)
// Value VLAN (\d+)

// Start
//   ^interface ${NAME}
//   ^\s+description ${DESCRIPTION}
//   ^\s+ip address ${IP_ADDRESS} ${IP_MASK}
//   ^\s+vlan-type dot1q vid ${VLAN}
//   ^\s+ip binding vpn-instance ${VRF} -> Record
//   ^# -> Record

// EOF`

// 	fsm := gotextfsm.TextFSM{}
// 	err := fsm.ParseString(template)
// 	if err != nil {
// 		panic(fmt.Errorf("failed to parse TextFSM template: %v", err))
// 	}

// 	parser := gotextfsm.ParserOutput{}
// 	err = parser.ParseTextString(adapter.current, fsm, false)
// 	if err != nil {
// 		panic(fmt.Errorf("failed to parse configuration: %v", err))
// 	}

// 	var portList []api.Port
// 	for _, record := range parser.Dict {
// 		port := SECPATH.NewSecPathPort(
// 			getString(record, "NAME"),
// 			getString(record, "VRF"),
// 			map[network.IPFamily][]string{},
// 			[]api.Member{},
// 		)
// 		port.WithAliasName(getString(record, "DESCRIPTION"))
// 		port.WithVrf(getString(record, "VRF"))

// 		ipAddress := getString(record, "IP_ADDRESS")
// 		ipMask := getString(record, "IP_MASK")
// 		if ipAddress != "" && ipMask != "" {
// 			ipNet := fmt.Sprintf("%s/%s", ipAddress, ipMask)
// 			if net.ParseIP(ipAddress).To4() != nil {
// 				port.AddIpv4(ipNet)
// 			} else {
// 				port.AddIpv6(ipNet)
// 			}
// 		}

// 		portList = append(portList, port)
// 	}

// 	// 获取安全区域信息
// 	zones, err := adapter.Zones(false)
// 	if err != nil {
// 		panic(fmt.Errorf("failed to get zones: %v", err))
// 	}

// 	// 将安全区域信息应用到端口列表
// 	for _, zoneInterface := range zones {
// 		zone := zoneInterface.(map[string]interface{})
// 		zoneName := zone["ZoneName"].(string)
// 		interfaceName := zone["IfName"].(string)
// 		for i, port := range portList {
// 			if port.Name() == interfaceName {
// 				portList[i].(*SECPATH.SecPathPort).WithZone(zoneName)
// 				break
// 			}
// 		}
// 	}

// 	for _, port := range portList {
// 		if port.Vrf() == "" {
// 			port.WithVrf(enum.DefaultVrf)
// 		}
// 	}

// 	return portList
// }

func (adapter *SecPathAdapter) stringAdapterPortList() []api.Port {
	// 首先将配置分段
	interfaces := splitInterfaces(adapter.current)

	var portList []api.Port

	// 遍历每个接口配置
	for _, interfaceConfig := range interfaces {
		port := parseInterface(interfaceConfig)
		if port != nil {
			portList = append(portList, port)
		}
	}

	// 获取安全区域信息
	zones, err := adapter.Zones(false)
	if err != nil {
		fmt.Printf("Failed to get zones: %v\n", err)
	} else {
		// 将安全区域信息应用到端口列表
		applyZonesToPorts(portList, zones)
	}

	// 确保所有端口都有 VRF
	ensureDefaultVrf(portList)

	return portList
}

func splitInterfaces(config string) []string {
	var interfaces []string
	lines := strings.Split(config, "\n")
	var currentInterface strings.Builder

	for _, line := range lines {
		if strings.HasPrefix(line, "interface ") {
			if currentInterface.Len() > 0 {
				interfaces = append(interfaces, currentInterface.String())
				currentInterface.Reset()
			}
		}
		currentInterface.WriteString(line + "\n")
	}

	if currentInterface.Len() > 0 {
		interfaces = append(interfaces, currentInterface.String())
	}

	return interfaces
}

func parseInterface(interfaceConfig string) api.Port {
	lines := strings.Split(interfaceConfig, "\n")
	var name, description, vrf string
	var ipv4, ipv6 []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "interface "):
			name = strings.TrimPrefix(line, "interface ")
		case strings.HasPrefix(line, "description "):
			description = strings.TrimPrefix(line, "description ")
		case strings.HasPrefix(line, "ip binding vpn-instance "):
			vrf = strings.TrimPrefix(line, "ip binding vpn-instance ")
		case strings.HasPrefix(line, "ip address "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ipv4 = append(ipv4, fmt.Sprintf("%s/%s", parts[2], parts[3]))
			}
		case strings.HasPrefix(line, "ipv6 address "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ipv6 = append(ipv6, parts[2])
			}
		}
	}

	if name == "" {
		return nil
	}

	port := SECPATH.NewSecPathPort(
		name,
		vrf,
		map[network.IPFamily][]string{
			network.IPv4: ipv4,
			network.IPv6: ipv6,
		},
		[]api.Member{},
	)
	port.WithVrf(vrf)
	port.WithAliasName(description)

	return port
}

func applyZonesToPorts(portList []api.Port, zones []interface{}) {
	for _, zoneInterface := range zones {
		zone := zoneInterface.(map[string]interface{})
		zoneName := zone["ZoneName"].(string)
		interfaceName := zone["IfName"].(string)
		for i, port := range portList {
			if port.Name() == interfaceName {
				portList[i].(*SECPATH.SecPathPort).WithZone(zoneName)
				break
			}
		}
	}
}

func ensureDefaultVrf(portList []api.Port) {
	for _, port := range portList {
		if port.Vrf() == "" {
			port.WithVrf(enum.DefaultVrf)
		}
	}
}

// func getString(record map[string]interface{}, key string) string {
//     if value, ok := record[key]; ok {
//         if strValue, ok := value.(string); ok {
//             return strings.TrimSpace(strValue)
//         }
//     }
//     return ""
// }

func (adapter *SecPathAdapter) parseRouteTable(v4, force bool) map[string]*network.AddressTable {
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
	// func (adapter *SecPathAdapter) getAPI(apiKey, key string, timeout int, force, nested bool) (map[string]interface{}, error) {
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

func (adapter *SecPathAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	if adapter.Type == api.LiveAdapter {
		return adapter.liveAdapterRouteTable(force)
	} else if adapter.Type == api.StringAdapter {
		return adapter.stringAdapterRouteTable()
	}
	// 如果类型不匹配，返回空映射
	return map[string]*network.AddressTable{}, map[string]*network.AddressTable{}
}

func (adapter *SecPathAdapter) liveAdapterRouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	ipv4routeTableMap := adapter.parseRouteTable(true, force)
	ipv6routeTableMap := adapter.parseRouteTable(false, force)

	ipv4TableMap = map[string]*network.AddressTable{
		// SECPATH_DEFAULT_VRF: ipv4routeTable,
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
func (adapter *SecPathAdapter) stringAdapterRouteTable() (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	ipv4TableMap = make(map[string]*network.AddressTable)
	ipv6TableMap = make(map[string]*network.AddressTable)

	lines := strings.Split(adapter.current, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip route-static") {
			parseIPv4Route(line, ipv4TableMap, adapter)
		} else if strings.HasPrefix(line, "ipv6 route-static") {
			parseIPv6Route(line, ipv6TableMap, adapter)
		}
	}

	return ipv4TableMap, ipv6TableMap
}
func parseIPv4Route(line string, tableMap map[string]*network.AddressTable, adapter *SecPathAdapter) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return
	}

	var vrf, destination, mask, nextHop, interface_ string
	index := 2

	if fields[2] == "vpn-instance" {
		vrf = fields[3]
		index = 4
	} else {
		vrf = enum.DefaultVrf
	}

	destination = fields[index]
	mask = fields[index+1]

	if len(fields) > index+3 {
		interface_ = fields[index+2]
		nextHop = fields[index+3]
	} else {
		nextHop = fields[index+2]
	}

	if _, ok := tableMap[vrf]; !ok {
		tableMap[vrf] = network.NewAddressTable(network.IPv4)
	}
	table := tableMap[vrf]

	net, err := network.ParseIPNet(fmt.Sprintf("%s/%s", destination, mask))
	if err != nil {
		return
	}

	nextHopObj := &network.NextHop{}

	// 如果 interface_ 为空，尝试通过 hitByIpWithoutPrefix 获取接口
	if interface_ == "" {
		if port, ok := adapter.hitByIpWithoutPrefix(nextHop, vrf); ok {
			interface_ = port.Name()
		}
	}

	nextHopObj.AddHop(interface_, nextHop, false, false, nil)

	table.PushRoute(net, nextHopObj)
}

func parseIPv6Route(line string, tableMap map[string]*network.AddressTable, adapter *SecPathAdapter) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return
	}

	var vrf, destination, prefixLength, nextHop, interface_ string
	index := 2

	if fields[2] == "vpn-instance" {
		vrf = fields[3]
		index = 4
	} else {
		vrf = enum.DefaultVrf
	}

	destination = fields[index]
	prefixLength = fields[index+1]

	if len(fields) > index+3 {
		interface_ = fields[index+2]
		nextHop = fields[index+3]
	} else {
		nextHop = fields[index+2]
	}

	if _, ok := tableMap[vrf]; !ok {
		tableMap[vrf] = network.NewAddressTable(network.IPv6)
	}
	table := tableMap[vrf]

	net, err := network.ParseIPNet(fmt.Sprintf("%s/%s", destination, prefixLength))
	if err != nil {
		return
	}

	if interface_ == "" {
		if port, ok := adapter.hitByIpWithoutPrefix(nextHop, vrf); ok {
			interface_ = port.Name()
		}
	}

	nextHopObj := &network.NextHop{}
	nextHopObj.AddHop(interface_, nextHop, false, false, nil)

	table.PushRoute(net, nextHopObj)
}

func (adapter *SecPathAdapter) serviceGroupObject(force bool) (groups []interface{}) {
	return adapter.getDataList("ServObjs", force)
}

func (adapter *SecPathAdapter) ipv4ObjectGroup(force bool) (groups []interface{}) {
	return adapter.getDataList("IPv4Groups", force)
}

func (adapter *SecPathAdapter) ipv4Objects(force bool) (objs []interface{}) {
	return adapter.getDataList("IPv4Objs", force)
}

func (adapter *SecPathAdapter) ipv6ObjectGroup(force bool) (groups []interface{}) {
	return adapter.getDataList("IPv6Groups", force)
}

func (adapter *SecPathAdapter) ipv6Objects(force bool) (objs []interface{}) {
	return adapter.getDataList("IPv6Objs", force)
}

func (adapter *SecPathAdapter) natPolicyRules(force bool) (rules []interface{}) {
	return adapter.getDataList("PolicyRuleMembers", force)
}

func (adapter *SecPathAdapter) outboundDynamicRules(force bool) (rules []interface{}) {
	return adapter.getDataList("OutboundDynamicRules", force)
}

func (adapter *SecPathAdapter) staticOnInterface(force bool) (rules []interface{}) {
	return adapter.getDataList("StaticOnInterfaces", force)
}

func (adapter *SecPathAdapter) serverOnInterface(force bool) (rules []interface{}) {
	return adapter.getDataList("ServerOnInterfaces", force)
}

func (adapter *SecPathAdapter) natAddrGroups(force bool) (rules []interface{}) {
	return adapter.getDataList("AddrGroupMembers", force)
}

func (adapter *SecPathAdapter) outboundStaticRules(force bool) (rules []interface{}) {
	return adapter.getDataList("OutboundStaticMappings", force)
}

func (adapter *SecPathAdapter) ipv4NamedBasicAcl(force bool) (rules []interface{}) {
	return adapter.getDataList("IPv4NamedBasicRules", force)
}

func (adapter *SecPathAdapter) ipv4NamedAdvanceAcl(force bool) (rules []interface{}) {
	return adapter.getDataList("IPv4NamedAdvanceRules", force)
}

func (adapter *SecPathAdapter) ipv6NamedBasicAcl(force bool) (rules []interface{}) {
	return adapter.getDataList("IPv6NamedBasicRules", force)
}

func (adapter *SecPathAdapter) ipv6NamedAdvanceAcl(force bool) (rules []interface{}) {
	return adapter.getDataList("IPv6NamedAdvanceRules", force)
}

func (adapter *SecPathAdapter) securityPolicyRules(force bool) (rules []interface{}) {
	return adapter.getDataList("GetRules", force)
}

func (adapter *SecPathAdapter) Zones(force bool) ([]interface{}, error) {
	if adapter.Type == api.LiveAdapter {
		return adapter.liveAdapterZones(force)
	} else if adapter.Type == api.StringAdapter {
		return adapter.stringAdapterZones()
	}
	return nil, fmt.Errorf("unsupported adapter type")
}

func (adapter *SecPathAdapter) liveAdapterZones(force bool) ([]interface{}, error) {
	return adapter.getDataList("ZoneInterfaces", force), nil
}

func (adapter *SecPathAdapter) stringAdapterZones() ([]interface{}, error) {
	// 使用 TextFSM 解析配置文件中的安全区域信息
	template := `Value ZONE_NAME (\S+)
Value INTERFACE (\S+)

Start
  ^security-zone name ${ZONE_NAME}
  ^\s+import interface ${INTERFACE} -> Record

EOF`

	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(template)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TextFSM template: %v", err)
	}

	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(adapter.current, fsm, false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %v", err)
	}

	var zones []interface{}
	for _, record := range parser.Dict {
		zone := map[string]interface{}{
			"ZoneName": getString(record, "ZONE_NAME"),
			"IfName":   getString(record, "INTERFACE"),
		}
		zones = append(zones, zone)
	}

	return zones, nil
}

func (adapter *SecPathAdapter) GetConfig(force bool) interface{} {
	data := map[string]interface{}{}
	if adapter.Type == api.LiveAdapter {
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
	}

	data["Config"] = adapter.current

	return data
}

func (adapter *SecPathAdapter) ParseName(force bool) string {
	info, err := adapter.Info(force)
	if err != nil {
		panic(err)
	}
	if adapter.Type == api.LiveAdapter {
		adapter.getCliConfig()
	}
	return info.Hostname
}

func (adapter *SecPathAdapter) Post(url, data string) (interface{}, error) {
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
func (adapter *SecPathAdapter) BatchRun(p interface{}) (interface{}, error) {
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
					// 如果关键命令执行出错，则停止后续命令的执行
					mustStop = true
				}
			}
		}
	}

	return p, err
}

func (adapter *SecPathAdapter) getCliConfig() {
	info := adapter.Session.Info.BaseInfo
	//
	base := terminal.BaseInfo{
		Host:     info.Host,
		Username: info.Username,
		Password: info.Password,
		Telnet:   false,
	}
	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.SecPath, &base)
	exec.Add("display current", "", 2, "sh_run", "")
	exec.Prepare(false)
	result := exec.Run(false)

	if result.Error() != nil {
		panic(result.Error())
	}

	ok, sh_run := result.GetResult("sh_run")
	//
	if !ok {
		panic(fmt.Sprintf("node: %+v, get result failed", info.Host))
	}
	new_shrun := []string{}
	for _, es := range sh_run {
		configstrfmt := fmt.Sprintf("%v", es)
		utf8Encoder := mahonia.NewEncoder("UTF-8")
		configstr := utf8Encoder.ConvertString(configstrfmt)
		new_shrun = append(new_shrun, configstr)
	}

	adapter.current = strings.Join(new_shrun, "\n")
}

// 为了避免多次登录设备执行命令，需要将所有待执行命令合并到一起执行
// 但是为了前端显示方便区分阶段性执行结果，又需要将执行结果按照输入时的顺序进行保存
func (adapter *SecPathAdapter) BatchConfig(p ...interface{}) (interface{}, error) {

	info := adapter.Session.Info.BaseInfo
	base := terminal.BaseInfo{
		Host:     info.Host,
		Username: info.Username,
		Password: info.Password,
		AuthPass: info.AuthPass,
		Telnet:   info.Telnet,
	}

	exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.SecPath, &base)
	// exec.AttachMonChan(adapter.screenOut)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	cmdList := []command.Command{}

	// var hasError bool
	var err error

	// p为需要进行批量执行的命令主体
	for _, cll := range p {
		switch cll.(type) {
		case []interface{}:
			// cl其实是[]*CliCmdList
			for _, cl := range cll.([]interface{}) {
				for _, cmd := range cl.(*command.CliCmdList).Cmds {
					key := cmd.Key()
					if cmd.Key() == "" {
						key = strings.ReplaceAll(cmd.Cmd(), " ", "_")
					}
					exec.Add(cmd.Cmd(), "", 2, key, "")
					c := command.NewCliCmd(cmd.Cmd(), key, 2, true)
					c.WithLevel(command.MUST)
					cmdList = append(cmdList, c)
				}
			}
		case []string:
			for _, cmd := range cll.([]string) {
				key := strings.ReplaceAll(cmd, " ", "_")
				c := command.NewCliCmd(cmd, key, 2, true)
				c.WithLevel(command.MUST)
				exec.Add(cmd, "", 2, key, "")
				cmdList = append(cmdList, c)
			}
		default:
			panic("unsupoort data type")
		}
	}

	// 需要自动填充First和Last命令
	exec.Prepare(false)
	result := exec.Run(true)

	for _, cmd := range cmdList {
		ok, data := result.GetResult(cmd.Key())
		cmd.WithMsg(strings.Join(data, "\n"))
		if !ok {
			cmd.WithOk(false)
			err = fmt.Errorf("get result failed, key:%s", cmd.Key())
			// hasError = true
		} else {
			cmd.WithOk(true)
		}
	}

	firstCmdList := []command.Command{}
	for _, fc := range exec.DeviceMode.First_Chain {
		c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
		if fc.Status == terminalmode.CMD_COMPLETED {
			c.WithOk(true)
			c.WithMsg(fc.Output)
			c.SetCacheData(command.NewCacheData([]byte(fc.Output)))
		} else {
			c.WithMsg(fc.Msg)
		}
		c.WithLevel(command.OPTION)
		firstCmdList = append(firstCmdList, c)
	}

	lastCmdList := []command.Command{}
	for _, fc := range exec.DeviceMode.Last_Chain {
		c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
		if fc.Status == terminalmode.CMD_COMPLETED {
			c.WithOk(true)
			c.WithMsg(fc.Output)
			c.SetCacheData(command.NewCacheData([]byte(fc.Output)))
		} else {
			c.WithMsg(fc.Msg)
		}
		// c.WithMsg(fc.Msg)
		c.WithLevel(command.OPTION)
		lastCmdList = append(lastCmdList, c)
	}

	cliCmdList := command.NewCliCmdList(base.Host, true)
	for _, cmd := range firstCmdList {
		cliCmdList.AddCmd(cmd)
	}
	for _, cmd := range cmdList {
		cliCmdList.AddCmd(cmd)
	}
	for _, cmd := range lastCmdList {
		cliCmdList.AddCmd(cmd)
	}

	return cliCmdList, err

}

func (secpath *SecPathAdapter) AttachChannel(out chan string) bool {
	// secpath.screenOut = out
	return true
}

func (secpath *SecPathAdapter) GetRawConfig(_ string, force bool) (any, error) {
	return secpath.GetConfig(force), nil
}
