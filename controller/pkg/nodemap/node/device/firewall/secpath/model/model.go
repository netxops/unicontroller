package model

import (
	"encoding/json"
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/tools"
)

const (
	SECPATH_ANY_ZONE = "any"
)

type ApiPortOpType int

const (
	OP_LT ApiPortOpType = iota + 1
	OP_EQ
	OP_GT
	OP_NEQ
	OP_RANGE
)

type ApiACLStatusType int

const (
	ACL_STATUS_ACTIVE ApiACLStatusType = iota + 1
	ACL_STATUS_INACTIVE
)

type ApiIpType int

const (
	SECPATH_IP_IPV4 ApiIpType = iota + 1
	SECPATH_IP_IPV6
)

type ApiRuleActionType int

const (
	SECPATH_RULE_DENY ApiRuleActionType = iota + 1
	SECPATH_RULE_PERMIT
)

type ApiRuleServiceObjectType int

const (
	SECPATH_SERVICE_TCP ApiRuleServiceObjectType = iota
	SECPATH_SERVICE_UDP
	SECPATH_SERVICE_ICMP
	SECPATH_SERVICE_ICMP6
	SECPATH_SERVICE_PROTOCOL
)

const (
	SECPATH_NIL_ZONE = "global"
)

type ApiSrvObjType int

const (
	SERVICE_NESTED ApiSrvObjType = iota
	SERVICE_PROTOCOL
	SERVICE_ICMP
	SERVICE_TCP
	SERVICE_UDP
	SERVICE_ICMP6
)

func (t ApiSrvObjType) String() string {
	return []string{"NESTED", "PROTOCOL", "ICMP", "TCP", "UDP", "ICMP6"}[t]
}

type ApiAddressObjType int

const (
	ADDRESS_NESTED ApiAddressObjType = iota
	ADDRESS_SUBNET
	ADDRESS_RANGE
	ADDRESS_HOST
	ADDRESS_DNS
	ADDRESS_USER
	ADDRESS_USERGROUP
	ADDRESS_WILDCARD
)

func (t ApiAddressObjType) String() string {
	return []string{"NESTED", "SUBNET", "RANGE", "HOST", "DNS", "USER", "USERGROUP", "WILDCARD"}[t]
}

type ApiNatRuleMethod int

const (
	_ ApiNatRuleMethod = iota
	SECPATH_NAT_POLICY
	SECPATH_NAT_OUTBOUND_STATIC
	SECPATH_NAT_OUTBOUNT_DYNAMIC
	SECPATH_NAT_SERVER_ON_INTERFACE
	SECPATH_NAT_GLOBAL_POLICY
)

func (ae ApiNatRuleMethod) String() string {
	return []string{"NAT_POLICY", "NAT_OUTBOUND_STATIC", "NAT_OUTBOUND_DYNAMIC", "NAT_SERVER_ON_INTERFACE", "NAT_GLOBAL_POLICY"}[ae-1]
}

type ApiNatPolicyActionType int

const (
	NO_PAT ApiNatPolicyActionType = iota
	PAT
	EASYIP
	NONAT
)

func (at ApiNatPolicyActionType) String() string {
	return []string{"NO_PAT", "PAT", "EASYIP", "NONAT"}[at]
}

type XmlNatPolicyStruct struct {
	Action          *ApiNatPolicyActionType `mapstructure:"Action" json:"Action,omitempty"`
	AddrGroupNumber int64                   `mapstructure:"AddrGroupNumber" json:"AddrGroupNumber,omitempty"`
	Counting        bool                    `mapstructure:"Counting" json:"Counting,omitempty"`
	Disable         bool                    `mapstructure:"Disable" json:"Disable,omitempty"`
	DstObjGrpList   struct {
		DstIPObjGroup []string `mapstructure:"DstIpObjGroup" json:"DstIpObjGroup,omitempty"`
		DstIpObj      string   `json:"DstIpObj,omitempty"`
	} `mapstructure:"DstObjGrpList" json:"DstObjGrpList,omitempty"`
	MatchingCount     int64  `mapstructure:"MatchingCount" json:"MatchingCount,omitempty"`
	OutboundInterface int64  `mapstructure:"OutboundInterface" json:"OutboundInterface,omitempty"`
	PortPreserved     bool   `mapstructure:"PortPreserved" json:"PortPreserved,omitempty"`
	Reversible        bool   `mapstructure:"Reversible" json:"Reversible,omitempty"`
	RuleName          string `mapstructure:"RuleName" json:"RuleName,omitempty"`
	SrcObjGrpList     struct {
		SrcIPObjGroup []string `mapstructure:"SrcIpObjGroup" json:"SrcIpObjGroup,omitempty"`
		SrcIpObj      string   `json:"SrcIpObj,omitempty"`
	} `mapstructure:"SrcObjGrpList" json:"SrcObjGrpList,omitempty"`
	SrvObjGrpList struct {
		ServiceObjGroup []string `mapstructure:"ServiceObjGroup" json:"ServiceObjGroup,omitempty"`
		SrvObj          string   `json:"SrvObj,omitempty"`
	} `mapstructure:"SrvObjGrpList" json:"SrvObjGrpList,omitempty"`
}

type XmlOutboundStaticStruct struct {
	IfIndex   int `mapstructure:"IfIndex" json:"IfIndex"`
	LocalInfo struct {
		LocalVRF         string `mapstructure:"LocalVRF" json:"LocalVrf"`
		StartIpv4Address string `mapstructure:"StartIpv4Address" json:"StartIpv4Address"`
		EndIpv4Address   string `mapstructure:"EndIpv4Address" json:"EndIpv4Address"`
	} `mapstructure:"LocalInfo" json:"LocalInfo"`
	GlobalInfo struct {
		GlobalVRF        string `mapstructure:"GlobalVRF" json:"GlobalVrf"`
		Ipv4Address      string `mapstructure:"Ipv4Address" json:"Ipv4Address"`
		Ipv4PrefixLength int    `mapstructure:"Ipv4PrefixLength" json:"Ipv4PrefixLength"`
	} `mapstructure:"GlobalInfo" json:"GlobalInfo"`
	ACLNumber     string `mapstructure:"ACLNumber" json:"AclNumber"`
	Reversible    bool   `mapstructure:"Reversible" json:"Reversible"`
	Disable       bool   `mapstructure:"Disable" json:"Disable"`
	Description   string `mapstructure:"Description" json:"Description"`
	MatchingCount int    `mapstructure:"MatchingCount" json:"MatchingCount"`
	Counting      bool   `mapstructure:"Counting" json:"Counting"`
}
type XmlStaticOnInterfaceStruct struct {
	IfIndex      string `mapstructure:"IfIndex"`
	EnableStatic bool   `mapstructure:"EnableStatic"`
}

type XmlServerOnInterfaceStruct struct {
	IfIndex      int `mapstructure:"IfIndex" json:"IfIndex,omitempty"`
	ProtocolType int `mapstructure:"ProtocolType" json:"ProtocolType"`
	GlobalInfo   struct {
		GlobalVRF              string `mapstructure:"GlobalVRF" json:"GlobalVRF"`
		GlobalStartIpv4Address string `mapstructure:"GlobalStartIpv4Address" json:"GlobalStartIpv4Address,omitempty"`
		GlobalEndIpv4Address   string `mapstructure:"GlobalEndIpv4Address" json:"GlobalEndIpv4Address,omitempty"`
		GlobalStartPortNumber  string `mapstructure:"GlobalStartPortNumber" json:"GlobalStartPortNumber,omitempty"`
		GlobalEndPortNumber    string `mapstructure:"GlobalEndPortNumber" json:"GlobalEndPortNumber,omitempty"`
		GlobalIfIndex          string `mapstructure:"GlobalIfIndex" json:"GlobalIfIndex"`
	} `mapstructure:"GlobalInfo" json:"GlobalInfo,omitempty"`
	LocalInfo struct {
		LocalVRF              string `mapstructure:"LocalVRF" json:"LocalVRF,omitempty"`
		LocalStartIpv4Address string `mapstructure:"LocalStartIpv4Address" json:"LocalStartIpv4Address,omitempty"`
		LocalEndIpv4Address   string `mapstructure:"LocalEndIpv4Address" json:"LocalEndIpv4Address,omitempty"`
		LocalStartPortNumber  string `mapstructure:"LocalStartPortNumber" json:"LocalStartPortNumber,omitempty"`
		LocalEndPortNumber    string `mapstructure:"LocalEndPortNumber" json:"LocalEndPortNumber,omitempty"`
	} `mapstructure:"LocalInfo" json:"LocalInfo,omitempty"`
	ACLNumber            string `mapstructure:"ACLNumber" json:"ACLNumber,omitempty"`
	Reversible           bool   `mapstructure:"Reversible" json:"Reversible,omitempty"`
	MatchingCount        int    `mapstructure:"MatchingCount" json:"MatchingCount,omitempty"`
	RuleName             string `mapstructure:"RuleName" json:"RuleName"`
	Disable              bool   `mapstructure:"Disable" json:"Disable"`
	WhetherPersistConfig bool   `mapstructure:"WhetherPersistConfig" json:"WhetherPersistConfig,omitempty"`
}

type XmlOutboundDynamicStruct struct {
	IfIndex              string `mapstructure:"IfIndex"`
	ACLNumber            string `mapstructure:"ACLNumber"`
	AddrGroupNumber      int    `mapstructure:"AddrGroupNumber"`
	NoPAT                bool   `mapstructure:"NoPAT"`
	Reversible           bool   `mapstructure:"Reversible"`
	PortPreserved        bool   `mapstructure:"PortPreserved"`
	MatchingCount        int    `mapstructure:"MatchingCount"`
	Disable              bool   `mapstructure:"Disable"`
	WhetherPersistConfig bool   `mapstructure:"WhetherPersistConfig"`
}
type XmlInboundDynamicStruct struct {
	IfIndex         int    `mapstructure:"IfIndex"`
	ACLNumber       string `mapstructure:"ACLNumber"`
	AddrGroupNumber int    `mapstructure:"AddrGroupNumber"`
	NoPAT           bool   `mapstructure:"NoPAT"`
	Reversible      bool   `mapstructure:"Reversible"`
	AutoAddRoute    bool   `mapstructure:"AutoAddRoute"`
	MatchingCount   int    `mapstructure:"MatchingCount"`
}

type XmlAddrGroupStruct struct {
	GroupNumber       int                         `json:"GroupNumber" mapstructure:"GroupNumber"`
	GroupName         string                      `json:"GroupName,omitempty" mapstructure:"GroupName"`
	PortBlockSize     int                         `json:"PortBlockSize,omitempty" mapstructure:"PortBlockSize"`
	StartPort         int                         `json:"StartPort,omitempty" mapstructure:"StartPort"`
	EndPort           int                         `json:"EndPort,omitempty" mapstructure:"EndPort"`
	HealthCheckStatus int                         `json:"HealthCheckStatus,omitempty" mapstructure:"HealthCheckStatus"`
	LackedAddresses   int                         `json:"LackedAddresses,omitempty" mapstructure:"LackedAddresses"`
	Members           []*XmlAddrGroupMemberStruct `json:"Members,omitempty"`
}

type XmlAddrGroupMemberStruct struct {
	GroupNumber      int    `mapstructure:"GroupNumber" json:"GroupNumber"`
	StartIpv4Address string `mapstructure:"StartIpv4Address" json:"StartIpv4Address"`
	EndIpv4Address   string `mapstructure:"EndIpv4Address" json:"EndIpv4Address"`
}

// type firewall.NatStatus int
//
// const (
// SECPATH_NAT_ACTIVE firewall.NatStatus = iota
// SECPATH_NAT_INACTIVE
// )
type AddressGroup struct {
	GroupNumber int `mapstructure:"GroupNumber"`
	C           string
	N           *network.NetworkGroup
}

// 实现 TypeInterface 接口
func (ag *AddressGroup) TypeName() string {
	return "AddressGroup"
}

// addressGroupJSON 用于序列化和反序列化
type addressGroupJSON struct {
	GroupNumber int             `json:"group_number"`
	C           string          `json:"cli"`
	N           json.RawMessage `json:"network"`
}

// MarshalJSON 实现 JSON 序列化
func (ag *AddressGroup) MarshalJSON() ([]byte, error) {
	networkRaw, err := json.Marshal(ag.N)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	return json.Marshal(addressGroupJSON{
		GroupNumber: ag.GroupNumber,
		C:           ag.C,
		N:           networkRaw,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ag *AddressGroup) UnmarshalJSON(data []byte) error {
	var agj addressGroupJSON
	if err := json.Unmarshal(data, &agj); err != nil {
		return err
	}

	ag.GroupNumber = agj.GroupNumber
	ag.C = agj.C

	ag.N = &network.NetworkGroup{}
	if err := json.Unmarshal(agj.N, ag.N); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}

	return nil
}

func (ag *AddressGroup) ID() string {
	return fmt.Sprintf("%d", ag.GroupNumber)
}

func (ag *AddressGroup) Cli() string {
	return ag.C
}

func (ag *AddressGroup) Name() string {
	return fmt.Sprintf("%d", ag.GroupNumber)
}

func (ag *AddressGroup) Network(node firewall.FirewallNode) *network.NetworkGroup {
	return ag.N
}

// MatchNetworkGroup 检查给定的网络组是否匹配当前地址组
func (ag *AddressGroup) MatchNetworkGroup(ng *network.NetworkGroup) bool {
	if ag.N == nil || ng == nil {
		return false
	}
	return ag.N.Same(ng)
}

func (ag *AddressGroup) Type() firewall.FirewallObjectType {
	return firewall.OBJECT_NETWORK
}

type XmlNetworkObject struct {
	Group string `mapstructure:"Group" json:"Group,omitempty"`
	// SecurityZone      string            `mapstructure:"SecurityZone" json:"SecurityZone,omitempty"`
	ID                int               `mapstructure:"ID" json:"ID,omitempty"`
	SubnetIPv4Address string            `mapstructure:"SubnetIPv4Address" json:"SubnetIPv4Address,omitempty"`
	IPv4Mask          string            `mapstructure:"IPv4Mask" json:"IPv4Mask,omitempty"`
	SubnetIPv6Address string            `mapstructure:"SubnetIPv6Address" json:"SubnetIPv6Address,omitempty"`
	IPv6PrefixLen     int               `mapstructure:"IPv6PrefixLen" json:"IPv6PrefixLen,omitempty"`
	StartIPv4Address  string            `mapstructure:"StartIPv4Address" json:"StartIPv4Address,omitempty"`
	EndIPv4Address    string            `mapstructure:"EndIPv4Address" json:"EndIPv4Address,omitempty"`
	StartIPv6Address  string            `mapstructure:"StartIPv6Address" json:"StartIPv6Address,omitempty"`
	EndIPv6Address    string            `mapstructure:"EndIPv6Address" json:"EndIPv6Address,omitempty"`
	HostIPv4Address   string            `mapstructure:"HostIPv4Address" json:"HostIPv4Address,omitempty"`
	HostIPv6Address   string            `mapstructure:"HostIPv6Address" json:"HostIPv6Address,omitempty"`
	NestedGroup       string            `mapstructure:"NestedGroup" json:"NestedGroup,omitempty"`
	Type              ApiAddressObjType `mapstructure:"Type" json:"Type,omitempty"`
	Zone              string            `json:"-"`
}

type XmlGroupStruct struct {
	Name         string `json:"Name"`
	Description  string `json:"Description,omitempty"`
	ObjNum       int    `json:"-"`
	InUse        bool   `json:"-"`
	SecurityZone string `json:"SecurityZone"`
	ValidObjNum  int    `json:"-"`
	// Members      []*XmlNetworkObject `json:"Members"`
}

type XmlServiceGroupStruct struct {
	Name        string              `json:"Name"`
	Description string              `json:"Description,omitempty"`
	ObjNum      int                 `json:"-"`
	InUse       bool                `json:"-"`
	ValidObjNum int                 `json:"-"`
	Members     []*XmlServiceObject `json:"Members,omitempty"`
}

func (xno *XmlNetworkObject) Network() (*network.NetworkGroup, error) {

	var text string
	switch xno.Type {
	case ADDRESS_HOST:
		if xno.HostIPv4Address != "" {
			text = xno.HostIPv4Address
		} else {
			text = xno.HostIPv6Address
		}
	case ADDRESS_RANGE:
		if xno.StartIPv4Address != "" {
			text = xno.StartIPv4Address + "-" + xno.EndIPv4Address
		} else {
			text = xno.StartIPv6Address + "-" + xno.EndIPv6Address
		}
	case ADDRESS_SUBNET:
		if xno.SubnetIPv4Address != "" {
			text = xno.SubnetIPv4Address + "/" + xno.IPv4Mask
		} else {
			text = xno.SubnetIPv6Address + "/" + fmt.Sprintf("%d", int(xno.IPv6PrefixLen))
		}
	default:
		panic(fmt.Sprintf("current not support: %+v", xno))
	}

	ng, err := network.NewNetworkGroupFromString(text)

	return ng, err
}

type XmlServiceObject struct {
	StartSrcPort  *int          `mapstructure:"StartSrcPort" json:"StartSrcPort,omitempty"`
	ID            int           `mapstructrue:"ID" json:"ID"`
	StartDestPort *int          `mapstructure:"StartDestPort" json:"StartDestPort,omitempty"`
	EndSrcPort    *int          `mapstructure:"EndSrcPort" json:"EndSrcPort,omitempty"`
	EndDestPort   *int          `mapstructure:"EndDestPort" json:"EndDestPort,omitempty"`
	Group         string        `mapstructure:"Group" json:"Group,omitempty"`
	Type          ApiSrvObjType `mapstructure:"Type" json:"Type,omitempty"`
	ICMPType      int           `mapstructure:"ICMPType" json:"ICMPType,omitempty"`
	ICMPCode      int           `mapstructure:"ICMPCode" json:"ICMPCode,omitempty"`
	Protocol      int           `mapstructure:"Protocol" json:"Protocol,omitempty"`
	NestedGroup   string        `mapstructure:"NestedGroup" json:"NestedGroup,omitempty"`
}

func (xso *XmlServiceObject) Service() (s *service.Service, err error) {
	s = &service.Service{}

	switch xso.Type {
	case SERVICE_PROTOCOL:
		l3, l3err := service.NewL3Protocol(service.IPProto(xso.Protocol))
		err = l3err
		s.Add(l3)
	case SERVICE_ICMP:
		icmp, icmp_err := service.NewICMPProto(service.ICMP, xso.ICMPType, xso.ICMPCode)
		err = icmp_err
		s.Add(icmp)
	case SERVICE_ICMP6:
		icmp, icmp_err := service.NewICMPProto(service.ICMP6, xso.ICMPType, xso.ICMPCode)
		err = icmp_err
		s.Add(icmp)
	case SERVICE_TCP:
		s, err = service.NewServiceWithL4("tcp", fmt.Sprintf("%d-%d", *xso.StartSrcPort, *xso.EndSrcPort), fmt.Sprintf("%d-%d", *xso.StartDestPort, *xso.EndDestPort))
	case SERVICE_UDP:
		s, err = service.NewServiceWithL4("udp", fmt.Sprintf("%d-%d", *xso.StartSrcPort, *xso.EndSrcPort), fmt.Sprintf("%d-%d", *xso.StartDestPort, *xso.EndDestPort))
	default:
		panic(fmt.Sprintf("unknow service object:%+v", xso))
	}

	return
}

type XmlIPv4AdvanceAclStruct struct {
	IPFamily     network.IPFamily
	GroupIndex   string            `mapstructure:"GroupIndex"`
	RuleID       int               `mapstructure:"RuleID"`
	Action       ApiRuleActionType `mapstructure:"Action" mapstructrue:"Action"`
	ProtocolType *int              `mapstructure:"ProtocolType"`
	SrcAny       bool              `mapstructure:"SrcAny"`
	SrcIPv4      *struct {
		SrcIPv4Addr     string `mapstructure:"SrcIPv4Addr"`
		SrcIPv4Wildcard string `mapstructure:"SrcIPv4Wildcard"`
	} `mapstructure:"SrcIPv4"`
	SrcIPv6 *struct {
		SrcIPv6Addr   string `mapstructure:"SrcIPv6Addr"`
		SrcIPv6Prefix int    `mapstructure:"SrcIPv6Prefix"`
	} `mapstructure:"SrcIPv6"`
	DstAny  bool `mapstructure:"DstAny"`
	DstIPv4 *struct {
		DstIPv4Addr     string `mapstructure:"DstIPv4Addr"`
		DstIPv4Wildcard string `mapstructure:"DstIPv4Wildcard"`
	} `mapstructure:"DstIPv4"`
	SrcPort *struct {
		SrcPortOp     ApiPortOpType `mapstructure:"SrcPortOp"`
		SrcPortValue1 int           `mapstructure:"SrcPortValue1"`
		SrcPortValue2 int           `mapstructure:"SrcPortValue2"`
	} `mapstructure:"SrcPort"`
	DstPort *struct {
		DstPortOp     ApiPortOpType `mapstructure:"DstPortOp"`
		DstPortValue1 int           `mapstructure:"DstPortValue1"`
		DstPortValue2 int           `mapstructure:"DstPortValue2"`
	} `mapstructure:"DstPort"`
	DstIPv6 *struct {
		DstIPv6Addr   string `mapstructure:"DstIPv6Addr"`
		DstIPv6Prefix int    `mapstructure:"DstIPv6Prefix"`
	} `mapstructure:"DstIPv6"`
	ICMP *struct {
		ICMPType int `mapstructure:"ICMPType"`
		ICMPCode int `mapstructure:"ICMPCode"`
	} `mapstructure:"ICMP"`
	Established bool             `mapstructure:"Established"`
	Fragment    bool             `mapstructure:"Fragment"`
	Counting    bool             `mapstructure:"Counting"`
	Logging     bool             `mapstructure:"Logging"`
	Status      ApiACLStatusType `mapstructure:"Status" mapstructrue:"Status"`
	Count       int              `mapstructure:"Count"`
}

// type xmlIPv6AclStruct struct {
// GroupIndex string `mapstructure:"GroupIndex"`
// RuleID     int    `mapstructure:"RuleID"`
// Action     int    `mapstructure:"Action"`
// SrcAny     bool   `mapstructure:"SrcAny"`
// SrcIPv6    struct {
// SrcIPv6Addr   string `mapstructure:"SrcIPv6Addr"`
// SrcIPv6Prefix int    `mapstructure:"SrcIPv6Prefix"`
// } `mapstructure:"SrcIPv6"`
// RoutingTypeAny bool `mapstructure:"RoutingTypeAny"`
// Fragment       bool `mapstructure:"Fragment"`
// Counting       bool `mapstructure:"Counting"`
// Logging        bool `mapstructure:"Logging"`
// Status         int  `mapstructure:"Status"`
// Count          int  `mapstructure:"Count"`
// }
//
// type xmlIPv6AdvanceAclStruct struct {
// GroupIndex   string `mapstructure:"GroupIndex"`
// RuleID       int    `mapstructure:"RuleID"`
// Action       int    `mapstructure:"Action"`
// ProtocolType int    `mapstructure:"ProtocolType"`
// SrcAny       bool   `mapstructure:"SrcAny"`
// SrcIPv6      *struct {
// SrcIPv6Addr   string `mapstructure:"SrcIPv6Addr"`
// SrcIPv6Prefix int    `mapstructure:"SrcIPv6Prefix"`
// } `mapstructure:"SrcIPv6"`
// DstAny  bool `mapstructure:"DstAny"`
// DstIPv6 *struct {
// DstIPv6Addr   string `mapstructure:"DstIPv6Addr"`
// DstIPv6Prefix int    `mapstructure:"DstIPv6Prefix"`
// } `mapstructure:"DstIPv6"`
// RoutingTypeAny bool `mapstructure:"RoutingTypeAny"`
// DstPort        *struct {
// DstPortOp     int `mapstructure:"DstPortOp"`
// DstPortValue1 int `mapstructure:"DstPortValue1"`
// DstPortValue2 int `mapstructure:"DstPortValue2"`
// } `mapstructure:"DstPort"`
// Established bool `mapstructure:"Established"`
// Fragment    bool `mapstructure:"Fragment"`
// HopTypeAny  bool `mapstructure:"HopTypeAny"`
// Counting    bool `mapstructure:"Counting"`
// Logging     bool `mapstructure:"Logging"`
// Status      int  `mapstructure:"Status"`
// Count       int  `mapstructure:"Count"`
// }
//

type XmlSecurityPolicyStruct struct {
	Type     ApiIpType `mapstructrue:"Type" json:"Type,omitempty"`
	SeqNum   int       `mapstructrue:"SeqNum" json:"SeqNum,omitempty"`
	ID       int       `mapstructrue:"ID" json:"ID,omitempty"`
	Name     string    `mapstructrue:"Name" json:"Name,omitempty"`
	RuleName string    `mapstructrue:"RuleName" json:"RuleName,omitempty"`
	VRF      string    `mapstructrue:"VRF" json:"VRF,omitempty"`
	// Action      int    `mapstructrue:"Action"`
	Action      ApiRuleActionType `mapstructure:"Action" mapstructrue:"Action" json:"Action,omitempty"`
	SrcZoneList struct {
		SrcZoneItem []string `mapstructrue:"SrcZoneItem" json:"SrcZoneItem,omitempty"`
	} `mapstructrue:"SrcZoneList" json:"SrcZoneList,omitempty"`
	DestZoneList struct {
		DestZoneItem []string `mapstructrue:"DestZoneItem" json:"DestZoneItem,omitempty"`
	} `mapstructrue:"DestZoneList" json:"DestZoneList,omitempty"`
	SrcAddrList struct {
		SrcAddrItem []string `mapstructrue:"SrcAddrItem" json:"SrcAddrItem,omitempty"`
	} `mapstructrue:"SrcAddrList" json:"SrcAddrList,omitempty"`
	DestAddrList struct {
		DestAddrItem []string `mapstructrue:"DestAddrItem" json:"DestAddrItem,omitempty"`
	} `mapstructrue:"DestAddrList" json:"DestAddrList,omitempty"`
	ServGrpList struct {
		ServGrpItem []string `mapstructrue:"ServGrpItem" json:"ServGrpItem,omitempty"`
	} `mapstructrue:"ServGrpList" json:"ServGrpList,omitempty"`
	SrcSimpleAddrList struct {
		SrcSimpleAddrItem []string `mapstructrue:"SrcSimpleAddrItem" json:"SrcSimpleAddrItem,omitempty"`
	} `mapstructrue:"SrcSimpleAddrList" json:"SrcSimpleAddrList,omitempty"`
	DestSimpleAddrList struct {
		DestSimpleAddrItem []string `mapstructrue:"DestSimpleAddrItem" json:"DestSimpleAddrItem,omitempty"`
	} `mapstructrue:"DestSimpleAddrList" json:"DestSimpleAddrList,omitempty"`
	ServObjList struct {
		ServObjItem []string `mapstructrue:"ServObjItem" json:"ServObjItem,omitempty"`
	} `mapstructrue:"ServObjList" json:"ServObjList,omitempty"`
	Enable                 *bool `mapstructrue:"Enable" json:"Enable,omitempty"`
	Log                    bool  `mapstructrue:"Log" json:"Log,omitempty"`
	Counting               bool  `mapstructrue:"Counting" json:"Counting,omitempty"`
	Count                  int   `mapstructrue:"Count" json:"Count,omitempty"`
	Byte                   int   `mapstructrue:"Byte" json:"Byte,omitempty"`
	SessAgingTimeSw        bool  `mapstructrue:"SessAgingTimeSw" json:"SessAgingTimeSw,omitempty"`
	SessPersistAgingTimeSw bool  `mapstructrue:"SessPersistAgingTimeSw" json:"SessPersistAgingTimeSw,omitempty"`
	AllRulesCount          int   `mapstructrue:"AllRulesCount" json:"AllRulesCount,omitempty"`
}

type XmlRuleServiceStruct struct {
	ID            int                      `mapstructrue:"ID" json:"ID,omitempty"`
	StartSrcPort  *int                     `mapstructure:"StartSrcPort" json:"StartSrcPort,omitempty"`
	StartDestPort *int                     `mapstructure:"StartDestPort" json:"StartDestPort,omitempty"`
	EndSrcPort    *int                     `mapstructure:"EndSrcPort" json:"EndSrcPort,omitempty"`
	EndDestPort   *int                     `mapstructure:"EndDestPort" json:"EndDestPort,omitempty"`
	Group         string                   `mapstructure:"Group" json:"Group,omitempty"`
	Type          ApiRuleServiceObjectType `mapstructure:"Type" json:"Type"`
	ICMPType      *int                     `mapstructure:"ICMPType" json:"ICMPType,omitempty"`
	ICMPCode      *int                     `mapstructure:"ICMPCode" json:"ICMPCode,omitempty"`
	Protocol      *int                     `mapstructure:"Protocol" json:"-"`
	// NestedGroup   string        `mapstructure:"NestedGroup" json:"NestedGroup"`
}

func ServiceToXmlRuleServiceStruct(s *service.Service) []*XmlRuleServiceStruct {
	xmlList := []*XmlRuleServiceStruct{}
	one := s.MustOneServiceEntry()
	if _, ok := one.(*service.L3Protocol); ok {
		xml := XmlRuleServiceStruct{}
		if one.Protocol() == service.IP {
			xml.Type = SECPATH_SERVICE_PROTOCOL
			xml.Protocol = func(d int) *int { return &d }(0)
		} else {
			xml.Type = SECPATH_SERVICE_PROTOCOL
			xml.Protocol = func(d int) *int { return &d }(int(one.Protocol()))
			xmlList = append(xmlList, &xml)
		}
		return xmlList
	}

	switch one.Protocol() {
	case service.ICMP, service.ICMP6:
		xml := XmlRuleServiceStruct{}
		if _, ok := one.(*service.L3Protocol); ok {
			xml.Type = SECPATH_SERVICE_PROTOCOL
			xml.Protocol = func(d int) *int { return &d }(int(one.Protocol()))
			xmlList = append(xmlList, &xml)
		} else {
			xml.Type = tools.Conditional(one.Protocol() == service.ICMP, SECPATH_SERVICE_ICMP, SECPATH_SERVICE_ICMP6).(ApiRuleServiceObjectType)
			xml.Protocol = func(d int) *int { return &d }(int(one.Protocol()))
			if one.(*service.ICMPProto).IcmpType != service.ICMP_DEFAULT_TYPE {
				xml.ICMPType = func(d int) *int { return &d }(one.(*service.ICMPProto).IcmpType)
				if one.(*service.ICMPProto).IcmpCode != service.ICMP_DEFAULT_CODE {
					xml.ICMPCode = func(d int) *int { return &d }(one.(*service.ICMPProto).IcmpCode)
				}
			}
			xmlList = append(xmlList, &xml)
		}
	case service.TCP, service.UDP:
		s := one.(*service.L4Service)
		srcPort := s.SrcPort()
		if srcPort == nil {
			srcPort, _ = service.NewL4Port(service.RANGE, 0, 65535, 0)
		}

		dstPort := s.DstPort()
		if dstPort == nil {
			dstPort, _ = service.NewL4Port(service.RANGE, 0, 65535, 0)
		}
		if len(srcPort.List()) > 1 && len(dstPort.List()) > 1 {
			panic("current not support complex service")
		}

		for srcIt := srcPort.Iterator(); srcIt.HasNext(); {
			_, s := srcIt.Next()
			for dstIt := dstPort.Iterator(); dstIt.HasNext(); {
				_, d := dstIt.Next()

				xml := XmlRuleServiceStruct{}
				xml.Type = tools.Conditional(one.Protocol() == service.TCP, SECPATH_SERVICE_TCP, SECPATH_SERVICE_UDP).(ApiRuleServiceObjectType)
				xml.Protocol = func(d int) *int { return &d }(int(one.Protocol()))

				xml.StartSrcPort = func(d int) *int { return &d }(int(s.Low().Int64()))
				xml.EndSrcPort = func(d int) *int { return &d }(int(s.High().Int64()))
				xml.StartDestPort = func(d int) *int { return &d }(int(d.Low().Int64()))
				xml.EndDestPort = func(d int) *int { return &d }(int(d.High().Int64()))
				xmlList = append(xmlList, &xml)
			}
		}

	default:
		panic("unknow error")
	}
	return xmlList
}

func (xrs *XmlRuleServiceStruct) Service() (s *service.Service, err error) {
	s = &service.Service{}
	switch xrs.Type {
	case SECPATH_SERVICE_PROTOCOL:
		l3, l3err := service.NewL3Protocol(service.IPProto(*xrs.Protocol))
		err = l3err
		s.Add(l3)
	case SECPATH_SERVICE_ICMP:
		icmp, icmp_err := service.NewICMPProto(service.ICMP, *xrs.ICMPType, *xrs.ICMPCode)
		err = icmp_err
		s.Add(icmp)
	case SECPATH_SERVICE_ICMP6:
		icmp, icmp_err := service.NewICMPProto(service.ICMP6, *xrs.ICMPType, *xrs.ICMPCode)
		err = icmp_err
		s.Add(icmp)
	case SECPATH_SERVICE_TCP:
		s, err = service.NewServiceWithL4("tcp", fmt.Sprintf("%d-%d", *xrs.StartSrcPort, *xrs.EndSrcPort), fmt.Sprintf("%d-%d", *xrs.StartDestPort, *xrs.EndDestPort))
	case SECPATH_SERVICE_UDP:
		s, err = service.NewServiceWithL4("udp", fmt.Sprintf("%d-%d", *xrs.StartSrcPort, *xrs.EndSrcPort), fmt.Sprintf("%d-%d", *xrs.StartDestPort, *xrs.EndDestPort))
	default:
		panic(fmt.Sprintf("unknow service object:%+v", xrs))
	}

	return
}

type XmlSecurityPolicyObject struct {
	ID       int `mapstructrue:"ID" json:"ID,omitempty"`
	SeqNum   int `mapstructrue:"SeqNum" json:"SeqNum"`
	NameList struct {
		NameItem []string `json:"NameItem"`
	} `json:"NameList"`
}

type XmlSecurityPolicyAddNetwork struct {
	ID             int `mapstructrue:"ID" json:"ID,omitempty"`
	SeqNum         int `mapstructrue:"SeqNum" json:"SeqNum"`
	SimpleAddrList struct {
		SimpleAddrItem []string
	}
}
type XmlSecurityPolicyAddNService struct {
	ID          int `mapstructrue:"ID" json:"ID,omitempty"`
	ServObjList struct {
		ServObjItem []string
	}
}
