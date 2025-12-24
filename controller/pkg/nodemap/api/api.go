package api

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/tools"
	"github.com/netxops/utils/validator"

	"gorm.io/gorm"
)

type NodeType int

const (
	_ NodeType = iota
	ROUTER
	FIREWALL
	LB
)

func (nt NodeType) String() string {
	return []string{"ROUTER", "FIREWALL", "LB"}[nt-1]
}

type FhrpMode int

const (
	NONE FhrpMode = iota
	HSRP
	VRRP
)

func (m FhrpMode) String() string {
	return []string{"NONE", "HSRP", "VRRP"}[m]
}

func ToMode(mode string) FhrpMode {
	for index, m := range []string{"HSRP", "VRRP"} {
		if strings.ToLower(m) == strings.ToLower(mode) {
			return FhrpMode(index + 1)
		}
	}
	return NONE
}

type Mode int

const (
	P2P Mode = iota + 1
	MP
)

func (m Mode) String() string {
	return []string{"P2P", "MP"}[m-1]
}

type PortStatus int

const (
	UNKNOWN PortStatus = iota
	DOWN
	UP
)

func (p PortStatus) String() string {
	return []string{"UNKNOWN", "DOWN", "UP"}[p]
}

func NewPortStatusFromString(status string) PortStatus {
	m := map[string]PortStatus{
		"UNKNOWN": UNKNOWN,
		"DOWN":    DOWN,
		"UP":      UP,
	}

	if value, ok := m[strings.ToUpper(status)]; !ok {
		panic(fmt.Sprintf("invalid port status: {%s}", status))
	} else {
		return value
	}

}

type JSONSerializer interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

type TypedInterface interface {
	TypeName() string
}

type Member interface {
	TypedInterface
	JSONSerializer
	IsActive() bool
	Hit(ip string) bool
	Ip() string
	FhrpMode() FhrpMode
	PortName() string
}

type FhrpGroup interface {
	TypedInterface
	JSONSerializer
	AddMember(member Member)
	Active() Member
	GroupIp() string
}

type Vrf interface {
	TypedInterface
	JSONSerializer
	Name() string
	Ipv4Table() *network.AddressTable
	Ipv6Table() *network.AddressTable
}

type Port interface {
	TypedInterface
	JSONSerializer
	ID() string
	Name() string
	Node() Node
	// Connector() Connector
	ConnectorID() string
	// AttachToConnector(connector Connector)
	Members() []Member
	AliasName() []string
	PeerVrf() []string
	Vrf() string
	AddIpv6(ip string)
	AddIpv4(ip string)
	Ipv4List() []string
	Ipv6List() []string
	V4NetworkGroup() *network.NetworkGroup
	V6NetworkGroup() *network.NetworkGroup

	HitByNetwork(net network.AbbrNet) bool
	FullMatchByIp(ip, vrf string) bool
	HitByIpWithoutPrefix(target, vrf string) bool
	HitByIp(target, vrf string) bool
	HitByIfIndex(ifIndex int) bool
	MatchVrfOrPeerVrf(name string) bool
	HitByName(name string) bool
	IfIndex() int

	WithStatus(status string) Port
	WithNode(node Node) Port
	WithVrf(vrf string) Port
	WithPeerVrf(name string) Port
	WithAliasName(name string) Port
	GetIpList() map[network.IPFamily][]string
	FlattenName() string
	FlattenPath() []string
	NetworkGroup() *network.NetworkGroup
	WithID(id string) Port
	// WithConnector(c Connector)
	WithConnectorID(id string)
	// Area related methods
	WithArea(areaName string, ipFamily network.IPFamily) Port
	Area(ipFamily network.IPFamily) string
	// StubArea related methods
	WithStubArea(isStubArea bool, ipFamily network.IPFamily) Port
	IsStubArea(ipFamily network.IPFamily) bool
}

// PortIterator 定义了一个接口，用于从 NodeMap 中获取 Port 对象
type PortIterator interface {
	// GetPort 根据端口引用（名称或ID）返回对应的 Port 对象
	GetPort(ref string) Port
	// GetAllPorts 返回所有的 Port 对象
	GetAllPorts() []Port
}

type AdapterType int

const (
	LiveAdapter AdapterType = iota
	StringAdapter
)

type Adapter interface {
	ParseName(force bool) string
	PortList(force bool) []Port
	RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable)
	GetConfig(force bool) interface{}
	BatchRun(interface{}) (interface{}, error)
	BatchConfig(p ...interface{}) (interface{}, error)
	TaskId() uint
	AttachChannel(out chan string) bool
	Info(bool) (*device.DeviceBaseInfo, error)
	GetRawConfig(string, bool) (any, error)
}

type Node interface {
	TypedInterface
	JSONSerializer
	WithID(id string) Node
	ID() string
	GetOrCreateVrf(name string) Vrf
	GetVrf(name string) Vrf

	SetIpv4RouteTable(vrfName string, table *network.AddressTable)
	SetIpv6RouteTable(vrfName string, table *network.AddressTable)
	GetPortByNameOrAlias(name string) Port
	GetPortByIfIndex(ifIndex int) Port
	GetPortByID(id string) Port
	AddPort(port Port, connection []*config.ConnectionInfo)
	FlattenPath() []string
	FlattenName() string
	WithNodeMap(name string) Node
	WithName(name string) Node
	Ipv4RouteTable(vrfName string) *network.AddressTable
	Ipv6RouteTable(vrfName string) *network.AddressTable
	Ipv6RouteCheck(netList network.NetworkList, inPort, vrf string) (bool, *tools.Table, []string, error)
	Ipv4RouteCheck(netList network.NetworkList, inPort, vrf string) (bool, *tools.Table, []string, error)
	IpRouteCheck(netList network.NetworkList, inPort, vrf string, af network.IPFamily) (bool, *tools.Table, []string, error)
	Name() string
	Vrfs() []Vrf
	PortList() []Port
	PortRefs() []string
	WithCmdIp(ip string)
	CmdIp() string
	NodeType() NodeType
	WithPortIterator(iterator PortIterator) Node

	SetDeviceConfig(deviceConfig *config.DeviceConfig)
	GetDeviceConfig() *config.DeviceConfig

	ExtraInit(adapter Adapter, deviceConfig *config.DeviceConfig)
}

type ConnectorCatalog int

const (
	_ ConnectorCatalog = iota
	NODE_CONNECTOR
)

type Connector interface {
	TypedInterface
	JSONSerializer
	ID() string
	Verify(port Port) validator.Result
	GetOrCreateFhrpGroup(groupIp string, mode FhrpMode) FhrpGroup
	PortCount() int
	Port(name string) Port
	Attach(port Port)
	SelectPortListByNetwork(net network.AbbrNet, vrf string) []Port
	HitByNetwork(net network.AbbrNet, vrf string) bool
	HitByIp(ipWithPrefix, vrf string) bool
	SelectNodeByIp(ip, vrf string) (Node, Port)
	AddFhrpGroupMember(member Member)
	// NetworkList() []map[network.IPFamily][]string
	IPv4List() StringList
	IPv6List() StringList
	PortList() []Port
	Mode() Mode
	WithPortIterator(iterator PortIterator)
}

type NodeSession interface {
	BatchRun(cmds interface{}, stopOnError bool) error
}

type StringList []string

func (m *StringList) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal []string value:", value))
	}

	err := json.Unmarshal(bytes, m)
	return err
}

func (m StringList) Value() (driver.Value, error) {
	if len(m) == 0 {
		return nil, nil
	}

	return json.Marshal(&m)
}

func (StringList) GormDataType() string {
	return "string_list"
}

type ByteList []byte

func (m *ByteList) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal []byte value:", value))
	}

	err := json.Unmarshal(bytes, m)
	return err
}

func (m ByteList) Value() (driver.Value, error) {
	if len(m) == 0 {
		return nil, nil
	}

	return json.Marshal(&m)
}

func (ByteList) GormDataType() string {
	return "byte_list"
}

func (m ByteList) MarshalJSON() (b []byte, err error) {
	var data []string
	for _, d := range m {
		data = append(data, fmt.Sprintf("%d", d))
	}

	return json.Marshal(data)
}

func (m *ByteList) UnmarshalJSON(b []byte) error {
	var data []string

	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	for _, d := range data {
		byteData, err := strconv.Atoi(d)
		if err != nil {
			return err
		}

		*m = append(*m, byte(byteData))
	}

	return nil
}

type FirewallDumper interface {
	ServiceObjectToDb(*gorm.DB, uint)
	NetworkObjectToDb(*gorm.DB, uint)
	PolicyToDb(*gorm.DB, uint)
	AclToDb(*gorm.DB, uint)
	AddressGroupToDb(*gorm.DB, uint)
	NatsToDb(*gorm.DB, uint)
	ExtraToDb(*gorm.DB, uint)
}
