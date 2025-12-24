package model

import (
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/tools"
)

// NodeType 节点类型
type NodeType string

const (
	NodeTypeRouter   NodeType = "router"
	NodeTypeFirewall NodeType = "firewall"
	NodeTypeLB       NodeType = "lb"
	NodeTypeSwitch   NodeType = "switch"
)

// Node 节点接口（抽象，不依赖具体设备类型）
type Node interface {
	ID() string
	Name() string
	Type() NodeType

	// 路由表管理
	GetRouteTable(vrf string, ipFamily network.IPFamily) (*RouteTable, error)
	SetRouteTable(vrf string, ipFamily network.IPFamily, table *RouteTable) error

	// 路由查询
	QueryRoute(dst network.NetworkList, inPort, vrf string, ipFamily network.IPFamily) (*RouteResult, error)

	// 端口管理
	GetPort(portID string) (Port, error)
	GetPortByName(name string) (Port, error)
	ListPorts() []Port
}

// Port 端口接口
type Port interface {
	ID() string
	Name() string
	VRF() string
	Node() Node
	IPAddresses(ipFamily network.IPFamily) []string
	ConnectorID() string
}

// Connector 连接器接口
type Connector interface {
	ID() string
	SelectNodeByIP(ip, vrf string) (Node, Port, error)
	SelectPortsByNetwork(net network.AbbrNet, vrf string) []Port
	HitByNetwork(net network.AbbrNet, vrf string) bool
	HitByIp(ip, vrf string) bool
}

// RouteTable 路由表
type RouteTable struct {
	VRF      string
	IPFamily network.IPFamily
	table    *network.AddressTable
}

// NewRouteTable 创建路由表
func NewRouteTable(vrf string, ipFamily network.IPFamily) *RouteTable {
	return &RouteTable{
		VRF:      vrf,
		IPFamily: ipFamily,
		table:    network.NewAddressTable(ipFamily),
	}
}

// AddRoute 添加路由
func (rt *RouteTable) AddRoute(net *network.IPNet, nextHop *network.NextHop) error {
	return rt.table.PushRoute(net, nextHop)
}

// QueryRoute 查询路由
func (rt *RouteTable) QueryRoute(dst network.NetworkList) (*RouteMatchResult, error) {
	rmr := rt.table.MatchNetList(dst, true, false)

	// 如果 Unmatch 不为空，说明有未匹配的网络
	// 在这种情况下，调用 Table() 可能会出现问题，需要先检查
	var match *tools.Table
	var unmatch *tools.Table

	// 使用 recover 来捕获可能的 panic
	func() {
		defer func() {
			if r := recover(); r != nil {
				// 如果发生 panic，说明 Table() 方法无法处理当前状态
				// 这种情况下，match 和 unmatch 都保持为 nil
				match = nil
				unmatch = nil
			}
		}()
		match, _ = rmr.Table()
	}()

	// 检查是否有未匹配的网络
	if rmr.Unmatch != nil && rmr.Unmatch.Len() > 0 {
		// 如果 Unmatch 有值，表示有未匹配的网络
		// 这里暂时不转换 Unmatch 为 Table，只标记有未匹配的
		unmatch = nil // 保持为 nil，但可以通过检查 Match 是否为 nil 来判断
	}

	return &RouteMatchResult{
		Match:   match,
		Unmatch: unmatch,
	}, nil
}

// GetDefaultGateway 获取默认网关
func (rt *RouteTable) GetDefaultGateway() *network.NextHop {
	// DefaultGw() 返回的是 *flexrange.Entry，需要转换为 *network.NextHop
	// 这里暂时返回nil，需要根据实际情况实现
	return nil
}

// NewRouteTableFromAddressTable 从AddressTable创建RouteTable
func NewRouteTableFromAddressTable(vrf string, ipFamily network.IPFamily, table *network.AddressTable) *RouteTable {
	return &RouteTable{
		VRF:      vrf,
		IPFamily: ipFamily,
		table:    table,
	}
}

// GetAddressTable 获取AddressTable
func (rt *RouteTable) GetAddressTable() *network.AddressTable {
	return rt.table
}

// RouteMatchResult 路由匹配结果
type RouteMatchResult struct {
	Match   *tools.Table
	Unmatch *tools.Table
}
