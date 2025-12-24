package nodemap

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TyphonHill/go-mermaid/diagrams/flowchart"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"

	"sync"

	"github.com/netxops/utils/graph"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/tools"
	"github.com/netxops/utils/validator"

	"go.uber.org/zap"
)

var _ api.PortIterator = (*NodeMap)(nil)

// RedisClient 定义 Redis 客户端接口，用于统一不同版本的 Redis 客户端
type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
}

// redisV8Adapter 适配器，用于包装 go-redis/v8 的客户端
type redisV8Adapter struct {
	client *redis.Client
}

// Set 实现 RedisClient 接口
func (r *redisV8Adapter) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// NewRedisV8Adapter 创建一个新的 redisV8Adapter
func NewRedisV8Adapter(client *redis.Client) RedisClient {
	return &redisV8Adapter{client: client}
}

// NodeLocator 节点定位器，封装节点定位逻辑
type NodeLocator struct {
	nodeMap *NodeMap
	logger  *zap.Logger
}

type NodeMap struct {
	Name              string
	Ports             []api.Port
	Nodes             []api.Node
	Ipv4Areas         []*config.AreaInfo
	Ipv6Areas         []*config.AreaInfo
	Ipv4SecurityZones []*config.SecurityZoneInfo
	Ipv6SecurityZones []*config.SecurityZoneInfo
	Ipv4Stubs         []*StubInfo
	Ipv6Stubs         []*StubInfo
	CxMananger        *ConnectorManager
	TNodeMapID        *uint
	logger            *zap.Logger
	taskId            uint
	mutex             sync.Mutex
	redisClient       RedisClient // Redis 客户端，用于进度更新
	// Ctx        context.Context
}

// nodeMapJSON 用于序列化和反序列化
type nodeMapJSON struct {
	Name              string                     `json:"name"`
	Ports             []json.RawMessage          `json:"ports"`
	Nodes             []json.RawMessage          `json:"nodes"`
	Ipv4Areas         []*config.AreaInfo         `json:"ipv4Areas"`
	Ipv6Areas         []*config.AreaInfo         `json:"ipv6Areas"`
	Ipv4SecurityZones []*config.SecurityZoneInfo `json:"ipv4SecurityZones"`
	Ipv6SecurityZones []*config.SecurityZoneInfo `json:"ipv6SecurityZones"`
	Ipv4Stubs         []stubInfoJSON             `json:"ipv4Stubs"`
	Ipv6Stubs         []stubInfoJSON             `json:"ipv6Stubs"`
	CxMananger        *ConnectorManager          `json:"cxManager"`
	TNodeMapID        *uint                      `json:"tNodeMapID,omitempty"`
	TaskId            uint                       `json:"taskId"`
}

type stubInfoJSON struct {
	NodeID string `json:"node_id"`
	PortID string `json:"port_id"`
}

// MarshalJSON 实现 JSON 序列化
func (nm *NodeMap) MarshalJSON() ([]byte, error) {
	ports, err := registry.InterfacesToRawMessages(nm.Ports)
	if err != nil {
		return nil, err
	}

	nodes, err := registry.InterfacesToRawMessages(nm.Nodes)
	if err != nil {
		return nil, err
	}

	nmj := nodeMapJSON{
		Name:              nm.Name,
		Ports:             ports,
		Nodes:             nodes,
		Ipv4Areas:         nm.Ipv4Areas,
		Ipv6Areas:         nm.Ipv6Areas,
		Ipv4SecurityZones: nm.Ipv4SecurityZones,
		Ipv6SecurityZones: nm.Ipv6SecurityZones,
		Ipv4Stubs:         stubsToJSON(nm.Ipv4Stubs),
		Ipv6Stubs:         stubsToJSON(nm.Ipv6Stubs),
		CxMananger:        nm.CxMananger,
		TNodeMapID:        nm.TNodeMapID,
		TaskId:            nm.taskId,
	}

	return json.Marshal(nmj)
}

// UnmarshalJSON 实现 JSON 反序列化
func (nm *NodeMap) UnmarshalJSON(data []byte) error {
	var nmj nodeMapJSON
	if err := json.Unmarshal(data, &nmj); err != nil {
		return err
	}

	ports, err := registry.RawMessagesToInterfaces[api.Port](nmj.Ports)
	if err != nil {
		return err
	}

	nodes, err := registry.RawMessagesToInterfaces[api.Node](nmj.Nodes)
	if err != nil {
		return err
	}

	nm.Name = nmj.Name
	nm.Ports = ports
	nm.Nodes = nodes
	nm.Ipv4Areas = nmj.Ipv4Areas
	nm.Ipv6Areas = nmj.Ipv6Areas
	nm.Ipv4SecurityZones = nmj.Ipv4SecurityZones
	nm.Ipv6SecurityZones = nmj.Ipv6SecurityZones
	nm.Ipv4Stubs = jsonToStubs(nmj.Ipv4Stubs, nm)
	nm.Ipv6Stubs = jsonToStubs(nmj.Ipv6Stubs, nm)
	nm.CxMananger = nmj.CxMananger
	nm.TNodeMapID = nmj.TNodeMapID
	nm.taskId = nmj.TaskId
	nm.mutex = sync.Mutex{}

	for i, node := range nm.Nodes {
		node.WithNodeMap(nm.Name)
		node.WithPortIterator(nm)
		for _, port := range node.PortList() {
			port.WithNode(nm.Nodes[i])
		}
	}

	for _, c := range nm.CxMananger.ConnectorList {
		c.WithPortIterator(nm)
	}

	for _, stub := range nmj.Ipv4Stubs {
		node := nm.GetNodeById(stub.NodeID)
		port := node.GetPortByID(stub.PortID)
		stubInfo := &StubInfo{
			Node: node,
			Port: port,
		}
		nm.Ipv4Stubs = append(nm.Ipv4Stubs, stubInfo)
	}

	for _, stub := range nmj.Ipv6Stubs {
		node := nm.GetNodeById(stub.NodeID)
		port := node.GetPortByID(stub.PortID)
		stubInfo := &StubInfo{
			Node: node,
			Port: port,
		}
		nm.Ipv6Stubs = append(nm.Ipv6Stubs, stubInfo)
	}

	return nil
}

func (NodeMap) TableName() string {
	return "nodemap"
}

func (nm *NodeMap) FlattenPath() []string {
	return []string{nm.Name}
}

func (nm *NodeMap) FlattenName() string {
	return nm.Name
}

// GetPort 根据端口引用（名称或ID）返回对应的 Port 对象
func (nm *NodeMap) GetPort(ref string) api.Port {
	// 首先尝试通过ID匹配（这是主要方式，因为portRefs存储的是ID）
	for _, port := range nm.Ports {
		if port.ID() == ref {
			return port
		}
	}
	// 如果通过ID找不到，尝试通过名称匹配（用于向后兼容）
	for _, port := range nm.Ports {
		if port.HitByName(ref) {
			return port
		}
	}
	return nil
}

// GetAllPorts 返回所有的 Port 对象
func (nm *NodeMap) GetAllPorts() []api.Port {
	return nm.Ports
}

// func (nm *NodeMap) WithContent(ctx context.Context) {
// 	nm.Ctx = ctx
// }

func (nm *NodeMap) WithLogger(logger *zap.Logger) {
	nm.logger = logger
}

// WithRedisClient 设置 Redis 客户端
func (nm *NodeMap) WithRedisClient(client RedisClient) {
	nm.redisClient = client
}

func (nm *NodeMap) SetStubInterface(nodeName, portName string, ipType network.IPFamily) {
	// fmt.Println("============================11111:", nodeName, portName, ipType)
	node := nm.GetNode(nodeName)
	if node == nil {
		panic(fmt.Sprintf("can not find %s", nodeName))
	}

	port := node.GetPortByNameOrAlias(portName)
	if port == nil {
		panic(fmt.Sprintf("can not find interface %s on %s", portName, nodeName))
	}

	var stubList []*StubInfo
	stubList = append(stubList, &StubInfo{
		Node: node,
		Port: port,
	})

	// 设置 stub area 标记到 port
	port.WithStubArea(true, ipType)

	// var routeTable *network.AddressTable
	if ipType == network.IPv4 {
		// routeTable = n.Ipv4RouteTable(port.Vrf())
		nm.Ipv4Stubs = append(nm.Ipv4Stubs, stubList...)
	} else {
		// routeTable = n.Ipv6RouteTable(port.Vrf())
		nm.Ipv6Stubs = append(nm.Ipv6Stubs, stubList...)
	}

	for _, stub := range stubList {
		if stub.Node.FlattenName() == node.FlattenName() && stub.Port.FlattenName() == port.FlattenName() {
			return
		}
	}
}

func (nm *NodeMap) IsStubPort(node api.Node, port api.Port, ipType network.IPFamily) bool {

	var stubList []*StubInfo
	if ipType == network.IPv4 {
		stubList = append(stubList, nm.Ipv4Stubs...)
	} else {
		stubList = append(stubList, nm.Ipv6Stubs...)
	}

	for _, stub := range stubList {
		if stub.Node.FlattenName() == node.FlattenName() && stub.Port.FlattenName() == port.FlattenName() {
			return true
		}
	}

	return false
}

// func (nm *NodeMap) SetOutside(nodeName, portName, areaName string, ipv4, force bool) {
// 	n := nm.GetNode(nodeName)
// 	if n == nil {
// 		panic(fmt.Sprintf("can not find %s", nodeName))
// 	}

// 	port := n.GetPort(portName)
// 	if port == nil {
// 		panic(fmt.Sprintf("can not find interface %s on %s", portName, nodeName))
// 	}

// 	var areaList []*config.AreaInfo
// 	var routeTable *network.AddressTable
// 	if ipv4 {
// 		routeTable = n.Ipv4RouteTable(port.Vrf())
// 		areaList = nm.Ipv4Areas
// 	} else {
// 		routeTable = n.Ipv6RouteTable(port.Vrf())
// 		areaList = nm.Ipv6Areas
// 	}

// 	if routeTable.DefaultGw() == nil {
// 		panic(fmt.Sprintf("default gateway is not exist on %s, set outside failed", nodeName))
// 	}

// 	ports := routeTable.OutputInterface(routeTable.DefaultGw())

// 	portNameList := []string{}
// 	for _, name := range port.AliasName() {
// 		portNameList = append(portNameList, name)
// 	}
// 	portNameList = append(portNameList, port.Name())

// 	if len(tools.Intersection(ports, portNameList)) == 0 {
// 		panic(fmt.Sprintf("set outside failed, [%v] not int [%v]", ports, portNameList))
// 	}
// 	//
// 	if port.Connector().PortCount() > 1 {
// 		// 注意: 需要保持Connector中只有一个接口，为了达到这个条件，可能需要忽略掉一台外部设备
// 		panic("set outside failed")
// 	}

// 	areaList = append(areaList, &config.AreaInfo{
// 		Interface: portName,
// 		Name:      areaName,
// 		NodeName:  nodeName,
// 		Force:     force,
// 	})
// 	if ipv4 {
// 		nm.Ipv4Areas = areaList
// 	} else {
// 		nm.Ipv6Areas = areaList
// 	}
// }

func (nm *NodeMap) SetOutside(nodeName, portName, areaName string, ipv4, force bool) {
	n := nm.GetNode(nodeName)
	if n == nil {
		panic(fmt.Sprintf("can not find %s", nodeName))
	}

	port := n.GetPortByNameOrAlias(portName)
	if port == nil {
		panic(fmt.Sprintf("can not find interface %s on %s", portName, nodeName))
	}

	var areaList []*config.AreaInfo
	// var routeTable *network.AddressTable
	if ipv4 {
		// routeTable = n.Ipv4RouteTable(port.Vrf())
		areaList = nm.Ipv4Areas
	} else {
		// routeTable = n.Ipv6RouteTable(port.Vrf())
		areaList = nm.Ipv6Areas
	}

	// if routeTable.DefaultGw() == nil {
	// 	panic(fmt.Sprintf("default gateway is not exist on %s, set outside failed", nodeName))
	// }

	// ports := routeTable.OutputInterface(routeTable.DefaultGw())

	// portNameList := []string{}
	// for _, name := range port.AliasName() {
	// 	portNameList = append(portNameList, name)
	// }
	// portNameList = append(portNameList, port.Name())

	// if len(tools.Intersection(ports, portNameList)) == 0 {
	// 	panic(fmt.Sprintf("set outside failed, [%v] not int [%v]", ports, portNameList))
	// }
	//

	portConnector := nm.CxMananger.GetConnectorByID(port.ConnectorID())
	if portConnector != nil && portConnector.PortCount() > 1 {
		panic("set outside failed")
	}

	// if port.Connector().PortCount() > 1 {
	// 	// 注意: 需要保持Connector中只有一个接口，为了达到这个条件，可能需要忽略掉一台外部设备
	// 	panic("set outside failed")
	// }

	// 设置 area 信息到 port
	var ipFamily network.IPFamily
	if ipv4 {
		ipFamily = network.IPv4
	} else {
		ipFamily = network.IPv6
	}
	port.WithArea(areaName, ipFamily)

	areaList = append(areaList, &config.AreaInfo{
		Interface: portName,
		Name:      areaName,
		NodeName:  nodeName,
		Force:     force,
	})
	if ipv4 {
		nm.Ipv4Areas = areaList
	} else {
		nm.Ipv6Areas = areaList
	}
}

func (nm *NodeMap) GetPortsByArea(area string, ipFamily network.IPFamily) []api.Port {
	var ports []api.Port
	var areas []*config.AreaInfo

	if ipFamily == network.IPv4 {
		areas = nm.Ipv4Areas
	} else {
		areas = nm.Ipv6Areas
	}

	for _, areaInfo := range areas {
		if areaInfo.Name == area {
			node := nm.GetNode(areaInfo.NodeName)
			if node != nil {
				port := node.GetPortByNameOrAlias(areaInfo.Interface)
				if port != nil {
					ports = append(ports, port)
				}
			}
		}
	}

	return ports
}

// func (nm *NodeMap) IsOutsidePort(nodeName, portName string, af network.IPFamily) bool {
// 	var areas []*config.AreaInfo
// 	if af == network.IPv4 {
// 		areas = nm.Ipv4Areas
// 	} else {
// 		areas = nm.Ipv6Areas
// 	}

// 	n := nm.GetNode(nodeName)

// 	port := n.GetPort(portName)

// 	for _, area := range areas {
// 		if area.NodeName == nodeName {
// 			if port.HitByName(area.Interface) {
// 				return true
// 			}
// 		}
// 	}

// 	return false
// }

func (nm *NodeMap) IsOutsidePort(nodeName, portName string, af network.IPFamily) (bool, string) {
	var areas []*config.AreaInfo
	if af == network.IPv4 {
		areas = nm.Ipv4Areas
	} else {
		areas = nm.Ipv6Areas
	}

	n := nm.GetNode(nodeName)
	if n == nil {
		return false, ""
	}

	port := n.GetPortByNameOrAlias(portName)
	if port == nil {
		return false, ""
	}

	for _, area := range areas {
		if area.NodeName == nodeName {
			if port.HitByName(area.Interface) {
				return true, area.Name
			}
		}
	}

	return false, ""
}

func (nm *NodeMap) GetNode(name string) api.Node {
	for _, node := range nm.Nodes {
		if node.Name() == name || node.FlattenName() == name {
			return node
		}
	}

	return nil
}

func (nm *NodeMap) GetNodeById(id string) api.Node {
	for _, node := range nm.Nodes {
		if node.ID() == id {
			return node
		}
	}

	return nil
}

func (nm *NodeMap) AddNode(n api.Node, connections []*config.ConnectionInfo) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	// 分配一个新的 ID
	newID := len(nm.Nodes) + 1
	n.WithID(fmt.Sprintf("node_%d", newID))
	n.WithNodeMap(nm.Name)

	for _, port := range n.PortList() {
		c := nm.CxMananger.GetOrCreateConnectorByPort(port, connections)
		c.WithPortIterator(nm)
		nm.AttachToConnector(port, c)

		for _, member := range port.Members() {
			c.AddFhrpGroupMember(member)
		}
	}

	nm.Nodes = append(nm.Nodes, n)
}

// NewNodeLocator 创建新的节点定位器
func NewNodeLocator(nm *NodeMap) *NodeLocator {
	return &NodeLocator{
		nodeMap: nm,
		logger:  nm.logger,
	}
}

// Locator 返回节点定位器实例
func (nm *NodeMap) Locator() *NodeLocator {
	return NewNodeLocator(nm)
}

func (nm *NodeMap) SelectPortListByNetwork(net network.AbbrNet, vrf string) []api.Port {
	c := nm.CxMananger.GetConnectorByNetwork(net, vrf)
	if c == nil {
		return []api.Port{}
	}

	return c.SelectPortListByNetwork(net, vrf)
}

func (nm *NodeMap) LocateStubNode(netList *network.NetworkList, vrf string, ipType network.IPFamily) (bool, api.Node, api.Port) {
	var stubList []*StubInfo
	if ipType == network.IPv4 {
		stubList = nm.Ipv4Stubs
	} else {
		stubList = nm.Ipv6Stubs
	}

	for _, stub := range stubList {
		var routeTable *network.AddressTable
		if ipType == network.IPv4 {
			routeTable = stub.Node.Ipv4RouteTable(stub.Port.Vrf())
		} else {
			routeTable = stub.Node.Ipv6RouteTable(stub.Port.Vrf())
		}

		// 如果路由表不存在，跳过
		if routeTable == nil {
			continue
		}

		routeTable.Pretty()
		rmr := routeTable.MatchNetList(*netList, false, true)

		if !rmr.IsFullMatch() {
			continue
		}

		match, _ := rmr.Table()
		match.PrettyPrint()
		nextPorts := match.Column("interface").List().Distinct()

		if len(nextPorts) > 1 {
			panic("current not support multiple stub interface")
		} else if len(nextPorts) == 1 {
			port := stub.Node.GetPortByNameOrAlias(nextPorts[0].(string))
			if tools.IsNil(port) {
				panic("unknown error")
			}
			if port.FlattenName() == stub.Port.FlattenName() {
				return true, stub.Node, port
				// continue
			}

			// return true, stub.Node, port
		} else {
			panic("unknown error")
		}
	}

	return false, nil, nil
}

// LocateNode 定位节点（备份方法，保留用于向后兼容）
// 新的实现请使用 NodeLocator.Locate 方法
func (nm *NodeMap) LocateNode(srcnetList *network.NetworkList, dstnetList *network.NetworkList, nodeName, vrf, gw, area string) (bool, api.Node, string) {
	logger := nm.logger.With(
		zap.String("function", "LocateNode"),
		zap.String("vrf", vrf),
		zap.String("gw", gw),
		zap.String("area", area),
		zap.String("inputNodeName", nodeName),
	)

	if nodeName != "" {
		node := nm.GetNode(nodeName)
		// node.IpRouteCheck(*srcnetList)
		if area != "" {
			var areaInfoList []*config.AreaInfo
			if srcnetList.Type() == network.IPv4 {
				areaInfoList = nm.Ipv4Areas
			} else {
				areaInfoList = nm.Ipv6Areas
			}
			for _, areaInfo := range areaInfoList {
				if areaInfo.Name == area && areaInfo.NodeName == nodeName {
					return true, node, areaInfo.Interface
				}
			}
			return false, nil, "Area not found."
		} else {
			_, _, outPorts, err := node.IpRouteCheck(*srcnetList, "", vrf, srcnetList.Type())
			if err != nil {
				logger.Error("Check route failed", zap.Error(err))
				return false, nil, err.Error()
			}
			if len(outPorts) == 0 {
				logger.Info("No matching ports found")
				return false, nil, "No matching ports found."
			}
			if len(outPorts) > 1 {
				logger.Info("Multiple matching ports found", zap.Int("count", len(outPorts)))
				return false, nil, "Multiple matching ports found."
			}
			return true, node, outPorts[0]
		}
	}

	portList := []api.Port{}
	portListMap := map[api.Port]bool{}
	for _, net := range srcnetList.List() {
		ps := nm.SelectPortListByNetwork(net, vrf)
		for _, p := range ps {
			portListMap[p] = true
		}
	}

	logger.Debug("Port list map", zap.Any("portListMap", portListMap))

	if len(portListMap) == 0 {
		logger.Info("No matching ports found, checking stub nodes")
		stubOk, stubNode, stubPort := nm.LocateStubNode(srcnetList, vrf, srcnetList.Type())
		if stubOk {
			logger.Info("Stub node found", zap.String("node", stubNode.Name()), zap.String("port", stubPort.Name()))
			return stubOk, stubNode, stubPort.Name()
		}

		nodeList := nm.WhichNodeHasOutside(vrf, srcnetList.Type())
		logger.Debug("Nodes with outside connections", zap.Int("count", len(nodeList)))

		if len(nodeList) == 0 {
			// 如果没有 outside 节点，检查 nodemap 中是否只有一台设备
			// 如果只有一台设备，通过路由查询接口检查是否能匹配接口
			if len(nm.Nodes) == 1 {
				node := nm.Nodes[0]
				logger.Info("Only one device in nodemap, checking route match", zap.String("node", node.Name()))

				// 通过路由查询接口检查是否能匹配接口
				ok, _, outPorts, err := node.IpRouteCheck(*srcnetList, "", vrf, srcnetList.Type())
				if err != nil {
					logger.Warn("Route check failed for single device", zap.Error(err))
					return false, nil, fmt.Sprintf("Route check failed: %v", err)
				}
				if ok && len(outPorts) == 1 {
					portName := outPorts[0]
					port := node.GetPortByNameOrAlias(portName)
					if port != nil {
						logger.Info("Found source interface via route check for single device", zap.String("node", node.Name()), zap.String("port", portName))
						return true, node, portName
					}
				}
				logger.Warn("No matching route found for single device", zap.String("node", node.Name()))
				return false, nil, "No matching route found for single device."
			}
			logger.Warn("No outside node found")
			return false, nil, "No outside node."
		} else if len(nodeList) == 1 {
			node := nodeList[0]
			var routeTable *network.AddressTable
			if srcnetList.Type() == network.IPv4 {
				routeTable = node.Ipv4RouteTable(vrf)
			} else {
				routeTable = node.Ipv6RouteTable(vrf)
			}

			// 优先通过路由表查找源IP应该从哪个接口出去
			// 而不是直接使用默认网关的输出接口
			rmr := routeTable.MatchNetList(*srcnetList, false, true)
			if rmr.IsFullMatch() {
				match, _ := rmr.Table()
				nextPorts := match.Column("interface").List().Distinct()
				if len(nextPorts) == 1 {
					portName := nextPorts[0].(string)
					port := node.GetPortByNameOrAlias(portName)
					if port != nil {
						logger.Info("Found source interface via routing table", zap.String("node", node.Name()), zap.String("port", portName))
						return true, node, portName
					}
				} else if len(nextPorts) > 1 {
					logger.Warn("Multiple source interfaces found via routing table", zap.Int("interfaceCount", len(nextPorts)))
					// 如果有多条路由，使用第一个
					portName := nextPorts[0].(string)
					port := node.GetPortByNameOrAlias(portName)
					if port != nil {
						logger.Info("Using first source interface from routing table", zap.String("node", node.Name()), zap.String("port", portName))
						return true, node, portName
					}
				}
			}

			// 如果路由表查找失败，回退到使用默认网关的输出接口
			ps := routeTable.OutputInterface(routeTable.DefaultGw())
			if len(ps) == 1 {
				port := node.GetPortByNameOrAlias(ps[0])
				if port == nil {
					logger.Error("Failed to get port", zap.String("node", node.Name()), zap.String("port", ps[0]))
					return false, node, fmt.Sprintf("get port failed, node:%s, port:%s", node.Name(), ps[0])
				}
				logger.Info("Found matching outside node and port via default gateway", zap.String("node", node.Name()), zap.String("port", ps[0]))
				return true, node, ps[0]
			} else {
				logger.Warn("Multiple outside interfaces not supported", zap.Int("interfaceCount", len(ps)))
				return false, nil, "current not support multiple outside interface"
			}
		} else {
			if area == "" {
				logger.Warn("Multiple outside connections, area info required")
				return false, nil, "nodemap have multiple outside connections, must give area info"
			} else {
				var areaInfoList []*config.AreaInfo
				if srcnetList.Type() == network.IPv4 {
					areaInfoList = nm.Ipv4Areas
				} else {
					areaInfoList = nm.Ipv6Areas
				}
				var candidateNodes []api.Node
				var candidateInterfaces []string

				for _, areaInfo := range areaInfoList {
					if areaInfo.Name == area {
						n := nm.GetNode(areaInfo.NodeName)

						if n == nil {
							logger.Error("Node not found for area", zap.String("area", area), zap.Any("areaInfo", areaInfo))
							continue // Skip to the next areaInfo if the node is not found
						}

						port := n.GetPortByNameOrAlias(areaInfo.Interface)
						if port == nil {
							continue
						}

						// Check if the node can route the network list
						ok, _, outPorts, err := n.IpRouteCheck(*dstnetList, areaInfo.Interface, port.Vrf(), srcnetList.Type())
						if err != nil {
							logger.Info("Error checking route", zap.Error(err), zap.String("node", n.Name()))
							continue // Skip to the next areaInfo if there's an error checking the route
						}

						if ok && len(outPorts) == 1 {
							candidateNodes = append(candidateNodes, n)
							candidateInterfaces = append(candidateInterfaces, areaInfo.Interface)
						}

						logger.Debug("Node route check result",
							zap.String("node", n.Name()),
							zap.String("interface", areaInfo.Interface),
							zap.Bool("routeOk", ok),
							zap.Int("outPortsCount", len(outPorts)))
					}
				}

				if len(candidateNodes) == 0 {
					logger.Error("No suitable node found for area", zap.String("area", area))
					return false, nil, fmt.Sprintf("No suitable node found for area: %s", area)
				} else if len(candidateNodes) > 1 {
					logger.Error("Multiple suitable nodes found for area", zap.String("area", area), zap.Int("nodeCount", len(candidateNodes)))
					return false, nil, fmt.Sprintf("Multiple suitable nodes found for area: %s", area)
				} else {
					logger.Info("Found matching node for area",
						zap.String("node", candidateNodes[0].Name()),
						zap.String("interface", candidateInterfaces[0]))
					return true, candidateNodes[0], candidateInterfaces[0]
				}
				// for _, areaInfo := range areaInfoList {
				// 	if areaInfo.Name == area {
				// 		// n := nm.GetNode(areaInfo.NodeName)

				// 		// if n == nil {
				// 		// 	logger.Error("Node not found for area", zap.String("area", area), zap.Any("areaInfo", areaInfo))
				// 		// 	return false, nil, fmt.Sprintf("area: %s, areaInfo:%+v", area, areaInfo)
				// 		// }
				// 		// logger.Info("Found matching node for area", zap.String("node", n.Name()), zap.String("interface", areaInfo.Interface))
				// 		// return true, n, areaInfo.Interface
				// 		n := nm.GetNode(areaInfo.NodeName)

				// 		if n == nil {
				// 			logger.Error("Node not found for area", zap.String("area", area), zap.Any("areaInfo", areaInfo))
				// 			continue // Skip to the next areaInfo if the node is not found
				// 		}

				// 		port := n.GetPort(areaInfo.Interface)
				// 		if port == nil {
				// 			continue
				// 		}

				// 		// Check if the node can route the network list
				// 		ok, _, outPorts, err := n.IpRouteCheck(*dstnetList, areaInfo.Interface, port.Vrf(), netList.Type())
				// 		if err != nil {
				// 			logger.Error("Error checking route", zap.Error(err), zap.String("node", n.Name()))
				// 			continue // Skip to the next areaInfo if there's an error checking the route
				// 		}

				// 		if ok && len(outPorts) == 1 {

				// 		}

				// 		logger.Debug("Node cannot route the network list or interface doesn't match",
				// 			zap.String("node", n.Name()),
				// 			zap.String("interface", areaInfo.Interface))

				// 	}
				// }

				// logger.Error("Unknown error for area", zap.String("area", area))
				// return false, nil, fmt.Sprintf("unknown error, area: %s", area)
			}
		}
	}

	// 处理找到地址归属接口的情况
	portNameMap := map[string]int{}
	for p := range portListMap {
		portNameMap[p.FlattenName()] = 1
		portList = append(portList, p)
	}

	logger.Debug("Port list", zap.Any("portList", portList))

	if len(portList) > 1 {
		data := map[string]interface{}{
			"port_list": portList,
		}

		result := PortListIsSameNodeValidator{}.Validate(data)
		if !result.Status() {
			if gw == "" {
				logger.Warn("Multiple nodes found, but gateway is empty")
				return false, nil, "Multiple nodes, but gw is empty"
			} else {
				for _, port := range portList {
					if port.FullMatchByIp(gw, vrf) {
						logger.Info("Found matching port by gateway IP", zap.String("node", port.Node().Name()), zap.String("port", port.Name()))
						return true, port.Node(), port.Name()
					}
				}

				logger.Warn("No matching node found for gateway", zap.String("gw", gw))
				return false, nil, fmt.Sprintf("Multiple nodes, but can not find node by gw: %s", gw)
			}
		}
	} else if len(portList) == 1 {
		port := portList[0]
		portName := port.Name()
		portAlias := port.AliasName()
		var name string
		if portName == "" && len(portAlias) != 0 {
			name = portAlias[0]
		} else if portName != "" {
			name = portName
		}
		if name == "" {
			logger.Error("Port name is empty")
			return false, nil, "port name is empty"
		}
		logger.Info("Found single matching port", zap.String("node", port.Node().Name()), zap.String("port", name))
		return true, port.Node(), name
	}

	logger.Warn("No matching node found, port list is empty")
	return false, nil, "can not find node, port list is empty"
}

// Locate 定位节点（NodeLocator 的新实现，使用策略模式）
func (nl *NodeLocator) Locate(srcnetList *network.NetworkList, dstnetList *network.NetworkList, nodeName, vrf, gw, area string) (bool, api.Node, string) {
	logger := nl.logger.With(
		zap.String("function", "NodeLocator.Locate"),
		zap.String("vrf", vrf),
		zap.String("gw", gw),
		zap.String("area", area),
		zap.String("inputNodeName", nodeName),
	)

	// 创建定位请求
	req := &LocateRequest{
		SrcNetList: srcnetList,
		DstNetList: dstnetList,
		NodeName:   nodeName,
		Vrf:        vrf,
		Gw:         gw,
		Area:       area,
		IPFamily:   srcnetList.Type(),
		NodeMap:    nl.nodeMap,
		Logger:     logger,
	}

	// 使用策略链模式，按优先级依次尝试各个策略
	strategies := nl.getStrategies()
	for _, strategy := range strategies {
		if strategy.CanHandle(req) {
			ok, node, portName := strategy.Locate(req)
			if ok {
				logger.Info("Node located successfully", zap.String("strategy", nl.getStrategyName(strategy)), zap.String("node", node.Name()), zap.String("port", portName))
				return ok, node, portName
			}
			// 如果策略返回 false 但错误信息为空，继续尝试下一个策略
			if portName != "" {
				logger.Debug("Strategy failed", zap.String("strategy", nl.getStrategyName(strategy)), zap.String("error", portName))
			}
		}
	}

	logger.Warn("All strategies failed to locate node")
	return false, nil, "can not find node, all strategies failed"
}

// getStrategies 获取定位策略列表（按优先级排序）
func (nl *NodeLocator) getStrategies() []LocatorStrategy {
	strategies := []LocatorStrategy{
		// 1. 节点名称定位策略（最高优先级）
		NewNodeNameLocator(nl.nodeMap, nl.logger),
		// 2. 安全区域定位策略
		NewSecurityZoneLocator(nl.nodeMap, nl.logger),
		// 3. 网络地址定位策略
		NewNetworkLocator(nl.nodeMap, nl.logger),
		// 4. Stub 节点定位策略
		NewStubNodeLocator(nl.nodeMap, nl.logger),
		// 5. Outside 节点定位策略（最低优先级）
		NewOutsideNodeLocator(nl.nodeMap, nl.logger),
	}
	return strategies
}

// getStrategyName 获取策略名称（用于日志）
func (nl *NodeLocator) getStrategyName(strategy LocatorStrategy) string {
	switch strategy.(type) {
	case *NodeNameLocator:
		return "NodeNameLocator"
	case *SecurityZoneLocator:
		return "SecurityZoneLocator"
	case *NetworkLocator:
		return "NetworkLocator"
	case *StubNodeLocator:
		return "StubNodeLocator"
	case *OutsideNodeLocator:
		return "OutsideNodeLocator"
	default:
		return "UnknownStrategy"
	}
}

// LocateLegacy 定位节点（旧实现，保留用于向后兼容和测试）
func (nl *NodeLocator) LocateLegacy(srcnetList *network.NetworkList, dstnetList *network.NetworkList, nodeName, vrf, gw, area string) (bool, api.Node, string) {
	logger := nl.logger.With(
		zap.String("function", "NodeLocator.LocateLegacy"),
		zap.String("vrf", vrf),
		zap.String("gw", gw),
		zap.String("area", area),
		zap.String("inputNodeName", nodeName),
	)

	if nodeName != "" {
		node := nl.nodeMap.GetNode(nodeName)
		// node.IpRouteCheck(*srcnetList)
		if area != "" {
			var areaInfoList []*config.AreaInfo
			if srcnetList.Type() == network.IPv4 {
				areaInfoList = nl.nodeMap.Ipv4Areas
			} else {
				areaInfoList = nl.nodeMap.Ipv6Areas
			}
			for _, areaInfo := range areaInfoList {
				if areaInfo.Name == area && areaInfo.NodeName == nodeName {
					return true, node, areaInfo.Interface
				}
			}
			return false, nil, "Area not found."
		} else {
			_, _, outPorts, err := node.IpRouteCheck(*srcnetList, "", vrf, srcnetList.Type())
			if err != nil {
				logger.Error("Check route failed", zap.Error(err))
				return false, nil, err.Error()
			}
			if len(outPorts) == 0 {
				logger.Info("No matching ports found")
				return false, nil, "No matching ports found."
			}
			if len(outPorts) > 1 {
				logger.Info("Multiple matching ports found", zap.Int("count", len(outPorts)))
				return false, nil, "Multiple matching ports found."
			}
			return true, node, outPorts[0]
		}
	}

	portList := []api.Port{}
	portListMap := map[api.Port]bool{}
	for _, net := range srcnetList.List() {
		ps := nl.nodeMap.SelectPortListByNetwork(net, vrf)
		for _, p := range ps {
			portListMap[p] = true
		}
	}

	logger.Debug("Port list map", zap.Any("portListMap", portListMap))

	if len(portListMap) == 0 {
		logger.Info("No matching ports found, checking stub nodes")
		stubOk, stubNode, stubPort := nl.nodeMap.LocateStubNode(srcnetList, vrf, srcnetList.Type())
		if stubOk {
			logger.Info("Stub node found", zap.String("node", stubNode.Name()), zap.String("port", stubPort.Name()))
			return stubOk, stubNode, stubPort.Name()
		}

		nodeList := nl.nodeMap.WhichNodeHasOutside(vrf, srcnetList.Type())
		logger.Debug("Nodes with outside connections", zap.Int("count", len(nodeList)))

		if len(nodeList) == 0 {
			// 如果没有 outside 节点，检查 nodemap 中是否只有一台设备
			// 如果只有一台设备，通过路由查询接口检查是否能匹配接口
			if len(nl.nodeMap.Nodes) == 1 {
				node := nl.nodeMap.Nodes[0]
				logger.Info("Only one device in nodemap, checking route match", zap.String("node", node.Name()))

				// 通过路由查询接口检查是否能匹配接口
				ok, _, outPorts, err := node.IpRouteCheck(*srcnetList, "", vrf, srcnetList.Type())
				if err != nil {
					logger.Warn("Route check failed for single device", zap.Error(err))
					return false, nil, fmt.Sprintf("Route check failed: %v", err)
				}
				if ok && len(outPorts) == 1 {
					portName := outPorts[0]
					port := node.GetPortByNameOrAlias(portName)
					if port != nil {
						logger.Info("Found source interface via route check for single device", zap.String("node", node.Name()), zap.String("port", portName))
						return true, node, portName
					}
				}
				logger.Warn("No matching route found for single device", zap.String("node", node.Name()))
				return false, nil, "No matching route found for single device."
			}
			logger.Warn("No outside node found")
			return false, nil, "No outside node."
		} else if len(nodeList) == 1 {
			node := nodeList[0]
			var routeTable *network.AddressTable
			if srcnetList.Type() == network.IPv4 {
				routeTable = node.Ipv4RouteTable(vrf)
			} else {
				routeTable = node.Ipv6RouteTable(vrf)
			}

			// 优先通过路由表查找源IP应该从哪个接口出去
			// 而不是直接使用默认网关的输出接口
			rmr := routeTable.MatchNetList(*srcnetList, false, true)
			if rmr.IsFullMatch() {
				match, _ := rmr.Table()
				nextPorts := match.Column("interface").List().Distinct()
				if len(nextPorts) == 1 {
					portName := nextPorts[0].(string)
					port := node.GetPortByNameOrAlias(portName)
					if port != nil {
						logger.Info("Found source interface via routing table", zap.String("node", node.Name()), zap.String("port", portName))
						return true, node, portName
					}
				} else if len(nextPorts) > 1 {
					logger.Warn("Multiple source interfaces found via routing table", zap.Int("interfaceCount", len(nextPorts)))
					// 如果有多条路由，使用第一个
					portName := nextPorts[0].(string)
					port := node.GetPortByNameOrAlias(portName)
					if port != nil {
						logger.Info("Using first source interface from routing table", zap.String("node", node.Name()), zap.String("port", portName))
						return true, node, portName
					}
				}
			}

			// 如果路由表查找失败，回退到使用默认网关的输出接口
			ps := routeTable.OutputInterface(routeTable.DefaultGw())
			if len(ps) == 1 {
				port := node.GetPortByNameOrAlias(ps[0])
				if port == nil {
					logger.Error("Failed to get port", zap.String("node", node.Name()), zap.String("port", ps[0]))
					return false, node, fmt.Sprintf("get port failed, node:%s, port:%s", node.Name(), ps[0])
				}
				logger.Info("Found matching outside node and port via default gateway", zap.String("node", node.Name()), zap.String("port", ps[0]))
				return true, node, ps[0]
			} else {
				logger.Warn("Multiple outside interfaces not supported", zap.Int("interfaceCount", len(ps)))
				return false, nil, "current not support multiple outside interface"
			}
		} else {
			if area == "" {
				logger.Warn("Multiple outside connections, area info required")
				return false, nil, "nodemap have multiple outside connections, must give area info"
			} else {
				var areaInfoList []*config.AreaInfo
				if srcnetList.Type() == network.IPv4 {
					areaInfoList = nl.nodeMap.Ipv4Areas
				} else {
					areaInfoList = nl.nodeMap.Ipv6Areas
				}
				var candidateNodes []api.Node
				var candidateInterfaces []string

				for _, areaInfo := range areaInfoList {
					if areaInfo.Name == area {
						n := nl.nodeMap.GetNode(areaInfo.NodeName)

						if n == nil {
							logger.Error("Node not found for area", zap.String("area", area), zap.Any("areaInfo", areaInfo))
							continue // Skip to the next areaInfo if the node is not found
						}

						port := n.GetPortByNameOrAlias(areaInfo.Interface)
						if port == nil {
							continue
						}

						// Check if the node can route the network list
						ok, _, outPorts, err := n.IpRouteCheck(*dstnetList, areaInfo.Interface, port.Vrf(), srcnetList.Type())
						if err != nil {
							logger.Info("Error checking route", zap.Error(err), zap.String("node", n.Name()))
							continue // Skip to the next areaInfo if there's an error checking the route
						}

						if ok && len(outPorts) == 1 {
							candidateNodes = append(candidateNodes, n)
							candidateInterfaces = append(candidateInterfaces, areaInfo.Interface)
						}

						logger.Debug("Node route check result",
							zap.String("node", n.Name()),
							zap.String("interface", areaInfo.Interface),
							zap.Bool("routeOk", ok),
							zap.Int("outPortsCount", len(outPorts)))
					}
				}

				if len(candidateNodes) == 0 {
					logger.Error("No suitable node found for area", zap.String("area", area))
					return false, nil, fmt.Sprintf("No suitable node found for area: %s", area)
				} else if len(candidateNodes) > 1 {
					logger.Error("Multiple suitable nodes found for area", zap.String("area", area), zap.Int("nodeCount", len(candidateNodes)))
					return false, nil, fmt.Sprintf("Multiple suitable nodes found for area: %s", area)
				} else {
					logger.Info("Found matching node for area",
						zap.String("node", candidateNodes[0].Name()),
						zap.String("interface", candidateInterfaces[0]))
					return true, candidateNodes[0], candidateInterfaces[0]
				}
			}
		}
	}

	// 处理找到地址归属接口的情况
	portNameMap := map[string]int{}
	for p := range portListMap {
		portNameMap[p.FlattenName()] = 1
		portList = append(portList, p)
	}

	logger.Debug("Port list", zap.Any("portList", portList))

	if len(portList) > 1 {
		data := map[string]interface{}{
			"port_list": portList,
		}

		result := PortListIsSameNodeValidator{}.Validate(data)
		if !result.Status() {
			if gw == "" {
				logger.Warn("Multiple nodes found, but gateway is empty")
				return false, nil, "Multiple nodes, but gw is empty"
			} else {
				for _, port := range portList {
					if port.FullMatchByIp(gw, vrf) {
						logger.Info("Found matching port by gateway IP", zap.String("node", port.Node().Name()), zap.String("port", port.Name()))
						return true, port.Node(), port.Name()
					}
				}

				logger.Warn("No matching node found for gateway", zap.String("gw", gw))
				return false, nil, fmt.Sprintf("Multiple nodes, but can not find node by gw: %s", gw)
			}
		}
	} else if len(portList) == 1 {
		port := portList[0]
		portName := port.Name()
		portAlias := port.AliasName()
		var name string
		if portName == "" && len(portAlias) != 0 {
			name = portAlias[0]
		} else if portName != "" {
			name = portName
		}
		if name == "" {
			logger.Error("Port name is empty")
			return false, nil, "port name is empty"
		}
		logger.Info("Found single matching port", zap.String("node", port.Node().Name()), zap.String("port", name))
		return true, port.Node(), name
	}

	logger.Warn("No matching node found, port list is empty")
	return false, nil, "can not find node, port list is empty"
}

// func (nm *NodeMap) LocateNode(netList *network.NetworkList, vrf, gw, area string) (bool, api.Node, string) {
// 	portList := []api.Port{}
// 	portListMap := map[api.Port]bool{}
// 	for _, net := range netList.List() {
// 		ps := nm.SelectPortListByNetwork(net, vrf)
// 		// portList = append(portList, ps...)
// 		for _, p := range ps {
// 			portListMap[p] = true
// 		}
// 	}

// 	fmt.Println("===================++++-------->>>", portListMap)
// 	// 表示没有找到对应的地址段的归属，很大可能来自与Outside
// 	if len(portListMap) == 0 {
// 		stubOk, stubNode, stubPort := nm.LocateStubNode(netList, vrf, netList.Type())
// 		if stubOk {
// 			return stubOk, stubNode, stubPort.Name()
// 		}

// 		nodeList := nm.WhichNodeHasOutside(vrf, netList.Type())

// 		if len(nodeList) == 0 {
// 			return false, nil, "No outside node."
// 		} else if len(nodeList) == 1 {
// 			var routeTable *network.AddressTable
// 			if netList.Type() == network.IPv4 {
// 				routeTable = nodeList[0].Ipv4RouteTable(vrf)
// 			} else {
// 				routeTable = nodeList[0].Ipv6RouteTable(vrf)
// 			}

// 			ps := routeTable.OutputInterface(routeTable.DefaultGw())
// 			if len(ps) == 1 {
// 				port := nodeList[0].GetPort(ps[0])
// 				if port == nil {
// 					return false, nodeList[0], fmt.Sprintf("get port failed, node:%s, port:%s", nodeList[0].Name(), ps[0])
// 				}
// 				return true, nodeList[0], ps[0]
// 			} else {
// 				return false, nil, "current not support multiple outside interface"
// 			}

// 		} else {
// 			if area == "" {
// 				return false, nil, fmt.Sprintf("nodemap have multiple outside connections, must give area info")
// 			} else {
// 				var areaInfoList []*config.AreaInfo
// 				if netList.Type() == network.IPv4 {
// 					areaInfoList = nm.Ipv4Areas
// 				} else {
// 					areaInfoList = nm.Ipv6Areas
// 				}

// 				for _, areaInfo := range areaInfoList {
// 					if areaInfo.Name == area {
// 						n := nm.GetNode(areaInfo.NodeName)
// 						if n == nil {
// 							return false, nil, fmt.Sprintf("area: %s, areaInfo:%+v", area, areaInfo)
// 						}
// 						return true, n, areaInfo.Interface
// 					}
// 				}

// 				return false, nil, fmt.Sprintf("unknown error, area: %s", area)
// 			}
// 		}
// 	}

// 	// 表示找到了地址的归属接口
// 	portNameMap := map[string]int{}
// 	for p := range portListMap {
// 		portNameMap[p.FlattenName()] = 1
// 		portList = append(portList, p)
// 	}

// 	portNameList := []string{}
// 	for name, _ := range portNameMap {
// 		portNameList = append(portNameList, name)
// 	}

// 	if len(portList) > 1 {
// 		data := map[string]interface{}{
// 			"port_list": portList,
// 		}

// 		result := PortListIsSameNodeValidator{}.Validate(data)
// 		if !result.Status() {
// 			if gw == "" {
// 				return false, nil, "Multiple nodes, but gw is empty"
// 			} else {
// 				for _, port := range portList {
// 					if port.FullMatchByIp(gw, vrf) {
// 						return true, port.Node(), port.Name()
// 					}
// 					// else {
// 					// return false, nil, fmt.Sprintf("Multiple nodes, but can not find node by gw: %s", gw)
// 					// }
// 				}

// 				return false, nil, fmt.Sprintf("Multiple nodes, but can not find node by gw: %s", gw)
// 			}
// 		}

// 	} else if len(portList) == 1 {
// 		portName := portList[0].Name()
// 		portAlias := portList[0].AliasName()
// 		var name string
// 		if portName == "" && len(portAlias) != 0 {
// 			name = portAlias[0]
// 		} else if portName != "" {
// 			name = portName
// 		}
// 		if name == "" {
// 			return false, nil, "port name is empty"
// 		}
// 		return true, portList[0].Node(), name
// 	}
// 	return false, nil, "can not find node, port list is empty"

// }

func (nm *NodeMap) WhichNodeHasOutside(vrf string, af network.IPFamily) []api.Node {
	nodeList := []api.Node{}
	for _, n := range nm.Nodes {
		var routeTable *network.AddressTable
		if af == network.IPv4 {
			routeTable = n.Ipv4RouteTable(vrf)
		} else {
			routeTable = n.Ipv6RouteTable(vrf)
		}

		// 检查路由表是否存在且有默认网关
		if routeTable != nil && routeTable.DefaultGw() != nil {
			nodeList = append(nodeList, n)
		}
	}

	return nodeList
}

type PortListIsSameNodeValidator struct{}

func (pv PortListIsSameNodeValidator) Validate(data map[string]interface{}) validator.Result {
	portList := data["port_list"].([]api.Port)

	var nodeName string
	for index, port := range portList {
		if index == 0 {
			nodeName = port.Node().Name()
		} else {
			if nodeName != port.Node().Name() {
				return validator.NewValidateResult(false, fmt.Sprintf("portName: %s is not same node with %s", port.Node().Name(), nodeName))
			}
		}

	}

	return validator.NewValidateResult(true, "")
}

// NewNodeMapFromNetwork 创建新的 NodeMap
// templatePath: 防火墙模板路径，如果为空则使用默认路径
func NewNodeMapFromNetwork(name string, deviceList []config.DeviceConfig, force bool, task_id uint, nodeMapId *uint, templatePath ...string) (*NodeMap, context.Context) {
	logger := zap.NewNop().With(zap.String("function", "NewNodeMapFromNetwork"))
	logger.Info("Starting to create new NodeMap",
		zap.String("name", name),
		zap.Uint("task_id", task_id),
		zap.Bool("force", force))

	nodemap := &NodeMap{
		Name:       name,
		CxMananger: &ConnectorManager{},
		taskId:     task_id,
		TNodeMapID: nodeMapId,
		logger:     logger, // 初始化 logger
	}
	// logger.Debug("NodeMap initialized", zap.Any("nodemap", nodemap))

	// 确定模板路径
	var finalTemplatePath string
	if len(templatePath) > 0 && templatePath[0] != "" {
		finalTemplatePath = templatePath[0]
	} else {
		finalTemplatePath = firewall.DefaultFirewallTemplatePath
	}

	ctx := &firewall.PolicyContext{
		Context:            context.Background(),
		DeviceSpecificData: make(map[string]interface{}),
		Variables:          make(map[string]interface{}),
		TemplatePath:       finalTemplatePath,
	}
	logger.Debug("PolicyContext created", zap.String("template_path", finalTemplatePath))

	for index, conf := range deviceList {
		logger.Info("Processing device configuration",
			zap.Int("index", index),
			zap.String("host", conf.Host),
			zap.String("mode", conf.Mode))

		adapter := NewAdapter(&conf)
		if adapter == nil {
			err := fmt.Errorf("unsupport device type: %s, host: %s", conf.Mode, conf.Host)
			logger.Error("Failed to create adapter", zap.Error(err))
			panic(err)
		}
		logger.Debug("Adapter created", zap.Any("adapter", adapter))

		portList := adapter.PortList(force)
		logger.Debug("Port list retrieved", zap.Int("portCount", len(portList)))

		node := NewNodeFromAdapter(adapter, name, force)
		node.WithPortIterator(nodemap)
		node.WithCmdIp(conf.Host)
		logger.Info("Node created", zap.String("nodeName", node.Name()), zap.String("cmdIp", conf.Host))

		for _, port := range portList {
			uuid := uuid.New().String()
			port.WithID(uuid)

			node.AddPort(port, conf.Connection)
			nodemap.Ports = append(nodemap.Ports, port)
			port.WithNode(node)
			logger.Debug("Port added to node", zap.String("portName", port.Name()))
		}

		nodemap.AddNode(node, conf.Connection)
		logger.Info("Node added to NodeMap", zap.String("nodeName", node.Name()))

		ipv4Tables, ipv6Tables := adapter.RouteTable(force)
		logger.Debug("Route tables retrieved",
			zap.Int("ipv4TableCount", len(ipv4Tables)),
			zap.Int("ipv6TableCount", len(ipv6Tables)))

		rt := ipv4Tables["default"]
		if rt != nil {
			rt.Pretty()
		}
		for vrf, table := range ipv4Tables {
			node.GetOrCreateVrf(vrf)
			node.SetIpv4RouteTable(vrf, table)
			logger.Debug("IPv4 route table set",
				zap.String("vrf", vrf),
				zap.String("tableDescription", table.Describe()))
		}

		for vrf, table := range ipv6Tables {
			node.GetOrCreateVrf(vrf)
			node.SetIpv6RouteTable(vrf, table)
			logger.Debug("IPv6 route table set",
				zap.String("vrf", vrf),
				zap.String("tableDescription", table.Describe()))
		}

		for _, areaInfo := range conf.Ipv4Area {
			nodemap.SetOutside(node.Name(), areaInfo.Interface, areaInfo.Name, true, force)
			logger.Info("IPv4 outside area set",
				zap.String("nodeName", node.Name()),
				zap.String("interface", areaInfo.Interface),
				zap.String("areaName", areaInfo.Name))
		}

		for _, areaInfo := range conf.Ipv6Area {
			nodemap.SetOutside(node.Name(), areaInfo.Interface, areaInfo.Name, false, force)
			logger.Info("IPv6 outside area set",
				zap.String("nodeName", node.Name()),
				zap.String("interface", areaInfo.Interface),
				zap.String("areaName", areaInfo.Name))
		}

		for _, stubInfo := range conf.Ipv4Stub {
			nodemap.SetStubInterface(node.Name(), stubInfo.PortName, network.IPv4)
			logger.Info("IPv4 stub interface set",
				zap.String("nodeName", node.Name()),
				zap.String("portName", stubInfo.PortName))
		}

		for _, stubInfo := range conf.Ipv6Stub {
			nodemap.SetStubInterface(node.Name(), stubInfo.PortName, network.IPv6)
			logger.Info("IPv6 stub interface set",
				zap.String("nodeName", node.Name()),
				zap.String("portName", stubInfo.PortName))
		}
		// 加载IPv4安全区域配置
		for _, securityZoneInfo := range conf.Ipv4SecurityZones {
			szInfo := &config.SecurityZoneInfo{
				ConfigZoneName:  securityZoneInfo.ConfigZoneName,
				NodeName:        node.Name(),
				NetworkSegments: securityZoneInfo.NetworkSegments,
				Priority:        securityZoneInfo.Priority,
			}
			if node.Name() != securityZoneInfo.NodeName {
				panic(fmt.Sprintf("node name %s is not equal to security zone node name %s", node.Name(), securityZoneInfo.NodeName))
			}
			nodemap.Ipv4SecurityZones = append(nodemap.Ipv4SecurityZones, szInfo)
			logger.Info("IPv4 security zone loaded",
				zap.String("configZoneName", securityZoneInfo.ConfigZoneName),
				zap.String("nodeName", securityZoneInfo.NodeName),
				zap.Int("segmentCount", len(securityZoneInfo.NetworkSegments)))
		}

		// 加载IPv6安全区域配置
		for _, securityZoneInfo := range conf.Ipv6SecurityZones {
			szInfo := &config.SecurityZoneInfo{
				ConfigZoneName:  securityZoneInfo.ConfigZoneName,
				NodeName:        node.Name(),
				NetworkSegments: securityZoneInfo.NetworkSegments,
				Priority:        securityZoneInfo.Priority,
			}
			if node.Name() != securityZoneInfo.NodeName {
				panic(fmt.Sprintf("node name %s is not equal to security zone node name %s", node.Name(), securityZoneInfo.NodeName))
			}
			nodemap.Ipv6SecurityZones = append(nodemap.Ipv6SecurityZones, szInfo)
			logger.Info("IPv6 security zone loaded",
				zap.String("configZoneName", securityZoneInfo.ConfigZoneName),
				zap.String("nodeName", securityZoneInfo.NodeName),
				zap.Int("segmentCount", len(securityZoneInfo.NetworkSegments)))
		}

		node.ExtraInit(adapter, &conf)
		logger.Debug("Extra initialization completed for node", zap.String("nodeName", node.Name()))

		if _, ok := node.(api.FirewallDumper); ok {
			// node.(api.FirewallDumper).ExtraToDb(global.GVA_DB, adapter.TaskId())
			logger.Info("Firewall data dumped to database", zap.String("nodeName", node.Name()))
		}

		node.SetDeviceConfig(&deviceList[index])
		logger.Debug("Device configuration set for node", zap.String("nodeName", node.Name()))
	}

	for _, device := range deviceList {
		ctx.DeviceSpecificData[device.Host] = device.MetaData
		logger.Debug("Device-specific metadata added to PolicyContext",
			zap.String("host", device.Host),
			zap.Any("metadata", device.MetaData))
	}

	logger.Info("NodeMap creation completed", zap.String("name", name))
	return nodemap, ctx
}

func (nm *NodeMap) AttachToConnector(p api.Port, connector api.Connector) {
	connector.Attach(p)
	p.WithConnectorID(connector.ID())
}

func (nm *NodeMap) MakeTemplates(intent *policy.Intent, ctx context.Context) *TraverseProcess {
	// 创建路由跟踪器
	tracer := NewRouteTracer(nm.logger, intent)
	tracer.LogEvent(EventMakeTemplatesStart, map[string]interface{}{
		"intent": intent,
	})

	intent, intent6 := intent.SplitIntent()

	if intent != nil {
		if intent.Vrf == "" {
			intent.Vrf = "default"
		}
		tp := TraverseProcess{
			SimpleGraph: graph.SimpleGraph{
				Directed: true,
				Vertices: map[interface{}]graph.Vertex{},
			},
			Intent:         intent,
			IPFamily:       network.IPv4,
			NodeMap:        nm,
			Vrf:            intent.Vrf,
			Gateway:        intent.Gw,
			Area:           intent.Area,
			TraverseOnly:   intent.TraverseOnly,
			Results:        &TraverseResult{},
			FuncationNodes: []api.Node{},
			Vertices:       map[interface{}]graph.Vertex{},
			RouteTracer:    tracer, // 添加路由跟踪器
		}
		tp.WithLogger(nm.logger)
		tp.Traverse(ctx)

		// 记录完成事件
		tracer.LogEvent(EventMakeTemplatesEnd, map[string]interface{}{
			"result": tp.Results,
		})

		return &tp
	}
	if intent6 != nil {
		if intent6.Vrf == "" {
			intent6.Vrf = "default"
		}
		// 如果 intent 为 nil（只有 IPv6），使用 intent6 的字段
		var vrf, gw, area string
		var traverseOnly bool
		if intent != nil {
			vrf = intent.Vrf
			gw = intent.Gw
			area = intent.Area
			traverseOnly = intent.TraverseOnly
		} else {
			vrf = intent6.Vrf
			gw = intent6.Gw
			area = intent6.Area
			traverseOnly = intent6.TraverseOnly
		}

		tp := TraverseProcess{
			SimpleGraph: graph.SimpleGraph{
				Directed: true,
				Vertices: map[interface{}]graph.Vertex{},
			},
			Intent:         intent6,
			IPFamily:       network.IPv6,
			NodeMap:        nm,
			Vrf:            vrf,
			Gateway:        gw,
			Area:           area,
			TraverseOnly:   traverseOnly,
			Results:        &TraverseResult{},
			FuncationNodes: []api.Node{},
			Vertices:       map[interface{}]graph.Vertex{},
			RouteTracer:    tracer, // 添加路由跟踪器
		}
		tp.WithLogger(nm.logger)
		tp.Traverse(ctx)

		// 记录完成事件
		tracer.LogEvent(EventMakeTemplatesEnd, map[string]interface{}{
			"result": tp.Results,
		})

		return &tp
	}
	return nil
}

func Execute(result *TraverseResult, deviceList []*config.DeviceConfig, taskId uint) {
	for _, item := range result.Items {
		ip := item.Node.CmdIp()
		for _, dc := range deviceList {
			if ip == dc.Host {
				// adapter := NewAdapter(dc, taskId, true)
				adapter := NewAdapter(dc)

				// 在某一台防火墙设备上执行配置推送
				cmdList, err := adapter.BatchConfig(item.CmdListList, item.AdditionCli)
				if err != nil {
					panic(err)
				}

				// color: 显示当前设备推送配置的亮灯状态，GREEN、YELLOW(表示必须执行的命令都成功了，但是部分选命令执行出错)、RED(表示有必须命名执行出错)
				color := cmdList.(command.CmdExecuteStatus).Color()
				fmt.Println(color)

				// 所有的必须命令
				mainCmdList, _, _, _ := cmdList.(command.CmdExecuteStatus).MainCmds()
				for _, c := range mainCmdList {
					// 如果c.Ok()为true, 表示执行成功
					// 但是c.Ok()为false，并不一定表示执行设备，因为golang的默认bool类型为false，要结合c.Msg()，来判定该命令是否执行。
					// c.Cmd()，表示执行具体命令是什么
					// c.Msg(), 如果成功，Msg中可能包含成功命令的返回结果，但是有的命令可能是不返回内容的，此时Msg为空字符串。执行失败，Msg中包含失败内容或原因。

					if c.Ok() {
						zap.NewNop().Info(c.Cmd())
					} else {
						// c.Msg()不为空字符串
						if c.Msg() != "" {
							zap.NewNop().Error(c.Cmd(), zap.Any("Msg", c.Msg()))
						}
					}

				}

				// 所有的辅助命令
				// 辅助命名中包含了执行前的配置备份和执行后的配置获取，用于进行前后对比。
				assistCmdList, _, _, _ := cmdList.(command.CmdExecuteStatus).Assist()
				for _, c := range assistCmdList {
					if c.Ok() {
						zap.NewNop().Info(c.Cmd())
					} else {
						if c.Msg() != "" {
							zap.NewNop().Error(c.Cmd(), zap.Any("Msg", c.Msg()))
						}
					}

				}

				// fmt.Println(assistCmdList)
				// fmt.Println("success:", success)
				// fmt.Println("failed:", failed)

				// dmp := diffmatchpatch.New()
				// var after, before string
				// for _, cl := range cmdList.([]command.Command) {
				// if cl.Key() == "after" {
				// after = cl.Msg()
				// }
				//
				// if cl.Key() == "before" {
				// before = cl.Msg()
				// }
				// }
				//
				// var out string
				// buf := bytes.NewBufferString(out)
				// tools.WriteDiffHTML(buf, before, after, "测试")
				//
				// fmt.Println(buf)
				//
				// fmt.Println(after[0:200])
				// fmt.Println(before[0:200])

				// fmt.Println(pretty.Diff(before, after))

				// diffs := dmp.DiffMain(before, after, false)
				//
				// fmt.Println(dmp.DiffPrettyText(diffs))

			}
		}
	}
}

func (nm *NodeMap) ToDot() string {
	var sb strings.Builder
	sb.WriteString("digraph NodeMap {\n")

	// 设备节点
	for _, node := range nm.Nodes {
		safeName := makeSafeDotIdentifier(node.Name())
		sb.WriteString(fmt.Sprintf("  %s [shape=box];\n", safeName))
	}

	// IPv4 和 IPv6 区域节点
	for _, area := range nm.Ipv4Areas {
		safeAreaName := makeSafeDotIdentifier(fmt.Sprintf("area_ipv4_%s", area.Name))
		safeNodeName := makeSafeDotIdentifier(area.NodeName)
		sb.WriteString(fmt.Sprintf("  %s [shape=diamond];\n", safeAreaName))
		sb.WriteString(fmt.Sprintf("  %s -> %s;\n", safeNodeName, safeAreaName))
	}
	for _, area := range nm.Ipv6Areas {
		safeAreaName := makeSafeDotIdentifier(fmt.Sprintf("area_ipv6_%s", area.Name))
		safeNodeName := makeSafeDotIdentifier(area.NodeName)
		sb.WriteString(fmt.Sprintf("  %s [shape=diamond];\n", safeAreaName))
		sb.WriteString(fmt.Sprintf("  %s -> %s;\n", safeNodeName, safeAreaName))
	}

	// IPv4 和 IPv6 存根节点
	for _, stub := range nm.Ipv4Stubs {
		safeStubName := makeSafeDotIdentifier(fmt.Sprintf("%s_ipv4_stub_%s", stub.Node.Name(), stub.Port.Name()))
		safeNodeName := makeSafeDotIdentifier(stub.Node.Name())
		sb.WriteString(fmt.Sprintf("  %s [shape=ellipse];\n", safeStubName))
		sb.WriteString(fmt.Sprintf("  %s -> %s;\n", safeNodeName, safeStubName))

		// 存根节点下的路由
		routeTable := stub.Node.Ipv4RouteTable(stub.Port.Vrf())
		addRoutesToDot(&sb, routeTable, safeStubName, stub.Port)
	}
	for _, stub := range nm.Ipv6Stubs {
		safeStubName := makeSafeDotIdentifier(fmt.Sprintf("%s_ipv6_stub_%s", stub.Node.Name(), stub.Port.Name()))
		safeNodeName := makeSafeDotIdentifier(stub.Node.Name())
		sb.WriteString(fmt.Sprintf("  %s [shape=ellipse];\n", safeStubName))
		sb.WriteString(fmt.Sprintf("  %s -> %s;\n", safeNodeName, safeStubName))

		// 存根节点下的路由
		routeTable := stub.Node.Ipv6RouteTable(stub.Port.Vrf())
		addRoutesToDot(&sb, routeTable, safeStubName, stub.Port)
	}

	// 处理每个节点的路由表
	for _, node := range nm.Nodes {
		safeNodeName := makeSafeDotIdentifier(node.Name())
		for _, vrf := range node.Vrfs() {
			ipv4Table := node.Ipv4RouteTable(vrf.Name())
			ipv6Table := node.Ipv6RouteTable(vrf.Name())

			addRoutesToDot(&sb, ipv4Table, safeNodeName, nil)
			addRoutesToDot(&sb, ipv6Table, safeNodeName, nil)
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

func addRoutesToDot(sb *strings.Builder, table *network.AddressTable, nodeName string, stubPort api.Port) {
	if table == nil {
		return
	}
	sliceMap := table.ToSliceMap()
	for _, route := range sliceMap {
		net := route["net"]
		iface := route["interface"]
		nextHopIP := route["ip"]
		connected := route["connected"] == "true"
		defaultGw := route["default_gw"] == "true"
		vrf := route["vrf"]

		if vrf != "" && vrf != "default" {
			// 跳过非默认 VRF 的路由
			continue
		}

		// 确保节点名称是有效的 DOT 标识符
		safeNodeName := makeSafeDotIdentifier(nodeName)

		if defaultGw {
			// 默认路由
			sb.WriteString(fmt.Sprintf("  %s -> default_route [label=\"%s\"];\n", safeNodeName, iface))
		} else if stubPort != nil && iface == stubPort.Name() {
			// 存根节点下的路由
			routeName := makeSafeDotIdentifier(fmt.Sprintf("%s_route_%s", safeNodeName, strings.Replace(net, "/", "_", -1)))
			sb.WriteString(fmt.Sprintf("  %s -> %s [label=\"%s\"];\n", safeNodeName, routeName, net))
		} else if connected {
			// 直连路由
			connectedRouteName := makeSafeDotIdentifier(fmt.Sprintf("connected_route_%s", strings.Replace(net, "/", "_", -1)))
			sb.WriteString(fmt.Sprintf("  %s [shape=diamond];\n", connectedRouteName))
			sb.WriteString(fmt.Sprintf("  %s -> %s [label=\"%s\"];\n", safeNodeName, connectedRouteName, net))
		} else {
			// 其他路由（未知路由）
			unknownRouteName := makeSafeDotIdentifier(fmt.Sprintf("unknown_route_%s", strings.Replace(net, "/", "_", -1)))
			sb.WriteString(fmt.Sprintf("  %s [shape=point];\n", unknownRouteName))
			sb.WriteString(fmt.Sprintf("  %s -> %s [label=\"%s via %s\"];\n", safeNodeName, unknownRouteName, net, nextHopIP))
		}
	}
}

// makeSafeDotIdentifier 函数用于将任意字符串转换为有效的 DOT 标识符
func makeSafeDotIdentifier(s string) string {
	// 将横线替换为下划线
	s = strings.ReplaceAll(s, "-", "_")

	// 移除或替换其他无效字符
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	s = re.ReplaceAllString(s, "_")

	// 确保标识符不以数字开头
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}

	return s
}

func (nm *NodeMap) ToMermaid() string {
	fc := flowchart.NewFlowchart()
	fc.Title = "Network Topology"

	// 创建设备节点
	deviceNodes := make(map[string]*flowchart.Node)
	for _, node := range nm.Nodes {
		deviceNodes[node.Name()] = fc.AddNode(node.Name())
		deviceNodes[node.Name()].Shape = flowchart.NodeShapeProcess
	}

	// 添加 IPv4 和 IPv6 区域节点
	for _, area := range nm.Ipv4Areas {
		areaName := fmt.Sprintf("IPv4 Area: %s", area.Name)
		areaNode := fc.AddNode(areaName)
		areaNode.Shape = flowchart.NodeShapeDecision
		fc.AddLink(deviceNodes[area.NodeName], areaNode)
	}
	for _, area := range nm.Ipv6Areas {
		areaName := fmt.Sprintf("IPv6 Area: %s", area.Name)
		areaNode := fc.AddNode(areaName)
		areaNode.Shape = flowchart.NodeShapeDecision
		fc.AddLink(deviceNodes[area.NodeName], areaNode)
	}

	// 添加 IPv4 和 IPv6 存根节点
	addStubNodes(fc, deviceNodes, nm.Ipv4Stubs, "IPv4")
	addStubNodes(fc, deviceNodes, nm.Ipv6Stubs, "IPv6")

	return fc.String()
}

func addStubNodes(fc *flowchart.Flowchart, deviceNodes map[string]*flowchart.Node, stubs []*StubInfo, ipVersion string) {
	for _, stub := range stubs {
		stubName := fmt.Sprintf("%s %s Stub: %s", stub.Node.Name(), ipVersion, stub.Port.Name())
		stubNode := fc.AddNode(stubName)
		stubNode.Shape = flowchart.NodeShapeStart
		fc.AddLink(deviceNodes[stub.Node.Name()], stubNode)

		// 添加存根节点下的路由
		var routeTable *network.AddressTable
		if ipVersion == "IPv4" {
			routeTable = stub.Node.Ipv4RouteTable(stub.Port.Vrf())
		} else {
			routeTable = stub.Node.Ipv6RouteTable(stub.Port.Vrf())
		}
		addRoutesToMermaid(fc, routeTable, stubNode, stub.Port)
	}
}

func addRoutesToMermaid(fc *flowchart.Flowchart, table *network.AddressTable, stubNode *flowchart.Node, stubPort api.Port) {
	if table == nil || stubPort == nil {
		return
	}
	sliceMap := table.ToSliceMap()

	var routes []string
	for _, route := range sliceMap {
		net := route["net"]
		vrf := route["vrf"]
		iface := route["interface"]

		if vrf != "" && vrf != "default" {
			continue
		}

		// 只处理与stubPort相关的路由
		if iface == stubPort.Name() {
			routes = append(routes, net)
		}
	}

	if len(routes) > 0 {
		// 创建路由信息节点
		// routeInfoName := fmt.Sprintf("%s Stub Routes", stubNode.Text)
		routeInfo := fmt.Sprintf("Routes (%d):\n%s", len(routes), strings.Join(routes, "\n"))
		routeInfoNode := fc.AddNode(routeInfo)
		routeInfoNode.Shape = flowchart.NodeShapeProcess
		fc.AddLink(stubNode, routeInfoNode)
	}
}

// func addRoutesToMermaid(g *mermaid.Graph, table *network.AddressTable, nodeName string, stubPort api.Port) {
// 	if table == nil || stubPort == nil {
// 		return
// 	}
// 	sliceMap := table.ToSliceMap()

// 	var routes []string
// 	for _, route := range sliceMap {
// 		net := route["net"]
// 		vrf := route["vrf"]
// 		iface := route["interface"]

// 		if vrf != "" && vrf != "default" {
// 			continue
// 		}

// 		// 只处理与stubPort相关的路由
// 		if iface == stubPort.Name() {
// 			routes = append(routes, net)
// 		}
// 	}

// 	if len(routes) > 0 {
// 		// 创建路由信息节点
// 		routeInfoName := fmt.Sprintf("%s_stub_routes", nodeName)
// 		routeInfo := fmt.Sprintf("Stub Routes (%d):\n%s", len(routes), strings.Join(routes, "\n"))
// 		g.AddNode(mermaid.NewNode(routeInfoName).WithLabel(routeInfo))
// 		g.AddEdge(mermaid.NewEdge(nodeName, routeInfoName))
// 	}
// }

func createJSONString(data interface{}) string {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "Error creating JSON"
	}
	return strings.ReplaceAll(string(jsonBytes), "\"", "'")
}

func makeSafeMermaidIdentifier(s string) string {
	// 将空格和特殊字符替换为下划线
	re := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	s = re.ReplaceAllString(s, "_")

	// 确保标识符不以数字开头
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}

	return s
}

// 辅助函数：将 StubInfo 转换为 stubInfoJSON
func stubsToJSON(stubs []*StubInfo) []stubInfoJSON {
	result := make([]stubInfoJSON, len(stubs))
	for i, stub := range stubs {
		result[i] = stubInfoJSON{
			NodeID: stub.Node.ID(),
			PortID: stub.Port.ID(),
		}
	}
	return result
}

// 辅助函数：将 stubInfoJSON 转换回 StubInfo
func jsonToStubs(jsonStubs []stubInfoJSON, nm *NodeMap) []*StubInfo {
	result := make([]*StubInfo, 0, len(jsonStubs))
	for _, jsonStub := range jsonStubs {
		node := nm.GetNode(jsonStub.NodeID)
		if node == nil {
			continue
		}
		port := node.GetPortByID(jsonStub.PortID)
		if port == nil {
			continue
		}
		result = append(result, &StubInfo{
			Node: node,
			Port: port,
		})
	}
	return result
}
