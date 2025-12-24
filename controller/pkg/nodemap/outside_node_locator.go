package nodemap

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"go.uber.org/zap"
)

// OutsideNodeLocator Outside 节点定位策略
type OutsideNodeLocator struct {
	*BaseLocatorStrategy
}

// NewOutsideNodeLocator 创建 Outside 节点定位器
func NewOutsideNodeLocator(nodeMap *NodeMap, logger *zap.Logger) *OutsideNodeLocator {
	return &OutsideNodeLocator{
		BaseLocatorStrategy: NewBaseLocatorStrategy(nodeMap, logger),
	}
}

// CanHandle 判断是否可以处理该定位请求
func (l *OutsideNodeLocator) CanHandle(req *LocateRequest) bool {
	// Stub 节点定位失败后，尝试 Outside 节点定位
	// 这个策略总是可以尝试（如果前面的策略都失败了）
	return true
}

// Locate 执行定位逻辑
func (l *OutsideNodeLocator) Locate(req *LocateRequest) (bool, api.Node, string) {
	logger := l.BaseLocatorStrategy.Logger.With(
		zap.String("strategy", "OutsideNodeLocator"),
	)

	nodeList := l.BaseLocatorStrategy.NodeMap.WhichNodeHasOutside(req.Vrf, req.IPFamily)
	logger.Debug("Nodes with outside connections", zap.Int("count", len(nodeList)))

	if len(nodeList) == 0 {
		// 如果没有 outside 节点，检查 nodemap 中是否只有一台设备
		// 如果只有一台设备，通过路由查询接口检查是否能匹配接口
		if len(l.BaseLocatorStrategy.NodeMap.Nodes) == 1 {
			node := l.BaseLocatorStrategy.NodeMap.Nodes[0]
			logger.Info("Only one device in nodemap, checking route match", zap.String("node", node.Name()))

			// 通过路由查询接口检查是否能匹配接口
			ok, _, outPorts, err := node.IpRouteCheck(*req.SrcNetList, "", req.Vrf, req.IPFamily)
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
		// 单 Outside 节点策略
		return l.locateSingleOutsideNode(nodeList[0], req, logger)
	} else {
		// 多 Outside 节点策略
		return l.locateMultipleOutsideNodes(nodeList, req, logger)
	}
}

// locateSingleOutsideNode 定位单个 Outside 节点
func (l *OutsideNodeLocator) locateSingleOutsideNode(node api.Node, req *LocateRequest, logger *zap.Logger) (bool, api.Node, string) {
	routeTable := l.BaseLocatorStrategy.GetRouteTable(node, req.Vrf, req.IPFamily)

	// 优先通过路由表查找源IP应该从哪个接口出去
	// 而不是直接使用默认网关的输出接口
	rmr := routeTable.MatchNetList(*req.SrcNetList, false, true)
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
}

// locateMultipleOutsideNodes 定位多个 Outside 节点
func (l *OutsideNodeLocator) locateMultipleOutsideNodes(nodeList []api.Node, req *LocateRequest, logger *zap.Logger) (bool, api.Node, string) {
	if req.Area == "" {
		logger.Warn("Multiple outside connections, area info required")
		return false, nil, "nodemap have multiple outside connections, must give area info"
	}

	areaInfoList := l.BaseLocatorStrategy.GetAreaInfoList(req.IPFamily)
	var candidateNodes []api.Node
	var candidateInterfaces []string

	for _, areaInfo := range areaInfoList {
		if areaInfo.Name == req.Area {
			n := l.BaseLocatorStrategy.NodeMap.GetNode(areaInfo.NodeName)

			if n == nil {
				logger.Error("Node not found for area", zap.String("area", req.Area), zap.Any("areaInfo", areaInfo))
				continue // Skip to the next areaInfo if the node is not found
			}

			port := n.GetPortByNameOrAlias(areaInfo.Interface)
			if port == nil {
				continue
			}

			// Check if the node can route the network list
			ok, _, outPorts, err := n.IpRouteCheck(*req.DstNetList, areaInfo.Interface, port.Vrf(), req.IPFamily)
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
		logger.Error("No suitable node found for area", zap.String("area", req.Area))
		return false, nil, fmt.Sprintf("No suitable node found for area: %s", req.Area)
	} else if len(candidateNodes) > 1 {
		logger.Error("Multiple suitable nodes found for area", zap.String("area", req.Area), zap.Int("nodeCount", len(candidateNodes)))
		return false, nil, fmt.Sprintf("Multiple suitable nodes found for area: %s", req.Area)
	} else {
		logger.Info("Found matching node for area",
			zap.String("node", candidateNodes[0].Name()),
			zap.String("interface", candidateInterfaces[0]))
		return true, candidateNodes[0], candidateInterfaces[0]
	}
}
