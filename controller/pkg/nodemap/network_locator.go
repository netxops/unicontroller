package nodemap

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"go.uber.org/zap"
)

// NetworkLocator 网络地址定位策略
type NetworkLocator struct {
	*BaseLocatorStrategy
}

// NewNetworkLocator 创建网络地址定位器
func NewNetworkLocator(nodeMap *NodeMap, logger *zap.Logger) *NetworkLocator {
	return &NetworkLocator{
		BaseLocatorStrategy: NewBaseLocatorStrategy(nodeMap, logger),
	}
}

// CanHandle 判断是否可以处理该定位请求
func (l *NetworkLocator) CanHandle(req *LocateRequest) bool {
	// 收集所有匹配的端口
	portList := []api.Port{}
	portListMap := map[api.Port]bool{}
	for _, net := range req.SrcNetList.List() {
		ps := l.BaseLocatorStrategy.NodeMap.SelectPortListByNetwork(net, req.Vrf)
		for _, p := range ps {
			portListMap[p] = true
		}
	}

	// 将结果存储到请求中
	req.SetPortList(portList, portListMap)

	// 如果有匹配的端口，可以处理
	return len(portListMap) > 0
}

// Locate 执行定位逻辑
func (l *NetworkLocator) Locate(req *LocateRequest) (bool, api.Node, string) {
	logger := l.BaseLocatorStrategy.Logger.With(
		zap.String("strategy", "NetworkLocator"),
	)

	portList, portListMap := req.GetPortList()
	if len(portListMap) == 0 {
		// 重新收集端口列表
		portList = []api.Port{}
		portListMap = map[api.Port]bool{}
		for _, net := range req.SrcNetList.List() {
			ps := l.BaseLocatorStrategy.NodeMap.SelectPortListByNetwork(net, req.Vrf)
			for _, p := range ps {
				portListMap[p] = true
			}
		}
	}

	logger.Debug("Port list map", zap.Any("portListMap", portListMap))

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
			if req.Gw == "" {
				logger.Warn("Multiple nodes found, but gateway is empty")
				return false, nil, "Multiple nodes, but gw is empty"
			} else {
				for _, port := range portList {
					if port.FullMatchByIp(req.Gw, req.Vrf) {
						logger.Info("Found matching port by gateway IP", zap.String("node", port.Node().Name()), zap.String("port", port.Name()))
						return true, port.Node(), port.Name()
					}
				}

				logger.Warn("No matching node found for gateway", zap.String("gw", req.Gw))
				return false, nil, fmt.Sprintf("Multiple nodes, but can not find node by gw: %s", req.Gw)
			}
		}
		// 如果所有端口都在同一个节点上，返回第一个端口
		if len(portList) > 0 {
			port := portList[0]
			portName := port.Name()
			portAlias := port.AliasName()
			var name string
			if portName == "" && len(portAlias) != 0 {
				name = portAlias[0]
			} else if portName != "" {
				name = portName
			}
			if name != "" {
				logger.Info("Found matching port (same node)", zap.String("node", port.Node().Name()), zap.String("port", name))
				return true, port.Node(), name
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
