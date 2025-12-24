package nodemap

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"go.uber.org/zap"
)

// NodeNameLocator 节点名称定位策略
type NodeNameLocator struct {
	*BaseLocatorStrategy
}

// NewNodeNameLocator 创建节点名称定位器
func NewNodeNameLocator(nodeMap *NodeMap, logger *zap.Logger) *NodeNameLocator {
	return &NodeNameLocator{
		BaseLocatorStrategy: NewBaseLocatorStrategy(nodeMap, logger),
	}
}

// CanHandle 判断是否可以处理该定位请求
func (l *NodeNameLocator) CanHandle(req *LocateRequest) bool {
	return req.NodeName != ""
}

// Locate 执行定位逻辑
func (l *NodeNameLocator) Locate(req *LocateRequest) (bool, api.Node, string) {
	logger := l.BaseLocatorStrategy.Logger.With(
		zap.String("strategy", "NodeNameLocator"),
		zap.String("nodeName", req.NodeName),
	)

	node := l.BaseLocatorStrategy.NodeMap.GetNode(req.NodeName)
	if node == nil {
		logger.Warn("Node not found", zap.String("nodeName", req.NodeName))
		return false, nil, fmt.Sprintf("Node not found: %s", req.NodeName)
	}

	// 如果指定了 area，通过 area 信息查找接口
	if req.Area != "" {
		areaInfoList := l.BaseLocatorStrategy.GetAreaInfoList(req.IPFamily)
		for _, areaInfo := range areaInfoList {
			if areaInfo.Name == req.Area && areaInfo.NodeName == req.NodeName {
				logger.Info("Found node via area", zap.String("area", req.Area), zap.String("interface", areaInfo.Interface))
				return true, node, areaInfo.Interface
			}
		}
		logger.Warn("Area not found", zap.String("area", req.Area), zap.String("nodeName", req.NodeName))
		return false, nil, "Area not found."
	}

	// 否则通过路由检查定位端口
	_, _, outPorts, err := node.IpRouteCheck(*req.SrcNetList, "", req.Vrf, req.IPFamily)
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
	logger.Info("Found node via route check", zap.String("port", outPorts[0]))
	return true, node, outPorts[0]
}
