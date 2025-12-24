package nodemap

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"go.uber.org/zap"
)

// StubNodeLocator Stub 节点定位策略
type StubNodeLocator struct {
	*BaseLocatorStrategy
}

// NewStubNodeLocator 创建 Stub 节点定位器
func NewStubNodeLocator(nodeMap *NodeMap, logger *zap.Logger) *StubNodeLocator {
	return &StubNodeLocator{
		BaseLocatorStrategy: NewBaseLocatorStrategy(nodeMap, logger),
	}
}

// CanHandle 判断是否可以处理该定位请求
func (l *StubNodeLocator) CanHandle(req *LocateRequest) bool {
	// 检查端口列表是否为空（网络地址定位失败）
	_, portListMap := req.GetPortList()
	return len(portListMap) == 0
}

// Locate 执行定位逻辑
func (l *StubNodeLocator) Locate(req *LocateRequest) (bool, api.Node, string) {
	logger := l.BaseLocatorStrategy.Logger.With(
		zap.String("strategy", "StubNodeLocator"),
	)

	logger.Info("No matching ports found, checking stub nodes")
	stubOk, stubNode, stubPort := l.BaseLocatorStrategy.NodeMap.LocateStubNode(req.SrcNetList, req.Vrf, req.IPFamily)
	if stubOk {
		logger.Info("Stub node found", zap.String("node", stubNode.Name()), zap.String("port", stubPort.Name()))
		return stubOk, stubNode, stubPort.Name()
	}

	// Stub 节点定位失败，返回 false 让下一个策略处理
	return false, nil, ""
}
