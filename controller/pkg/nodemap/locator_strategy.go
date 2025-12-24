package nodemap

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/netxops/utils/network"
	"go.uber.org/zap"
)

// LocatorStrategy 定位策略接口
type LocatorStrategy interface {
	// CanHandle 判断是否可以处理该定位请求
	CanHandle(req *LocateRequest) bool

	// Locate 执行定位逻辑
	Locate(req *LocateRequest) (bool, api.Node, string)
}

// LocateRequest 定位请求
type LocateRequest struct {
	SrcNetList       *network.NetworkList
	DstNetList       *network.NetworkList
	NodeName         string
	Vrf              string
	Gw               string
	Area             string
	IPFamily         network.IPFamily
	NodeMap          *NodeMap
	Logger           *zap.Logger
	securityZoneInfo *config.SecurityZoneInfo // 内部使用，存储安全区域匹配结果
	portList         []api.Port               // 内部使用，存储端口列表
	portListMap      map[api.Port]bool        // 内部使用，存储端口映射
}

// SetPortList 设置端口列表
func (req *LocateRequest) SetPortList(portList []api.Port, portListMap map[api.Port]bool) {
	req.portList = portList
	req.portListMap = portListMap
}

// GetPortList 获取端口列表
func (req *LocateRequest) GetPortList() ([]api.Port, map[api.Port]bool) {
	return req.portList, req.portListMap
}

// SetSecurityZoneInfo 设置安全区域信息
func (req *LocateRequest) SetSecurityZoneInfo(info *config.SecurityZoneInfo) {
	req.securityZoneInfo = info
}

// GetSecurityZoneInfo 获取安全区域信息
func (req *LocateRequest) GetSecurityZoneInfo() *config.SecurityZoneInfo {
	return req.securityZoneInfo
}

// BaseLocatorStrategy 基础定位策略，提供公共功能
type BaseLocatorStrategy struct {
	NodeMap *NodeMap
	Logger  *zap.Logger
}

// NewBaseLocatorStrategy 创建基础定位策略
func NewBaseLocatorStrategy(nodeMap *NodeMap, logger *zap.Logger) *BaseLocatorStrategy {
	return &BaseLocatorStrategy{
		NodeMap: nodeMap,
		Logger:  logger,
	}
}

// GetAreaInfoList 根据 IP 地址族获取对应的 Area 信息列表
func (b *BaseLocatorStrategy) GetAreaInfoList(ipFamily network.IPFamily) []*config.AreaInfo {
	if ipFamily == network.IPv4 {
		return b.NodeMap.Ipv4Areas
	}
	return b.NodeMap.Ipv6Areas
}

// GetRouteTable 根据节点和 VRF 获取路由表
func (b *BaseLocatorStrategy) GetRouteTable(node api.Node, vrf string, ipFamily network.IPFamily) *network.AddressTable {
	if ipFamily == network.IPv4 {
		return node.Ipv4RouteTable(vrf)
	}
	return node.Ipv6RouteTable(vrf)
}
