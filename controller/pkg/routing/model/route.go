package model

import (
	"github.com/netxops/utils/network"
)

// RouteResult 路由查询结果
type RouteResult struct {
	Matched     bool
	Routes      []*RouteEntry
	OutPorts    []string
	NextHops    []*NextHopInfo
	IsConnected bool // 是否为直连路由
	IsECMP      bool // 是否为ECMP路由
}

// RouteEntry 路由条目
type RouteEntry struct {
	Network   *network.IPNet
	NextHops  []*NextHopInfo
	VRF       string
	Connected bool
	DefaultGw bool
}

// NextHopInfo 下一跳信息
type NextHopInfo struct {
	Interface string
	NextHopIP string
	Connected bool
	Weight    int // 路径权重（用于ECMP）
}

// NewNextHopInfo 创建下一跳信息
func NewNextHopInfo(interfaceName, nextHopIP string, connected bool) *NextHopInfo {
	return &NextHopInfo{
		Interface: interfaceName,
		NextHopIP: nextHopIP,
		Connected: connected,
		Weight:    1, // 默认权重
	}
}
