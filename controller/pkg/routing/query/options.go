package query

import (
	"github.com/netxops/utils/network"
)

// PathQueryOptions 路径查询选项
type PathQueryOptions struct {
	Source      *network.NetworkList
	Destination *network.NetworkList
	VRF         string
	Gateway     string
	Area        string
	SourceNode  string
	IPFamily    network.IPFamily
	MaxPaths    int   // 最大路径数量（0表示无限制）
	EnableECMP  bool  // 是否启用ECMP
	MaxDepth    int   // 最大路径深度（0表示无限制）
}

// NewPathQueryOptions 创建路径查询选项
func NewPathQueryOptions() *PathQueryOptions {
	return &PathQueryOptions{
		VRF:        "default",
		IPFamily:   network.IPv4,
		MaxPaths:   100,
		EnableECMP: true,
		MaxDepth:   50,
	}
}

// WithSource 设置源网络
func (o *PathQueryOptions) WithSource(src *network.NetworkList) *PathQueryOptions {
	o.Source = src
	return o
}

// WithDestination 设置目标网络
func (o *PathQueryOptions) WithDestination(dst *network.NetworkList) *PathQueryOptions {
	o.Destination = dst
	return o
}

// WithVRF 设置VRF
func (o *PathQueryOptions) WithVRF(vrf string) *PathQueryOptions {
	o.VRF = vrf
	return o
}

// WithECMP 启用/禁用ECMP
func (o *PathQueryOptions) WithECMP(enable bool) *PathQueryOptions {
	o.EnableECMP = enable
	return o
}

// WithMaxPaths 设置最大路径数
func (o *PathQueryOptions) WithMaxPaths(maxPaths int) *PathQueryOptions {
	o.MaxPaths = maxPaths
	return o
}

// LocateOptions 节点定位选项
type LocateOptions struct {
	VRF     string
	Gateway string
	Area    string
	Node    string
}

