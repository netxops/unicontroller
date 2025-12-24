package fixtures

import (
	"github.com/google/uuid"
	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/netxops/utils/network"
	"go.uber.org/zap"
)

// NodeMapOption 用于配置 NodeMap 的选项函数
type NodeMapOption func(*NodeMapBuilder)

// NodeMapBuilder NodeMap 构建器
type NodeMapBuilder struct {
	name      string
	nodes     []api.Node
	ports     []api.Port
	ipv4Areas []*config.AreaInfo
	ipv6Areas []*config.AreaInfo
}

// WithName 设置 NodeMap 名称
func WithName(name string) NodeMapOption {
	return func(b *NodeMapBuilder) {
		b.name = name
	}
}

// WithNode 添加节点
func WithNode(n api.Node) NodeMapOption {
	return func(b *NodeMapBuilder) {
		b.nodes = append(b.nodes, n)
	}
}

// WithPort 添加端口
func WithPort(p api.Port) NodeMapOption {
	return func(b *NodeMapBuilder) {
		b.ports = append(b.ports, p)
	}
}

// WithArea 添加区域信息
func WithArea(area *config.AreaInfo, ipv4 bool) NodeMapOption {
	return func(b *NodeMapBuilder) {
		if ipv4 {
			b.ipv4Areas = append(b.ipv4Areas, area)
		} else {
			b.ipv6Areas = append(b.ipv6Areas, area)
		}
	}
}

// NewTestNodeMap 创建测试用的 NodeMap
func NewTestNodeMap(opts ...NodeMapOption) *nodemap.NodeMap {
	builder := &NodeMapBuilder{
		name:  "TestNodeMap",
		nodes: []api.Node{},
		ports: []api.Port{},
	}

	// 应用选项
	for _, opt := range opts {
		opt(builder)
	}

	nm := &nodemap.NodeMap{
		Name:       builder.name,
		Ports:      builder.ports,
		Nodes:      builder.nodes,
		Ipv4Areas:  builder.ipv4Areas,
		Ipv6Areas:  builder.ipv6Areas,
		CxMananger: &nodemap.ConnectorManager{},
		TNodeMapID: new(uint),
	}

	// 设置默认 logger（如果测试需要，可以通过 WithLogger 覆盖）
	nm.WithLogger(zap.NewNop())

	// 设置 PortIterator
	for _, n := range nm.Nodes {
		n.WithPortIterator(nm)
	}

	return nm
}

// NewTestNode 创建测试用的节点
func NewTestNode(name string, nodeType api.NodeType) api.Node {
	return node.NewDeviceNode(uuid.New().String(), name, nodeType)
}

// NewTestPort 创建测试用的端口
func NewTestPort(name, vrf string, ipList map[network.IPFamily][]string) api.Port {
	if ipList == nil {
		ipList = map[network.IPFamily][]string{
			network.IPv4: {"192.168.1.1/24"},
		}
	}
	port := node.NewPort(name, vrf, ipList, nil)
	port.WithID(uuid.New().String())
	return port
}

// NewTestAreaInfo 创建测试用的区域信息
func NewTestAreaInfo(name, nodeName, iface string) *config.AreaInfo {
	return &config.AreaInfo{
		Name:      name,
		NodeName:  nodeName,
		Interface: iface,
		Force:     false,
	}
}
