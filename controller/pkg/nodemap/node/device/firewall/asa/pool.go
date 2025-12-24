package asa

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
)

// ASANatPool 实现 firewall.NatPool 接口，用于测试
type ASANatPool struct {
	id      string
	name    string
	network *network.NetworkGroup
	cli     string
}

// NewASANatPool 创建一个新的 ASA NAT Pool
func NewASANatPool(id, name string, network *network.NetworkGroup, cli string) *ASANatPool {
	return &ASANatPool{
		id:      id,
		name:    name,
		network: network,
		cli:     cli,
	}
}

// ID 实现 firewall.NatPool 接口
func (p *ASANatPool) ID() string {
	return p.id
}

// Name 实现 firewall.Namer 接口
func (p *ASANatPool) Name() string {
	return p.name
}

// Cli 实现 firewall.NatPool 接口
func (p *ASANatPool) Cli() string {
	return p.cli
}

// MatchNetworkGroup 实现 firewall.NatPool 接口
func (p *ASANatPool) MatchNetworkGroup(ng *network.NetworkGroup) bool {
	if p.network == nil || ng == nil {
		return false
	}
	return p.network.Same(ng)
}

// Network 返回 pool 的网络组（用于测试）
func (p *ASANatPool) Network() *network.NetworkGroup {
	return p.network
}

// ASANatPoolWrapper 包装 ASA 的 mapped object 作为 NAT pool
type ASANatPoolWrapper struct {
	id      string
	name    string
	network *network.NetworkGroup
	cli     string
}

// ID 实现 firewall.NatPool 接口
func (p *ASANatPoolWrapper) ID() string {
	return p.id
}

// Name 实现 firewall.Namer 接口
func (p *ASANatPoolWrapper) Name() string {
	return p.name
}

// Cli 实现 firewall.NatPool 接口
func (p *ASANatPoolWrapper) Cli() string {
	return p.cli
}

// MatchNetworkGroup 实现 firewall.NatPool 接口
func (p *ASANatPoolWrapper) MatchNetworkGroup(ng *network.NetworkGroup) bool {
	if p.network == nil || ng == nil {
		return false
	}
	return p.network.Same(ng)
}

// Network 返回 pool 的网络组（用于重叠检测）
func (p *ASANatPoolWrapper) Network(_ firewall.FirewallNode) *network.NetworkGroup {
	return p.network
}
