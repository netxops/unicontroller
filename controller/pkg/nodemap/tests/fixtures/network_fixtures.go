package fixtures

import (
	"github.com/netxops/utils/network"
)

// NewTestNetworkList 创建测试用的网络列表（IPv4）
func NewTestNetworkList(addresses ...string) *network.NetworkList {
	ng := network.NewNetworkGroup()
	for _, addr := range addresses {
		if addr != "" {
			subNg, err := network.NewNetworkGroupFromString(addr)
			if err == nil {
				ng.AddGroup(subNg)
			}
		}
	}
	return ng.NetworkList(network.IPv4)
}

// NewTestNetworkGroup 创建测试用的网络组
func NewTestNetworkGroup(addresses ...string) *network.NetworkGroup {
	ng := network.NewNetworkGroup()
	for _, addr := range addresses {
		if addr != "" {
			subNg, err := network.NewNetworkGroupFromString(addr)
			if err == nil {
				ng.AddGroup(subNg)
			}
		}
	}
	return ng
}

// NewTestIPv4NetworkList 创建测试用的 IPv4 网络列表
func NewTestIPv4NetworkList(addresses ...string) *network.NetworkList {
	ng := network.NewNetworkGroup()
	for _, addr := range addresses {
		if addr != "" {
			subNg, err := network.NewNetworkGroupFromString(addr)
			if err == nil {
				ng.AddGroup(subNg)
			}
		}
	}
	return ng.IPv4()
}

// NewTestIPv6NetworkList 创建测试用的 IPv6 网络列表
func NewTestIPv6NetworkList(addresses ...string) *network.NetworkList {
	ng := network.NewNetworkGroup()
	for _, addr := range addresses {
		if addr != "" {
			subNg, err := network.NewNetworkGroupFromString(addr)
			if err == nil {
				ng.AddGroup(subNg)
			}
		}
	}
	return ng.IPv6()
}
