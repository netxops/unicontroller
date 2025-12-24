package model

import (
	"testing"

	"github.com/netxops/utils/network"
)

// TestNewNextHopInfo 测试创建下一跳信息
func TestNewNextHopInfo(t *testing.T) {
	nextHop := NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", true)

	if nextHop == nil {
		t.Fatal("NextHopInfo不应该为空")
	}

	if nextHop.Interface != "GigabitEthernet0/0" {
		t.Errorf("期望接口为GigabitEthernet0/0，实际为%s", nextHop.Interface)
	}

	if nextHop.NextHopIP != "192.168.1.1" {
		t.Errorf("期望下一跳IP为192.168.1.1，实际为%s", nextHop.NextHopIP)
	}

	if !nextHop.Connected {
		t.Error("期望Connected为true")
	}

	if nextHop.Weight != 1 {
		t.Errorf("期望默认权重为1，实际为%d", nextHop.Weight)
	}
}

// TestNextHopInfo_Weight 测试下一跳权重
func TestNextHopInfo_Weight(t *testing.T) {
	nextHop := NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", false)
	nextHop.Weight = 10

	if nextHop.Weight != 10 {
		t.Errorf("期望权重为10，实际为%d", nextHop.Weight)
	}
}

// TestRouteEntry 测试路由条目
func TestRouteEntry(t *testing.T) {
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop1 := NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", false)
	nextHop2 := NewNextHopInfo("GigabitEthernet0/1", "192.168.1.2", false)

	entry := &RouteEntry{
		Network:   net,
		NextHops:  []*NextHopInfo{nextHop1, nextHop2},
		VRF:       "default",
		Connected: false,
		DefaultGw: false,
	}

	if entry.Network == nil {
		t.Error("路由条目的网络不应该为空")
	}

	if len(entry.NextHops) != 2 {
		t.Errorf("期望下一跳数量为2，实际为%d", len(entry.NextHops))
	}

	if entry.VRF != "default" {
		t.Errorf("期望VRF为default，实际为%s", entry.VRF)
	}
}

// TestRouteEntry_Connected 测试直连路由条目
func TestRouteEntry_Connected(t *testing.T) {
	net, err := network.ParseIPNet("192.168.1.0/24")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", true)

	entry := &RouteEntry{
		Network:   net,
		NextHops:  []*NextHopInfo{nextHop},
		VRF:       "default",
		Connected: true,
		DefaultGw: false,
	}

	if !entry.Connected {
		t.Error("期望Connected为true")
	}

	if entry.NextHops[0].Connected != true {
		t.Error("下一跳的Connected应该为true")
	}
}

// TestRouteEntry_DefaultGateway 测试默认网关路由条目
func TestRouteEntry_DefaultGateway(t *testing.T) {
	net, err := network.ParseIPNet("0.0.0.0/0")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", false)

	entry := &RouteEntry{
		Network:   net,
		NextHops:  []*NextHopInfo{nextHop},
		VRF:       "default",
		Connected: false,
		DefaultGw: true,
	}

	if !entry.DefaultGw {
		t.Error("期望DefaultGw为true")
	}
}

// TestRouteResult 测试路由结果
func TestRouteResult(t *testing.T) {
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop1 := NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", false)
	nextHop2 := NewNextHopInfo("GigabitEthernet0/1", "192.168.1.2", false)

	entry := &RouteEntry{
		Network:  net,
		NextHops: []*NextHopInfo{nextHop1, nextHop2},
		VRF:      "default",
	}

	result := &RouteResult{
		Matched:     true,
		Routes:      []*RouteEntry{entry},
		OutPorts:    []string{"GigabitEthernet0/0", "GigabitEthernet0/1"},
		NextHops:    []*NextHopInfo{nextHop1, nextHop2},
		IsConnected: false,
		IsECMP:      true,
	}

	if !result.Matched {
		t.Error("期望Matched为true")
	}

	if len(result.Routes) != 1 {
		t.Errorf("期望路由数量为1，实际为%d", len(result.Routes))
	}

	if len(result.OutPorts) != 2 {
		t.Errorf("期望输出端口数量为2，实际为%d", len(result.OutPorts))
	}

	if len(result.NextHops) != 2 {
		t.Errorf("期望下一跳数量为2，实际为%d", len(result.NextHops))
	}

	if !result.IsECMP {
		t.Error("期望IsECMP为true")
	}
}

// TestRouteResult_NoMatch 测试未匹配的路由结果
func TestRouteResult_NoMatch(t *testing.T) {
	result := &RouteResult{
		Matched:     false,
		Routes:      []*RouteEntry{},
		OutPorts:    []string{},
		NextHops:    []*NextHopInfo{},
		IsConnected: false,
		IsECMP:      false,
	}

	if result.Matched {
		t.Error("期望Matched为false")
	}

	if len(result.Routes) != 0 {
		t.Errorf("期望路由数量为0，实际为%d", len(result.Routes))
	}

	if len(result.OutPorts) != 0 {
		t.Errorf("期望输出端口数量为0，实际为%d", len(result.OutPorts))
	}
}

// TestRouteResult_Connected 测试直连路由结果
func TestRouteResult_Connected(t *testing.T) {
	net, err := network.ParseIPNet("192.168.1.0/24")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", true)

	result := &RouteResult{
		Matched:     true,
		Routes:      []*RouteEntry{{Network: net, NextHops: []*NextHopInfo{nextHop}}},
		OutPorts:    []string{"GigabitEthernet0/0"},
		NextHops:    []*NextHopInfo{nextHop},
		IsConnected: true,
		IsECMP:      false,
	}

	if !result.IsConnected {
		t.Error("期望IsConnected为true")
	}

	if result.IsECMP {
		t.Error("期望IsECMP为false（直连路由不是ECMP）")
	}
}

// TestRouteResult_SinglePath 测试单一路径
func TestRouteResult_SinglePath(t *testing.T) {
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", false)

	result := &RouteResult{
		Matched:     true,
		Routes:      []*RouteEntry{{Network: net, NextHops: []*NextHopInfo{nextHop}}},
		OutPorts:    []string{"GigabitEthernet0/0"},
		NextHops:    []*NextHopInfo{nextHop},
		IsConnected: false,
		IsECMP:      false,
	}

	if result.IsECMP {
		t.Error("单一路径不应该标记为ECMP")
	}

	if len(result.NextHops) != 1 {
		t.Errorf("期望下一跳数量为1，实际为%d", len(result.NextHops))
	}
}

// TestRouteResult_ECMP 测试ECMP路由结果
func TestRouteResult_ECMP(t *testing.T) {
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHops := []*NextHopInfo{
		NewNextHopInfo("GigabitEthernet0/0", "192.168.1.1", false),
		NewNextHopInfo("GigabitEthernet0/1", "192.168.1.2", false),
		NewNextHopInfo("GigabitEthernet0/2", "192.168.1.3", false),
	}

	result := &RouteResult{
		Matched:     true,
		Routes:      []*RouteEntry{{Network: net, NextHops: nextHops}},
		OutPorts:    []string{"GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2"},
		NextHops:    nextHops,
		IsConnected: false,
		IsECMP:      true,
	}

	if !result.IsECMP {
		t.Error("期望IsECMP为true")
	}

	if len(result.NextHops) != 3 {
		t.Errorf("期望下一跳数量为3，实际为%d", len(result.NextHops))
	}

	if len(result.OutPorts) != 3 {
		t.Errorf("期望输出端口数量为3，实际为%d", len(result.OutPorts))
	}
}

