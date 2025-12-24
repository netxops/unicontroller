package core

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/routing/model"
	"github.com/netxops/utils/network"
)

// TestMultihopRouting_Path1 测试Path1: R1 -> R2 -> R4 -> R7 -> R10
func TestMultihopRouting_Path1(t *testing.T) {
	// 创建R1路由表
	r1 := model.NewRouteTable("default", network.IPv4)
	// 添加源网络（直连）
	net, _ := network.ParseIPNet("10.1.0.0/24")
	nextHop := &network.NextHop{}
	nextHop.AddHop("Eth0/3", "10.1.0.1", true, false, nil) // 直连
	r1.AddRoute(net, nextHop)

	// 添加到目标网络的路由
	net, _ = network.ParseIPNet("10.10.0.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.1.1.2", false, false, nil) // 下一跳是R2的Eth0/0 (10.2.1.1)
	r1.AddRoute(net, nextHop)

	// 创建R2路由表
	r2 := model.NewRouteTable("default", network.IPv4)
	net, _ = network.ParseIPNet("10.2.1.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.2.1.1", true, false, nil) // 直连
	r2.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.2.4.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/1", "10.2.4.1", true, false, nil) // 直连
	r2.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.10.0.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/1", "10.2.4.2", false, false, nil) // 下一跳是R4的Eth0/2 (10.4.1.1)
	r2.AddRoute(net, nextHop)

	// 创建R4路由表
	r4 := model.NewRouteTable("default", network.IPv4)
	net, _ = network.ParseIPNet("10.4.1.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/2", "10.4.1.1", true, false, nil) // 直连
	r4.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.4.7.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.4.7.1", true, false, nil) // 直连
	r4.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.10.0.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.4.7.2", false, false, nil) // 下一跳是R7的Eth0/2 (10.7.1.1)
	r4.AddRoute(net, nextHop)

	// 创建R7路由表
	r7 := model.NewRouteTable("default", network.IPv4)
	net, _ = network.ParseIPNet("10.7.1.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/2", "10.7.1.1", true, false, nil) // 直连
	r7.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.7.10.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.7.10.1", true, false, nil) // 直连
	r7.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.10.0.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.7.10.2", false, false, nil) // 下一跳是R10的Eth0/0 (10.10.0.1)
	r7.AddRoute(net, nextHop)

	// 创建R10路由表
	r10 := model.NewRouteTable("default", network.IPv4)
	net, _ = network.ParseIPNet("10.10.0.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.10.0.1", true, false, nil) // 直连
	r10.AddRoute(net, nextHop)

	// 测试R1查询到目标网络
	rq1 := NewRouteQuery(r1)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq1.QueryRoute(*dst, "Eth0/3", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.Matched {
		t.Error("R1应该匹配到路由")
	}

	if len(result.NextHops) == 0 {
		t.Error("R1应该有下一跳")
		return
	}

	if result.NextHops[0].Interface != "Eth0/0" {
		t.Errorf("期望接口为Eth0/0，实际为%s", result.NextHops[0].Interface)
	}
}

// TestMultihopRouting_ECMP_R1 测试R1的ECMP场景（3条路径）
func TestMultihopRouting_ECMP_R1(t *testing.T) {
	// 创建R1路由表，包含3条ECMP路径
	r1 := model.NewRouteTable("default", network.IPv4)

	net, _ := network.ParseIPNet("10.10.0.0/24")
	nextHop := &network.NextHop{}
	// Path1: Eth0/0 -> R2
	nextHop.AddHop("Eth0/0", "10.1.1.2", false, false, nil)
	// Path2: Eth0/1 -> R2 (ECMP)
	nextHop.AddHop("Eth0/1", "10.1.2.2", false, false, nil)
	// Path3: Eth0/2 -> R3 (ECMP)
	nextHop.AddHop("Eth0/2", "10.1.3.2", false, false, nil)
	r1.AddRoute(net, nextHop)

	rq1 := NewRouteQuery(r1)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq1.QueryRoute(*dst, "Eth0/3", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.Matched {
		t.Error("R1应该匹配到路由")
	}

	if !result.IsECMP {
		t.Error("R1应该识别为ECMP路由")
	}

	if len(result.NextHops) != 3 {
		t.Errorf("期望下一跳数量为3，实际为%d", len(result.NextHops))
	}

	// 验证所有路径的接口
	interfaces := make(map[string]bool)
	for _, hop := range result.NextHops {
		interfaces[hop.Interface] = true
	}

	if !interfaces["Eth0/0"] {
		t.Error("应该包含Eth0/0接口")
	}
	if !interfaces["Eth0/1"] {
		t.Error("应该包含Eth0/1接口")
	}
	if !interfaces["Eth0/2"] {
		t.Error("应该包含Eth0/2接口")
	}
}

// TestMultihopRouting_ECMP_R2 测试R2的ECMP场景（2条路径）
func TestMultihopRouting_ECMP_R2(t *testing.T) {
	// 创建R2路由表，包含2条ECMP路径
	r2 := model.NewRouteTable("default", network.IPv4)

	net, _ := network.ParseIPNet("10.10.0.0/24")
	nextHop := &network.NextHop{}
	// Path1: Eth0/1 -> R4
	nextHop.AddHop("Eth0/1", "10.2.4.2", false, false, nil)
	// Path2: Eth0/2 -> R5 (ECMP)
	nextHop.AddHop("Eth0/2", "10.2.5.2", false, false, nil)
	r2.AddRoute(net, nextHop)

	rq2 := NewRouteQuery(r2)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq2.QueryRoute(*dst, "Eth0/0", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.Matched {
		t.Error("R2应该匹配到路由")
	}

	if !result.IsECMP {
		t.Error("R2应该识别为ECMP路由")
	}

	if len(result.NextHops) != 2 {
		t.Errorf("期望下一跳数量为2，实际为%d", len(result.NextHops))
	}
}

// TestMultihopRouting_MergePoint_R5 测试R5的路径合并场景
func TestMultihopRouting_MergePoint_R5(t *testing.T) {
	// R5是路径2和路径3的合并点
	// Path2: R2 -> R5 -> R7 -> R10
	// Path3: R3 -> R5 -> R7 -> R10

	// 创建R5路由表
	r5 := model.NewRouteTable("default", network.IPv4)

	// 直连网络
	net, _ := network.ParseIPNet("10.5.1.0/24")
	nextHop := &network.NextHop{}
	nextHop.AddHop("Eth0/1", "10.5.1.1", true, false, nil)
	r5.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.5.2.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/2", "10.5.2.1", true, false, nil)
	r5.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.5.7.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.5.7.1", true, false, nil)
	r5.AddRoute(net, nextHop)

	// 到目标网络的路由（路径2和路径3在此合并）
	net, _ = network.ParseIPNet("10.10.0.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.5.7.2", false, false, nil) // 下一跳是R7
	r5.AddRoute(net, nextHop)

	rq5 := NewRouteQuery(r5)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq5.QueryRoute(*dst, "Eth0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.Matched {
		t.Error("R5应该匹配到路由")
	}

	// R5到目标只有一条路径（合并后）
	if result.IsECMP {
		t.Error("R5不应该识别为ECMP路由（合并后单一路径）")
	}

	if len(result.NextHops) != 1 {
		t.Errorf("期望下一跳数量为1，实际为%d", len(result.NextHops))
	}

	if result.NextHops[0].Interface != "Eth0/0" {
		t.Errorf("期望接口为Eth0/0，实际为%s", result.NextHops[0].Interface)
	}
}

// TestMultihopRouting_MergePoint_R6 测试R6的路径合并场景
func TestMultihopRouting_MergePoint_R6(t *testing.T) {
	// R6是路径4和路径5的合并点
	// Path4: R3 -> R6 -> R8 -> R9 -> R10
	// Path5: R4 -> R6 -> R8 -> R9 -> R10

	// 创建R6路由表
	r6 := model.NewRouteTable("default", network.IPv4)

	// 直连网络
	net, _ := network.ParseIPNet("10.6.1.0/24")
	nextHop := &network.NextHop{}
	nextHop.AddHop("Eth0/1", "10.6.1.1", true, false, nil)
	r6.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.6.3.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/2", "10.6.3.1", true, false, nil)
	r6.AddRoute(net, nextHop)

	net, _ = network.ParseIPNet("10.6.8.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.6.8.1", true, false, nil)
	r6.AddRoute(net, nextHop)

	// 到目标网络的路由（路径4和路径5在此合并）
	net, _ = network.ParseIPNet("10.10.0.0/24")
	nextHop = &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.6.8.2", false, false, nil) // 下一跳是R8
	r6.AddRoute(net, nextHop)

	rq6 := NewRouteQuery(r6)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq6.QueryRoute(*dst, "Eth0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.Matched {
		t.Error("R6应该匹配到路由")
	}

	// R6到目标只有一条路径（合并后）
	if result.IsECMP {
		t.Error("R6不应该识别为ECMP路由（合并后单一路径）")
	}

	if len(result.NextHops) != 1 {
		t.Errorf("期望下一跳数量为1，实际为%d", len(result.NextHops))
	}
}

// TestMultihopRouting_ECMP_R7 测试R7的ECMP场景（多条路径汇聚）
func TestMultihopRouting_ECMP_R7(t *testing.T) {
	// R7是路径1、2、3的汇聚点
	// 创建R7路由表，包含2条ECMP路径到R10
	r7 := model.NewRouteTable("default", network.IPv4)

	net, _ := network.ParseIPNet("10.10.0.0/24")
	nextHop := &network.NextHop{}
	// ECMP路径1
	nextHop.AddHop("Eth0/0", "10.7.10.2", false, false, nil)
	// ECMP路径2
	nextHop.AddHop("Eth0/1", "10.7.10.3", false, false, nil)
	r7.AddRoute(net, nextHop)

	rq7 := NewRouteQuery(r7)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq7.QueryRoute(*dst, "Eth0/2", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.Matched {
		t.Error("R7应该匹配到路由")
	}

	if !result.IsECMP {
		t.Error("R7应该识别为ECMP路由")
	}

	if len(result.NextHops) != 2 {
		t.Errorf("期望下一跳数量为2，实际为%d", len(result.NextHops))
	}
}

// TestMultihopRouting_QueryAllRoutes_ECMP 测试查询所有ECMP路径
func TestMultihopRouting_QueryAllRoutes_ECMP(t *testing.T) {
	// 创建R1路由表，包含3条ECMP路径
	r1 := model.NewRouteTable("default", network.IPv4)

	net, _ := network.ParseIPNet("10.10.0.0/24")
	nextHop := &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.1.1.2", false, false, nil)
	nextHop.AddHop("Eth0/1", "10.1.2.2", false, false, nil)
	nextHop.AddHop("Eth0/2", "10.1.3.2", false, false, nil)
	r1.AddRoute(net, nextHop)

	rq1 := NewRouteQuery(r1)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	results, err := rq1.QueryAllRoutes(*dst, "Eth0/3", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询所有路由失败: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("期望路由数量为3，实际为%d", len(results))
	}

	// 验证每个路由都是单一路径（不是ECMP）
	for i, result := range results {
		if result.IsECMP {
			t.Errorf("路由%d不应该标记为ECMP", i)
		}

		if len(result.NextHops) != 1 {
			t.Errorf("路由%d的下一跳数量应该为1，实际为%d", i, len(result.NextHops))
		}
	}

	// 验证所有路径的接口都不同
	interfaces := make(map[string]bool)
	for _, result := range results {
		if len(result.NextHops) > 0 {
			iface := result.NextHops[0].Interface
			if interfaces[iface] {
				t.Errorf("接口%s重复", iface)
			}
			interfaces[iface] = true
		}
	}
}

// TestMultihopRouting_LongestPath 测试最长路径Path5 (7跳)
func TestMultihopRouting_LongestPath(t *testing.T) {
	// Path5: R1 -> R2 -> R4 -> R6 -> R8 -> R9 -> R10 (7跳)
	// 这里只测试R4到R6这一段，因为完整测试需要完整的拓扑

	// 创建R4路由表
	r4 := model.NewRouteTable("default", network.IPv4)

	net, _ := network.ParseIPNet("10.10.0.0/24")
	nextHop := &network.NextHop{}
	// Path1: Eth0/0 -> R7 -> R10 (5跳)
	nextHop.AddHop("Eth0/0", "10.4.7.2", false, false, nil)
	// Path5: Eth0/1 -> R6 -> R8 -> R9 -> R10 (7跳)
	nextHop.AddHop("Eth0/1", "10.4.6.2", false, false, nil)
	r4.AddRoute(net, nextHop)

	rq4 := NewRouteQuery(r4)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq4.QueryRoute(*dst, "Eth0/2", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.Matched {
		t.Error("R4应该匹配到路由")
	}

	if !result.IsECMP {
		t.Error("R4应该识别为ECMP路由（有2条路径）")
	}

	if len(result.NextHops) != 2 {
		t.Errorf("期望下一跳数量为2，实际为%d", len(result.NextHops))
	}

	// 验证包含Path5的接口
	hasPath5 := false
	for _, hop := range result.NextHops {
		if hop.Interface == "Eth0/1" {
			hasPath5 = true
			break
		}
	}
	if !hasPath5 {
		t.Error("应该包含Path5的接口Eth0/1")
	}
}

// TestMultihopRouting_RouteLoop 测试路由环路检测
func TestMultihopRouting_RouteLoop(t *testing.T) {
	// 创建路由表，输入端口和输出端口相同，应该检测到环路
	r1 := model.NewRouteTable("default", network.IPv4)

	net, _ := network.ParseIPNet("10.10.0.0/24")
	nextHop := &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.1.1.2", false, false, nil)
	r1.AddRoute(net, nextHop)

	rq1 := NewRouteQuery(r1)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	// 输入端口和输出端口相同，应该检测到环路
	result, err := rq1.QueryRoute(*dst, "Eth0/0", "default", network.IPv4)
	if err == nil {
		t.Error("应该检测到路由环路")
	}

	if result != nil && result.Matched {
		t.Error("不应该匹配到路由（环路）")
	}
}

// TestMultihopRouting_ConnectedRoute 测试直连路由
func TestMultihopRouting_ConnectedRoute(t *testing.T) {
	// 测试R10的直连路由
	r10 := model.NewRouteTable("default", network.IPv4)

	net, _ := network.ParseIPNet("10.10.0.0/24")
	nextHop := &network.NextHop{}
	nextHop.AddHop("Eth0/0", "10.10.0.1", true, false, nil) // 直连
	r10.AddRoute(net, nextHop)

	rq10 := NewRouteQuery(r10)
	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq10.QueryRoute(*dst, "Eth0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.Matched {
		t.Error("R10应该匹配到路由")
	}

	if !result.IsConnected {
		t.Error("应该识别为直连路由")
	}

	if result.IsECMP {
		t.Error("直连路由不应该是ECMP")
	}
}
