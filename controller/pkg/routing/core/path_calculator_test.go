package core

import (
	"context"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/routing/graph"
	"github.com/influxdata/telegraf/controller/pkg/routing/query"
	"github.com/netxops/utils/network"
	"go.uber.org/zap"
)

// TestNewPathCalculator 测试创建路径计算器
func TestNewPathCalculator(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	pc := NewPathCalculator(topology, options)

	if pc == nil {
		t.Fatal("PathCalculator不应该为空")
	}

	if pc.topology == nil {
		t.Error("topology不应该为nil")
	}

	if pc.pathTracker == nil {
		t.Error("pathTracker不应该为nil")
	}

	if pc.options == nil {
		t.Error("options不应该为nil")
	}

	if pc.options != options {
		t.Error("options应该是指定的options")
	}
}

// TestNewPathCalculator_NilOptions 测试使用nil选项创建路径计算器
func TestNewPathCalculator_NilOptions(t *testing.T) {
	topology := graph.NewBaseTopology()
	pc := NewPathCalculator(topology, nil)

	if pc == nil {
		t.Fatal("PathCalculator不应该为空")
	}

	if pc.options == nil {
		t.Error("options不应该为nil（应该使用默认值）")
	}

	// 验证默认选项
	if pc.options.VRF != "default" {
		t.Errorf("期望默认VRF为default，实际为%s", pc.options.VRF)
	}

	if pc.options.IPFamily != network.IPv4 {
		t.Errorf("期望默认IPFamily为IPv4，实际为%v", pc.options.IPFamily)
	}

	if pc.options.MaxPaths != 100 {
		t.Errorf("期望默认MaxPaths为100，实际为%d", pc.options.MaxPaths)
	}

	if !pc.options.EnableECMP {
		t.Error("期望默认EnableECMP为true")
	}

	if pc.options.MaxDepth != 50 {
		t.Errorf("期望默认MaxDepth为50，实际为%d", pc.options.MaxDepth)
	}
}

// TestPathCalculator_WithLogger 测试设置日志器
func TestPathCalculator_WithLogger(t *testing.T) {
	topology := graph.NewBaseTopology()
	pc := NewPathCalculator(topology, nil)

	if pc.logger != nil {
		t.Error("初始logger应该为nil")
	}

	logger := zap.NewNop()
	pc = pc.WithLogger(logger)

	if pc.logger == nil {
		t.Error("设置logger后不应该为nil")
	}

	if pc.logger != logger {
		t.Error("logger应该是指定的logger")
	}
}

// TestPathCalculator_CalculatePath_NoSource 测试源网络为空
func TestPathCalculator_CalculatePath_NoSource(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	options.Source = nil

	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}
	options.Destination = dst

	pc := NewPathCalculator(topology, options)

	ctx := context.Background()
	paths, err := pc.CalculatePath(ctx)

	if err == nil {
		t.Error("应该返回错误（源网络为空）")
	}

	if paths != nil {
		t.Error("路径应该为nil")
	}
}

// TestPathCalculator_CalculatePath_NoDestination 测试目标网络为空
func TestPathCalculator_CalculatePath_NoDestination(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	options.Destination = nil

	srcNet, err := network.NewNetworkFromString("10.1.0.1/32")
	if err != nil {
		t.Fatalf("创建源网络失败: %v", err)
	}
	src, err := network.NewNetworkListFromList([]network.AbbrNet{srcNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}
	options.Source = src

	pc := NewPathCalculator(topology, options)

	ctx := context.Background()
	paths, err := pc.CalculatePath(ctx)

	if err == nil {
		t.Error("应该返回错误（目标网络为空）")
	}

	if paths != nil {
		t.Error("路径应该为nil")
	}
}

// TestPathCalculator_CalculatePath_NoSourceAndDestination 测试源和目标都为空
func TestPathCalculator_CalculatePath_NoSourceAndDestination(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	options.Source = nil
	options.Destination = nil

	pc := NewPathCalculator(topology, options)

	ctx := context.Background()
	paths, err := pc.CalculatePath(ctx)

	if err == nil {
		t.Error("应该返回错误（源和目标网络为空）")
	}

	if paths != nil {
		t.Error("路径应该为nil")
	}
}

// TestPathCalculator_CalculatePath_TopologyNotImplemented 测试拓扑未实现
func TestPathCalculator_CalculatePath_TopologyNotImplemented(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()

	srcNet, err := network.NewNetworkFromString("10.1.0.1/32")
	if err != nil {
		t.Fatalf("创建源网络失败: %v", err)
	}
	src, err := network.NewNetworkListFromList([]network.AbbrNet{srcNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}
	options.Source = src

	dstNet, err := network.NewNetworkFromString("10.10.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}
	options.Destination = dst

	pc := NewPathCalculator(topology, options)

	ctx := context.Background()
	paths, err := pc.CalculatePath(ctx)

	// BaseTopology 的 LocateSourceNode 返回未实现错误
	if err == nil {
		t.Error("应该返回错误（拓扑未实现）")
	}

	if paths != nil {
		t.Error("路径应该为nil")
	}
}

// TestPathCalculator_Options_MaxDepth 测试最大深度选项
func TestPathCalculator_Options_MaxDepth(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	options.MaxDepth = 5

	pc := NewPathCalculator(topology, options)

	if pc.options.MaxDepth != 5 {
		t.Errorf("期望MaxDepth为5，实际为%d", pc.options.MaxDepth)
	}
}

// TestPathCalculator_Options_MaxPaths 测试最大路径数选项
func TestPathCalculator_Options_MaxPaths(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	options.MaxPaths = 10

	pc := NewPathCalculator(topology, options)

	if pc.options.MaxPaths != 10 {
		t.Errorf("期望MaxPaths为10，实际为%d", pc.options.MaxPaths)
	}
}

// TestPathCalculator_Options_EnableECMP 测试ECMP选项
func TestPathCalculator_Options_EnableECMP(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	options.EnableECMP = false

	pc := NewPathCalculator(topology, options)

	if pc.options.EnableECMP {
		t.Error("期望EnableECMP为false")
	}
}

// TestPathCalculator_Options_VRF 测试VRF选项
func TestPathCalculator_Options_VRF(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	options.VRF = "vrf1"

	pc := NewPathCalculator(topology, options)

	if pc.options.VRF != "vrf1" {
		t.Errorf("期望VRF为vrf1，实际为%s", pc.options.VRF)
	}
}

// TestPathCalculator_Options_IPFamily 测试IPFamily选项
func TestPathCalculator_Options_IPFamily(t *testing.T) {
	topology := graph.NewBaseTopology()
	options := query.NewPathQueryOptions()
	options.IPFamily = network.IPv6

	pc := NewPathCalculator(topology, options)

	if pc.options.IPFamily != network.IPv6 {
		t.Errorf("期望IPFamily为IPv6，实际为%v", pc.options.IPFamily)
	}
}

// TestPathCalculator_PathTracker 测试路径跟踪器
func TestPathCalculator_PathTracker(t *testing.T) {
	topology := graph.NewBaseTopology()
	pc := NewPathCalculator(topology, nil)

	if pc.pathTracker == nil {
		t.Fatal("pathTracker不应该为nil")
	}

	// 测试路径跟踪器的基本功能
	stats := pc.pathTracker.GetStats()
	if stats == nil {
		t.Error("GetStats不应该返回nil")
	}

	if stats.TotalPaths != 0 {
		t.Errorf("期望初始TotalPaths为0，实际为%d", stats.TotalPaths)
	}
}

// TestPathCalculator_ErrorConstants 测试错误常量
func TestPathCalculator_ErrorConstants(t *testing.T) {
	if ErrNoRoute == nil {
		t.Error("ErrNoRoute不应该为nil")
	}

	if ErrNoNextHop == nil {
		t.Error("ErrNoNextHop不应该为nil")
	}

	if ErrPathLoop == nil {
		t.Error("ErrPathLoop不应该为nil")
	}

	if ErrMaxDepthExceeded == nil {
		t.Error("ErrMaxDepthExceeded不应该为nil")
	}

	if ErrMaxPathsExceeded == nil {
		t.Error("ErrMaxPathsExceeded不应该为nil")
	}

	// 验证错误消息
	if ErrNoRoute.Error() != "未找到路由" {
		t.Errorf("期望ErrNoRoute消息为'未找到路由'，实际为%s", ErrNoRoute.Error())
	}

	if ErrNoNextHop.Error() != "未找到下一跳" {
		t.Errorf("期望ErrNoNextHop消息为'未找到下一跳'，实际为%s", ErrNoNextHop.Error())
	}

	if ErrPathLoop.Error() != "路径环路" {
		t.Errorf("期望ErrPathLoop消息为'路径环路'，实际为%s", ErrPathLoop.Error())
	}

	if ErrMaxDepthExceeded.Error() != "超过最大路径深度" {
		t.Errorf("期望ErrMaxDepthExceeded消息为'超过最大路径深度'，实际为%s", ErrMaxDepthExceeded.Error())
	}

	if ErrMaxPathsExceeded.Error() != "超过最大路径数" {
		t.Errorf("期望ErrMaxPathsExceeded消息为'超过最大路径数'，实际为%s", ErrMaxPathsExceeded.Error())
	}
}

// TestPathCalculator_WithLogger_Chain 测试链式调用WithLogger
func TestPathCalculator_WithLogger_Chain(t *testing.T) {
	topology := graph.NewBaseTopology()
	pc := NewPathCalculator(topology, nil)

	logger1 := zap.NewNop()
	logger2 := zap.NewNop()

	pc = pc.WithLogger(logger1).WithLogger(logger2)

	if pc.logger != logger2 {
		t.Error("最后设置的logger应该生效")
	}
}

// TestPathCalculator_Options_DefaultValues 测试默认选项值
func TestPathCalculator_Options_DefaultValues(t *testing.T) {
	topology := graph.NewBaseTopology()
	pc := NewPathCalculator(topology, nil)

	// 验证所有默认值
	if pc.options.VRF != "default" {
		t.Errorf("期望默认VRF为default，实际为%s", pc.options.VRF)
	}

	if pc.options.IPFamily != network.IPv4 {
		t.Errorf("期望默认IPFamily为IPv4，实际为%v", pc.options.IPFamily)
	}

	if pc.options.MaxPaths != 100 {
		t.Errorf("期望默认MaxPaths为100，实际为%d", pc.options.MaxPaths)
	}

	if !pc.options.EnableECMP {
		t.Error("期望默认EnableECMP为true")
	}

	if pc.options.MaxDepth != 50 {
		t.Errorf("期望默认MaxDepth为50，实际为%d", pc.options.MaxDepth)
	}

	if pc.options.Gateway != "" {
		t.Errorf("期望默认Gateway为空，实际为%s", pc.options.Gateway)
	}

	if pc.options.Area != "" {
		t.Errorf("期望默认Area为空，实际为%s", pc.options.Area)
	}

	if pc.options.SourceNode != "" {
		t.Errorf("期望默认SourceNode为空，实际为%s", pc.options.SourceNode)
	}
}
