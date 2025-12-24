package nodemap

import (
	"testing"

	"github.com/netxops/utils/policy"
	"go.uber.org/zap"
)

func TestRoutePathString(t *testing.T) {
	// 创建测试用的logger
	logger := zap.NewNop()

	// 创建测试用的Intent
	intent := &policy.Intent{
		// 这里需要根据实际的policy.Intent结构来设置
	}

	// 创建RouteTracer
	tracer := NewRouteTracer(logger, intent)

	// 添加路由跳信息（使用新的LogRouteHop方法）
	tracer.LogRouteHop("Eth-Trunk21.101", "YZ-YiZ-C8U31-FW-1.DCN.Edu1000E", "Eth-Trunk21.102")

	// 获取路由路径字符串
	pathString := tracer.GetRoutePathString()

	// 验证路径格式
	expected := "[[Eth-Trunk21.101、YZ-YiZ-C8U31-FW-1.DCN.Edu1000E、Eth-Trunk21.102]]"
	if pathString != expected {
		t.Errorf("路由路径格式不正确，期望: %s, 实际: %s", expected, pathString)
	}

	t.Logf("路由路径: %s", pathString)
}

func TestRoutePathStringMultipleHops(t *testing.T) {
	// 创建测试用的logger
	logger := zap.NewNop()

	// 创建测试用的Intent
	intent := &policy.Intent{
		// 这里需要根据实际的policy.Intent结构来设置
	}

	// 创建RouteTracer
	tracer := NewRouteTracer(logger, intent)

	// 添加多个路由跳信息
	tracer.AddRouteHop("eth0", "firewall-01", "eth1")
	tracer.AddRouteHop("eth1", "router-01", "eth2")
	tracer.LogDestinationNode("eth3", "server-01")

	// 获取路由路径字符串
	pathString := tracer.GetRoutePathString()

	// 验证路径格式
	expected := "[[eth0、firewall-01、eth1] [eth1、router-01、eth2] [eth3、server-01]]"
	if pathString != expected {
		t.Errorf("多跳路由路径格式不正确，期望: %s, 实际: %s", expected, pathString)
	}

	t.Logf("多跳路由路径: %s", pathString)
}
