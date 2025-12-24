package model

import (
	"testing"
	"time"
)

// TestNewPathResult 测试创建路径结果
func TestNewPathResult(t *testing.T) {
	pathID := "path_123"
	pr := NewPathResult(pathID)

	if pr == nil {
		t.Fatal("PathResult不应该为空")
	}

	if pr.PathID != pathID {
		t.Errorf("期望PathID为%s，实际为%s", pathID, pr.PathID)
	}

	if pr.Hops == nil {
		t.Error("Hops不应该为nil")
	}

	if len(pr.Hops) != 0 {
		t.Errorf("期望初始Hops长度为0，实际为%d", len(pr.Hops))
	}

	if pr.Metadata == nil {
		t.Error("Metadata不应该为nil")
	}

	if pr.StartTime.IsZero() {
		t.Error("StartTime不应该为零值")
	}

	if !pr.EndTime.IsZero() {
		t.Error("EndTime应该为零值（未完成时）")
	}

	if pr.Success {
		t.Error("初始Success应该为false")
	}
}

// TestPathResult_AddHop 测试添加路径跳
func TestPathResult_AddHop(t *testing.T) {
	pr := NewPathResult("path_123")

	hop1 := &PathHop{
		Node:      "node1",
		InPort:    "port1",
		OutPort:   "port2",
		VRF:       "default",
		NextHopIP: "192.168.1.1",
	}

	hop2 := &PathHop{
		Node:      "node2",
		InPort:    "port3",
		OutPort:   "port4",
		VRF:       "default",
		NextHopIP: "192.168.1.2",
	}

	pr.AddHop(hop1)
	pr.AddHop(hop2)

	if len(pr.Hops) != 2 {
		t.Errorf("期望Hops长度为2，实际为%d", len(pr.Hops))
	}

	if pr.TotalHops != 2 {
		t.Errorf("期望TotalHops为2，实际为%d", pr.TotalHops)
	}

	// 验证HopIndex自动设置
	if pr.Hops[0].HopIndex != 0 {
		t.Errorf("期望第一个Hop的HopIndex为0，实际为%d", pr.Hops[0].HopIndex)
	}

	if pr.Hops[1].HopIndex != 1 {
		t.Errorf("期望第二个Hop的HopIndex为1，实际为%d", pr.Hops[1].HopIndex)
	}
}

// TestPathResult_Complete 测试完成路径
func TestPathResult_Complete(t *testing.T) {
	pr := NewPathResult("path_123")

	startTime := pr.StartTime
	time.Sleep(10 * time.Millisecond) // 确保时间差

	pr.Complete(true, nil)

	if !pr.Success {
		t.Error("期望Success为true")
	}

	if pr.Error != nil {
		t.Errorf("期望Error为nil，实际为%v", pr.Error)
	}

	if pr.EndTime.IsZero() {
		t.Error("EndTime不应该为零值")
	}

	if pr.EndTime.Before(startTime) {
		t.Error("EndTime应该在StartTime之后")
	}
}

// TestPathResult_Complete_WithError 测试完成路径（带错误）
func TestPathResult_Complete_WithError(t *testing.T) {
	pr := NewPathResult("path_123")

	err := &testError{msg: "测试错误"}
	pr.Complete(false, err)

	if pr.Success {
		t.Error("期望Success为false")
	}

	if pr.Error == nil {
		t.Error("期望Error不为nil")
	}

	if pr.Error.Error() != "测试错误" {
		t.Errorf("期望错误消息为'测试错误'，实际为%s", pr.Error.Error())
	}
}

// testError 用于测试的错误类型
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// TestPathResult_PathString 测试路径字符串表示
func TestPathResult_PathString(t *testing.T) {
	pr := NewPathResult("path_123")

	// 空路径
	pathStr := pr.PathString()
	if pathStr != "" {
		t.Errorf("期望空路径字符串为空，实际为%s", pathStr)
	}

	// 添加跳
	pr.AddHop(&PathHop{
		Node:    "node1",
		InPort:  "port1",
		OutPort: "port2",
	})

	pr.AddHop(&PathHop{
		Node:    "node2",
		InPort:  "port3",
		OutPort: "port4",
	})

	pathStr = pr.PathString()
	expected := "node1:port1->port2 -> node2:port3->port4"
	if pathStr != expected {
		t.Errorf("期望路径字符串为%s，实际为%s", expected, pathStr)
	}
}

// TestPathResult_PathString_NoOutPort 测试路径字符串（无输出端口）
func TestPathResult_PathString_NoOutPort(t *testing.T) {
	pr := NewPathResult("path_123")

	pr.AddHop(&PathHop{
		Node:    "node1",
		InPort:  "port1",
		OutPort: "", // 无输出端口（可能是最后一跳）
	})

	pathStr := pr.PathString()
	expected := "node1:port1"
	if pathStr != expected {
		t.Errorf("期望路径字符串为%s，实际为%s", expected, pathStr)
	}
}

// TestPathHop 测试路径跳
func TestPathHop(t *testing.T) {
	hop := &PathHop{
		Node:        "node1",
		InPort:      "port1",
		OutPort:     "port2",
		VRF:         "default",
		NextHopIP:   "192.168.1.1",
		IsConnected: false,
		IsECMP:      false,
		HopIndex:    0,
	}

	if hop.Node != "node1" {
		t.Errorf("期望Node为node1，实际为%s", hop.Node)
	}

	if hop.InPort != "port1" {
		t.Errorf("期望InPort为port1，实际为%s", hop.InPort)
	}

	if hop.OutPort != "port2" {
		t.Errorf("期望OutPort为port2，实际为%s", hop.OutPort)
	}

	if hop.VRF != "default" {
		t.Errorf("期望VRF为default，实际为%s", hop.VRF)
	}

	if hop.NextHopIP != "192.168.1.1" {
		t.Errorf("期望NextHopIP为192.168.1.1，实际为%s", hop.NextHopIP)
	}

	if hop.IsConnected {
		t.Error("期望IsConnected为false")
	}

	if hop.IsECMP {
		t.Error("期望IsECMP为false")
	}

	if hop.HopIndex != 0 {
		t.Errorf("期望HopIndex为0，实际为%d", hop.HopIndex)
	}
}

// TestPathHop_Connected 测试直连路径跳
func TestPathHop_Connected(t *testing.T) {
	hop := &PathHop{
		Node:        "node1",
		InPort:      "port1",
		OutPort:     "",
		VRF:         "default",
		IsConnected: true,
	}

	if !hop.IsConnected {
		t.Error("期望IsConnected为true")
	}

	if hop.OutPort != "" {
		t.Error("直连路由的OutPort应该为空")
	}
}

// TestPathHop_ECMP 测试ECMP路径跳
func TestPathHop_ECMP(t *testing.T) {
	hop := &PathHop{
		Node:      "node1",
		InPort:    "port1",
		OutPort:   "port2",
		VRF:       "default",
		NextHopIP: "192.168.1.1",
		IsECMP:    true,
	}

	if !hop.IsECMP {
		t.Error("期望IsECMP为true")
	}
}

// TestPathResult_Metadata 测试路径元数据
func TestPathResult_Metadata(t *testing.T) {
	pr := NewPathResult("path_123")

	pr.Metadata["key1"] = "value1"
	pr.Metadata["key2"] = 123
	pr.Metadata["key3"] = true

	if pr.Metadata["key1"] != "value1" {
		t.Errorf("期望key1为value1，实际为%v", pr.Metadata["key1"])
	}

	if pr.Metadata["key2"] != 123 {
		t.Errorf("期望key2为123，实际为%v", pr.Metadata["key2"])
	}

	if pr.Metadata["key3"] != true {
		t.Errorf("期望key3为true，实际为%v", pr.Metadata["key3"])
	}
}

// TestPathResult_MultipleHops 测试多个路径跳
func TestPathResult_MultipleHops(t *testing.T) {
	pr := NewPathResult("path_123")

	// 添加多个跳
	for i := 0; i < 5; i++ {
		hop := &PathHop{
			Node:      "node" + string(rune('1'+i)),
			InPort:    "port" + string(rune('1'+i)),
			OutPort:   "port" + string(rune('2'+i)),
			HopIndex:  i,
		}
		pr.AddHop(hop)
	}

	if len(pr.Hops) != 5 {
		t.Errorf("期望Hops长度为5，实际为%d", len(pr.Hops))
	}

	if pr.TotalHops != 5 {
		t.Errorf("期望TotalHops为5，实际为%d", pr.TotalHops)
	}

	// 验证每个跳的索引
	for i, hop := range pr.Hops {
		if hop.HopIndex != i {
			t.Errorf("期望Hop[%d]的HopIndex为%d，实际为%d", i, i, hop.HopIndex)
		}
	}
}

