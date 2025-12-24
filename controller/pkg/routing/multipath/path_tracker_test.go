package multipath

import (
	"testing"
)

func TestPathTracker_StartPath(t *testing.T) {
	pt := NewPathTracker()

	// 启动路径
	pathID := PathID("path_1")
	pt.StartPath(pathID, "", false)

	// 验证路径状态
	state, err := pt.GetPathState(pathID)
	if err != nil {
		t.Fatalf("获取路径状态失败: %v", err)
	}

	if state != PathStateRunning {
		t.Errorf("期望路径状态为Running，实际为%v", state)
	}

	// 验证统计信息
	stats := pt.GetStats()
	if stats.TotalPaths != 1 {
		t.Errorf("期望总路径数为1，实际为%d", stats.TotalPaths)
	}
}

func TestPathTracker_AddNodeToPath(t *testing.T) {
	pt := NewPathTracker()

	// 启动路径
	pathID := PathID("path_1")
	pt.StartPath(pathID, "", false)

	// 添加节点
	nodeKey := "node_1"
	pt.AddNodeToPath(pathID, nodeKey)

	// 验证节点是否在路径上
	if !pt.CheckNodeVisited(pathID, nodeKey) {
		t.Error("节点应该已经在路径上")
	}

	// 验证路径深度
	depth := pt.GetPathDepth(pathID)
	if depth != 1 {
		t.Errorf("期望路径深度为1，实际为%d", depth)
	}

	// 验证节点路径映射
	nodePaths := pt.GetNodePaths(nodeKey)
	if len(nodePaths) != 1 {
		t.Errorf("期望节点路径数为1，实际为%d", len(nodePaths))
	}

	if nodePaths[0] != pathID {
		t.Errorf("期望路径ID为%s，实际为%s", pathID, nodePaths[0])
	}
}

func TestPathTracker_CompletePath(t *testing.T) {
	pt := NewPathTracker()

	// 启动路径
	pathID := PathID("path_1")
	pt.StartPath(pathID, "", false)

	// 添加节点
	pt.AddNodeToPath(pathID, "node_1")
	pt.AddNodeToPath(pathID, "node_2")

	// 完成路径（成功）
	pt.CompletePath(pathID, true, nil)

	// 验证路径状态
	state, err := pt.GetPathState(pathID)
	if err != nil {
		t.Fatalf("获取路径状态失败: %v", err)
	}

	if state != PathStateSuccess {
		t.Errorf("期望路径状态为Success，实际为%v", state)
	}

	// 验证统计信息
	stats := pt.GetStats()
	if stats.SuccessPaths != 1 {
		t.Errorf("期望成功路径数为1，实际为%d", stats.SuccessPaths)
	}
}

func TestPathTracker_ECMP(t *testing.T) {
	pt := NewPathTracker()

	// 启动父路径
	parentPathID := PathID("path_parent")
	pt.StartPath(parentPathID, "", false)

	// 启动ECMP子路径
	childPathID1 := PathID("path_child_1")
	pt.StartPath(childPathID1, parentPathID, true)

	childPathID2 := PathID("path_child_2")
	pt.StartPath(childPathID2, parentPathID, true)

	// 验证统计信息
	stats := pt.GetStats()
	if stats.ECMPPaths != 2 {
		t.Errorf("期望ECMP路径数为2，实际为%d", stats.ECMPPaths)
	}

	// 验证路径关系
	pathInfo, err := pt.GetPathInfo(childPathID1)
	if err != nil {
		t.Fatalf("获取路径信息失败: %v", err)
	}

	if pathInfo.ParentPathID != parentPathID {
		t.Errorf("期望父路径ID为%s，实际为%s", parentPathID, pathInfo.ParentPathID)
	}

	if !pathInfo.IsECMP {
		t.Error("路径应该标记为ECMP")
	}
}

func TestPathTracker_MergeNodeResults(t *testing.T) {
	pt := NewPathTracker()

	// 启动多条路径
	pathID1 := PathID("path_1")
	pt.StartPath(pathID1, "", false)
	pt.AddNodeToPath(pathID1, "node_1")
	pt.AddNodeResult(pathID1, "node_1", "result_1")

	pathID2 := PathID("path_2")
	pt.StartPath(pathID2, "", false)
	pt.AddNodeToPath(pathID2, "node_1")
	pt.AddNodeResult(pathID2, "node_1", "result_2")

	// 合并节点结果
	mergedResult := pt.MergeNodeResults("node_1")

	// 验证合并结果
	if mergedResult == nil {
		t.Fatal("合并结果为空")
	}

	results, ok := mergedResult.([]interface{})
	if !ok {
		t.Fatal("合并结果类型不正确")
	}

	if len(results) != 2 {
		t.Errorf("期望合并结果数量为2，实际为%d", len(results))
	}

	// 验证统计信息
	stats := pt.GetStats()
	if stats.MergedNodes != 1 {
		t.Errorf("期望合并节点数为1，实际为%d", stats.MergedNodes)
	}
}

func TestGeneratePathID(t *testing.T) {
	// 测试根路径ID生成
	pathID1 := GeneratePathID("", "node_1", "default", "port_1", "")
	if pathID1 == "" {
		t.Error("路径ID不应该为空")
	}

	// 测试子路径ID生成
	parentPathID := PathID("path_parent")
	pathID2 := GeneratePathID(parentPathID, "node_2", "default", "port_1", "port_2")
	if pathID2 == "" {
		t.Error("路径ID不应该为空")
	}

	if pathID2 == pathID1 {
		t.Error("不同路径的ID应该不同")
	}
}

