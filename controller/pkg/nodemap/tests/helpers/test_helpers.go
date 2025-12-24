package helpers

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"go.uber.org/zap"
)

// CleanupTestData 清理测试数据
// 目前主要用于日志记录，未来可以扩展为实际的清理操作
func CleanupTestData(logger *zap.Logger) {
	if logger != nil {
		logger.Info("Cleaning up test data")
	}
}

// CompareNodeMaps 比较两个 NodeMap 的基本属性
// 返回差异列表
func CompareNodeMaps(nm1, nm2 *nodemap.NodeMap) []string {
	var differences []string

	if nm1.Name != nm2.Name {
		differences = append(differences, "Name mismatch")
	}

	if len(nm1.Nodes) != len(nm2.Nodes) {
		differences = append(differences, "Nodes count mismatch")
	}

	if len(nm1.Ports) != len(nm2.Ports) {
		differences = append(differences, "Ports count mismatch")
	}

	if len(nm1.Ipv4Areas) != len(nm2.Ipv4Areas) {
		differences = append(differences, "IPv4Areas count mismatch")
	}

	if len(nm1.Ipv6Areas) != len(nm2.Ipv6Areas) {
		differences = append(differences, "IPv6Areas count mismatch")
	}

	return differences
}
