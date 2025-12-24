package multipath

import (
	"fmt"
	"sync"
	"time"

	"github.com/netxops/utils/tools"
)

// PathID 路径唯一标识
type PathID string

// PathState 路径状态
type PathState int

const (
	PathStatePending PathState = iota
	PathStateRunning
	PathStateSuccess
	PathStateFailed
	PathStateMerged
)

func (ps PathState) String() string {
	switch ps {
	case PathStatePending:
		return "pending"
	case PathStateRunning:
		return "running"
	case PathStateSuccess:
		return "success"
	case PathStateFailed:
		return "failed"
	case PathStateMerged:
		return "merged"
	default:
		return "unknown"
	}
}

// PathTracker 路径跟踪器
type PathTracker struct {
	mu sync.RWMutex

	// 路径管理
	paths map[PathID]*PathStateInfo // 所有路径的状态

	// 节点路径映射：记录每个节点被哪些路径访问
	nodePaths map[string]map[PathID]bool // nodeKey -> pathIDs

	// 路径节点映射：记录每条路径经过的节点
	pathNodes map[PathID][]string // pathID -> nodeKeys

	// 路径结果映射：记录每条路径上每个节点的处理结果
	pathResults map[PathID]map[string]interface{} // pathID -> nodeKey -> result

	// 路径关系：记录路径的分支和合并关系
	pathRelations map[PathID]*PathRelation // pathID -> relation

	// 统计信息
	stats *PathTrackerStats
}

// PathStateInfo 路径状态信息
type PathStateInfo struct {
	PathID       PathID
	State        PathState
	ParentPathID PathID // 父路径ID（如果是从父路径分支）
	BranchIndex  int    // 分支索引（同一节点的多个分支）
	StartTime    time.Time
	EndTime      time.Time
	Error        error
	NodeCount    int  // 路径上的节点数量
	IsECMP       bool // 是否为ECMP路径
}

// PathRelation 路径关系
type PathRelation struct {
	ParentPathID PathID   // 父路径
	ChildPathIDs []PathID // 子路径（分支）
	MergePathID  PathID   // 合并到的路径（如果与其他路径合并）
}

// PathTrackerStats 路径跟踪统计
type PathTrackerStats struct {
	TotalPaths     int
	SuccessPaths   int
	FailedPaths    int
	ECMPPaths      int
	MergedNodes    int // 合并的节点数量
	MaxPathDepth   int // 最大路径深度
	AvgPathLength  float64 // 平均路径长度
}

// NewPathTracker 创建路径跟踪器
func NewPathTracker() *PathTracker {
	return &PathTracker{
		paths:        make(map[PathID]*PathStateInfo),
		nodePaths:    make(map[string]map[PathID]bool),
		pathNodes:    make(map[PathID][]string),
		pathResults:  make(map[PathID]map[string]interface{}),
		pathRelations: make(map[PathID]*PathRelation),
		stats:        &PathTrackerStats{},
	}
}

// GeneratePathID 生成路径ID
func GeneratePathID(parentPathID PathID, nodeID, vrf, inPort, outPort string) PathID {
	if parentPathID == "" {
		// 根路径
		return PathID(fmt.Sprintf("path_%s_%s_%s", vrf, nodeID, inPort))
	}
	// 子路径（从父路径分支）
	return PathID(fmt.Sprintf("%s->%s:%s:%s->%s",
		parentPathID, vrf, nodeID, inPort, outPort))
}

// StartPath 开始跟踪一条新路径
func (pt *PathTracker) StartPath(pathID PathID, parentPathID PathID, isECMP bool) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.paths[pathID] = &PathStateInfo{
		PathID:       pathID,
		State:        PathStateRunning,
		ParentPathID: parentPathID,
		StartTime:    time.Now(),
		IsECMP:       isECMP,
	}

	pt.pathNodes[pathID] = []string{}
	pt.pathResults[pathID] = make(map[string]interface{})

	if parentPathID != "" {
		// 记录路径关系
		if pt.pathRelations[parentPathID] == nil {
			pt.pathRelations[parentPathID] = &PathRelation{
				ParentPathID: parentPathID,
				ChildPathIDs: []PathID{},
			}
		}
		pt.pathRelations[parentPathID].ChildPathIDs = append(
			pt.pathRelations[parentPathID].ChildPathIDs, pathID)
	}

	pt.stats.TotalPaths++
	if isECMP {
		pt.stats.ECMPPaths++
	}
}

// AddNodeToPath 将节点添加到路径
func (pt *PathTracker) AddNodeToPath(pathID PathID, nodeKey string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	// 添加到路径节点列表
	if pt.pathNodes[pathID] == nil {
		pt.pathNodes[pathID] = []string{}
	}
	pt.pathNodes[pathID] = append(pt.pathNodes[pathID], nodeKey)

	// 更新节点路径映射
	if pt.nodePaths[nodeKey] == nil {
		pt.nodePaths[nodeKey] = make(map[PathID]bool)
	}
	pt.nodePaths[nodeKey][pathID] = true

	// 更新路径节点计数
	if pathInfo, exists := pt.paths[pathID]; exists {
		pathInfo.NodeCount = len(pt.pathNodes[pathID])
	}
}

// AddNodeResult 添加节点处理结果
func (pt *PathTracker) AddNodeResult(pathID PathID, nodeKey string, result interface{}) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if pt.pathResults[pathID] == nil {
		pt.pathResults[pathID] = make(map[string]interface{})
	}

	pt.pathResults[pathID][nodeKey] = result
}

// CompletePath 完成路径（成功或失败）
func (pt *PathTracker) CompletePath(pathID PathID, success bool, err error) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if pathInfo, exists := pt.paths[pathID]; exists {
		pathInfo.EndTime = time.Now()
		if success {
			pathInfo.State = PathStateSuccess
			pt.stats.SuccessPaths++
		} else {
			pathInfo.State = PathStateFailed
			pathInfo.Error = err
			pt.stats.FailedPaths++
		}
	}
}

// CheckNodeVisited 检查节点是否在特定路径上已访问
func (pt *PathTracker) CheckNodeVisited(pathID PathID, nodeKey string) bool {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	// 检查节点是否在当前路径上
	if nodes, exists := pt.pathNodes[pathID]; exists {
		return tools.Contains(nodes, nodeKey)
	}
	return false
}

// GetNodePaths 获取访问过节点的所有路径
func (pt *PathTracker) GetNodePaths(nodeKey string) []PathID {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if paths, exists := pt.nodePaths[nodeKey]; exists {
		result := make([]PathID, 0, len(paths))
		for pathID := range paths {
			result = append(result, pathID)
		}
		return result
	}
	return []PathID{}
}

// GetPathDepth 获取路径深度
func (pt *PathTracker) GetPathDepth(pathID PathID) int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if nodes, exists := pt.pathNodes[pathID]; exists {
		return len(nodes)
	}
	return 0
}

// GetPathState 获取路径状态
func (pt *PathTracker) GetPathState(pathID PathID) (PathState, error) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if pathInfo, exists := pt.paths[pathID]; exists {
		return pathInfo.State, nil
	}
	return PathStatePending, fmt.Errorf("路径不存在: %s", pathID)
}

// GetPathInfo 获取路径信息
func (pt *PathTracker) GetPathInfo(pathID PathID) (*PathStateInfo, error) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if pathInfo, exists := pt.paths[pathID]; exists {
		return pathInfo, nil
	}
	return nil, fmt.Errorf("路径不存在: %s", pathID)
}

// GetStats 获取路径统计信息
func (pt *PathTracker) GetStats() *PathTrackerStats {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	// 计算平均路径长度
	totalLength := 0
	for _, nodes := range pt.pathNodes {
		totalLength += len(nodes)
	}
	if pt.stats.TotalPaths > 0 {
		pt.stats.AvgPathLength = float64(totalLength) / float64(pt.stats.TotalPaths)
	}

	// 计算最大路径深度
	maxDepth := 0
	for _, nodes := range pt.pathNodes {
		if len(nodes) > maxDepth {
			maxDepth = len(nodes)
		}
	}
	pt.stats.MaxPathDepth = maxDepth

	return pt.stats
}

// MergeNodeResults 合并节点在不同路径上的结果
func (pt *PathTracker) MergeNodeResults(nodeKey string) interface{} {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	// 获取访问过该节点的所有路径
	pathIDs := pt.GetNodePaths(nodeKey)
	if len(pathIDs) == 0 {
		return nil
	}

	if len(pathIDs) == 1 {
		// 只有一条路径，直接返回
		if results, exists := pt.pathResults[pathIDs[0]]; exists {
			if result, exists := results[nodeKey]; exists {
				return result
			}
		}
		return nil
	}

	// 多条路径：合并结果
	// 这里返回所有路径的结果，由调用者决定如何合并
	allResults := make([]interface{}, 0, len(pathIDs))
	for _, pathID := range pathIDs {
		if results, exists := pt.pathResults[pathID]; exists {
			if result, exists := results[nodeKey]; exists {
				allResults = append(allResults, result)
			}
		}
	}

	pt.stats.MergedNodes++
	return allResults
}

