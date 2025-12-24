package core

import (
	"context"
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/routing/graph"
	"github.com/influxdata/telegraf/controller/pkg/routing/model"
	"github.com/influxdata/telegraf/controller/pkg/routing/multipath"
	"github.com/influxdata/telegraf/controller/pkg/routing/query"
	"github.com/netxops/utils/network"
	"go.uber.org/zap"
)

var (
	ErrNoRoute          = fmt.Errorf("未找到路由")
	ErrNoNextHop        = fmt.Errorf("未找到下一跳")
	ErrPathLoop         = fmt.Errorf("路径环路")
	ErrMaxDepthExceeded = fmt.Errorf("超过最大路径深度")
	ErrMaxPathsExceeded = fmt.Errorf("超过最大路径数")
)

// PathCalculator 路径计算器
type PathCalculator struct {
	topology    graph.Topology
	pathTracker *multipath.PathTracker
	options     *query.PathQueryOptions
	logger      *zap.Logger
}

// NewPathCalculator 创建路径计算器
func NewPathCalculator(topology graph.Topology, options *query.PathQueryOptions) *PathCalculator {
	if options == nil {
		options = query.NewPathQueryOptions()
	}
	return &PathCalculator{
		topology:    topology,
		pathTracker: multipath.NewPathTracker(),
		options:     options,
	}
}

// WithLogger 设置日志器
func (pc *PathCalculator) WithLogger(logger *zap.Logger) *PathCalculator {
	pc.logger = logger
	return pc
}

// CalculatePath 计算路径
func (pc *PathCalculator) CalculatePath(ctx context.Context) ([]*model.PathResult, error) {
	if pc.options.Source == nil || pc.options.Destination == nil {
		return nil, fmt.Errorf("源网络和目标网络不能为空")
	}

	// 1. 定位源节点
	srcNode, srcPort, err := pc.topology.LocateSourceNode(
		*pc.options.Source,
		&graph.LocateOptions{
			VRF:     pc.options.VRF,
			Gateway: pc.options.Gateway,
			Area:    pc.options.Area,
			Node:    pc.options.SourceNode,
		})
	if err != nil {
		return nil, fmt.Errorf("定位源节点失败: %w", err)
	}

	// 2. 创建初始路径
	pathID := multipath.GeneratePathID("", srcNode.ID(), srcPort.VRF(), srcPort.Name(), "")
	pc.pathTracker.StartPath(pathID, "", false)

	// 3. 开始路径计算
	return pc.calculatePathRecursive(ctx, srcNode, srcPort, pathID, *pc.options.Destination)
}

// calculatePathRecursive 递归计算路径
func (pc *PathCalculator) calculatePathRecursive(
	ctx context.Context,
	node model.Node,
	inPort model.Port,
	pathID multipath.PathID,
	dst network.NetworkList) ([]*model.PathResult, error) {

	// 1. 检查路径状态（环路检测）
	if pc.pathTracker.CheckNodeVisited(pathID, node.ID()) {
		if pc.logger != nil {
			pc.logger.Warn("检测到路径环路",
				zap.String("路径", string(pathID)),
				zap.String("节点", node.ID()))
		}
		return nil, ErrPathLoop
	}

	// 2. 检查最大深度
	if pc.options.MaxDepth > 0 {
		depth := pc.pathTracker.GetPathDepth(pathID)
		if depth >= pc.options.MaxDepth {
			if pc.logger != nil {
				pc.logger.Warn("超过最大路径深度",
					zap.String("路径", string(pathID)),
					zap.Int("深度", depth))
			}
			return nil, ErrMaxDepthExceeded
		}
	}

	// 3. 添加节点到路径
	pc.pathTracker.AddNodeToPath(pathID, node.ID())

	// 4. 查询路由
	routeQuery := NewRouteQuery(nil) // 需要从node获取路由表
	routeTable, err := node.GetRouteTable(inPort.VRF(), pc.options.IPFamily)
	if err != nil {
		pc.pathTracker.CompletePath(pathID, false, err)
		return nil, fmt.Errorf("获取路由表失败: %w", err)
	}

	routeQuery.routeTable = routeTable
	routeResult, err := routeQuery.QueryRoute(dst, inPort.Name(), inPort.VRF(), pc.options.IPFamily)
	if err != nil {
		pc.pathTracker.CompletePath(pathID, false, err)
		return nil, err
	}

	if !routeResult.Matched {
		pc.pathTracker.CompletePath(pathID, false, ErrNoRoute)
		return nil, ErrNoRoute
	}

	// 5. 处理直连路由
	if routeResult.IsConnected {
		pathResult := model.NewPathResult(string(pathID))
		pathResult.AddHop(&model.PathHop{
			Node:        node.ID(),
			InPort:      inPort.Name(),
			OutPort:     "",
			VRF:         inPort.VRF(),
			IsConnected: true,
		})
		pathResult.Complete(true, nil)
		pc.pathTracker.CompletePath(pathID, true, nil)
		return []*model.PathResult{pathResult}, nil
	}

	// 6. 处理下一跳
	if len(routeResult.NextHops) == 0 {
		pc.pathTracker.CompletePath(pathID, false, ErrNoNextHop)
		return nil, ErrNoNextHop
	}

	// 7. 多路径处理
	if len(routeResult.NextHops) > 1 && pc.options.EnableECMP {
		return pc.handleECMP(ctx, node, inPort, pathID, routeResult.NextHops, dst)
	}

	// 8. 单路径处理
	return pc.handleSinglePath(ctx, node, inPort, pathID, routeResult.NextHops[0], dst)
}

// handleECMP 处理ECMP（多路径）
func (pc *PathCalculator) handleECMP(
	ctx context.Context,
	node model.Node,
	inPort model.Port,
	parentPathID multipath.PathID,
	nextHops []*model.NextHopInfo,
	dst network.NetworkList) ([]*model.PathResult, error) {

	var allPaths []*model.PathResult

	// 检查路径数量限制
	if pc.options.MaxPaths > 0 {
		stats := pc.pathTracker.GetStats()
		if stats.TotalPaths >= pc.options.MaxPaths {
			if pc.logger != nil {
				pc.logger.Warn("达到最大路径数限制",
					zap.Int("当前路径数", stats.TotalPaths),
					zap.Int("最大路径数", pc.options.MaxPaths))
			}
			return nil, ErrMaxPathsExceeded
		}
	}

	// 为每个下一跳创建独立的路径分支
	for i, nextHop := range nextHops {
		// 创建新的路径ID
		branchPathID := multipath.GeneratePathID(
			parentPathID, node.ID(), inPort.VRF(), inPort.Name(), nextHop.Interface)

		// 启动新路径跟踪
		pc.pathTracker.StartPath(branchPathID, parentPathID, true)

		// 查找下一跳节点
		connector, err := pc.topology.GetConnector(inPort.ConnectorID())
		if err != nil {
			pc.pathTracker.CompletePath(branchPathID, false, err)
			continue
		}

		nextNode, nextPort, err := connector.SelectNodeByIP(nextHop.NextHopIP, inPort.VRF())
		if err != nil {
			pc.pathTracker.CompletePath(branchPathID, false, err)
			continue
		}

		// 递归计算路径
		branchPaths, err := pc.calculatePathRecursive(ctx, nextNode, nextPort, branchPathID, dst)
		if err != nil {
			pc.pathTracker.CompletePath(branchPathID, false, err)
			if pc.logger != nil {
				pc.logger.Warn("ECMP路径分支处理失败",
					zap.Int("分支索引", i),
					zap.String("路径", string(branchPathID)),
					zap.Error(err))
			}
			continue
		}

		// 为每个分支路径添加当前跳
		for _, branchPath := range branchPaths {
			// 在路径开头添加当前跳
			currentHop := &model.PathHop{
				Node:      node.ID(),
				InPort:    inPort.Name(),
				OutPort:   nextHop.Interface,
				VRF:       inPort.VRF(),
				NextHopIP: nextHop.NextHopIP,
				IsECMP:    true,
			}
			branchPath.Hops = append([]*model.PathHop{currentHop}, branchPath.Hops...)
			branchPath.TotalHops = len(branchPath.Hops)
			branchPath.IsECMP = true
		}

		allPaths = append(allPaths, branchPaths...)
	}

	return allPaths, nil
}

// handleSinglePath 处理单路径
func (pc *PathCalculator) handleSinglePath(
	ctx context.Context,
	node model.Node,
	inPort model.Port,
	pathID multipath.PathID,
	nextHop *model.NextHopInfo,
	dst network.NetworkList) ([]*model.PathResult, error) {

	// 查找下一跳节点
	connector, err := pc.topology.GetConnector(inPort.ConnectorID())
	if err != nil {
		pc.pathTracker.CompletePath(pathID, false, err)
		return nil, err
	}

	nextNode, nextPort, err := connector.SelectNodeByIP(nextHop.NextHopIP, inPort.VRF())
	if err != nil {
		pc.pathTracker.CompletePath(pathID, false, err)
		return nil, err
	}

	// 递归计算路径
	paths, err := pc.calculatePathRecursive(ctx, nextNode, nextPort, pathID, dst)
	if err != nil {
		pc.pathTracker.CompletePath(pathID, false, err)
		return nil, err
	}

	// 为每个路径添加当前跳
	for _, path := range paths {
		currentHop := &model.PathHop{
			Node:      node.ID(),
			InPort:    inPort.Name(),
			OutPort:   nextHop.Interface,
			VRF:       inPort.VRF(),
			NextHopIP: nextHop.NextHopIP,
		}
		path.Hops = append([]*model.PathHop{currentHop}, path.Hops...)
		path.TotalHops = len(path.Hops)
	}

	return paths, nil
}
