package core

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/routing/model"
	"github.com/netxops/utils/network"
)

// RouteQuery 路由查询器
type RouteQuery struct {
	routeTable *model.RouteTable
}

// NewRouteQuery 创建路由查询器
func NewRouteQuery(routeTable *model.RouteTable) *RouteQuery {
	return &RouteQuery{
		routeTable: routeTable,
	}
}

// QueryRoute 查询路由（支持多路径）
func (rq *RouteQuery) QueryRoute(
	dst network.NetworkList,
	inPort, vrf string,
	ipFamily network.IPFamily) (*model.RouteResult, error) {

	if rq.routeTable == nil {
		return nil, fmt.Errorf("路由表为空")
	}

	// 1. 在路由表中匹配目标网络
	rmr, err := rq.routeTable.QueryRoute(dst)
	if err != nil {
		return nil, err
	}

	// 2. 检查是否完全匹配
	// 如果 Match 为 nil，说明没有匹配到路由
	if rmr.Match == nil {
		return &model.RouteResult{Matched: false}, nil
	}

	// 3. 支持多路径：不再检查 IsSameIp，直接返回所有匹配的路由
	match := rmr.Match
	if match == nil {
		return &model.RouteResult{Matched: false}, nil
	}

	// 4. 提取输出接口
	outInterfaces := match.Column("interface").List().Distinct()

	var outPortList []string
	var nextHops []*model.NextHopInfo

	for _, p := range outInterfaces {
		portName := p.(string)
		if portName == inPort {
			// 输入端口不能是输出端口，防止环路
			return nil, fmt.Errorf("路由环路: 节点输入端口 %s 在输出端口列表中", inPort)
		}
		outPortList = append(outPortList, portName)
	}

	// 5. 提取下一跳信息
	for it := match.Iterator(); it.HasNext(); {
		_, hopMap := it.Next()
		interfaceName := hopMap["interface"].(string)
		nextHopIP := hopMap["ip"].(string)
		connected := hopMap["connected"].(bool)

		nextHops = append(nextHops, model.NewNextHopInfo(interfaceName, nextHopIP, connected))
	}

	// 6. 判断是否为ECMP
	isECMP := len(nextHops) > 1

	// 7. 判断是否为直连路由
	isConnected := false
	if len(nextHops) > 0 {
		isConnected = nextHops[0].Connected
	}

	return &model.RouteResult{
		Matched:     true,
		OutPorts:    outPortList,
		NextHops:    nextHops,
		IsConnected: isConnected,
		IsECMP:      isECMP,
	}, nil
}

// QueryAllRoutes 查询所有路由（多路径）
func (rq *RouteQuery) QueryAllRoutes(
	dst network.NetworkList,
	inPort, vrf string,
	ipFamily network.IPFamily) ([]*model.RouteResult, error) {

	// 与QueryRoute类似，但返回所有可能的路径
	result, err := rq.QueryRoute(dst, inPort, vrf, ipFamily)
	if err != nil {
		return nil, err
	}

	if !result.Matched {
		return []*model.RouteResult{}, nil
	}

	// 如果是ECMP，为每个下一跳创建独立的结果
	if result.IsECMP {
		results := make([]*model.RouteResult, 0, len(result.NextHops))
		for _, nextHop := range result.NextHops {
			results = append(results, &model.RouteResult{
				Matched:     true,
				OutPorts:    []string{nextHop.Interface},
				NextHops:    []*model.NextHopInfo{nextHop},
				IsConnected: nextHop.Connected,
				IsECMP:      false, // 单个下一跳不是ECMP
			})
		}
		return results, nil
	}

	// 单一路径
	return []*model.RouteResult{result}, nil
}
