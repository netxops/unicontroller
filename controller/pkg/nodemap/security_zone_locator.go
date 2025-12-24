package nodemap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"go.uber.org/zap"
)

// SecurityZoneLocator 安全区域定位策略
// 重新设计：对所有节点生成 AddressTable，使用最长匹配，排除默认路由
type SecurityZoneLocator struct {
	*BaseLocatorStrategy
}

// NewSecurityZoneLocator 创建安全区域定位器
func NewSecurityZoneLocator(nodeMap *NodeMap, logger *zap.Logger) *SecurityZoneLocator {
	return &SecurityZoneLocator{
		BaseLocatorStrategy: NewBaseLocatorStrategy(nodeMap, logger),
	}
}

// CanHandle 判断是否可以处理该定位请求
func (l *SecurityZoneLocator) CanHandle(req *LocateRequest) bool {
	// 检查是否有防火墙节点
	firewallNodes := l.getFirewallNodes()
	return len(firewallNodes) > 0
}

func (l *SecurityZoneLocator) Locate(req *LocateRequest) (bool, api.Node, string) {
	// 检查源网络列表
	if req.SrcNetList == nil || len(req.SrcNetList.List()) == 0 {
		return false, nil, "source network list is empty"
	}

	// 如果最长匹配失败，且只有一个节点，尝试使用默认路由
	if len(l.BaseLocatorStrategy.NodeMap.Nodes) == 0 {
		return false, nil, "NodeMap has no nodes"
	}
	// 尝试通过最长匹配定位
	node, portName, err := l.locate(req)
	if err == nil {
		return true, node, portName
	}
	locateErr := err.Error()

	if len(l.BaseLocatorStrategy.NodeMap.Nodes) > 1 {
		return false, nil, fmt.Sprintf("no match found, multiple firewalls: %s", locateErr)
	}

	if len(l.BaseLocatorStrategy.NodeMap.Nodes) == 1 {
		node := l.BaseLocatorStrategy.NodeMap.Nodes[0]
		if node.NodeType() != api.FIREWALL {
			return false, nil, fmt.Sprintf("single node is not a firewall: %s", locateErr)
		}

		securityZones := l.getSecurityZones(req)
		if len(securityZones) == 0 {
			return false, nil, fmt.Sprintf("no security zones configured: %s", locateErr)
		}

		// 查找该节点的默认路由 SecurityZoneInfo
		for _, zoneInfo := range securityZones {
			if zoneInfo.NodeName == node.Name() {
				// 检查 VRF 匹配
				if req.Vrf != "" && zoneInfo.Vrf != "" && zoneInfo.Vrf != req.Vrf {
					continue
				}

				for _, segmentStr := range zoneInfo.NetworkSegments {
					if segmentStr == "0.0.0.0/0" || segmentStr == "::/0" {
						portName := l.findPortByZoneName(node, zoneInfo.ConfigZoneName, l.BaseLocatorStrategy.Logger)
						if portName != "" {
							return true, node, portName
						}
					}
				}
			}
		}

		return false, nil, fmt.Sprintf("no default route zone found: %s", locateErr)
	}

	// 多个节点时，不能使用默认路由
	return false, nil, fmt.Sprintf("no match found, multiple firewalls: %s", locateErr)
}

func (l *SecurityZoneLocator) locate(req *LocateRequest) (api.Node, string, error) {
	if req.NodeMap == nil {
		return nil, "", errors.New("NodeMap is nil")
	}

	securityZones := l.getSecurityZones(req)
	if len(securityZones) == 0 {
		return nil, "", errors.New("no security zones configured")
	}

	// 构建 AddressTable：从所有 SecurityZoneInfo 的网段生成
	addressTable := network.NewAddressTable(req.IPFamily)
	validRoutesCount := 0
	networkMap := map[string][]string{}
	for _, zoneInfo := range securityZones {
		// 检查 VRF 匹配
		if req.Vrf != "" && zoneInfo.Vrf != "" && zoneInfo.Vrf != req.Vrf {
			continue
		}

		for _, segmentStr := range zoneInfo.NetworkSegments {
			// 跳过默认路由（在最长匹配阶段不参与）
			if segmentStr == "0.0.0.0/0" || segmentStr == "::/0" {
				continue
			}

			ng, err := network.NewNetworkGroupFromString(segmentStr)
			if err != nil {
				l.BaseLocatorStrategy.Logger.Debug("Failed to parse security zone segment",
					zap.String("segment", segmentStr),
					zap.String("configZoneName", zoneInfo.ConfigZoneName),
					zap.String("nodeName", zoneInfo.NodeName),
					zap.Error(err))
				continue
			}

			var netlist *network.NetworkList
			if req.IPFamily == network.IPv4 {
				netlist = ng.IPv4()
			} else {
				netlist = ng.IPv6()
			}
			if netlist == nil || len(netlist.List()) == 0 {
				continue
			}

			for _, net := range netlist.List() {
				networkMap[net.String()] = append(networkMap[net.String()], fmt.Sprintf("%s||%s", zoneInfo.NodeName, zoneInfo.ConfigZoneName))
			}
		}

	}
	for netStr, hopInfos := range networkMap {
		net, err := network.ParseIPNet(netStr)
		if err != nil {
			l.BaseLocatorStrategy.Logger.Error("Failed to parse network",
				zap.String("network", netStr),
				zap.Error(err))
			continue
		}
		nexthop := network.NewNextHop()
		// 使用 "NodeName||ConfigZoneName" 格式存储节点和区域信息
		for _, hopInfo := range hopInfos {
			parts := strings.Split(hopInfo, "||")
			if len(parts) != 2 {
				l.BaseLocatorStrategy.Logger.Error("Invalid hop info format",
					zap.String("hopInfo", hopInfo),
					zap.Error(fmt.Errorf("invalid format")))
				continue
			}
			nodeName := parts[0]
			configZoneName := parts[1]
			_, err := nexthop.AddHop(hopInfo, "", true, false, nil)
			if err != nil {
				l.BaseLocatorStrategy.Logger.Error("Failed to add hop to next hop",
					zap.String("nodeName", nodeName),
					zap.String("configZoneName", configZoneName),
					zap.String("network", net.String()),
					zap.Error(err))
				continue
			}
		}
		if nexthop.Count() == 0 {
			continue
		}

		if err := addressTable.PushRoute(net, nexthop); err != nil {
			l.BaseLocatorStrategy.Logger.Error("Failed to push route to address table",
				zap.String("network", net.String()),
				zap.Error(err),
				zap.Any("nexthop", nexthop))
			continue
		}
		validRoutesCount++
	}
	if validRoutesCount == 0 {
		return nil, "", errors.New("no valid routes found in security zones")
	}

	// 执行最长前缀匹配（排除默认路由）
	rmr := addressTable.MatchNetList(*req.SrcNetList, true, false)
	if rmr.Match == nil || rmr.Match.Len() == 0 {
		return nil, "", errors.New("no match found via longest prefix match")
	}

	if rmr.Unmatch != nil && rmr.Unmatch.Len() > 0 {
		return nil, "", errors.New("no match found via longest prefix match")
	}

	// 检查是否所有匹配结果都指向同一个接口（节点+区域）
	ok, nodeZone := rmr.IsSameInterface()
	if !ok {
		return nil, "", errors.New("route divergence detected")
	}

	// 解析节点名称和区域名称
	parts := strings.Split(nodeZone, "||")
	if len(parts) != 2 {
		return nil, "", fmt.Errorf("invalid nodeZone format: %s", nodeZone)
	}
	nodeName := parts[0]
	zone := parts[1]

	// 查找节点
	node := l.BaseLocatorStrategy.NodeMap.GetNode(nodeName)
	if node == nil {
		return nil, "", fmt.Errorf("node '%s' not found", nodeName)
	}

	// 通过 ConfigZoneName 查找防火墙接口
	portName := l.findPortByZoneName(node, zone, l.BaseLocatorStrategy.Logger)
	if portName == "" {
		return nil, "", fmt.Errorf("no firewall port found for zone '%s'", zone)
	}

	return node, portName, nil
}

func (l *SecurityZoneLocator) getSecurityZones(req *LocateRequest) []*config.SecurityZoneInfo {
	if req.IPFamily == network.IPv4 {
		return l.BaseLocatorStrategy.NodeMap.Ipv4SecurityZones
	}
	return l.BaseLocatorStrategy.NodeMap.Ipv6SecurityZones
}

// getFirewallNodes 获取所有防火墙节点
func (l *SecurityZoneLocator) getFirewallNodes() []api.Node {
	firewallNodes := make([]api.Node, 0)
	for _, node := range l.BaseLocatorStrategy.NodeMap.Nodes {
		if node.NodeType() == api.FIREWALL {
			firewallNodes = append(firewallNodes, node)
		}
	}
	return firewallNodes
}

// buildAddressTable 从所有 SecurityZoneInfo 构建全局 AddressTable（不按节点过滤）
// 返回: addressTable, defaultRouteZones, zoneInfoMap
func (l *SecurityZoneLocator) buildAddressTable(securityZones []*config.SecurityZoneInfo, vrf string, ipFamily network.IPFamily, logger *zap.Logger) (*network.AddressTable, []*config.SecurityZoneInfo, map[int]*config.SecurityZoneInfo) {
	addressTable := network.NewAddressTable(ipFamily)
	var defaultRouteZones []*config.SecurityZoneInfo
	zoneInfoMap := make(map[int]*config.SecurityZoneInfo)
	zoneIndex := 0

	// 遍历所有 SecurityZoneInfo（不按节点过滤）
	for _, zoneInfo := range securityZones {

		// 如果指定了 VRF，需要匹配 VRF
		if vrf != "" && zoneInfo.Vrf != "" && zoneInfo.Vrf != vrf {
			logger.Debug("VRF mismatch, skipping security zone",
				zap.String("zoneVrf", zoneInfo.Vrf),
				zap.String("requestVrf", vrf),
				zap.String("configZoneName", zoneInfo.ConfigZoneName),
				zap.String("nodeName", zoneInfo.NodeName))
			continue
		}

		// 将 SecurityZone 的每个网段添加到 AddressTable
		for _, segmentStr := range zoneInfo.NetworkSegments {
			// 解析网段字符串
			ng, err := network.NewNetworkGroupFromString(segmentStr)
			if err != nil {
				logger.Debug("Failed to parse security zone segment",
					zap.String("segment", segmentStr),
					zap.String("configZoneName", zoneInfo.ConfigZoneName),
					zap.String("nodeName", zoneInfo.NodeName),
					zap.Error(err))
				continue
			}

			// 获取对应 IP 协议族的网络列表
			var segmentNetList *network.NetworkList
			if ipFamily == network.IPv4 {
				segmentNetList = ng.IPv4()
			} else {
				segmentNetList = ng.IPv6()
			}

			if segmentNetList == nil || len(segmentNetList.List()) == 0 {
				continue
			}

			// 为每个网络添加路由条目
			for _, net := range segmentNetList.List() {
				// 检查是否为默认路由
				if l.isDefaultRoute(net, ipFamily) {
					// 默认路由不参加匹配，但保存信息用于最后匹配
					defaultRouteZones = append(defaultRouteZones, zoneInfo)
					continue
				}

				nextHop := &network.NextHop{}
				// 使用 Interface 字段存储 zoneIndex（作为标识符）
				// 当 IP 为空时，需要设置 connected=true（表示直连路由）
				nextHop.AddHop(fmt.Sprintf("%d", zoneIndex), "", true, false, nil)
				if err := addressTable.PushRoute(net, nextHop); err != nil {
					logger.Debug("Failed to push route to address table",
						zap.String("segment", segmentStr),
						zap.String("configZoneName", zoneInfo.ConfigZoneName),
						zap.String("nodeName", zoneInfo.NodeName),
						zap.Error(err))
					continue
				}
			}
		}

		// 保存索引到 SecurityZoneInfo 的映射
		zoneInfoMap[zoneIndex] = zoneInfo
		zoneIndex++
	}

	return addressTable, defaultRouteZones, zoneInfoMap
}

// isDefaultRoute 检查网络是否为默认路由（0.0.0.0/0 或 ::/0）
func (l *SecurityZoneLocator) isDefaultRoute(net network.AbbrNet, ipFamily network.IPFamily) bool {
	netStr := net.String()
	if ipFamily == network.IPv4 {
		return netStr == "0.0.0.0/0"
	}
	return netStr == "::/0"
}

// selectHighestPriorityZone 从 zone 列表中选择优先级最高的 zone（优先级数字越小越优先）
func (l *SecurityZoneLocator) selectHighestPriorityZone(zones []*config.SecurityZoneInfo) *config.SecurityZoneInfo {
	if len(zones) == 0 {
		return nil
	}
	selected := zones[0]
	for _, zone := range zones[1:] {
		if zone.Priority < selected.Priority {
			selected = zone
		}
	}
	return selected
}

// findPortByZoneName 通过 ConfigZoneName 查找防火墙接口
func (l *SecurityZoneLocator) findPortByZoneName(node api.Node, configZoneName string, logger *zap.Logger) string {
	if configZoneName == "" {
		return ""
	}

	// 遍历节点的所有端口，查找 Zone() 方法返回值与 ConfigZoneName 匹配的接口
	for _, port := range node.PortList() {
		// 检查端口是否实现了 ZoneFirewall 接口
		if zonePort, ok := port.(firewall.ZoneFirewall); ok {
			portZoneName := zonePort.Zone()
			if portZoneName == configZoneName {
				logger.Debug("Found port matching zone name",
					zap.String("nodeName", node.Name()),
					zap.String("portName", port.Name()),
					zap.String("configZoneName", configZoneName),
					zap.String("portZoneName", portZoneName))
				return port.Name()
			}
		}
	}

	return ""
}
