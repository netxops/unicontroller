package nodemap

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/netxops/utils/network"
	"go.uber.org/zap"
)

// MatchSecurityZone 检查源网络是否匹配安全区域（公开方法）
// 返回匹配的安全区域信息和是否匹配
func (nm *NodeMap) MatchSecurityZone(srcnetList *network.NetworkList, vrf string, ipFamily network.IPFamily) (*config.SecurityZoneInfo, bool) {
	return nm.matchSecurityZone(srcnetList, vrf, ipFamily)
}

// matchSecurityZone 检查源网络是否匹配安全区域（内部方法）
// 使用 AddressTable 实现最长掩码匹配
// 规则：
// 1. 默认路由不参与匹配过程
// 2. 只有出现路由分歧（多个不同的 zone）或无法匹配时，才使用默认路由
// 返回匹配的安全区域信息和是否匹配
func (nm *NodeMap) matchSecurityZone(srcnetList *network.NetworkList, vrf string, ipFamily network.IPFamily) (*config.SecurityZoneInfo, bool) {
	if srcnetList == nil || len(srcnetList.List()) == 0 {
		nm.logger.Debug("Source network list is empty")
		return nil, false
	}

	var securityZones []*config.SecurityZoneInfo
	if ipFamily == network.IPv4 {
		securityZones = nm.Ipv4SecurityZones
	} else {
		securityZones = nm.Ipv6SecurityZones
	}

	if len(securityZones) == 0 {
		nm.logger.Debug("No security zones configured")
		return nil, false
	}

	// 构建 AddressTable，将每个 SecurityZone 的网段作为路由条目
	// 使用 NextHop 的 Interface 字段存储 SecurityZoneInfo 的索引（用于后续查找）
	addressTable := network.NewAddressTable(ipFamily)
	var defaultRouteZones []*config.SecurityZoneInfo      // 保存默认路由对应的区域（可能有多个）
	zoneInfoMap := make(map[int]*config.SecurityZoneInfo) // 索引到 SecurityZoneInfo 的映射
	zoneIndex := 0

	for _, zoneInfo := range securityZones {
		// 如果指定了 VRF，需要匹配 VRF
		if vrf != "" && zoneInfo.Vrf != "" && zoneInfo.Vrf != vrf {
			nm.logger.Debug("VRF mismatch, skipping security zone",
				zap.String("zoneVrf", zoneInfo.Vrf),
				zap.String("requestVrf", vrf),
				zap.String("configZoneName", zoneInfo.ConfigZoneName))
			continue
		}

		// 将 SecurityZone 的每个网段添加到 AddressTable
		for _, segmentStr := range zoneInfo.NetworkSegments {
			// 解析网段字符串
			ng, err := network.NewNetworkGroupFromString(segmentStr)
			if err != nil {
				nm.logger.Debug("Failed to parse security zone segment",
					zap.String("segment", segmentStr),
					zap.String("configZoneName", zoneInfo.ConfigZoneName),
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
				if nm.isDefaultRoute(net, ipFamily) {
					// 默认路由不参加匹配，但保存信息用于最后匹配
					defaultRouteZones = append(defaultRouteZones, zoneInfo)
					continue
				}

				nextHop := &network.NextHop{}
				// 使用 Interface 字段存储 zoneIndex（作为标识符）
				// 当 IP 为空时，需要设置 connected=true（表示直连路由）
				nextHop.AddHop(fmt.Sprintf("%d", zoneIndex), "", true, false, nil)
				if err := addressTable.PushRoute(net, nextHop); err != nil {
					nm.logger.Debug("Failed to push route to address table",
						zap.String("segment", segmentStr),
						zap.String("configZoneName", zoneInfo.ConfigZoneName),
						zap.Error(err))
					continue
				}
			}
		}

		// 保存索引到 SecurityZoneInfo 的映射
		zoneInfoMap[zoneIndex] = zoneInfo
		zoneIndex++
	}

	// 使用 AddressTable 进行最长匹配（不包含默认路由）
	// MatchNetList 的第二个参数为 true 表示使用最长匹配
	rmr := addressTable.MatchNetList(*srcnetList, true, false)

	// 检查是否有未匹配的网络（Unmatch 不为空表示没有完整匹配）
	if rmr.Unmatch != nil && rmr.Unmatch.Len() > 0 {
		// 如果没有完整匹配，尝试使用默认路由
		if len(defaultRouteZones) > 0 {
			// 选择优先级最高的默认路由（优先级数字越小越优先）
			defaultZone := nm.selectHighestPriorityZone(defaultRouteZones)
			nm.logger.Debug("No full match found, using default route zone",
				zap.String("defaultRouteZone", defaultZone.ConfigZoneName))
			return defaultZone, true
		}
		// 如果没有默认路由，返回不匹配
		nm.logger.Debug("No full match found and no default route available")
		return nil, false
	}

	// 从匹配结果中提取区域信息
	zoneSet := make(map[int]*config.SecurityZoneInfo)
	if rmr.Match != nil && rmr.Match.Len() > 0 {
		matchTable, err := rmr.Table()
		if err == nil && matchTable != nil {
			// 从匹配表中提取 interface 列（存储的是 zoneIndex）
			interfaces := matchTable.Column("interface").List().Distinct()
			for _, iface := range interfaces {
				zoneIndexStr := iface.(string)
				var zoneIdx int
				if _, err := fmt.Sscanf(zoneIndexStr, "%d", &zoneIdx); err == nil {
					if zoneInfo, ok := zoneInfoMap[zoneIdx]; ok {
						zoneSet[zoneIdx] = zoneInfo
					}
				}
			}
		}
	}

	// 如果匹配到多个不同的 zone（路由分歧），使用默认路由
	if len(zoneSet) > 1 {
		if len(defaultRouteZones) > 0 {
			// 选择优先级最高的默认路由
			defaultZone := nm.selectHighestPriorityZone(defaultRouteZones)
			nm.logger.Debug("Multiple zones matched (route divergence), using default route zone",
				zap.Int("zoneCount", len(zoneSet)),
				zap.String("defaultRouteZone", defaultZone.ConfigZoneName))
			return defaultZone, true
		}
		// 如果没有默认路由，选择优先级最高的匹配 zone
		matchedZone := nm.selectHighestPriorityZoneFromMap(zoneSet)
		nm.logger.Debug("Multiple zones matched but no default route, using highest priority zone",
			zap.String("selectedZone", matchedZone.ConfigZoneName))
		return matchedZone, true
	}

	// 如果只匹配到一个 zone，返回该 zone
	if len(zoneSet) == 1 {
		for _, zoneInfo := range zoneSet {
			nm.logger.Debug("Security zone matched",
				zap.String("configZoneName", zoneInfo.ConfigZoneName),
				zap.String("nodeName", zoneInfo.NodeName),
				zap.Int("priority", zoneInfo.Priority))
			return zoneInfo, true
		}
	}

	// 如果没有匹配到任何 zone，尝试使用默认路由
	if len(defaultRouteZones) > 0 {
		defaultZone := nm.selectHighestPriorityZone(defaultRouteZones)
		nm.logger.Debug("No zone matched, using default route zone",
			zap.String("defaultRouteZone", defaultZone.ConfigZoneName))
		return defaultZone, true
	}

	return nil, false
}

// isNetworkInSecurityZone 检查网络是否在安全区域的网段列表中
func (nm *NodeMap) isNetworkInSecurityZone(srcnetList *network.NetworkList, zoneInfo *config.SecurityZoneInfo) bool {
	if srcnetList == nil || len(srcnetList.List()) == 0 {
		nm.logger.Debug("Source network list is empty")
		return false
	}

	for _, segmentStr := range zoneInfo.NetworkSegments {
		// 解析网段字符串（支持IP、CIDR、IP范围）
		matched, err := nm.parseAndMatchAddress(segmentStr, srcnetList)
		if err != nil {
			nm.logger.Warn("Failed to parse segment in security zone",
				zap.String("segment", segmentStr),
				zap.String("configZoneName", zoneInfo.ConfigZoneName),
				zap.Error(err))
			continue
		}
		nm.logger.Debug("Segment match result",
			zap.String("segment", segmentStr),
			zap.Bool("matched", matched))
		if matched {
			return true
		}
	}
	return false
}

// parseAndMatchAddress 解析地址字符串并匹配网络
// 支持格式：
// - IP地址: "192.168.1.1"
// - CIDR网段: "192.168.1.0/24"
// - IP范围: "192.168.1.1-192.168.1.100"
func (nm *NodeMap) parseAndMatchAddress(addrStr string, srcnetList *network.NetworkList) (bool, error) {
	addrStr = strings.TrimSpace(addrStr)

	// 检查是否是IP范围格式 (start-end)
	if strings.Contains(addrStr, "-") {
		parts := strings.Split(addrStr, "-")
		if len(parts) == 2 {
			startIP := strings.TrimSpace(parts[0])
			endIP := strings.TrimSpace(parts[1])
			return nm.matchIPRange(startIP, endIP, srcnetList)
		}
	}

	// 检查是否是CIDR格式或普通IP地址
	ng, err := network.NewNetworkGroupFromString(addrStr)
	if err != nil {
		return false, fmt.Errorf("invalid address format: %w", err)
	}

	// 检查源网络列表中的任何网络是否与地址网络组匹配
	// 遍历源网络列表，检查是否有任何网络与地址网络组匹配
	matched := false
	for _, net := range srcnetList.List() {
		// 创建包含单个网络项的 NetworkGroup
		itemNg := network.NewNetworkGroup()
		itemNg.Add(net)

		// 使用 NetworkGroupCmp 检查网络是否重叠
		// mid 表示两个网络组的交集，如果不为空则说明有重叠
		left, mid, right := network.NetworkGroupCmp(*ng, *itemNg)
		nm.logger.Debug("Network comparison",
			zap.String("addrStr", addrStr),
			zap.String("addrNg", ng.String()),
			zap.String("itemNg", itemNg.String()),
			zap.String("left", func() string {
				if left != nil {
					return left.String()
				}
				return "nil"
			}()),
			zap.String("mid", func() string {
				if mid != nil {
					return mid.String()
				}
				return "nil"
			}()),
			zap.String("right", func() string {
				if right != nil {
					return right.String()
				}
				return "nil"
			}()),
			zap.Bool("hasOverlap", mid != nil && !mid.IsEmpty()))
		if mid != nil && !mid.IsEmpty() {
			matched = true
			break
		}
	}

	return matched, nil
}

// matchIPRange 匹配IP范围
func (nm *NodeMap) matchIPRange(startIP, endIP string, srcnetList *network.NetworkList) (bool, error) {
	startNg, err := network.NewNetworkGroupFromString(startIP)
	if err != nil {
		return false, fmt.Errorf("invalid start IP: %w", err)
	}

	endNg, err := network.NewNetworkGroupFromString(endIP)
	if err != nil {
		return false, fmt.Errorf("invalid end IP: %w", err)
	}

	// 检查源网络列表中的任何网络是否在范围内
	// 创建一个包含整个IP范围的网络组
	rangeNg := network.NewNetworkGroup()
	rangeNg.AddGroup(startNg)
	rangeNg.AddGroup(endNg)

	matched := false
	for _, net := range srcnetList.List() {
		// 创建包含单个网络项的 NetworkGroup
		itemNg := network.NewNetworkGroup()
		itemNg.Add(net)

		// 使用 NetworkGroupCmp 检查网络是否与范围有重叠
		_, mid, _ := network.NetworkGroupCmp(*rangeNg, *itemNg)
		if mid != nil && !mid.IsEmpty() {
			matched = true
			break
		}
	}

	return matched, nil
}

// isDefaultRoute 检查网络是否为默认路由（0.0.0.0/0 或 ::/0）
func (nm *NodeMap) isDefaultRoute(net network.AbbrNet, ipFamily network.IPFamily) bool {
	netStr := net.String()
	if ipFamily == network.IPv4 {
		return netStr == "0.0.0.0/0"
	}
	return netStr == "::/0"
}

// selectHighestPriorityZone 从 zone 列表中选择优先级最高的 zone（优先级数字越小越优先）
func (nm *NodeMap) selectHighestPriorityZone(zones []*config.SecurityZoneInfo) *config.SecurityZoneInfo {
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

// selectHighestPriorityZoneFromMap 从 zone map 中选择优先级最高的 zone（优先级数字越小越优先）
func (nm *NodeMap) selectHighestPriorityZoneFromMap(zoneMap map[int]*config.SecurityZoneInfo) *config.SecurityZoneInfo {
	if len(zoneMap) == 0 {
		return nil
	}
	var selected *config.SecurityZoneInfo
	for _, zone := range zoneMap {
		if selected == nil || zone.Priority < selected.Priority {
			selected = zone
		}
	}
	return selected
}
