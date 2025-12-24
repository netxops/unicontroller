package sangfor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// parseCLIString 解析 Sangfor CLI 配置字符串
// 将 config.txt 格式的 CLI 配置解析为 map[string]interface{} 格式
func parseCLIString(cli string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var networks []interface{}
	var services []interface{}
	var policies []interface{}
	var staticNats []interface{}
	var dynamicNats []interface{}
	var staticRoutes []interface{}
	var zones []interface{}
	var interfaces []interface{}

	// 按 config/end 分割配置块
	blocks := splitConfigBlocks(cli)

	for _, block := range blocks {
		if len(block) == 0 {
			continue
		}

		// 解析配置块的第一行获取类型和名称
		firstLine := strings.TrimSpace(block[0])
		if firstLine == "" {
			continue
		}

		// 解析不同类型的配置块
		// 注意：第一行可能是 "config"，需要检查第二行
		var actualFirstLine string
		if len(block) > 0 && strings.TrimSpace(block[0]) == "config" {
			// 如果第一行是 "config"，检查第二行
			if len(block) > 1 {
				actualFirstLine = strings.TrimSpace(block[1])
			} else {
				// 如果只有 "config" 行，跳过
				continue
			}
		} else {
			actualFirstLine = firstLine
		}

		if strings.HasPrefix(actualFirstLine, "ipgroup") {
			// 解析网络对象/组
			networkObj := parseIPGroupBlock(block)
			if networkObj != nil {
				networks = append(networks, networkObj)
			}
		} else if strings.HasPrefix(actualFirstLine, "service") {
			// 解析服务对象
			serviceObj := parseServiceBlock(block)
			if serviceObj != nil {
				services = append(services, serviceObj)
			}
		} else if strings.HasPrefix(actualFirstLine, "servgroup") {
			// 解析服务组
			serviceObj := parseServGroupBlock(block)
			if serviceObj != nil {
				services = append(services, serviceObj)
			}
		} else if strings.HasPrefix(firstLine, "policy") {
			// 解析安全策略
			policyObj := parsePolicyBlock(block)
			if policyObj != nil {
				policies = append(policies, policyObj)
			}
		} else if strings.HasPrefix(firstLine, "dnat-rule") {
			// 解析 DNAT 规则
			natObj := parseDNATBlock(block)
			if natObj != nil {
				staticNats = append(staticNats, natObj)
			}
		} else if strings.HasPrefix(firstLine, "snat-rule") {
			// 解析 SNAT 规则
			natObj := parseSNATBlock(block)
			if natObj != nil {
				dynamicNats = append(dynamicNats, natObj)
			}
		} else if strings.HasPrefix(firstLine, "ip route") {
			// 解析静态路由
			routeObj := parseIPRouteBlock(block)
			if routeObj != nil {
				staticRoutes = append(staticRoutes, routeObj)
			}
		} else if strings.HasPrefix(firstLine, "zone") {
			// 解析区域配置
			zoneObj := parseZoneBlock(block)
			if zoneObj != nil {
				zones = append(zones, zoneObj)
			}
		} else if strings.HasPrefix(firstLine, "interface") {
			// 解析接口配置
			interfaceObj := parseInterfaceBlock(block)
			if interfaceObj != nil {
				interfaces = append(interfaces, interfaceObj)
			}
		}
	}

	if len(networks) > 0 {
		result["NETWORK"] = networks
	}
	if len(services) > 0 {
		result["SERVICE"] = services
	}
	if len(policies) > 0 {
		result["SECURITY_POLICY"] = policies
	}
	if len(staticNats) > 0 {
		result["STATIC_NAT"] = staticNats
	}
	// 注意：SNAT 规则在 Sangfor 中可能被归类为动态 NAT，但根据 parseFlyConfig 的实现，
	// 我们暂时将它们也放入 STATIC_NAT，或者需要扩展 parseFlyConfig 支持动态 NAT
	if len(dynamicNats) > 0 {
		// 暂时也放入 STATIC_NAT，后续可以根据需要调整
		staticNats = append(staticNats, dynamicNats...)
		result["DYNAMIC_NAT"] = staticNats
	}

	if len(staticRoutes) > 0 {
		result["STATIC_ROUTE"] = staticRoutes
	}

	if len(zones) > 0 {
		result["ZONE"] = zones
	}

	if len(interfaces) > 0 {
		result["INTERFACE"] = interfaces
	}

	return result, nil
}

// splitConfigBlocks 按 config/end 分割配置块
// 支持 "config" 和 "#config" 两种格式（# 是分隔符）
func splitConfigBlocks(cli string) [][]string {
	var blocks [][]string
	var currentBlock []string
	inBlock := false

	lines := strings.Split(cli, "\n")
	for _, line := range lines {
		originalLine := line
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 检查是否是 config 行（支持 "config" 和 "#config" 格式）
		// 去掉可能的 # 前缀后再检查
		lineToCheck := line
		if strings.HasPrefix(lineToCheck, "#") {
			lineToCheck = strings.TrimPrefix(lineToCheck, "#")
			lineToCheck = strings.TrimSpace(lineToCheck)
		}

		if strings.HasPrefix(lineToCheck, "config") {
			if inBlock {
				// 开始新的块，保存之前的块
				if len(currentBlock) > 0 {
					blocks = append(blocks, currentBlock)
				}
			}
			currentBlock = []string{}
			inBlock = true
			// 注意：如果 "config" 或 "#config" 是单独一行，不添加到 currentBlock
			// 后续的行（如 "ipgroup ..."）会作为块的第一行
		} else if line == "end" {
			if inBlock {
				blocks = append(blocks, currentBlock)
				currentBlock = []string{}
				inBlock = false
			}
		} else if inBlock {
			// 添加到当前块（保留原始行，包括可能的缩进）
			currentBlock = append(currentBlock, originalLine)
		}
	}

	// 处理最后一个块（如果没有 end）
	if len(currentBlock) > 0 {
		blocks = append(blocks, currentBlock)
	}

	return blocks
}

// parseIPGroupBlock 解析 ipgroup 配置块
func parseIPGroupBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 解析第一行：ipgroup "name" ipv4
	firstLine := block[0]
	re := regexp.MustCompile(`ipgroup\s+"([^"]+)"\s+(\w+)`)
	matches := re.FindStringSubmatch(firstLine)
	if len(matches) < 3 {
		return nil
	}

	name := matches[1]
	addressType := matches[2]

	result := map[string]interface{}{
		"name":        name,
		"addressType": addressType,
		"uuid":        "", // CLI 中没有 UUID，使用空字符串
	}

	// 解析其他属性
	var ipRanges []interface{} // 改为 []interface{} 以匹配 API 格式
	var refIpGroup []string
	var members []string // 支持 member 关键字
	businessType := "IP"
	importance := "COMMON"

	for i := 1; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" {
			continue
		}

		// 解析 type
		if strings.HasPrefix(line, "type ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				businessType = strings.ToUpper(parts[1])
			}
		}

		// 解析 importance
		if strings.HasPrefix(line, "importance ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				importance = strings.ToUpper(parts[1])
			}
		}

		// 解析 ipentry
		if strings.HasPrefix(line, "ipentry ") {
			ipEntry := strings.TrimPrefix(line, "ipentry ")
			ipEntry = strings.TrimSpace(ipEntry)
			ipRange := parseIPEntry(ipEntry)
			if ipRange != nil {
				ipRanges = append(ipRanges, ipRange) // ipRange 是 map[string]interface{}，可以添加到 []interface{}
			}
		}

		// 解析 member（新格式，支持对象名称、IP地址或CIDR）
		if strings.HasPrefix(line, "member ") {
			member := strings.TrimPrefix(line, "member ")
			member = strings.Trim(member, `"`)
			member = strings.TrimSpace(member)
			members = append(members, member)
		}

		// 解析 refIpGroup（兼容旧格式）
		if strings.HasPrefix(line, "refIpGroup ") {
			ref := strings.TrimPrefix(line, "refIpGroup ")
			ref = strings.Trim(ref, `"`)
			refIpGroup = append(refIpGroup, ref)
		}
	}

	result["businessType"] = businessType
	result["important"] = importance

	if len(ipRanges) > 0 {
		result["ipRanges"] = ipRanges
	}

	// 优先使用 member，如果没有则使用 refIpGroup（兼容旧格式）
	if len(members) > 0 {
		result["member"] = members
		// 如果有 member，则类型为地址组
		if businessType == "IP" {
			result["businessType"] = "ADDRGROUP"
		}
	} else if len(refIpGroup) > 0 {
		result["refIpGroup"] = refIpGroup
		// 如果有引用，则类型为地址组
		if businessType == "IP" {
			result["businessType"] = "ADDRGROUP"
		}
	}

	// 确保 ipRanges 字段存在（即使是空的）
	if len(ipRanges) == 0 && len(refIpGroup) == 0 {
		// 如果没有 ipRanges 也没有 refIpGroup，创建一个空的
		result["ipRanges"] = []interface{}{}
	} else if len(ipRanges) > 0 {
		// 确保 ipRanges 字段存在
		result["ipRanges"] = ipRanges
	}

	return result
}

// parseIPEntry 解析 ipentry 行
// 支持格式：
// - 192.168.1.0-192.168.1.255 (IP 范围)
// - 192.168.100.0/24 (CIDR)
// - 1.1.1.1 (单 IP)
func parseIPEntry(ipEntry string) map[string]interface{} {
	ipEntry = strings.TrimSpace(ipEntry)
	if ipEntry == "" {
		return nil
	}

	result := make(map[string]interface{})

	// 检查是否是 IP 范围格式 (start-end)
	if strings.Contains(ipEntry, "-") && !strings.Contains(ipEntry, "/") {
		parts := strings.Split(ipEntry, "-")
		if len(parts) == 2 {
			result["start"] = strings.TrimSpace(parts[0])
			result["end"] = strings.TrimSpace(parts[1])
			return result
		}
	}

	// 检查是否是 CIDR 格式（支持 /24 和 /255.255.255.0 两种格式）
	if strings.Contains(ipEntry, "/") {
		parts := strings.Split(ipEntry, "/")
		if len(parts) == 2 {
			result["start"] = strings.TrimSpace(parts[0])
			bitsStr := strings.TrimSpace(parts[1])
			fmt.Printf("[parseIPEntry] 解析 CIDR: %s, bits 字符串: %s\n", ipEntry, bitsStr)

			// 首先尝试解析为数字（CIDR 前缀长度，如 24）
			if bitsFloat, err := strconv.ParseFloat(bitsStr, 64); err == nil {
				result["bits"] = bitsFloat
				fmt.Printf("[parseIPEntry] 成功解析 bits (CIDR): %f\n", bitsFloat)
				return result
			}

			// 如果解析失败，可能是点分十进制掩码格式（如 255.255.255.0）
			// 尝试转换为 CIDR 前缀长度
			if maskParts := strings.Split(bitsStr, "."); len(maskParts) == 4 {
				fmt.Printf("[parseIPEntry] 检测到点分十进制掩码格式: %s\n", bitsStr)
				// 将点分十进制掩码转换为 CIDR 前缀长度
				var prefixLen int
				for i, part := range maskParts {
					octet, err := strconv.Atoi(strings.TrimSpace(part))
					if err != nil {
						fmt.Printf("[parseIPEntry] 解析掩码字节 %d 失败: %v\n", i, err)
						result["bits"] = bitsStr // 回退到字符串
						return result
					}
					// 计算前缀长度
					if octet == 255 {
						prefixLen += 8
					} else if octet == 0 {
						break
					} else {
						// 计算非 255/0 的字节的前缀长度
						for j := 7; j >= 0; j-- {
							if (octet & (1 << j)) != 0 {
								prefixLen++
							} else {
								break
							}
						}
						break
					}
				}
				result["bits"] = float64(prefixLen)
				fmt.Printf("[parseIPEntry] 转换点分十进制掩码 %s 为 CIDR 前缀长度: %d\n", bitsStr, prefixLen)
				return result
			}

			// 如果都不匹配，保持为字符串
			fmt.Printf("[parseIPEntry] 无法解析 bits，保持为字符串: %s\n", bitsStr)
			result["bits"] = bitsStr
			return result
		}
	}

	// 单 IP
	result["start"] = ipEntry
	return result
}

// parseServiceBlock 解析 service 配置块
// 支持格式（新格式）：
// config
// service "name"
// icmp type 6 code 8
// protocol 55
// tcp src-port 0-65535 dst-port 8888,999-1005
// udp src-port 0-65535 dst-port 5555
// end
//
// 兼容旧格式：
// config
// service "name"
// tcp-entry destination-port 80
// udp-entry destination-port 53
// icmp-entry
// icmpv6-entry
// other-entry protocol ip
// servsInfo "ref-service-name"
// end
func parseServiceBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 查找 service "name" 行（可能在 block[0] 或 block[1]）
	var name string
	for i := 0; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" || line == "config" || line == "end" {
			continue
		}
		re := regexp.MustCompile(`service\s+"([^"]+)"`)
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			name = matches[1]
			break
		}
	}
	if name == "" {
		return nil
	}

	result := map[string]interface{}{
		"name":     name,
		"uuid":     "",
		"servType": "USRDEF_SERV", // 默认为自定义服务
	}

	var tcpEntrys []map[string]interface{}
	var udpEntrys []map[string]interface{}
	var icmpEntrys []map[string]interface{}
	var icmpv6Entrys []map[string]interface{}
	var other []interface{}
	var servsInfo []string

	// 解析所有行，跳过 "config"、"end" 和 service 行本身
	for i := 0; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" || line == "end" || line == "config" || strings.HasPrefix(line, "service ") {
			continue
		}

		// 解析 icmp type <type> code <code>
		// 格式: icmp type 6 code 8
		if strings.HasPrefix(line, "icmp ") {
			icmpRe := regexp.MustCompile(`icmp\s+type\s+(\d+)(?:\s+code\s+(\d+))?`)
			matches := icmpRe.FindStringSubmatch(line)
			if len(matches) >= 2 {
				typeVal, _ := strconv.ParseFloat(matches[1], 64)
				var codeVal float64 = 255 // 默认全部
				if len(matches) >= 3 && matches[2] != "" {
					codeVal, _ = strconv.ParseFloat(matches[2], 64)
				}
				icmpEntrys = append(icmpEntrys, map[string]interface{}{
					"type": typeVal,
					"code": codeVal,
				})
			}
			continue
		}

		// 解析 protocol <number>
		// 格式: protocol 55
		if strings.HasPrefix(line, "protocol ") {
			protocolStr := strings.TrimPrefix(line, "protocol ")
			protocolStr = strings.TrimSpace(protocolStr)
			if protoNum, err := strconv.ParseFloat(protocolStr, 64); err == nil {
				other = append(other, protoNum)
			}
			continue
		}

		// 解析 tcp src-port <range> dst-port <ports>
		// 格式: tcp src-port 0-65535 dst-port 8888,999-1005
		if strings.HasPrefix(line, "tcp ") {
			tcpEntry := parseTCPUDPEntry(line, "tcp")
			if tcpEntry != nil {
				tcpEntrys = append(tcpEntrys, tcpEntry)
			}
			continue
		}

		// 解析 udp src-port <range> dst-port <ports>
		// 格式: udp src-port 0-65535 dst-port 5555
		if strings.HasPrefix(line, "udp ") {
			udpEntry := parseTCPUDPEntry(line, "udp")
			if udpEntry != nil {
				udpEntrys = append(udpEntrys, udpEntry)
			}
			continue
		}

		// 兼容旧格式：tcp-entry destination-port <port>
		if strings.HasPrefix(line, "tcp-entry destination-port ") {
			portStr := strings.TrimPrefix(line, "tcp-entry destination-port ")
			portStr = strings.TrimSpace(portStr)
			tcpEntry := parseServicePortEntry(portStr)
			if tcpEntry != nil {
				tcpEntrys = append(tcpEntrys, tcpEntry)
			}
			continue
		}

		// 兼容旧格式：udp-entry destination-port <port>
		if strings.HasPrefix(line, "udp-entry destination-port ") {
			portStr := strings.TrimPrefix(line, "udp-entry destination-port ")
			portStr = strings.TrimSpace(portStr)
			udpEntry := parseServicePortEntry(portStr)
			if udpEntry != nil {
				udpEntrys = append(udpEntrys, udpEntry)
			}
			continue
		}

		// 兼容旧格式：icmp-entry
		if line == "icmp-entry" {
			icmpEntrys = append(icmpEntrys, map[string]interface{}{
				"type": float64(255), // 255 表示全部
				"code": float64(255),
			})
			continue
		}

		// 兼容旧格式：icmpv6-entry
		if line == "icmpv6-entry" {
			icmpv6Entrys = append(icmpv6Entrys, map[string]interface{}{
				"type": float64(255), // 255 表示全部
				"code": float64(255),
			})
			continue
		}

		// 兼容旧格式：other-entry protocol <protocol>
		if strings.HasPrefix(line, "other-entry protocol ") {
			protocol := strings.TrimPrefix(line, "other-entry protocol ")
			protocol = strings.TrimSpace(protocol)
			protoNum := protocolToNumber(protocol)
			if protoNum > 0 {
				other = append(other, float64(protoNum))
			}
			continue
		}

		// 解析 servsInfo（服务组引用）
		if strings.HasPrefix(line, "servsInfo ") {
			ref := strings.TrimPrefix(line, "servsInfo ")
			ref = strings.Trim(ref, `"`)
			servsInfo = append(servsInfo, ref)
			result["servType"] = "SERV_GRP" // 如果有引用，则是服务组
			continue
		}
	}

	if len(tcpEntrys) > 0 {
		result["tcpEntrys"] = tcpEntrys
	}
	if len(udpEntrys) > 0 {
		result["udpEntrys"] = udpEntrys
	}
	if len(icmpEntrys) > 0 {
		result["icmpEntrys"] = icmpEntrys
	}
	if len(icmpv6Entrys) > 0 {
		result["icmpv6Entrys"] = icmpv6Entrys
	}
	if len(other) > 0 {
		result["other"] = other
	}
	if len(servsInfo) > 0 {
		result["servsInfo"] = servsInfo
	}

	return result
}

// parseTCPUDPEntry 解析 tcp/udp 条目
// 格式: tcp src-port 0-65535 dst-port 8888,999-1005
// 格式: udp src-port 0-65535 dst-port 5555
func parseTCPUDPEntry(line, protocol string) map[string]interface{} {
	result := make(map[string]interface{})

	// 解析 src-port
	srcPortRe := regexp.MustCompile(`src-port\s+([0-9\-]+)`)
	srcMatches := srcPortRe.FindStringSubmatch(line)
	var srcPorts []map[string]interface{}
	if len(srcMatches) >= 2 {
		srcPorts = parsePortRange(srcMatches[1])
	} else {
		// 默认全部端口
		srcPorts = []map[string]interface{}{
			{"start": float64(0), "end": float64(65535)},
		}
	}

	// 解析 dst-port（支持逗号分隔的多个端口或范围）
	dstPortRe := regexp.MustCompile(`dst-port\s+([0-9\-,]+)`)
	dstMatches := dstPortRe.FindStringSubmatch(line)
	var dstPorts []map[string]interface{}
	if len(dstMatches) >= 2 {
		// 按逗号分割多个端口
		portList := strings.Split(dstMatches[1], ",")
		for _, portStr := range portList {
			portStr = strings.TrimSpace(portStr)
			parsedPorts := parsePortRange(portStr)
			dstPorts = append(dstPorts, parsedPorts...)
		}
	} else {
		// 默认全部端口
		dstPorts = []map[string]interface{}{
			{"start": float64(0), "end": float64(65535)},
		}
	}

	result["srcPorts"] = srcPorts
	result["dstPorts"] = dstPorts
	return result
}

// parsePortRange 解析端口范围
// 支持格式: 80, 80-8080, 0-65535
func parsePortRange(portStr string) []map[string]interface{} {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return nil
	}

	var result []map[string]interface{}

	// 检查是否是端口范围
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) == 2 {
			start, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			end, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if err1 == nil && err2 == nil {
				result = append(result, map[string]interface{}{
					"start": start,
					"end":   end,
				})
			}
		}
	} else {
		// 单个端口
		if port, err := strconv.ParseFloat(portStr, 64); err == nil {
			result = append(result, map[string]interface{}{
				"start": port,
				"end":   port,
			})
		}
	}

	return result
}

// parseServicePortEntry 解析服务端口条目（兼容旧格式）
// 支持格式：
// - 80 (单个端口)
// - 80-8080 (端口范围)
func parseServicePortEntry(portStr string) map[string]interface{} {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return nil
	}

	result := make(map[string]interface{})

	// 检查是否是端口范围
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) == 2 {
			start, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			end, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if err1 == nil && err2 == nil {
				result["dstPorts"] = []map[string]interface{}{
					{
						"start": start,
						"end":   end,
					},
				}
				// 源端口默认为 0-65535
				result["srcPorts"] = []map[string]interface{}{
					{
						"start": float64(0),
						"end":   float64(65535),
					},
				}
				return result
			}
		}
	}

	// 单个端口
	if port, err := strconv.ParseFloat(portStr, 64); err == nil {
		result["dstPorts"] = []map[string]interface{}{
			{
				"start": port,
				"end":   port, // 单个端口时，end 等于 start
			},
		}
		// 源端口默认为 0-65535
		result["srcPorts"] = []map[string]interface{}{
			{
				"start": float64(0),
				"end":   float64(65535),
			},
		}
		return result
	}

	return nil
}

// parseServGroupBlock 解析 servgroup 配置块
// 支持格式：
// config
// servgroup "name"
// service "service1"
// service "service2"
// end
func parseServGroupBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 查找 servgroup "name" 行
	var name string
	for i := 0; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" || line == "config" || line == "end" {
			continue
		}
		re := regexp.MustCompile(`servgroup\s+"([^"]+)"`)
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			name = matches[1]
			break
		}
	}
	if name == "" {
		return nil
	}

	result := map[string]interface{}{
		"name":     name,
		"uuid":     "",
		"servType": "SERV_GRP", // 服务组
	}

	var servsInfo []string

	// 解析所有 service 引用
	for i := 0; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" || line == "end" || line == "config" || strings.HasPrefix(line, "servgroup ") {
			continue
		}

		// 解析 service "name"
		if strings.HasPrefix(line, "service ") {
			re := regexp.MustCompile(`service\s+"([^"]+)"`)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 2 {
				servsInfo = append(servsInfo, matches[1])
			}
		}
	}

	if len(servsInfo) > 0 {
		result["servsInfo"] = servsInfo
	}

	return result
}

// protocolToNumber 将协议名转换为协议号
func protocolToNumber(protocol string) float64 {
	protocol = strings.ToLower(protocol)
	protocolMap := map[string]float64{
		"ip":   0,
		"icmp": 1,
		"tcp":  6,
		"udp":  17,
		"esp":  50,
		"ah":   51,
		"gre":  47,
	}
	if num, ok := protocolMap[protocol]; ok {
		return num
	}
	return 0
}

// parsePolicyBlock 解析 policy 配置块
func parsePolicyBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 解析第一行：policy "name" bottom
	firstLine := block[0]
	re := regexp.MustCompile(`policy\s+"([^"]+)"`)
	matches := re.FindStringSubmatch(firstLine)
	if len(matches) < 2 {
		return nil
	}

	name := matches[1]

	result := map[string]interface{}{
		"name": name,
		"uuid": "", // CLI 中没有 UUID
	}

	// 解析其他属性
	enable := true
	var srcZones []interface{}
	var srcIpGroups []interface{}
	var dstIpGroups []interface{}
	var services []interface{}
	action := "DENY"
	policyType := "INTERNET_ACCESS"

	for i := 1; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" {
			continue
		}

		// 解析 enable
		if line == "enable" {
			enable = true
		} else if line == "disable" || strings.HasPrefix(line, "no ") {
			enable = false
		}

		// 解析 src-zone
		if strings.HasPrefix(line, "src-zone ") {
			zone := strings.TrimPrefix(line, "src-zone ")
			zone = strings.Trim(zone, `"`)
			srcZones = append(srcZones, zone)
		}

		// 解析 src-ipgroup
		if strings.HasPrefix(line, "src-ipgroup ") {
			ipgroup := strings.TrimPrefix(line, "src-ipgroup ")
			ipgroup = strings.Trim(ipgroup, `"`)
			srcIpGroups = append(srcIpGroups, ipgroup)
		}

		// 解析 dst-ipgroup
		if strings.HasPrefix(line, "dst-ipgroup ") {
			ipgroup := strings.TrimPrefix(line, "dst-ipgroup ")
			ipgroup = strings.Trim(ipgroup, `"`)
			dstIpGroups = append(dstIpGroups, ipgroup)
		}

		// 解析 service
		if strings.HasPrefix(line, "service ") {
			service := strings.TrimPrefix(line, "service ")
			service = strings.Trim(service, `"`)
			services = append(services, service)
		}

		// 解析 action
		if strings.HasPrefix(line, "action ") {
			actionStr := strings.TrimPrefix(line, "action ")
			if actionStr == "permit" {
				action = "ALLOW"
			} else {
				action = "DENY"
			}
		}
	}

	result["enable"] = enable
	result["policyType"] = policyType

	if len(srcZones) > 0 {
		result["srcZones"] = srcZones
	}

	// 构建 srcAddrs
	srcAddrs := map[string]interface{}{
		"srcAddrType": "NETOBJECT",
	}
	if len(srcIpGroups) > 0 {
		srcAddrs["srcIpGroups"] = srcIpGroups
	}
	result["srcAddrs"] = srcAddrs

	if len(dstIpGroups) > 0 {
		result["dstIpGroups"] = dstIpGroups
	}

	if len(services) > 0 {
		result["services"] = services
	}

	result["action"] = action

	return result
}

// parseDNATBlock 解析 dnat-rule 配置块
func parseDNATBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 解析第一行：dnat-rule "name" bottom
	firstLine := block[0]
	re := regexp.MustCompile(`dnat-rule\s+"([^"]+)"`)
	matches := re.FindStringSubmatch(firstLine)
	if len(matches) < 2 {
		return nil
	}

	name := matches[1]

	result := map[string]interface{}{
		"name":    name,
		"uuid":    "",
		"natType": "DNAT",
	}

	enable := true
	var srcZones []string
	var srcIpGroups []string
	var dstIpGroups []string
	var dstIp string
	var services []string
	var transfer map[string]interface{}

	for i := 1; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" {
			continue
		}

		if line == "enable" {
			enable = true
		} else if line == "disable" || strings.HasPrefix(line, "no ") {
			enable = false
		}

		// 解析 src-zone
		if strings.HasPrefix(line, "src-zone ") {
			zone := strings.TrimPrefix(line, "src-zone ")
			zone = strings.Trim(zone, `"`)
			srcZones = append(srcZones, zone)
		}

		// 解析 src-ipgroup
		if strings.HasPrefix(line, "src-ipgroup ") {
			ipgroup := strings.TrimPrefix(line, "src-ipgroup ")
			ipgroup = strings.Trim(ipgroup, `"`)
			srcIpGroups = append(srcIpGroups, ipgroup)
		}

		// 解析 dst-ipgroup
		if strings.HasPrefix(line, "dst-ipgroup ") {
			ipgroup := strings.TrimPrefix(line, "dst-ipgroup ")
			ipgroup = strings.Trim(ipgroup, `"`)
			dstIpGroups = append(dstIpGroups, ipgroup)
		}

		// 解析 dst-ip
		if strings.HasPrefix(line, "dst-ip ") {
			dstIp = strings.TrimPrefix(line, "dst-ip ")
			dstIp = strings.TrimSpace(dstIp)
		}

		// 解析 service
		if strings.HasPrefix(line, "service ") {
			service := strings.TrimPrefix(line, "service ")
			service = strings.Trim(service, `"`)
			services = append(services, service)
		}

		// 解析 transfer（只处理第一个有效的 transfer，避免被后续的 transfer load-balance 覆盖）
		if strings.HasPrefix(line, "transfer ") {
			fmt.Printf("[parseDNATBlock] 解析 transfer 行: %s\n", line)
			parsedTransfer := parseTransfer(line)
			fmt.Printf("[parseDNATBlock] parseTransfer 返回: %v\n", parsedTransfer)
			// 只有当 transfer 为空或者解析出的 transfer 不为空时才更新
			// 这样可以避免 transfer load-balance 覆盖之前的 transfer ip
			if transfer == nil || len(parsedTransfer) > 0 {
				// 如果 parsedTransfer 不为空，说明是有效的 transfer（如 transfer ip ...）
				// 如果 parsedTransfer 为空，说明是 transfer load-balance 等，不应该覆盖
				if len(parsedTransfer) > 0 {
					transfer = parsedTransfer
				}
			}
		}
	}

	result["enable"] = enable

	// 构建 dnat 对象（与 API 响应格式一致）
	dnat := make(map[string]interface{})
	if len(srcZones) > 0 {
		dnat["srcZones"] = srcZones
	}
	if len(srcIpGroups) > 0 {
		dnat["srcIpGroups"] = srcIpGroups
	}
	if len(dstIpGroups) > 0 {
		dnat["dstIpGroups"] = dstIpGroups
	}
	if dstIp != "" {
		dnat["dstIp"] = dstIp
	}
	if len(services) > 0 {
		dnat["natService"] = services
	}
	if transfer != nil {
		fmt.Printf("[parseDNATBlock] transfer 不为 nil，键: %v\n", func() []string {
			keys := make([]string, 0, len(transfer))
			for k := range transfer {
				keys = append(keys, k)
			}
			return keys
		}())
		dnat["transfer"] = transfer
		// 根据 transfer 类型设置相应的字段（与 parseNatItem 期望的格式一致）
		if transferType, ok := transfer["transferType"].(string); ok {
			fmt.Printf("[parseDNATBlock] transferType: %s\n", transferType)
			switch transferType {
			case "IP":
				if ip, ok := transfer["ip"].(string); ok {
					fmt.Printf("[parseDNATBlock] 设置 transferIP: %s\n", ip)
					dnat["transferIP"] = ip
					// 如果有 port，也设置 transferPort
					if port, ok := transfer["port"].(string); ok {
						fmt.Printf("[parseDNATBlock] 设置 transferPort: %s\n", port)
						dnat["transferPort"] = port
					} else {
						fmt.Printf("[parseDNATBlock] transfer 中没有 port 字段\n")
					}
				} else {
					fmt.Printf("[parseDNATBlock] transfer 中没有 ip 字段\n")
				}
			case "IP_RANGE":
				if start, ok := transfer["start"].(string); ok {
					if end, ok2 := transfer["end"].(string); ok2 {
						dnat["transferIPRange"] = start + "-" + end
					}
				}
			case "IPGROUP":
				if ipgroup, ok := transfer["ipgroup"].(string); ok {
					dnat["transferIPGroup"] = ipgroup
				}
			}
		}
	}
	result["dnat"] = dnat

	return result
}

// parseSNATBlock 解析 snat-rule 配置块
func parseSNATBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 解析第一行：snat-rule "name" bottom
	firstLine := block[0]
	re := regexp.MustCompile(`snat-rule\s+"([^"]+)"`)
	matches := re.FindStringSubmatch(firstLine)
	if len(matches) < 2 {
		return nil
	}

	name := matches[1]

	result := map[string]interface{}{
		"name":    name,
		"uuid":    "",
		"natType": "SNAT",
	}

	enable := true
	var srcZones []string
	var srcIpGroups []string
	var dstZones []string
	var dstIpGroups []string
	var services []string
	var transfer map[string]interface{}

	for i := 1; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" {
			continue
		}

		if line == "enable" {
			enable = true
		} else if line == "disable" || strings.HasPrefix(line, "no ") {
			enable = false
		}

		// 解析 src-zone
		if strings.HasPrefix(line, "src-zone ") {
			zone := strings.TrimPrefix(line, "src-zone ")
			zone = strings.Trim(zone, `"`)
			srcZones = append(srcZones, zone)
		}

		// 解析 src-ipgroup
		if strings.HasPrefix(line, "src-ipgroup ") {
			ipgroup := strings.TrimPrefix(line, "src-ipgroup ")
			ipgroup = strings.Trim(ipgroup, `"`)
			srcIpGroups = append(srcIpGroups, ipgroup)
		}

		// 解析 dst-zone
		if strings.HasPrefix(line, "dst-zone ") {
			zone := strings.TrimPrefix(line, "dst-zone ")
			zone = strings.TrimSpace(zone)
			zone = strings.Trim(zone, `"`)
			dstZones = append(dstZones, zone)
		}

		// 解析 dst-ipgroup
		if strings.HasPrefix(line, "dst-ipgroup ") {
			ipgroup := strings.TrimPrefix(line, "dst-ipgroup ")
			ipgroup = strings.Trim(ipgroup, `"`)
			dstIpGroups = append(dstIpGroups, ipgroup)
		}

		// 解析 service
		if strings.HasPrefix(line, "service ") {
			service := strings.TrimPrefix(line, "service ")
			service = strings.Trim(service, `"`)
			services = append(services, service)
		}

		// 解析 transfer
		if strings.HasPrefix(line, "transfer ") {
			transfer = parseTransfer(line)
		}
	}

	result["enable"] = enable

	// 构建 snat 对象（与 API 响应格式一致）
	snat := make(map[string]interface{})
	if len(srcZones) > 0 {
		snat["srcZones"] = srcZones
	}
	if len(srcIpGroups) > 0 {
		snat["srcIpGroups"] = srcIpGroups
	}
	if len(dstZones) > 0 {
		snat["dstZones"] = dstZones
		// 构建 dstNetobj
		dstNetobj := map[string]interface{}{
			"dstNetobjType": "ZONE",
			"zone":          dstZones,
		}
		snat["dstNetobj"] = dstNetobj
	}
	if len(dstIpGroups) > 0 {
		snat["dstIpGroups"] = dstIpGroups
	}
	if len(services) > 0 {
		snat["natService"] = services
	}
	if transfer != nil {
		snat["transfer"] = transfer
		// 根据 transfer 类型设置相应的字段
		if transferType, ok := transfer["transferType"].(string); ok {
			switch transferType {
			case "IPGROUP":
				if ipgroup, ok := transfer["ipgroup"].(string); ok {
					snat["transferIPGroup"] = ipgroup
				}
			case "IP":
				if ip, ok := transfer["ip"].(string); ok {
					snat["transferIP"] = ip
				}
			case "IP_RANGE":
				if start, ok := transfer["start"].(string); ok {
					if end, ok2 := transfer["end"].(string); ok2 {
						snat["transferIPRange"] = start + "-" + end
					}
				}
			}
		}
	}
	result["snat"] = snat

	return result
}

// parseTransfer 解析 transfer 行
// 支持格式：
// - transfer ip 192.168.100.111 port 22
// - transfer iprange 192.168.100.1-192.168.100.255
// - transfer ipgroup dst-text1
// - transfer iprange 192.168.100.101-192.168.100.102 dynamic
func parseTransfer(line string) map[string]interface{} {
	originalLine := line
	line = strings.TrimPrefix(line, "transfer ")
	line = strings.TrimSpace(line)
	fmt.Printf("[parseTransfer] 输入: %s, 处理后: %s\n", originalLine, line)

	result := make(map[string]interface{})

	// 解析 transfer ip <ip> [port <port>]
	if strings.HasPrefix(line, "ip ") {
		parts := strings.Fields(line)
		fmt.Printf("[parseTransfer] 解析 'ip' 格式，parts: %v, 数量: %d\n", parts, len(parts))
		if len(parts) >= 2 {
			result["transferType"] = "IP"
			result["ip"] = parts[1]
			fmt.Printf("[parseTransfer] 设置 ip: %s\n", parts[1])
			if len(parts) >= 4 && parts[2] == "port" {
				result["port"] = parts[3]
				fmt.Printf("[parseTransfer] 设置 port: %s\n", parts[3])
			} else {
				fmt.Printf("[parseTransfer] 没有 port 字段（parts 数量: %d, parts[2]: %s）\n", len(parts), func() string {
					if len(parts) > 2 {
						return parts[2]
					}
					return "<nil>"
				}())
			}
		}
	} else if strings.HasPrefix(line, "iprange ") {
		// 解析 transfer iprange <start>-<end> [dynamic]
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			result["transferType"] = "IP_RANGE"
			ipRange := parts[1]
			if strings.Contains(ipRange, "-") {
				rangeParts := strings.Split(ipRange, "-")
				if len(rangeParts) == 2 {
					result["start"] = rangeParts[0]
					result["end"] = rangeParts[1]
				}
			}
			// 检查是否有 dynamic
			if len(parts) > 2 && parts[2] == "dynamic" {
				result["mode"] = "DYNAMIC"
			} else {
				result["mode"] = "STATIC"
			}
		}
	} else if strings.HasPrefix(line, "ipgroup ") {
		// 解析 transfer ipgroup <name>
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			result["transferType"] = "IPGROUP"
			result["ipgroup"] = parts[1]
		}
	}

	return result
}

// parseIPRouteBlock 解析 ip route 配置块
// 支持格式：
// ip route <prefix> <gateway> interface <ifname> description "..." metric <metric> tag <tag>
func parseIPRouteBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 解析第一行：ip route <prefix> <gateway> [interface <ifname>] [description "..."] [metric <metric>] [tag <tag>]
	firstLine := block[0]
	parts := strings.Fields(firstLine)

	// 至少需要 "ip route <prefix> <gateway>"
	if len(parts) < 4 || parts[0] != "ip" || parts[1] != "route" {
		return nil
	}

	result := map[string]interface{}{
		"uuid":     "",
		"enable":   true,
		"prefix":   parts[2],
		"gateway":  parts[3],
		"metric":   float64(0),
		"distance": float64(1),
		"weight":   float64(1),
		"tag":      float64(0),
	}

	// 解析后续参数
	for i := 4; i < len(parts); i++ {
		switch parts[i] {
		case "interface":
			if i+1 < len(parts) {
				result["ifname"] = parts[i+1]
				i++
			}
		case "description":
			if i+1 < len(parts) {
				desc := parts[i+1]
				// 移除引号
				desc = strings.Trim(desc, `"`)
				result["description"] = desc
				i++
			}
		case "metric":
			if i+1 < len(parts) {
				if metric, err := strconv.ParseFloat(parts[i+1], 64); err == nil {
					result["metric"] = metric
				}
				i++
			}
		case "tag":
			if i+1 < len(parts) {
				if tag, err := strconv.ParseFloat(parts[i+1], 64); err == nil {
					result["tag"] = tag
				}
				i++
			}
		}
	}

	return result
}

// parseZoneBlock 解析 zone 配置块
// 支持格式：
// zone "name"
// forward-type <type>
// interfaces <interface1> [<interface2> ...]
func parseZoneBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 解析第一行：zone "name"
	firstLine := block[0]
	re := regexp.MustCompile(`zone\s+"([^"]+)"`)
	matches := re.FindStringSubmatch(firstLine)
	if len(matches) < 2 {
		return nil
	}

	name := matches[1]

	result := map[string]interface{}{
		"name":        name,
		"uuid":        "",
		"enable":      true,
		"description": "",
		"interfaces":  []string{},
		"priority":    float64(0),
		"type":        "",
	}

	// 解析其他属性
	for i := 1; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" {
			continue
		}

		// 解析 forward-type
		if strings.HasPrefix(line, "forward-type ") {
			forwardType := strings.TrimPrefix(line, "forward-type ")
			forwardType = strings.TrimSpace(forwardType)
			result["type"] = forwardType
		}

		// 解析 interfaces
		if strings.HasPrefix(line, "interfaces ") {
			interfacesStr := strings.TrimPrefix(line, "interfaces ")
			interfacesStr = strings.TrimSpace(interfacesStr)
			// 分割多个接口（用空格分隔）
			interfaceList := strings.Fields(interfacesStr)
			if len(interfaceList) > 0 {
				result["interfaces"] = interfaceList
			}
		}
	}

	return result
}

// parseInterfaceBlock 解析 interface 配置块
// 支持格式：
// interface <name>
// wan disable|enable
// shutdown|no shutdown
// ip address <ip>/<mask>
// ipv6 enable|disable
// default-gateway <gateway>
// reverse-route disable|enable
// manage <service> enable|disable
// bandwidth upstream <value>
// bandwidth downstream <value>
func parseInterfaceBlock(block []string) map[string]interface{} {
	if len(block) == 0 {
		return nil
	}

	// 解析第一行：interface <name>
	firstLine := block[0]
	parts := strings.Fields(firstLine)
	if len(parts) < 2 || parts[0] != "interface" {
		return nil
	}

	name := parts[1]

	result := map[string]interface{}{
		"name":        name,
		"uuid":        "",
		"description": "",
		"mtu":         float64(1500),
		"ifType":      "PHYSICALIF",
		"ifMode":      "ROUTE",
		"shutdown":    false,
		"ipv4": map[string]interface{}{
			"ipv4Mode": "STATIC",
			"staticIp": []interface{}{},
		},
		"ipv6": map[string]interface{}{
			"ipv6Mode": "STATIC",
		},
	}

	// 解析其他属性
	for i := 1; i < len(block); i++ {
		line := strings.TrimSpace(block[i])
		if line == "" {
			continue
		}

		// 解析 wan
		if strings.HasPrefix(line, "wan ") {
			wanValue := strings.TrimPrefix(line, "wan ")
			wanValue = strings.TrimSpace(wanValue)
			// wan disable 表示不是 WAN，wan enable 表示是 WAN
			result["wan"] = wanValue == "enable"
		}

		// 解析 shutdown
		if line == "shutdown" {
			result["shutdown"] = true
		} else if line == "no shutdown" {
			result["shutdown"] = false
		}

		// 解析 ip address
		if strings.HasPrefix(line, "ip address ") {
			ipAddr := strings.TrimPrefix(line, "ip address ")
			ipAddr = strings.TrimSpace(ipAddr)
			// 解析 IP 地址和掩码（格式：192.168.1.1/24）
			if strings.Contains(ipAddr, "/") {
				parts := strings.Split(ipAddr, "/")
				if len(parts) == 2 {
					ip := parts[0]
					maskStr := parts[1]
					if mask, err := strconv.ParseFloat(maskStr, 64); err == nil {
						ipv4 := result["ipv4"].(map[string]interface{})
						staticIp := ipv4["staticIp"].([]interface{})
						ipv4["staticIp"] = append(staticIp, map[string]interface{}{
							"ipaddress": map[string]interface{}{
								"start": ip,
								"end":   "",
								"bits":  mask,
							},
							"isSync": false,
						})
					}
				}
			}
		}

		// 解析 ipv6 enable
		if line == "ipv6 enable" {
			ipv6 := result["ipv6"].(map[string]interface{})
			ipv6["ipv6Mode"] = "STATIC"
		} else if line == "ipv6 disable" {
			ipv6 := result["ipv6"].(map[string]interface{})
			ipv6["ipv6Mode"] = "DISABLE"
		}

		// 解析 default-gateway
		if strings.HasPrefix(line, "default-gateway ") {
			gateway := strings.TrimPrefix(line, "default-gateway ")
			gateway = strings.TrimSpace(gateway)
			result["defaultGateway"] = gateway
		}

		// 解析 reverse-route
		if strings.HasPrefix(line, "reverse-route ") {
			reverseRoute := strings.TrimPrefix(line, "reverse-route ")
			result["reverseRoute"] = reverseRoute == "enable"
		}

		// 解析 manage <service> enable|disable
		if strings.HasPrefix(line, "manage ") {
			manageParts := strings.Fields(line)
			if len(manageParts) >= 3 {
				service := manageParts[1]
				enable := manageParts[2] == "enable"
				// 可以存储到 manage 字段中
				if manageMap, ok := result["manage"].(map[string]interface{}); ok {
					manageMap[service] = enable
				} else {
					result["manage"] = map[string]interface{}{
						service: enable,
					}
				}
			}
		}

		// 解析 bandwidth upstream
		if strings.HasPrefix(line, "bandwidth upstream ") {
			valueStr := strings.TrimPrefix(line, "bandwidth upstream ")
			if value, err := strconv.ParseFloat(valueStr, 64); err == nil {
				result["bandwidthUpstream"] = value
			}
		}

		// 解析 bandwidth downstream
		if strings.HasPrefix(line, "bandwidth downstream ") {
			valueStr := strings.TrimPrefix(line, "bandwidth downstream ")
			if value, err := strconv.ParseFloat(valueStr, 64); err == nil {
				result["bandwidthDownstream"] = value
			}
		}
	}

	return result
}
