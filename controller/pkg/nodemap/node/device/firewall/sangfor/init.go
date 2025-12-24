package sangfor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sangforEnum "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/sangfor/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"gopkg.in/yaml.v2"
)

func (sangfor *SangforNode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
	sangfor.WithNodeType(api.FIREWALL)

	// 获取网络对象配置
	ipGroups, err := adapter.GetRawConfig(string(sangforEnum.IPGroups), false)
	if err != nil {
		fmt.Println("sangfor ipGroups fetch err: ", err)
	} else {
		if ipGroupsMap, ok := ipGroups.(map[string]interface{}); ok {
			objectSet := NewSangforObjectSet(sangfor)
			objectSet.parseRespResultForNetwork(ipGroupsMap)
			sangfor.objectSet = objectSet
		}
	}

	// 获取服务对象配置
	services, err := adapter.GetRawConfig(string(sangforEnum.Services), false)
	if err != nil {
		fmt.Println("sangfor services fetch err: ", err)
	} else {
		if servicesMap, ok := services.(map[string]interface{}); ok {
			if sangfor.objectSet == nil {
				sangfor.objectSet = NewSangforObjectSet(sangfor)
			}
			sangfor.objectSet.parseRespResultForService(servicesMap)
		}
	}

	// 确保 objectSet 已初始化
	if sangfor.objectSet == nil {
		sangfor.objectSet = NewSangforObjectSet(sangfor)
	}

	// 获取 NAT 配置
	nats, err := adapter.GetRawConfig(string(sangforEnum.NATs), false)
	if err != nil {
		fmt.Println("sangfor nats fetch err: ", err)
	} else {
		if natsMap, ok := nats.(map[string]interface{}); ok {
			natSet := NewSangforNats(sangfor)
			natSet.parseRespResultForNat(natsMap)
			sangfor.nats = natSet
		}
	}

	// 确保 nats 已初始化
	if sangfor.nats == nil {
		sangfor.nats = &Nats{
			objects:             sangfor.objectSet,
			node:                sangfor,
			destinationNatRules: []*NatRule{},
			sourceNatRules:      []*NatRule{},
			natPolicyRules:      []*NatRule{},
			natServers:          []*NatRule{},
		}
	}

	// 获取应用访问策略配置
	appcontrols, err := adapter.GetRawConfig(string(sangforEnum.Appcontrols), false)
	if err != nil {
		fmt.Println("sangfor appcontrols fetch err: ", err)
	} else {
		if appcontrolsMap, ok := appcontrols.(map[string]interface{}); ok {
			policySet := &PolicySet{
				objects:   sangfor.objectSet,
				node:      sangfor,
				policySet: []*Policy{},
			}
			policySet.parseRespResultForPolicy(appcontrolsMap)
			sangfor.policySet = policySet
		}
	}

	// 确保 policySet 已初始化
	if sangfor.policySet == nil {
		sangfor.policySet = &PolicySet{
			objects:   sangfor.objectSet,
			node:      sangfor,
			policySet: []*Policy{},
		}
	}

	fmt.Println("sangfor objectSet--->", sangfor.objectSet)
	fmt.Println("sangfor nats--->", sangfor.nats)
	fmt.Println("sangfor policySet--->", sangfor.policySet)

	// 将 NAT 和 Policy 转换为 YAML 格式并保存到文件
	sangfor.saveNatsAndPoliciesToYAML()

	sangfor.snatDesignInfo = deviceConfig.Snat
}

func (sangfor *SangforNode) FlyConfig(cli interface{}) {
	// FlyConfig 用于从生成的 CLI 配置中解析对象
	// 支持 map[string]interface{} 和 map[string]string 格式的 FlyConfig 数据
	fmt.Printf("[FlyConfig] 输入类型: %T\n", cli)
	if flyObjectMap, ok := cli.(map[string]interface{}); ok {
		fmt.Printf("[FlyConfig] 检测到 map[string]interface{} 格式，键: %v\n", func() []string {
			keys := make([]string, 0, len(flyObjectMap))
			for k := range flyObjectMap {
				keys = append(keys, k)
			}
			return keys
		}())
		sangfor.parseFlyConfig(flyObjectMap)
	} else if flyObjectStrMap, ok := cli.(map[string]string); ok {
		// 支持 map[string]string 格式（FlyObject 的实际类型）
		fmt.Printf("[FlyConfig] 检测到 map[string]string 格式，键: %v\n", func() []string {
			keys := make([]string, 0, len(flyObjectStrMap))
			for k := range flyObjectStrMap {
				keys = append(keys, k)
			}
			return keys
		}())
		// 将 map[string]string 转换为字符串后解析
		var combinedCLI strings.Builder
		for _, value := range flyObjectStrMap {
			if value != "" {
				combinedCLI.WriteString(value)
				combinedCLI.WriteString("\n")
			}
		}
		cliStr := combinedCLI.String()
		fmt.Printf("[FlyConfig] 合并后的 CLI 长度: %d\n", len(cliStr))
		flyObjectMap, err := parseCLIString(cliStr)
		if err != nil {
			fmt.Printf("[FlyConfig] 解析 CLI 字符串失败: %v\n", err)
			return
		}
		fmt.Printf("[FlyConfig] parseCLIString 返回的键: %v\n", func() []string {
			keys := make([]string, 0, len(flyObjectMap))
			for k := range flyObjectMap {
				keys = append(keys, k)
			}
			return keys
		}())
		sangfor.parseFlyConfig(flyObjectMap)
	} else if cliStr, ok := cli.(string); ok {
		fmt.Printf("[FlyConfig] 检测到 string 格式，长度: %d\n", len(cliStr))
		// 如果传入的是字符串，解析 CLI 配置
		flyObjectMap, err := parseCLIString(cliStr)
		if err != nil {
			fmt.Printf("[FlyConfig] 解析 CLI 字符串失败: %v\n", err)
			return
		}
		fmt.Printf("[FlyConfig] parseCLIString 返回的键: %v\n", func() []string {
			keys := make([]string, 0, len(flyObjectMap))
			for k := range flyObjectMap {
				keys = append(keys, k)
			}
			return keys
		}())
		sangfor.parseFlyConfig(flyObjectMap)
	} else {
		fmt.Printf("[FlyConfig] 不支持的输入类型: %T\n", cli)
	}
}

// parseFlyConfig 解析 FlyConfig 数据
func (sangfor *SangforNode) parseFlyConfig(flyObjectMap map[string]interface{}) {
	fmt.Printf("[parseFlyConfig] 开始解析，输入键: %v\n", func() []string {
		keys := make([]string, 0, len(flyObjectMap))
		for k := range flyObjectMap {
			keys = append(keys, k)
		}
		return keys
	}())

	// 首先处理 POOL 对象（SNAT pool），确保在 NAT 规则之前解析
	// POOL 对象在 FlyObject 中是字符串格式的 CLI，需要解析为网络对象
	poolValue, poolExists := flyObjectMap[common.FlyObjectPool]
	if poolExists {
		fmt.Printf("[parseFlyConfig] POOL 存在，类型: %T, 值: %v\n", poolValue, poolValue)
	}
	if pools, ok := flyObjectMap[common.FlyObjectPool].([]interface{}); ok {
		fmt.Printf("[parseFlyConfig] POOL 是 []interface{}，数量: %d\n", len(pools))
		for _, pool := range pools {
			if poolStr, ok := pool.(string); ok {
				// 解析 POOL CLI 字符串
				poolMap, err := parseCLIString(poolStr)
				if err == nil {
					// 将解析出的网络对象添加到 objectSet
					if networks, ok := poolMap[common.FlyObjectNetwork].([]interface{}); ok {
						for _, nk := range networks {
							if networkMap, ok := nk.(map[string]interface{}); ok {
								// 标记为 POOL 类型
								networkMap["objType"] = "POOL"
								sangfor.objectSet.parseNetworkItem(networkMap)
							}
						}
					}
				}
			} else if poolMap, ok := pool.(map[string]interface{}); ok {
				// 如果已经是 map 格式，直接处理
				poolMap["objType"] = "POOL"
				sangfor.objectSet.parseNetworkItem(poolMap)
			}
		}
	} else if poolStr, ok := flyObjectMap[common.FlyObjectPool].(string); ok {
		// 如果 POOL 是单个字符串
		poolMap, err := parseCLIString(poolStr)
		if err == nil {
			if networks, ok := poolMap["NETWORK"].([]interface{}); ok {
				for _, nk := range networks {
					if networkMap, ok := nk.(map[string]interface{}); ok {
						networkMap["objType"] = "POOL"
						sangfor.objectSet.parseNetworkItem(networkMap)
					}
				}
			}
		}
	}

	// 处理网络对象（在 POOL 之后，以便 POOL 优先）
	networkValue, networkExists := flyObjectMap[common.FlyObjectNetwork]
	if networkExists {
		fmt.Printf("[parseFlyConfig] NETWORK 存在，类型: %T\n", networkValue)
	}
	if networks, ok := flyObjectMap[common.FlyObjectNetwork].([]interface{}); ok {
		fmt.Printf("[parseFlyConfig] NETWORK 是 []interface{}，数量: %d\n", len(networks))
		for i, nk := range networks {
			if networkMap, ok := nk.(map[string]interface{}); ok {
				name, _ := networkMap["name"].(string)
				fmt.Printf("[parseFlyConfig] 解析网络对象 %d: %s\n", i, name)
				sangfor.objectSet.parseNetworkItem(networkMap)
			} else {
				fmt.Printf("[parseFlyConfig] 网络对象 %d 类型断言失败: %T\n", i, nk)
			}
		}
		fmt.Printf("[parseFlyConfig] 解析后网络对象数量: %d\n", len(sangfor.objectSet.networkMap))
	} else if networkExists {
		fmt.Printf("[parseFlyConfig] NETWORK 类型断言失败，期望 []interface{}，实际: %T\n", networkValue)
	}

	// 处理服务对象
	serviceValue, serviceExists := flyObjectMap[common.FlyObjectService]
	if serviceExists {
		fmt.Printf("[parseFlyConfig] SERVICE 存在，类型: %T\n", serviceValue)
	}
	if services, ok := flyObjectMap[common.FlyObjectService].([]interface{}); ok {
		fmt.Printf("[parseFlyConfig] SERVICE 是 []interface{}，数量: %d\n", len(services))
		for i, svc := range services {
			if serviceMap, ok := svc.(map[string]interface{}); ok {
				name, _ := serviceMap["name"].(string)
				fmt.Printf("[parseFlyConfig] 解析服务对象 %d: %s\n", i, name)
				sangfor.objectSet.parseServiceItem(serviceMap)
			} else {
				fmt.Printf("[parseFlyConfig] 服务对象 %d 类型断言失败: %T\n", i, svc)
			}
		}
		fmt.Printf("[parseFlyConfig] 解析后服务对象数量: %d\n", len(sangfor.objectSet.serviceMap))
	} else if serviceExists {
		fmt.Printf("[parseFlyConfig] SERVICE 类型断言失败，期望 []interface{}，实际: %T\n", serviceValue)
	}

	// 处理 NAT 规则（包括 STATIC_NAT 和 DYNAMIC_NAT）
	staticNatValue, staticNatExists := flyObjectMap[common.FlyObjectStaticNat]
	if staticNatExists {
		fmt.Printf("[parseFlyConfig] STATIC_NAT 存在，类型: %T\n", staticNatValue)
	}
	if nats, ok := flyObjectMap[common.FlyObjectStaticNat].([]interface{}); ok {
		fmt.Printf("[parseFlyConfig] STATIC_NAT 是 []interface{}，数量: %d\n", len(nats))
		if sangfor.nats == nil {
			sangfor.nats = NewSangforNats(sangfor)
		}
		// 确保 nats.objects 指向当前的 objectSet（可能在解析过程中更新）
		sangfor.nats.objects = sangfor.objectSet
		fmt.Printf("[parseFlyConfig] nats.objects 网络对象数量: %d, 服务对象数量: %d\n",
			len(sangfor.nats.objects.networkMap), len(sangfor.nats.objects.serviceMap))
		for i, nat := range nats {
			if natMap, ok := nat.(map[string]interface{}); ok {
				name, _ := natMap["name"].(string)
				natType, _ := natMap["natType"].(string)
				fmt.Printf("[parseFlyConfig] 解析 NAT 规则 %d: %s (类型: %s)\n", i, name, natType)
				rule := sangfor.nats.parseNatItem(natMap)
				if rule != nil {
					// 根据 natType 决定放入哪个列表
					if natType == "SNAT" {
						sangfor.nats.sourceNatRules = append(sangfor.nats.sourceNatRules, rule)
						fmt.Printf("[parseFlyConfig] 添加 SNAT 规则: %s\n", name)
					} else {
						sangfor.nats.destinationNatRules = append(sangfor.nats.destinationNatRules, rule)
						fmt.Printf("[parseFlyConfig] 添加 DNAT 规则: %s\n", name)
					}
				} else {
					fmt.Printf("[parseFlyConfig] NAT 规则 %s 解析失败\n", name)
				}
			} else {
				fmt.Printf("[parseFlyConfig] NAT 规则 %d 类型断言失败: %T\n", i, nat)
			}
		}
		fmt.Printf("[parseFlyConfig] 解析后 DNAT 规则数量: %d, SNAT 规则数量: %d\n",
			len(sangfor.nats.destinationNatRules), len(sangfor.nats.sourceNatRules))
	} else if staticNatExists {
		fmt.Printf("[parseFlyConfig] STATIC_NAT 类型断言失败，期望 []interface{}，实际: %T\n", staticNatValue)
	}
	// 处理动态 NAT（如果有单独的 DYNAMIC_NAT 键）
	if nats, ok := flyObjectMap[common.FlyObjectDynamicNat].([]interface{}); ok {
		if sangfor.nats == nil {
			sangfor.nats = NewSangforNats(sangfor)
		}
		// 确保 nats.objects 指向当前的 objectSet（可能在解析过程中更新）
		sangfor.nats.objects = sangfor.objectSet
		for _, nat := range nats {
			if natMap, ok := nat.(map[string]interface{}); ok {
				rule := sangfor.nats.parseNatItem(natMap)
				if rule != nil {
					sangfor.nats.sourceNatRules = append(sangfor.nats.sourceNatRules, rule)
				}
			}
		}
	}

	// 处理策略（插入到首位）
	if policies, ok := flyObjectMap[common.FlyObjectSecurityPolicy].([]interface{}); ok {
		if sangfor.policySet == nil {
			sangfor.policySet = &PolicySet{
				objects:   sangfor.objectSet,
				node:      sangfor,
				policySet: []*Policy{},
			}
		}
		// 将策略插入到首位（按顺序插入，第一个策略在最前面）
		for i := len(policies) - 1; i >= 0; i-- {
			plc := policies[i]
			if policyMap, ok := plc.(map[string]interface{}); ok {
				policy := sangfor.policySet.parsePolicyItem(policyMap)
				if policy != nil {
					// 插入到首位：创建新切片，先添加新策略，再添加旧策略
					sangfor.policySet.policySet = append([]*Policy{policy}, sangfor.policySet.policySet...)
				}
			}
		}
	}
}

func (sangfor *SangforNode) FlyObjectToFlattenCli(flyObject interface{}, ctx *firewall.PolicyContext) string {
	if str, ok := flyObject.(string); ok {
		return strings.TrimSpace(str)
	}
	return ""
}

// saveNatsAndPoliciesToYAML 将 NAT 和 Policy 转换为 YAML 格式并保存到文件
func (sangfor *SangforNode) saveNatsAndPoliciesToYAML() {
	var policies []map[string]interface{}

	// 处理 NAT 规则（DNAT）
	if sangfor.nats != nil {
		for _, rule := range sangfor.nats.destinationNatRules {
			if rule.original == nil {
				continue
			}

			policyMap := make(map[string]interface{})

			// source
			if srcNg := rule.original.Src(); srcNg != nil && !srcNg.IsEmpty() {
				policyMap["source"] = formatNetworkGroup(srcNg)
			}

			// destination
			if dstNg := rule.original.Dst(); dstNg != nil && !dstNg.IsEmpty() {
				policyMap["destination"] = formatNetworkGroup(dstNg)
			}

			// realIp (DNAT 的 translate.Dst())
			if rule.translate != nil {
				if translateDstNg := rule.translate.Dst(); translateDstNg != nil && !translateDstNg.IsEmpty() {
					policyMap["realIp"] = formatNetworkGroup(translateDstNg)
				}
			}

			// realPort (DNAT 的 translate.Service())
			if rule.translate != nil {
				if translateSvc := rule.translate.Service(); translateSvc != nil && !translateSvc.IsEmpty() {
					portStr := formatServicePort(translateSvc)
					if portStr != "" {
						policyMap["realPort"] = portStr
					}
				}
			}

			// service
			if svc := rule.original.Service(); svc != nil && !svc.IsEmpty() {
				serviceMap := formatService(svc)
				if len(serviceMap) > 0 {
					policyMap["service"] = serviceMap
				}
			}

			// ticketNumber (使用规则名称)
			if rule.name != "" {
				policyMap["ticketNumber"] = rule.name
			}

			if len(policyMap) > 0 {
				policies = append(policies, policyMap)
			}
		}

		// 处理 SNAT 规则（通常不需要 realIp/realPort，但可以记录）
		for _, rule := range sangfor.nats.sourceNatRules {
			if rule.original == nil {
				continue
			}

			policyMap := make(map[string]interface{})

			// source
			if srcNg := rule.original.Src(); srcNg != nil && !srcNg.IsEmpty() {
				policyMap["source"] = formatNetworkGroup(srcNg)
			}

			// destination
			if dstNg := rule.original.Dst(); dstNg != nil && !dstNg.IsEmpty() {
				policyMap["destination"] = formatNetworkGroup(dstNg)
			}

			// realIp (SNAT 的 translate.Src())
			if rule.translate != nil {
				if translateSrcNg := rule.translate.Src(); translateSrcNg != nil && !translateSrcNg.IsEmpty() {
					policyMap["realIp"] = formatNetworkGroup(translateSrcNg)
				}
			}

			// service
			if svc := rule.original.Service(); svc != nil && !svc.IsEmpty() {
				serviceMap := formatService(svc)
				if len(serviceMap) > 0 {
					policyMap["service"] = serviceMap
				}
			}

			// ticketNumber (使用规则名称)
			if rule.name != "" {
				policyMap["ticketNumber"] = rule.name
			}

			if len(policyMap) > 0 {
				policies = append(policies, policyMap)
			}
		}
	}

	// 处理 Policy 规则
	if sangfor.policySet != nil {
		for _, policy := range sangfor.policySet.policySet {
			policyMap := make(map[string]interface{})

			// 从 policyEntry 提取信息
			if policy.policyEntry != nil {
				// source
				if srcNg := policy.policyEntry.Src(); srcNg != nil && !srcNg.IsEmpty() {
					policyMap["source"] = formatNetworkGroup(srcNg)
				}

				// destination
				if dstNg := policy.policyEntry.Dst(); dstNg != nil && !dstNg.IsEmpty() {
					policyMap["destination"] = formatNetworkGroup(dstNg)
				}

				// service
				if svc := policy.policyEntry.Service(); svc != nil && !svc.IsEmpty() {
					serviceMap := formatService(svc)
					if len(serviceMap) > 0 {
						policyMap["service"] = serviceMap
					}
				}
			}

			// 如果 policyEntry 为空或没有信息，尝试从策略的其他字段获取信息
			// 例如从 zones 或其他字段推断
			if len(policyMap) == 0 || (policyMap["source"] == nil && policyMap["destination"] == nil && policyMap["service"] == nil) {
				// 至少保存策略的基本信息
				if len(policy.srcZones) > 0 {
					policyMap["srcZones"] = policy.srcZones
				}
				if len(policy.dstZones) > 0 {
					policyMap["dstZones"] = policy.dstZones
				}
				if policy.name != "" {
					policyMap["name"] = policy.name
				}
			}

			// ticketNumber (使用 description 或 name)
			if policy.description != "" {
				policyMap["ticketNumber"] = policy.description
			} else if policy.name != "" {
				policyMap["ticketNumber"] = policy.name
			}

			// 至少保存 ticketNumber
			if len(policyMap) > 0 {
				policies = append(policies, policyMap)
			}
		}
	}

	// 保存到文件
	if len(policies) > 0 {
		// 创建输出目录
		outputDir := "sangfor_policies"
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Printf("创建输出目录失败: %v\n", err)
			return
		}

		// 生成文件名（使用设备名称或时间戳）
		fileName := "policies.yaml"
		if sangfor.DeviceNode != nil && sangfor.DeviceNode.Name() != "" {
			fileName = fmt.Sprintf("policies_%s.yaml", strings.ReplaceAll(sangfor.DeviceNode.Name(), "/", "_"))
		}

		filePath := filepath.Join(outputDir, fileName)

		// 转换为 YAML 格式（每个 policy 作为独立条目，用 --- 分隔）
		var yamlLines []string
		for _, policy := range policies {
			policyYAML, err := yaml.Marshal(policy)
			if err != nil {
				fmt.Printf("YAML 序列化单个策略失败: %v\n", err)
				continue
			}
			yamlLines = append(yamlLines, "policy:")
			// 添加缩进
			lines := strings.Split(string(policyYAML), "\n")
			for _, line := range lines {
				if line != "" {
					yamlLines = append(yamlLines, "  "+line)
				}
			}
			yamlLines = append(yamlLines, "") // 空行分隔
		}

		// 写入文件
		yamlContent := strings.Join(yamlLines, "\n")
		yamlBytes := []byte(yamlContent)

		if err := os.WriteFile(filePath, yamlBytes, 0644); err != nil {
			fmt.Printf("写入文件失败: %v\n", err)
			return
		}

		fmt.Printf("✓ 已保存 %d 个策略到文件: %s\n", len(policies), filePath)
	} else {
		fmt.Println("⚠ 没有找到可保存的策略")
	}
}

// formatNetworkGroup 将 NetworkGroup 格式化为字符串
func formatNetworkGroup(ng *network.NetworkGroup) string {
	if ng == nil || ng.IsEmpty() {
		return ""
	}

	var parts []string
	ng.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
		if ipNet, ok := item.(*network.IPNet); ok {
			// CIDR 格式
			parts = append(parts, ipNet.String())
		} else if ipRange, ok := item.(*network.IPRange); ok {
			// IP 范围格式
			parts = append(parts, fmt.Sprintf("%s-%s", ipRange.Start.String(), ipRange.End.String()))
		}
		return true
	})

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ",")
}

// formatService 将 Service 格式化为 map
func formatService(svc *service.Service) map[string]interface{} {
	if svc == nil || svc.IsEmpty() {
		return nil
	}

	var protocols []string
	var ports []string

	svc.EachDetailed(func(entry service.ServiceEntry) bool {
		if l4, ok := entry.(*service.L4Service); ok {
			protocol := strings.ToLower(l4.Protocol().String())
			protocols = append(protocols, protocol)

			if dstPort := l4.DstPort(); dstPort != nil && len(dstPort.L) > 0 {
				var portParts []string
				for _, portRange := range dstPort.L {
					if portRange.Low() == portRange.High() {
						portParts = append(portParts, fmt.Sprintf("%d", portRange.Low()))
					} else {
						portParts = append(portParts, fmt.Sprintf("%d-%d", portRange.Low(), portRange.High()))
					}
				}
				if len(portParts) > 0 {
					ports = append(ports, strings.Join(portParts, ","))
				}
			}
		} else if icmp, ok := entry.(*service.ICMPProto); ok {
			protocol := strings.ToLower(icmp.Protocol().String())
			protocols = append(protocols, protocol)
		}
		return true
	})

	if len(protocols) == 0 {
		return nil
	}

	// 去重协议
	protocolMap := make(map[string]bool)
	var uniqueProtocols []string
	for _, p := range protocols {
		if !protocolMap[p] {
			protocolMap[p] = true
			uniqueProtocols = append(uniqueProtocols, p)
		}
	}

	result := make(map[string]interface{})
	if len(uniqueProtocols) == 1 {
		result["protocol"] = uniqueProtocols[0]
	} else if len(uniqueProtocols) > 1 {
		result["protocol"] = strings.Join(uniqueProtocols, ",")
	}

	if len(ports) > 0 {
		// 合并所有端口
		allPorts := strings.Join(ports, ",")
		result["port"] = allPorts
	}

	return result
}

// formatServicePort 将 Service 格式化为端口字符串（用于 realPort）
func formatServicePort(svc *service.Service) string {
	if svc == nil || svc.IsEmpty() {
		return ""
	}

	var ports []string
	svc.EachDetailed(func(entry service.ServiceEntry) bool {
		if l4, ok := entry.(*service.L4Service); ok {
			if dstPort := l4.DstPort(); dstPort != nil && len(dstPort.L) > 0 {
				for _, portRange := range dstPort.L {
					if portRange.Low() == portRange.High() {
						ports = append(ports, fmt.Sprintf("%d", portRange.Low()))
					} else {
						ports = append(ports, fmt.Sprintf("%d-%d", portRange.Low(), portRange.High()))
					}
				}
			}
		}
		return true
	})

	if len(ports) == 0 {
		return ""
	}
	return strings.Join(ports, ",")
}
