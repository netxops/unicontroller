package main

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/jinzhu/copier"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

const (
	defaultArea = "Internet"
)

type Config struct {
	NodeMap struct {
		Name   string `yaml:"name"`
		Force  bool   `yaml:"force"`
		TaskID uint   `yaml:"task_id"`
	} `yaml:"nodemap"`
	Policy struct {
		Source       string `yaml:"source"`
		Destination  string `yaml:"destination"`
		RealIp       string `yaml:"realIp"`
		RealPort     string `yaml:"realPort"`
		TicketNumber string `yaml:"ticketNumber"`
		SubTicket    string `yaml:"subTicket"`
		Service      struct {
			Protocol string `yaml:"protocol"`
			Port     string `yaml:"port"`
		} `yaml:"service"`
		Snat string `yaml:"snat"`
	} `yaml:"policy"`
}

func loadConfig() (*Config, error) {
	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// func NewNodeMapFromNetwork(name string, deviceList []config.DeviceConfig, force bool, task_id uint, nodeMapId *uint, ctx context.Context) *NodeMap {
// func (nm *NodeMap) MakeTemplates(intent *policy.Intent) *TraverseProcess {

func initRedis() {
	client := redis.NewClient(&redis.Options{
		Addr:     "192.168.100.122:6379",
		Password: "Redis@Passw0rd",
		//Password: redisCfg.Password, // no password set
		DB: 0, // use default DB
	})
	global.Redis = client
}

func initLogger() *zap.Logger {
	return zap.NewNop()
}

type Device struct {
	config.DeviceConfig `yaml:",inline"`
	FilePath            string `yaml:"file_path"`
}

func initDeviceConfig() []config.DeviceConfig {
	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		panic(fmt.Sprintf("Error reading YAML file: %v", err))
	}

	var devicesConfig struct {
		ConfigFilePath string   `yaml:"config_file_path"`
		Devices        []Device `yaml:"devices"`
	}

	err = yaml.Unmarshal(yamlFile, &devicesConfig)
	if err != nil {
		panic(fmt.Sprintf("Error unmarshaling YAML: %v", err))
	}

	// 打印整个解析后的结构
	fmt.Printf("Parsed YAML: %+v", devicesConfig)

	var deviceConfigs []config.DeviceConfig

	for i, device := range devicesConfig.Devices {
		// 读取设备配置文件
		content, _ := ioutil.ReadFile(device.FilePath)
		// if err != nil {
		// 	fmt.Printf("Error reading file %s: %v\n", device.FilePath, err)
		// 	continue
		// }
		// 创建 DeviceConfig
		deviceConfig := device.DeviceConfig

		fmt.Printf("Device %d:\n", i+1)
		fmt.Printf("  Host: %s\n", device.Host)
		fmt.Printf("  Username: %s\n", device.Username)
		fmt.Printf("  Port: %d\n", device.Port)
		fmt.Printf("  Mode: %s\n", device.Mode)
		fmt.Printf("  Telnet: %v\n", device.Telnet)
		fmt.Printf("  Ipv4Area: %+v\n", device.Ipv4Area)

		if len(device.Ipv4Area) == 0 {
			fmt.Printf("  Warning: Ipv4Area is empty for device %s\n", device.Host)
		}

		copier.Copy(&deviceConfig, &device)
		deviceConfig.Config = string(content)
		deviceConfigs = append(deviceConfigs, deviceConfig)

	}

	return deviceConfigs
}

func mustService(serviceString string) *service.Service {
	s, err := service.NewServiceFromString(serviceString)
	if err != nil {
		panic(err)
	}
	return s
}

func setupNodeMap(logger *zap.Logger) {
	config, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	pe := policy.NewPolicyEntry()
	src, _ := network.NewNetworkGroupFromString(config.Policy.Source)
	dst, _ := network.NewNetworkGroupFromString(config.Policy.Destination)
	svs, _ := service.NewServiceWithL4(config.Policy.Service.Protocol, "", config.Policy.Service.Port)
	pe.AddSrc(src)
	pe.AddDst(dst)
	pe.AddService(svs)

	intent := policy.Intent{
		PolicyEntry:  *pe,
		Snat:         config.Policy.Snat,
		TicketNumber: config.Policy.TicketNumber,
		SubTicket:    config.Policy.SubTicket,
	}

	if config.Policy.RealIp != "" {
		intent.RealIp = config.Policy.RealIp
		intent.RealPort = config.Policy.RealPort
	}

	dcList := initDeviceConfig()
	nm, ctx := nodemap.NewNodeMapFromNetwork(config.NodeMap.Name, dcList, config.NodeMap.Force, config.NodeMap.TaskID, nil)
	fmt.Println(ctx)
	nm.WithLogger(logger)

	tp := nm.MakeTemplates(&intent, ctx)
	processErr := tp.Results.GetErr()
	if processErr.NotNil() {
		logger.Error("====Process error info: ", zap.Any("mark", processErr.GetMark()), zap.Any("desc", processErr.GetDesc()))
	}

	// 辅助函数：获取 map 的所有键
	getMapKeys := func(m map[string]interface{}) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		return keys
	}

	// 打印路由警告信息
	if len(tp.Warnings) > 0 {
		fmt.Println("====路由警告信息:")
		for warningIndex, warning := range tp.Warnings {
			// 确定警告类型的中文显示名称
			warningTypeName := warning.Type
			switch warning.Type {
			case model.WarningMultiRouteMatch:
				warningTypeName = "⚠️  多路由匹配"
			case model.WarningRouteQueryFailed:
				warningTypeName = "⚠️  路由查询失败"
			case model.WarningNextHopEmpty:
				warningTypeName = "⚠️  下一跳路由为空"
			case model.WarningRouteLoop:
				warningTypeName = "⚠️  路由环路"
			case model.WarningNextHopNotInNodeMap:
				warningTypeName = "⚠️  路由下一跳不在NodeMap中（配置/环境问题）"
			case model.WarningMissRoute:
				warningTypeName = "⚠️  路由缺失"
			}

			fmt.Printf("\n  [警告 %d] %s\n", warningIndex+1, warningTypeName)
			fmt.Printf("    消息: %s\n", warning.Message)
			fmt.Printf("    时间: %s\n", warning.Timestamp.Format("2006-01-02 15:04:05"))

			// 显示问题类型（如果是配置/环境问题）
			if issueType, ok := warning.Details["issue_type"].(string); ok {
				fmt.Printf("    问题类型: %s\n", issueType)
			}

			// 显示关键信息
			if node, ok := warning.Details["node"].(string); ok {
				fmt.Printf("    节点: %s\n", node)
			}
			if inPort, ok := warning.Details["in_port"].(string); ok {
				fmt.Printf("    入接口: %s\n", inPort)
			}
			if outPort, ok := warning.Details["out_interface"].(string); ok {
				fmt.Printf("    出接口: %s\n", outPort)
			}
			if nextHopIp, ok := warning.Details["next_hop_ip"].(string); ok {
				fmt.Printf("    下一跳IP: %s\n", nextHopIp)
			}
			if vrf, ok := warning.Details["vrf"].(string); ok {
				fmt.Printf("    VRF: %s\n", vrf)
			}
			if dstNet, ok := warning.Details["destination_network"].(string); ok {
				fmt.Printf("    目标网络: %s\n", dstNet)
			}

			// 如果是路由下一跳不在NodeMap中的警告，显示详细说明和建议
			if warning.Type == model.WarningNextHopNotInNodeMap {
				if description, ok := warning.Details["description"].(string); ok {
					fmt.Printf("\n    问题说明:\n")
					fmt.Printf("      %s\n", description)
				}
				if suggestions, ok := warning.Details["suggestions"].([]string); ok && len(suggestions) > 0 {
					fmt.Printf("\n    解决建议:\n")
					for i, suggestion := range suggestions {
						fmt.Printf("      %d. %s\n", i+1, suggestion)
					}
				} else if suggestions, ok := warning.Details["suggestions"].([]interface{}); ok && len(suggestions) > 0 {
					fmt.Printf("\n    解决建议:\n")
					for i, suggestion := range suggestions {
						if suggestionStr, ok := suggestion.(string); ok {
							fmt.Printf("      %d. %s\n", i+1, suggestionStr)
						}
					}
				}
			}

			// 如果是多路由匹配，详细显示所有匹配的路由
			if warning.Type == model.WarningMultiRouteMatch {
				fmt.Printf("    问题: 目标网络匹配到多条不同的路由，无法确定唯一路径\n")

				// 检查是否有匹配的路由详情
				// 尝试多种类型断言，因为数据可能经过序列化/反序列化
				var matchedRoutes []interface{}
				var hasMatchedRoutes bool

				// 尝试直接断言为 []interface{}
				if routes, ok := warning.Details["matched_routes"].([]interface{}); ok {
					matchedRoutes = routes
					hasMatchedRoutes = true
				} else if routes, ok := warning.Details["matched_routes"].([]map[string]interface{}); ok {
					// 如果是 []map[string]interface{}，转换为 []interface{}
					matchedRoutes = make([]interface{}, len(routes))
					for i, r := range routes {
						matchedRoutes[i] = r
					}
					hasMatchedRoutes = true
				} else if routesRaw, exists := warning.Details["matched_routes"]; exists {
					// 尝试通过反射处理
					if routesSlice, ok := routesRaw.([]interface{}); ok {
						matchedRoutes = routesSlice
						hasMatchedRoutes = true
					} else {
						// 打印调试信息
						fmt.Printf("    ⚠️  调试: matched_routes 类型为 %T, 值: %v\n", routesRaw, routesRaw)
					}
				}

				if hasMatchedRoutes && len(matchedRoutes) > 0 {
					fmt.Printf("    匹配到的路由详情 (%d 条):\n", len(matchedRoutes))
					for routeIndex, route := range matchedRoutes {
						if routeMap, ok := route.(map[string]interface{}); ok {
							fmt.Printf("      路由 %d:\n", routeIndex+1)
							if iface, ok := routeMap["interface"].(string); ok {
								fmt.Printf("        出接口: %s\n", iface)
							} else if iface, ok := routeMap["interface"]; ok {
								fmt.Printf("        出接口: %v\n", iface)
							}
							if ip, ok := routeMap["ip"].(string); ok {
								fmt.Printf("        下一跳IP: %s\n", ip)
							} else if ip, ok := routeMap["ip"]; ok {
								fmt.Printf("        下一跳IP: %v\n", ip)
							}
							if connected, ok := routeMap["connected"].(bool); ok {
								connectedStr := "否"
								if connected {
									connectedStr = "是"
								}
								fmt.Printf("        直连路由: %s\n", connectedStr)
							} else if connected, ok := routeMap["connected"]; ok {
								fmt.Printf("        直连路由: %v\n", connected)
							}
						} else {
							// 如果类型断言失败，打印原始值
							fmt.Printf("      路由 %d: %v (类型: %T)\n", routeIndex+1, route, route)
						}
					}
				} else {
					// 如果没有匹配的路由详情，尝试显示其他可用信息
					if errorDetails, ok := warning.Details["error_details"].(string); ok {
						fmt.Printf("    错误详情: %s\n", errorDetails)
					}
					// 打印调试信息以帮助诊断问题
					fmt.Printf("    ⚠️  调试信息:\n")
					fmt.Printf("      警告详情键: %v\n", getMapKeys(warning.Details))
					if matchedRoutesRaw, exists := warning.Details["matched_routes"]; exists {
						fmt.Printf("      matched_routes 存在，类型: %T\n", matchedRoutesRaw)
						// 尝试打印前几个元素以便调试
						if routesSlice, ok := matchedRoutesRaw.([]interface{}); ok {
							fmt.Printf("      matched_routes 是 []interface{}，长度: %d\n", len(routesSlice))
							if len(routesSlice) > 0 {
								fmt.Printf("      第一个元素类型: %T, 值: %v\n", routesSlice[0], routesSlice[0])
							}
						} else {
							fmt.Printf("      matched_routes 值: %v\n", matchedRoutesRaw)
						}
					} else {
						fmt.Printf("      matched_routes 不存在于 Details 中\n")
						// 打印所有 Details 的键和类型
						fmt.Printf("      所有 Details 键和类型:\n")
						for k, v := range warning.Details {
							fmt.Printf("        %s: %T = %v\n", k, v, v)
						}
					}
				}

				// 显示匹配路由数量（去重后）
				var routeCount int
				if rc, ok := warning.Details["route_count"].(int); ok {
					routeCount = rc
					fmt.Printf("    匹配路由数量（去重后）: %d\n", routeCount)
				} else if rc, ok := warning.Details["route_count"].(int64); ok {
					routeCount = int(rc)
					fmt.Printf("    匹配路由数量（去重后）: %d\n", routeCount)
				} else if rc, ok := warning.Details["route_count"].(float64); ok {
					routeCount = int(rc)
					fmt.Printf("    匹配路由数量（去重后）: %d\n", routeCount)
				}

				// 显示原始匹配数量（去重前，如果有的话）
				if rawRouteCount, ok := warning.Details["raw_route_count"].(int); ok {
					if rawRouteCount > routeCount {
						fmt.Printf("    原始匹配数量（去重前）: %d\n", rawRouteCount)
					}
				} else if rawRouteCount, ok := warning.Details["raw_route_count"].(int64); ok {
					if int(rawRouteCount) > routeCount {
						fmt.Printf("    原始匹配数量（去重前）: %d\n", int(rawRouteCount))
					}
				} else if rawRouteCount, ok := warning.Details["raw_route_count"].(float64); ok {
					if int(rawRouteCount) > routeCount {
						fmt.Printf("    原始匹配数量（去重前）: %d\n", int(rawRouteCount))
					}
				}
			} else {
				// 其他类型的警告，显示错误详情
				if errorDetails, ok := warning.Details["error_details"].(string); ok {
					fmt.Printf("    错误详情: %s\n", errorDetails)
				}
				// 检查是否在错误详情中提到了多路由匹配
				if errorDetails, ok := warning.Details["error_details"].(string); ok {
					if strings.Contains(errorDetails, "多路由") || strings.Contains(errorDetails, "multiple match route") {
						fmt.Printf("    ⚠️  注意: 此警告实际上是由于多路由匹配导致的\n")
					}
				}
			}

			// 显示其他详情信息（如果有）
			otherDetails := make(map[string]interface{})
			for k, v := range warning.Details {
				if k != "node" && k != "in_port" && k != "vrf" && k != "destination_network" &&
					k != "matched_routes" && k != "route_count" && k != "raw_route_count" && k != "error_details" {
					otherDetails[k] = v
				}
			}
			if len(otherDetails) > 0 {
				fmt.Printf("    其他信息: %v\n", otherDetails)
			}
		}
		fmt.Println()
	}

	// 打印路由跟踪信息
	if tp.RouteTracer != nil {
		logger.Info("====路由跟踪信息:")

		// 打印路由跳信息
		routeHops := tp.GetRouteHops()
		if len(routeHops) > 0 {
			fmt.Printf("  路由跳信息:\n")
			for i, hop := range routeHops {
				if hop.OutPort != "" {
					fmt.Printf("    跳 %d: [入接口: %s, 节点: %s, 出接口: %s]\n", i+1, hop.InPort, hop.Node, hop.OutPort)
				} else {
					fmt.Printf("    跳 %d: [入接口: %s, 节点: %s]\n", i+1, hop.InPort, hop.Node)
				}
			}
		} else {
			fmt.Printf("  路由跳信息: 无\n")
		}

		// 打印路由决策信息
		decisions := tp.GetRouteDecisions()
		if len(decisions) > 0 {
			fmt.Printf("  路由决策信息:\n")
			for i, decision := range decisions {
				fmt.Printf("    决策 %d: %s\n", i+1, decision.DecisionType)
				fmt.Printf("      节点: %s, 端口: %s, VRF: %s\n", decision.Node, decision.Port, decision.VRF)
				fmt.Printf("      结果: %s, 原因: %s\n", decision.Result, decision.Reason)
				if decision.Area != "" {
					fmt.Printf("      区域: %s\n", decision.Area)
				}
				if len(decision.Criteria) > 0 {
					fmt.Printf("      决策依据: %v\n", decision.Criteria)
				}
			}
		} else {
			fmt.Printf("  路由决策信息: 无\n")
		}

		// 打印退出信息
		exitInfo := tp.RouteTracer.GetExitInfo()
		if exitInfo != nil {
			fmt.Printf("  退出信息:\n")
			fmt.Printf("    原因: %s\n", exitInfo.Reason)
			fmt.Printf("    节点: %s, 端口: %s, VRF: %s\n", exitInfo.Node, exitInfo.Port, exitInfo.VRF)
			fmt.Printf("    成功: %v\n", exitInfo.Success)
			if exitInfo.ErrorMsg != "" {
				fmt.Printf("    错误消息: %s\n", exitInfo.ErrorMsg)
			}
			if len(exitInfo.Details) > 0 {
				fmt.Printf("    详情: %v\n", exitInfo.Details)
			}
		}

		// 打印路由路径
		routePath := tp.GetRoutePathString()
		if routePath != "[]" && routePath != "" {
			fmt.Printf("  路由路径: %s\n", routePath)
		}

		fmt.Println()
	}

	// 打印 TraverseResult 中的 ProcessStep 信息
	fmt.Println("\n====配置命令行信息:")
	for itemIndex, item := range tp.Results.Items {
		// 打印节点信息
		fmt.Printf("\n[节点 %d] %s (类型: %d)\n", itemIndex+1, item.Node.CmdIp(), int(item.Node.NodeType()))

		// 从 CmdListList 中提取配置信息
		if len(item.CmdListList) > 0 {
			fmt.Printf("  📝 生成的配置命令列表 (%d 条):\n", len(item.CmdListList))
			for i, cmdList := range item.CmdListList {
				fmt.Printf("    [命令列表 %d]\n", i+1)

				// 使用类型断言来提取命令
				extractCommands := func(cmdList interface{}) {
					// 首先尝试转换为 *command.CliCmdList
					if cliCmdList, ok := cmdList.(*command.CliCmdList); ok {
						fmt.Printf("      目标IP: %s, Force: %v\n", cliCmdList.Ip, cliCmdList.Force)
						// 使用 Table() 方法获取命令列表
						for _, cmd := range cliCmdList.Cmds {
							fmt.Printf("      命令: %v\n", cmd.Cmd())
						}
					} else {
						// 打印原始类型和值用于调试
						fmt.Printf("      [调试] 命令列表类型: %T, 值: %+v\n", cmdList, cmdList)
					}
				}

				extractCommands(cmdList)
			}
		}

		// 打印 AdditionCli
		if len(item.AdditionCli) > 0 {
			fmt.Printf("  📋 附加命令行 (%d 条):\n", len(item.AdditionCli))
			for i, cli := range item.AdditionCli {
				fmt.Printf("    [附加命令 %d]: %s\n", i+1, cli)
			}
		}

		if item.StepProcess == nil {
			fmt.Printf("  ℹ️  该节点没有 ProcessStep 信息\n")
			continue
		}

		// 分别收集匹配的配置和新生成的配置
		var matchedConfigs []struct {
			stepName string
			step     *processor.ProcessStep
		}
		var generatedConfigs []struct {
			stepName string
			step     *processor.ProcessStep
		}

		// 遍历 StepProcess 中的所有 ProcessStep，分类收集
		iterator := item.StepProcess.Iterator()
		fmt.Printf("  [调试] 开始遍历 ProcessStep...\n")
		for iterator.HasNext() {
			stepName, step := iterator.Next()
			if step == nil {
				fmt.Printf("  [调试] stepName=%s, step=nil (跳过)\n", stepName)
				continue
			}

			phaseAction := step.GetPhaseAction()
			phaseActionStr := "UNKNOWN"
			switch phaseAction {
			case processor.PHASE_MATCHED:
				phaseActionStr = "PHASE_MATCHED"
			case processor.PHASE_GENERATED:
				phaseActionStr = "PHASE_GENERATED"
			default:
				phaseActionStr = fmt.Sprintf("UNKNOWN(%d)", int(phaseAction))
			}
			hasCli := step.GetCli() != ""
			hasCmdList := step.GetCmdList() != nil
			fmt.Printf("  [调试] stepName=%s, phaseAction=%s (值=%d), hasCli=%v, hasCmdList=%v\n",
				stepName, phaseActionStr, int(phaseAction), hasCli, hasCmdList)

			// 特殊处理：如果 phaseAction 未设置（为0），根据 stepName 和实际情况判断
			shouldTreatAsGenerated := false
			shouldTreatAsMatched := false

			if phaseAction == 0 {
				// INPUT_POLICY 如果未设置 phaseAction，通常是因为匹配到策略后仍然生成了配置
				// 从日志看，即使匹配到策略，也可能需要生成配置（比如策略不完整）
				// 如果有 CmdList 或 CLI，说明是生成的配置
				if stepName == "INPUT_POLICY" {
					if hasCmdList || hasCli {
						shouldTreatAsGenerated = true
						fmt.Printf("  [调试] INPUT_POLICY phaseAction未设置但hasCmdList或hasCli=true，视为生成配置\n")
					} else {
						// 如果没有 CmdList 和 CLI，但匹配到了策略，视为匹配
						// 这里我们需要检查是否有匹配结果
						if step.GetResult() != nil && step.GetResult().Action() == 2 { // POLICY_PERMIT
							shouldTreatAsMatched = true
							fmt.Printf("  [调试] INPUT_POLICY phaseAction未设置但匹配到PERMIT策略，视为匹配配置\n")
						}
					}
				}
			}

			switch {
			case phaseAction == processor.PHASE_MATCHED || shouldTreatAsMatched:
				matchedConfigs = append(matchedConfigs, struct {
					stepName string
					step     *processor.ProcessStep
				}{stepName: stepName, step: step})
			case phaseAction == processor.PHASE_GENERATED || shouldTreatAsGenerated:
				generatedConfigs = append(generatedConfigs, struct {
					stepName string
					step     *processor.ProcessStep
				}{stepName: stepName, step: step})
			default:
				// 如果既不是匹配也不是生成，但仍然有结果，也显示出来（可能是其他状态）
				if step.GetResult() != nil {
					fmt.Printf("  [调试] stepName=%s 有结果但phaseAction未设置，添加到生成配置列表\n", stepName)
					generatedConfigs = append(generatedConfigs, struct {
						stepName string
						step     *processor.ProcessStep
					}{stepName: stepName, step: step})
				}
			}
		}
		fmt.Printf("  [调试] 收集完成: 匹配配置=%d条, 生成配置=%d条\n", len(matchedConfigs), len(generatedConfigs))

		// 打印节点信息
		fmt.Printf("\n[节点 %d] %s (类型: %d)\n", itemIndex+1, item.Node.CmdIp(), int(item.Node.NodeType()))

		// 辅助函数：获取接口名称
		getPortName := func(port api.Port) string {
			if port == nil {
				return "N/A"
			}
			return port.Name()
		}

		// 辅助函数：获取动作名称
		getActionName := func(action int) string {
			switch action {
			case 1:
				return "POLICY_DENY"
			case 2:
				return "POLICY_PERMIT"
			case 3:
				return "POLICY_REJECT"
			case 4:
				return "POLICY_IMPLICIT_PERMIT"
			case 5:
				return "POLICY_IMPLICIT_DENY"
			case 6:
				return "NAT_MATCHED"
			case 7:
				return "NAT_NOMATCHED"
			default:
				return fmt.Sprintf("UNKNOWN(%d)", action)
			}
		}

		// 打印匹配的配置命令行
		if len(matchedConfigs) > 0 {
			fmt.Printf("  📋 匹配到的配置 (%d 条):\n", len(matchedConfigs))
			for i, matched := range matchedConfigs {
				fmt.Printf("    [匹配配置 %d] %s\n", i+1, matched.stepName)
				if matched.step.GetResult() != nil {
					result := matched.step.GetResult()
					policyName := result.Name()
					if policyName == "" {
						policyName = "N/A"
					}
					fmt.Printf("      策略名称: %s\n", policyName)
					fmt.Printf("      入接口: %s, 出接口: %s\n", getPortName(result.FromPort()), getPortName(result.OutPort()))
					fmt.Printf("      动作: %s (%d)\n", getActionName(result.Action()), result.Action())
				}
				cli := matched.step.GetCli()
				if cli != "" {
					fmt.Printf("      命令行:\n")
					cliLines := strings.Split(cli, "\n")
					for _, line := range cliLines {
						if strings.TrimSpace(line) != "" {
							fmt.Printf("        %s\n", line)
						}
					}
				} else {
					fmt.Printf("      命令行: (无)\n")
				}
				fmt.Println()
			}
		}

		// 打印新生成的配置命令行
		if len(generatedConfigs) > 0 {
			fmt.Printf("  ✨ 新生成的配置 (%d 条):\n", len(generatedConfigs))
			for i, generated := range generatedConfigs {
				fmt.Printf("    [生成配置 %d] %s\n", i+1, generated.stepName)
				if generated.step.GetResult() != nil {
					result := generated.step.GetResult()
					policyName := result.Name()
					if policyName == "" {
						policyName = "N/A"
					}
					fmt.Printf("      策略名称: %s\n", policyName)
					fmt.Printf("      入接口: %s, 出接口: %s\n", getPortName(result.FromPort()), getPortName(result.OutPort()))
					fmt.Printf("      动作: %s (%d)\n", getActionName(result.Action()), result.Action())
				}
				cli := generated.step.GetCli()
				if cli != "" {
					fmt.Printf("      命令行:\n")
					cliLines := strings.Split(cli, "\n")
					for _, line := range cliLines {
						if strings.TrimSpace(line) != "" {
							fmt.Printf("        %s\n", line)
						}
					}
				} else {
					fmt.Printf("      命令行: (无)\n")
				}
				fmt.Println()
			}
		}

		// 如果没有匹配也没有生成，打印提示
		if len(matchedConfigs) == 0 && len(generatedConfigs) == 0 {
			fmt.Printf("  ℹ️  该节点没有匹配或生成的配置\n")
		}
	}
	fmt.Println()

}

func main() {
	// 初始化 Redis 和 Logger
	initRedis()
	logger := initLogger()

	// // 定义命令行参数
	// ipRanges := flag.String("ip", "", "IP addresses or CIDRs to match in source or destination (can be specified multiple times)")
	// protocol := flag.String("proto", "", "Protocol (tcp, udp, icmp)")
	// port := flag.String("port", "", "Port number or range")
	// action := flag.String("action", "", "Action (permit, deny, reject, implicit_permit, implicit_deny, nat_matched, nat_nomatched)")
	// matchStrategy := flag.String("strategy", "overlap", "Match strategy (overlap, contains, containedby, exact, threshold, overlapignoreany)")
	// threshold := flag.Float64("threshold", 0.0, "Threshold for overlap strategy (0.0 to 1.0)")
	// matchType := flag.String("match", "both", "Match type: src (source only), dst (destination only), or both (default)")
	// policyName := flag.String("name", "", "Policy name to match")

	// // outputFile := flag.String("output", "", "Output file path for matched policies")
	// outputFile := flag.String("output", "matched_policies", "Output file path prefix for matched policies (without extension)")

	// // 解析命令行参数
	// flag.Parse()

	// // 验证必要的参数
	// if *ipRanges == "" {
	// 	fmt.Println("IP ranges must be specified")
	// 	flag.PrintDefaults()
	// 	os.Exit(1)
	// }

	// 创建匹配器
	// 设置 NodeMap 并执行查询
	setupNodeMap(logger)
}
