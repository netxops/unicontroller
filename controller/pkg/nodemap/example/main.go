package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
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
		content, err := ioutil.ReadFile(device.FilePath)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", device.FilePath, err)
			continue
		}
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

// func setupNodeMap(logger *zap.Logger, matcher nodemap.PolicyMatcher, outputFile string) {
// 	config, err := loadConfig()
// 	if err != nil {
// 		logger.Fatal("Failed to load config", zap.Error(err))
// 	}

// 	pe := policy.NewPolicyEntry()
// 	src, _ := network.NewNetworkGroupFromString(config.Policy.Source)
// 	dst, _ := network.NewNetworkGroupFromString(config.Policy.Destination)
// 	svs, _ := service.NewServiceWithL4(config.Policy.Service.Protocol, "", config.Policy.Service.Port)
// 	pe.AddSrc(src)
// 	pe.AddDst(dst)
// 	pe.AddService(svs)

// 	intent := policy.Intent{
// 		PolicyEntry:  *pe,
// 		Snat:         config.Policy.Snat,
// 		TicketNumber: config.Policy.TicketNumber,
// 		SubTicket:    config.Policy.SubTicket,
// 	}

// 	if config.Policy.RealIp != "" {
// 		intent.RealIp = config.Policy.RealIp
// 		intent.RealPort = config.Policy.RealPort
// 	}

// 	dcList := initDeviceConfig()
// 	nm := nodemap.NewNodeMapFromNetwork(config.NodeMap.Name, dcList, config.NodeMap.Force, config.NodeMap.TaskID, nil, context.Background())
// 	nm.WithLogger(logger)

// 	var output *os.File
// 	if outputFile != "" {
// 		output, err = os.Create(outputFile)
// 		if err != nil {
// 			logger.Error("Failed to create output file", zap.Error(err))
// 			return
// 		}
// 		defer output.Close()
// 	}

// 	// 获取匹配的策略
// 	// matchedPolicies := nm.Policies(compositeMatcher)
// 	matchedPolicies := nm.Policies(matcher)

// 	totalPolicies := 0
// 	for device, policies := range matchedPolicies {
// 		logger.Info("Matched policies for device", zap.String("device", device), zap.Int("count", len(policies)))
// 		if output != nil {
// 			fmt.Fprintf(output, "Matched policies for device %s (count: %d)\n", device, len(policies))
// 		}

// 		for i, policyResult := range policies {
// 			policy := policyResult.Policy
// 			logInfo := fmt.Sprintf("  Policy %d:", i+1)
// 			logFields := []zap.Field{
// 				zap.String("Name", policy.Name()),
// 				zap.String("Action", policy.Action().String()),
// 				zap.String("Source", policy.PolicyEntry().Src().String()),
// 				zap.String("Destination", policy.PolicyEntry().Dst().String()),
// 				zap.String("Service", policy.PolicyEntry().Service().String()),
// 				zap.String("CLI", policy.Cli()),
// 			}
// 			logger.Info(logInfo, logFields...)

// 			if output != nil {
// 				fmt.Fprintf(output, "%s\n", logInfo)
// 				fmt.Fprintf(output, "    Name: %s\n", policy.Name())
// 				fmt.Fprintf(output, "    Action: %s\n", policy.Action().String())
// 				fmt.Fprintf(output, "    Source: %s\n", policy.PolicyEntry().Src().String())
// 				fmt.Fprintf(output, "    Destination: %s\n", policy.PolicyEntry().Dst().String())
// 				fmt.Fprintf(output, "    Service: %s\n", policy.PolicyEntry().Service().String())
// 				fmt.Fprintf(output, "    CLI: %s\n", policy.Cli())
// 			}

// 			for matcherName, detail := range policyResult.MatchDetails {
// 				matcherInfo := fmt.Sprintf("    Matcher: %s", matcherName)
// 				matcherFields := []zap.Field{
// 					zap.Bool("Matched", detail.Matched),
// 					zap.String("Type", detail.MatcherType),
// 					zap.String("Value", detail.MatcherValue),
// 					zap.Float64("OverlapDetail", detail.OverlapDetail),
// 					zap.Bool("IsSourceMatch", detail.IsSourceMatch),
// 					zap.Any("ExtraInfo", detail.ExtraInfo),
// 				}
// 				logger.Info(matcherInfo, matcherFields...)

// 				// if output != nil {
// 				// 	fmt.Fprintf(output, "%s\n", matcherInfo)
// 				// 	fmt.Fprintf(output, "      Matched: %v\n", detail.Matched)
// 				// 	fmt.Fprintf(output, "      Type: %s\n", detail.MatcherType)
// 				// 	fmt.Fprintf(output, "      Value: %s\n", detail.MatcherValue)
// 				// 	fmt.Fprintf(output, "      OverlapDetail: %f\n", detail.OverlapDetail)
// 				// 	fmt.Fprintf(output, "      IsSourceMatch: %v\n", detail.IsSourceMatch)
// 				// 	fmt.Fprintf(output, "      ExtraInfo: %v\n", detail.ExtraInfo)
// 				// }
// 			}

// 			if output != nil {
// 				fmt.Fprintln(output) // Add a blank line between policies
// 			}
// 		}
// 		totalPolicies += len(policies)
// 	}

// 	logger.Info("Total matched policies", zap.Int("count", totalPolicies))
// 	if output != nil {
// 		fmt.Fprintf(output, "Total matched policies: %d\n", totalPolicies)
// 	}

// 	// fmt.Println(nm)
// 	// polices := nm.Policies()
// 	// fmt.Println(polices)

// 	// fmt.Println(intent)
// 	// tp := nm.MakeTemplates(&intent)
// 	// processErr := tp.Results.GetErr()
// 	// if processErr.NotNil() {
// 	// 	logger.Error("====Process error info: ", zap.Any("mark", processErr.GetMark()), zap.Any("desc", processErr.GetDesc()))
// 	// }

// 	// fmt.Println(tp)
// }

func setupNodeMap(logger *zap.Logger, matcher nodemap.PolicyMatcher, outputFile string) {
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

	// 获取匹配的策略
	matchedPolicies := nm.Policies("123", matcher)

	totalPolicies := 0
	for device, policies := range matchedPolicies {
		logger.Info("Matched policies for device", zap.String("device", device), zap.Int("count", len(policies)))
		totalPolicies += len(policies)
	}

	logger.Info("Total matched policies", zap.Int("count", totalPolicies))

	frontendData := PreparePolicyDataForFrontend(matchedPolicies)

	// 将数据转换为JSON
	jsonData, err := json.MarshalIndent(frontendData, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal policy data to JSON", zap.Error(err))
	} else {
		// 将JSON数据写入文件或发送到前端
		err = ioutil.WriteFile(outputFile+".json", jsonData, 0644)
		if err != nil {
			logger.Error("Failed to write JSON data to file", zap.Error(err))
		} else {
			logger.Info("JSON data file generated successfully", zap.String("file", outputFile+".json"))
		}
	}

	// 生成Excel文件
	// excelFile := outputFile + ".xlsx"
	// err = writeToExcel(matchedPolicies, excelFile)
	// if err != nil {
	// 	logger.Error("Failed to write Excel file", zap.Error(err))
	// } else {
	// 	logger.Info("Excel file generated successfully", zap.String("file", excelFile))
	// }

	// // 生成文本日志文件
	// textFile := outputFile + ".log"
	// logFile, err := os.Create(textFile)
	// if err != nil {
	// 	logger.Error("Failed to create log file", zap.Error(err))
	// } else {
	// 	defer logFile.Close()

	// 	for device, policies := range matchedPolicies {
	// 		fmt.Fprintf(logFile, "Matched policies for device %s (count: %d)\n", device, len(policies))

	// 		for i, policyResult := range policies {
	// 			policy := policyResult.Policy
	// 			fmt.Fprintf(logFile, "  Policy %d:\n", i+1)
	// 			fmt.Fprintf(logFile, "    Name: %s\n", policy.Name())
	// 			fmt.Fprintf(logFile, "    Action: %s\n", policy.Action().String())
	// 			fmt.Fprintf(logFile, "    Source: %s\n", policy.PolicyEntry().Src().String())
	// 			fmt.Fprintf(logFile, "    Destination: %s\n", policy.PolicyEntry().Dst().String())
	// 			fmt.Fprintf(logFile, "    Service: %s\n", policy.PolicyEntry().Service().String())
	// 			fmt.Fprintf(logFile, "    CLI: %s\n", policy.Cli())
	// 			fmt.Fprintf(logFile, "    Matched Address: %s\n", tools.ConditionalT(policyResult.MatchedAddress == nil, "", policyResult.MatchedAddress.String()))

	// 			for matcherName, detail := range policyResult.MatchDetails {
	// 				fmt.Fprintf(logFile, "    Matcher: %s\n", matcherName)
	// 				fmt.Fprintf(logFile, "      Matched: %v\n", detail.Matched)
	// 				fmt.Fprintf(logFile, "      Type: %s\n", detail.MatcherType)
	// 				fmt.Fprintf(logFile, "      Value: %s\n", detail.MatcherValue)
	// 				fmt.Fprintf(logFile, "      OverlapDetail: %f\n", detail.OverlapDetail)
	// 				fmt.Fprintf(logFile, "      MatchType: %v\n", detail.MatchType)
	// 				fmt.Fprintf(logFile, "      ExtraInfo: %v\n", detail.ExtraInfo)
	// 			}

	// 			fmt.Fprintln(logFile) // Add a blank line between policies
	// 		}
	// 	}

	// 	fmt.Fprintf(logFile, "Total matched policies: %d\n", totalPolicies)
	// 	logger.Info("Log file generated successfully", zap.String("file", textFile))
	// }
}

func main() {
	// 初始化 Redis 和 Logger
	initRedis()
	logger := initLogger()

	// 定义命令行参数
	ipRanges := flag.String("ip", "", "IP addresses or CIDRs to match in source or destination (can be specified multiple times)")
	protocol := flag.String("proto", "", "Protocol (tcp, udp, icmp)")
	port := flag.String("port", "", "Port number or range")
	action := flag.String("action", "", "Action (permit, deny, reject, implicit_permit, implicit_deny, nat_matched, nat_nomatched)")
	matchStrategy := flag.String("strategy", "overlap", "Match strategy (overlap, contains, containedby, exact, threshold, overlapignoreany)")
	threshold := flag.Float64("threshold", 0.0, "Threshold for overlap strategy (0.0 to 1.0)")
	matchType := flag.String("match", "both", "Match type: src (source only), dst (destination only), or both (default)")
	policyName := flag.String("name", "", "Policy name to match")

	// outputFile := flag.String("output", "", "Output file path for matched policies")
	outputFile := flag.String("output", "matched_policies", "Output file path prefix for matched policies (without extension)")

	// 解析命令行参数
	flag.Parse()

	// 验证必要的参数
	if *ipRanges == "" {
		fmt.Println("IP ranges must be specified")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 创建匹配器
	var matchers []nodemap.PolicyMatcher

	// 处理 IP 范围
	ipRangesList := getIPRanges()
	if len(ipRangesList) == 0 {
		fmt.Println("At least one IP range must be specified")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var ipMatchers []nodemap.PolicyMatcher
	for _, ipRange := range ipRangesList {
		matcher := createIPMatchers(ipRange, *matchStrategy, *matchType, *threshold)
		ipMatchers = append(ipMatchers, matcher)
	}
	if len(ipMatchers) > 0 {
		matchers = append(matchers, nodemap.OrMatcher{Matchers: ipMatchers})
	}

	// 处理协议和端口
	if *protocol != "" || *port != "" {
		serviceStr := fmt.Sprintf("%s:%s", *protocol, *port)
		matchers = append(matchers, nodemap.ServiceMatcher{Service: mustService(serviceStr)})
	}

	// 处理动作
	if *action != "" {
		actionMatcher := createActionMatcher(*action)
		if actionMatcher != nil {
			matchers = append(matchers, actionMatcher)
		}
	}

	// 处理策略名
	if *policyName != "" {
		matchers = append(matchers, nodemap.NameMatcher{Name: *policyName})
	}

	// 组合所有匹配器
	compositeMatcher := nodemap.CompositeMatcher{Matchers: matchers}

	// 设置 NodeMap 并执行查询
	setupNodeMap(logger, compositeMatcher, *outputFile)
}

// 创建 IP 匹配器
func createIPMatchers(ips, strategy, matchType string, threshold float64) nodemap.PolicyMatcher {
	var matchers []nodemap.PolicyMatcher
	for _, ip := range strings.Split(ips, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			switch matchType {
			case "src":
				matchers = append(matchers, nodemap.NewAddressMatcher(ip, getMatchStrategy(strategy), true, threshold))
			case "dst":
				matchers = append(matchers, nodemap.NewAddressMatcher(ip, getMatchStrategy(strategy), false, threshold))
			default: // "both"
				srcMatcher := nodemap.NewAddressMatcher(ip, getMatchStrategy(strategy), true, threshold)
				dstMatcher := nodemap.NewAddressMatcher(ip, getMatchStrategy(strategy), false, threshold)
				matchers = append(matchers, nodemap.OrMatcher{Matchers: []nodemap.PolicyMatcher{srcMatcher, dstMatcher}})
			}
		}
	}
	return nodemap.OrMatcher{Matchers: matchers}
}

func getMatchStrategy(strategy string) nodemap.MatchStrategy {
	switch strategy {
	case "overlap":
		return nodemap.StrategyOverlap
	case "contains":
		return nodemap.StrategyContains
	case "containedby":
		return nodemap.StrategyContainedBy
	case "exact":
		return nodemap.StrategyExactMatch
	case "threshold":
		return nodemap.StrategyThreshold
	case "overlapignoreany":
		return nodemap.StrategyOverlapIgnoreAny
	default:
		return nodemap.StrategyOverlap
	}
}

func createActionMatcher(actionStr string) nodemap.PolicyMatcher {
	var action firewall.Action
	switch strings.ToLower(actionStr) {
	case "deny":
		action = firewall.POLICY_DENY
	case "permit":
		action = firewall.POLICY_PERMIT
	case "reject":
		action = firewall.POLICY_REJECT
	case "implicit_permit":
		action = firewall.POLICY_IMPLICIT_PERMIT
	case "implicit_deny":
		action = firewall.POLICY_IMPLICIT_DENY
	case "nat_matched":
		action = firewall.NAT_MATCHED
	case "nat_nomatched":
		action = firewall.NAT_NOMATCHED
	default:
		fmt.Printf("Invalid action: %s. Using default (no action filter).\n", actionStr)
		return nil
	}
	return nodemap.ActionMatcher{Action: action}
}

func getIPRanges() []string {
	var ipRanges []string
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "ip" {
			ipRanges = append(ipRanges, f.Value.String())
		}
	})
	return ipRanges
}

// func writeToExcel(matchedPolicies
func writeToExcel(matchedPolicies map[string][]nodemap.PolicyMatchResult, outputFile string) error {
	f := excelize.NewFile()

	// 创建一个自动换行的样式
	wrapStyle, err := f.NewStyle(`{"alignment":{"wrap_text":true}}`)
	if err != nil {
		return err
	}

	for device, policies := range matchedPolicies {
		sheetName := device
		f.NewSheet(sheetName)

		// 设置表头
		// headers := []string{"CLI", "方向", "Object CLI", "Rule Name", "Action", "Source", "Destination", "Service"}
		headers := []string{"CLI", "方向", "Object CLI", "Rule Name", "Action", "Source", "Destination", "Service", "Matched Address"}

		for i, header := range headers {
			cell := fmt.Sprintf("%s1", string(rune('A'+i)))
			f.SetCellValue(sheetName, cell, header)
		}

		row := 2
		for _, policyResult := range policies {
			policy := policyResult.Policy
			m := policy.Extended()

			// 分行打印CLI
			cliLines := strings.Split(policy.Cli(), "\n")
			for i, line := range cliLines {
				f.SetCellValue(sheetName, fmt.Sprintf("A%d", row+i), line)

				// 检查是否包含 source-ip 或 destination-ip
				if strings.Contains(line, "source-ip") || strings.Contains(line, "destination-ip") || strings.Index(strings.TrimSpace(line), "service ") == 0 {
					objectName := strings.Fields(line)[len(strings.Fields(line))-1]
					var objectCli string

					if strings.Contains(line, "source-ip") {
						if srcObjects, ok := m["SrcObject"].([]string); ok {
							for _, src := range srcObjects {
								if src == objectName {
									if srcObjectCli, ok := m["SrcObjectCli"].([]string); ok {
										for _, cli := range srcObjectCli {
											if strings.Contains(cli, objectName) {
												objectCli = cli
												break
											}
										}
									}
									break
								}
							}
						}
					} else if strings.Contains(line, "destination-ip") {
						if dstObjects, ok := m["DstObject"].([]string); ok {
							for _, dst := range dstObjects {
								if dst == objectName {
									if dstObjectCli, ok := m["DstObjectCli"].([]string); ok {
										for _, cli := range dstObjectCli {
											if strings.Contains(cli, objectName) {
												objectCli = cli
												break
											}
										}
									}
									break
								}
							}
						}
					} else if strings.Index(strings.TrimSpace(line), "service ") == 0 {
						if srvObjects, ok := m["SrvObject"].([]string); ok {
							for _, srv := range srvObjects {
								if srv == objectName {
									if srvObjectCli, ok := m["SrvObjectCli"].([]string); ok {
										for _, cli := range srvObjectCli {
											if strings.Contains(cli, objectName) {
												objectCli = cli
												break
											}
										}
									}
									break
								}
							}
						}
					}

					if objectCli != "" {
						objectCliCell := fmt.Sprintf("C%d", row+i)
						f.SetCellValue(sheetName, objectCliCell, objectCli)
						f.SetCellStyle(sheetName, objectCliCell, objectCliCell, wrapStyle)
					}
				}
			}

			// 确定方向
			direction := policyResult.MatchType
			f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), direction)

			// 设置其他列的值
			f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), policy.Name())
			f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), policy.Action().String())
			f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), policy.PolicyEntry().Src().String())
			f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), policy.PolicyEntry().Dst().String())
			f.SetCellValue(sheetName, fmt.Sprintf("H%d", row), policy.PolicyEntry().Service().String())
			// f.SetCellValue(sheetName, fmt.Sprintf("I%d", row), policyResult.OverallMatch)
			// 在每个策略之后添加一行，内容为单个 '#'

			// 添加MatchedAddress列
			if policyResult.MatchedAddress != nil {
				f.SetCellValue(sheetName, fmt.Sprintf("I%d", row), policyResult.MatchedAddress.String())
			} else {
				f.SetCellValue(sheetName, fmt.Sprintf("I%d", row), "N/A")
			}

			// 调整MatchedAddress列的宽度
			f.SetColWidth(sheetName, "I", "I", 30) // 为 Matched Address 列设置适当的宽度

			f.SetCellValue(sheetName, fmt.Sprintf("A%d", row+len(cliLines)), "#")

			// 计算下一行的位置，考虑CLI的行数和额外的空行
			row += len(cliLines) + 1
		}

		// 调整列宽以适应内容
		for i := 0; i < len(headers); i++ {
			col := string(rune('A' + i))
			f.SetColWidth(sheetName, col, col, 20)
		}
		f.SetColWidth(sheetName, "A", "A", 50) // 为 CLI 列设置更宽的宽度
		f.SetColWidth(sheetName, "C", "C", 50) // 为 Object CLI 列设置更宽的宽度
	}

	// 删除默认的 Sheet1
	f.DeleteSheet("Sheet1")

	// 保存Excel文件
	return f.SaveAs(outputFile)
}

// 更新 PolicyData 和 PolicyDetails 结构体
type PolicyData struct {
	Device   string          `json:"device"`
	Policies []PolicyDetails `json:"policies"`
}

type PolicyDetails struct {
	Cli             string            `json:"cli"`
	RuleName        string            `json:"ruleName"`
	Action          string            `json:"action"`
	Source          string            `json:"source"`
	Destination     string            `json:"destination"`
	Service         string            `json:"service"`
	MatchType       string            `json:"matchType"`
	OverallMatch    bool              `json:"overallMatch"`
	MatchedAddress  string            `json:"matchedAddress,omitempty"`
	ObjectRelations []ObjectRelation  `json:"objectRelations"`
	MatchDetails    []MatchDetailInfo `json:"matchDetails"`
}

type ObjectRelation struct {
	Type       string `json:"type"`       // "source", "destination", or "service"
	Name       string `json:"name"`       // Object name in the policy
	CLI        string `json:"cli"`        // CLI of the object
	PolicyLine string `json:"policyLine"` // The line in the policy that references this object
}

type MatchDetailInfo struct {
	MatcherName   string                 `json:"matcherName"`
	Matched       bool                   `json:"matched"`
	MatcherType   string                 `json:"matcherType"`
	MatcherValue  string                 `json:"matcherValue"`
	OverlapDetail float64                `json:"overlapDetail"`
	MatchType     string                 `json:"matchType"`
	ExtraInfo     map[string]interface{} `json:"extraInfo"`
}

func PreparePolicyDataForFrontend(matchedPolicies map[string][]nodemap.PolicyMatchResult) []PolicyData {
	var policyDataList []PolicyData

	for device, policies := range matchedPolicies {
		policyData := PolicyData{
			Device:   device,
			Policies: make([]PolicyDetails, 0, len(policies)),
		}

		for _, policyResult := range policies {
			policyDetails := PolicyDetails{
				// Intent: policyResult.Policy.PolicyEntry(),
				// MatchResult:     policyResult.MatchResult,
				Cli:         policyResult.Policy.Cli(),
				RuleName:    policyResult.Policy.Name(),
				Action:      policyResult.Policy.Action().String(),
				Source:      policyResult.Policy.PolicyEntry().Src().String(),
				Destination: policyResult.Policy.PolicyEntry().Dst().String(),
				Service:     policyResult.Policy.PolicyEntry().Service().String(),
				// Rule:            policyResult.Policy,
				MatchType:       policyResult.MatchType.String(),
				OverallMatch:    policyResult.OverallMatch,
				ObjectRelations: []ObjectRelation{},
			}

			// 处理对象关系
			cliLines := strings.Split(policyResult.Policy.Cli(), "\n")
			for _, line := range cliLines {
				if strings.Contains(line, "source-ip ") ||
					strings.Contains(line, "destination-ip ") ||
					(strings.Index(strings.TrimSpace(line), "service ") == 0 && !strings.Contains(line, "service protocol")) ||
					strings.Contains(line, "source-address address-set") ||
					strings.Contains(line, "destination-address address-set") ||
					strings.Contains(line, "src-address address-object") ||
					strings.Contains(line, "dst-address address-object") ||
					strings.Contains(line, "service service-object") {
					objectName := strings.Fields(line)[len(strings.Fields(line))-1]
					objectType := getObjectType(line)
					objectCli := getObjectCLI(policyResult.Policy.Extended(), line, objectName)

					if objectCli != "" {
						relation := ObjectRelation{
							Type:       objectType,
							Name:       objectName,
							CLI:        objectCli,
							PolicyLine: line,
						}
						policyDetails.ObjectRelations = append(policyDetails.ObjectRelations, relation)
					}
				} else {
					relation := ObjectRelation{
						PolicyLine: line,
					}
					policyDetails.ObjectRelations = append(policyDetails.ObjectRelations, relation)
				}
			}

			// 添加匹配详情
			for matcherName, detail := range policyResult.MatchDetails {
				matchDetail := MatchDetailInfo{
					MatcherName:   matcherName,
					Matched:       detail.Matched,
					MatcherType:   detail.MatcherType,
					MatcherValue:  detail.MatcherValue,
					OverlapDetail: detail.OverlapDetail,
					MatchType:     detail.MatchType.String(),
					ExtraInfo:     detail.ExtraInfo,
				}
				policyDetails.MatchDetails = append(policyDetails.MatchDetails, matchDetail)
			}

			// 添加匹配的地址信息
			if policyResult.MatchedAddress != nil {
				policyDetails.MatchedAddress = policyResult.MatchedAddress.String()
			}

			policyData.Policies = append(policyData.Policies, policyDetails)
		}

		policyDataList = append(policyDataList, policyData)
	}

	return policyDataList
}

// func PreparePolicyDataForFrontend(matchedPolicies map[string][]nodemap.PolicyMatchResult) []PolicyData {
// 	var policyDataList []PolicyData

// 	for device, policies := range matchedPolicies {
// 		policyData := PolicyData{
// 			Device:   device,
// 			Policies: make([]PolicyDetails, 0, len(policies)),
// 		}

// 		for _, policyResult := range policies {
// 			policyDetails := PolicyDetails{
// 				// Intent: policyResult.Policy.PolicyEntry(),
// 				// MatchResult:     policyResult.MatchResult,
// 				FirewallPolicy:  policyResult.Policy,
// 				MatchType:       policyResult.MatchType.String(),
// 				OverallMatch:    policyResult.OverallMatch,
// 				ObjectRelations: []ObjectRelation{},
// 			}

// 			// 处理对象关系
// 			cliLines := strings.Split(policyResult.Policy.Cli(), "\n")
// 			for _, line := range cliLines {
// 				if strings.Contains(line, "source-ip") || strings.Contains(line, "destination-ip") || strings.Index(strings.TrimSpace(line), "service ") == 0 {
// 					objectName := strings.Fields(line)[len(strings.Fields(line))-1]
// 					objectType := getObjectType(line)
// 					objectCli := getObjectCLI(policyResult.Policy.Extended(), line, objectName)

// 					if objectCli != "" {
// 						relation := ObjectRelation{
// 							Type:       objectType,
// 							Name:       objectName,
// 							CLI:        objectCli,
// 							PolicyLine: line,
// 						}
// 						policyDetails.ObjectRelations = append(policyDetails.ObjectRelations, relation)
// 					}
// 				} else {
// 					relation := ObjectRelation{
// 						PolicyLine: line,
// 					}
// 					policyDetails.ObjectRelations = append(policyDetails.ObjectRelations, relation)
// 				}
// 			}

// 			// 添加匹配详情
// 			for matcherName, detail := range policyResult.MatchDetails {
// 				matchDetail := MatchDetailInfo{
// 					MatcherName:   matcherName,
// 					Matched:       detail.Matched,
// 					MatcherType:   detail.MatcherType,
// 					MatcherValue:  detail.MatcherValue,
// 					OverlapDetail: detail.OverlapDetail,
// 					MatchType:     detail.MatchType.String(),
// 					ExtraInfo:     detail.ExtraInfo,
// 				}
// 				policyDetails.MatchDetails = append(policyDetails.MatchDetails, matchDetail)
// 			}

// 			// 添加匹配的地址信息
// 			if policyResult.MatchedAddress != nil {
// 				policyDetails.MatchedAddress = policyResult.MatchedAddress.String()
// 			}

// 			policyData.Policies = append(policyData.Policies, policyDetails)
// 		}

// 		policyDataList = append(policyDataList, policyData)
// 	}

// 	return policyDataList
// }

// func getObjectType(line string) string {
// 	if strings.Contains(line, "source-ip") {
// 		return "source"
// 	} else if strings.Contains(line, "destination-ip") {
// 		return "destination"
// 	} else if strings.Index(strings.TrimSpace(line), "service ") == 0 {
// 		return "service"
// 	}
// 	return "unknown"
// }

func getObjectType(line string) string {
	// USG 防火墙
	if strings.Contains(line, "source-address address-set") {
		return "source-address-set"
	} else if strings.Contains(line, "destination-address address-set") {
		return "destination-address-set"
		// } else if strings.Contains(line, "source-address") {
		//     return "source"
		// } else if strings.Contains(line, "destination-address") {
		//     return "destination"
	} else if strings.Contains(line, "service") && !strings.Contains(line, "service protocol") {
		return "service-object"
	}

	// DPTech 防火墙
	if strings.Contains(line, "src-address address-object") {
		return "source-address-object"
	} else if strings.Contains(line, "dst-address address-object") {
		return "destination-address-object"
	} else if strings.Contains(line, "service service-object") {
		return "service-object"
	}

	// 默认情况
	if strings.Contains(line, "source-ip ") {
		return "source-address-object"
	} else if strings.Contains(line, "destination-ip ") {
		return "destination-address-object"
	}
	// else if strings.Index(strings.TrimSpace(line), "service ") == 0 {
	//     return "service"
	// }
	return "unknown"
}

// getObjectCLI 函数需要根据实际情况进行调整
//
//	func getObjectCLI(extended map[string]interface{}, line, objectName string) string {
//		// 这里的实现需要根据 FirewallPolicy 的 Extended() 方法返回的实际数据结构进行调整
//		// 以下是一个示例实现，可能需要根据实际情况修改
//		if strings.Contains(line, "source-ip") {
//			return getCliFromObject(extended, "SrcObject", "SrcObjectCli", objectName)
//		} else if strings.Contains(line, "destination-ip") {
//			return getCliFromObject(extended, "DstObject", "DstObjectCli", objectName)
//		} else if strings.Index(strings.TrimSpace(line), "service ") == 0 {
//			return getCliFromObject(extended, "SrvObject", "SrvObjectCli", objectName)
//		}
//		return ""
//	}
func getObjectCLI(extended map[string]interface{}, line, objectName string) string {
	objectType := getObjectType(line)
	switch objectType {
	case "source-address-set", "source-address-object":
		return getCliFromObject(extended, "SrcObject", "SrcObjectCli", objectName)
	case "destination-address-set", "destination-address-object":
		return getCliFromObject(extended, "DstObject", "DstObjectCli", objectName)
	case "service-object":
		return getCliFromObject(extended, "SrvObject", "SrvObjectCli", objectName)
	}
	return ""
}

func getCliFromObject(extended map[string]interface{}, objectKey, cliKey, objectName string) string {
	if objects, ok := extended[objectKey].([]string); ok {
		for _, obj := range objects {
			if obj == objectName {
				if clis, ok := extended[cliKey].([]string); ok {
					for _, cli := range clis {
						if strings.Contains(cli, objectName) {
							return cli
						}
					}
				}
				break
			}
		}
	}
	return ""
}
