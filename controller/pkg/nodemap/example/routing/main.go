package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
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
	Devices []struct {
		config.DeviceConfig `yaml:",inline"`
		FilePath            string `yaml:"file_path"`
		// Metadata            map[string]string `yaml:"metadata"`
	} `yaml:"devices"`
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
		Snat     string            `yaml:"snat"`
		MetaData map[string]string `yaml:"metadata"`
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
		Password: "Redis@Passw0rd", // no password set
		DB:       0,                // use default DB
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

// func initDeviceConfig() []config.DeviceConfig {
// 	yamlFile, err := ioutil.ReadFile("config.yaml")
// 	if err != nil {
// 		panic(fmt.Sprintf("Error reading YAML file: %v", err))
// 	}

// 	var devicesConfig struct {
// 		ConfigFilePath string   `yaml:"config_file_path"`
// 		Devices        []Device `yaml:"devices"`
// 	}

// 	err = yaml.Unmarshal(yamlFile, &devicesConfig)
// 	if err != nil {
// 		panic(fmt.Sprintf("Error unmarshaling YAML: %v", err))
// 	}

// 	// 打印整个解析后的结构
// 	fmt.Printf("Parsed YAML: %+v", devicesConfig)

// 	var deviceConfigs []config.DeviceConfig

// 	for i, device := range devicesConfig.Devices {
// 		var content []byte
// 		var err error
// 		// 读取设备配置文件
// 		if device.FilePath != "" {
// 			content, err = ioutil.ReadFile(device.FilePath)
// 			if err != nil {
// 				fmt.Printf("Error reading file %s: %v\n", device.FilePath, err)
// 				deviceConfigs = append(deviceConfigs, devicesConfig.Devices[i].DeviceConfig)
// 				continue
// 			}
// 		}

// 		// 创建 DeviceConfig
// 		deviceConfig := device.DeviceConfig

// 		fmt.Printf("Device %d:\n", i+1)
// 		fmt.Printf("  Host: %s\n", device.Host)
// 		fmt.Printf("  Username: %s\n", device.Username)
// 		fmt.Printf("  Port: %d\n", device.Port)
// 		fmt.Printf("  Mode: %s\n", device.Mode)
// 		fmt.Printf("  Telnet: %v\n", device.Telnet)
// 		fmt.Printf("  Ipv4Area: %+v\n", device.Ipv4Area)

// 		if len(device.Ipv4Area) == 0 {
// 			fmt.Printf("  Warning: Ipv4Area is empty for device %s\n", device.Host)
// 		}

// 		copier.Copy(&deviceConfig, &device)
// 		deviceConfig.Config = string(content)
// 		deviceConfigs = append(deviceConfigs, deviceConfig)

// 	}

//		return deviceConfigs
//	}
func initDeviceConfig() []config.DeviceConfig {
	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		panic(fmt.Sprintf("Error reading YAML file: %v", err))
	}

	var cfg Config
	err = yaml.Unmarshal(yamlFile, &cfg)
	if err != nil {
		panic(fmt.Sprintf("Error unmarshaling YAML: %v", err))
	}

	fmt.Printf("Parsed YAML: %+v\n", cfg)

	var deviceConfigs []config.DeviceConfig

	for i, device := range cfg.Devices {
		var content []byte
		var err error
		if device.FilePath != "" {
			content, err = ioutil.ReadFile(device.FilePath)
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", device.FilePath, err)
				deviceConfigs = append(deviceConfigs, cfg.Devices[i].DeviceConfig)
				continue
			}
		}

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

		// 使用 MetaData 来存储设备特定的配置
		if deviceConfig.MetaData == nil {
			deviceConfig.MetaData = make(map[string]interface{})
		}

		// 添加设备特定的元数据
		for k, v := range device.MetaData {
			deviceConfig.MetaData[k] = v
		}

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
		// MetaData:     config.Policy.MetaData,
	}

	if config.Policy.RealIp != "" {
		intent.RealIp = config.Policy.RealIp
		intent.RealPort = config.Policy.RealPort
	}

	dcList := initDeviceConfig()
	nm, _ := nodemap.NewNodeMapFromNetwork(config.NodeMap.Name, dcList, config.NodeMap.Force, config.NodeMap.TaskID, nil)
	printNodeDetails(nm)
	fmt.Println(nm.ToMermaid())
	// fmt.Println("-----------------------------------------------------------------------------------------------")
	// for _, node := range nm.Nodes {
	// 	for _, vrf := range node.Vrfs() {
	// 		table := node.Ipv4RouteTable(vrf.Name())
	// 		if table != nil {
	// 			fmt.Println("Node:", node.Name())
	// 			fmt.Println("IPv4 route table:", vrf.Name())
	// 			fmt.Println(table.String())
	// 		}
	// 		table = node.Ipv6RouteTable(vrf.Name())
	// 		if table != nil {
	// 			fmt.Println("Node:", node.Name())
	// 			fmt.Println("IPv6 route table:", vrf.Name())
	// 			fmt.Println(table.String())
	// 		}
	// 	}
	// }
}

func printNodeDetails(nm *nodemap.NodeMap) {
	fmt.Println("===============================================================================================")
	fmt.Println("Node Details:")
	fmt.Println("===============================================================================================")

	for _, node := range nm.Nodes {
		printSingleNodeDetails(node)
	}
}

// func printSingleNodeDetails(node api.Node) {
// 	fmt.Printf("Node: %s\n", node.Name())

// 	// 打印Zone信息
// 	zones := make(map[string]bool)
// 	for _, port := range node.PortList() {
// 		if zf, ok := port.(firewall.ZoneFirewall); ok {
// 			zones[zf.Zone()] = true
// 		}
// 	}
// 	fmt.Println("  Zones:")
// 	for zone := range zones {
// 		fmt.Printf("    - %s\n", zone)
// 	}

// 	// 打印Interface信息
// 	fmt.Println("  Interfaces:")
// 	for _, iface := range node.PortList() {
// 		fmt.Printf("    - Name: %s\n", iface.Name())
// 		if zf, ok := iface.(firewall.ZoneFirewall); ok {
// 			fmt.Printf("      Zone: %s\n", zf.Zone())
// 		}
// 		fmt.Printf("      VRF: %s\n", iface.Vrf())

// 		// 打印IPv4地址
// 		ipv4Addrs := iface.Ipv4List()
// 		if len(ipv4Addrs) > 0 {
// 			fmt.Println("      IPv4 Addresses:")
// 			for _, addr := range ipv4Addrs {
// 				fmt.Printf("        - %s\n", addr)
// 			}
// 		}

// 		// 打印IPv6地址
// 		ipv6Addrs := iface.Ipv6List()
// 		if len(ipv6Addrs) > 0 {
// 			fmt.Println("      IPv6 Addresses:")
// 			for _, addr := range ipv6Addrs {
// 				fmt.Printf("        - %s\n", addr)
// 			}
// 		}
// 	}

// 	// 打印VRF和路由表信息
// 	for _, vrf := range node.Vrfs() {
// 		fmt.Printf("  VRF: %s\n", vrf.Name())

// 		// IPv4路由表
// 		ipv4Table := node.Ipv4RouteTable(vrf.Name())
// 		if ipv4Table != nil {
// 			fmt.Println("    IPv4 Route Table:")
// 			fmt.Println("      Default Route:")
// 			defaultRoute := ipv4Table.DefaultGw()
// 			if defaultRoute != nil {
// 				fmt.Printf("        - %s\n", defaultRoute.String())
// 			} else {
// 				fmt.Println("        No default route")
// 			}
// 		}

// 		// IPv6路由表
// 		ipv6Table := node.Ipv6RouteTable(vrf.Name())
// 		if ipv6Table != nil {
// 			fmt.Println("    IPv6 Route Table:")
// 			fmt.Println("      Default Route:")
// 			defaultRoute := ipv6Table.DefaultGw()
// 			if defaultRoute != nil {
// 				fmt.Printf("        - %s\n", defaultRoute.String())
// 			} else {
// 				fmt.Println("        No default route")
// 			}
// 		}
// 	}

// 	fmt.Println("-----------------------------------------------------------------------------------------------")
// }

func IsInSameSubnet(netAddr string, ip string) bool {
	ipnet, err := network.ParseIPNet(netAddr)
	if err != nil {
		return false
	}
	ipaddr, err := network.ParseIP(ip)
	if err != nil {
		return false
	}

	return ipnet.MatchIP(ipaddr)
}

type interfaceInfo struct {
	HasRoute       bool
	IsDefaultRoute bool
	Zone           string
	VRF            string
	IPv4Addresses  []string
	IPv6Addresses  []string
}

func printSingleNodeDetails(node api.Node) {
	fmt.Printf("Node: %s\n", node.Name())

	// 用于存储有路由的接口和其他信息
	interfaceInfoMap := make(map[string]interfaceInfo)

	// 收集所有接口的基本信息
	for _, iface := range node.PortList() {
		info := interfaceInfoMap[iface.Name()]
		if zf, ok := iface.(firewall.ZoneFirewall); ok {
			info.Zone = zf.Zone()
		}
		info.VRF = iface.Vrf()
		info.IPv4Addresses = iface.Ipv4List()
		info.IPv6Addresses = iface.Ipv6List()
		interfaceInfoMap[iface.Name()] = info
	}

	// 检查所有VRF的路由表
	for _, vrf := range node.Vrfs() {
		ipv4Table := node.Ipv4RouteTable(vrf.Name())
		ipv6Table := node.Ipv6RouteTable(vrf.Name())

		// 检查IPv4路由表
		if ipv4Table != nil {
			checkRoutesAndUpdateInfo(node, ipv4Table, interfaceInfoMap, true)
		}

		// 检查IPv6路由表
		if ipv6Table != nil {
			checkRoutesAndUpdateInfo(node, ipv6Table, interfaceInfoMap, false)
		}
	}

	// 打印收集到的信息
	// printCollectedInfo(interfaceInfoMap)

	printFormattedInterfaceInfo(node, interfaceInfoMap)
}

func checkRoutesAndUpdateInfo(node api.Node, table *network.AddressTable, interfaceInfo map[string]interfaceInfo, isIPv4 bool) {
	for it := table.Iterator(); it.HasNext(); {
		_, nextHop := it.Next()
		for hopIt := nextHop.Iterator(); hopIt.HasNext(); {
			_, hop := hopIt.Next()
			if iface := node.GetPortByNameOrAlias(hop.(*network.Hop).Interface); iface != nil {
				info := interfaceInfo[iface.Name()]
				info.HasRoute = true

				// 检查是否为默认路由
				if table.DefaultGw() != nil {
					for hopIt := table.DefaultGw().Data().RawData.(*network.NextHop).Iterator(); hopIt.HasNext(); {
						_, hop := hopIt.Next()
						if hop.(*network.Hop).Interface == iface.Name() {
							info.IsDefaultRoute = true
							break
						}
					}
				}

				interfaceInfo[iface.Name()] = info
			}
		}
	}
}

// func printFormattedInterfaceInfo(node api.Node, interfaceInfo map[string]interfaceInfo) {
//     fmt.Printf("Node: %s\n", node.Name())

//     // 打印 ipv4_area
//     fmt.Println("  ipv4_area:")
//     for ifaceName, info := range interfaceInfo {
//         if info.IsDefaultRoute {
//             fmt.Printf("    - interface: \"%s\"\n", ifaceName)
//             fmt.Printf("      name: \"%s\"\n", info.Zone)
//             fmt.Printf("      node_name: \"%s\"\n", node.Name())
//             fmt.Println("      force: true")
//         }
//     }

//     // 打印 ipv4_stub
//     fmt.Println("  ipv4_stub:")
//     for ifaceName, info := range interfaceInfo {
//         if !info.IsDefaultRoute && info.HasRoute {
//             fmt.Printf("    - port_name: \"%s\"\n", ifaceName)
//         }
//     }

//     fmt.Println("-----------------------------------------------------------------------------------------------")
// }

func printFormattedInterfaceInfo(node api.Node, interfaceInfo map[string]interfaceInfo) {
	fmt.Printf("Node: %s\n", node.Name())

	// 打印 ipv4_area
	fmt.Println("  ipv4_area:")
	hasDefaultRoute := false
	for ifaceName, info := range interfaceInfo {
		if info.IsDefaultRoute && info.VRF == "default" {
			fmt.Printf("    - interface: \"%s\"\n", ifaceName)
			fmt.Printf("      name: \"%s\"\n", info.Zone)
			fmt.Printf("      node_name: \"%s\"\n", node.Name())
			fmt.Println("      force: true")
			hasDefaultRoute = true
		}
	}
	if !hasDefaultRoute {
		fmt.Println("    No default route interfaces in the default VRF")
	}

	// 打印 ipv4_stub
	fmt.Println("  ipv4_stub:")
	hasStubRoutes := false
	for ifaceName, info := range interfaceInfo {
		if !info.IsDefaultRoute && info.HasRoute && info.VRF == "default" {
			fmt.Printf("    - port_name: \"%s\"\n", ifaceName)
			hasStubRoutes = true
		}
	}
	if !hasStubRoutes {
		fmt.Println("    No stub route interfaces in the default VRF")
	}

	fmt.Println("-----------------------------------------------------------------------------------------------")
}

func printCollectedInfo(interfaceInfo map[string]interfaceInfo) {
	fmt.Println("  Zones:")

	// 用于存储每个区域的接口信息
	zoneInterfaces := make(map[string][]struct {
		Name           string
		IsDefaultRoute bool
		VRF            string
	})

	// 收集每个区域的接口信息
	for ifaceName, info := range interfaceInfo {
		if !info.HasRoute {
			continue
		}

		zone := info.Zone
		if zone == "" {
			zone = "Unzoned" // 对于没有区域的接口，使用 "Unzoned" 作为区域名
		}

		zoneInterfaces[zone] = append(zoneInterfaces[zone], struct {
			Name           string
			IsDefaultRoute bool
			VRF            string
		}{
			Name:           ifaceName,
			IsDefaultRoute: info.IsDefaultRoute,
			VRF:            info.VRF,
		})
	}

	// 按区域名称排序
	var sortedZones []string
	for zone := range zoneInterfaces {
		sortedZones = append(sortedZones, zone)
	}
	sort.Strings(sortedZones)

	// 打印每个区域的信息
	for _, zone := range sortedZones {
		fmt.Printf("    - %s:\n", zone)
		for _, iface := range zoneInterfaces[zone] {
			fmt.Printf("      InterfaceName: %s, VRF: %s, IsDefaultRoute: %v\n",
				iface.Name, iface.VRF, iface.IsDefaultRoute)
		}
	}

	fmt.Println("-----------------------------------------------------------------------------------------------")
}

func main() {
	// 初始化 Redis 和 Logger
	initRedis()
	logger := initLogger()

	// 设置 NodeMap 并执行查询
	setupNodeMap(logger)
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

// func writeToExcel(matchedPolicies map[string][]nodemap.PolicyMatchResult, outputFile string) error {
//     f := excelize.NewFile()

//     for device, policies := range matchedPolicies {
//         sheetName := device
//         f.NewSheet(sheetName)

//         // 设置表头
//         headers := []string{"CLI", "方向", "Rule Name", "Action", "Source", "Destination", "Service", "Overall Match"}
//         for i, header := range headers {
//             cell := fmt.Sprintf("%s1", string(rune('A'+i)))
//             f.SetCellValue(sheetName, cell, header)
//         }

//         row := 2
//         for _, policyResult := range policies {
//             policy := policyResult.Policy

//             m := policy.Extended()

//             // 组合CLI、SrcObjectCli和DstObjectCli
//             combinedCli := policy.Cli() + "\n"
//             if srcObjectCli, ok := m["SrcObjectCli"].([]string); ok && len(srcObjectCli) > 0 {
//                 combinedCli += "\nSource Object CLI:\n" + strings.Join(srcObjectCli, "\n") + "\n"
//             }
//             if dstObjectCli, ok := m["DstObjectCli"].([]string); ok && len(dstObjectCli) > 0 {
//                 combinedCli += "\nDestination Object CLI:\n" + strings.Join(dstObjectCli, "\n") + "\n"
//             }

//             // 分行打印组合后的CLI
//             cliLines := strings.Split(combinedCli, "\n")
//             for i, line := range cliLines {
//                 f.SetCellValue(sheetName, fmt.Sprintf("A%d", row+i), line)
//             }

//             // 确定方向
//             direction := policyResult.MatchType

//             f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), direction)
//             // f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), policy.Name())
//             // f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), policy.Action().String())
//             // f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), policy.PolicyEntry().Src().String())
//             // f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), policy.PolicyEntry().Dst().String())
//             // f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), policy.PolicyEntry().Service().String())
//             // f.SetCellValue(sheetName, fmt.Sprintf("H%d", row), policyResult.OverallMatch)

//             // 计算下一行的位置，考虑组合后CLI的行数和额外的空行
//             row += len(cliLines) + 2
//         }

//         // 调整列宽以适应内容
//         for i := 0; i < len(headers); i++ {
//             col := string(rune('A' + i))
//             f.SetColWidth(sheetName, col, col, 20)
//         }
//         f.SetColWidth(sheetName, "A", "A", 50) // 为 CLI 列设置更宽的宽度
//     }

//     // 删除默认的 Sheet1
//     f.DeleteSheet("Sheet1")

//     // 保存Excel文件
//     return f.SaveAs(outputFile)
// }

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
