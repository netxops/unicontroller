package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
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

func serializeNodeMap(nm *nodemap.NodeMap) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(nm)
	return buf.Bytes(), err
}

func deserializeNodeMap(data []byte) (*nodemap.NodeMap, error) {
	nm := &nodemap.NodeMap{}
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(nm)
	return nm, err
}

func getOrCreateNodeMap(config *Config, dcList []config.DeviceConfig) (*nodemap.NodeMap, context.Context, error) {
	ctx := context.Background()
	cacheKey := "nodemap:" + config.NodeMap.Name

	// 尝试从 Redis 获取缓存的 NodeMap
	cachedData, err := global.Redis.Get(ctx, cacheKey).Bytes()
	if err == nil {
		// 如果找到缓存，尝试反序列化
		nm, err := deserializeNodeMap(cachedData)
		if err == nil {
			return nm, ctx, nil
		}
		// 如果反序列化失败，记录错误并继续创建新的 NodeMap
		zap.NewNop().Error("Failed to deserialize cached NodeMap", zap.Error(err))
	}

	// 如果没有找到缓存或反序列化失败，创建新的 NodeMap
	nm, newCtx := nodemap.NewNodeMapFromNetwork(config.NodeMap.Name, dcList, config.NodeMap.Force, config.NodeMap.TaskID, nil, "pkg/nodemap/node/device/firewall/common/v4/templates")

	// 序列化并缓存新创建的 NodeMap
	serializedNM, err := serializeNodeMap(nm)
	if err == nil {
		// 设置缓存，有效期为 1 小时（可以根据需要调整）
		err = global.Redis.Set(ctx, cacheKey, serializedNM, 1*time.Hour).Err()
		if err != nil {
			zap.NewNop().Error("Failed to cache NodeMap in Redis", zap.Error(err))
		}
	} else {
		zap.NewNop().Error("Failed to serialize NodeMap for caching", zap.Error(err))
	}

	return nm, newCtx, nil
}

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
		Area         string `yaml:"area"`
		SubTicket    string `yaml:"subTicket"`
		Service      struct {
			Protocol string `yaml:"protocol"`
			Port     string `yaml:"port"`
		} `yaml:"service"`
		Snat      string            `yaml:"snat"`
		MetaData  map[string]string `yaml:"metadata"`
		InputNode string            `yaml:"inputNode"`
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
	return zap.NewExample()
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

func setupNodeMap(logger *zap.Logger) {
	config, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	var nm nodemap.NodeMap
	var ctx context.Context

	_, err = os.Stat("nm.json")
	if err == nil {
		// 尝试从 nm.json 文件加载 NodeMap
		jsonData, err := ioutil.ReadFile("nm.json")
		if err == nil {
			// 如果文件存在并且可以读取,尝试反序列化
			err = json.Unmarshal(jsonData, &nm)
			if err == nil {
				logger.Info("Successfully loaded NodeMap from nm.json")
				// 创建一个新的 PolicyContext
				ctx = &firewall.PolicyContext{
					Context:            context.Background(),
					DeviceSpecificData: make(map[string]interface{}),
					Variables:          make(map[string]interface{}),
				}
				nm.WithLogger(logger)
			} else {
				logger.Warn("Failed to unmarshal NodeMap from nm.json, will create a new one", zap.Error(err))
			}
		} else {
			logger.Warn("Failed to read nm.json, will create a new NodeMap", zap.Error(err))
		}
	}

	// 如果无法从文件加载,则创建新的 NodeMap
	if nm.Name == "" {
		dcList := initDeviceConfig()
		var pnm *nodemap.NodeMap
		pnm, ctx = nodemap.NewNodeMapFromNetwork(config.NodeMap.Name, dcList, config.NodeMap.Force, config.NodeMap.TaskID, nil, "pkg/nodemap/node/device/firewall/common/v4/templates")
		if pnm != nil {
			nm = *pnm
		}
		if pnm != nil {
			pnm.WithLogger(logger)
		}

		// 序列化并保存新创建的 NodeMap
		jsonData, err := json.MarshalIndent(pnm, "", " ")
		if err != nil {
			logger.Error("Failed to marshal NodeMap", zap.Error(err))
		} else {
			err = ioutil.WriteFile("nm.json", jsonData, 0644)
			if err != nil {
				logger.Error("Failed to write NodeMap to file", zap.Error(err))
			} else {
				logger.Info("NodeMap has been saved to nm.json")
			}
		}
	}

	ctx.(*firewall.PolicyContext).DeviceSpecificData["ExtraInfo"] = config.Policy.MetaData

	// 创建 intent
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
		Area:         config.Policy.Area,
		InputNode:    config.Policy.InputNode,
	}

	if config.Policy.RealIp != "" {
		intent.RealIp = config.Policy.RealIp
		intent.RealPort = config.Policy.RealPort
	}

	fmt.Println(intent)
	tp := nm.MakeTemplates(&intent, ctx)
	processErr := tp.Results.GetErr()
	if processErr.NotNil() {
		logger.Error("====Process error info: ", zap.Any("mark", processErr.GetMark()), zap.Any("desc", processErr.GetDesc()))
	}
}

func main() {
	// 初始化 Redis 和 Logger
	initRedis()
	logger := initLogger()

	// 运行基于test_policy.yaml的测试
	runTestFromYAML(logger)
}

// TestPolicyConfig test_policy.yaml 的结构体定义
// 每个防火墙可以包含多个测试组，每组有独立的策略和测试用例
type TestPolicyConfig struct {
	Name       string      `yaml:"Name"`
	TestGroups []TestGroup `yaml:"TestGroups"` // 测试组数组
}

// TestGroup 测试组定义，每组有独立的策略和测试用例
type TestGroup struct {
	GroupName string      `yaml:"GroupName"` // 测试组名称（可选）
	Policy    []PolicyDef `yaml:"Policy"`    // 该组的策略定义
	TestCase  []TestCase  `yaml:"TestCase"`  // 该组的测试用例数组（根据name字段区分类型）
}

type PolicyDef struct {
	PolicyName string `yaml:"PolicyName"`
	PolicyCli  string `yaml:"PolicyCli"`
}

type TestCase struct {
	Name        string            `yaml:"name"` // 测试用例类型：Contained, Exact, Partial, New
	Description string            `yaml:"description"`
	Src         string            `yaml:"src"`
	Dst         string            `yaml:"dst"`
	Service     TestService       `yaml:"service"`
	MetaData    map[string]string `yaml:"meta_data"`
}

type TestService struct {
	Protocol string `yaml:"protocol"`
	Port     string `yaml:"port"`
}

// SingleNodeMapCache 单节点NodeMap缓存
type SingleNodeMapCache struct {
	cache map[string]struct {
		nm  *nodemap.NodeMap
		ctx context.Context
	}
	mu sync.Mutex
}

var nodeMapCache = &SingleNodeMapCache{
	cache: make(map[string]struct {
		nm  *nodemap.NodeMap
		ctx context.Context
	}),
}

// getOrCreateSingleNodeMap 获取或创建单节点NodeMap
func (c *SingleNodeMapCache) getOrCreateSingleNodeMap(nodeName string, logger *zap.Logger) (*nodemap.NodeMap, context.Context, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查缓存
	if cached, exists := c.cache[nodeName]; exists {
		logger.Info("使用缓存的单节点NodeMap", zap.String("nodeName", nodeName))
		return cached.nm, cached.ctx, nil
	}

	// 创建新的单节点NodeMap
	logger.Info("创建新的单节点NodeMap", zap.String("nodeName", nodeName))

	// 加载配置
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}

	// 查找对应的DeviceConfig
	deviceConfig, err := findDeviceConfigByNodeName(nodeName, cfg, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find device config for node %s: %w", nodeName, err)
	}

	// 创建单设备NodeMap
	deviceList := []config.DeviceConfig{deviceConfig}
	nmName := fmt.Sprintf("SingleNode_%s", nodeName)
	nm, ctx := nodemap.NewNodeMapFromNetwork(nmName, deviceList, cfg.NodeMap.Force, cfg.NodeMap.TaskID, nil, "pkg/nodemap/node/device/firewall/common/v4/templates")

	if nm == nil {
		return nil, nil, fmt.Errorf("failed to create NodeMap for node: %s", nodeName)
	}

	nm.WithLogger(logger)

	// 设置PolicyContext，确保所有配置信息都被保留
	if policyCtx, ok := ctx.(*firewall.PolicyContext); ok {
		// 设置ExtraInfo（policy级别的metadata）
		if cfg.Policy.MetaData != nil {
			policyCtx.DeviceSpecificData["ExtraInfo"] = cfg.Policy.MetaData
		}

		// 确保设备级别的metadata被正确设置
		// NewNodeMapFromNetwork会自动将device.MetaData设置到ctx.DeviceSpecificData[device.Host]
		// 但如果Host为空，需要手动设置
		if deviceConfig.Host == "" {
			// 如果Host为空，使用nodeName作为key来设置metadata
			// 这样可以通过nodeName获取metadata
			if deviceConfig.MetaData != nil {
				policyCtx.DeviceSpecificData[nodeName] = deviceConfig.MetaData
				logger.Info("使用nodeName设置设备metadata",
					zap.String("nodeName", nodeName),
					zap.Any("metadata", deviceConfig.MetaData))
			}
		} else {
			// 如果Host不为空，确保metadata已设置（NewNodeMapFromNetwork应该已经设置了）
			// 但为了保险，再次确认
			if deviceConfig.MetaData != nil {
				if _, exists := policyCtx.DeviceSpecificData[deviceConfig.Host]; !exists {
					policyCtx.DeviceSpecificData[deviceConfig.Host] = deviceConfig.MetaData
					logger.Info("补充设置设备metadata",
						zap.String("host", deviceConfig.Host),
						zap.Any("metadata", deviceConfig.MetaData))
				}
			}
		}

		// 同时，也通过节点获取DeviceConfig并确保metadata可用
		// 从NodeMap中获取节点，确保DeviceConfig被正确设置
		for _, node := range nm.Nodes {
			if node.Name() == nodeName {
				if deviceCfg := node.GetDeviceConfig(); deviceCfg != nil {
					// 确保节点的DeviceConfig包含所有metadata
					if deviceCfg.MetaData == nil {
						deviceCfg.MetaData = make(map[string]interface{})
					}
					// 合并metadata（确保所有配置都被保留）
					if deviceConfig.MetaData != nil {
						for k, v := range deviceConfig.MetaData {
							deviceCfg.MetaData[k] = v
						}
					}
					logger.Info("确保节点DeviceConfig包含所有metadata",
						zap.String("nodeName", nodeName),
						zap.Any("metadata", deviceCfg.MetaData))
				}
				break
			}
		}
	}

	// 缓存NodeMap
	c.cache[nodeName] = struct {
		nm  *nodemap.NodeMap
		ctx context.Context
	}{nm: nm, ctx: ctx}

	logger.Info("单节点NodeMap创建并缓存成功", zap.String("nodeName", nodeName), zap.String("nmName", nmName))

	return nm, ctx, nil
}

// findDeviceConfigByNodeName 根据节点名称查找对应的DeviceConfig
func findDeviceConfigByNodeName(nodeName string, cfg *Config, logger *zap.Logger) (config.DeviceConfig, error) {
	// 优先通过 ipv4_area 或 ipv6_area 中的 node_name 匹配
	for i := range cfg.Devices {
		// 检查 ipv4_area 中的 node_name
		for _, area := range cfg.Devices[i].Ipv4Area {
			if area.NodeName == nodeName {
				logger.Info("通过 ipv4_area.node_name 找到设备配置",
					zap.String("node", nodeName),
					zap.String("host", cfg.Devices[i].Host),
					zap.String("filePath", cfg.Devices[i].FilePath))
				return prepareDeviceConfig(cfg.Devices[i], cfg.Devices[i].FilePath)
			}
		}
		// 检查 ipv6_area 中的 node_name
		for _, area := range cfg.Devices[i].Ipv6Area {
			if area.NodeName == nodeName {
				logger.Info("通过 ipv6_area.node_name 找到设备配置",
					zap.String("node", nodeName),
					zap.String("host", cfg.Devices[i].Host),
					zap.String("filePath", cfg.Devices[i].FilePath))
				return prepareDeviceConfig(cfg.Devices[i], cfg.Devices[i].FilePath)
			}
		}
	}

	return config.DeviceConfig{}, fmt.Errorf("device config not found for nodeName: %s", nodeName)
}

// prepareDeviceConfig 准备DeviceConfig（读取配置文件内容）
func prepareDeviceConfig(device struct {
	config.DeviceConfig `yaml:",inline"`
	FilePath            string `yaml:"file_path"`
}, filePath string) (config.DeviceConfig, error) {
	// 使用copier确保所有字段（包括MetaData）都被正确复制
	deviceConfig := config.DeviceConfig{}
	err := copier.Copy(&deviceConfig, &device.DeviceConfig)
	if err != nil {
		return deviceConfig, fmt.Errorf("failed to copy device config: %w", err)
	}

	// 读取配置文件内容
	if filePath != "" {
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			return deviceConfig, fmt.Errorf("failed to read file %s: %w", filePath, err)
		}
		deviceConfig.Config = string(content)
	}

	// 确保MetaData被正确设置（如果为空则初始化，否则保留原有值）
	if deviceConfig.MetaData == nil {
		deviceConfig.MetaData = make(map[string]interface{})
	}

	// 确保所有metadata都被复制（copier应该已经处理了，但为了保险再检查一次）
	if device.DeviceConfig.MetaData != nil {
		for k, v := range device.DeviceConfig.MetaData {
			if _, exists := deviceConfig.MetaData[k]; !exists {
				deviceConfig.MetaData[k] = v
			}
		}
	}

	return deviceConfig, nil
}

// TestResult 测试结果结构
type TestResult struct {
	NodeName          string
	GroupName         string // 测试组名称
	Scenario          string
	TestCaseIndex     int
	TestCase          TestCase
	PolicyCli         string // 从test_policy.yaml中获取的PolicyCli
	MatchedCount      int    // 匹配到的策略数量
	GeneratedCount    int    // 生成的策略数量
	ExpectedMatch     bool   // 是否期望匹配
	ExpectedGenerate  bool   // 是否期望生成
	ActualMatch       bool   // 实际是否匹配
	ActualGenerate    bool   // 实际是否生成
	Passed            bool
	Error             string
	MatchedPolicies   []MatchedPolicyInfo   // 匹配到的策略信息
	GeneratedPolicies []GeneratedPolicyInfo // 生成的策略信息
}

// MatchedPolicyInfo 匹配的策略信息
type MatchedPolicyInfo struct {
	PolicyName string
	PolicyCli  string
	Action     string
}

// GeneratedPolicyInfo 生成的策略信息
type GeneratedPolicyInfo struct {
	PolicyName string
	PolicyCli  string
	Action     string
}

// runTestFromYAML 从test_policy.yaml运行测试
func runTestFromYAML(logger *zap.Logger) {
	fmt.Println("\n========== 开始基于 test_policy.yaml 的测试 ==========")

	// 1. 加载test_policy.yaml
	testConfigs, err := loadTestPolicyYAML("test_policy.yaml")
	if err != nil {
		logger.Fatal("Failed to load test_policy.yaml", zap.Error(err))
	}

	fmt.Printf("加载了 %d 个测试配置\n", len(testConfigs))

	var allResults []TestResult

	// 2. 遍历每个测试配置
	for _, testConfig := range testConfigs {
		fmt.Printf("\n处理测试配置: %s\n", testConfig.Name)

		// 3. 根据Name字段查找对应的nodemap（从缓存获取或创建）
		nm, ctx, err := nodeMapCache.getOrCreateSingleNodeMap(testConfig.Name, logger)
		if err != nil {
			logger.Error("Failed to get or create single node NodeMap",
				zap.String("nodeName", testConfig.Name),
				zap.Error(err))
			continue
		}

		// 4. 遍历每个测试组
		for _, testGroup := range testConfig.TestGroups {
			groupName := testGroup.GroupName
			if groupName == "" {
				groupName = "default"
			}
			fmt.Printf("  处理测试组: %s\n", groupName)

			// 获取该组的 PolicyCli
			policyCli := ""
			if len(testGroup.Policy) > 0 {
				policyCli = testGroup.Policy[0].PolicyCli
			}

			// 运行该组的各种类型的测试用例
			// 根据TestCase中的name字段分类处理
			for idx, testCase := range testGroup.TestCase {
				scenario := testCase.Name
				if scenario == "" {
					scenario = "Unknown"
				}
				// 将单个TestCase转换为数组传递给runTestCases，并传递测试用例在组内的索引
				results := runTestCases(testConfig.Name, groupName, scenario, []TestCase{testCase}, idx+1, policyCli, nm, ctx, logger)
				allResults = append(allResults, results...)
			}
		}
	}

	// 5. 生成HTML报告
	generateHTMLReport(allResults, logger)

	fmt.Println("\n========== 测试完成 ==========")
}

// loadTestPolicyYAML 加载test_policy.yaml文件
func loadTestPolicyYAML(filename string) ([]TestPolicyConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	var testConfigs []TestPolicyConfig
	err = yaml.Unmarshal(data, &testConfigs)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	return testConfigs, nil
}

// runTestCases 运行测试用例
// startIndex 是测试用例在组内的起始索引（从1开始）
func runTestCases(nodeName, groupName, scenario string, testCases []TestCase, startIndex int, policyCli string, nm *nodemap.NodeMap, ctx context.Context, logger *zap.Logger) []TestResult {
	fmt.Printf("  运行 %s 测试用例: %d 个\n", scenario, len(testCases))

	var results []TestResult

	for i, testCase := range testCases {
		caseIndex := startIndex + i
		fmt.Printf("    [%s-%d] 源: %s, 目: %s, 服务: %s:%s\n",
			scenario, caseIndex, testCase.Src, testCase.Dst, testCase.Service.Protocol, testCase.Service.Port)

		// 创建PolicyEntry
		pe := policy.NewPolicyEntry()

		// 解析源地址
		if testCase.Src != "" {
			srcNg, err := network.NewNetworkGroupFromString(testCase.Src)
			if err != nil {
				logger.Error("Failed to parse source address",
					zap.String("node", nodeName),
					zap.String("src", testCase.Src),
					zap.Error(err))
				continue
			}
			pe.AddSrc(srcNg)
		}

		// 解析目标地址
		if testCase.Dst != "" {
			dstNg, err := network.NewNetworkGroupFromString(testCase.Dst)
			if err != nil {
				logger.Error("Failed to parse destination address",
					zap.String("node", nodeName),
					zap.String("dst", testCase.Dst),
					zap.Error(err))
				continue
			}
			pe.AddDst(dstNg)
		}

		// 解析服务
		if testCase.Service.Protocol != "" {
			var svc *service.Service
			var err error

			protocol := strings.ToLower(testCase.Service.Protocol)
			if protocol == "tcp" || protocol == "udp" {
				if testCase.Service.Port != "" {
					svc, err = service.NewServiceWithL4(protocol, "", testCase.Service.Port)
				} else {
					svc, err = service.NewServiceFromString(protocol)
				}
			} else {
				svc, err = service.NewServiceFromString(protocol)
			}

			if err != nil {
				logger.Error("Failed to create service",
					zap.String("node", nodeName),
					zap.String("protocol", testCase.Service.Protocol),
					zap.String("port", testCase.Service.Port),
					zap.Error(err))
				continue
			}

			if svc != nil {
				pe.AddService(svc)
			}
		}

		// 创建Intent
		intent := &policy.Intent{
			PolicyEntry: *pe,
		}

		// 定位输入节点（通过源地址）
		srcNg := pe.Src()
		if srcNg != nil {
			srcNetList := srcNg.IPv4()
			if srcNetList == nil || srcNetList.IsEmpty() {
				srcNetList = srcNg.IPv6()
			}

			dstNg := pe.Dst()
			var dstNetList *network.NetworkList
			if dstNg != nil {
				dstNetList = dstNg.IPv4()
				if dstNetList == nil || dstNetList.IsEmpty() {
					dstNetList = dstNg.IPv6()
				}
			}
			if dstNetList == nil {
				dstNetList = &network.NetworkList{}
			}

			ok, locatedNode, inputPortName := nm.Locator().Locate(srcNetList, dstNetList, "", "default", "", "")
			if ok {
				intent.InputNode = locatedNode.Name()
				fmt.Printf("      定位输入节点: %s, 接口: %s\n", locatedNode.Name(), inputPortName)
			} else {
				intent.InputNode = nodeName
				fmt.Printf("      定位失败，使用节点名称: %s\n", nodeName)
			}
		} else {
			intent.InputNode = nodeName
		}
		intent.WithMetaData(testCase.MetaData)

		// 调用MakeTemplates进行测试
		tp := nm.MakeTemplates(intent, ctx)

		// 检查错误
		processErr := tp.Results.GetErr()
		var matchedCount int
		var matchedPolicies []MatchedPolicyInfo
		var generatedCount int
		var generatedPolicies []GeneratedPolicyInfo
		var expectedMatch, expectedGenerate bool
		var actualMatch, actualGenerate bool
		var passed bool
		var errorMsg string

		if processErr.NotNil() {
			// 有错误时，记录为失败，但仍然统计
			errorMsg = processErr.GetDesc()
			logger.Warn("MakeTemplates 处理过程中有错误",
				zap.String("node", nodeName),
				zap.String("scenario", scenario),
				zap.String("error", errorMsg))
			fmt.Printf("      ✗ 错误: %s\n", errorMsg)
			// 即使有错误，也尝试统计（可能部分成功）
			matchedCount, matchedPolicies, generatedCount, generatedPolicies = countPoliciesWithInfo(tp)
			// 有错误时，测试一定失败
			expectedMatch, expectedGenerate = shouldMatchOrGenerateForScenario(scenario)
			actualMatch = matchedCount > 0
			actualGenerate = generatedCount > 0
			passed = false // 有错误时，测试一定失败
		} else {
			// 统计匹配和生成的策略数量并收集策略信息
			matchedCount, matchedPolicies, generatedCount, generatedPolicies = countPoliciesWithInfo(tp)
			fmt.Printf("      匹配策略数: %d, 生成策略数: %d\n", matchedCount, generatedCount)

			// 根据场景判断预期结果
			expectedMatch, expectedGenerate = shouldMatchOrGenerateForScenario(scenario)
			actualMatch = matchedCount > 0
			actualGenerate = generatedCount > 0

			// 判断测试是否通过（严格判断，不允许失败通过）
			passed = false
			if expectedMatch && expectedGenerate {
				// 既期望匹配又期望生成（这种情况较少见）
				passed = actualMatch && actualGenerate
			} else if expectedMatch {
				// 只期望匹配：必须匹配且不生成
				passed = actualMatch && !actualGenerate
			} else if expectedGenerate {
				// 只期望生成：必须生成且不匹配
				passed = actualGenerate && !actualMatch
			} else {
				// 既不期望匹配也不期望生成：必须都不匹配且都不生成
				passed = !actualMatch && !actualGenerate
			}
		}

		statusIcon := "✓"
		if !passed {
			statusIcon = "✗"
		}

		if passed {
			fmt.Printf("      %s 测试通过", statusIcon)
			if expectedMatch {
				fmt.Printf(" (期望匹配: %v, 实际匹配: %v)", expectedMatch, actualMatch)
			}
			if expectedGenerate {
				fmt.Printf(" (期望生成: %v, 实际生成: %v)", expectedGenerate, actualGenerate)
			}
			fmt.Println()
		} else {
			fmt.Printf("      %s 测试失败", statusIcon)
			if errorMsg != "" {
				fmt.Printf(" (错误: %s)", errorMsg)
			}
			if expectedMatch {
				fmt.Printf(" (期望匹配: %v, 实际匹配: %v)", expectedMatch, actualMatch)
			}
			if expectedGenerate {
				fmt.Printf(" (期望生成: %v, 实际生成: %v)", expectedGenerate, actualGenerate)
			}
			fmt.Println()
		}

		// 保存测试结果（无论成功还是失败都要记录）
		result := TestResult{
			NodeName:          nodeName,
			GroupName:         groupName,
			Scenario:          scenario,
			TestCaseIndex:     caseIndex,
			TestCase:          testCase,
			PolicyCli:         policyCli,
			MatchedCount:      matchedCount,
			GeneratedCount:    generatedCount,
			ExpectedMatch:     expectedMatch,
			ExpectedGenerate:  expectedGenerate,
			ActualMatch:       actualMatch,
			ActualGenerate:    actualGenerate,
			Passed:            passed,
			MatchedPolicies:   matchedPolicies,
			GeneratedPolicies: generatedPolicies,
		}
		results = append(results, result)
	}

	return results
}

// shouldMatchOrGenerateForScenario 根据场景判断是否应该匹配或生成策略
// 返回 (shouldMatch, shouldGenerate)
func shouldMatchOrGenerateForScenario(scenario string) (bool, bool) {
	switch scenario {
	case "Contained", "Exact":
		return true, false // 这些场景应该匹配到现有策略，不应该生成新策略
	case "New":
		return false, true // 全新测试应该生成新策略，不应该匹配现有策略
	case "Partial":
		return false, true // 部分匹配应该生成新策略，不应该匹配现有策略
	default:
		return true, false
	}
}

// countPoliciesWithInfo 统计匹配和生成的策略数量并收集策略信息
// 返回 (matchedCount, matchedPolicies, generatedCount, generatedPolicies)
func countPoliciesWithInfo(tp *nodemap.TraverseProcess) (int, []MatchedPolicyInfo, int, []GeneratedPolicyInfo) {
	matchedCount := 0
	var matchedPolicies []MatchedPolicyInfo
	generatedCount := 0
	var generatedPolicies []GeneratedPolicyInfo

	for _, item := range tp.Results.Items {
		if item.StepProcess != nil {
			iterator := item.StepProcess.Iterator()
			for iterator.HasNext() {
				_, step := iterator.Next()
				if step != nil {
					phaseAction := step.GetPhaseAction()

					// 检查是否是策略匹配（PHASE_MATCHED表示匹配到现有策略）
					if phaseAction == processor.PHASE_MATCHED {
						matchedCount++

						// 收集匹配的策略信息
						policyInfo := MatchedPolicyInfo{}
						if matchResult, ok := step.GetResult().(*firewall.PolicyMatchResult); ok {
							policy := matchResult.Rule()
							if policy != nil {
								policyInfo.PolicyName = policy.Name()
								policyInfo.PolicyCli = policy.Cli()

								// 获取动作信息
								action := policy.Action()
								switch action {
								case firewall.POLICY_PERMIT:
									policyInfo.Action = "PERMIT"
								case firewall.POLICY_DENY:
									policyInfo.Action = "DENY"
								case firewall.POLICY_IMPLICIT_PERMIT:
									policyInfo.Action = "IMPLICIT_PERMIT"
								case firewall.POLICY_IMPLICIT_DENY:
									policyInfo.Action = "IMPLICIT_DENY"
								default:
									policyInfo.Action = fmt.Sprintf("UNKNOWN(%d)", int(action))
								}
							}
						}
						matchedPolicies = append(matchedPolicies, policyInfo)
					}

					// 检查是否是策略生成（PHASE_GENERATED表示生成了新策略）
					if phaseAction == processor.PHASE_GENERATED {
						// 检查是否有生成的CLI
						cli := step.GetCli()
						if cli != "" {
							generatedCount++

							// 收集生成的策略信息
							policyInfo := GeneratedPolicyInfo{
								PolicyCli: cli,
							}

							// 尝试从CLI中提取策略名称（如果可能）
							// 这里可以根据不同防火墙类型的CLI格式来解析
							lines := strings.Split(cli, "\n")
							for _, line := range lines {
								line = strings.TrimSpace(line)
								// 尝试匹配常见的策略名称模式
								if strings.Contains(line, "name") || strings.Contains(line, "policy") {
									// 简单提取，可以根据实际情况改进
									policyInfo.PolicyName = extractPolicyNameFromCLI(line)
								}
							}

							// 从result中获取动作信息（如果有）
							if step.GetResult() != nil {
								action := step.GetResult().Action()
								switch action {
								case int(firewall.POLICY_PERMIT):
									policyInfo.Action = "PERMIT"
								case int(firewall.POLICY_DENY):
									policyInfo.Action = "DENY"
								case int(firewall.POLICY_IMPLICIT_PERMIT):
									policyInfo.Action = "IMPLICIT_PERMIT"
								case int(firewall.POLICY_IMPLICIT_DENY):
									policyInfo.Action = "IMPLICIT_DENY"
								default:
									policyInfo.Action = fmt.Sprintf("UNKNOWN(%d)", action)
								}
							} else {
								policyInfo.Action = "GENERATED"
							}

							generatedPolicies = append(generatedPolicies, policyInfo)
						}
					}
				}
			}
		}
	}
	return matchedCount, matchedPolicies, generatedCount, generatedPolicies
}

// extractPolicyNameFromCLI 从CLI中提取策略名称（简单实现）
func extractPolicyNameFromCLI(cli string) string {
	// 尝试匹配常见的策略名称模式
	// 例如: "rule 4330 name GL4F-policy4330" -> "GL4F-policy4330"
	// 或者: "policy name test-policy" -> "test-policy"
	patterns := []string{
		`name\s+([^\s]+)`,
		`policy\s+([^\s]+)`,
		`rule\s+\d+\s+name\s+([^\s]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(cli)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return "Generated Policy"
}

// generateHTMLReport 生成HTML测试报告
func generateHTMLReport(results []TestResult, logger *zap.Logger) {
	htmlContent := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>策略测试报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #333; text-align: center; }
        .summary { background: #fff; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .passed { color: #28a745; font-weight: bold; }
        .failed { color: #dc3545; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; position: sticky; top: 0; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f5f5f5; }
        .error { color: #dc3545; font-size: 0.9em; }
        .policy-cli { 
            background-color: #f8f9fa; 
            border: 1px solid #dee2e6; 
            border-radius: 4px; 
            padding: 10px; 
            font-family: 'Courier New', monospace; 
            font-size: 0.85em; 
            white-space: pre-wrap; 
            word-wrap: break-word;
            max-height: 300px;
            overflow-y: auto;
        }
        .matched-policy { 
            margin-top: 10px; 
            padding: 8px; 
            background-color: #e7f3ff; 
            border-left: 3px solid #2196F3; 
        }
        .matched-policy-name { font-weight: bold; color: #1976D2; }
        .matched-policy-action { color: #666; font-size: 0.9em; }
        .test-case-info { 
            background-color: #fff3cd; 
            padding: 8px; 
            border-radius: 4px; 
            margin: 5px 0; 
        }
        .scenario-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .scenario-contained { background-color: #d4edda; color: #155724; }
        .scenario-exact { background-color: #cce5ff; color: #004085; }
        .scenario-partial { background-color: #fff3cd; color: #856404; }
        .scenario-new { background-color: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <h1>策略自动化测试报告</h1>
    <div class="summary">
        <h2>汇总信息</h2>`

	// 统计信息
	totalTests := len(results)
	passedTests := 0
	failedTests := 0
	scenarioStats := make(map[string]int)
	scenarioPassed := make(map[string]int)
	groupStats := make(map[string]int)
	groupPassed := make(map[string]int)

	for _, result := range results {
		if result.Passed {
			passedTests++
			scenarioPassed[result.Scenario]++
		} else {
			failedTests++
		}
		scenarioStats[result.Scenario]++

		// 统计测试组信息
		groupName := result.GroupName
		if groupName == "" {
			groupName = "default"
		}
		groupStats[groupName]++
		if result.Passed {
			groupPassed[groupName]++
		}
	}

	htmlContent += fmt.Sprintf(`
        <p>总测试用例数: <strong>%d</strong></p>
    </div>`, totalTests)

	// 按测试组统计
	htmlContent += `
    <div class="summary">
        <h2>按测试组统计</h2>
        <table>
            <tr>
                <th>测试组</th>
                <th>总数</th>
            </tr>`

	for groupName, count := range groupStats {
		htmlContent += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td>%d</td>
            </tr>`, html.EscapeString(groupName), count)
	}

	htmlContent += `
        </table>
    </div>`

	// 按场景统计
	htmlContent += `
    <div class="summary">
        <h2>按场景统计</h2>
        <table>
            <tr>
                <th>场景</th>
                <th>总数</th>
            </tr>`

	for scenario, count := range scenarioStats {
		htmlContent += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td>%d</td>
            </tr>`, scenario, count)
	}

	htmlContent += `
        </table>
    </div>`

	// 详细测试结果
	htmlContent += `
    <div class="summary">
        <h2>详细测试结果</h2>
        <table>
            <tr>
                <th>节点名称</th>
                <th>测试组</th>
                <th>场景</th>
                <th>测试用例</th>
                <th>测试数据</th>
                <th>策略CLI</th>
                <th>匹配策略数</th>
                <th>匹配的策略详情</th>
                <th>生成策略数</th>
                <th>生成的策略详情</th>
            </tr>`

	for _, result := range results {
		// 格式化测试数据
		testDataInfo := fmt.Sprintf("源: %s<br>目: %s<br>服务: %s:%s",
			result.TestCase.Src, result.TestCase.Dst,
			result.TestCase.Service.Protocol, result.TestCase.Service.Port)

		// 格式化策略CLI
		policyCliHTML := ""
		if result.PolicyCli != "" {
			policyCliHTML = fmt.Sprintf(`<div class="policy-cli">%s</div>`, strings.ReplaceAll(html.EscapeString(result.PolicyCli), "\n", "<br>"))
		} else {
			policyCliHTML = "<em>无</em>"
		}

		// 格式化匹配的策略详情
		matchedPoliciesHTML := ""
		if len(result.MatchedPolicies) > 0 {
			for _, policy := range result.MatchedPolicies {
				matchedPoliciesHTML += fmt.Sprintf(`
                    <div class="matched-policy">
                        <div class="matched-policy-name">策略名称: %s</div>
                        <div class="matched-policy-action">动作: %s</div>
                        <div class="policy-cli" style="margin-top: 5px;">%s</div>
                    </div>`,
					html.EscapeString(policy.PolicyName),
					html.EscapeString(policy.Action),
					strings.ReplaceAll(html.EscapeString(policy.PolicyCli), "\n", "<br>"))
			}
		} else {
			matchedPoliciesHTML = "<em>无匹配策略</em>"
		}

		// 格式化生成的策略详情
		generatedPoliciesHTML := ""
		if len(result.GeneratedPolicies) > 0 {
			for _, policy := range result.GeneratedPolicies {
				generatedPoliciesHTML += fmt.Sprintf(`
                    <div class="matched-policy" style="background-color: #d1ecf1; border-left-color: #0c5460;">
                        <div class="matched-policy-name">策略名称: %s</div>
                        <div class="matched-policy-action">动作: %s</div>
                        <div class="policy-cli" style="margin-top: 5px;">%s</div>
                    </div>`,
					html.EscapeString(policy.PolicyName),
					html.EscapeString(policy.Action),
					strings.ReplaceAll(html.EscapeString(policy.PolicyCli), "\n", "<br>"))
			}
		} else {
			generatedPoliciesHTML = "<em>无生成策略</em>"
		}

		// 场景标签
		scenarioClass := ""
		switch result.Scenario {
		case "Contained":
			scenarioClass = "scenario-contained"
		case "Exact":
			scenarioClass = "scenario-exact"
		case "Partial":
			scenarioClass = "scenario-partial"
		case "New":
			scenarioClass = "scenario-new"
		}

		// 格式化测试组名称
		groupNameDisplay := result.GroupName
		if groupNameDisplay == "" {
			groupNameDisplay = "default"
		}

		htmlContent += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td>%s</td>
                <td><span class="scenario-badge %s">%s</span></td>
                <td>#%d</td>
                <td>%s</td>
                <td>%s</td>
                <td>%d</td>
                <td>%s</td>
                <td>%d</td>
                <td>%s</td>
            </tr>`,
			html.EscapeString(result.NodeName),
			html.EscapeString(groupNameDisplay),
			scenarioClass,
			result.Scenario,
			result.TestCaseIndex,
			testDataInfo,
			policyCliHTML,
			result.MatchedCount,
			matchedPoliciesHTML,
			result.GeneratedCount,
			generatedPoliciesHTML)
	}

	htmlContent += `
        </table>
    </div>
</body>
</html>`

	// 写入文件
	filename := "test_policy_report.html"
	err := ioutil.WriteFile(filename, []byte(htmlContent), 0644)
	if err != nil {
		logger.Error("Failed to write HTML report", zap.Error(err))
		fmt.Printf("警告: 无法生成HTML报告: %v\n", err)
	} else {
		fmt.Printf("\nHTML报告已生成: %s\n", filename)
	}
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
