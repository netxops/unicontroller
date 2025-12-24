package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/jinzhu/copier"
	"github.com/netxops/log"
	"github.com/netxops/utils/service"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func (mnm *NodemapService) L3NodeMapQuery(ctx context.Context, queryInfo *structs.L3Query, deviceConfigs []config.DeviceConfig, result *structs.PolicyData, nm *nodemap.NodeMap) error {
	// If no NodeMap was provided, create one
	if nm == nil {
		var nodemapId uint = 0
		nm, _ = nodemap.NewNodeMapFromNetwork(mnm.MNM.Name, deviceConfigs, true, 123456, &nodemapId)
	}

	matchers, err := mnm.makePolicyMatcher(queryInfo)
	if err != nil {
		return err
	}

	// 组合所有匹配器
	compositeMatcher := nodemap.CompositeMatcher{Matchers: matchers}

	// 获取匹配的策略
	matchedPolicies := nm.Policies(queryInfo.QueryKey, compositeMatcher)

	devicePolicies := mnm.preparePolicyDataForFrontend(matchedPolicies)
	result.Result = append(result.Result, devicePolicies...)
	return nil
}
func (mnm *NodemapService) makePolicyMatcher(queryInfo *structs.L3Query) ([]nodemap.PolicyMatcher, error) {
	if queryInfo == nil {
		return nil, fmt.Errorf("l3 query info is nil")
	}

	ipRanges := queryInfo.Condition.IpRanges
	// 验证必要的参数
	if ipRanges == "" {
		return nil, fmt.Errorf("l3 query remote has error: %s", "IP ranges must be specified")
	}

	// 创建匹配器
	var matchers []nodemap.PolicyMatcher

	// 处理 IP 范围
	ipRangesList := strings.Split(ipRanges, ",")
	if len(ipRangesList) == 0 {
		return nil, fmt.Errorf("l3 query remote has error: %s", "At least one IP range must be specified")
	}

	var ipMatchers []nodemap.PolicyMatcher
	for _, ipRange := range ipRangesList {
		matcher := mnm.createIPMatchers(ipRange, queryInfo.Condition.MatchStrategy, queryInfo.Condition.MatchType, queryInfo.Condition.Threshold)
		ipMatchers = append(ipMatchers, matcher)
	}
	if len(ipMatchers) > 0 {
		matchers = append(matchers, nodemap.OrMatcher{Matchers: ipMatchers})
	}

	// 处理协议和端口
	protocol := queryInfo.Condition.Protocol
	port := queryInfo.Condition.Port
	if protocol != "" || port != "" {
		serviceStr := fmt.Sprintf("%s:%s", protocol, port)
		matchers = append(matchers, nodemap.ServiceMatcher{Service: mnm.mustService(serviceStr)})
	}

	// 处理动作
	action := queryInfo.Condition.Action
	if action != "" {
		actionMatcher := mnm.createActionMatcher(action)
		if actionMatcher != nil {
			matchers = append(matchers, actionMatcher)
		}
	}

	// 处理策略名
	policyName := queryInfo.Condition.PolicyName
	if policyName != "" {
		matchers = append(matchers, nodemap.NameMatcher{Name: policyName})
	}

	return matchers, nil
}

// 创建 IP 匹配器
func (mnm *NodemapService) createIPMatchers(ips string, strategy structs.MatchStrategy, matchType structs.MatchType, threshold float64) nodemap.PolicyMatcher {
	var matchers []nodemap.PolicyMatcher
	for _, ip := range strings.Split(ips, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			switch matchType {
			case structs.Src:
				matchers = append(matchers, nodemap.NewAddressMatcher(ip, mnm.getMatchStrategy(strategy), true, threshold))
			case structs.Dst:
				matchers = append(matchers, nodemap.NewAddressMatcher(ip, mnm.getMatchStrategy(strategy), false, threshold))
			default: // "both"
				srcMatcher := nodemap.NewAddressMatcher(ip, mnm.getMatchStrategy(strategy), true, threshold)
				dstMatcher := nodemap.NewAddressMatcher(ip, mnm.getMatchStrategy(strategy), false, threshold)
				matchers = append(matchers, nodemap.OrMatcher{Matchers: []nodemap.PolicyMatcher{srcMatcher, dstMatcher}})
			}
		}
	}
	return nodemap.OrMatcher{Matchers: matchers}
}

// getMatchStrategy 将查询策略转换为 nodemap 的匹配策略
// 这些策略用于判断查询的 IP 范围与防火墙策略中的 IP 范围之间的关系
//
// 示例说明（假设查询 IP: 10.1.0.0/16，策略 IP: 10.0.0.0/8）：
// - Overlap: 查询 IP 与策略 IP 有重叠即可（10.1.0.0/16 与 10.0.0.0/8 重叠）
// - Contains: 策略 IP 必须完全包含查询 IP（10.0.0.0/8 包含 10.1.0.0/16，匹配）
// - ContainedBy: 查询 IP 必须完全包含策略 IP（10.1.0.0/16 不包含 10.0.0.0/8，不匹配）
// - Exact: 查询 IP 与策略 IP 必须完全一致（10.1.0.0/16 ≠ 10.0.0.0/8，不匹配）
// - Threshold: 基于重叠比例的阈值匹配（例如：重叠部分占查询 IP 的 50% 以上）
// - OverlapIgnoreAny: 重叠匹配，但忽略策略中的 Any/0.0.0.0/0 地址
// - IsolatedInQuery: 策略地址中的孤立地址在查询范围内（遍历策略中的每个孤立地址，只要任意一个在查询范围内即匹配）
func (mnm *NodemapService) getMatchStrategy(strategy structs.MatchStrategy) nodemap.MatchStrategy {
	switch strategy {
	case structs.Overlap:
		// 重叠匹配：查询 IP 与策略 IP 有交集即可匹配（只要有任何重叠部分就匹配）
		// 例如：查询 10.1.0.0/24，策略 10.1.0.128/25 → 匹配（部分重叠：10.1.0.128-10.1.0.255）
		//      查询 10.1.0.0/24，策略 10.1.1.0/24 → 不匹配（无重叠：10.1.0.0-10.1.0.255 vs 10.1.1.0-10.1.1.255）
		//      查询 10.1.0.0/16，策略 10.0.0.0/8 → 匹配（10.1.0.0/16 完全在 10.0.0.0/8 内，有重叠）
		return nodemap.StrategyOverlap
	case structs.Contains:
		// 包含匹配：策略 IP 必须完全包含查询 IP（策略包含查询）
		// 例如：查询 10.1.0.0/16，策略 10.0.0.0/8 → 匹配（策略包含查询）
		//      查询 10.0.0.0/8，策略 10.1.0.0/16 → 不匹配（策略不包含查询）
		return nodemap.StrategyContains
	case structs.ContainedBy:
		// 被包含匹配：查询 IP 必须完全包含策略 IP（查询包含策略）
		// 例如：查询 10.0.0.0/8，策略 10.1.0.0/16 → 匹配（查询包含策略）
		//      查询 10.1.0.0/16，策略 10.0.0.0/8 → 不匹配（查询不包含策略）
		return nodemap.StrategyContainedBy
	case structs.Exact:
		// 精确匹配：查询 IP 与策略 IP 必须完全一致
		// 例如：查询 10.1.0.0/16，策略 10.1.0.0/16 → 匹配
		//      查询 10.1.0.0/16，策略 10.1.0.0/24 → 不匹配（虽然包含，但不完全一致）
		return nodemap.StrategyExactMatch
	case structs.Threshold:
		// 阈值匹配：基于重叠比例的匹配，需要配合 threshold 参数使用
		// 例如：threshold=0.5 表示重叠部分必须占查询 IP 的 50% 以上才匹配
		return nodemap.StrategyThreshold
	case structs.OverlapIgnoreAny:
		// 重叠匹配（忽略 Any）：与 Overlap 相同，但忽略策略中的 Any/0.0.0.0/0 地址
		// 用于排除过于宽泛的策略（如允许所有 IP 的策略）
		return nodemap.StrategyOverlapIgnoreAny
	case structs.IsolatedInQuery:
		// 孤立地址在查询范围内匹配：遍历策略地址中的每个孤立地址，检查是否在查询范围内
		// 只要策略中的任意一个孤立地址在查询范围内，就视为匹配
		// 例如：策略包含 [10.1.0.0/24, 10.2.0.0/24, 192.168.1.0/24]
		//      查询 10.0.0.0/8 → 匹配（10.1.0.0/24 和 10.2.0.0/24 在查询范围内）
		//      查询 192.168.0.0/16 → 匹配（192.168.1.0/24 在查询范围内）
		//      查询 172.16.0.0/16 → 不匹配（所有孤立地址都不在查询范围内）
		return nodemap.StrategyIsolatedInQuery
	default:
		// 默认使用重叠匹配
		return nodemap.StrategyOverlap
	}
}

func (mnm *NodemapService) createActionMatcher(actionStr structs.Action) nodemap.PolicyMatcher {
	var action firewall.Action
	switch actionStr {
	case structs.Deny:
		action = firewall.POLICY_DENY
	case structs.Permit:
		action = firewall.POLICY_PERMIT
	case structs.Reject:
		action = firewall.POLICY_REJECT
	case structs.ImplicitPermit:
		action = firewall.POLICY_IMPLICIT_PERMIT
	case structs.ImplicitDeny:
		action = firewall.POLICY_IMPLICIT_DENY
	case structs.NatMatched:
		action = firewall.NAT_MATCHED
	case structs.NatNoMatched:
		action = firewall.NAT_NOMATCHED
	default:
		fmt.Printf("Invalid action: %s. Using default (no action filter).\n", actionStr)
		return nil
	}
	return nodemap.ActionMatcher{Action: action}
}

func (mnm *NodemapService) mustService(serviceString string) *service.Service {
	s, err := service.NewServiceFromString(serviceString)
	if err != nil {
		panic(err)
	}
	return s
}

func (mnm *NodemapService) validateL3Config(l3Config structs.L3Config) error {
	if l3Config.NodeMap.Name == "" {
		return fmt.Errorf("l3 config nodemap name is empty")
	}
	if l3Config.NodeMap.TaskID == 0 {
		return fmt.Errorf("l3 config nodemap task id is valid")
	}

	if l3Config.Policy.Source == "" {
		return fmt.Errorf("l3 config policy source is empty")
	}

	if l3Config.Policy.Destination == "" {
		return fmt.Errorf("l3 config policy destination is empty")
	}

	if l3Config.Policy.TicketNumber == "" {
		return fmt.Errorf("l3 config policy ticketNumber is empty")
	}

	if l3Config.Policy.SubTicket == "" {
		return fmt.Errorf("l3 config policy subTicket is empty")
	}

	if l3Config.Policy.Service.Protocol == "" {
		return fmt.Errorf("l3 config service protocol is empty")
	}

	if l3Config.Policy.Service.Port == "" {
		return fmt.Errorf("l3 config service port is empty")
	}

	//if l3Config.Policy.Snat == "" {
	//	return fmt.Errorf("l3 config policy snat is empty")
	//}

	return nil
}

func (mnm *NodemapService) setupNodeMap(deviceConfigs []config.DeviceConfig, actionID string, matcher nodemap.PolicyMatcher, ctx context.Context, nm *nodemap.NodeMap) ([]structs.DevicePolicy, error) {
	logger := log.NewLogger(nil, true).Logger

	// If no NodeMap was provided, create one
	if nm == nil {
		var nodemapId uint = 0
		nm, _ = nodemap.NewNodeMapFromNetwork(mnm.MNM.Name, deviceConfigs, true, 123456, &nodemapId)
	}
	nm.WithLogger(logger)

	// 获取匹配的策略
	matchedPolicies := nm.Policies(actionID, matcher)

	totalPolicies := 0
	for device, policies := range matchedPolicies {
		logger.Info("Matched policies for device", zap.String("device", device), zap.Int("count", len(policies)))
		totalPolicies += len(policies)
	}

	logger.Info("Total matched policies", zap.Int("count", totalPolicies))

	devicePolicies := mnm.preparePolicyDataForFrontend(matchedPolicies)
	fmt.Println("==========Log policy info generated successfully===========")
	return devicePolicies, nil
}
func (mnm *NodemapService) loadConfig() (*structs.L3Config, error) {
	yamlFile, err := os.ReadFile("../pkg/nodemap/example/config.yaml")
	if err != nil {
		return nil, err
	}

	var l3Config structs.L3Config
	if err = yaml.Unmarshal(yamlFile, &l3Config); err != nil {
		return nil, err
	}

	return &l3Config, nil
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

func (mnm *NodemapService) initDeviceConfig(deviceFilePath string) []config.DeviceConfig {
	yamlFile, err := os.ReadFile("../pkg/nodemap/example/sangfor_example/config.yaml")
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
			content, err = os.ReadFile(filepath.Join(deviceFilePath, device.FilePath))
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

func (mnm *NodemapService) preparePolicyDataForFrontend(matchedPolicies map[string][]nodemap.PolicyMatchResult) []structs.DevicePolicy {
	var policyDataList []structs.DevicePolicy
	for device, policies := range matchedPolicies {
		policyData := structs.DevicePolicy{
			Device:   device,
			Policies: make([]structs.PolicyDetails, 0, len(policies)),
		}

		for _, policyResult := range policies {
			policyDetails := structs.PolicyDetails{
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
				ObjectRelations: []structs.ObjectRelation{},
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
					objectType := mnm.getObjectType(line)
					objectCli := mnm.getObjectCLI(policyResult.Policy.Extended(), line, objectName)

					if objectCli != "" {
						relation := structs.ObjectRelation{
							Type:       objectType,
							Name:       objectName,
							CLI:        objectCli,
							PolicyLine: line,
						}
						policyDetails.ObjectRelations = append(policyDetails.ObjectRelations, relation)
					}
				} else {
					relation := structs.ObjectRelation{
						PolicyLine: line,
					}
					policyDetails.ObjectRelations = append(policyDetails.ObjectRelations, relation)
				}
			}

			// 添加匹配详情
			for matcherName, detail := range policyResult.MatchDetails {
				matchDetail := structs.MatchDetailInfo{
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

func (mnm *NodemapService) getObjectType(line string) string {
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
func (mnm *NodemapService) getObjectCLI(extended map[string]interface{}, line, objectName string) string {
	objectType := mnm.getObjectType(line)
	switch objectType {
	case "source-address-set", "source-address-object":
		return mnm.getCliFromObject(extended, "SrcObject", "SrcObjectCli", objectName)
	case "destination-address-set", "destination-address-object":
		return mnm.getCliFromObject(extended, "DstObject", "DstObjectCli", objectName)
	case "service-object":
		return mnm.getCliFromObject(extended, "SrvObject", "SrvObjectCli", objectName)
	}
	return ""
}

func (mnm *NodemapService) getCliFromObject(extended map[string]interface{}, objectKey, cliKey, objectName string) string {
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
