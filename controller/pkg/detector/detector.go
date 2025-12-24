package detector

import (
	"fmt"
	"log"
	"time"

	ps "github.com/netxops/netlink/service"
)

// DeviceDetector 设备检测器
// MVP: 模块化设计，配置驱动
type DeviceDetector struct {
	templatePath        string
	connectivityChecker *ConnectivityChecker // 连接检测模块
	infoCollector       *InfoCollector       // 信息采集模块
	ruleLoader          *RuleLoader          // 规则匹配模块
	versionExtractor    *VersionExtractor    // 版本提取模块
	configMatcher       *ConfigMatcher       // 配置匹配模块
	cache               *DetectionCache      // 缓存模块
	pipelineService     *ps.PipelineService  // Pipeline服务
}

// NewDeviceDetector 创建设备检测器
// MVP: 初始化所有模块化组件
func NewDeviceDetector(templatePath string) (*DeviceDetector, error) {
	// 创建连接检测器（配置驱动）
	connectivityChecker, err := NewConnectivityChecker(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create connectivity checker: %w", err)
	}

	// 创建信息采集器（配置驱动）
	infoCollector, err := NewInfoCollector(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create info collector: %w", err)
	}

	// 创建规则加载器
	ruleLoader, err := NewRuleLoader(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule loader: %w", err)
	}

	// 创建版本提取器
	versionExtractor := NewVersionExtractor()

	// 创建PipelineService
	pipelineService := ps.NewPipelineService(templatePath)

	// 创建配置匹配器
	configMatcher, err := NewConfigMatcher(templatePath, pipelineService)
	if err != nil {
		return nil, fmt.Errorf("failed to create config matcher: %w", err)
	}

	// 创建缓存（TTL: 1小时）
	cache := NewDetectionCache(1 * time.Hour)

	return &DeviceDetector{
		templatePath:        templatePath,
		connectivityChecker: connectivityChecker,
		infoCollector:       infoCollector,
		ruleLoader:          ruleLoader,
		versionExtractor:    versionExtractor,
		configMatcher:       configMatcher,
		cache:               cache,
		pipelineService:     pipelineService,
	}, nil
}

// Detect 执行设备检测
// MVP: 使用模块化组件，配置驱动的检测流程
func (dd *DeviceDetector) Detect(req *DetectionRequest) (*DetectionResult, error) {
	// 1. 检查缓存
	if cached, exists := dd.cache.Get(req.IP); exists {
		log.Printf("Using cached detection result for %s", req.IP)
		return cached, nil
	}

	// 2. 连接检测（配置驱动）
	protocols, err := dd.connectivityChecker.Check(req)
	if err != nil {
		return nil, fmt.Errorf("connectivity check failed: %w", err)
	}

	// 检查是否有可用协议
	if len(protocols) == 0 {
		log.Printf("No available protocols for %s, but continuing with available credentials", req.IP)
		// 即使没有检测到协议，也尝试使用提供的凭证进行采集
		// 这样可以处理SNMP未开启但SSH可用的情况
		if req.SSHCredentials != nil {
			protocols["SSH"] = true
		}
		if req.TelnetCredentials != nil {
			protocols["TELNET"] = true
		}
		if req.SNMPCommunity != "" {
			protocols["SNMP"] = true
		}
	}

	// 3. 信息采集（配置驱动）
	collectedData, err := dd.infoCollector.Collect(req, protocols)
	if err != nil {
		log.Printf("Info collection had errors but continuing: %v", err)
		// 即使采集有错误，也继续尝试规则匹配（可能部分数据已采集成功）
	}

	// 检查是否采集到任何数据
	if len(collectedData) == 0 {
		return nil, fmt.Errorf("no data collected from %s, available protocols: %v", req.IP, protocols)
	}

	// 4. 规则匹配
	detectionResult, err := dd.ruleLoader.MatchRules(collectedData)
	if err != nil {
		return nil, fmt.Errorf("rule matching failed: %w", err)
	}

	// 5. 版本提取（基于规则配置）
	if detectionResult != nil {
		// 从匹配的规则中提取版本
		matchedRule := dd.ruleLoader.GetMatchedRule(collectedData)
		if matchedRule != nil && matchedRule.VersionExtract != nil {
			if version := dd.versionExtractor.Extract(collectedData, matchedRule); version != "" {
				detectionResult.Version = version
			}
		}
	}

	// 6. 配置匹配
	deviceConfig, err := dd.configMatcher.Match(
		detectionResult.Manufacturer,
		detectionResult.Platform,
		detectionResult.Version,
		detectionResult.Catalog,
	)
	if err == nil && deviceConfig != nil {
		detectionResult.DeviceConfig = deviceConfig
	} else {
		detectionResult.Errors = append(detectionResult.Errors, fmt.Errorf("config matching failed: %w", err))
	}

	// 7. 缓存结果
	dd.cache.Set(req.IP, detectionResult)

	return detectionResult, nil
}

// 注意：旧的硬编码方法已移除，现在使用模块化组件：
// - ConnectivityChecker: 连接检测（配置驱动）
// - InfoCollector: 信息采集（配置驱动）
// - VersionExtractor: 版本提取（基于规则配置）

// VerifyDetection 验证检测结果
func (dd *DeviceDetector) VerifyDetection(req *DetectionRequest, result *DetectionResult) error {
	// 可选：执行一次完整的采集来验证检测结果
	// 这里可以执行一个简单的采集任务来确认设备类型
	return nil
}
