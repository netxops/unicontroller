package detector

import (
	"time"

	"github.com/netxops/netlink/structs"
)

// DetectionRequest 检测请求
type DetectionRequest struct {
	IP                string
	SNMPCommunity     string
	SSHCredentials    *SSHCredentials
	TelnetCredentials *TelnetCredentials
}

// SSHCredentials SSH凭证
type SSHCredentials struct {
	Username   string
	Password   string
	Port       int
	PrivateKey string
}

// TelnetCredentials TELNET凭证
type TelnetCredentials struct {
	Username string
	Password string
	Port     int
}

// DetectionResult 检测结果
type DetectionResult struct {
	Manufacturer string                `json:"manufacturer"`
	Platform     string                `json:"platform"`
	Version      string                `json:"version"`
	Catalog      string                `json:"catalog"`
	Confidence   float64               `json:"confidence"`
	DeviceConfig *structs.DeviceConfig `json:"device_config,omitempty"`
	Errors       []error               `json:"errors,omitempty"`
	DetectedAt   time.Time             `json:"detected_at"`
}

// DetectionRule 检测规则
type DetectionRule struct {
	Name           string              `yaml:"name"`
	Manufacturer   string              `yaml:"manufacturer"`
	Platform       string              `yaml:"platform"`
	Catalog        string              `yaml:"catalog"`
	Priority       int                 `yaml:"priority"`
	Patterns       []Pattern           `yaml:"patterns"`
	VersionExtract *VersionExtractRule `yaml:"versionExtract,omitempty"`
	Score          float64             // 运行时计算的匹配分数
}

// Pattern 匹配模式
type Pattern struct {
	Source     string  `yaml:"source"`
	Regex      string  `yaml:"regex"`
	Confidence float64 `yaml:"confidence"`
	Required   bool    `yaml:"required"`
}

// VersionExtractRule 版本提取规则
type VersionExtractRule struct {
	Source string   `yaml:"source"`
	Regex  string   `yaml:"regex"`
	Groups []string `yaml:"groups"`
}

// ConnectivityCheckConfig 连接检测配置
type ConnectivityCheckConfig struct {
	Name      string           `yaml:"name"`
	Timeout   string           `yaml:"timeout"`
	Protocols []ProtocolConfig `yaml:"protocols"`
}

// ProtocolConfig 协议配置
type ProtocolConfig struct {
	Name     string      `yaml:"name"`
	Enabled  bool        `yaml:"enabled"`
	Check    CheckConfig `yaml:"check"`
	Priority int         `yaml:"priority"`
}

// CheckConfig 检测配置
type CheckConfig struct {
	Type    string `yaml:"type"`
	OID     string `yaml:"oid,omitempty"`
	Port    int    `yaml:"port,omitempty"`
	Timeout string `yaml:"timeout"`
	Retries int    `yaml:"retries"`
}

// DeviceInfoCollectConfig 设备信息采集配置
type DeviceInfoCollectConfig struct {
	Name       string            `yaml:"name"`
	Timeout    string            `yaml:"timeout"`
	Retries    int               `yaml:"retries"`
	Strategies []CollectStrategy `yaml:"strategies"`
}

// CollectStrategy 采集策略
type CollectStrategy struct {
	Name       string        `yaml:"name"`
	Priority   int           `yaml:"priority"`
	Conditions []Condition   `yaml:"conditions"`
	Collect    []CollectItem `yaml:"collect"`
}

// Condition 条件
type Condition struct {
	Protocol  string `yaml:"protocol"`
	Available bool   `yaml:"available"`
}

// CollectItem 采集项
type CollectItem struct {
	Name       string          `yaml:"name"`
	Type       string          `yaml:"type"`
	Method     string          `yaml:"method"`
	Target     string          `yaml:"target"`
	Timeout    string          `yaml:"timeout"`
	Output     string          `yaml:"output"` // 可以是单个字段或多个字段（逗号分隔）
	Required   bool            `yaml:"required"`
	Fallback   []FallbackItem  `yaml:"fallback,omitempty"`
	SNMPConfig *SNMPItemConfig `yaml:"snmpConfig,omitempty"` // SNMP特定配置
	SSHConfig  *SSHItemConfig  `yaml:"sshConfig,omitempty"`  // SSH特定配置
}

// SNMPItemConfig SNMP采集项配置
type SNMPItemConfig struct {
	IndexPositions      []int             `yaml:"indexPositions"`
	ClassifierPositions []int             `yaml:"classifierPositions"`
	PrefixMap           map[string]string `yaml:"prefixMap"`
}

// SSHItemConfig SSH采集项配置
type SSHItemConfig struct {
	Port    int    `yaml:"port,omitempty"`
	Timeout string `yaml:"timeout,omitempty"`
}

// FallbackItem 备选采集项
type FallbackItem struct {
	Target string `yaml:"target"`
}

// ConfigMatcherConfig 配置匹配器配置
type ConfigMatcherConfig struct {
	Name            string             `yaml:"name"`
	Strategies      []MatchingStrategy `yaml:"strategies"`
	VersionMappings []VersionMapping   `yaml:"versionMappings,omitempty"`
	DefaultConfigs  map[string]string  `yaml:"defaultConfigs,omitempty"`
}

// MatchingStrategy 匹配策略
type MatchingStrategy struct {
	Name             string                    `yaml:"name"`
	Priority         int                       `yaml:"priority"`
	Match            MatchConfig               `yaml:"match"`
	PathTemplate     string                    `yaml:"pathTemplate"`
	Fallback         []FallbackPath            `yaml:"fallback,omitempty"`
	DefaultPlatforms map[string]string         `yaml:"defaultPlatforms,omitempty"`
	CatalogDefaults  map[string]CatalogDefault `yaml:"catalogDefaults,omitempty"`
}

// MatchConfig 匹配配置
type MatchConfig struct {
	Manufacturer string `yaml:"manufacturer"`
	Platform     string `yaml:"platform"`
	Version      string `yaml:"version"`
	Catalog      string `yaml:"catalog"`
}

// FallbackPath 备选路径
type FallbackPath struct {
	PathTemplate string `yaml:"pathTemplate"`
}

// CatalogDefault 分类默认值
type CatalogDefault struct {
	Manufacturer string `yaml:"manufacturer"`
	Platform     string `yaml:"platform"`
}

// VersionMapping 版本映射
type VersionMapping struct {
	Pattern  string `yaml:"pattern"`
	Template string `yaml:"template"`
}

// ProtocolResult 协议检测结果
type ProtocolResult struct {
	Protocol  string
	Available bool
	Error     error
}

// CollectedData 采集的数据
type CollectedData map[string]string
