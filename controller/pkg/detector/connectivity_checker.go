package detector

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
)

// ConnectivityChecker 连接检测器
// MVP: 基于配置文件的连接检测模块
type ConnectivityChecker struct {
	config *ConnectivityCheckConfig
}

// NewConnectivityChecker 创建连接检测器
func NewConnectivityChecker(templatePath string) (*ConnectivityChecker, error) {
	config, err := loadConnectivityConfig(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load connectivity config: %w", err)
	}

	return &ConnectivityChecker{
		config: config,
	}, nil
}

// Check 检测设备连接性
// 基于配置文件中的协议配置进行检测
func (cc *ConnectivityChecker) Check(req *DetectionRequest) (map[string]bool, error) {
	protocols := make(map[string]bool)

	// 按优先级排序协议
	sortedProtocols := make([]ProtocolConfig, 0, len(cc.config.Protocols))
	for _, proto := range cc.config.Protocols {
		if proto.Enabled {
			sortedProtocols = append(sortedProtocols, proto)
		}
	}

	// 简单排序（按priority）
	for i := 0; i < len(sortedProtocols)-1; i++ {
		for j := i + 1; j < len(sortedProtocols); j++ {
			if sortedProtocols[i].Priority > sortedProtocols[j].Priority {
				sortedProtocols[i], sortedProtocols[j] = sortedProtocols[j], sortedProtocols[i]
			}
		}
	}

	// 根据配置检测每个协议
	for _, proto := range sortedProtocols {
		available, err := cc.checkProtocol(req, proto)
		if err != nil {
			log.Printf("Protocol %s check failed: %v", proto.Name, err)
			continue
		}
		if available {
			protocols[proto.Name] = true
			log.Printf("Protocol %s is available for %s", proto.Name, req.IP)
		}
	}

	return protocols, nil
}

// checkProtocol 检测单个协议
func (cc *ConnectivityChecker) checkProtocol(req *DetectionRequest, proto ProtocolConfig) (bool, error) {
	switch proto.Check.Type {
	case "SNMP":
		// SNMP检测：需要community，如果没有提供则跳过（不返回错误）
		if req.SNMPCommunity == "" {
			log.Printf("SNMP community not provided, skipping SNMP check for %s", req.IP)
			return false, nil // 返回false但不报错，允许其他协议继续检测
		}
		// 简单的SNMP可达性检测（可以通过实际SNMP Get来检测）
		// TODO: 实现实际的SNMP Get检测
		// 目前假设如果提供了community就认为可用（实际会在采集时验证）
		return true, nil

	case "TCP":
		// TCP端口检测
		port := proto.Check.Port
		if port == 0 {
			// 根据协议名称设置默认端口
			switch proto.Name {
			case "SSH":
				if req.SSHCredentials != nil && req.SSHCredentials.Port > 0 {
					port = req.SSHCredentials.Port
				} else {
					port = 22
				}
			case "TELNET":
				if req.TelnetCredentials != nil && req.TelnetCredentials.Port > 0 {
					port = req.TelnetCredentials.Port
				} else {
					port = 23
				}
			}
		}
		// 如果协议需要凭证但未提供，跳过检测
		if proto.Name == "SSH" && req.SSHCredentials == nil {
			log.Printf("SSH credentials not provided, skipping SSH check for %s", req.IP)
			return false, nil
		}
		if proto.Name == "TELNET" && req.TelnetCredentials == nil {
			log.Printf("TELNET credentials not provided, skipping TELNET check for %s", req.IP)
			return false, nil
		}
		available := cc.isPortOpen(req.IP, port, parseTimeout(proto.Check.Timeout))
		return available, nil

	default:
		return false, fmt.Errorf("unsupported check type: %s", proto.Check.Type)
	}
}

// isPortOpen 检测端口是否开放
func (cc *ConnectivityChecker) isPortOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// loadConnectivityConfig 加载连接检测配置
func loadConnectivityConfig(templatePath string) (*ConnectivityCheckConfig, error) {
	configPath := filepath.Join(templatePath, "detect/connectivity_check.yaml")
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read connectivity config: %w", err)
	}

	var config ConnectivityCheckConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal connectivity config: %w", err)
	}

	return &config, nil
}

// parseTimeout 解析超时时间字符串
func parseTimeout(timeoutStr string) time.Duration {
	if timeoutStr == "" {
		return 5 * time.Second // 默认5秒
	}

	duration, err := time.ParseDuration(timeoutStr)
	if err != nil {
		log.Printf("Failed to parse timeout %s, using default 5s", timeoutStr)
		return 5 * time.Second
	}

	return duration
}
