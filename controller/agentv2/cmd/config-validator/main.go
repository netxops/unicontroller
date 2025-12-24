package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	clientv3 "go.etcd.io/etcd/client/v3"
)

var (
	configPath = flag.String("config", "", "Path to agent configuration file (required)")
	verbose    = flag.Bool("verbose", false, "Enable verbose output")
	testEtcd   = flag.Bool("test-etcd", true, "Test etcd connection")
	outputJSON = flag.Bool("json", false, "Output results in JSON format")
)

type ValidationResult struct {
	Valid       bool               `json:"valid"`
	Errors      []string           `json:"errors,omitempty"`
	Warnings    []string           `json:"warnings,omitempty"`
	Config      *config.Config     `json:"config,omitempty"`
	EtcdTest    *EtcdTestResult    `json:"etcd_test,omitempty"`
	NetworkTest *NetworkTestResult `json:"network_test,omitempty"`
	Summary     string             `json:"summary"`
}

type EtcdTestResult struct {
	Connected bool     `json:"connected"`
	Error     string   `json:"error,omitempty"`
	Endpoints []string `json:"endpoints"`
	HasAuth   bool     `json:"has_auth"`
	KeysFound []string `json:"keys_found,omitempty"`
}

type NetworkTestResult struct {
	EtcdReachable bool   `json:"etcd_reachable"`
	EtcdError     string `json:"etcd_error,omitempty"`
	PortAvailable bool   `json:"port_available"`
	PortError     string `json:"port_error,omitempty"`
}

func main() {
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "Error: -config flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	result := validateConfig(*configPath)

	if *outputJSON {
		outputJSONResult(result)
	} else {
		outputTextResult(result)
	}

	if !result.Valid {
		os.Exit(1)
	}
}

func validateConfig(configPath string) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// 1. 加载配置文件
	cfg, err := config.Load(configPath)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to load config: %v", err))
		return result
	}
	result.Config = cfg

	// 2. 验证基本配置
	validateBasicConfig(cfg, result)

	// 3. 验证注册配置
	validateRegistryConfig(cfg, result)

	// 4. 测试etcd连接
	if *testEtcd && cfg.Registry.Enabled {
		result.EtcdTest = testEtcdConnection(cfg)
		if !result.EtcdTest.Connected {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Etcd connection failed: %s", result.EtcdTest.Error))
		}
	}

	// 5. 测试网络连接
	result.NetworkTest = testNetworkConnectivity(cfg)

	// 6. 生成摘要
	result.Summary = generateSummary(result)

	return result
}

func validateBasicConfig(cfg *config.Config, result *ValidationResult) {
	// 验证Agent配置
	if cfg.Agent.Code == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "agent.code is required")
	} else if len(cfg.Agent.Code) < 3 {
		result.Warnings = append(result.Warnings, "agent.code is too short (minimum 3 characters)")
	}

	// 验证服务器配置
	if cfg.Server.GRPCPort <= 0 || cfg.Server.GRPCPort > 65535 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("server.grpc_port must be between 1 and 65535, got %d", cfg.Server.GRPCPort))
	}

	if cfg.Server.HTTPPort <= 0 || cfg.Server.HTTPPort > 65535 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("server.http_port must be between 1 and 65535, got %d", cfg.Server.HTTPPort))
	}

	if cfg.Server.GRPCPort == cfg.Server.HTTPPort {
		result.Valid = false
		result.Errors = append(result.Errors, "server.grpc_port and server.http_port cannot be the same")
	}

	// 验证工作目录
	if cfg.Agent.Workspace != "" {
		if info, err := os.Stat(cfg.Agent.Workspace); err != nil {
			if os.IsNotExist(err) {
				result.Warnings = append(result.Warnings, fmt.Sprintf("agent.workspace does not exist: %s", cfg.Agent.Workspace))
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Cannot access agent.workspace: %v", err))
			}
		} else if !info.IsDir() {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("agent.workspace is not a directory: %s", cfg.Agent.Workspace))
		}
	}
}

func validateRegistryConfig(cfg *config.Config, result *ValidationResult) {
	if !cfg.Registry.Enabled {
		result.Warnings = append(result.Warnings, "registry.enabled is false, Agent will not register to etcd")
		return
	}

	// 验证etcd端点
	if len(cfg.Registry.EtcdEndpoints) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "registry.etcd_endpoints is required when registry is enabled")
		return
	}

	// 验证每个端点格式
	for i, endpoint := range cfg.Registry.EtcdEndpoints {
		if endpoint == "" {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("registry.etcd_endpoints[%d] is empty", i))
			continue
		}

		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("registry.etcd_endpoints[%d] has invalid format: %v", i, err))
			continue
		}

		if host == "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("registry.etcd_endpoints[%d] has empty host, using localhost", i))
		}
	}

	// 验证认证配置
	hasUsername := cfg.Registry.EtcdUsername != ""
	hasPassword := cfg.Registry.EtcdPassword != ""

	if hasUsername && !hasPassword {
		result.Warnings = append(result.Warnings, "registry.etcd_username is set but etcd_password is empty")
	}
	if hasPassword && !hasUsername {
		result.Warnings = append(result.Warnings, "registry.etcd_password is set but etcd_username is empty")
	}

	// 验证注册间隔和TTL
	if cfg.Registry.RegisterInterval <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "registry.register_interval must be greater than 0")
	}

	if cfg.Registry.TTL <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "registry.ttl must be greater than 0")
	}

	if cfg.Registry.TTL <= cfg.Registry.RegisterInterval {
		result.Warnings = append(result.Warnings, fmt.Sprintf("registry.ttl (%v) should be greater than register_interval (%v) to avoid expiration", cfg.Registry.TTL, cfg.Registry.RegisterInterval))
	}

	// 建议TTL至少是注册间隔的2倍
	if cfg.Registry.TTL < cfg.Registry.RegisterInterval*2 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("registry.ttl (%v) is recommended to be at least 2x register_interval (%v)", cfg.Registry.TTL, cfg.Registry.RegisterInterval))
	}
}

func testEtcdConnection(cfg *config.Config) *EtcdTestResult {
	result := &EtcdTestResult{
		Endpoints: cfg.Registry.EtcdEndpoints,
		HasAuth:   cfg.Registry.EtcdUsername != "" && cfg.Registry.EtcdPassword != "",
	}

	// 创建etcd客户端配置
	etcdConfig := clientv3.Config{
		Endpoints:   cfg.Registry.EtcdEndpoints,
		DialTimeout: 5 * time.Second,
	}

	if cfg.Registry.EtcdUsername != "" && cfg.Registry.EtcdPassword != "" {
		etcdConfig.Username = cfg.Registry.EtcdUsername
		etcdConfig.Password = cfg.Registry.EtcdPassword
	}

	// 创建客户端
	client, err := clientv3.New(etcdConfig)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create etcd client: %v", err)
		return result
	}
	defer client.Close()

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.Status(ctx, cfg.Registry.EtcdEndpoints[0])
	if err != nil {
		result.Error = fmt.Sprintf("Failed to connect to etcd: %v", err)
		return result
	}

	result.Connected = true

	// 尝试查找已注册的Agent
	if *verbose {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel2()

		resp, err := client.Get(ctx2, "grpc://server-agent/", clientv3.WithPrefix(), clientv3.WithKeysOnly())
		if err == nil {
			for _, kv := range resp.Kvs {
				result.KeysFound = append(result.KeysFound, string(kv.Key))
			}
		}
	}

	return result
}

func testNetworkConnectivity(cfg *config.Config) *NetworkTestResult {
	result := &NetworkTestResult{}

	// 测试etcd连接
	if cfg.Registry.Enabled && len(cfg.Registry.EtcdEndpoints) > 0 {
		endpoint := cfg.Registry.EtcdEndpoints[0]
		host, port, err := net.SplitHostPort(endpoint)
		if err == nil {
			if host == "" || host == "127.0.0.1" || host == "localhost" {
				host = "127.0.0.1"
			}

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
			if err != nil {
				result.EtcdReachable = false
				result.EtcdError = err.Error()
			} else {
				result.EtcdReachable = true
				conn.Close()
			}
		} else {
			result.EtcdReachable = false
			result.EtcdError = fmt.Sprintf("Invalid endpoint format: %v", err)
		}
	}

	// 测试gRPC端口是否可用（检查是否被占用）
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		result.PortAvailable = false
		result.PortError = fmt.Sprintf("Port %d is already in use", cfg.Server.GRPCPort)
	} else {
		result.PortAvailable = true
		listener.Close()
	}

	return result
}

func generateSummary(result *ValidationResult) string {
	if !result.Valid {
		return fmt.Sprintf("Configuration validation FAILED with %d error(s)", len(result.Errors))
	}

	warnings := len(result.Warnings)
	if warnings > 0 {
		return fmt.Sprintf("Configuration validation PASSED with %d warning(s)", warnings)
	}

	return "Configuration validation PASSED"
}

func outputTextResult(result *ValidationResult) {
	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Println("Agent Configuration Validator")
	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Println()

	// 显示配置信息
	if result.Config != nil {
		fmt.Println("Configuration:")
		fmt.Printf("  Agent Code:     %s\n", result.Config.Agent.Code)
		fmt.Printf("  Workspace:      %s\n", result.Config.Agent.Workspace)
		fmt.Printf("  gRPC Port:       %d\n", result.Config.Server.GRPCPort)
		fmt.Printf("  HTTP Port:       %d\n", result.Config.Server.HTTPPort)
		fmt.Printf("  Registry:       %v\n", result.Config.Registry.Enabled)
		if result.Config.Registry.Enabled {
			fmt.Printf("  Etcd Endpoints:  %v\n", result.Config.Registry.EtcdEndpoints)
			fmt.Printf("  Etcd Auth:       %v\n", result.Config.Registry.EtcdUsername != "")
			fmt.Printf("  Register Interval: %v\n", result.Config.Registry.RegisterInterval)
			fmt.Printf("  TTL:             %v\n", result.Config.Registry.TTL)
		}
		fmt.Println()
	}

	// 显示错误
	if len(result.Errors) > 0 {
		fmt.Println("Errors:")
		for i, err := range result.Errors {
			fmt.Printf("  [%d] %s\n", i+1, err)
		}
		fmt.Println()
	}

	// 显示警告
	if len(result.Warnings) > 0 {
		fmt.Println("Warnings:")
		for i, warn := range result.Warnings {
			fmt.Printf("  [%d] %s\n", i+1, warn)
		}
		fmt.Println()
	}

	// 显示etcd测试结果
	if result.EtcdTest != nil {
		fmt.Println("Etcd Connection Test:")
		if result.EtcdTest.Connected {
			fmt.Printf("  Status:         ✓ Connected\n")
			fmt.Printf("  Endpoints:     %v\n", result.EtcdTest.Endpoints)
			fmt.Printf("  Authentication: %v\n", result.EtcdTest.HasAuth)
			if len(result.EtcdTest.KeysFound) > 0 {
				fmt.Printf("  Existing Agents: %d found\n", len(result.EtcdTest.KeysFound))
				if *verbose {
					for _, key := range result.EtcdTest.KeysFound {
						fmt.Printf("    - %s\n", key)
					}
				}
			}
		} else {
			fmt.Printf("  Status:         ✗ Failed\n")
			fmt.Printf("  Error:          %s\n", result.EtcdTest.Error)
		}
		fmt.Println()
	}

	// 显示网络测试结果
	if result.NetworkTest != nil {
		fmt.Println("Network Connectivity Test:")
		if result.NetworkTest.EtcdReachable {
			fmt.Printf("  Etcd:          ✓ Reachable\n")
		} else {
			fmt.Printf("  Etcd:          ✗ Not reachable: %s\n", result.NetworkTest.EtcdError)
		}
		if result.NetworkTest.PortAvailable {
			fmt.Printf("  gRPC Port:     ✓ Available\n")
		} else {
			fmt.Printf("  gRPC Port:     ✗ %s\n", result.NetworkTest.PortError)
		}
		fmt.Println()
	}

	// 显示摘要
	fmt.Println("=" + strings.Repeat("=", 70))
	if result.Valid {
		fmt.Printf("✓ %s\n", result.Summary)
	} else {
		fmt.Printf("✗ %s\n", result.Summary)
	}
	fmt.Println("=" + strings.Repeat("=", 70))
}

func outputJSONResult(result *ValidationResult) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
