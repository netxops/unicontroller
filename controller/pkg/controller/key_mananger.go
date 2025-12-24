package controller

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/netxops/keys"
	clientv3 "go.etcd.io/etcd/client/v3"
	"gopkg.in/yaml.v2"
)

// Config 定义了控制器的配置
type Config struct {
	Upstream       Upstream               `yaml:"upstream"`
	BaseConfig     BaseConfig             `yaml:"base_config" json:"base_config"`
	GitConfig      GitConfig              `yaml:"git"`
	FunctionArea   string                 `yaml:"function_area" json:"function_area"`
	EtcdConfig     map[string]interface{} `yaml:"etcd" json:"etcd"`
	UseDockerEtcd  bool                   `yaml:"use_docker_etcd" json:"use_docker_etcd"` // 是否使用 Docker 启动 etcd，false 时使用外部 etcd，默认为 true（向后兼容）
	Telegraf       TelegrafConfig         `yaml:"telegraf" json:"telegraf"`
	Minio          MinioConfig            `yaml:"minio" json:"minio"`
	UniOpsConfig   UniOpsConfig           `yaml:"uniops" json:"uniops"`
	Database       DatabaseConfig         `yaml:"database" json:"database"`
	SyslogManager  SyslogManagerConfig    `yaml:"syslog_manager" json:"syslog_manager"`
	MetricsManager MetricsManagerConfig   `yaml:"metrics_manager" json:"metrics_manager"`
	Nacos          NacosConfig            `yaml:"nacos" json:"nacos"`
	Redis          RedisConfig            `yaml:"redis" json:"redis"`
	SkipInit       bool                   `yaml:"skip_init" json:"skip_init"`
}

type RedisConfig struct {
	Addresses []string `yaml:"addresses" json:"addresses"`
	DB        int      `yaml:"db" json:"db"`
	Password  string   `yaml:"password" json:"password"`
	PoolSize  int      `yaml:"pool_size" json:"pool_size"`
}

// 定义NacosConfig结构体
type NacosConfig struct {
	Server     string `yaml:"server" json:"server"`
	Port       int    `yaml:"port" json:"port"`
	Namespace  string `yaml:"namespace" json:"namespace"`
	Group      string `yaml:"group" json:"group"`
	AgentGroup string `yaml:"agent_group" json:"agent_group"`
	DataID     string `yaml:"data_id" json:"data_id"`
	Username   string `yaml:"username" json:"username"`
	Password   string `yaml:"password" json:"password"`
	LogDir     string `yaml:"log_dir" json:"log_dir"`
	CacheDir   string `yaml:"cache_dir" json:"cache_dir"`
	LogLevel   string `yaml:"log_level" json:"log_level"`
}

type Deployment struct {
	// Timeout               int `yaml:"timeout"`
	ConcurrentDeployments int `yaml:"concurrent_deployments"`
	// RetryAttempts         int `yaml:"retry_attempts"`
	// StatusUpdateInterval  int `yaml:"status_update_interval"`
	// LogRetentionDays      int `yaml:"log_retention_days"`
}

type Upstream struct {
	EtcdAddresses []string `yaml:"etcd_addresses"`
	Watch         string   `yaml:"watch"`
	Username      string   `yaml:"username"` // 新增
	Password      string   `yaml:"password"` // 新增
}

type BaseConfig struct {
	DefaultPort           int                            `yaml:"default_port"`
	Resources             map[models.ResourceType]string `yaml:"resources"`
	PrometheusLabelKey    string                         `yaml:"prometheusLabelKey"`
	LokiLabelKey          string                         `yaml:"lokiLabelKey"`
	HomePath              string                         `yaml:"home_path"`
	Templates             []string                       `yaml:"templates"`
	PreferredNetworks     []string                       `yaml:"preferred_networks"`
	SshProxy              int                            `yaml:"ssh_proxy"`
	GrpcProxy             int                            `yaml:"grpc_proxy"`
	Deployment            Deployment                     `yaml:"deployment"`
	LokiListenPath        string                         `yaml:"loki_listen_path"`
	PrometheusListenPath  string                         `yaml:"prometheus_listen_path"`
	UpstreamLokiUrl       string                         `yaml:"upstream_loki_url"`
	UpstreamPrometheusUrl string                         `yaml:"upstream_prometheus_url"`
	PipelineTemplates     string                         `yaml:"pipelineTemplates"`
	// FirewallTemplatePath 防火墙模板路径，默认为 "pkg/nodemap/node/device/firewall/common/v4/templates"
	FirewallTemplatePath string `yaml:"firewall_template_path" json:"firewall_template_path"`
	// JumpServer 连接空闲超时时间（秒），默认60秒，0表示禁用
	JumpServerIdleTimeout int `yaml:"jump_server_idle_timeout"`
}

type GitConfig struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Branch   string `yaml:"branch"`
}

type DatabaseConfig struct {
	Type        string `yaml:"type" json:"type"`                   // 数据库类型，这里应该是 "mongodb"
	URI         string `yaml:"uri" json:"uri"`                     // MongoDB 连接 URI
	Database    string `yaml:"database" json:"database"`           // 数据库名称
	MaxPoolSize uint64 `yaml:"max_pool_size" json:"max_pool_size"` // 连接池最大连接数
}

type UniOpsConfig struct {
	Address  string `yaml:"address"`
	Account  string `yaml:"account"`
	Password string `yaml:"password"`
}

type TelegrafConfig struct {
	Enable             *bool  `yaml:"enable" json:"enable"` // 是否启用TelegrafManager，nil表示未设置（默认启用），true表示启用，false表示禁用
	Image              string `yaml:"image"`
	Name               string `yaml:"name"`
	ConfigPath         string `yaml:"config_path" json:"config_path"`
	PrometheusPort     int    `yaml:"prometheus_port" json:"prometheus_port"`
	LokiEndpoint       string `yaml:"loki_endpoint" json:"loki_endpoint"`
	PrometheusEndpoint string `yaml:"prometheus_endpoint" json:"prometheus_endpoint"`
}

type MinioConfig struct {
	Endpoint        string `yaml:"endpoint" json:"endpoint"`
	AccessKeyID     string `yaml:"accessKeyID" json:"access_key_id"`
	SecretAccessKey string `yaml:"secretAccessKey" json:"secret_access_key"`
	UseSSL          bool   `yaml:"useSSL" json:"use_ssl"`
	BucketName      string `yaml:"bucketName" json:"bucketName"`
	ProxyAddr       string `yaml:"proxyAddr" json:"proxy_addr"`
}

// SyslogManagerConfig 定义了 Syslog 管理器的配置
type SyslogManagerConfig struct {
	Port         int    `yaml:"port" json:"port"`
	Protocol     string `yaml:"protocol" json:"protocol"`
	LokiEndpoint string `yaml:"loki_endpoint" json:"loki_endpoint"`
}

// MetricsManagerConfig 定义了指标管理器的配置
type MetricsManagerConfig struct {
	Port           int    `yaml:"port" json:"port"`
	RemoteWriteURL string `yaml:"remoteWriteurl" json:"remoteWriteurl"`
}

// LoadConfig 从指定的 YAML 文件加载配置
func LoadConfig(configPath string) (*Config, error) {
	filename, _ := filepath.Abs(configPath)
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %v", err)
	}

	// 验证必要的配置项
	if config.FunctionArea == "" {
		return nil, fmt.Errorf("area must be specified in config")
	}

	return &config, nil
}

// ProvideConfig 提供配置对象，从本地YAML文件加载
func ProvideConfig(configPath string) (*Config, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	return config, nil
}

type KeyManager struct {
	config *Config
}

// ProvideKeyManager 为 Wire 依赖注入提供的构造函数
func ProvideKeyManager(config *Config) (*KeyManager, error) {
	return NewKeyManager(config)
}

// ProvideEtcdClient 创建并返回一个 etcd 客户端
// 支持 Docker etcd 和外部 etcd
func ProvideEtcdClient(config *Config) (*clientv3.Client, error) {
	if config.EtcdConfig == nil {
		return nil, fmt.Errorf("etcd config is nil")
	}

	// 检查是否使用 Docker etcd
	useDockerEtcd := false
	if config.UseDockerEtcd {
		useDockerEtcd = true
	} else if etcdUseDocker, ok := config.EtcdConfig["use_docker_etcd"].(bool); ok {
		useDockerEtcd = etcdUseDocker
	}

	// 如果使用 Docker etcd，先尝试启动容器
	if useDockerEtcd {
		if err := ensureDockerEtcdRunning(config); err != nil {
			return nil, fmt.Errorf("failed to ensure Docker etcd container is running: %v", err)
		}
	}

	// 获取 etcd 地址
	var host string
	var port = 2379

	// 如果使用外部 etcd，host 应该指向外部 etcd 的地址
	// 如果使用 Docker etcd，host 通常是 localhost 或 127.0.0.1
	if config.EtcdConfig["host"] == nil {
		return nil, fmt.Errorf("invalid etcd config: host is required")
	}

	host = config.EtcdConfig["host"].(string)

	// 获取端口
	if hostPort, ok := config.EtcdConfig["hostPort"]; ok {
		switch v := hostPort.(type) {
		case int:
			port = v
		case int64:
			port = int(v)
		case float64:
			port = int(v)
		case string:
			if p, err := strconv.Atoi(v); err == nil {
				port = p
			}
		}
	}

	// 获取用户名和密码
	// 优先从 EtcdConfig 中读取，如果没有则从 Upstream 中读取
	var username, password string
	if etcdUsername, ok := config.EtcdConfig["username"].(string); ok && etcdUsername != "" {
		username = etcdUsername
	} else if config.Upstream.Username != "" {
		username = config.Upstream.Username
	}

	if etcdPassword, ok := config.EtcdConfig["password"].(string); ok && etcdPassword != "" {
		password = etcdPassword
	} else if config.Upstream.Password != "" {
		password = config.Upstream.Password
	}

	// 构建 etcd 客户端配置
	etcdConfig := clientv3.Config{
		DialTimeout: 5 * time.Second,
	}

	// 如果配置了用户名和密码，添加到配置中
	if username != "" {
		etcdConfig.Username = username
	}
	if password != "" {
		etcdConfig.Password = password
	}

	// 如果使用外部 etcd，可能配置中直接提供了 endpoints
	if endpoints, ok := config.EtcdConfig["endpoints"].([]interface{}); ok && len(endpoints) > 0 {
		endpointStrs := make([]string, 0, len(endpoints))
		for _, ep := range endpoints {
			if epStr, ok := ep.(string); ok {
				endpointStrs = append(endpointStrs, epStr)
			}
		}
		if len(endpointStrs) > 0 {
			etcdConfig.Endpoints = endpointStrs
			cli, err := clientv3.New(etcdConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create etcd client with endpoints: %v", err)
			}
			return cli, nil
		}
	}

	// 使用 host:port 方式连接
	endpoint := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	etcdConfig.Endpoints = []string{endpoint}

	// 如果使用 Docker etcd，需要等待容器启动
	// 因为 clientv3.New() 会立即尝试连接，如果容器未启动会失败
	if useDockerEtcd {
		log.Printf("Using Docker etcd, waiting for container to be ready on %s...", endpoint)
		// 等待 etcd 服务启动（最多等待60秒）
		maxWaitTime := 60 * time.Second
		checkInterval := 1 * time.Second
		startTime := time.Now()
		ready := false

		for time.Since(startTime) < maxWaitTime {
			// 先检查 TCP 连接
			conn, err := net.DialTimeout("tcp", endpoint, 1*time.Second)
			if err != nil {
				time.Sleep(checkInterval)
				continue
			}
			conn.Close()

			// TCP 连接成功，尝试创建临时 etcd 客户端验证服务是否可用
			testConfig := clientv3.Config{
				Endpoints:   []string{endpoint},
				DialTimeout: 2 * time.Second,
			}
			if username != "" {
				testConfig.Username = username
			}
			if password != "" {
				testConfig.Password = password
			}

			testClient, err := clientv3.New(testConfig)
			if err == nil {
				// 尝试执行一个简单的操作来验证 etcd 是否真的可用
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_, err = testClient.Get(ctx, "__health_check__")
				cancel()
				testClient.Close()

				if err == nil {
					ready = true
					log.Printf("Docker etcd container is ready and responding on %s", endpoint)
					break
				}
			}
			// 服务还未就绪，等待后重试
			time.Sleep(checkInterval)
		}

		if !ready {
			return nil, fmt.Errorf("docker etcd container is not ready on %s after waiting 60 seconds", endpoint)
		}
	}

	cli, err := clientv3.New(etcdConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %v", err)
	}
	return cli, nil
}

// ensureDockerEtcdRunning 确保 Docker etcd 容器正在运行
func ensureDockerEtcdRunning(config *Config) error {
	// 创建 Docker 客户端
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.41"))
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %v", err)
	}
	defer dockerClient.Close()

	// 获取容器名称
	containerName := "default_area_etcd" // 默认容器名
	if name, ok := config.EtcdConfig["name"].(string); ok && name != "" {
		containerName = name
	}

	ctx := context.Background()

	// 检查容器是否存在
	containers, err := dockerClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		// 检查是否为权限错误
		if strings.Contains(err.Error(), "permission denied") {
			log.Printf("Warning: Docker permission denied while trying to ensure etcd container, skipping: %v", err)
			// 权限错误时跳过，假设容器可能已经存在或由其他方式管理
			return nil
		}
		// 其他错误也记录警告并跳过
		log.Printf("Warning: Failed to list containers while ensuring etcd, skipping: %v", err)
		return nil
	}

	var containerID string
	for _, c := range containers {
		for _, n := range c.Names {
			if n == "/"+containerName {
				containerID = c.ID
				break
			}
		}
		if containerID != "" {
			break
		}
	}

	// 如果容器存在，检查状态并启动
	if containerID != "" {
		containerJSON, err := dockerClient.ContainerInspect(ctx, containerID)
		if err != nil {
			return fmt.Errorf("failed to inspect container: %v", err)
		}

		if containerJSON.State.Status != "running" {
			log.Printf("Starting existing etcd container %s...", containerName)
			if err := dockerClient.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
				return fmt.Errorf("failed to start container: %v", err)
			}
			log.Printf("Etcd container %s started", containerName)
		} else {
			log.Printf("Etcd container %s is already running", containerName)
		}
	} else {
		// 容器不存在，直接创建并启动
		log.Printf("Etcd container %s does not exist, creating it now...", containerName)
		if err := createAndStartEtcdContainer(dockerClient, config, containerName); err != nil {
			return fmt.Errorf("failed to create etcd container: %v", err)
		}
		log.Printf("Etcd container %s created and started", containerName)
	}

	return nil
}

// createAndStartEtcdContainer 创建并启动 etcd 容器
func createAndStartEtcdContainer(dockerClient *client.Client, config *Config, containerName string) error {
	ctx := context.Background()

	// 获取 etcd 配置
	etcdImage := "quay.io/coreos/etcd:v3.5.0"
	if image, ok := config.EtcdConfig["image"].(string); ok && image != "" {
		etcdImage = image
	}

	etcdPort := int64(2379)
	if port, ok := config.EtcdConfig["port"]; ok {
		switch v := port.(type) {
		case int:
			etcdPort = int64(v)
		case int64:
			etcdPort = v
		case float64:
			etcdPort = int64(v)
		}
	}

	etcdHostPort := int64(2379)
	if hostPort, ok := config.EtcdConfig["hostPort"]; ok {
		switch v := hostPort.(type) {
		case int:
			etcdHostPort = int64(v)
		case int64:
			etcdHostPort = v
		case float64:
			etcdHostPort = int64(v)
		}
	}

	dataDir := "/var/lib/etcd"
	if dir, ok := config.EtcdConfig["dataDir"].(string); ok && dir != "" {
		dataDir = dir
	}

	// 确保镜像存在
	_, _, err := dockerClient.ImageInspectWithRaw(ctx, etcdImage)
	if err != nil {
		if client.IsErrNotFound(err) {
			log.Printf("Image %s not found locally, attempting to pull...", etcdImage)
			out, err := dockerClient.ImagePull(ctx, etcdImage, image.PullOptions{})
			if err != nil {
				return fmt.Errorf("failed to pull image %s: %v", etcdImage, err)
			}
			defer out.Close()
			if _, err = io.Copy(io.Discard, out); err != nil {
				return fmt.Errorf("error while pulling image %s: %v", etcdImage, err)
			}
			log.Printf("Successfully pulled image %s", etcdImage)
		} else {
			return fmt.Errorf("error inspecting image %s: %v", etcdImage, err)
		}
	}

	// 准备容器配置
	containerConfig := &container.Config{
		Image: etcdImage,
		Cmd:   []string{"/usr/local/bin/etcd"},
		Labels: map[string]string{
			"resource_type": string(models.ResourceTypeEtcd),
		},
		Env: []string{
			fmt.Sprintf("ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:%d", etcdPort),
			fmt.Sprintf("ETCD_ADVERTISE_CLIENT_URLS=http://0.0.0.0:%d", etcdPort),
			fmt.Sprintf("ETCD_DATA_DIR=%s", dataDir),
			"ETCD_QUOTA_BACKEND_BYTES=8589934592", // 8GB quota (default is 2GB)
			"ETCD_AUTO_COMPACTION_MODE=revision",  // Enable auto compaction
			"ETCD_AUTO_COMPACTION_RETENTION=1000", // Keep last 1000 revisions
		},
	}

	// 准备主机配置（端口映射和卷）
	portBindings := nat.PortMap{
		nat.Port(fmt.Sprintf("%d/tcp", etcdPort)): []nat.PortBinding{
			{
				HostIP:   "0.0.0.0",
				HostPort: fmt.Sprintf("%d", etcdHostPort),
			},
		},
	}

	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		Binds: []string{
			fmt.Sprintf("%s:%s", dataDir, dataDir),
		},
		RestartPolicy: container.RestartPolicy{
			Name: "unless-stopped",
		},
	}

	// 创建容器
	resp, err := dockerClient.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, containerName)
	if err != nil {
		return fmt.Errorf("failed to create container: %v", err)
	}
	log.Printf("Successfully created etcd container with ID: %s", resp.ID)

	// 启动容器
	if err := dockerClient.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %v", err)
	}
	log.Printf("Successfully started etcd container %s", resp.ID)

	// 等待容器运行
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	timeout := 30 * time.Second
	startTime := time.Now()

	for time.Since(startTime) < timeout {
		<-ticker.C
		containerJSON, err := dockerClient.ContainerInspect(ctx, resp.ID)
		if err != nil {
			continue
		}
		if containerJSON.State.Status == "running" {
			return nil
		}
	}

	return fmt.Errorf("timeout waiting for etcd container to start")
}

func NewKeyManager(config *Config) (*KeyManager, error) {
	if config.FunctionArea == "" {
		return nil, fmt.Errorf("area must be specified in config")
	}
	return &KeyManager{config: config}, nil
}

func (km *KeyManager) GenerateResourceKey(resourceType, containerName string) (string, error) {
	if resourceType == "" {
		return "", fmt.Errorf("resourceType cannot be empty")
	}
	if containerName == "" {
		return "", fmt.Errorf("containerName cannot be empty")
	}

	return keys.NewKeyBuilder(km.config.FunctionArea, resourceType, containerName).Separator("/").String(), nil
}

func (km *KeyManager) ParseResourceKey(key string) (string, string, string, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid key format: %s", key)
	}
	area, resourceType, resourceID := parts[0], parts[1], parts[2]
	if area != km.config.FunctionArea {
		return "", "", "", fmt.Errorf("key is not from the current area: %s", key)
	}
	return area, resourceType, resourceID, nil
}

func (km *KeyManager) GenerateResourcePrefix(resourceType string) (string, error) {
	if resourceType == "" {
		return "", fmt.Errorf("resourceType cannot be empty")
	}
	return keys.NewKeyBuilder(km.config.FunctionArea, resourceType).Separator("/").String(), nil
}

// func (km *KeyManager) GenerateServiceKey(serviceName, serviceID string) (string, error) {
// 	if serviceName == "" {
// 		return "", fmt.Errorf("serviceName cannot be empty")
// 	}
// 	if serviceID == "" {
// 		return "", fmt.Errorf("serviceID cannot be empty")
// 	}

// 	return keys.NewKeyBuilder(km.config.Area, string(models.ResourceTypeService), serviceName, serviceID).Separator("/").String(), nil
// }

// func (km *KeyManager) ParseServiceKey(key string) (string, string, string, error) {
// 	parts := strings.Split(key, "/")
// 	if len(parts) != 4 {
// 		return "", "", "", fmt.Errorf("invalid key format: %s", key)
// 	}
// 	area, serviceName, serviceID := parts[0], parts[2], parts[3]
// 	if area != km.config.Area {
// 		return "", "", "", fmt.Errorf("key is not from the current area: %s", key)
// 	}
// 	return area, serviceName, serviceID, nil
// }

func (km *KeyManager) GenerateServiceKey(serviceName, hostIdentifier, port string) (string, error) {
	if serviceName == "" {
		return "", fmt.Errorf("serviceName cannot be empty")
	}
	if hostIdentifier == "" {
		return "", fmt.Errorf("hostIdentifier cannot be empty")
	}
	if port == "" {
		return "", fmt.Errorf("port cannot be empty")
	}

	serviceID := fmt.Sprintf("%s-%s-%s", serviceName, hostIdentifier, port)
	return keys.NewKeyBuilder(km.config.FunctionArea, string(models.ResourceTypeService), serviceName, serviceID).Separator("/").String(), nil
}

func (km *KeyManager) ParseServiceKey(key string) (string, string, string, string, string, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 {
		return "", "", "", "", "", fmt.Errorf("invalid key format: %s", key)
	}
	area, serviceName, serviceID := parts[0], parts[2], parts[3]
	if area != km.config.FunctionArea {
		return "", "", "", "", "", fmt.Errorf("key is not from the current area: %s", key)
	}

	// 解析 serviceID
	idParts := strings.Split(serviceID, "-")
	if len(idParts) != 3 {
		return "", "", "", "", "", fmt.Errorf("invalid serviceID format: %s", serviceID)
	}
	hostIdentifier, port := idParts[1], idParts[2]

	return area, serviceName, serviceID, hostIdentifier, port, nil
}

// func (km *KeyManager) GenerateServicePrefix(serviceName string) (string, error) {
// 	if serviceName == "" {
// 		return "", fmt.Errorf("serviceName cannot be empty")
// 	}
// 	return keys.NewKeyBuilder(km.config.Area, string(models.ResourceTypeService), serviceName).Separator("/").String(), nil
// }

func (km *KeyManager) GenerateServicePrefix(serviceName string) (string, error) {
	if serviceName == "" {
		return "", fmt.Errorf("serviceName cannot be empty")
	}

	return keys.NewKeyBuilder(km.config.FunctionArea, string(models.ResourceTypeService), serviceName).Separator("/").String(), nil
}
