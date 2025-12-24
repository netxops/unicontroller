package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/douyu/jupiter/pkg/server"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/keys"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// const ControllerServiceName = "agent-controller"
// const DefaultControllId = "controller-1"

type Controller struct {
	ConfigManager         *ConfigManager
	ResourceManager       *ResourceManager
	RegistryManager       *RegistryManager
	KeyManager            *KeyManager
	MinioManager          *MinioManager
	DeploymentManager     *DeploymentManager
	mongoClient           *mongo.Client
	AgentManager          *AgentManager
	JumperServerManager   *JumperServerManager
	GrpcProxyManager      *GrpcProxyManager
	LokiForwarder         *LokiForwarder
	PrometheusForwarder   *PrometheusForwarder
	TelegrafManager       *TelegrafManager
	RedisManager          *RedisManager
	MonitoringService     *MonitoringService
	PluginTemplateService *PluginTemplateService
	ctx                   context.Context
	cancel                context.CancelFunc
	serviceInfo           *models.ServiceInfo
	upstreamEtcdClient    *clientv3.Client
	upstreamEtcdMu        sync.RWMutex // 保护 upstreamEtcdClient 的并发访问
	startTime             time.Time
	version               string
	id                    string
	// installMutex        sync.Mutex
	// isInstalling        bool
}

// ProvideController 为 Wire 依赖注入提供的构造函数
func ProvideController(
	cm *ConfigManager,
	rm *ResourceManager,
	regm *RegistryManager,
	km *KeyManager,
	mm *MinioManager,
	ds *DeploymentManager,
	mongoClient *mongo.Client,
	am *AgentManager,
	jpm *JumperServerManager,
	gpm *GrpcProxyManager,
	lf *LokiForwarder,
	pf *PrometheusForwarder,
	tgm *TelegrafManager,
	rd *RedisManager,
	ms *MonitoringService,
	pts *PluginTemplateService,
	// slm *SyslogManager,
	// msm *MetricsManager,
) (*Controller, error) {
	return &Controller{
		ConfigManager:         cm,
		ResourceManager:       rm,
		RegistryManager:       regm,
		KeyManager:            km,
		MinioManager:          mm,
		DeploymentManager:     ds,
		mongoClient:           mongoClient,
		AgentManager:          am,
		JumperServerManager:   jpm,
		GrpcProxyManager:      gpm,
		LokiForwarder:         lf,
		PrometheusForwarder:   pf,
		TelegrafManager:       tgm,
		RedisManager:          rd,
		MonitoringService:     ms,
		PluginTemplateService: pts,
	}, nil
}

type controllerOption struct {
	Port int
}

type controllerOptionFunc func(*controllerOption)

func WithPort(port int) controllerOptionFunc {
	return func(o *controllerOption) {
		o.Port = port
	}
}

func (c *Controller) Start(options ...controllerOptionFunc) error {
	var opts controllerOption
	for _, opt := range options {
		opt(&opts)
	}

	port := c.ConfigManager.Config.BaseConfig.DefaultPort

	if opts.Port != 0 {
		port = opts.Port
	}

	c.startTime = time.Now()
	c.version = Version
	c.id = c.RegistryManager.HostIdentifier
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if err := c.ResourceManager.ClearContainers(); err != nil {
		return fmt.Errorf("failed to clear containers: %v", err)
	}
	// 需要优先启动 ResourceManager
	if err := c.ResourceManager.Start(); err != nil {
		return fmt.Errorf("failed to start resource manager: %v", err)
	}
	if err := c.ConfigManager.Start(); err != nil {
		return fmt.Errorf("failed to start config manager: %v", err)
	}
	if err := c.RedisManager.Start(); err != nil {
		return fmt.Errorf("failed to start redis manager: %v", err)
	}

	if err := c.RegistryManager.Start(); err != nil {
		return fmt.Errorf("failed to start registry manager: %v", err)
	}
	if err := c.MinioManager.Start(); err != nil {
		return fmt.Errorf("failed to start minio manager: %v", err)
	}
	if err := c.AgentManager.Start(); err != nil {
		return fmt.Errorf("failed to start agent manager: %v", err)
	}
	if err := c.JumperServerManager.Start(); err != nil {
		return fmt.Errorf("failed to start jumper server manager: %v", err)
	}
	if err := c.GrpcProxyManager.Start(); err != nil {
		return fmt.Errorf("failed to start gRPC proxy manager: %v", err)
	}
	if c.TelegrafManager != nil {
		if err := c.TelegrafManager.Start(); err != nil {
			return fmt.Errorf("failed to start telegraf manager: %v", err)
		}
	}
	// 初始化预设模板
	if c.PluginTemplateService != nil {
		if err := c.PluginTemplateService.EnsureIndexes(c.ctx); err != nil {
			return fmt.Errorf("failed to ensure template indexes: %v", err)
		}
		if err := c.PluginTemplateService.PresetTemplates(c.ctx); err != nil {
			return fmt.Errorf("failed to preset templates: %v", err)
		}
	}
	// 初始化监控服务索引
	if c.MonitoringService != nil {
		if err := c.MonitoringService.EnsureIndexes(c.ctx); err != nil {
			return fmt.Errorf("failed to ensure monitoring indexes: %v", err)
		}
	}

	if err := c.setAllAgentsOffline(); err != nil {
		return fmt.Errorf("failed to set all agents as offline on startup: %v", err)
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second) // 每5分钟更新一次
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := c.updateAgentStatus(); err != nil {
					fmt.Printf("Failed to update agent statuses: %v\n", err)
				}
			case <-c.ctx.Done():
				return
			}
		}
	}()

	key, err := c.KeyManager.GenerateServiceKey(string(models.ServiceNameController), c.RegistryManager.HostIdentifier, fmt.Sprintf("%d", port))
	if err != nil {
		return fmt.Errorf("failed to generate resource key: %v", err)
	}
	serviceInfo := &models.ServiceInfo{
		Key:      key,
		Name:     string(models.ServiceNameController),
		Protocol: "tcp",
		Address:  fmt.Sprintf(":%d", port),
	}

	c.serviceInfo = serviceInfo
	// 启动周期性注册
	go c.periodicRegister()

	upstreamEtcdEndpoints := c.ConfigManager.Config.Upstream.EtcdAddresses
	if err := c.RegisterToUpstreamEtcd(upstreamEtcdEndpoints); err != nil {
		// 不再阻止启动，只记录警告
		fmt.Printf("Warning: failed to start upstream etcd registration (will retry in background): %v\n", err)
	}

	return nil
}
func (c *Controller) GetStatus() (*models.ControllerStatus, error) {
	return &models.ControllerStatus{
		ControllerID: c.id,
		StartTime:    c.startTime,
		Version:      c.version,
		FunctionArea: c.ConfigManager.Config.FunctionArea,
		SystemInfo: struct {
			Hostname string `json:"hostname"`
			OS       string `json:"os"`
		}{
			Hostname: c.getHostname(),
			OS:       c.getOSInfo(),
		},
		MongoDBStatus: c.getMongoDBStatus(),
		EtcdStatus:    c.getEtcdStatus(),
	}, nil
}

func (c *Controller) getManagerStatus(manager interface{}) string {
	if manager == nil {
		return "not initialized"
	}
	return "running"
}

func (c *Controller) getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func (c *Controller) getOSInfo() string {
	return runtime.GOOS
}

func (c *Controller) getMongoDBStatus() string {
	if c.mongoClient == nil {
		return "not connected"
	}
	err := c.mongoClient.Ping(context.Background(), nil)
	if err != nil {
		return "error: " + err.Error()
	}
	return "connected"
}

// GetMongoClient 返回 MongoDB 客户端（用于其他模块访问）
func (c *Controller) GetMongoClient() *mongo.Client {
	return c.mongoClient
}

func (c *Controller) getEtcdStatus() string {
	if c.ConfigManager == nil || c.ConfigManager.EtcdClient == nil {
		return "not connected"
	}
	_, err := c.ConfigManager.EtcdClient.Get(context.Background(), "test_key")
	if err != nil {
		return "error: " + err.Error()
	}
	return "connected"
}

func (c *Controller) updateAgentStatus() error {
	collection := c.mongoClient.Database("controller").Collection("agents")

	// Get all keys with the prefix for agent services
	// 使用 WithLease() 选项来获取租约信息
	resp, err := c.ConfigManager.EtcdClient.Get(context.Background(), "grpc:", clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("failed to get agent keys from etcd: %v", err)
	}

	// Create a map to store active agents
	activeAgents := make(map[string]bool)

	for _, kv := range resp.Kvs {
		if !strings.Contains(string(kv.Key), "server-agent") {
			continue
		}

		// 检查 key 的租约状态
		// etcd 的 Get 操作可能不返回租约信息（kv.Lease 可能为 0），
		// 但我们可以通过重新获取 key 来验证它是否仍然存在且有效
		// 如果 key 有租约，检查租约 TTL；如果没有租约信息，重新获取 key 验证其有效性
		keyValid := false

		if kv.Lease > 0 {
			// 有租约信息，检查租约 TTL
			ttlResp, err := c.ConfigManager.EtcdClient.TimeToLive(context.Background(), clientv3.LeaseID(kv.Lease))
			if err != nil {
				// 如果无法获取 TTL（可能是租约已过期），认为 key 无效
				fmt.Printf("Failed to get TTL for lease %d (key: %s): %v, marking agent as offline\n", kv.Lease, string(kv.Key), err)
				continue
			}
			// TTL = -1 表示租约已过期或不存在
			// TTL = 0 表示租约存在但已过期
			if ttlResp.TTL <= 0 {
				fmt.Printf("Lease expired for key %s (lease: %d, TTL: %d), skipping agent\n", string(kv.Key), kv.Lease, ttlResp.TTL)
				continue
			}
			keyValid = true
		} else {
			// 没有租约信息，重新获取 key 来验证其是否仍然存在且有有效租约
			// 注意：etcd 的 Get 操作可能不返回租约信息，所以我们需要重新获取
			verifyResp, err := c.ConfigManager.EtcdClient.Get(context.Background(), string(kv.Key))
			if err != nil || len(verifyResp.Kvs) == 0 {
				// key 不存在或已过期，跳过该 Agent
				fmt.Printf("Key %s no longer exists in etcd, marking agent as offline\n", string(kv.Key))
				continue
			}
			// key 仍然存在，检查是否有租约
			verifyKv := verifyResp.Kvs[0]
			if verifyKv.Lease > 0 {
				// 重新获取的 key 有租约信息，检查租约 TTL
				ttlResp, err := c.ConfigManager.EtcdClient.TimeToLive(context.Background(), clientv3.LeaseID(verifyKv.Lease))
				if err != nil {
					// 无法获取 TTL，认为租约已过期
					fmt.Printf("Failed to get TTL for lease %d (key: %s): %v, marking agent as offline\n", verifyKv.Lease, string(kv.Key), err)
					continue
				}
				if ttlResp.TTL <= 0 {
					fmt.Printf("Key %s has expired lease (lease: %d, TTL: %d), marking agent as offline\n", string(kv.Key), verifyKv.Lease, ttlResp.TTL)
					continue
				}
				// 租约有效
				keyValid = true
			} else {
				// 重新获取的 key 仍然没有租约信息
				// 这可能意味着 etcd 的 Get 操作不返回租约信息（即使 key 有租约）
				// 为了安全起见，我们检查 MongoDB 中该 Agent 的最后更新时间
				// 如果最后更新时间超过 90 秒（Agent 的 TTL 通常是 60 秒，加上一些缓冲），则认为已下线
				var agentInfo struct {
					Op        int                `json:"Op"`
					Addr      string             `json:"Addr"`
					MetadataX server.ServiceInfo `json:"MetadataX"`
				}
				if err := json.Unmarshal(verifyKv.Value, &agentInfo); err == nil {
					// 检查 MongoDB 中该 Agent 的最后更新时间
					var existingAgent struct {
						LastUpdated time.Time `bson:"lastUpdated"`
					}
					filter := bson.M{"id": agentInfo.MetadataX.AppID}
					err := collection.FindOne(context.Background(), filter).Decode(&existingAgent)
					if err == nil {
						// 如果最后更新时间超过 90 秒，认为 Agent 已下线
						if time.Since(existingAgent.LastUpdated) > 90*time.Second {
							fmt.Printf("Key %s has no lease info and last update was %v ago, marking agent as offline\n", string(kv.Key), time.Since(existingAgent.LastUpdated))
							continue
						}
						// 最后更新时间在 90 秒内，认为 Agent 仍然在线
						keyValid = true
					} else {
						// 无法从 MongoDB 获取信息，保守地认为已下线
						fmt.Printf("Warning: key %s has no lease info and cannot verify in MongoDB, skipping\n", string(kv.Key))
						continue
					}
				} else {
					// 无法解析 key 的值，跳过
					fmt.Printf("Warning: key %s has no lease info and cannot parse value, skipping\n", string(kv.Key))
					continue
				}
			}
		}

		if !keyValid {
			// 如果 key 无效，跳过该 Agent
			continue
		}

		var agentInfo struct {
			Op        int                `json:"Op"`
			Addr      string             `json:"Addr"`
			MetadataX server.ServiceInfo `json:"MetadataX"`
		}

		err := json.Unmarshal(kv.Value, &agentInfo)
		if err != nil {
			fmt.Printf("Failed to unmarshal agent data for key %s: %v\n", string(kv.Key), err)
			continue
		}

		// 优先使用 MetadataX.Address，如果没有则使用 Addr
		agentAddress := agentInfo.MetadataX.Address
		if agentAddress == "" {
			agentAddress = agentInfo.Addr
		}

		// Mark this agent as active
		activeAgents[agentInfo.MetadataX.AppID] = true

		filter := bson.M{"id": agentInfo.MetadataX.AppID}
		services := []models.PackageStatus{}
		if agentInfo.MetadataX.Metadata["services"] != "" {
			err = json.Unmarshal([]byte(agentInfo.MetadataX.Metadata["services"]), &services)
			if err != nil {
				fmt.Printf("Failed to unmarshal services for agent %s: %v\n", agentInfo.MetadataX.AppID, err)
			}
		}
		update := bson.M{"$set": bson.M{
			"id":           agentInfo.MetadataX.AppID,
			"name":         agentInfo.MetadataX.Name,
			"address":      agentAddress, // 使用解析出的地址
			"status":       "online",
			"lastUpdated":  time.Now(),
			"proxyAddress": agentInfo.MetadataX.Metadata["proxy_addr"],
			"version":      agentInfo.MetadataX.Version,
			"startTime":    agentInfo.MetadataX.Metadata["startTime"],
			"hostname":     agentInfo.MetadataX.Hostname,
			"functionArea": c.ConfigManager.Config.FunctionArea,
			"zone":         agentInfo.MetadataX.Zone,
			"mode":         agentInfo.MetadataX.Mode,
			"deployment":   agentInfo.MetadataX.Deployment,
			"group":        agentInfo.MetadataX.Group,
			"services":     services,
		}}
		_, err = collection.UpdateOne(context.Background(), filter, update, options.Update().SetUpsert(true))
		if err != nil {
			fmt.Printf("Failed to update status for agent %s in MongoDB: %v\n", agentInfo.MetadataX.AppID, err)
		} else {
			fmt.Printf("Updated agent %s status: address=%s, status=online\n", agentInfo.MetadataX.AppID, agentAddress)
		}
	}

	// Update agents that haven't been updated in the last 3 periods as offline
	// 如果 etcd 中已经没有 agent 的注册信息，它不会在 activeAgents 中，应该被标记为 offline
	threePeriodsAgo := time.Now().Add(-3 * 30 * time.Second)
	activeAgentKeys := getKeys(activeAgents)

	filter := bson.M{
		"$or": []bson.M{
			{"id": bson.M{"$nin": activeAgentKeys}},
			{"lastUpdated": bson.M{"$lt": threePeriodsAgo}},
		},
	}
	update := bson.M{"$set": bson.M{"status": "offline", "lastUpdated": time.Now()}}

	// 先查询有多少 agent 需要更新为 offline
	count, err := collection.CountDocuments(context.Background(), filter)
	if err != nil {
		fmt.Printf("Failed to count inactive agents in MongoDB: %v\n", err)
	} else if count > 0 {
		fmt.Printf("Found %d inactive agents to update as offline (active agents: %d)\n", count, len(activeAgentKeys))
	}

	// 执行更新
	result, err := collection.UpdateMany(context.Background(), filter, update)
	if err != nil {
		fmt.Printf("Failed to update inactive agents in MongoDB: %v\n", err)
	} else {
		if result.ModifiedCount > 0 {
			fmt.Printf("Updated %d agents to offline status in MongoDB\n", result.ModifiedCount)
		}
	}

	return nil
}

// New function to set all agents as offline on startup
func (c *Controller) setAllAgentsOffline() error {
	collection := c.mongoClient.Database("controller").Collection("agents")

	filter := bson.M{}
	update := bson.M{"$set": bson.M{"status": "offline", "lastUpdated": time.Now()}}
	_, err := collection.UpdateMany(context.Background(), filter, update)
	if err != nil {
		return fmt.Errorf("failed to set all agents as offline: %v", err)
	}

	return nil
}

// Helper function to get keys from a map
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (c *Controller) RegisterService() error {
	// 使用 c.serviceInfo，它在 Start 方法中已经被设置
	if c.serviceInfo == nil {
		return fmt.Errorf("service info is not initialized")
	}

	// 立即进行一次注册
	if err := c.RegistryManager.RegisterService(c.serviceInfo, 1*time.Minute); err != nil {
		return fmt.Errorf("failed to register service: %v", err)
	}

	return nil
}

func (c *Controller) RegisterToUpstreamEtcd(upstreamEtcdEndpoints []string) error {
	fmt.Printf("[ETCD] RegisterToUpstreamEtcd: called, endpoints: %v (from config: upstream.etcd_addresses)\n", upstreamEtcdEndpoints)
	// 如果没有配置上游 etcd 地址，跳过注册
	if len(upstreamEtcdEndpoints) == 0 {
		fmt.Println("[ETCD] RegisterToUpstreamEtcd: No upstream etcd endpoints configured, skipping upstream etcd registration")
		fmt.Println("[ETCD] RegisterToUpstreamEtcd: Please configure 'upstream.etcd_addresses' in your config file")
		return nil
	}

	// 显示端口信息
	for _, endpoint := range upstreamEtcdEndpoints {
		if host, port, err := net.SplitHostPort(endpoint); err == nil {
			fmt.Printf("[ETCD] RegisterToUpstreamEtcd: endpoint %s:%s (note: etcd default port is 2379, this is custom port)\n", host, port)
		}
	}

	// 启动周期性注册和配置监听（即使初始连接失败也会在后台重试）
	fmt.Printf("[ETCD] RegisterToUpstreamEtcd: starting periodic register goroutine\n")
	go c.periodicUpstreamRegister()
	fmt.Printf("[ETCD] RegisterToUpstreamEtcd: starting watch config goroutine\n")
	go c.watchUpstreamEtcdConfig()

	// 尝试创建初始连接（非阻塞）
	fmt.Printf("[ETCD] RegisterToUpstreamEtcd: starting reconnect goroutine\n")
	go c.reconnectUpstreamEtcd(upstreamEtcdEndpoints)

	fmt.Printf("[ETCD] RegisterToUpstreamEtcd: all goroutines started\n")
	return nil
}

// reconnectUpstreamEtcd 尝试重新连接到上游 etcd
func (c *Controller) reconnectUpstreamEtcd(upstreamEtcdEndpoints []string) {
	retryInterval := 10 * time.Second
	maxRetryInterval := 5 * time.Minute
	consecutiveFailures := 0

	for {
		// 检查是否已有可用的客户端
		c.upstreamEtcdMu.RLock()
		hasClient := c.upstreamEtcdClient != nil
		c.upstreamEtcdMu.RUnlock()

		if hasClient {
			if c.checkUpstreamEtcdConnection() {
				consecutiveFailures = 0
				retryInterval = 10 * time.Second
				// 连接正常，等待较长时间后再次检查
				select {
				case <-time.After(1 * time.Minute):
					continue
				case <-c.ctx.Done():
					return
				}
			}
		}

		// 关闭旧的客户端（如果存在）
		c.upstreamEtcdMu.Lock()
		if c.upstreamEtcdClient != nil {
			oldClient := c.upstreamEtcdClient
			c.upstreamEtcdClient = nil
			c.upstreamEtcdMu.Unlock()
			// 在锁外关闭，避免阻塞
			oldClient.Close()
		} else {
			c.upstreamEtcdMu.Unlock()
		}

		// 在创建客户端之前，先进行 TCP 连接测试
		canConnect := false
		for _, endpoint := range upstreamEtcdEndpoints {
			// 解析 endpoint (可能是 "127.0.0.1:3379" 格式)
			host, port, err := net.SplitHostPort(endpoint)
			if err != nil {
				// 如果不是 host:port 格式，尝试直接作为地址
				host = endpoint
				port = "2379" // 默认端口
			}

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 1*time.Second)
			if err == nil {
				conn.Close()
				canConnect = true
				break
			}
		}

		if !canConnect {
			consecutiveFailures++
			if consecutiveFailures >= 3 {
				retryInterval = minDuration(retryInterval*2, maxRetryInterval)
			}
			if consecutiveFailures == 1 || consecutiveFailures%10 == 0 {
				fmt.Printf("[ETCD] TCP connection failed (attempt %d, will retry in %v)\n",
					consecutiveFailures, retryInterval)
			}
			select {
			case <-time.After(retryInterval):
				continue
			case <-c.ctx.Done():
				return
			}
		}

		// TCP 连接测试通过，创建客户端（使用长连接配置）
		cfg := clientv3.Config{
			Endpoints:   upstreamEtcdEndpoints,
			DialTimeout: 5 * time.Second, // 使用较长的超时，给连接建立更多时间
			Username:    c.ConfigManager.Config.Upstream.Username,
			Password:    c.ConfigManager.Config.Upstream.Password,
			// 配置 KeepAlive 保持长连接
			DialKeepAliveTime:    10 * time.Second, // KeepAlive 时间
			DialKeepAliveTimeout: 3 * time.Second,  // KeepAlive 超时
			// 禁用自动重试（我们手动管理重试）
			// 注意：etcd 客户端库内部仍有重试机制，但我们可以通过配置减少重试频率
		}
		cli, err := clientv3.New(cfg)
		if err != nil {
			// 创建失败，立即关闭（如果创建了部分资源）
			if cli != nil {
				cli.Close()
			}
			consecutiveFailures++
			if consecutiveFailures >= 3 {
				retryInterval = minDuration(retryInterval*2, maxRetryInterval)
			}
			if consecutiveFailures == 1 || consecutiveFailures%10 == 0 {
				fmt.Printf("[ETCD] Failed to create etcd client (attempt %d, will retry in %v): %v\n",
					consecutiveFailures, retryInterval, err)
			}
			select {
			case <-time.After(retryInterval):
				continue
			case <-c.ctx.Done():
				return
			}
		}

		cliPtr := fmt.Sprintf("%p", cli)

		// 验证连接是否可用（使用稍长的超时，给长连接建立时间）
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err = cli.Get(ctx, "__health_check__")
		cancel()

		if err != nil {
			// 连接失败，立即关闭客户端，避免客户端库持续重试
			// 给一点时间让客户端库完成当前的重试，然后关闭
			time.Sleep(200 * time.Millisecond)
			cli.Close()
			consecutiveFailures++
			if consecutiveFailures >= 3 {
				retryInterval = minDuration(retryInterval*2, maxRetryInterval)
			}
			if consecutiveFailures == 1 || consecutiveFailures%10 == 0 {
				fmt.Printf("[ETCD] Health check failed (attempt %d, will retry in %v): %v\n",
					consecutiveFailures, retryInterval, err)
			}
			select {
			case <-time.After(retryInterval):
				continue
			case <-c.ctx.Done():
				return
			}
		}
		// 连接成功，设置客户端
		c.upstreamEtcdMu.Lock()
		// 再次检查是否有其他 goroutine 已经设置了客户端
		if c.upstreamEtcdClient != nil {
			// 关闭新创建的客户端，使用已存在的
			c.upstreamEtcdMu.Unlock()
			cli.Close()
			continue
		}
		c.upstreamEtcdClient = cli
		c.upstreamEtcdMu.Unlock()

		if consecutiveFailures > 0 {
			fmt.Printf("[ETCD] Successfully reconnected to etcd after %d failures\n", consecutiveFailures)
		}
		consecutiveFailures = 0
		retryInterval = 10 * time.Second

		// 启动一个 goroutine 来监控长连接状态（可选，用于提前发现连接问题）
		go c.monitorLongConnection(cliPtr, cli)
	}
}

func (c *Controller) periodicUpstreamRegister() {
	// 初始重试间隔为30秒
	retryInterval := 30 * time.Second
	maxRetryInterval := 5 * time.Minute // 最大重试间隔为5分钟
	consecutiveFailures := 0
	maxConsecutiveFailures := 3 // 连续失败3次后增加重试间隔

	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 先检查 etcd 客户端是否可用
			c.upstreamEtcdMu.RLock()
			hasClient := c.upstreamEtcdClient != nil
			c.upstreamEtcdMu.RUnlock()

			if !hasClient {
				consecutiveFailures++
				if consecutiveFailures >= maxConsecutiveFailures {
					retryInterval = minDuration(retryInterval*2, maxRetryInterval)
					ticker.Reset(retryInterval)
					fmt.Printf("Upstream etcd client is nil, increasing retry interval to %v\n", retryInterval)
				}
				continue
			}

			// 检查连接状态
			if !c.checkUpstreamEtcdConnection() {
				// 连接失败，关闭客户端避免持续重试
				// Connection check failed, closing client
				c.upstreamEtcdMu.Lock()
				if c.upstreamEtcdClient != nil {
					oldClient := c.upstreamEtcdClient
					c.upstreamEtcdClient = nil
					c.upstreamEtcdMu.Unlock()
					oldClient.Close()
				} else {
					c.upstreamEtcdMu.Unlock()
				}
				consecutiveFailures++
				if consecutiveFailures >= maxConsecutiveFailures {
					retryInterval = minDuration(retryInterval*2, maxRetryInterval)
					ticker.Reset(retryInterval)
					fmt.Printf("Upstream etcd connection failed, closing client and increasing retry interval to %v\n", retryInterval)
				}
				continue
			}

			// 尝试注册
			// Attempting to register
			if err := c.registerToUpstreamEtcd(); err != nil {
				// 如果是连接错误，关闭客户端避免持续重试
				if strings.Contains(err.Error(), "connection failed") ||
					strings.Contains(err.Error(), "DeadlineExceeded") ||
					strings.Contains(err.Error(), "connection refused") {
					// Registration failed (connection error), closing client
					c.upstreamEtcdMu.Lock()
					if c.upstreamEtcdClient != nil {
						oldClient := c.upstreamEtcdClient
						c.upstreamEtcdClient = nil
						c.upstreamEtcdMu.Unlock()
						oldClient.Close()
					} else {
						c.upstreamEtcdMu.Unlock()
					}
				}
				consecutiveFailures++
				if consecutiveFailures >= maxConsecutiveFailures {
					retryInterval = minDuration(retryInterval*2, maxRetryInterval)
					ticker.Reset(retryInterval)
					fmt.Printf("Failed to register to upstream etcd (consecutive failures: %d), closing client and increasing retry interval to %v: %v\n",
						consecutiveFailures, retryInterval, err)
				} else {
					fmt.Printf("Failed to register to upstream etcd (attempt %d/%d): %v\n",
						consecutiveFailures, maxConsecutiveFailures, err)
				}
			} else {
				// 注册成功，重置失败计数和重试间隔
				if consecutiveFailures > 0 {
					fmt.Printf("Successfully registered to upstream etcd after %d failures, resetting retry interval\n", consecutiveFailures)
				}
				consecutiveFailures = 0
				if retryInterval != 30*time.Second {
					retryInterval = 30 * time.Second
					ticker.Reset(retryInterval)
				}
			}
		case <-c.ctx.Done():
			return
		}
	}
}

// checkUpstreamEtcdConnection 检查上游 etcd 连接是否可用
func (c *Controller) checkUpstreamEtcdConnection() bool {
	c.upstreamEtcdMu.RLock()
	client := c.upstreamEtcdClient
	c.upstreamEtcdMu.RUnlock()

	if client == nil {
		return false
	}

	// 使用短超时进行健康检查
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// 尝试获取一个不存在的 key 来检查连接
	_, err := client.Get(ctx, "__health_check__")
	if err != nil {
		// 如果是 context deadline exceeded 或 connection refused，说明连接不可用
		if strings.Contains(err.Error(), "DeadlineExceeded") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "connection reset") {
			return false
		}
		// 其他错误（如 key not found）说明连接是可用的
	}
	return true
}

// minDuration 返回两个时间间隔中的较小值
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// monitorLongConnection 监控长连接状态，定期检查连接健康
func (c *Controller) monitorLongConnection(clientPtr string, client *clientv3.Client) {
	ticker := time.NewTicker(30 * time.Second) // 每30秒检查一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 检查客户端是否仍然是我们监控的客户端
			c.upstreamEtcdMu.RLock()
			currentClient := c.upstreamEtcdClient
			c.upstreamEtcdMu.RUnlock()

			// 如果客户端已经被替换或关闭，停止监控
			if currentClient != client {
				return
			}

			// 执行轻量级健康检查
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err := client.Get(ctx, "__health_check__")
			cancel()

			if err != nil {
				// 如果连接失败，标记客户端需要重新连接
				if strings.Contains(err.Error(), "DeadlineExceeded") ||
					strings.Contains(err.Error(), "connection refused") ||
					strings.Contains(err.Error(), "connection reset") {
					// 关闭客户端，触发重连
					c.upstreamEtcdMu.Lock()
					if c.upstreamEtcdClient == client {
						c.upstreamEtcdClient = nil
					}
					c.upstreamEtcdMu.Unlock()
					client.Close()
					fmt.Printf("[ETCD] Connection lost, will reconnect\n")
					return
				}
			}

		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Controller) registerToUpstreamEtcd() error {
	c.upstreamEtcdMu.RLock()
	client := c.upstreamEtcdClient
	c.upstreamEtcdMu.RUnlock()

	if client == nil {
		return fmt.Errorf("upstream etcd client is not initialized")
	}

	// 先进行连接健康检查
	if !c.checkUpstreamEtcdConnection() {
		return fmt.Errorf("upstream etcd connection is not available")
	}

	// 准备注册信息
	now := time.Now()
	controllerInfo := struct {
		ID            string    `json:"id"`
		Address       string    `json:"address"`
		FunctionArea  string    `json:"function_area"` // 修复拼写错误：jaon -> json
		StartTime     time.Time `json:"start_time"`
		Version       string    `json:"version"`
		Status        string    `json:"status"`
		LastHeartbeat time.Time `json:"last_heartbeat"`
	}{
		ID:            c.id,
		Address:       c.serviceInfo.Address,
		StartTime:     c.startTime,
		Version:       c.version,
		FunctionArea:  c.ConfigManager.Config.FunctionArea,
		Status:        "online",
		LastHeartbeat: now,
	}

	infoJSON, err := json.Marshal(controllerInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal controller info: %v", err)
	}

	// 生成 etcd 键
	key := keys.NewKeyBuilder("controllers", c.ConfigManager.Config.FunctionArea, c.id).Separator("/").String()

	// 设置较短的超时时间（3秒），避免长时间等待
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 创建租约
	lease, err := client.Grant(ctx, 60)
	if err != nil {
		// 检查是否是连接错误
		if strings.Contains(err.Error(), "DeadlineExceeded") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "connection reset") {
			return fmt.Errorf("upstream etcd connection failed: %v", err)
		}
		return fmt.Errorf("failed to create lease: %v", err)
	}

	// 将控制器信息写入 etcd，并附加租约
	_, err = client.Put(ctx, key, string(infoJSON), clientv3.WithLease(lease.ID))
	if err != nil {
		// 检查是否是连接错误
		if strings.Contains(err.Error(), "DeadlineExceeded") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "connection reset") {
			return fmt.Errorf("upstream etcd connection failed: %v", err)
		}
		return fmt.Errorf("failed to put controller info to etcd: %v", err)
	}

	return nil
}

func (c *Controller) periodicRegister() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒注册一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.RegistryManager.RegisterService(c.serviceInfo, 1*time.Minute); err != nil {
				fmt.Printf("Failed to register service: %v\n", err)
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Controller) Stop() error {
	if err := c.JumperServerManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop jumper server manager: %v", err)
	}

	if err := c.GrpcProxyManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop grpc proxy manager: %v", err)
	}

	if err := c.AgentManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop agent manager: %v", err)
	}

	if err := c.MinioManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop minio manager: %v", err)
	}

	if err := c.RegistryManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop registry manager: %v", err)
	}

	if err := c.ResourceManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop resource manager: %v", err)
	}
	if err := c.ConfigManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop config manager: %v", err)
	}
	if err := c.RedisManager.Stop(); err != nil {
		return fmt.Errorf("failed to stop redis manager: %v", err)
	}
	if c.TelegrafManager != nil {
		if err := c.TelegrafManager.Stop(); err != nil {
			return fmt.Errorf("failed to stop telegraf manager: %v", err)
		}
	}

	return nil
}

func (c *Controller) UpdateConfig(resourceType models.ResourceType, resourceID string, config map[string]interface{}) error {
	err := c.ConfigManager.UpdateConfig(resourceType, resourceID, config)
	if err != nil {
		return fmt.Errorf("failed to update config: %v", err)
	}

	key, err := c.ConfigManager.KeyManager.GenerateResourceKey(string(resourceType), resourceID)
	if err != nil {
		return fmt.Errorf("failed to generate key for resource %s: %v", resourceID, err)
	}
	// 配置更新后重启资源
	err = c.ResourceManager.RestartResource(key)
	if err != nil {
		return fmt.Errorf("failed to restart resource after config update: %v", err)
	}

	return nil
}

func (c *Controller) GetConfig(resourceType models.ResourceType, resourceID string) (map[string]interface{}, error) {
	return c.ConfigManager.GetConfig(resourceType, resourceID)
}

func (c *Controller) DeleteConfig(resourceType models.ResourceType, resourceID string) error {
	err := c.ConfigManager.DeleteConfig(resourceType, resourceID)
	if err != nil {
		return fmt.Errorf("failed to delete config: %v", err)
	}

	key, err := c.ConfigManager.KeyManager.GenerateResourceKey(string(resourceType), resourceID)
	if err != nil {
		return fmt.Errorf("failed to generate key for resource %s: %v", resourceID, err)
	}

	// 配置删除后停止资源
	err = c.ResourceManager.StopResource(key)
	if err != nil {
		return fmt.Errorf("failed to stop resource after config deletion: %v", err)
	}

	return nil
}

func (c *Controller) ListConfigs(resourceType models.ResourceType) ([]string, error) {
	return c.ConfigManager.ListResourceIDs(resourceType)
}

func (c *Controller) CreateResource(resourceType models.ResourceType, resourceID string, config map[string]interface{}) error {
	err := c.ConfigManager.UpdateConfig(resourceType, resourceID, config)
	if err != nil {
		return fmt.Errorf("failed to create config: %v", err)
	}

	_, err = c.ResourceManager.CreateResource(resourceType, resourceID, config, true)
	if err != nil {
		// 如果创建资源失败，删除已创建的配置
		_ = c.ConfigManager.DeleteConfig(resourceType, resourceID)
		return fmt.Errorf("failed to create resource: %v", err)
	}

	return nil
}

func (c *Controller) DeleteResource(resourceType models.ResourceType, resourceID string) error {
	key, err := c.ConfigManager.KeyManager.GenerateResourceKey(string(resourceType), resourceID)
	if err != nil {
		return fmt.Errorf("failed to generate key for resource %s: %v", resourceID, err)
	}
	err = c.ResourceManager.DeleteResource(key)
	if err != nil {
		return fmt.Errorf("failed to delete resource: %v", err)
	}

	err = c.ConfigManager.DeleteConfig(resourceType, resourceID)
	if err != nil {
		return fmt.Errorf("failed to delete config after resource deletion: %v", err)
	}

	return nil
}

func (c *Controller) GetResourceStatus(resourceType models.ResourceType, resourceID string) (string, error) {
	key, err := c.ConfigManager.KeyManager.GenerateResourceKey(string(resourceType), resourceID)
	if err != nil {
		return "", fmt.Errorf("failed to generate key for resource %s: %v", resourceID, err)
	}
	return c.ResourceManager.GetResourceStatus(key)
}

func (c *Controller) ListResources() []string {
	return c.ResourceManager.ListAllResources()
}

// POST /api/v1/deployments
func (c *Controller) CreateDeployment(req models.DeploymentRequest) (*models.Deployment, error) {

	return c.DeploymentManager.CreateDeployment(req)
}

// // GET /api/v1/deployments/{id}
// func (c *Controller) GetDeploymentStatus(w http.ResponseWriter, r *http.Request) {
// 	deploymentID := chi.URLParam(r, "id")

// 	status, err := c.DeploymentManager.GetDeploymentStatus(deploymentID)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	json.NewEncoder(w).Encode(status)
// }

// GET /api/v1/deployments
func (c *Controller) ListDeployments(w http.ResponseWriter, r *http.Request) {
	deployments, err := c.DeploymentManager.ListDeployments()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(deployments)
}

func (c *Controller) GetAssets(tags string) ([]*structs.L2DeviceRemoteInfo, error) {
	uniOpsConfig := c.ConfigManager.Config.UniOpsConfig

	// 登录获取token
	token, err := c.login(uniOpsConfig)
	if err != nil {
		fmt.Printf("Failed to login: %v\n", err)
		return nil, fmt.Errorf("login failed: %v", err)
	}

	masterKeys := strings.Split(tags, ",")

	// 准备请求体
	requestBody := map[string]interface{}{
		"master_keys": masterKeys,
		"oob":         false,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	// 创建HTTP请求
	url := fmt.Sprintf("%s/api/v1/resource_index/remotes", uniOpsConfig.Address)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))

	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", token)

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to send HTTP request: %v\n", err)
		return nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()
	fmt.Printf("Received response status code: %d\n", resp.StatusCode)

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	// 解析响应
	var response struct {
		Code int                           `json:"code"`
		Msg  string                        `json:"msg"`
		Data []*structs.L2DeviceRemoteInfo `json:"data"`
	}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %v", err)
	}

	if response.Code != 0 {
		return nil, fmt.Errorf("API request failed: %s", response.Msg)
	}

	return response.Data, nil
}

func (c *Controller) login(config UniOpsConfig) (string, error) {
	loginData := map[string]interface{}{
		"login_type": 0,
		"account":    config.Account,
		"password":   config.Password,
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(config.Address+"/api/v1/access/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var loginResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &loginResp); err != nil {
		return "", fmt.Errorf("failed to parse login response: %v", err)
	}

	if loginResp.Code != 0 {
		return "", fmt.Errorf("login failed: %s", loginResp.Msg)
	}

	if loginResp.Data.Token == "" {
		return "", fmt.Errorf("token not found in response")
	}

	return loginResp.Data.Token, nil
}

func generateDeploymentID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (c *Controller) watchUpstreamEtcdConfig() {
	// 如果没有配置 watch key，跳过
	if c.ConfigManager.Config.Upstream.Watch == "" {
		fmt.Printf("[ETCD] watchUpstreamEtcdConfig: watch key not configured, skipping\n")
		return
	}

	watchKey := fmt.Sprintf("%s/%s", c.ConfigManager.Config.Upstream.Watch, c.ConfigManager.Config.FunctionArea)
	// watchUpstreamEtcdConfig: starting watch
	retryInterval := 30 * time.Second
	maxRetryInterval := 5 * time.Minute
	consecutiveFailures := 0

	for {
		// 检查客户端是否可用
		c.upstreamEtcdMu.RLock()
		hasClient := c.upstreamEtcdClient != nil
		c.upstreamEtcdMu.RUnlock()

		if !hasClient {
			// 等待一段时间后重试
			select {
			case <-time.After(retryInterval):
				consecutiveFailures++
				if consecutiveFailures >= 3 {
					retryInterval = minDuration(retryInterval*2, maxRetryInterval)
				}
				continue
			case <-c.ctx.Done():
				return
			}
		}

		// 检查连接是否可用
		if !c.checkUpstreamEtcdConnection() {
			// 连接不可用，关闭客户端并等待重试
			c.upstreamEtcdMu.Lock()
			if c.upstreamEtcdClient != nil {
				oldClient := c.upstreamEtcdClient
				c.upstreamEtcdClient = nil
				c.upstreamEtcdMu.Unlock()
				oldClient.Close()
			} else {
				c.upstreamEtcdMu.Unlock()
			}
			consecutiveFailures++
			if consecutiveFailures >= 3 {
				retryInterval = minDuration(retryInterval*2, maxRetryInterval)
			}
			select {
			case <-time.After(retryInterval):
				continue
			case <-c.ctx.Done():
				return
			}
		}

		// 连接可用，重置失败计数
		consecutiveFailures = 0
		if retryInterval != 30*time.Second {
			retryInterval = 30 * time.Second
		}

		// 获取客户端引用
		c.upstreamEtcdMu.RLock()
		client := c.upstreamEtcdClient
		c.upstreamEtcdMu.RUnlock()

		if client == nil {
			select {
			case <-time.After(retryInterval):
				continue
			case <-c.ctx.Done():
				return
			}
		}

		// 创建带超时的 context 用于 Watch
		watchCtx, watchCancel := context.WithCancel(c.ctx)
		watchChan := client.Watch(watchCtx, watchKey, clientv3.WithPrefix())

		// 监听 watch 事件
		for watchResp := range watchChan {
			if watchResp.Err() != nil {
				// Watch 出错，关闭并重试
				watchCancel()
				if strings.Contains(watchResp.Err().Error(), "DeadlineExceeded") ||
					strings.Contains(watchResp.Err().Error(), "connection refused") ||
					strings.Contains(watchResp.Err().Error(), "connection reset") {
					// 连接错误，关闭客户端
					c.upstreamEtcdMu.Lock()
					if c.upstreamEtcdClient != nil {
						oldClient := c.upstreamEtcdClient
						c.upstreamEtcdClient = nil
						c.upstreamEtcdMu.Unlock()
						oldClient.Close()
						fmt.Printf("[ETCD] Watch connection lost, will reconnect\n")
					} else {
						c.upstreamEtcdMu.Unlock()
					}
				}
				break
			}

			for _, event := range watchResp.Events {
				switch event.Type {
				case clientv3.EventTypePut:
					fmt.Printf("Config updated: %s = %s\n", event.Kv.Key, event.Kv.Value)
					c.handleConfigUpdate(event.Kv.Key, event.Kv.Value)
				case clientv3.EventTypeDelete:
					fmt.Printf("Config deleted: %s\n", event.Kv.Key)
					go c.handleConfigDelete(event.Kv.Key)
				}
			}
		}

		watchCancel()

		// Watch 通道关闭，等待后重试
		select {
		case <-time.After(retryInterval):
			continue
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Controller) handleConfigUpdate(key, value []byte) {
	// log.Printf("Received config update for key: %s", key)

	// var config map[string]interface{}
	// if err := json.Unmarshal(value, &config); err != nil {
	// 	log.Printf("Error unmarshalling config update: %v", err)
	// 	return
	// }

	// log.Printf("Applying config update for key: %s", key)
	// if gjson.Get(string(value), "enabled").String() == "true" {
	// 	c.installMutex.Lock()
	// 	if c.isInstalling {
	// 		log.Printf("Another package installation is in progress. Ignoring update for key: %s", key)
	// 		c.installMutex.Unlock()
	// 		return
	// 	}
	// 	c.isInstalling = true
	// 	log.Printf("Starting package installation for key: %s", key)
	// 	c.installMutex.Unlock()

	// 	go func() {
	// 		defer func() {
	// 			c.installMutex.Lock()
	// 			c.isInstalling = false
	// 			log.Printf("Package installation completed for key: %s", key)
	// 			c.installMutex.Unlock()
	// 		}()
	// 		// if err := c.InstallPackage(string(key), config); err != nil {
	// 		// 	log.Printf("Error installing package for key %s: %v", key, err)
	// 		// } else {
	// 		// 	log.Printf("Successfully installed package for key: %s", key)
	// 		// }
	// 	}()
	// } else {
	// 	log.Printf("Config update for key %s is not enabled, skipping installation", key)
	// }
}

func (c *Controller) handleConfigDelete(key []byte) {
	// 处理配置删除
	fmt.Printf("Handling config deletion for key: %s\n", key)
	// TODO: 实现配置删除逻辑
}

func (c *Controller) GetAgentVariables(ctx context.Context, agentID, appID string) (map[string]string, error) {
	variables, err := c.RegistryManager.GetVariables(ctx, agentID, appID)
	if err != nil {
		return nil, err
	}
	variables["loki_forward_path"] = "/api/v1/loki/push"

	return variables, nil
}

func (c *Controller) GetRegisteredAgentsCount() int {
	// Implement this method to return the number of registered agents
	count, _ := c.RegistryManager.GetAgentCount()
	return count
}
