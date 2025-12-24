package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// AgentDiscovery Agent 自动发现模块
type AgentDiscovery struct {
	etcdClient   *clientv3.Client
	mongoClient  *mongo.Client
	ctx          context.Context
	cancel       context.CancelFunc
	watchPrefix  string
	syncInterval time.Duration
}

// NewAgentDiscovery 创建 Agent 发现模块
func NewAgentDiscovery(etcdClient *clientv3.Client, mongoClient *mongo.Client, watchPrefix string) *AgentDiscovery {
	ctx, cancel := context.WithCancel(context.Background())
	return &AgentDiscovery{
		etcdClient:   etcdClient,
		mongoClient:  mongoClient,
		ctx:          ctx,
		cancel:       cancel,
		watchPrefix:  watchPrefix,
		syncInterval: 30 * time.Second,
	}
}

// Start 启动 Agent 发现
func (ad *AgentDiscovery) Start() error {
	xlog.Info("Starting AgentDiscovery",
		xlog.String("watch_prefix", ad.watchPrefix),
		xlog.Duration("sync_interval", ad.syncInterval))
	fmt.Printf("[AgentDiscovery] Starting AgentDiscovery: watch_prefix=%s, sync_interval=%v\n",
		ad.watchPrefix, ad.syncInterval)

	// 启动 Watch
	go ad.WatchAgents(ad.ctx)

	// 启动定期同步
	go ad.PeriodicSync(ad.ctx)

	// 立即同步一次
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ad.SyncAgentsFromEtcd(ctx); err != nil {
		xlog.Warn("Failed to initial sync agents from etcd",
			xlog.String("watch_prefix", ad.watchPrefix),
			xlog.FieldErr(err))
		fmt.Printf("[AgentDiscovery] Failed to initial sync agents from etcd: watch_prefix=%s, error=%v\n",
			ad.watchPrefix, err)
	} else {
		xlog.Info("Initial sync agents from etcd completed",
			xlog.String("watch_prefix", ad.watchPrefix))
		fmt.Printf("[AgentDiscovery] Initial sync agents from etcd completed: watch_prefix=%s\n",
			ad.watchPrefix)
	}

	return nil
}

// Stop 停止 Agent 发现
func (ad *AgentDiscovery) Stop() {
	ad.cancel()
}

// WatchAgents 监听 etcd 中的 Agent 变化
func (ad *AgentDiscovery) WatchAgents(ctx context.Context) {
	watcher := ad.etcdClient.Watch(ctx, ad.watchPrefix, clientv3.WithPrefix())

	for {
		select {
		case response, ok := <-watcher:
			if !ok {
				xlog.Info("Agent watch channel closed")
				return
			}
			if response.Err() != nil {
				xlog.Error("Agent watch error", xlog.FieldErr(response.Err()))
				continue
			}

			for _, event := range response.Events {
				ad.handleAgentEvent(ctx, event)
			}
		case <-ctx.Done():
			xlog.Info("Agent watch context cancelled")
			return
		}
	}
}

// handleAgentEvent 处理 Agent 事件
func (ad *AgentDiscovery) handleAgentEvent(ctx context.Context, event *clientv3.Event) {
	key := string(event.Kv.Key)

	switch event.Type {
	case clientv3.EventTypePut:
		// Agent 注册或更新
		agent, err := ad.parseAgentFromEtcdValue(event.Kv.Value)
		if err != nil {
			xlog.Error("Failed to parse agent from etcd value",
				xlog.String("key", key),
				xlog.FieldErr(err))
			return
		}

		if err := ad.upsertAgentToMongo(ctx, agent); err != nil {
			xlog.Error("Failed to upsert agent to MongoDB",
				xlog.String("agent_id", agent.ID),
				xlog.String("address", agent.Address),
				xlog.FieldErr(err))
		} else {
			xlog.Info("Agent registered/updated",
				xlog.String("agent_id", agent.ID),
				xlog.String("address", agent.Address),
				xlog.String("status", string(agent.Status)))
		}

	case clientv3.EventTypeDelete:
		// Agent 注销
		agentID := ad.extractAgentIDFromKey(key)
		if agentID != "" {
			if err := ad.updateAgentStatus(ctx, agentID, models.AgentStatusOffline); err != nil {
				xlog.Error("Failed to update agent status to offline",
					xlog.String("agent_id", agentID),
					xlog.FieldErr(err))
			} else {
				xlog.Info("Agent unregistered", xlog.String("agent_id", agentID))
			}
		}
	}
}

// parseAgentFromEtcdValue 从 etcd value 解析 Agent 信息
func (ad *AgentDiscovery) parseAgentFromEtcdValue(value []byte) (*models.Agent, error) {
	// Agent V2 注册格式：
	// {
	//   "Op": 0,
	//   "Addr": "192.168.1.100:10380",
	//   "MetadataX": {
	//     "AppID": "agent-001",
	//     "Name": "server-agent",
	//     "Address": "192.168.1.100:10380",
	//     "Metadata": {
	//       "agent_code": "agent-001",
	//       "services": "[{...}]"
	//     },
	//     "Scheme": "grpc"
	//   }
	// }

	var registerValue map[string]interface{}
	if err := json.Unmarshal(value, &registerValue); err != nil {
		return nil, fmt.Errorf("failed to unmarshal register value: %w", err)
	}

	metadataX, ok := registerValue["MetadataX"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid MetadataX format")
	}

	agentCode, ok := metadataX["AppID"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid AppID format")
	}

	address, ok := metadataX["Address"].(string)
	if !ok {
		// 尝试从 Addr 获取
		if addr, ok := registerValue["Addr"].(string); ok {
			address = addr
		} else {
			return nil, fmt.Errorf("invalid Address format")
		}
	}

	// 解析服务列表
	var services []models.PackageStatus
	if metadata, ok := metadataX["Metadata"].(map[string]interface{}); ok {
		if servicesJSON, ok := metadata["services"].(string); ok && servicesJSON != "" {
			if err := json.Unmarshal([]byte(servicesJSON), &services); err != nil {
				xlog.Warn("Failed to parse services JSON",
					xlog.String("agent_code", agentCode),
					xlog.FieldErr(err))
			}
		}
	}

	// 获取 hostname（从 address 提取或使用 agent_code）
	hostname := agentCode
	if parts := strings.Split(address, ":"); len(parts) > 0 && parts[0] != "" {
		hostname = parts[0]
	}

	// 从 Metadata 中提取 agent_code（如果明确提供）
	agentCodeFromMeta := agentCode
	if metadata, ok := metadataX["Metadata"].(map[string]interface{}); ok {
		if code, ok := metadata["agent_code"].(string); ok && code != "" {
			agentCodeFromMeta = code
		}
	}

	agent := &models.Agent{
		ID:            agentCode,
		AgentCode:     agentCodeFromMeta, // 设置 AgentCode 字段（统一使用 agent code 作为唯一标识）
		Address:       address,
		Hostname:      hostname,
		Status:        models.AgentStatusOnline,
		Version:       "v2", // Agent V2
		LastHeartbeat: time.Now(),
		RegisterTime:  time.Now(),
		Services:      services,
		Labels:        make(map[string]string),
	}

	// 从 Metadata 提取其他信息
	if metadata, ok := metadataX["Metadata"].(map[string]interface{}); ok {
		if areaID, ok := metadata["area_id"].(string); ok {
			agent.AreaID = areaID
		}
	}

	return agent, nil
}

// extractAgentIDFromKey 从 etcd key 提取 Agent ID
func (ad *AgentDiscovery) extractAgentIDFromKey(key string) string {
	// key 格式: grpc://server-agent/192.168.1.100:10380
	// 需要从 etcd 中查询对应的 agent_code
	// 这里简化处理，通过地址查找
	parts := strings.Split(key, "/")
	if len(parts) > 0 {
		address := parts[len(parts)-1]
		// 通过地址查找 Agent
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		collection := ad.mongoClient.Database("controller").Collection("agents")
		var agent models.Agent
		err := collection.FindOne(ctx, bson.M{"address": address}).Decode(&agent)
		if err == nil {
			return agent.ID
		}
	}
	return ""
}

// upsertAgentToMongo 将 Agent 信息插入或更新到 MongoDB
func (ad *AgentDiscovery) upsertAgentToMongo(ctx context.Context, agent *models.Agent) error {
	collection := ad.mongoClient.Database("controller").Collection("agents")

	// 检查 Agent 是否已存在
	var existingAgent models.Agent
	err := collection.FindOne(ctx, bson.M{"id": agent.ID}).Decode(&existingAgent)
	if err == nil {
		// 更新现有 Agent
		agent.RegisterTime = existingAgent.RegisterTime // 保留注册时间
		update := bson.M{
			"$set": bson.M{
				"agent_code":     agent.AgentCode, // 更新 AgentCode 字段
				"address":        agent.Address,
				"hostname":       agent.Hostname,
				"status":         agent.Status,
				"version":        agent.Version,
				"last_heartbeat": agent.LastHeartbeat,
				"services":       agent.Services,
				"labels":         agent.Labels,
				"area_id":        agent.AreaID,
			},
		}
		_, err = collection.UpdateOne(ctx, bson.M{"id": agent.ID}, update)
	} else if err == mongo.ErrNoDocuments {
		// 插入新 Agent
		_, err = collection.InsertOne(ctx, agent)
	} else {
		return fmt.Errorf("failed to check existing agent: %w", err)
	}

	return err
}

// updateAgentStatus 更新 Agent 状态
func (ad *AgentDiscovery) updateAgentStatus(ctx context.Context, agentID string, status models.AgentStatus) error {
	collection := ad.mongoClient.Database("controller").Collection("agents")
	_, err := collection.UpdateOne(
		ctx,
		bson.M{"id": agentID},
		bson.M{
			"$set": bson.M{
				"status":         status,
				"last_heartbeat": time.Now(),
			},
		},
	)
	return err
}

// PeriodicSync 定期从 etcd 同步 Agent 信息
func (ad *AgentDiscovery) PeriodicSync(ctx context.Context) {
	ticker := time.NewTicker(ad.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			syncCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := ad.SyncAgentsFromEtcd(syncCtx); err != nil {
				xlog.Warn("Failed to sync agents from etcd", xlog.FieldErr(err))
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

// SyncAgentsFromEtcd 从 etcd 同步所有 Agent 到 MongoDB
func (ad *AgentDiscovery) SyncAgentsFromEtcd(ctx context.Context) error {
	xlog.Debug("Syncing agents from etcd",
		xlog.String("watch_prefix", ad.watchPrefix))
	fmt.Printf("[AgentDiscovery] Syncing agents from etcd: watch_prefix=%s\n", ad.watchPrefix)

	// 检查etcd客户端配置
	endpoints := ad.etcdClient.Endpoints()
	fmt.Printf("[AgentDiscovery] Etcd client endpoints: %v\n", endpoints)

	// 测试etcd连接（使用一个简单的key）
	testCtx, testCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer testCancel()
	_, testErr := ad.etcdClient.Get(testCtx, "__health_check__")
	if testErr != nil {
		fmt.Printf("[AgentDiscovery] WARNING: Etcd connection test failed: %v\n", testErr)
	} else {
		fmt.Printf("[AgentDiscovery] Etcd connection test successful\n")
	}

	resp, err := ad.etcdClient.Get(ctx, ad.watchPrefix, clientv3.WithPrefix())
	if err != nil {
		xlog.Error("Failed to get agents from etcd",
			xlog.String("watch_prefix", ad.watchPrefix),
			xlog.FieldErr(err))
		fmt.Printf("[AgentDiscovery] Failed to get agents from etcd: watch_prefix=%s, error=%v\n",
			ad.watchPrefix, err)
		return fmt.Errorf("failed to get agents from etcd: %w", err)
	}

	xlog.Debug("Found agents in etcd",
		xlog.String("watch_prefix", ad.watchPrefix),
		xlog.Int("count", len(resp.Kvs)))
	fmt.Printf("[AgentDiscovery] Found %d agents in etcd: watch_prefix=%s\n",
		len(resp.Kvs), ad.watchPrefix)

	collection := ad.mongoClient.Database("controller").Collection("agents")

	// 获取所有在线 Agent 的 ID
	onlineAgentIDs := make(map[string]bool)

	for _, kv := range resp.Kvs {
		fmt.Printf("[AgentDiscovery] Processing etcd key: %s, value length: %d\n", string(kv.Key), len(kv.Value))
		agent, err := ad.parseAgentFromEtcdValue(kv.Value)
		if err != nil {
			xlog.Warn("Failed to parse agent from etcd",
				xlog.String("key", string(kv.Key)),
				xlog.FieldErr(err))
			fmt.Printf("[AgentDiscovery] Failed to parse agent from etcd: key=%s, error=%v\n",
				string(kv.Key), err)
			continue
		}
		fmt.Printf("[AgentDiscovery] Parsed agent: id=%s, agent_code=%s, address=%s\n",
			agent.ID, agent.AgentCode, agent.Address)

		onlineAgentIDs[agent.ID] = true

		// 更新或插入 Agent
		if err := ad.upsertAgentToMongo(ctx, agent); err != nil {
			xlog.Warn("Failed to upsert agent",
				xlog.String("agent_id", agent.ID),
				xlog.String("address", agent.Address),
				xlog.FieldErr(err))
		} else {
			xlog.Info("Synced agent from etcd to MongoDB",
				xlog.String("agent_id", agent.ID),
				xlog.String("agent_code", agent.AgentCode),
				xlog.String("address", agent.Address),
				xlog.String("status", string(agent.Status)))
			fmt.Printf("[AgentDiscovery] Synced agent from etcd to MongoDB: agent_id=%s, agent_code=%s, address=%s, status=%s\n",
				agent.ID, agent.AgentCode, agent.Address, string(agent.Status))
		}
	}

	// 将不在 etcd 中的 Agent 标记为离线
	// 注意：这里只标记，不删除，保留历史记录
	filter := bson.M{
		"status": models.AgentStatusOnline,
	}
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to find online agents: %w", err)
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var agent models.Agent
		if err := cursor.Decode(&agent); err != nil {
			continue
		}

		if !onlineAgentIDs[agent.ID] {
			// Agent 不在 etcd 中，标记为离线
			if err := ad.updateAgentStatus(ctx, agent.ID, models.AgentStatusOffline); err != nil {
				xlog.Warn("Failed to update agent status",
					xlog.String("agent_id", agent.ID),
					xlog.FieldErr(err))
			}
		}
	}

	return nil
}
