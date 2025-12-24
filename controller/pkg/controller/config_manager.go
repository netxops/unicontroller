package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	clientv3 "go.etcd.io/etcd/client/v3"
	"gopkg.in/yaml.v2"
)

type ConfigManager struct {
	EtcdClient   *clientv3.Client `wire:"-"`
	NacosManager *NacosManager
	KeyManager   *KeyManager
	ctx          context.Context    `wire:"-"`
	cancel       context.CancelFunc `wire:"-"`
	Config       *Config
}

// ProvideConfigManager 为 Wire 依赖注入提供的构造函数
func ProvideConfigManager(km *KeyManager, etcdClient *clientv3.Client, config *Config, nm *NacosManager) (*ConfigManager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &ConfigManager{
		EtcdClient:   etcdClient,
		KeyManager:   km,
		NacosManager: nm,
		ctx:          ctx,
		cancel:       cancel,
		Config:       config,
	}, nil
}

func (cm *ConfigManager) Start() error {
	// 检查基础配置是否存在
	exists, err := cm.checkBaseConfigExists()
	if err != nil {
		return fmt.Errorf("failed to check base config: %v", err)
	}

	// 如果基础配置不存在，则注册
	if !exists {
		if err := cm.registerBaseConfig(); err != nil {
			return fmt.Errorf("failed to register base config: %v", err)
		}
	}

	if err := cm.registerResourceConfigs(); err != nil {
		return fmt.Errorf("failed to register resource configs: %v", err)
	}

	globalVars, err := cm.GetGlobalVariables()
	if err != nil {
		return fmt.Errorf("failed to get global variables: %v", err)
	}

	if len(globalVars) == 0 {
		// 设置一些默认的全局变量
		defaultGlobalVars := map[string]string{
			"environment": "production",
			// ... 其他默认全局变量 ...
		}
		if err := cm.SetGlobalVariables(defaultGlobalVars); err != nil {
			return fmt.Errorf("failed to set default global variables: %v", err)
		}
	}

	// 从Nacos获取初始配置
	err = cm.fetchConfigFromNacos()
	if err != nil {
		return fmt.Errorf("failed to fetch initial config from Nacos: %v", err)
	}

	// 启动Nacos配置监听
	go cm.watchNacosConfig()

	apps, err := cm.ListApps()
	if err != nil {
		return fmt.Errorf("failed to list apps: %v", err)
	}

	for _, appID := range apps {
		_, err := cm.GetAppVariables(appID)
		if err != nil {
			// 如果获取失败，可能是因为变量还不存在，尝试设置默认变量
			defaultVars := map[string]string{
				"app_status": "active",
				// ... 其他默认变量 ...
			}
			if err := cm.SetAppVariables(appID, defaultVars); err != nil {
				fmt.Printf("Failed to set default variables for app %s: %v\n", appID, err)
			}
		}
	}

	go cm.watchConfigs()
	return nil
}

func (cm *ConfigManager) checkBaseConfigExists() (bool, error) {
	key := "/base_config"
	// 如果使用Docker etcd，可能需要等待容器启动，添加重试逻辑
	maxRetries := 10
	retryInterval := 1 * time.Second
	var resp *clientv3.GetResponse
	var err error

	for i := 0; i < maxRetries; i++ {
		ctx, cancel := context.WithTimeout(cm.ctx, 3*time.Second)
		resp, err = cm.EtcdClient.Get(ctx, key)
		cancel()
		if err == nil {
			return len(resp.Kvs) > 0, nil
		}
		// 如果是连接错误，等待后重试
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "no route to host") {
			if i < maxRetries-1 {
				time.Sleep(retryInterval)
				continue
			}
		}
		// 其他错误直接返回
		return false, err
	}
	return false, err
}

func (cm *ConfigManager) registerBaseConfig() error {
	key := "/base_config"
	configJSON, err := json.Marshal(cm.Config.BaseConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	_, err = cm.EtcdClient.Put(cm.ctx, key, string(configJSON))
	if err != nil {
		return fmt.Errorf("failed to store base config in etcd: %v", err)
	}

	fmt.Println("Base configuration registered in etcd")
	return nil
}

func (cm *ConfigManager) registerResourceConfigs() error {
	// 注册 Telegraf 配置
	err := cm.registerResourceConfig(models.ResourceTypeTelegraf, cm.Config.Telegraf)
	if err != nil {
		return fmt.Errorf("failed to register Telegraf config: %v", err)
	}

	// 注册 Minio 配置
	err = cm.registerResourceConfig(models.ResourceTypeMinio, cm.Config.Minio)
	if err != nil {
		return fmt.Errorf("failed to register Minio config: %v", err)
	}

	return nil
}

func (cm *ConfigManager) registerResourceConfig(resourceType models.ResourceType, config interface{}) error {
	// 将配置转换为 map[string]interface{}
	configMap, err := structToMap(config)
	if err != nil {
		return fmt.Errorf("failed to convert %s config to map: %v", resourceType, err)
	}

	// 优先从配置中获取容器名称，如果没有则从 BaseConfig.Resources 获取
	var containerName string
	if name, ok := configMap["name"].(string); ok && name != "" {
		containerName = name
	} else {
		// 如果配置中没有 name，尝试从 BaseConfig.Resources 获取
		containerName, err = cm.GetContainerNameByResourceType(resourceType)
		if err != nil {
			// 如果 BaseConfig 中也没有，使用默认名称
			switch resourceType {
			case models.ResourceTypeTelegraf:
				containerName = "telegraf"
			case models.ResourceTypeMinio:
				containerName = "minio"
			default:
				return fmt.Errorf("failed to get container name for %s: %v", resourceType, err)
			}
		}
		// 将容器名称设置到配置中
		configMap["name"] = containerName
	}

	// 检查配置是否已存在
	existing, err := cm.GetConfig(resourceType, containerName)
	if err == nil && len(existing) > 0 {
		// 配置已存在，不需要重新注册
		return nil
	}

	// 注册配置
	err = cm.UpdateConfig(resourceType, containerName, configMap)
	if err != nil {
		return fmt.Errorf("failed to register %s config: %v", resourceType, err)
	}

	return nil
}

func (cm *ConfigManager) Stop() error {
	cm.cancel()

	// 检查 context 是否已经被取消
	select {
	case <-cm.ctx.Done():
		// context 已经被取消，直接返回 nil
		return nil
	default:
		// context 还没有被取消，关闭 EtcdClient
		return cm.EtcdClient.Close()
	}
}

func (cm *ConfigManager) watchConfigs() {
	watchChan := cm.EtcdClient.Watch(cm.ctx, "/configs/", clientv3.WithPrefix())
	for {
		select {
		case <-cm.ctx.Done():
			return
		case watchResp := <-watchChan:
			for _, event := range watchResp.Events {
				cm.handleConfigChange(event)
			}
		}
	}
}

func (cm *ConfigManager) handleConfigChange(event *clientv3.Event) {
	key := string(event.Kv.Key)
	_, resourceType, resourceID, err := cm.KeyManager.ParseResourceKey(key)
	if err != nil {
		fmt.Printf("Error parsing key %s: %v\n", key, err)
		return
	}

	switch models.ResourceType(resourceType) {
	case models.ResourceTypeTelegraf:
		cm.applyTelegrafConfig(resourceID, event.Kv.Value)
	case models.ResourceTypeAgent:
		cm.applyAgentConfig(resourceID, event.Kv.Value)
	default:
		fmt.Printf("Unknown resource type: %s\n", resourceType)
	}
}

func (cm *ConfigManager) applyTelegrafConfig(resourceID string, configData []byte) {
	// 实现 Telegraf 配置应用逻辑
	fmt.Printf("Applying Telegraf config for resource %s\n", resourceID)
	// TODO: 实现配置应用和重启 Telegraf 服务的逻辑
}

func (cm *ConfigManager) applyAgentConfig(resourceID string, configData []byte) {
	// 实现 agent 配置应用逻辑
	fmt.Printf("Applying agent config for resource %s\n", resourceID)
	// TODO: 实现配置应用和通知 agent 重新加载配置的逻辑
}
func (cm *ConfigManager) UpdateConfig(resourceType models.ResourceType, containerName string, config map[string]interface{}) error {
	key, err := cm.KeyManager.GenerateResourceKey(string(resourceType), containerName)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	_, err = cm.EtcdClient.Put(cm.ctx, key, string(configJSON))
	if err != nil {
		return fmt.Errorf("failed to store config in etcd: %v", err)
	}

	return nil
}

func (cm *ConfigManager) UpdateConfigWithMeta(resourceType models.ResourceType, containerName string, config map[string]interface{}, meta map[string]interface{}) error {
	dataKey, err := cm.KeyManager.GenerateResourceKey(string(resourceType), containerName)
	if err != nil {
		return fmt.Errorf("failed to generate data key: %v", err)
	}
	metaKey := dataKey + "_meta"

	dataJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal meta: %v", err)
	}

	_, err = cm.EtcdClient.Txn(cm.ctx).
		Then(clientv3.OpPut(dataKey, string(dataJSON)), clientv3.OpPut(metaKey, string(metaJSON))).
		Commit()
	if err != nil {
		return fmt.Errorf("failed to store config and meta in etcd: %v", err)
	}

	return nil
}

func (cm *ConfigManager) GetConfigWithMeta(resourceType models.ResourceType, containerName string) (config map[string]interface{}, meta map[string]interface{}, err error) {
	dataKey, err := cm.KeyManager.GenerateResourceKey(string(resourceType), containerName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %v", err)
	}
	metaKey := dataKey + "_meta"

	// 使用事务同时获取配置数据和元数据
	txnResp, err := cm.EtcdClient.Txn(cm.ctx).Then(
		clientv3.OpGet(dataKey),
		clientv3.OpGet(metaKey),
	).Commit()

	if err != nil {
		return nil, nil, fmt.Errorf("failed to get config and meta from etcd: %v", err)
	}

	if !txnResp.Succeeded || len(txnResp.Responses) != 2 {
		return nil, nil, fmt.Errorf("unexpected transaction response")
	}

	// 解析配置数据
	dataResp := txnResp.Responses[0].GetResponseRange()
	if len(dataResp.Kvs) == 0 {
		return nil, nil, fmt.Errorf("config not found for key: %s", dataKey)
	}

	err = json.Unmarshal(dataResp.Kvs[0].Value, &config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// 解析元数据
	metaResp := txnResp.Responses[1].GetResponseRange()
	if len(metaResp.Kvs) > 0 {
		err = json.Unmarshal(metaResp.Kvs[0].Value, &meta)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal meta: %v", err)
		}
	}

	return config, meta, nil
}

func (cm *ConfigManager) GetContainerNameByResourceType(resourceType models.ResourceType) (string, error) {
	// 从 etcd 获取基础配置
	baseConfigKey := "/base_config"
	resp, err := cm.EtcdClient.Get(cm.ctx, baseConfigKey)
	if err != nil {
		return "", fmt.Errorf("failed to get base config from etcd: %v", err)
	}

	if len(resp.Kvs) == 0 {
		return "", fmt.Errorf("base config not found in etcd")
	}

	var baseConfig BaseConfig
	err = json.Unmarshal(resp.Kvs[0].Value, &baseConfig)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal base config: %v", err)
	}

	// 从基础配置中获取容器名称
	containerName, ok := baseConfig.Resources[resourceType]
	if !ok {
		return "", fmt.Errorf("no container name found for resource type: %s", resourceType)
	}

	if len(containerName) == 0 {
		return "", fmt.Errorf("container name not found in base config")
	}

	return containerName, nil
}

func (cm *ConfigManager) ContainerName(resourceType models.ResourceType) (string, error) {
	return cm.GetContainerNameByResourceType(resourceType)
}

func (cm *ConfigManager) GetConfig(resourceType models.ResourceType, containerName string) (map[string]interface{}, error) {
	// 如果没有提供 containerName，则从基础配置中获取
	if containerName == "" {
		var err error
		containerName, err = cm.GetContainerNameByResourceType(resourceType)
		if err != nil {
			return nil, err
		}
	}

	key, err := cm.KeyManager.GenerateResourceKey(string(resourceType), containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	resp, err := cm.EtcdClient.Get(cm.ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get config from etcd: %v", err)
	}

	if len(resp.Kvs) == 0 {
		return nil, fmt.Errorf("no config found for resource: %s", key)
	}

	var config map[string]interface{}
	err = json.Unmarshal(resp.Kvs[0].Value, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	return config, nil
}

func (cm *ConfigManager) GetJson(resourceType models.ResourceType) (string, error) {
	containerName, err := cm.GetContainerNameByResourceType(resourceType)
	if err != nil {
		return "", err
	}
	cfg, err := cm.GetConfig(resourceType, containerName)
	if err != nil {
		return "", err
	}
	jsonData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func (cm *ConfigManager) DeleteConfig(resourceType models.ResourceType, containerName string) error {
	key, err := cm.KeyManager.GenerateResourceKey(string(resourceType), containerName)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	_, err = cm.EtcdClient.Delete(cm.ctx, key)
	if err != nil {
		return fmt.Errorf("failed to delete config from etcd: %v", err)
	}

	return nil
}

func (cm *ConfigManager) ListResourceIDs(resourceType models.ResourceType) ([]string, error) {
	prefix, err := cm.KeyManager.GenerateResourcePrefix(string(resourceType))
	if err != nil {
		return nil, fmt.Errorf("failed to generate key prefix: %v", err)
	}

	resp, err := cm.EtcdClient.Get(cm.ctx, prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, fmt.Errorf("failed to list resource IDs from etcd: %v", err)
	}

	var resourceIDs []string
	for _, kv := range resp.Kvs {
		key := string(kv.Key)
		_, _, resourceID, err := cm.KeyManager.ParseResourceKey(key)
		if err != nil {
			continue // Skip invalid keys
		}
		resourceIDs = append(resourceIDs, resourceID)
	}

	return resourceIDs, nil
}

func (cm *ConfigManager) BatchUpdateConfigs(updates map[models.ResourceType]map[string]map[string]interface{}) error {
	ops := []clientv3.Op{}
	for resourceType, resourceUpdates := range updates {
		for resourceID, config := range resourceUpdates {
			key, err := cm.KeyManager.GenerateResourceKey(string(resourceType), resourceID)
			if err != nil {
				return fmt.Errorf("failed to generate key: %v", err)
			}
			configJSON, err := json.Marshal(config)
			if err != nil {
				return fmt.Errorf("failed to marshal config: %v", err)
			}
			ops = append(ops, clientv3.OpPut(key, string(configJSON)))
		}
	}

	_, err := cm.EtcdClient.Txn(cm.ctx).Then(ops...).Commit()
	if err != nil {
		return fmt.Errorf("failed to batch update configs: %v", err)
	}
	return nil
}

func (cm *ConfigManager) ListConfigsWithDetails(resourceType models.ResourceType) (map[string]map[string]interface{}, error) {
	prefix, err := cm.KeyManager.GenerateResourcePrefix(string(resourceType))
	if err != nil {
		return nil, fmt.Errorf("failed to generate key prefix: %v", err)
	}

	resp, err := cm.EtcdClient.Get(cm.ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to list configs from etcd: %v", err)
	}

	configs := make(map[string]map[string]interface{})
	for _, kv := range resp.Kvs {
		_, _, resourceID, err := cm.KeyManager.ParseResourceKey(string(kv.Key))
		if err != nil {
			continue // Skip invalid keys
		}
		var config map[string]interface{}
		if err := json.Unmarshal(kv.Value, &config); err != nil {
			continue // Skip invalid values
		}
		configs[resourceID] = config
	}

	return configs, nil
}

func (cm *ConfigManager) ListConfigKeys(resourceType models.ResourceType) ([]string, error) {
	prefix, err := cm.KeyManager.GenerateResourcePrefix(string(resourceType))
	if err != nil {
		return nil, fmt.Errorf("failed to generate key prefix: %v", err)
	}

	resp, err := cm.EtcdClient.Get(cm.ctx, prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, fmt.Errorf("failed to list config keys from etcd: %v", err)
	}

	var keys []string
	for _, kv := range resp.Kvs {
		keys = append(keys, string(kv.Key))
	}

	return keys, nil
}

func (cm *ConfigManager) FilterConfigs(resourceType models.ResourceType, filter func(map[string]interface{}) bool) ([]string, error) {
	configs, err := cm.ListConfigsWithDetails(resourceType)
	if err != nil {
		return nil, err
	}

	var filteredIDs []string
	for resourceID, config := range configs {
		if filter(config) {
			filteredIDs = append(filteredIDs, resourceID)
		}
	}

	return filteredIDs, nil
}

func (cm *ConfigManager) CompareConfigVersions(resourceType models.ResourceType, resourceID string, version1, version2 string) (map[string]interface{}, error) {
	key, err := cm.KeyManager.GenerateResourceKey(string(resourceType), resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	// Convert version1 string to int64
	rev1, err := strconv.ParseInt(version1, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version1 as int64: %v", err)
	}

	// Convert version2 string to int64
	rev2, err := strconv.ParseInt(version2, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version2 as int64: %v", err)
	}

	resp1, err := cm.EtcdClient.Get(cm.ctx, key, clientv3.WithRev(rev1))
	if err != nil {
		return nil, fmt.Errorf("failed to get config version1 from etcd: %v", err)
	}

	resp2, err := cm.EtcdClient.Get(cm.ctx, key, clientv3.WithRev(rev2))
	if err != nil {
		return nil, fmt.Errorf("failed to get config version2 from etcd: %v", err)
	}

	var config1, config2 map[string]interface{}
	if len(resp1.Kvs) > 0 {
		if err := json.Unmarshal(resp1.Kvs[0].Value, &config1); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config version1: %v", err)
		}
	}
	if len(resp2.Kvs) > 0 {
		if err := json.Unmarshal(resp2.Kvs[0].Value, &config2); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config version2: %v", err)
		}
	}

	diff := make(map[string]interface{})
	for k, v1 := range config1 {
		if v2, ok := config2[k]; !ok || v1 != v2 {
			diff[k] = map[string]interface{}{"version1": v1, "version2": v2}
		}
	}
	for k, v2 := range config2 {
		if _, ok := config1[k]; !ok {
			diff[k] = map[string]interface{}{"version1": nil, "version2": v2}
		}
	}

	return diff, nil
}

func (cm *ConfigManager) BatchGetConfigs(resourceType models.ResourceType, resourceIDs []string) (map[string]map[string]interface{}, error) {
	ops := make([]clientv3.Op, len(resourceIDs))
	for i, resourceID := range resourceIDs {
		key, err := cm.KeyManager.GenerateResourceKey(string(resourceType), resourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %v", err)
		}
		ops[i] = clientv3.OpGet(key)
	}

	resp, err := cm.EtcdClient.Txn(cm.ctx).Then(ops...).Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to batch get configs from etcd: %v", err)
	}

	configs := make(map[string]map[string]interface{})
	for i, resourceID := range resourceIDs {
		rangeResp := resp.Responses[i].GetResponseRange()
		if len(rangeResp.Kvs) > 0 {
			var config map[string]interface{}
			if err := json.Unmarshal(rangeResp.Kvs[0].Value, &config); err != nil {
				continue // Skip invalid values
			}
			configs[resourceID] = config
		}
	}

	return configs, nil
}

func (cm *ConfigManager) SearchConfigs(resourceType models.ResourceType, searchTerm string) ([]string, error) {
	configs, err := cm.ListConfigsWithDetails(resourceType)
	if err != nil {
		return nil, err
	}

	var matchedIDs []string
	for resourceID, config := range configs {
		configJSON, err := json.Marshal(config)
		if err != nil {
			continue
		}
		if strings.Contains(string(configJSON), searchTerm) {
			matchedIDs = append(matchedIDs, resourceID)
		}
	}

	return matchedIDs, nil
}

func (cm *ConfigManager) GetConfigStats(resourceType models.ResourceType) (map[string]int, error) {
	configs, err := cm.ListConfigsWithDetails(resourceType)
	if err != nil {
		return nil, err
	}

	stats := map[string]int{
		"total_count": len(configs),
		"total_size":  0,
	}

	for _, config := range configs {
		configJSON, err := json.Marshal(config)
		if err != nil {
			continue
		}
		stats["total_size"] += len(configJSON)
	}

	if stats["total_count"] > 0 {
		stats["average_size"] = stats["total_size"] / stats["total_count"]
	}

	return stats, nil
}

// func (cm *ConfigManager) ValidateConfig(resourceType models.ResourceType, config map[string]interface{}) error {
// 	// This is a placeholder implementation. You should replace this with your actual validation logic.
// 	switch resourceType {
// 	case models.ResourceTypeAgent:
// 		return cm.validateAgentConfig(config)
// 	default:
// 		return fmt.Errorf("unknown resource type: %s", resourceType)
// 	}
// }

func (cm *ConfigManager) GetGlobalVariables() (map[string]string, error) {
	globalVarsKey := "/global_variables"
	resp, err := cm.EtcdClient.Get(cm.ctx, globalVarsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get global variables from etcd: %v", err)
	}

	if len(resp.Kvs) == 0 {
		// 如果没有找到全局变量，返回一个空的 map
		return make(map[string]string), nil
	}

	var globalVars map[string]string
	err = json.Unmarshal(resp.Kvs[0].Value, &globalVars)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal global variables: %v", err)
	}

	return globalVars, nil
}

func (cm *ConfigManager) SetGlobalVariables(variables map[string]string) error {
	globalVarsKey := "/global_variables"

	jsonData, err := json.Marshal(variables)
	if err != nil {
		return fmt.Errorf("failed to marshal global variables: %v", err)
	}

	_, err = cm.EtcdClient.Put(cm.ctx, globalVarsKey, string(jsonData))
	if err != nil {
		return fmt.Errorf("failed to set global variables in etcd: %v", err)
	}

	return nil
}

func (cm *ConfigManager) GetAppVariables(appID string) (map[string]string, error) {
	appVarsKey := fmt.Sprintf("/apps/%s/variables", appID)
	resp, err := cm.EtcdClient.Get(cm.ctx, appVarsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get app variables from etcd: %v", err)
	}

	var appVars map[string]string
	if len(resp.Kvs) > 0 {
		err = json.Unmarshal(resp.Kvs[0].Value, &appVars)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal app variables: %v", err)
		}
	} else {
		appVars = make(map[string]string)
	}

	// 获取全局变量
	globalVars, err := cm.GetGlobalVariables()
	if err != nil {
		return nil, fmt.Errorf("failed to get global variables: %v", err)
	}

	// 合并全局变量和应用特定变量，应用特定变量优先
	mergedVars := make(map[string]string)
	for k, v := range globalVars {
		mergedVars[k] = v
	}
	for k, v := range appVars {
		mergedVars[k] = v
	}

	// 特殊处理 runtime_vars
	if runtimeVarsStr, ok := mergedVars["runtime_vars"]; ok {
		runtimeVars := strings.Split(runtimeVarsStr, ",")
		for _, v := range runtimeVars {
			mergedVars[v] = "" // 设置为空字符串，实际值可能需要从其他地方获取
		}
		delete(mergedVars, "runtime_vars")
	}

	return mergedVars, nil
}

func (cm *ConfigManager) SetAppVariables(appID string, variables map[string]string) error {
	appVarsKey := fmt.Sprintf("/apps/%s/variables", appID)

	jsonData, err := json.Marshal(variables)
	if err != nil {
		return fmt.Errorf("failed to marshal app variables: %v", err)
	}

	_, err = cm.EtcdClient.Put(cm.ctx, appVarsKey, string(jsonData))
	if err != nil {
		return fmt.Errorf("failed to set app variables in etcd: %v", err)
	}

	return nil
}

func (cm *ConfigManager) ListApps() ([]string, error) {
	// 使用前缀 "/apps/" 来获取所有应用的键
	prefix := "/apps/"
	resp, err := cm.EtcdClient.Get(cm.ctx, prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, fmt.Errorf("failed to list apps from etcd: %v", err)
	}

	var appIDs []string
	for _, kv := range resp.Kvs {
		key := string(kv.Key)
		// 从键中提取应用 ID
		parts := strings.Split(key, "/")
		if len(parts) >= 3 {
			appID := parts[2]
			// 确保我们只添加唯一的应用 ID
			if !contains(appIDs, appID) {
				appIDs = append(appIDs, appID)
			}
		}
	}

	return appIDs, nil
}

// contains 是一个辅助函数，用于检查一个字符串切片是否包含特定的字符串
func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

// func (cm *ConfigManager) Start() error {
//     // 现有的初始化代码...

//     // 从Nacos获取初始配置
//     err := cm.fetchConfigFromNacos()
//     if err != nil {
//         return fmt.Errorf("failed to fetch initial config from Nacos: %v", err)
//     }

//     // 启动Nacos配置监听
//     go cm.watchNacosConfig()

//     // 现有的其他初始化代码...

//     return nil
// }

func (cm *ConfigManager) fetchConfigFromNacos() error {
	config, err := cm.NacosManager.GetConfig(cm.Config.Nacos.DataID, cm.Config.Nacos.Group)
	if err != nil {
		return fmt.Errorf("failed to get config from Nacos: %v", err)
	}

	// 解析配置并更新到etcd
	return cm.updateConfigFromNacos(config)
}

func (cm *ConfigManager) watchNacosConfig() {
	for {
		err := cm.NacosManager.ListenConfig(cm.Config.Nacos.DataID, cm.Config.Nacos.Group, func(config string) {
			err := cm.updateConfigFromNacos(config)
			if err != nil {
				log.Printf("Failed to update config from Nacos: %v", err)
			}
		})
		if err != nil {
			log.Printf("Nacos config listening failed: %v, retrying in 5 seconds", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (cm *ConfigManager) updateConfigFromNacos(config string) error {
	// 解析Nacos配置
	var nacosConfig map[string]interface{}
	err := yaml.Unmarshal([]byte(config), &nacosConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Nacos config: %v", err)
	}

	// 更新全局变量
	if globalVars, ok := nacosConfig["global_variables"].(map[string]interface{}); ok {
		stringVars := make(map[string]string)
		for k, v := range globalVars {
			stringVars[k] = fmt.Sprintf("%v", v)
		}
		err = cm.SetGlobalVariables(stringVars)
		if err != nil {
			return fmt.Errorf("failed to update global variables: %v", err)
		}
	}

	// 更新应用变量
	if appVars, ok := nacosConfig["app_variables"].(map[string]interface{}); ok {
		for appID, vars := range appVars {
			if varMap, ok := vars.(map[string]interface{}); ok {
				stringVars := make(map[string]string)
				for k, v := range varMap {
					// 处理 runtime_vars 特殊情况
					if k == "runtime_vars" {
						if runtimeVars, ok := v.([]interface{}); ok {
							runtimeVarsStr := make([]string, len(runtimeVars))
							for i, rv := range runtimeVars {
								runtimeVarsStr[i] = fmt.Sprintf("%v", rv)
							}
							stringVars[k] = strings.Join(runtimeVarsStr, ",")
						}
					} else {
						stringVars[k] = fmt.Sprintf("%v", v)
					}
				}
				err = cm.SetAppVariables(appID, stringVars)
				if err != nil {
					return fmt.Errorf("failed to update variables for app %s: %v", appID, err)
				}
			}
		}
	}

	return nil
}

// structToMap 将结构体转换为 map[string]interface{}
func structToMap(v interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("input must be a struct or a pointer to a struct")
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// 跳过未导出的字段
		if !fieldType.IsExported() {
			continue
		}

		tag := fieldType.Tag.Get("yaml")
		if tag == "-" {
			continue
		}

		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = fieldType.Name
		}

		switch field.Kind() {
		case reflect.Struct:
			nestedMap, err := structToMap(field.Interface())
			if err != nil {
				return nil, err
			}
			result[name] = nestedMap
		case reflect.Slice, reflect.Array:
			sliceLen := field.Len()
			sliceMap := make([]interface{}, sliceLen)
			for j := 0; j < sliceLen; j++ {
				elem := field.Index(j)
				if elem.Kind() == reflect.Struct {
					nestedMap, err := structToMap(elem.Interface())
					if err != nil {
						return nil, err
					}
					sliceMap[j] = nestedMap
				} else {
					sliceMap[j] = elem.Interface()
				}
			}
			result[name] = sliceMap
		case reflect.Map:
			mapKeys := field.MapKeys()
			mapValue := make(map[string]interface{})
			for _, key := range mapKeys {
				value := field.MapIndex(key)
				if value.Kind() == reflect.Struct {
					nestedMap, err := structToMap(value.Interface())
					if err != nil {
						return nil, err
					}
					mapValue[key.String()] = nestedMap
				} else {
					mapValue[key.String()] = value.Interface()
				}
			}
			result[name] = mapValue
		default:
			result[name] = field.Interface()
		}
	}

	return result, nil
}

func yamlToMap(yamlStr string) (map[string]interface{}, error) {
	var result map[string]interface{}

	err := yaml.Unmarshal([]byte(yamlStr), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	// 递归处理每一级
	processedResult := processMap(result)

	return processedResult, nil
}

func processMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		switch value := v.(type) {
		case map[interface{}]interface{}:
			// 将 map[interface{}]interface{} 转换为 map[string]interface{}
			result[k] = processMap(toStringKeyMap(value))
		case []interface{}:
			// 处理数组
			result[k] = processSlice(value)
		default:
			// 其他类型直接赋值
			result[k] = v
		}
	}
	return result
}

func processSlice(s []interface{}) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		switch value := v.(type) {
		case map[interface{}]interface{}:
			// 将 map[interface{}]interface{} 转换为 map[string]interface{}
			result[i] = processMap(toStringKeyMap(value))
		case []interface{}:
			// 递归处理嵌套数组
			result[i] = processSlice(value)
		default:
			// 其他类型直接赋值
			result[i] = v
		}
	}
	return result
}

func toStringKeyMap(m map[interface{}]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		if key, ok := k.(string); ok {
			result[key] = v
		}
	}
	return result
}
