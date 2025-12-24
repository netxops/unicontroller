package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/netxops/utils/tools"
	"github.com/tidwall/gjson"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const DefaultEtcdContainerName = "etcd-main"

type SafeResourceMap struct {
	sync.RWMutex
	m map[string]*models.ResourceInfo
}

type ResourceManager struct {
	Config       *Config
	dockerClient *client.Client `wire:"-"`
	Resources    *tools.SafeMap[string, *models.ResourceInfo]
	KeyManager   *KeyManager
	eventChan    chan events.Message `wire:"-"`
	doneChan     chan struct{}       `wire:"-"`
}

// ProvideResourceManager 为 Wire 依赖注入提供的构造函数
func ProvideResourceManager(km *KeyManager, c *Config) (*ResourceManager, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.41"))
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}

	rm := &ResourceManager{
		dockerClient: cli,
		Config:       c,
		Resources:    tools.NewSafeMap[string, *models.ResourceInfo](),
		KeyManager:   km,
		eventChan:    make(chan events.Message),
		doneChan:     make(chan struct{}),
	}

	go rm.listenForEvents()
	go rm.periodicSync()

	return rm, nil
}

func (rm *ResourceManager) listenForEvents() {
	for {
		select {
		case event := <-rm.eventChan:
			rm.handleEvent(event)
		case <-rm.doneChan:
			return
		}
	}
}

func (rm *ResourceManager) handleEvent(event events.Message) {
	if event.Type == events.ContainerEventType {
		containerID := event.Actor.ID
		multiLevelKey, err := rm.GetResourceFromContainerID(containerID)
		if err != nil {
			log.Printf("Error retrieving resource for container %s: %v", containerID, err)
			return
		}

		switch event.Action {
		case "start", "die", "stop", "pause", "unpause":
			rm.updateResourceStatus(multiLevelKey, containerID)
		case "destroy":
			rm.Resources.Delete(multiLevelKey)
		}
	}
}

func (rm *ResourceManager) GetStatus() map[string]interface{} {
	status := make(map[string]interface{})

	// 获取所有资源的状态
	resourceStatuses := make(map[string]interface{})
	rm.Resources.Range(func(key string, info *models.ResourceInfo) bool {
		resourceStatuses[key] = map[string]interface{}{
			"containerID": info.ContainerID,
			"name":        info.Name,
			"type":        info.Type,
			"status":      info.Status,
			"metadata":    info.Metadata,
			"ports":       info.Ports,
			"lastUpdated": info.LastUpdated,
		}
		return true
	})
	status["resources"] = resourceStatuses

	// 获取 Docker 客户端信息
	if rm.dockerClient != nil {
		dockerInfo, err := rm.dockerClient.Info(context.Background())
		if err == nil {
			status["docker_info"] = map[string]interface{}{
				"containers":         dockerInfo.Containers,
				"containers_running": dockerInfo.ContainersRunning,
				"containers_paused":  dockerInfo.ContainersPaused,
				"containers_stopped": dockerInfo.ContainersStopped,
				"images":             dockerInfo.Images,
			}
		} else {
			status["docker_info_error"] = err.Error()
		}
	}

	// 获取配置信息
	if rm.Config != nil {
		status["config"] = map[string]interface{}{
			"etcd_config": rm.Config.EtcdConfig,
			// 添加其他配置信息...
		}
	}

	// 获取 KeyManager 信息
	if rm.KeyManager != nil {
		status["key_manager"] = "initialized"
	} else {
		status["key_manager"] = "not initialized"
	}

	// 获取事件监听状态
	status["event_listener"] = map[string]interface{}{
		"is_running": rm.doneChan != nil,
	}

	return status
}

func (rm *ResourceManager) GetResourceFromContainerID(containerID string) (string, error) {
	var multiLevelKey string
	rm.Resources.Range(func(key string, value *models.ResourceInfo) bool {
		if containerID == value.ContainerID {
			multiLevelKey = key
			return false
		}
		return true
	})
	if multiLevelKey == "" {
		return multiLevelKey, fmt.Errorf("no resource found for container ID %s", containerID)
	}
	return multiLevelKey, nil
}

func (rm *ResourceManager) updateResourceStatus(multiLevelKey, containerID string) error {
	log.Printf("Updating resource status for container %s with key %s", containerID, multiLevelKey)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	containerJSON, err := rm.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		if client.IsErrNotFound(err) {
			// 容器不存在，更新状态为 "removed"
			rm.Resources.Set(multiLevelKey, &models.ResourceInfo{
				ContainerID: containerID,
				Status:      "removed",
				LastUpdated: time.Now(),
			})
			return nil
		}
		return fmt.Errorf("error inspecting container %s: %v", containerID, err)
	}

	status := mapDockerStatusToResourceStatus(containerJSON.State.Status)
	log.Printf("Mapped Docker status %s to resource status %s for container %s", containerJSON.State.Status, status, containerID)

	metadata := map[string]string{
		"image":       containerJSON.Config.Image,
		"created":     containerJSON.Created,
		"started_at":  containerJSON.State.StartedAt,
		"finished_at": containerJSON.State.FinishedAt,
		"ip_address":  containerJSON.NetworkSettings.IPAddress,
	}

	log.Printf("Collected basic metadata for container %s", containerID)

	// Add exposed ports to metadata
	for port := range containerJSON.Config.ExposedPorts {
		metadata["exposed_port_"+string(port)] = "true"
	}

	// Add labels to metadata
	for k, v := range containerJSON.Config.Labels {
		metadata["label_"+k] = v
	}

	metadata["network_mode"] = string(containerJSON.HostConfig.NetworkMode)
	metadata["port_bindings"] = fmt.Sprintf("%v", containerJSON.HostConfig.PortBindings)

	log.Printf("Added additional metadata for container %s", containerID)

	// Get container stats
	statsReader, err := rm.dockerClient.ContainerStats(ctx, containerID, false)
	if err == nil {
		defer statsReader.Body.Close()

		var stats container.StatsResponse
		if err := json.NewDecoder(statsReader.Body).Decode(&stats); err == nil {
			metadata["cpu_usage"] = fmt.Sprintf("%d", stats.CPUStats.CPUUsage.TotalUsage)
			metadata["memory_usage"] = fmt.Sprintf("%d", stats.MemoryStats.Usage)
			if stats.Networks != nil {
				if eth0, ok := stats.Networks["eth0"]; ok {
					metadata["network_rx_bytes"] = fmt.Sprintf("%d", eth0.RxBytes)
					metadata["network_tx_bytes"] = fmt.Sprintf("%d", eth0.TxBytes)
				}
			}
			log.Printf("Successfully added stats to metadata for container %s", containerID)
		} else {
			log.Printf("Error decoding container stats for %s: %v", containerID, err)
		}
	} else {
		log.Printf("Error getting container stats for %s: %v", containerID, err)
	}

	// 获取端口映射信息
	ports := make(map[string]string)
	for containerPort, bindings := range containerJSON.NetworkSettings.Ports {
		if len(bindings) > 0 {
			ports[string(containerPort)] = bindings[0].HostPort
		}
	}

	if resource, exists := rm.Resources.Get(multiLevelKey); exists {
		resource.Status = status
		resource.LastUpdated = time.Now()
		resource.Metadata = metadata
		resource.Name = containerJSON.Name
		resource.ContainerID = containerID // Update ID in case it changed
		resource.Ports = ports
		rm.Resources.Set(multiLevelKey, resource)
		log.Printf("Updated existing resource %s in resources map", multiLevelKey)
	} else {
		rm.Resources.Set(multiLevelKey, &models.ResourceInfo{
			ContainerID: containerID,
			Name:        containerJSON.Name,
			Type:        models.ResourceType(containerJSON.Config.Labels["resource_type"]),
			Status:      status,
			Metadata:    metadata,
			Ports:       ports,
			LastUpdated: time.Now(),
		})
		log.Printf("Added new resource %s to resources map", multiLevelKey)
	}

	log.Printf("Finished updating resource status for container %s with key %s", containerID, multiLevelKey)
	return nil
}
func mapDockerStatusToResourceStatus(dockerStatus string) string {
	switch dockerStatus {
	case "created", "running", "paused", "restarting", "removing", "exited", "dead":
		return dockerStatus
	default:
		return string(models.ResourceStatusUnknown)
	}
}

func (rm *ResourceManager) periodicSync() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.fullSync()
		case <-rm.doneChan:
			return
		}
	}
}

func (rm *ResourceManager) fullSync() {
	containers, err := rm.dockerClient.ContainerList(context.Background(), container.ListOptions{All: true})
	if err != nil {
		log.Printf("Error listing containers: %v", err)
		return
	}

	for _, c := range containers {
		multiLevelKey, err := rm.GetResourceFromContainerID(c.ID)
		if err != nil {
			continue
		}

		rm.updateResourceStatus(multiLevelKey, c.ID)
	}
}

func (rm *ResourceManager) Start() error {
	// 首先刷新现有资源信息
	if err := rm.refreshResourceInfo(); err != nil {
		return fmt.Errorf("failed to refresh resource info: %v", err)
	}

	// 定义需要启动的资源类型
	resourcesToStart := []struct {
		Type       models.ResourceType
		DockerName string
		ConfigFn   func() map[string]interface{}
	}{}

	// 根据配置决定是否启动 Docker etcd
	// 优先检查显式设置的 use_docker_etcd 配置
	useDockerEtcd := true  // 默认值，向后兼容
	explicitlySet := false // 标记是否显式设置了 use_docker_etcd

	// 调试：打印配置信息
	if rm.Config != nil {
		log.Printf("Config.UseDockerEtcd: %v", rm.Config.UseDockerEtcd)
		if rm.Config.EtcdConfig != nil {
			log.Printf("EtcdConfig: host=%v, use_docker_etcd=%v", rm.Config.EtcdConfig["host"], rm.Config.EtcdConfig["use_docker_etcd"])
		} else {
			log.Printf("EtcdConfig is nil")
		}
	}

	if rm.Config != nil {
		// 优先级 1: 检查 EtcdConfig 中的 use_docker_etcd（最具体）
		if rm.Config.EtcdConfig != nil {
			if useDocker, ok := rm.Config.EtcdConfig["use_docker_etcd"].(bool); ok {
				useDockerEtcd = useDocker
				explicitlySet = true
				log.Printf("Using etcd.use_docker_etcd setting: %v", useDockerEtcd)
			}
		}

		// 优先级 2: 如果 EtcdConfig 中没有设置，检查 Config 中的 UseDockerEtcd
		// 注意：由于 Go 的零值问题，如果配置文件中没有设置 use_docker_etcd，
		// 它会是 false（零值）。为了区分"未设置"和"显式设置为 false"，
		// 我们检查 EtcdConfig 是否存在 host：如果有 host 配置，说明用户配置了 etcd，
		// 此时 UseDockerEtcd 的值（无论 true/false）都认为是显式设置
		if !explicitlySet {
			if rm.Config.EtcdConfig != nil && rm.Config.EtcdConfig["host"] != nil {
				// 有 etcd 配置，尊重 use_docker_etcd 的设置
				// 如果为 false，使用外部 etcd；如果为 true，使用 Docker etcd
				useDockerEtcd = rm.Config.UseDockerEtcd
				explicitlySet = true
				if !useDockerEtcd {
					log.Printf("use_docker_etcd is false, using external etcd (host: %v)", rm.Config.EtcdConfig["host"])
				} else {
					log.Printf("use_docker_etcd is true, using Docker etcd")
				}
			} else if rm.Config.UseDockerEtcd {
				// 没有 etcd 配置，但 use_docker_etcd 为 true，使用 Docker etcd
				useDockerEtcd = true
				explicitlySet = true
				log.Printf("use_docker_etcd is true, using Docker etcd")
			}
			// 如果 UseDockerEtcd 为 false 且没有 EtcdConfig，可能是零值，使用默认值
		}

		// 如果都没有显式设置，使用默认值（Docker etcd，向后兼容）
		if !explicitlySet {
			useDockerEtcd = true
			log.Printf("use_docker_etcd not explicitly set, using default: Docker etcd (backward compatible)")
		}
	}

	if useDockerEtcd {
		log.Printf("Using Docker etcd container")
		resourcesToStart = append(resourcesToStart, struct {
			Type       models.ResourceType
			DockerName string
			ConfigFn   func() map[string]interface{}
		}{
			models.ResourceTypeEtcd, rm.getEtcdConfig()["name"].(string), rm.getEtcdConfig,
		})
	} else {
		log.Printf("Using external etcd, skipping Docker etcd container startup")
	}

	// 在这里添加其他需要启动的资源

	for _, resource := range resourcesToStart {
		if err := rm.startOrCreateResource(resource.Type, resource.DockerName, resource.ConfigFn); err != nil {
			return fmt.Errorf("failed to start or create %s: %v", resource.Type, err)
		}
	}

	// 启动其他 Docker 容器
	// if err := rm.startOtherDockerContainers(); err != nil {
	// 	return fmt.Errorf("failed to start other Docker containers: %v", err)
	// }

	return nil
}

func (rm *ResourceManager) createAndStartResource(resourceType models.ResourceType, containerName string, config map[string]interface{}, autoStart bool) (string, error) {
	ctx := context.Background()

	// 检查并拉取镜像
	imageName, ok := config["image"].(string)
	if !ok {
		return "", fmt.Errorf("image name not provided or invalid")
	}

	log.Printf("Creating resource of type %s with name %s using image %s", resourceType, containerName, imageName)

	// 检查是否存在同名容器，如果存在则先删除
	if err := rm.removeContainerByNameIfExists(ctx, containerName); err != nil {
		log.Printf("Warning: failed to remove existing container %s: %v", containerName, err)
		// 不返回错误，继续尝试创建
	}

	if err := rm.ensureImageExists(ctx, imageName); err != nil {
		return "", err
	}

	// 准备容器配置
	containerConfig, hostConfig := rm.prepareContainerConfig(resourceType, containerName, config)

	// 创建容器
	resp, err := rm.dockerClient.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, containerName)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %v", err)
	}
	log.Printf("Successfully created container with ID: %s", resp.ID)

	// 生成新资源的键
	multiLevelKey, err := rm.KeyManager.GenerateResourceKey(string(resourceType), containerName)
	if err != nil {
		return "", fmt.Errorf("failed to generate key for resource: %v", err)
	}
	log.Printf("Generated resource key: %s", multiLevelKey)

	if autoStart {
		log.Printf("Auto-starting container %s", resp.ID)
		if err := rm.dockerClient.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
			return "", fmt.Errorf("failed to start container: %v", err)
		}
		log.Printf("Successfully started container %s", resp.ID)

		if err := rm.waitForContainerRunning(ctx, resp.ID); err != nil {
			return "", fmt.Errorf("container failed to reach running state: %v", err)
		}
		if err := rm.updateResourceStatus(multiLevelKey, resp.ID); err != nil {
			return "", fmt.Errorf("failed to update resource status: %v", err)
		}

		if resourceType == models.ResourceTypeEtcd {
			resourceInfo, err := rm.GetResourceInfo(multiLevelKey)
			if err != nil {
				return "", fmt.Errorf("failed to get resource info for %s: %v", multiLevelKey, err)
			}
			if err := rm.waitForEtcdReady(ctx, resourceInfo); err != nil {
				return "", fmt.Errorf("etcd service failed to become ready: %v", err)
			}
		}
	}

	if err := rm.updateResourceStatus(multiLevelKey, resp.ID); err != nil {
		return "", fmt.Errorf("failed to update resource status: %v", err)
	}
	log.Printf("Updated resource status for key %s", multiLevelKey)

	return multiLevelKey, nil
}

func (rm *ResourceManager) ensureImageExists(ctx context.Context, imageName string) error {
	_, _, err := rm.dockerClient.ImageInspectWithRaw(ctx, imageName)
	if err != nil {
		if client.IsErrNotFound(err) {
			log.Printf("Image %s not found locally, attempting to pull...", imageName)
			out, err := rm.dockerClient.ImagePull(ctx, imageName, image.PullOptions{})
			if err != nil {
				return fmt.Errorf("failed to pull image %s: %v", imageName, err)
			}
			defer out.Close()
			if _, err = io.Copy(io.Discard, out); err != nil {
				return fmt.Errorf("error while pulling image %s: %v", imageName, err)
			}
			log.Printf("Successfully pulled image %s", imageName)
		} else {
			return fmt.Errorf("error inspecting image %s: %v", imageName, err)
		}
	}
	return nil
}

func (rm *ResourceManager) startOrCreateResource(resourceType models.ResourceType, dockerName string, getConfigFn func() map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 删除现有资源（如果存在）
	var wg sync.WaitGroup
	deletionErrors := make(chan error, 1)
	rm.Resources.Range(func(multiLevelKey string, info *models.ResourceInfo) bool {
		if info.Type == resourceType {
			wg.Add(1)
			go func() {
				defer wg.Done()
				log.Printf("Deleting existing %s container (%s)", resourceType, info.ContainerID)
				if err := rm.DeleteResource(multiLevelKey); err != nil {
					log.Printf("Warning: failed to delete existing %s container: %v", resourceType, err)
					select {
					case deletionErrors <- err:
					default:
					}
				}
			}()
			return false
		}
		return true
	})

	// 等待删除操作完成
	wg.Wait()
	select {
	case err := <-deletionErrors:
		return fmt.Errorf("error occurred while deleting existing resources: %v", err)
	default:
	}

	// 创建新资源
	config := getConfigFn()
	resultChan := make(chan string)
	errorChan := make(chan error)

	go func() {
		multiLevelKey, err := rm.createAndStartResource(resourceType, dockerName, config, true)
		if err != nil {
			errorChan <- fmt.Errorf("failed to create or start %s resource: %v", resourceType, err)
			return
		}
		resultChan <- multiLevelKey
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("timeout while creating or starting %s resource", resourceType)
	case err := <-errorChan:
		return err
	case multiLevelKey := <-resultChan:
		log.Printf("%s container (key: %s) is now running and service is ready", resourceType, multiLevelKey)
		return nil
	}
}

func (rm *ResourceManager) CreateResource(resourceType models.ResourceType, containerName string, config map[string]interface{}, autoStart bool) (string, error) {
	return rm.createAndStartResource(resourceType, containerName, config, autoStart)
}

func (rm *ResourceManager) getEtcdConfig() map[string]interface{} {
	etcdConfig, _ := json.Marshal(rm.Config.EtcdConfig)
	etcdImage := gjson.Get(string(etcdConfig), "image").String()
	etcdImage = tools.Conditional(etcdImage == "", "quay.io/coreos/etcd:v3.5.0", etcdImage).(string)
	etcdPort := gjson.Get(string(etcdConfig), "port").Int()
	etcdPort = tools.Conditional(etcdPort == 0, int64(2379), etcdPort).(int64)

	etcdHostPort := gjson.Get(string(etcdConfig), "hostPort").Int()
	etcdHostPort = tools.Conditional(etcdHostPort == 0, int64(2379), etcdHostPort).(int64)

	name := gjson.Get(string(etcdConfig), "name").String()
	name = tools.Conditional(name == "", DefaultEtcdContainerName, name).(string)

	// 定义数据卷路径
	dataDir := gjson.Get(string(etcdConfig), "dataDir").String()
	dataDir = tools.Conditional(dataDir == "", "/var/lib/etcd", dataDir).(string)

	return map[string]interface{}{
		"image":   etcdImage,
		"command": "/usr/local/bin/etcd",
		"ports": map[string]interface{}{
			fmt.Sprintf("%d/tcp", etcdPort): etcdHostPort,
		},
		"environment": []string{
			fmt.Sprintf("ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:%d", etcdPort),
			fmt.Sprintf("ETCD_ADVERTISE_CLIENT_URLS=http://0.0.0.0:%d", etcdPort),
			fmt.Sprintf("ETCD_DATA_DIR=%s", dataDir),
		},
		"volumes": []string{
			fmt.Sprintf("%s:%s", dataDir, dataDir),
		},
		"name": name,
	}
}
func (rm *ResourceManager) startOtherDockerContainers() error {
	// 遍历所有资源，启动非 etcd 和非 vector 的容器
	rm.Resources.Range(func(key string, info *models.ResourceInfo) bool {
		if info.Type != models.ResourceTypeEtcd && info.Status != "running" {
			if err := rm.StartResource(key); err != nil {
				log.Printf("Failed to start container %s: %v", info.ContainerID, err)
			} else {
				log.Printf("Started container %s", info.ContainerID)
			}
		}
		return true
	})

	return nil
}

// // getVectorPortFromConfig 从配置中获取 Vector 端口

// func (rm *ResourceManager) getEtcdHostPortFromConfig() int {
// 	if rm.Config != nil && rm.Config.EtcdConfig != nil {
// 		if hostPort, ok := rm.Config.EtcdConfig["hostPort"].(int); ok && hostPort > 0 {
// 			return hostPort
// 		}
// 		// ... 其他类型检查 ...
// 	}
// 	return rm.getEtcdPortFromConfig() // 默认使用容器端口
// }

// // getEtcdImageFromConfig 从配置中获取 etcd 镜像
// func (rm *ResourceManager) getEtcdImageFromConfig() string {
// 	// 默认镜像
// 	defaultImage := "quay.io/coreos/etcd:v3.5.0"

// 	if rm.Config != nil {
// 		if etcdImage, ok := rm.Config.EtcdConfig["image"].(string); ok && etcdImage != "" {
// 			return etcdImage
// 		}
// 	}

// 	return defaultImage
// }

// // getEtcdPortFromConfig 从配置中获取 etcd 端口
// func (rm *ResourceManager) getEtcdPortFromConfig() int {
// 	// 默认端口
// 	defaultPort := 2379

// 	// 如果 Config 中有配置，则使用配置中的端口
// 	if rm.Config != nil && rm.Config.EtcdConfig != nil {
// 		// 尝试获取端口配置
// 		if etcdPort, ok := rm.Config.EtcdConfig["port"].(int); ok && etcdPort > 0 {
// 			return etcdPort
// 		}

// 		// 尝试将字符串转换为整数
// 		if etcdPortStr, ok := rm.Config.EtcdConfig["port"].(string); ok && etcdPortStr != "" {
// 			if port, err := strconv.Atoi(etcdPortStr); err == nil && port > 0 {
// 				return port
// 			}
// 		}

// 		// 尝试将浮点数转换为整数
// 		if etcdPortFloat, ok := rm.Config.EtcdConfig["port"].(float64); ok && etcdPortFloat > 0 {
// 			return int(etcdPortFloat)
// 		}
// 	}

// 	return defaultPort
// }

// waitForContainerRunning 等待容器达到运行状态
func (rm *ResourceManager) waitForContainerRunning(ctx context.Context, containerID string) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for container to start")
		case <-ticker.C:
			containerJSON, err := rm.dockerClient.ContainerInspect(ctx, containerID)
			if err != nil {
				if client.IsErrNotFound(err) {
					return fmt.Errorf("container was removed")
				}
				log.Printf("Error inspecting container: %v", err)
				continue
			}

			if containerJSON.State.Status == "running" {
				return nil
			}
		}
	}
}

// waitForEtcdReady 等待 etcd 服务在容器内启动并可用
// func (rm *ResourceManager) waitForEtcdReady(ctx context.Context, etcdInfo *models.ResourceInfo) error {
// 	// 获取 etcd 容器的端口映射
// 	hostPort, ok := etcdInfo.Ports["2379/tcp"]
// 	if !ok {
// 		return fmt.Errorf("etcd container does not have port 2379 mapped")
// 	}

// 	ticker := time.NewTicker(500 * time.Millisecond)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return fmt.Errorf("timeout waiting for etcd to become ready")
// 		case <-ticker.C:
// 			// 尝试连接到 etcd 服务
// 			endpoint := fmt.Sprintf("http://localhost:%s", hostPort)
// 			client, err := clientv3.New(clientv3.Config{
// 				Endpoints:   []string{endpoint},
// 				DialTimeout: 2 * time.Second,
// 			})

// 			if err != nil {
// 				log.Printf("Etcd not yet ready, connection error: %v", err)
// 				continue
// 			}

// 			// 尝试执行一个简单的操作来验证 etcd 是否正常工作
// 			_, err = client.Get(ctx, "health_check")
// 			client.Close()

// 			if err != nil {
// 				log.Printf("Etcd not yet ready, operation error: %v", err)
// 				continue
// 			}

// 			log.Printf("Etcd is now ready and accepting connections")
// 			return nil
// 		}
// 	}
// }

func (rm *ResourceManager) waitForEtcdReady(ctx context.Context, etcdInfo *models.ResourceInfo) error {
	// 查找 etcd 的端口映射
	var hostPort string
	for containerPort, mappedPort := range etcdInfo.Ports {
		if strings.HasPrefix(containerPort, "2379/") {
			hostPort = mappedPort
			break
		}
	}

	if hostPort == "" {
		return fmt.Errorf("etcd container does not have port 2379 mapped")
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for etcd to become ready")
		case <-ticker.C:
			// 尝试连接到 etcd 服务
			endpoint := fmt.Sprintf("http://localhost:%s", hostPort)
			client, err := clientv3.New(clientv3.Config{
				Endpoints:   []string{endpoint},
				DialTimeout: 2 * time.Second,
			})

			if err != nil {
				log.Printf("Etcd not yet ready, connection error: %v", err)
				continue
			}

			// 尝试执行一个简单的操作来验证 etcd 是否正常工作
			_, err = client.Get(ctx, "health_check")
			client.Close()

			if err != nil {
				log.Printf("Etcd not yet ready, operation error: %v", err)
				continue
			}

			log.Printf("Etcd is now ready and accepting connections on port %s", hostPort)
			return nil
		}
	}
}

func (rm *ResourceManager) Stop() error {
	close(rm.doneChan)
	return rm.dockerClient.Close()
}

func (rm *ResourceManager) refreshResourceInfo() error {
	containers, err := rm.dockerClient.ContainerList(context.Background(), container.ListOptions{All: true})
	if err != nil {
		// 检查是否为权限错误
		if strings.Contains(err.Error(), "permission denied") {
			log.Printf("Warning: Docker permission denied while trying to refresh resource info, skipping: %v", err)
			// 权限错误时跳过，初始化空的资源列表
			rm.Resources = tools.NewSafeMap[string, *models.ResourceInfo]()
			return nil
		}
		// 其他错误也记录警告并跳过
		log.Printf("Warning: Failed to list containers while refreshing resource info, skipping: %v", err)
		rm.Resources = tools.NewSafeMap[string, *models.ResourceInfo]()
		return nil
	}

	rm.Resources = tools.NewSafeMap[string, *models.ResourceInfo]()
	for _, c := range containers {
		resourceType := models.ResourceType(c.Labels["resource_type"])
		containerName := c.Labels["container_name"]
		if resourceType == "" {
			continue // Skip containers that are not managed by our system
		}
		if containerName == "" {
			continue // Skip containers without a container name
		}

		multiLevelKey, err := rm.KeyManager.GenerateResourceKey(string(resourceType), containerName)
		if err != nil {
			return fmt.Errorf("failed to generate key for resource %s: %v", c.ID, err)
		}

		// rm.Resources.Set(multiLevelKey, &models.ResourceInfo{
		// 	ContainerID: c.ID,
		// 	Name:        c.Names[0][1:],
		// 	Type:        resourceType,
		// 	Status:      c.State,
		// 	Metadata: map[string]string{
		// 		"image": c.Image,
		// 	},
		// })
		err = rm.updateResourceStatus(multiLevelKey, c.ID)
		if err != nil {
			return fmt.Errorf("failed to update resource status for container %s: %v", c.ID, err)
		}
	}

	return nil
}

func (rm *ResourceManager) GetResourceInfo(multiLevelKey string) (*models.ResourceInfo, error) {
	info, ok := rm.Resources.Get(multiLevelKey)
	if !ok {
		return nil, fmt.Errorf("resource with key %s not found", multiLevelKey)
	}
	return info, nil
}

func (rm *ResourceManager) StartResource(multiLevelKey string) error {
	info, err := rm.GetResourceInfo(multiLevelKey)
	if err != nil {
		return err
	}

	ctx := context.Background()
	err = rm.dockerClient.ContainerStart(ctx, info.ContainerID, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("failed to start resource %s: %v", multiLevelKey, err)
	}

	rm.updateResourceStatus(multiLevelKey, info.ContainerID)

	return nil
}

// func (rm *ResourceManager) StopResource(multiLevelKey string) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
// 	defer cancel()

// 	info, err := rm.GetResourceInfo(multiLevelKey)
// 	if err != nil {
// 		return err
// 	}
// 	containerID := info.ContainerID

// 	// 设置停止超时为10秒
// 	timeout := 10 * time.Second
// 	seconds := int(timeout.Seconds())
// 	err = rm.dockerClient.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &seconds})
// 	if err != nil {
// 		return fmt.Errorf("failed to stop resource %s: %v", multiLevelKey, err)
// 	}

// 	// 使用带超时的轮询来检查容器状态
// 	ticker := time.NewTicker(500 * time.Millisecond)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return fmt.Errorf("timeout waiting for container %s to stop", containerID)
// 		case <-ticker.C:
// 			containerJSON, err := rm.dockerClient.ContainerInspect(ctx, containerID)
// 			if err != nil {
// 				if client.IsErrNotFound(err) {
// 					// 容器已经被移除，认为停止成功
// 					err = rm.updateResourceStatus(multiLevelKey, containerID)
// 					if err != nil {
// 						return fmt.Errorf("failed to update resource status after container removal: %v", err)
// 					}
// 					return nil
// 				}
// 				return fmt.Errorf("failed to inspect container %s: %v", containerID, err)
// 			}
// 			if containerJSON.State.Status == "exited" || containerJSON.State.Status == "dead" {
// 				err = rm.updateResourceStatus(multiLevelKey, containerID)
// 				if err != nil {
// 					return fmt.Errorf("failed to update resource status after stopping: %v", err)
// 				}
// 				return nil
// 			}
// 		}
// 	}
// }

func (rm *ResourceManager) StopResource(multiLevelKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	info, err := rm.GetResourceInfo(multiLevelKey)
	if err != nil {
		return err
	}
	containerID := info.ContainerID

	// 设置停止超时为30秒
	timeout := 30 * time.Second
	seconds := int(timeout.Seconds())
	err = rm.dockerClient.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &seconds})
	if err != nil {
		return fmt.Errorf("failed to stop resource %s: %v", multiLevelKey, err)
	}

	// 使用带超时的轮询来检查容器状态
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for container %s to stop", containerID)
		case <-ticker.C:
			containerJSON, err := rm.dockerClient.ContainerInspect(ctx, containerID)
			if err != nil {
				if client.IsErrNotFound(err) {
					// 容器已经被移除，认为停止成功
					return rm.updateResourceStatus(multiLevelKey, containerID)
				}
				log.Printf("Error inspecting container %s: %v", containerID, err)
				continue
			}
			log.Printf("Container %s status: %s", containerID, containerJSON.State.Status)
			if containerJSON.State.Status == "exited" || containerJSON.State.Status == "dead" {
				log.Printf("Container %s has stopped with exit code: %d", containerID, containerJSON.State.ExitCode)
				return rm.updateResourceStatus(multiLevelKey, containerID)
			}
		}
	}
}

func (rm *ResourceManager) RestartResource(multiLevelKey string) error {
	info, err := rm.GetResourceInfo(multiLevelKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	timeout := time.Second * 10
	seconds := int(timeout.Seconds())
	err = rm.dockerClient.ContainerRestart(ctx, info.ContainerID, container.StopOptions{Timeout: &seconds})
	if err != nil {
		return fmt.Errorf("failed to restart resource %s: %v", multiLevelKey, err)
	}

	// 等待容器重新启动
	err = rm.waitForContainerRunning(ctx, info.ContainerID)
	if err != nil {
		return fmt.Errorf("error waiting for container to restart: %v", err)
	}

	// 更新资源状态
	err = rm.updateResourceStatus(multiLevelKey, info.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to update resource status after restart: %v", err)
	}

	return nil
}

func (rm *ResourceManager) GetResourceStatus(multiLevelKey string) (string, error) {
	resource, exists := rm.Resources.Get(multiLevelKey)
	if !exists {
		return "", fmt.Errorf("resource with key '%s' not found in the resource manager", multiLevelKey)
	}

	err := rm.updateResourceStatus(multiLevelKey, resource.ContainerID)
	if err != nil {
		return "", fmt.Errorf("failed to update status for resource '%s': %v", multiLevelKey, err)
	}

	updatedResource, exists := rm.Resources.Get(multiLevelKey)
	if !exists {
		return "", fmt.Errorf("resource '%s' was removed during status update", multiLevelKey)
	}

	return updatedResource.Status, nil
}

func (rm *ResourceManager) GetAllResourcesStatus() map[string]string {

	statuses := make(map[string]string)
	rm.Resources.Range(func(key string, info *models.ResourceInfo) bool {
		statuses[key] = info.Status
		return true
	})
	return statuses
}

func (rm *ResourceManager) ListAllResources() []string {

	var resources []string
	rm.Resources.Range(func(key string, info *models.ResourceInfo) bool {
		resources = append(resources, key)
		return true
	})

	return resources
}

func (rm *ResourceManager) prepareContainerConfig(resourceType models.ResourceType, containerName string, config map[string]interface{}) (*container.Config, *container.HostConfig) {
	containerConfig := &container.Config{
		Image: config["image"].(string),
		Labels: map[string]string{
			"resource_type": string(resourceType),
			"container_nae": containerName,
		},
	}

	hostConfig := &container.HostConfig{}

	for k, v := range config {
		switch k {
		case "command":
			if cmd, ok := v.(string); ok {
				containerConfig.Cmd = strings.Fields(cmd)
			}
			if cmds, ok := v.([]string); ok {
				containerConfig.Cmd = cmds
			}
		case "environment":
			if env, ok := v.([]string); ok {
				containerConfig.Env = env
			}
		case "ports":
			if ports, ok := v.(map[string]interface{}); ok {
				portBindings, exposedPorts := rm.parsePortMappings(ports)
				hostConfig.PortBindings = portBindings
				containerConfig.ExposedPorts = exposedPorts
			}
		case "volumes":
			volumes, _ := v.([]string)
			hostConfig.Binds = append(hostConfig.Binds, volumes...)
		}
	}

	return containerConfig, hostConfig
}

func (rm *ResourceManager) parsePortMappings(ports map[string]interface{}) (nat.PortMap, nat.PortSet) {
	portBindings := nat.PortMap{}
	exposedPorts := nat.PortSet{}

	for containerPortProto, hostPortInterface := range ports {
		// 分割容器端口和协议
		parts := strings.Split(containerPortProto, "/")
		containerPort := parts[0]
		proto := "tcp" // 默认协议为 tcp
		if len(parts) > 1 {
			proto = parts[1]
		}

		// 创建 nat.Port
		port, err := nat.NewPort(proto, containerPort)
		if err != nil {
			log.Printf("Error creating port for %s: %v", containerPortProto, err)
			continue
		}

		// 处理主机端口
		var hostPort string
		switch v := hostPortInterface.(type) {
		case string:
			hostPort = v
		case float64:
			hostPort = strconv.Itoa(int(v))
		case int:
			hostPort = strconv.Itoa(v)
		case int64:
			hostPort = strconv.Itoa(int(v))
		default:
			log.Printf("Unexpected type for host port: %T", hostPortInterface)
			continue
		}

		// 创建 PortBinding
		binding := nat.PortBinding{HostPort: hostPort}
		if existing, exists := portBindings[port]; exists {
			portBindings[port] = append(existing, binding)
		} else {
			portBindings[port] = []nat.PortBinding{binding}
		}

		// 添加到 exposedPorts
		exposedPorts[port] = struct{}{}
	}

	return portBindings, exposedPorts
}

// func (rm *ResourceManager) parseVolumes(volumes map[string]interface{}) []string {
// 	var binds []string
// 	for hostPath, containerPathInterface := range volumes {
// 		if containerPath, ok := containerPathInterface.(map[string]interface{}); ok {
// 			bind := fmt.Sprintf("%s:%s", hostPath, containerPath["bind"])
// 			if mode, ok := containerPath["mode"].(string); ok {
// 				bind += ":" + mode
// 			}
// 			binds = append(binds, bind)
// 		}
// 	}
// 	return binds
// }

func (rm *ResourceManager) DeleteResource(multiLevelKey string) error {
	info, err := rm.GetResourceInfo(multiLevelKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = rm.dockerClient.ContainerRemove(ctx, info.ContainerID, container.RemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	})
	if err != nil {
		return fmt.Errorf("failed to remove container %s: %v", info.ContainerID, err)
	}

	// 从资源列表中移除
	rm.Resources.Delete(multiLevelKey)

	log.Printf("Successfully deleted resource %s (Container ID: %s)", multiLevelKey, info.ContainerID)
	return nil
}

// func (rm *ResourceManager) UpdateResource(multiLevelKey string, config map[string]interface{}) (string, error) {
// 	log.Printf("Starting to update resource with key: %s", multiLevelKey)
// 	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
// 	defer cancel()

// 	info, err := rm.GetResourceInfo(multiLevelKey)
// 	if err != nil {
// 		if client.IsErrNotFound(err) {
// 			log.Printf("Container not found for key %s", multiLevelKey)
// 			// Extract resource type and name from the key
// 			resourceType, containerName, _, err := rm.KeyManager.ParseResourceKey(multiLevelKey)
// 			if err != nil {
// 				return "", fmt.Errorf("failed to parse resource key: %v", err)
// 			}

// 			// Create a new container with the provided configuration
// 			return rm.createNewContainer(ctx, multiLevelKey, models.ResourceType(resourceType), containerName, config)
// 		}
// 		return "", fmt.Errorf("failed to get resource info: %v", err)
// 	}

// 	log.Printf("Stopping and removing old container with ID: %s", info.ContainerID)
// 	if err := rm.stopAndRemoveContainer(ctx, info.ContainerID); err != nil {
// 		return "", fmt.Errorf("failed to stop and remove old container: %v", err)
// 	}

// 	var newID string
// 	log.Printf("Creating and starting new container for key: %s", multiLevelKey)
// 	if newID, err = rm.createNewContainer(ctx, multiLevelKey, info.Type, info.Name, config); err != nil {
// 		return "", fmt.Errorf("failed to create and start new container: %v", err)
// 	}

// 	err = rm.updateResourceStatus(multiLevelKey, newID)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to update resource status: %v", err)
// 	}

// 	log.Printf("Successfully updated resource with key: %s, new container ID: %s", multiLevelKey, newID)
// 	return newID, nil
// }

func (rm *ResourceManager) stopAndRemoveContainer(ctx context.Context, containerID string) error {
	// 停止容器
	timeout := 10 * time.Second
	seconds := int(timeout.Seconds())
	err := rm.dockerClient.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &seconds})
	if err != nil && !client.IsErrNotFound(err) {
		return fmt.Errorf("failed to stop container: %v", err)
	}

	// 删除容器
	err = rm.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
	if err != nil && !client.IsErrNotFound(err) {
		return fmt.Errorf("failed to remove container: %v", err)
	}

	return nil
}

func (rm *ResourceManager) ClearContainers() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 获取所有需要清除的容器名称
	containersToRemove := rm.Config.BaseConfig.Resources

	// 获取所有容器
	containers, err := rm.dockerClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		// 检查是否为权限错误
		if strings.Contains(err.Error(), "permission denied") {
			log.Printf("Warning: Docker permission denied while trying to clear containers, skipping container cleanup: %v", err)
			log.Printf("提示：如果需要清理容器，请执行以下步骤之一：\n" +
				"  1. 将当前用户添加到 docker 组：\n" +
				"     sudo usermod -aG docker $USER\n" +
				"     然后重新登录或执行：newgrp docker\n\n" +
				"  2. 使用 sudo 运行程序：\n" +
				"     sudo ./controller\n\n" +
				"  3. 确保 Docker 服务正在运行：\n" +
				"     sudo systemctl status docker")
			// 权限错误时跳过清理，继续执行
			return nil
		}
		// 其他错误也记录警告并跳过，避免阻止启动
		log.Printf("Warning: Failed to list containers, skipping container cleanup: %v", err)
		return nil
	}
	if v, ok := rm.Config.EtcdConfig["name"]; ok {
		containersToRemove[models.ResourceTypeEtcd] = v.(string)
	}

	for _, containerName := range containersToRemove {
		for _, c := range containers {
			// 检查容器名称是否匹配（去掉前导斜杠）
			if strings.TrimPrefix(c.Names[0], "/") == containerName {
				// 停止容器
				timeout := 10 * time.Second
				seconds := int(timeout.Seconds())
				err := rm.dockerClient.ContainerStop(ctx, c.ID, container.StopOptions{Timeout: &seconds})
				if err != nil {
					log.Printf("Error stopping container %s: %v", containerName, err)
				}

				// 删除容器
				err = rm.dockerClient.ContainerRemove(ctx, c.ID, container.RemoveOptions{
					Force:         true,
					RemoveVolumes: true,
				})
				if err != nil {
					log.Printf("Error removing container %s: %v", containerName, err)
				} else {
					log.Printf("Successfully removed container: %s", containerName)
				}

				// 从资源管理器中移除资源
				rm.Resources.Range(func(key string, value *models.ResourceInfo) bool {
					if value.ContainerID == c.ID {
						rm.Resources.Delete(key)
						return false
					}
					return true
				})

				break // 找到并处理了匹配的容器，跳出内层循环
			}
		}
	}

	log.Println("All specified resources have been cleared")
	return nil
}

// removeContainerByNameIfExists 检查并删除指定名称的容器（如果存在）
func (rm *ResourceManager) removeContainerByNameIfExists(ctx context.Context, containerName string) error {
	// 列出所有容器（包括已停止的）
	containers, err := rm.dockerClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		// 检查是否为权限错误
		if strings.Contains(err.Error(), "permission denied") {
			log.Printf("Warning: Docker permission denied while trying to list containers for %s, skipping: %v", containerName, err)
			// 权限错误时跳过，返回 nil
			return nil
		}
		// 其他错误也记录警告并跳过
		log.Printf("Warning: Failed to list containers for %s, skipping: %v", containerName, err)
		return nil
	}

	// 查找同名容器
	for _, c := range containers {
		// 检查容器名称是否匹配（去掉前导斜杠）
		for _, name := range c.Names {
			if strings.TrimPrefix(name, "/") == containerName {
				log.Printf("Found existing container with name %s (ID: %s), removing it...", containerName, c.ID)

				// 停止容器（如果正在运行）
				if c.State == "running" {
					timeout := 10 * time.Second
					seconds := int(timeout.Seconds())
					if err := rm.dockerClient.ContainerStop(ctx, c.ID, container.StopOptions{Timeout: &seconds}); err != nil {
						log.Printf("Warning: failed to stop container %s: %v", containerName, err)
					}
				}

				// 删除容器
				if err := rm.dockerClient.ContainerRemove(ctx, c.ID, container.RemoveOptions{
					Force:         true,
					RemoveVolumes: true,
				}); err != nil {
					return fmt.Errorf("failed to remove container %s: %v", containerName, err)
				}

				log.Printf("Successfully removed existing container %s", containerName)

				// 从资源管理器中移除资源（如果存在）
				rm.Resources.Range(func(key string, value *models.ResourceInfo) bool {
					if value.ContainerID == c.ID {
						rm.Resources.Delete(key)
						return false
					}
					return true
				})

				return nil
			}
		}
	}

	// 容器不存在，这是正常情况
	return nil
}

// func (rm *ResourceManager) createNewContainer(ctx context.Context, key string, resourceType models.ResourceType, containerName string, config map[string]interface{}) (string, error) {
// 	log.Printf("Preparing container config for key: %s", key)
// 	containerConfig, hostConfig := rm.prepareContainerConfig(resourceType, containerName, config)

// 	log.Printf("Creating container for key: %s", key)
// 	resp, err := rm.dockerClient.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, containerName)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to create container: %v", err)
// 	}

// 	log.Printf("Starting container with ID: %s", resp.ID)
// 	if err := rm.dockerClient.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
// 		return "", fmt.Errorf("failed to start container: %v", err)
// 	}

// 	log.Printf("Waiting for container %s to be in running state", resp.ID)
// 	if err := rm.waitForContainerRunning(ctx, resp.ID); err != nil {
// 		return "", fmt.Errorf("error waiting for container to start: %v", err)
// 	}

// 	return resp.ID, nil
// }

func (rm *ResourceManager) GetResourceLogs(multiLevelKey string, tail int) (string, error) {
	info, err := rm.GetResourceInfo(multiLevelKey)
	if err != nil {
		return "", err
	}

	options := container.LogsOptions{ShowStdout: true, ShowStderr: true, Tail: strconv.Itoa(tail)}
	logs, err := rm.dockerClient.ContainerLogs(context.Background(), info.ContainerID, options)
	if err != nil {
		return "", fmt.Errorf("failed to get logs for resource %s: %v", multiLevelKey, err)
	}
	defer logs.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(logs)
	if err != nil {
		return "", fmt.Errorf("failed to read logs for resource %s: %v", multiLevelKey, err)
	}

	return buf.String(), nil
}
