package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/netxops/utils/tools"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// const EtcdServiceName = "controller-etcd"
// const EtcdServiceId = "etcd-service"

type RegistryManager struct {
	services       *tools.SafeMap[string, *models.ServiceInfo] `wire:"-"`
	KeyManager     *KeyManager
	ConfigManager  *ConfigManager
	leases         *tools.SafeMap[string, clientv3.LeaseID] `wire:"-"`
	mongoClient    *mongo.Client
	HostIdentifier string
	ctx            context.Context
	cancel         context.CancelFunc
}

// ProvideRegistryManager 为 Wire 依赖注入提供的构造函数
func ProvideRegistryManager(km *KeyManager, cm *ConfigManager, mongoClient *mongo.Client) (*RegistryManager, error) {
	rm := &RegistryManager{
		services:      tools.NewSafeMap[string, *models.ServiceInfo](),
		KeyManager:    km,
		ConfigManager: cm,
		leases:        tools.NewSafeMap[string, clientv3.LeaseID](),
		mongoClient:   mongoClient,
	}

	hostIdentifier, err := rm.getHostIdentifier()
	if err != nil {
		return nil, fmt.Errorf("failed to get host identifier: %v", err)
	}
	rm.HostIdentifier = hostIdentifier

	return rm, nil
}

func (rm *RegistryManager) RegisterService(service *models.ServiceInfo, ttl time.Duration) error {
	// 创建一个带有超时的 context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	preferredNetworks := rm.ConfigManager.Config.BaseConfig.PreferredNetworks

	// 解析服务地址
	host, port, err := net.SplitHostPort(service.Address)
	if err != nil {
		return fmt.Errorf("invalid service address: %v", err)
	}

	// 如果服务绑定到所有接口（0.0.0.0）或者没有指定IP
	if host == "" || host == "0.0.0.0" {
		interfaceName, ip, err := selectPreferredInterface(preferredNetworks)
		if err != nil {
			return fmt.Errorf("failed to select preferred interface: %v", err)
		}

		// 更新服务信息
		service.Address = fmt.Sprintf("%s:%s", ip, port)
		if service.Meta == nil {
			service.Meta = make(map[string]interface{})
		}
		service.Meta["interface"] = interfaceName
		service.Meta["original_bind"] = "0.0.0.0"
	} else {
		// 验证指定的IP是否在优选网段内
		if !isIPInPreferredNetworks(host, preferredNetworks) {
			xlog.Default().Warn("Service IP is not in preferred networks", xlog.String("ip", host))
		}

		// 获取对应的接口名
		interfaceName, err := getInterfaceNameForIP(host)
		if err != nil {
			xlog.Default().Warn("Failed to get interface name for IP", xlog.String("ip", host), xlog.FieldErr(err))
		} else {
			if service.Meta == nil {
				service.Meta = make(map[string]interface{})
			}
			service.Meta["interface"] = interfaceName
		}
	}

	value, err := json.Marshal(service)
	if err != nil {
		return fmt.Errorf("failed to marshal service info: %v", err)
	}

	key, err := rm.KeyManager.GenerateServiceKey(service.Name, rm.HostIdentifier, port)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// 创建租约
	lease, err := rm.ConfigManager.EtcdClient.Grant(ctx, int64(ttl.Seconds()))
	if err != nil {
		return fmt.Errorf("failed to create lease: %v", err)
	}

	// 使用租约注册服务
	_, err = rm.ConfigManager.EtcdClient.Put(ctx, key, string(value), clientv3.WithLease(lease.ID))
	if err != nil {
		return fmt.Errorf("failed to register service: %v", err)
	}

	rm.services.Set(service.Key, service)
	rm.leases.Set(service.Key, lease.ID)

	// 启动一个 goroutine 来保持租约
	go rm.keepAliveLease(rm.ctx, service.Key, lease.ID)

	return nil
}

// func (rm *RegistryManager) GetStatus() map[string]interface{} {
// 	status := make(map[string]interface{})

// 	// Get the list of all registered services
// 	services := rm.ListServices()
// 	status["service_count"] = len(services)

// 	// Collect details about each service
// 	serviceDetails := make([]map[string]interface{}, 0, len(services))
// 	for _, service := range services {
// 		serviceDetail := map[string]interface{}{
// 			"key":      service.Key,
// 			"name":    service.Name,
// 			"address": service.Address,
// 			"meta":    service.Meta,
// 		}
// 		serviceDetails = append(serviceDetails, serviceDetail)
// 	}
// 	status["services"] = serviceDetails

// 	return status
// }

func (rm *RegistryManager) keepAliveLease(ctx context.Context, serviceID string, leaseID clientv3.LeaseID) {
	keepAliveChan, err := rm.ConfigManager.EtcdClient.KeepAlive(ctx, leaseID)
	if err != nil {
		xlog.Default().Error("Failed to keep lease alive", xlog.String("serviceID", serviceID), xlog.FieldErr(err))
		return
	}

	for {
		select {
		case _, ok := <-keepAliveChan:
			if !ok {
				xlog.Default().Warn("Lease keep alive channel closed", xlog.String("serviceID", serviceID))
				rm.UnregisterService(serviceID)
				return
			}
		case <-ctx.Done():
			xlog.Default().Info("Stopping lease keep-alive due to context cancellation", xlog.String("serviceID", serviceID))
			return
		}
	}
}

func (rm *RegistryManager) RefreshService(serviceID string, ttl time.Duration) error {
	leaseID, exists := rm.leases.Get(serviceID)
	if !exists {
		return fmt.Errorf("service with ID %s not found", serviceID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := rm.ConfigManager.EtcdClient.KeepAliveOnce(ctx, leaseID)
	if err != nil {
		return fmt.Errorf("failed to refresh service lease: %v", err)
	}

	return nil
}

// func (rm *RegistryManager) periodicHealthCheck(ctx context.Context) {
// 	ticker := time.NewTicker(1 * time.Minute)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ticker.C:
// 			rm.performHealthCheck()
// 		case <-ctx.Done():
// 			xlog.Default().Info("Stopping periodic health check due to context cancellation")
// 			return
// 		}
// 	}
// }

func (rm *RegistryManager) checkAndRemoveExpiredServices() {
	now := time.Now()
	var expiredServices []string

	rm.services.Range(func(id string, service *models.ServiceInfo) bool {
		if now.After(service.ExpiresAt) {
			expiredServices = append(expiredServices, id)
		}
		return true
	})

	for _, id := range expiredServices {
		if err := rm.UnregisterService(id); err != nil {
			xlog.Default().Error("Failed to unregister expired service", xlog.String("id", id), xlog.FieldErr(err))
		}
	}
}

// 检查IP是否在优选网段内
func isIPInPreferredNetworks(ip string, preferredNetworks []string) bool {
	for _, network := range preferredNetworks {
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}
		if ipNet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

// 获取IP对应的接口名
func getInterfaceNameForIP(ip string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.String() == ip {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no interface found for IP %s", ip)
}

func (rm *RegistryManager) UnregisterService(key string) error {
	leaseID, exists := rm.leases.Get(key)
	if exists {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := rm.ConfigManager.EtcdClient.Revoke(ctx, leaseID)
		if err != nil {
			xlog.Default().Error("Failed to revoke lease", xlog.String("serviceID", key), xlog.FieldErr(err))
		}
		rm.leases.Delete(key)
	}

	rm.services.Delete(key)
	return nil
}

func (rm *RegistryManager) GetService(key string) (*models.ServiceInfo, error) {
	service, exists := rm.services.Get(key)
	if !exists {
		return nil, fmt.Errorf("service with ID %s not found", key)
	}

	return service, nil
}

func (rm *RegistryManager) FirstByName(serviceName string) (*models.ServiceInfo, error) {
	for _, service := range rm.ListServices() {
		if service.Name == serviceName {
			return service, nil
		}
	}
	return nil, fmt.Errorf("service with name %s not found", serviceName)
}

func (rm *RegistryManager) ListServices() []*models.ServiceInfo {
	services := make([]*models.ServiceInfo, 0, rm.services.Len())

	rm.services.Range(func(_ string, service *models.ServiceInfo) bool {
		services = append(services, service)
		return true
	})
	return services
}

func (rm *RegistryManager) WatchServices(ctx context.Context) (<-chan *models.ServiceEvent, error) {
	watchChan := make(chan *models.ServiceEvent)

	prefix, err := rm.KeyManager.GenerateResourcePrefix(string(models.ResourceTypeService))
	if err != nil {
		xlog.Default().Error("failed to generate prefix for watching", xlog.FieldErr(err))
		return nil, fmt.Errorf("failed to generate prefix for watching: %v", err)
	}

	go func() {
		defer close(watchChan)

		watcher := rm.ConfigManager.EtcdClient.Watch(ctx, prefix, clientv3.WithPrefix())
		for {
			select {
			case response, ok := <-watcher:
				if !ok {
					xlog.Default().Info("Watch channel closed")
					return
				}
				if response.Err() != nil {
					xlog.Default().Error("Watch error", xlog.FieldErr(response.Err()))
					return
				}
				for _, event := range response.Events {
					serviceEvent := &models.ServiceEvent{}

					switch event.Type {
					case clientv3.EventTypePut:
						if event.IsCreate() {
							serviceEvent.Type = models.ServiceEventTypeRegistered
						} else {
							serviceEvent.Type = models.ServiceEventTypeUpdated
						}
					case clientv3.EventTypeDelete:
						serviceEvent.Type = models.ServiceEventTypeUnregistered
					}

					service := &models.ServiceInfo{}
					if event.Type != clientv3.EventTypeDelete {
						if err := json.Unmarshal(event.Kv.Value, service); err != nil {
							xlog.Default().Error("failed to unmarshal service info", xlog.FieldErr(err))
							continue
						}
					} else {
						// For delete events, we only have the key
						_, serviceName, _, _, _, err := rm.KeyManager.ParseServiceKey(string(event.Kv.Key))
						if err != nil {
							xlog.Default().Error("failed to parse service key", xlog.FieldErr(err))
							continue
						}
						service.Key = string(event.Kv.Key)
						service.Name = serviceName
					}

					serviceEvent.Service = service
					serviceEvent.Timestamp = time.Now().Unix()

					select {
					case watchChan <- serviceEvent:
					case <-ctx.Done():
						xlog.Default().Info("Context cancelled, stopping watch")
						return
					}
				}
			case <-ctx.Done():
				xlog.Default().Info("Context cancelled, stopping watch")
				return
			}
		}
	}()

	return watchChan, nil
}

func (rm *RegistryManager) UpdateServiceConfig(serviceID string, config map[string]interface{}) error {
	service, err := rm.GetService(serviceID)
	if err != nil {
		return err
	}

	err = rm.ConfigManager.UpdateConfig(models.ResourceTypeRegistry, serviceID, config)
	if err != nil {
		return fmt.Errorf("failed to update service config: %v", err)
	}

	err = rm.notifyServiceConfigChange(service)
	if err != nil {
		return fmt.Errorf("failed to notify service of config change: %v", err)
	}

	return nil
}

func (rm *RegistryManager) notifyServiceConfigChange(service *models.ServiceInfo) error {
	// Implement the logic to notify the service about the configuration change
	// This could involve sending a message over gRPC, a message queue, or another method
	return nil
}

func (rm *RegistryManager) Start() error {
	rm.ctx, rm.cancel = context.WithCancel(context.Background())
	key, err := rm.KeyManager.GenerateResourceKey(string(models.ResourceTypeRegistry), string(models.ServiceNameEtcd))
	if err != nil {
		return fmt.Errorf("failed to generate resource key for etcd service: %v", err)
	}

	// 获取 etcd 配置
	etcdConfig := rm.ConfigManager.Config.EtcdConfig
	containerPort := etcdConfig["port"]
	hostPort, hostPortExists := etcdConfig["hostPort"]

	var address string
	if hostPortExists {
		// 如果 hostPort 存在，使用它
		address = fmt.Sprintf(":%v", hostPort)
	} else {
		// 否则，使用容器端口
		address = fmt.Sprintf(":%v", containerPort)
	}

	info := models.ServiceInfo{
		Key:     key,
		Name:    string(models.ServiceNameEtcd),
		Address: address,
	}

	go rm.periodicRegister(&info)

	// 初始化所有已知 Agent 的变量

	agents, _, err := rm.ListAgents(context.Background(), map[string]string{}, -1, -1)
	if err != nil {
		return fmt.Errorf("failed to list agents: %v", err)
	}

	for _, agent := range agents {
		_, err := rm.GetAgentVariables(agent.ID)
		if err != nil {
			// 如果获取失败，可能是因为变量还不存在，尝试设置默认变量
			defaultVars := map[string]string{
				"agent_status": string(agent.Status),
				// ... 其他默认变量 ...
			}
			if err := rm.SetAgentVariables(agent.ID, defaultVars); err != nil {
				xlog.Default().Warn("Failed to set default variables for agent", xlog.String("agentID", agent.ID), xlog.FieldErr(err))
			}
		}
	}

	return nil
}

func (rm *RegistryManager) Stop() error {
	rm.cancel()
	return rm.ConfigManager.EtcdClient.Close()
}

func (rm *RegistryManager) periodicRegister(serviceInfo *models.ServiceInfo) {
	ticker := time.NewTicker(30 * time.Second) // 每30秒注册一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := rm.RegisterService(serviceInfo, 1*time.Minute) // TTL设置为1分钟
			if err != nil {
				fmt.Printf("Failed to register registry service: %v\n", err)
			}
		case <-rm.ctx.Done():
			fmt.Println("Stopping registry service registration")
			return
		}
	}
}

// func (rm *RegistryManager) periodicHealthCheck(ctx context.Context) {
// 	ticker := time.NewTicker(1 * time.Minute)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ticker.C:
// 			rm.performHealthCheck()
// 		case <-ctx.Done():
// 			xlog.Default().Info("Stopping periodic health check due to context cancellation")
// 			return
// 		}
// 	}
// }

// func (rm *RegistryManager) performHealthCheck() {
// 	now := time.Now()
// 	var expiredServices []string

// 	rm.services.Range(func(id string, service *models.ServiceInfo) bool {
// 		// 检查服务是否过期
// 		if now.After(service.ExpiresAt) {
// 			expiredServices = append(expiredServices, id)
// 			return true
// 		}

// 		// 执行服务的健康检查
// 		if err := rm.checkServiceHealth(service); err != nil {
// 			xlog.Default().Warn("Service health check failed",
// 				xlog.String("serviceID", id),
// 				xlog.String("serviceName", service.Name),
// 				xlog.FieldErr(err))

// 			// 可以在这里添加重试逻辑或者将服务标记为不健康
// 			service.Status = models.ServiceStatusUnhealthy
// 			rm.services.Set(id, service)
// 		} else {
// 			service.Status = models.ServiceStatusHealthy
// 			rm.services.Set(id, service)
// 		}

// 		return true
// 	})

// 	// 移除过期的服务
// 	for _, id := range expiredServices {
// 		if err := rm.UnregisterService(id); err != nil {
// 			xlog.Default().Error("Failed to unregister expired service",
// 				xlog.String("serviceID", id),
// 				xlog.FieldErr(err))
// 		}
// 	}
// }

func (rm *RegistryManager) checkServiceHealth(service *models.ServiceInfo) error {
	// 这里实现具体的健康检查逻辑
	// 例如，可以尝试连接服务的地址，或者调用服务的健康检查接口

	// 示例：简单的 TCP 连接检查
	conn, err := net.DialTimeout("tcp", service.Address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to service: %v", err)
	}
	conn.Close()

	return nil
}

// func (rm *RegistryManager) performHealthCheck() {
// 	rm.services.Range(func(_ string, service *models.ServiceInfo) bool {
// 		fmt.Println(service)
// 		return true
// 	})
// }

func selectPreferredIP(availableIPs []string, preferredNetworks []string) (string, error) {
	for _, network := range preferredNetworks {
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}
		for _, ip := range availableIPs {
			if ipNet.Contains(net.ParseIP(ip)) {
				return ip, nil
			}
		}
	}
	if len(availableIPs) > 0 {
		return availableIPs[0], nil // 如果没有匹配的优选网段，返回第一个可用 IP
	}
	return "", fmt.Errorf("no suitable IP address found")
}

func selectPreferredInterface(preferredNetworks []string) (string, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, network := range preferredNetworks {
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}

		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				ipAddr, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				ip := ipAddr.IP.To4()
				if ip == nil {
					continue // 跳过非IPv4地址
				}

				if ipNet.Contains(ip) {
					return iface.Name, ip.String(), nil
				}
			}
		}
	}

	// 如果没有找到匹配的优选网段，返回第一个非回环的IPv4地址
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue // 跳过回环接口
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP.To4()
			if ip == nil {
				continue // 跳过非IPv4地址
			}

			return iface.Name, ip.String(), nil
		}
	}

	return "", "", fmt.Errorf("no suitable network interface and IP found")
}

// GetEtcdAddress 返回 Etcd 服务的地址
func (rm *RegistryManager) GetEtcdAddress() (string, error) {
	// 检查是否使用 Docker etcd
	useDockerEtcd := false
	if rm.ConfigManager.Config.UseDockerEtcd {
		useDockerEtcd = true
	} else if etcdUseDocker, ok := rm.ConfigManager.Config.EtcdConfig["use_docker_etcd"].(bool); ok {
		useDockerEtcd = etcdUseDocker
	}

	// 如果使用 Docker etcd，需要返回 Controller 的主机地址和 hostPort
	if useDockerEtcd {
		etcdConfig := rm.ConfigManager.Config.EtcdConfig
		hostPort, hostPortExists := etcdConfig["hostPort"]

		if !hostPortExists {
			// 如果没有 hostPort，使用容器端口
			if port, ok := etcdConfig["port"]; ok {
				hostPort = port
			} else {
				hostPort = 2379
			}
		}

		// 获取 Controller 的主机地址（使用首选网络接口）
		preferredNetworks := rm.ConfigManager.Config.BaseConfig.PreferredNetworks
		_, controllerIP, err := selectPreferredInterface(preferredNetworks)
		if err != nil {
			// 如果无法获取首选网络 IP，尝试获取任何可用的 IP
			controllerIP, err = getAnyAvailableIP()
			if err != nil {
				return "", fmt.Errorf("failed to get controller IP address: %v", err)
			}
		}

		// 格式化端口
		var portStr string
		switch v := hostPort.(type) {
		case int:
			portStr = fmt.Sprintf("%d", v)
		case int64:
			portStr = fmt.Sprintf("%d", v)
		case float64:
			portStr = fmt.Sprintf("%.0f", v)
		case string:
			portStr = v
		default:
			portStr = "2379"
		}

		etcdAddress := fmt.Sprintf("%s:%s", controllerIP, portStr)
		log.Printf("[GetEtcdAddress] Using Docker etcd, returning Controller address: %s", etcdAddress)
		return etcdAddress, nil
	}

	// 使用外部 etcd，从服务注册中获取地址
	service, err := rm.FirstByName(string(models.ServiceNameEtcd))
	if err != nil {
		return "", fmt.Errorf("failed to get etcd service: %v", err)
	}
	return service.Address, nil
}

// GetControllerAddress 返回 Controller 服务的地址
func (rm *RegistryManager) GetControllerAddress() (string, error) {
	// 首先尝试从内存中的 services map 查找
	service, err := rm.FirstByName(string(models.ServiceNameController))
	if err == nil && service != nil {
		return service.Address, nil
	}

	// 如果内存中没有，尝试从 Etcd 直接查询
	log.Printf("[GetControllerAddress] 内存中未找到Controller服务，尝试从Etcd查询")

	// 生成服务前缀
	prefix, err := rm.KeyManager.GenerateResourcePrefix(string(models.ResourceTypeService))
	if err != nil {
		log.Printf("[GetControllerAddress] 生成服务前缀失败: %v", err)
		return "", fmt.Errorf("failed to generate service prefix: %v", err)
	}

	log.Printf("[GetControllerAddress] 查询etcd，前缀: %s", prefix)

	// 查询所有服务
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := rm.ConfigManager.EtcdClient.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		log.Printf("[GetControllerAddress] 从etcd查询服务失败: %v", err)
		return "", fmt.Errorf("failed to query services from etcd: %v", err)
	}

	log.Printf("[GetControllerAddress] 从etcd获取到 %d 个键值对", len(resp.Kvs))

	// 遍历查找 Controller 服务
	foundCount := 0
	for _, kv := range resp.Kvs {
		var serviceInfo models.ServiceInfo
		if err := json.Unmarshal(kv.Value, &serviceInfo); err != nil {
			log.Printf("[GetControllerAddress] 解析服务信息失败，key: %s, error: %v", string(kv.Key), err)
			continue
		}
		log.Printf("[GetControllerAddress] 找到服务: name=%s, address=%s, key=%s", serviceInfo.Name, serviceInfo.Address, string(kv.Key))
		foundCount++
		if serviceInfo.Name == string(models.ServiceNameController) {
			log.Printf("[GetControllerAddress] 从Etcd找到Controller服务: address=%s, key=%s", serviceInfo.Address, serviceInfo.Key)
			// 将服务添加到内存 map 中，以便下次快速查找
			rm.services.Set(serviceInfo.Key, &serviceInfo)
			return serviceInfo.Address, nil
		}
	}

	log.Printf("[GetControllerAddress] 在 %d 个服务中未找到Controller服务 (name=%s)", foundCount, string(models.ServiceNameController))
	return "", fmt.Errorf("failed to get controller service: service with name %s not found in etcd (searched %d services)", string(models.ServiceNameController), foundCount)
}

func (rm *RegistryManager) getHostIdentifier() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %v", err)
	}

	preferredNetworks := rm.ConfigManager.Config.BaseConfig.PreferredNetworks
	interfaceName, ip, err := selectPreferredInterface(preferredNetworks)
	if err != nil {
		// 如果无法获取首选网络的 IP，尝试获取任何可用的 IP
		ip, err = getAnyAvailableIP()
		if err != nil {
			return "", fmt.Errorf("failed to get any available IP: %v", err)
		}
	}

	// 组合主机名和 IP 地址
	identifier := fmt.Sprintf("%s-%s", hostname, ip)

	// 可选：添加接口名称，如果可用
	if interfaceName != "" {
		identifier = fmt.Sprintf("%s-%s", identifier, interfaceName)
	}

	return identifier, nil
}

func getAnyAvailableIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // 跳过未启用或回环接口
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("no available IP address found")
}

func (rm *RegistryManager) GetVariables(ctx context.Context, agentID, appID string) (map[string]string, error) {
	variables := make(map[string]string)
	// variables["prometheus_address"], _ = rm.GetMetricsAddress()
	// variables["syslog_address"], _ = rm.GetSyslogAddress()

	// 获取 Controller 地址（必需）
	controllerAddress, err := rm.GetControllerAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to get controller address (required): %w", err)
	}
	if controllerAddress == "" {
		return nil, fmt.Errorf("controller address is empty (required)")
	}
	variables["controller_address"] = controllerAddress

	// 获取 etcd 地址（必需）
	etcdEndpoint, err := rm.GetEtcdAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to get etcd address (required): %w", err)
	}
	if etcdEndpoint == "" {
		return nil, fmt.Errorf("etcd endpoint is empty (required)")
	}
	variables["etcd_endpoint"] = etcdEndpoint
	variables["config_center_address"] = etcdEndpoint

	// 处理 etcd_endpoints（数组格式）
	// 注意：当使用Docker etcd时，必须使用GetEtcdAddress()返回的地址（Controller主机IP+hostPort）
	// upstream.etcd_addresses 是用于Controller注册到上游etcd的，不应该用于Agent注册
	etcdEndpoints := make([]string, 0)

	// 检查是否使用Docker etcd
	useDockerEtcd := false
	if rm.ConfigManager.Config.UseDockerEtcd {
		useDockerEtcd = true
	} else if etcdUseDocker, ok := rm.ConfigManager.Config.EtcdConfig["use_docker_etcd"].(bool); ok {
		useDockerEtcd = etcdUseDocker
	}

	if useDockerEtcd {
		// 使用Docker etcd时，必须使用GetEtcdAddress()返回的地址（Controller主机IP+hostPort）
		// 这样Agent才能注册到与Controller相同的etcd实例
		if etcdEndpoint == "" {
			return nil, fmt.Errorf("etcd endpoint is empty (required) when using Docker etcd")
		}
		etcdEndpoints = append(etcdEndpoints, etcdEndpoint)
		log.Printf("[GetVariables] Using Docker etcd, etcd_endpoint=%s (from GetEtcdAddress)", etcdEndpoint)
	} else {
		// 使用外部etcd时，优先使用 upstream.etcd_addresses（如果配置了多个地址）
		if len(rm.ConfigManager.Config.Upstream.EtcdAddresses) > 0 {
			// 使用 upstream.etcd_addresses（数组）
			etcdEndpoints = append(etcdEndpoints, rm.ConfigManager.Config.Upstream.EtcdAddresses...)
			log.Printf("[GetVariables] Using external etcd, etcd_endpoints=%v (from upstream.etcd_addresses)", etcdEndpoints)
		} else {
			// 否则使用单个 etcd_endpoint
			if etcdEndpoint == "" {
				return nil, fmt.Errorf("etcd endpoint is empty (required) when using external etcd and upstream.etcd_addresses is not configured")
			}
			etcdEndpoints = append(etcdEndpoints, etcdEndpoint)
			log.Printf("[GetVariables] Using external etcd, etcd_endpoint=%s (from GetEtcdAddress)", etcdEndpoint)
		}
	}

	// 验证 etcd_endpoints 不为空（必需）
	if len(etcdEndpoints) == 0 {
		return nil, fmt.Errorf("etcd endpoints is empty (required), cannot proceed with agent deployment")
	}

	// 注意：由于 GetVariables 返回 map[string]string，无法直接传递数组
	// 模板会使用 etcd_endpoint（单个值）作为降级方案
	// Controller API 的 GetVariables 会处理 etcd_endpoints 数组

	variables["loki_listen_path"] = rm.ConfigManager.Config.BaseConfig.LokiListenPath
	variables["prometheus_listen_path"] = rm.ConfigManager.Config.BaseConfig.PrometheusListenPath

	// 构建 controller_url：必须使用 BaseConfig.DefaultPort，不能有歧义
	// 1. 获取 Controller 的 IP 地址（从 controller_address 中提取，或从首选网络获取）
	controllerIP := ""
	if controllerAddress, exists := variables["controller_address"]; exists && controllerAddress != "" {
		// 从 controller_address 中提取 IP（格式：ip:port）
		if host, _, err := net.SplitHostPort(controllerAddress); err == nil {
			controllerIP = host
		}
	}

	// 如果无法从 controller_address 提取，使用首选网络接口获取 IP
	if controllerIP == "" {
		preferredNetworks := rm.ConfigManager.Config.BaseConfig.PreferredNetworks
		_, ip, err := selectPreferredInterface(preferredNetworks)
		if err != nil {
			// 如果无法获取首选网络 IP，尝试获取任何可用的 IP
			ip, err = getAnyAvailableIP()
			if err != nil {
				return nil, fmt.Errorf("failed to get controller IP address: %v", err)
			}
		}
		controllerIP = ip
	}

	// 2. 使用 BaseConfig.DefaultPort 构建完整的 controller_url（必需）
	defaultPort := rm.ConfigManager.Config.BaseConfig.DefaultPort
	if defaultPort == 0 {
		return nil, fmt.Errorf("BaseConfig.DefaultPort is not configured (required), cannot build controller_url")
	}
	variables["controller_url"] = fmt.Sprintf("http://%s:%d", controllerIP, defaultPort)

	// 获取 etcd 用户名和密码
	etcdConfig := rm.ConfigManager.Config.EtcdConfig
	if etcdUsername, ok := etcdConfig["username"].(string); ok && etcdUsername != "" {
		variables["etcd_username"] = etcdUsername
	} else if rm.ConfigManager.Config.Upstream.Username != "" {
		variables["etcd_username"] = rm.ConfigManager.Config.Upstream.Username
	}

	if etcdPassword, ok := etcdConfig["password"].(string); ok && etcdPassword != "" {
		variables["etcd_password"] = etcdPassword
	} else if rm.ConfigManager.Config.Upstream.Password != "" {
		variables["etcd_password"] = rm.ConfigManager.Config.Upstream.Password
	}

	// 添加 etcd_prefix（如果配置中有，否则使用默认值）
	// 注意：Agent 配置中使用的是 etcd_prefix，默认值为 "/agents"
	if etcdPrefix, ok := etcdConfig["prefix"].(string); ok && etcdPrefix != "" {
		variables["etcd_prefix"] = etcdPrefix
	} else {
		// 使用默认值，与 Agent 配置保持一致
		variables["etcd_prefix"] = "/agents"
	}

	// 添加 metrics 增强型收集器配置（可选）
	// 注意：这些配置项是可选的，如果未设置，模板会使用默认值
	// enhanced_only_core 默认为 true（推荐用于生产环境）
	variables["metrics_enhanced_only_core"] = "true" // 默认值：只启用核心collectors

	// 添加指标策略配置（可选）
	// 默认启用策略功能，可以通过部署工具传递变量覆盖
	// strategy_enabled 默认为 true，自动启用策略功能
	// strategy_source 默认为 "api"，从 Controller API 获取策略
	// strategy_api_url 留空则使用 controller_url
	// strategy_sync_interval 默认为 "5m"（5分钟）
	// 注意：这些变量是可选的，如果未设置，模板会使用默认值
	variables["metrics_strategy_enabled"] = "true"     // 默认值：启用策略功能
	variables["metrics_strategy_source"] = "api"       // 默认值：从 API 获取策略
	variables["metrics_strategy_sync_interval"] = "5m" // 默认值：5分钟同步一次

	// enhanced_collectors 和 enhanced_exclude 是数组类型
	// 由于 GetVariables 返回 map[string]string，无法直接传递数组
	// 这些变量将在 API 层处理（类似 etcd_endpoints 的处理方式）

	return variables, nil
}

func (rm *RegistryManager) GetAgentVariables(agentID string) (map[string]string, error) {
	// 首先获取通用变量
	variables, err := rm.GetVariables(context.Background(), agentID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get common variables: %v", err)
	}

	// 获取特定于 Agent 的变量
	agentKey := fmt.Sprintf("/agents/%s/variables", agentID)
	resp, err := rm.ConfigManager.EtcdClient.Get(rm.ctx, agentKey)
	if err != nil {
		return variables, fmt.Errorf("failed to get agent-specific variables: %v", err)
	}

	if len(resp.Kvs) > 0 {
		var agentVars map[string]string
		if err := json.Unmarshal(resp.Kvs[0].Value, &agentVars); err != nil {
			return variables, fmt.Errorf("failed to unmarshal agent variables: %v", err)
		}
		// 合并 Agent 特定变量，允许覆盖通用变量
		for k, v := range agentVars {
			variables[k] = v
		}
	}

	// 添加 Agent 特定的其他变量
	variables["agent_id"] = agentID

	return variables, nil
}

func (rm *RegistryManager) SetAgentVariables(agentID string, variables map[string]string) error {
	agentKey := fmt.Sprintf("/agents/%s/variables", agentID)

	jsonData, err := json.Marshal(variables)
	if err != nil {
		return fmt.Errorf("failed to marshal agent variables: %v", err)
	}

	_, err = rm.ConfigManager.EtcdClient.Put(rm.ctx, agentKey, string(jsonData))
	if err != nil {
		return fmt.Errorf("failed to set agent variables in etcd: %v", err)
	}

	return nil
}

func (rm *RegistryManager) ListAgents(ctx context.Context, filter map[string]string, page, pageSize int) ([]models.Agent, int, error) {
	return listAgents(ctx, rm.mongoClient, filter, page, pageSize)
}

// func listAgents(ctx context.Context, mongoClient *mongo.Client, filter map[string]string, page, pageSize int) ([]models.Agent, int, error) {
// 	collection := mongoClient.Database("controller").Collection("agents")

// 	// 构建 MongoDB 查询
// 	query := bson.M{}
// 	for key, value := range filter {
// 		switch key {
// 		case "address", "hostname":
// 			// 对 address 和 hostname 字段使用正则表达式进行部分匹配
// 			query[key] = bson.M{"$regex": value, "$options": "i"}
// 		default:
// 			query[key] = value
// 		}
// 	}

// 	// 计算总数
// 	total, err := collection.CountDocuments(ctx, query)
// 	if err != nil {
// 		return nil, 0, fmt.Errorf("failed to count agents: %v", err)
// 	}

// 	// 设置分页
// 	skip := int64((page - 1) * pageSize)
// 	limit := int64(pageSize)

// 	// 执行查询
// 	cursor, err := collection.Find(ctx, query, options.Find().SetSkip(skip).SetLimit(limit))
// 	if err != nil {
// 		return nil, 0, fmt.Errorf("failed to find agents: %v", err)
// 	}
// 	defer cursor.Close(ctx)

// 	var agents []models.Agent
// 	if err = cursor.All(ctx, &agents); err != nil {
// 		return nil, 0, fmt.Errorf("failed to decode agents: %v", err)
// 	}

// 	return agents, int(total), nil
// }

func listAgents(ctx context.Context, mongoClient *mongo.Client, filter map[string]string, page, pageSize int) ([]models.Agent, int, error) {
	collection := mongoClient.Database("controller").Collection("agents")

	// 构建 MongoDB 查询
	query := bson.M{}
	for key, value := range filter {
		switch key {
		case "address", "hostname":
			// 对 address 和 hostname 字段使用正则表达式进行部分匹配
			query[key] = bson.M{"$regex": value, "$options": "i"}
		default:
			query[key] = value
		}
	}

	// 计算总数
	total, err := collection.CountDocuments(ctx, query)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count agents: %v", err)
	}

	// 设置查询选项
	findOptions := options.Find()
	if page != -1 && pageSize != -1 {
		// 正常分页
		skip := int64((page - 1) * pageSize)
		limit := int64(pageSize)
		findOptions.SetSkip(skip).SetLimit(limit)
	}

	// 执行查询
	cursor, err := collection.Find(ctx, query, findOptions)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to find agents: %v", err)
	}
	defer cursor.Close(ctx)

	var agents []models.Agent
	if err = cursor.All(ctx, &agents); err != nil {
		return nil, 0, fmt.Errorf("failed to decode agents: %v", err)
	}

	return agents, int(total), nil
}

func (rm *RegistryManager) GetAgentCount() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := rm.mongoClient.Database("controller").Collection("agents")

	// 计算总数
	count, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return 0, fmt.Errorf("failed to count agents: %v", err)
	}

	return int(count), nil
}
