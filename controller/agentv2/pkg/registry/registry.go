package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

// ServiceInfo 服务注册信息
type ServiceInfo struct {
	Key      string
	Name     string
	Protocol string
	Address  string
	Meta     map[string]interface{}
}

// Registry 服务注册接口
type Registry interface {
	Register(ctx context.Context, info *ServiceInfo, ttl time.Duration) error
	Unregister(ctx context.Context, key string) error
	Start(ctx context.Context) error
	Stop() error
}

// etcdRegistry etcd 注册实现
type etcdRegistry struct {
	client     *clientv3.Client
	endpoints  []string
	prefix     string
	logger     *zap.Logger
	leases     map[string]clientv3.LeaseID
	keepAlives map[string]context.CancelFunc
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewEtcdRegistry 创建 etcd 注册器
func NewEtcdRegistry(endpoints []string, prefix string, logger *zap.Logger) (Registry, error) {
	return NewEtcdRegistryWithAuth(endpoints, prefix, "", "", logger)
}

// NewEtcdRegistryWithAuth 创建带认证的 etcd 注册器
func NewEtcdRegistryWithAuth(endpoints []string, prefix, username, password string, logger *zap.Logger) (Registry, error) {
	cfg := clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	}

	// 如果提供了用户名和密码，添加到配置中
	hasAuth := false
	if username != "" {
		cfg.Username = username
		hasAuth = true
	}
	if password != "" {
		cfg.Password = password
		hasAuth = true
	}

	// 记录 etcd 连接配置（不记录密码）
	logger.Info("Creating etcd registry",
		zap.Strings("endpoints", endpoints),
		zap.String("prefix", prefix),
		zap.Bool("has_auth", hasAuth),
		zap.String("username", username), // 记录用户名用于调试
	)

	client, err := clientv3.New(cfg)
	if err != nil {
		logger.Error("Failed to create etcd client",
			zap.Strings("endpoints", endpoints),
			zap.Bool("has_auth", hasAuth),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	logger.Info("Etcd client created successfully",
		zap.Strings("endpoints", endpoints),
		zap.Bool("has_auth", hasAuth))

	ctx, cancel := context.WithCancel(context.Background())

	return &etcdRegistry{
		client:     client,
		endpoints:  endpoints,
		prefix:     prefix,
		logger:     logger,
		leases:     make(map[string]clientv3.LeaseID),
		keepAlives: make(map[string]context.CancelFunc),
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Register 注册服务
func (r *etcdRegistry) Register(ctx context.Context, info *ServiceInfo, ttl time.Duration) error {
	// 解析地址，如果绑定到 0.0.0.0，需要获取实际 IP
	host, port, err := net.SplitHostPort(info.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	if host == "" || host == "0.0.0.0" {
		// 获取本机 IP
		ip, err := getLocalIP()
		if err != nil {
			r.logger.Error("Failed to get local IP, trying to use address as-is",
				zap.String("original_address", info.Address),
				zap.Error(err))
			// 如果无法获取 IP，尝试使用原始地址（可能在某些环境下仍然有效）
			// 但通常这会导致注册失败，因为 Controller 需要有效的 IP 地址
			return fmt.Errorf("failed to get local IP: %w", err)
		}
		info.Address = fmt.Sprintf("%s:%s", ip, port)
		r.logger.Info("Resolved local IP for registration",
			zap.String("original_address", fmt.Sprintf("%s:%s", host, port)),
			zap.String("resolved_address", info.Address))
	}

	// Controller 期望的 key 格式: grpc://server-agent/{address}
	// 例如: grpc://server-agent/192.168.0.199:10380
	key := fmt.Sprintf("grpc://server-agent/%s", info.Address)

	// Controller 期望的 value 格式
	// 需要将 services 转换为 JSON 字符串
	servicesJSON := "[]"
	if servicesValue, ok := info.Meta["services"]; ok && servicesValue != nil {
		// 尝试直接序列化（支持 []PackageStatus 或其他类型）
		servicesBytes, err := json.Marshal(servicesValue)
		if err == nil {
			servicesJSON = string(servicesBytes)
		} else {
			r.logger.Warn("Failed to marshal services",
				zap.String("address", info.Address),
				zap.Error(err))
		}
	}

	// 构建符合 Controller 期望的注册信息
	// Controller 期望的格式: { "Op": 0, "Addr": "...", "MetadataX": { "AppID": "...", ... } }
	agentCode := info.Key
	if code, ok := info.Meta["agent_code"].(string); ok {
		agentCode = code
	}

	metadata := make(map[string]string)
	metadata["services"] = servicesJSON
	metadata["agent_code"] = agentCode

	// 构建 MetadataX 结构（符合 Controller 期望的 server.ServiceInfo 格式）
	metadataX := map[string]interface{}{
		"AppID":    agentCode,
		"Name":     "server-agent",
		"Address":  info.Address,
		"Metadata": metadata,
		"Scheme":   "grpc",
	}

	// 构建完整的注册信息
	registerValue := map[string]interface{}{
		"Op":        0, // registry.Add
		"Addr":      info.Address,
		"MetadataX": metadataX,
	}

	// 序列化注册信息
	value, err := json.Marshal(registerValue)
	if err != nil {
		return fmt.Errorf("failed to marshal register value: %w", err)
	}

	// 创建租约
	lease, err := r.client.Grant(ctx, int64(ttl.Seconds()))
	if err != nil {
		r.logger.Error("Failed to create etcd lease",
			zap.String("key", key),
			zap.String("address", info.Address),
			zap.Error(err))
		return fmt.Errorf("failed to create lease: %w", err)
	}

	// 注册服务
	_, err = r.client.Put(ctx, key, string(value), clientv3.WithLease(lease.ID))
	if err != nil {
		r.logger.Error("Failed to put key to etcd",
			zap.String("key", key),
			zap.String("address", info.Address),
			zap.String("endpoints", fmt.Sprintf("%v", r.endpoints)),
			zap.Error(err))
		return fmt.Errorf("failed to register service: %w", err)
	}

	r.leases[key] = lease.ID

	// 启动 keep-alive
	keepAliveCtx, cancel := context.WithCancel(r.ctx)
	r.keepAlives[key] = cancel

	go r.keepAlive(keepAliveCtx, key, lease.ID)

	r.logger.Info("Service registered",
		zap.String("key", key),
		zap.String("address", info.Address),
	)

	return nil
}

// Unregister 注销服务
func (r *etcdRegistry) Unregister(ctx context.Context, key string) error {
	fullKey := fmt.Sprintf("%s/%s/%s", r.prefix, "agent", key)

	// 停止 keep-alive
	if cancel, exists := r.keepAlives[fullKey]; exists {
		cancel()
		delete(r.keepAlives, fullKey)
	}

	// 删除服务
	_, err := r.client.Delete(ctx, fullKey)
	if err != nil {
		return fmt.Errorf("failed to unregister service: %w", err)
	}

	delete(r.leases, fullKey)

	r.logger.Info("Service unregistered", zap.String("key", fullKey))

	return nil
}

// keepAlive 保持租约活跃
func (r *etcdRegistry) keepAlive(ctx context.Context, key string, leaseID clientv3.LeaseID) {
	ch, err := r.client.KeepAlive(ctx, leaseID)
	if err != nil {
		r.logger.Error("Failed to start keep-alive", zap.String("key", key), zap.Error(err))
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ka, ok := <-ch:
			if !ok {
				r.logger.Warn("Keep-alive channel closed", zap.String("key", key))
				return
			}
			r.logger.Debug("Keep-alive received", zap.String("key", key), zap.Int64("ttl", ka.TTL))
		}
	}
}

// Start 启动注册器
func (r *etcdRegistry) Start(ctx context.Context) error {
	// 注册器已准备好，可以开始注册服务
	return nil
}

// Stop 停止注册器
func (r *etcdRegistry) Stop() error {
	r.cancel()
	return r.client.Close()
}

// getLocalIP 获取本机 IP（优先获取非回环、非 Docker 的 IPv4 地址）
func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %w", err)
	}

	var preferredIP string
	var fallbackIP string

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ipStr := ipNet.IP.String()

				// 跳过 Docker 网络（通常是 172.17.x.x 或 172.18.x.x 等）
				if ipNet.IP[0] == 172 && ipNet.IP[1] >= 16 && ipNet.IP[1] <= 31 {
					// 可能是 Docker 网络，作为备选
					if fallbackIP == "" {
						fallbackIP = ipStr
					}
					continue
				}

				// 跳过 169.254.x.x（链路本地地址）
				if ipNet.IP[0] == 169 && ipNet.IP[1] == 254 {
					continue
				}

				// 优先选择 192.168.x.x 或 10.x.x.x（常见的内网地址）
				if ipNet.IP[0] == 192 && ipNet.IP[1] == 168 {
					preferredIP = ipStr
					break
				}
				if ipNet.IP[0] == 10 {
					if preferredIP == "" {
						preferredIP = ipStr
					}
					continue
				}

				// 其他非回环地址作为备选
				if preferredIP == "" && fallbackIP == "" {
					fallbackIP = ipStr
				}
			}
		}
	}

	// 优先返回首选 IP，否则返回备选 IP
	if preferredIP != "" {
		return preferredIP, nil
	}
	if fallbackIP != "" {
		return fallbackIP, nil
	}

	return "", fmt.Errorf("no local IP found (checked %d addresses)", len(addrs))
}
