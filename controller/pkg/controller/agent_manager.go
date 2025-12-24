package controller

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/avast/retry-go"
	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pb"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/utils/tools"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"gopkg.in/yaml.v3"
)

type PackageInfo struct {
	ID        string `bson:"_id"`
	AgentCode string `bson:"agent_code"`
	Name      string `bson:"name"`
	Version   string `bson:"version"`
}

type PackageWatcher struct {
	watchedPackages sync.Map
	agentManager    *AgentManager
}

type AgentManager struct {
	mu               sync.RWMutex
	resourceManager  *ResourceManager
	configManager    *ConfigManager
	registryManager  *RegistryManager
	keyManager       *KeyManager
	agentConnections *tools.SafeMap[string, *grpc.ClientConn]
	// commandExecutors map[string]*CommandExecutor
	minioManager *MinioManager
	mongoClient  *mongo.Client
	// sshConfig        *ssh.ServerConfig
	nacosManager   *NacosManager
	packageWatcher *PackageWatcher
	agentDiscovery *AgentDiscovery
	batchOperator  *BatchOperator
	healthMonitor  *HealthMonitor
	metricsQuery   *MetricsQuery
	fileOperation  *FileOperation
	cancel         context.CancelFunc
	ctx            context.Context
}

// type CommandExecutor struct {
// 	cmd    *exec.Cmd
// 	stdout io.ReadCloser
// 	stderr io.ReadCloser
// 	done   chan struct{}
// }

func ProvideAgentManager(registry *RegistryManager, rm *ResourceManager, cm *ConfigManager, km *KeyManager, mm *MinioManager, mongoClient *mongo.Client, nacosManager *NacosManager) (*AgentManager, error) {
	am := &AgentManager{
		registryManager:  registry,
		resourceManager:  rm,
		configManager:    cm,
		keyManager:       km,
		minioManager:     mm,
		mongoClient:      mongoClient,
		agentConnections: tools.NewSafeMap[string, *grpc.ClientConn](),
		nacosManager:     nacosManager,
	}

	am.packageWatcher = &PackageWatcher{agentManager: am}

	// 初始化 Agent 发现模块
	watchPrefix := "grpc://server-agent/"
	am.agentDiscovery = NewAgentDiscovery(cm.EtcdClient, mongoClient, watchPrefix)

	// 初始化批量操作模块
	am.batchOperator = NewBatchOperator(am)

	// 初始化健康监控模块
	am.healthMonitor = NewHealthMonitor(am)

	// 初始化指标查询模块
	am.metricsQuery = NewMetricsQuery(am)

	// 初始化文件操作模块
	am.fileOperation = NewFileOperation(am)

	return am, nil
}

func (am *AgentManager) StartPackageWatcher(ctx context.Context) {
	go am.packageWatcher.Watch(ctx)
}

func (pw *PackageWatcher) Watch(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pw.checkPackages(ctx)
		}
	}
}

func (pw *PackageWatcher) checkPackages(ctx context.Context) {
	onlinePackages, err := pw.agentManager.getOnlinePackages(ctx)
	if err != nil {
		xlog.Error("Failed to get online packages", xlog.FieldErr(err))
		return
	}

	for _, pkg := range onlinePackages {
		if _, watched := pw.watchedPackages.Load(pkg.ID); !watched {
			// 创建一个带有超时的上下文
			syncCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()

			// 使用 errgroup 来管理并发和错误处理
			var eg errgroup.Group
			var syncErr error

			eg.Go(func() error {
				return pw.agentManager.syncPackageConfig(syncCtx, pkg.AgentCode, pkg.Name)
			})

			// 等待同步操作完成或上下文取消
			if err := eg.Wait(); err != nil {
				if err == context.DeadlineExceeded {
					xlog.Error("Package sync operation timed out",
						xlog.String("agentCode", pkg.AgentCode),
						xlog.String("packageName", pkg.Name))
				} else {
					xlog.Error("Failed to sync package config",
						xlog.String("agentCode", pkg.AgentCode),
						xlog.String("packageName", pkg.Name),
						xlog.FieldErr(err))
				}
				syncErr = err
			}

			if syncErr == nil {
				// 同步成功，设置watched状态
				pw.watchedPackages.Store(pkg.ID, true)
				xlog.Info("Package successfully synced and marked as watched",
					xlog.String("packageID", pkg.ID),
					xlog.String("agentCode", pkg.AgentCode),
					xlog.String("packageName", pkg.Name))
			} else {
				// 如果同步失败，不设置watched状态，下次会重试
				xlog.Warn("Package sync failed, will retry in next check",
					xlog.String("packageID", pkg.ID),
					xlog.String("agentCode", pkg.AgentCode),
					xlog.String("packageName", pkg.Name))
			}
		}
	}
}

func (am *AgentManager) syncPackageConfig(ctx context.Context, agentCode, packageName string) error {
	xlog.Info("Starting package config synchronization",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))

	// 获取 agent 上的 package 配置
	agentConfigs, err := am.GetPackageConfigs(ctx, agentCode, packageName)
	if err != nil {
		xlog.Error("Failed to get package configs from agent",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return err
	}

	// 将 agent 配置转换为 Nacos 可接受的格式
	nacosFormatConfig, err := am.convertAgentConfigToNacosFormat(agentConfigs, packageName)
	if err != nil {
		xlog.Error("Failed to convert agent config to Nacos format",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return err
	}

	dataId := am.AgentConfigDataId(packageName, agentCode)
	// 从 Nacos 获取配置
	nacosConfig, err := am.nacosManager.GetConfig(agentCode, packageName)
	if err != nil {
		if err == ErrNacosConfigNotFound {
			xlog.Info("No configs found in Nacos, updating Nacos with agent configs",
				xlog.String("packageName", packageName))
			err = am.nacosManager.SetConfig(dataId, am.configManager.Config.Nacos.AgentGroup, nacosFormatConfig)
			if err != nil {
				xlog.Error("Failed to update Nacos configs",
					xlog.String("packageName", packageName),
					xlog.FieldErr(err))
				return err
			}
		} else {
			xlog.Error("Failed to get configs from Nacos",
				xlog.String("packageName", packageName),
				xlog.FieldErr(err))
			return err
		}
	} else {
		if nacosConfig == "" {
			xlog.Info("No configs found in Nacos, updating Nacos with agent configs",
				xlog.String("packageName", packageName))
			err = am.nacosManager.SetConfig(dataId, am.configManager.Config.Nacos.AgentGroup, nacosFormatConfig)
			if err != nil {
				xlog.Error("Failed to update Nacos configs",
					xlog.String("packageName", packageName),
					xlog.FieldErr(err))
				return err
			}
		} else {
			agentFormatConfig, err := am.convertNacosConfigToAgentFormat(nacosConfig)
			if err != nil {
				xlog.Error("Failed to convert Nacos config to agent format",
					xlog.String("agentCode", agentCode),
					xlog.String("packageName", packageName),
					xlog.FieldErr(err))
				return err
			}

			// 比较并应用配置
			if !reflect.DeepEqual(agentConfigs, agentFormatConfig) {
				xlog.Info("Configs differ, applying Nacos configs to agent",
					xlog.String("agentCode", agentCode),
					xlog.String("packageName", packageName))
				err = am.ApplyPackageConfigs(ctx, agentCode, packageName, agentFormatConfig)
				if err != nil {
					xlog.Error("Failed to apply Nacos configs to agent",
						xlog.String("agentCode", agentCode),
						xlog.String("packageName", packageName),
						xlog.FieldErr(err))
					return err
				}
			}
		}

	}

	// 开始监听 Nacos 配置变化
	go am.watchNacosConfigChanges(ctx, agentCode, packageName)

	xlog.Info("Package config synchronization completed",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))

	return nil
}

func (am *AgentManager) AgentConfigDataId(packageName, agentCode string) string {
	return fmt.Sprintf("%s.%s", packageName, agentCode)
}

func (am *AgentManager) convertAgentConfigToNacosFormat(agentConfigs []*pb.ConfigItem, packageName string) (string, error) {
	// 创建配置结构
	packageConfig := struct {
		PackageName string `yaml:"packageName"`
		Version     string `yaml:"version"`
		Configs     []struct {
			FileName string `yaml:"fileName"`
			Content  string `yaml:"content"`
		} `yaml:"configs"`
	}{
		PackageName: packageName,
		Version:     "1.0.0", // 这里可以根据实际情况设置版本
		Configs: make([]struct {
			FileName string `yaml:"fileName"`
			Content  string `yaml:"content"`
		}, len(agentConfigs)),
	}

	// 填充配置内容
	for i, config := range agentConfigs {
		packageConfig.Configs[i] = struct {
			FileName string `yaml:"fileName"`
			Content  string `yaml:"content"`
		}{
			FileName: config.FileName,
			Content:  config.Content,
		}
	}

	// 将结构转换为 YAML
	yamlData, err := yaml.Marshal(packageConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config to YAML: %v", err)
	}

	return string(yamlData), nil
}

func (am *AgentManager) convertNacosConfigToAgentFormat(nacosConfig string) ([]*pb.ConfigItem, error) {
	var packageConfig struct {
		PackageName string `yaml:"packageName"`
		Version     string `yaml:"version"`
		Configs     []struct {
			FileName string `yaml:"fileName"`
			Content  string `yaml:"content"`
		} `yaml:"configs"`
	}

	err := yaml.Unmarshal([]byte(nacosConfig), &packageConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML config: %v", err)
	}

	var configItems []*pb.ConfigItem
	for _, config := range packageConfig.Configs {
		configItems = append(configItems, &pb.ConfigItem{
			FileName: config.FileName,
			Content:  config.Content,
		})
	}

	return configItems, nil
}

func (am *AgentManager) watchNacosConfigChanges(ctx context.Context, agentCode, packageName string) {
	xlog.Info("Setting up Nacos config listener",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))

	dataId := am.AgentConfigDataId(packageName, agentCode)
	err := am.nacosManager.ListenConfig(dataId, am.configManager.Config.Nacos.AgentGroup, func(data string) {
		xlog.Info("Nacos config changed, queueing update for package",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName))

		// 在新的 goroutine 中处理配置更新
		updateCtx, cancel := context.WithTimeout(ctx, time.Second*20)
		defer cancel()
		go am.handleConfigUpdate(updateCtx, agentCode, packageName, data)
	})

	if err != nil {
		xlog.Error("Failed to set up Nacos config listener",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
	} else {
		xlog.Info("Successfully set up Nacos config listener",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName))
	}
}

func (am *AgentManager) handleConfigUpdate(ctx context.Context, agentCode, packageName, data string) {
	configs, err := am.parseNacosConfig(data)
	if err != nil {
		xlog.Error("Failed to parse Nacos config",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	err = am.ApplyPackageConfigs(ctx, agentCode, packageName, configs)
	if err != nil {
		xlog.Error("Failed to apply changed Nacos configs to agent",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
	} else {
		xlog.Info("Successfully applied Nacos config changes to agent",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName))
	}
}

func (am *AgentManager) getOnlinePackages(ctx context.Context) ([]PackageInfo, error) {
	xlog.Info("Fetching online packages from MongoDB")

	collection := am.mongoClient.Database("controller").Collection("agents")

	// 查询所有在线的 agents
	filter := bson.M{"status": models.AgentStatusOnline}
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		xlog.Error("Failed to query agents from MongoDB", xlog.FieldErr(err))
		return nil, fmt.Errorf("failed to query agents: %v", err)
	}
	defer cursor.Close(ctx)

	var onlinePackages []PackageInfo

	for cursor.Next(ctx) {
		var agent models.Agent
		if err := cursor.Decode(&agent); err != nil {
			xlog.Error("Failed to decode agent document", xlog.FieldErr(err))
			continue
		}

		for _, service := range agent.Services {
			// if service.IsRunning {
			packageInfo := PackageInfo{
				ID:        fmt.Sprintf("%s-%s", agent.ID, service.Name), // 使用 agent ID 和 package 名称组合作为唯一标识
				AgentCode: agent.ID,
				Name:      service.Name,
				Version:   service.Version,
			}
			onlinePackages = append(onlinePackages, packageInfo)
			// }
		}
	}

	if err := cursor.Err(); err != nil {
		xlog.Error("Cursor error while iterating agents", xlog.FieldErr(err))
		return nil, fmt.Errorf("cursor error: %v", err)
	}

	xlog.Info("Successfully fetched online packages", xlog.Int("count", len(onlinePackages)))
	return onlinePackages, nil
}

func (am *AgentManager) parseNacosConfig(data string) ([]*pb.ConfigItem, error) {
	xlog.Info("Parsing Nacos config", xlog.String("data", data))

	var packageConfig struct {
		PackageName string `yaml:"packageName"`
		Version     string `yaml:"version"`
		Configs     []struct {
			FileName string `yaml:"fileName"`
			Content  string `yaml:"content"`
		} `yaml:"configs"`
	}

	err := yaml.Unmarshal([]byte(data), &packageConfig)
	if err != nil {
		xlog.Error("Failed to unmarshal YAML config", xlog.FieldErr(err))
		return nil, fmt.Errorf("failed to unmarshal YAML config: %v", err)
	}

	var configItems []*pb.ConfigItem
	for _, config := range packageConfig.Configs {
		configItems = append(configItems, &pb.ConfigItem{
			FileName: config.FileName,
			Content:  config.Content,
		})

		// 打印文件名和文件内容的字节数
		xlog.Info("Config file details",
			xlog.String("fileName", config.FileName),
			xlog.Int("contentBytes", len(config.Content)))
	}

	xlog.Info("Successfully parsed Nacos config",
		xlog.String("packageName", packageConfig.PackageName),
		xlog.String("version", packageConfig.Version),
		xlog.Int("configCount", len(configItems)))

	return configItems, nil
}

func (am *AgentManager) GetAgent(ctx context.Context, agentCode string) (*models.Agent, error) {
	collection := am.mongoClient.Database("controller").Collection("agents")

	var agent models.Agent
	err := collection.FindOne(ctx, bson.M{"id": agentCode}).Decode(&agent)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("agent with ID %s not found", agentCode)
		}
		return nil, fmt.Errorf("failed to get agent: %v", err)
	}

	return &agent, nil
}

// 辅助方法：根据设备ID获取Agent地址
func (am *AgentManager) getAgentAddress(agentCode string) (string, error) {
	agent, err := am.GetAgent(context.Background(), agentCode)
	if err != nil {
		return "", err
	}
	return agent.Address, nil
}
func (am *AgentManager) ListAgents(ctx context.Context, filter map[string]string, page, pageSize int) ([]models.Agent, int, error) {
	return listAgents(ctx, am.mongoClient, filter, page, pageSize)
}
func (am *AgentManager) Start() error {
	xlog.Info("Starting AgentManager")

	// 创建一个带有取消功能的上下文
	am.ctx, am.cancel = context.WithCancel(context.Background())

	// 启动包监视器
	go am.packageWatcher.Watch(am.ctx)

	// 启动 Agent 自动发现
	if am.agentDiscovery != nil {
		if err := am.agentDiscovery.Start(); err != nil {
			xlog.Error("Failed to start agent discovery", xlog.FieldErr(err))
			return fmt.Errorf("failed to start agent discovery: %v", err)
		}
		xlog.Info("Agent discovery started")
	}

	// // 初始化 SSH 服务器配置
	// am.initSSHServerConfig()

	// // 启动 SSH 跳板服务器
	// err := am.startSSHJumperServer()
	// if err != nil {
	//     xlog.Error("Failed to start SSH jumper server", xlog.FieldErr(err))
	//     return fmt.Errorf("failed to start SSH jumper server: %v", err)
	// }

	// 启动 gRPC 代理服务器
	// err = am.startGRPCProxyServer()
	// if err != nil {
	// 	xlog.Error("Failed to start gRPC proxy server", xlog.FieldErr(err))
	// 	return fmt.Errorf("failed to start gRPC proxy server: %v", err)
	// }

	// 初始化与所有在线 Agent 的连接
	// err = am.initializeAgentConnections()
	// if err != nil {
	// 	xlog.Error("Failed to initialize agent connections", xlog.FieldErr(err))
	// 	return fmt.Errorf("failed to initialize agent connections: %v", err)
	// }

	xlog.Info("AgentManager started successfully")
	return nil
}

// func (am *AgentManager) initializeAgentConnections() error {
// 	agents, _, err := am.ListAgents(context.Background(), map[string]string{"status": string(models.AgentStatusOnline)}, -1, -1)
// 	if err != nil {
// 		return fmt.Errorf("failed to list online agents: %v", err)
// 	}

// 	for _, agent := range agents {
// 		_, err := am.getAgentConnection(agent.ID)
// 		if err != nil {
// 			xlog.Warn("Failed to establish connection with agent",
// 				xlog.String("agentID", agent.ID),
// 				xlog.FieldErr(err))
// 		}
// 	}

// 	return nil
// }

func (am *AgentManager) startGRPCProxyServer() error {
	lis, err := net.Listen("tcp", ":50051") // 选择一个合适的端口
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnknownServiceHandler(am.proxyHandler),
	)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			xlog.Default().Error("Failed to serve gRPC proxy", xlog.FieldErr(err))
		}
	}()

	xlog.Default().Info("gRPC proxy server started on port 50051")
	return nil
}

func (am *AgentManager) proxyHandler(srv interface{}, stream grpc.ServerStream) error {
	fullMethodName, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		return fmt.Errorf("failed to get method name from stream")
	}

	ctx := stream.Context()
	agentCode, ok := getAgentCodeFromContext(ctx)
	if !ok {
		return fmt.Errorf("agent code not found in context")
	}

	conn, err := am.getAgentConnection(agentCode)
	if err != nil {
		return fmt.Errorf("failed to get agent connection: %v", err)
	}

	clientStream, err := conn.NewStream(ctx, streamDesc(stream), fullMethodName)
	if err != nil {
		return fmt.Errorf("failed to create client stream: %v", err)
	}

	return am.proxyClientToServer(stream, clientStream)
}

func (am *AgentManager) proxyClientToServer(serverStream grpc.ServerStream, clientStream grpc.ClientStream) error {
	// 从服务器端流向客户端流
	go func() {
		for {
			m := new(interface{})
			if err := clientStream.RecvMsg(m); err != nil {
				break
			}
			serverStream.SendMsg(m)
		}
	}()

	// 从客户端流向服务器端流
	for {
		m := new(interface{})
		if err := serverStream.RecvMsg(m); err != nil {
			break
		}
		clientStream.SendMsg(m)
	}

	return nil
}

func getAgentCodeFromContext(ctx context.Context) (string, bool) {
	// 从上下文中获取 AgentCode
	// 这里需要根据您的实际情况来实现
	// 例如，您可能需要从元数据中获取 AgentCode
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	agentCodes := md.Get("agent-code")
	if len(agentCodes) == 0 {
		return "", false
	}
	return agentCodes[0], true
}

func streamDesc(stream grpc.ServerStream) *grpc.StreamDesc {
	return &grpc.StreamDesc{
		ServerStreams: true,
		ClientStreams: true,
	}
}

// GetAgentDetail 获取 Agent 详情
func (am *AgentManager) GetAgentDetail(ctx context.Context, agentID string) (*models.Agent, error) {
	return am.GetAgent(ctx, agentID)
}

// GetAgentPackages 获取 Agent 管理的服务列表
func (am *AgentManager) GetAgentPackages(ctx context.Context, agentID string) ([]*pb.PackItem, error) {
	return am.PackageList(ctx, agentID)
}

// GetBatchOperator 获取批量操作模块
func (am *AgentManager) GetBatchOperator() *BatchOperator {
	return am.batchOperator
}

// GetHealthMonitor 获取健康监控模块
func (am *AgentManager) GetHealthMonitor() *HealthMonitor {
	return am.healthMonitor
}

// GetMetricsQuery 获取指标查询模块
func (am *AgentManager) GetMetricsQuery() *MetricsQuery {
	return am.metricsQuery
}

// GetFileOperation 获取文件操作模块
func (am *AgentManager) GetFileOperation() *FileOperation {
	if am.fileOperation == nil {
		am.fileOperation = NewFileOperation(am)
	}
	return am.fileOperation
}

func (am *AgentManager) Stop() error {
	// 停止 Agent 发现
	if am.agentDiscovery != nil {
		am.agentDiscovery.Stop()
	}
	xlog.Info("Stopping AgentManager")

	// 使用 context 来控制关闭过程
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 停止接受新的连接
	// if am.listener != nil {
	// 	am.listener.Close()
	// }

	// 等待所有现有的操作完成
	var wg sync.WaitGroup
	for _, conn := range am.agentConnections.Values() {
		wg.Add(1)
		go func(c *grpc.ClientConn) {
			defer wg.Done()
			c.Close()
		}(conn)
	}

	// 等待所有连接关闭或超时
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		xlog.Info("All connections closed successfully")
	case <-ctx.Done():
		xlog.Warn("Timeout while waiting for connections to close")
	}

	// 关闭其他资源
	if am.cancel != nil {
		am.cancel()
	}

	xlog.Info("AgentManager stopped successfully")
	return nil
}

// func (am *AgentManager) initSSHServerConfig() {
// 	am.sshConfig = &ssh.ServerConfig{
// 		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
// 			// 这里应该实现真正的身份验证逻辑
// 			if string(pass) == "your-password" {
// 				return nil, nil
// 			}
// 			return nil, fmt.Errorf("password rejected for %q", c.User())
// 		},
// 	}

// 	// 生成服务器密钥
// 	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		xlog.Default().Error("Failed to generate server key", xlog.FieldErr(err))
// 		return
// 	}

// 	// 将 RSA 私钥转换为 SSH 私钥
// 	signer, err := ssh.NewSignerFromKey(privateKey)
// 	if err != nil {
// 		xlog.Default().Error("Failed to create signer", xlog.FieldErr(err))
// 		return
// 	}

// 	am.sshConfig.AddHostKey(signer)
// }

// // 启动 SSH 跳板服务器
// func (am *AgentManager) startSSHJumperServer() error {
// 	listener, err := net.Listen("tcp", ":8022")
// 	if err != nil {
// 		return fmt.Errorf("failed to listen on port 8022: %v", err)
// 	}

// 	am.jumperListener = listener

// 	go func() {
// 		for {
// 			nConn, err := listener.Accept()
// 			if err != nil {
// 				xlog.Default().Error("Failed to accept incoming connection", xlog.FieldErr(err))
// 				continue
// 			}

// 			go am.handleSSHConnection(nConn)
// 		}
// 	}()

// 	xlog.Default().Info("SSH jumper server started on port 8022")
// 	return nil
// }

// // 处理 SSH 连接
// func (am *AgentManager) handleSSHConnection(nConn net.Conn) {
// 	defer nConn.Close()

// 	xlog.Default().Info("New SSH connection received", xlog.String("remoteAddr", nConn.RemoteAddr().String()))

// 	conn, chans, reqs, err := ssh.NewServerConn(nConn, am.sshConfig)
// 	if err != nil {
// 		xlog.Default().Error("Failed to handshake",
// 			xlog.String("remoteAddr", nConn.RemoteAddr().String()),
// 			xlog.FieldErr(err))
// 		return
// 	}
// 	defer conn.Close()

// 	xlog.Default().Info("SSH handshake successful",
// 		xlog.String("user", conn.User()),
// 		xlog.String("clientVersion", string(conn.ClientVersion())))

// 	go ssh.DiscardRequests(reqs)

// 	for newChannel := range chans {
// 		xlog.Default().Info("New channel received",
// 			xlog.String("channelType", newChannel.ChannelType()),
// 			xlog.String("user", conn.User()))

// 		if newChannel.ChannelType() != "direct-tcpip" {
// 			xlog.Default().Warn("Unsupported channel type",
// 				xlog.String("channelType", newChannel.ChannelType()),
// 				xlog.String("user", conn.User()))
// 			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
// 			continue
// 		}

// 		channel, requests, err := newChannel.Accept()
// 		if err != nil {
// 			xlog.Default().Error("Failed to accept channel",
// 				xlog.String("user", conn.User()),
// 				xlog.FieldErr(err))
// 			continue
// 		}

// 		go ssh.DiscardRequests(requests)

// 		var channelData struct {
// 			TargetAddr string
// 			TargetPort uint32
// 			OriginAddr string
// 			OriginPort uint32
// 		}

// 		extraData := newChannel.ExtraData()
// 		xlog.Default().Info("Channel extra data",
// 			xlog.String("user", conn.User()),
// 			xlog.String("extraData", fmt.Sprintf("%v", extraData)))

// 		if err := ssh.Unmarshal(extraData, &channelData); err != nil {
// 			xlog.Default().Error("Failed to unmarshal channel data",
// 				xlog.String("user", conn.User()),
// 				xlog.FieldErr(err))
// 			channel.Close()
// 			continue
// 		}

// 		xlog.Default().Info("Channel data unmarshalled successfully",
// 			xlog.String("user", conn.User()),
// 			xlog.String("targetAddr", channelData.TargetAddr),
// 			xlog.Uint("targetPort", uint(channelData.TargetPort)),
// 			xlog.String("originAddr", channelData.OriginAddr),
// 			xlog.Uint("originPort", uint(channelData.OriginPort)))

// 		go am.forwardConnection(channel, fmt.Sprintf("%s:%d", channelData.TargetAddr, channelData.TargetPort))
// 	}

// 	xlog.Default().Info("SSH connection handling completed",
// 		xlog.String("user", conn.User()),
// 		xlog.String("remoteAddr", nConn.RemoteAddr().String()))
// }

// // 转发连接
// func (am *AgentManager) forwardConnection(channel ssh.Channel, targetAddr string) {
// 	defer channel.Close()

// 	targetConn, err := net.Dial("tcp", targetAddr)
// 	if err != nil {
// 		xlog.Default().Error("Failed to connect to target", xlog.String("target", targetAddr), xlog.FieldErr(err))
// 		return
// 	}
// 	defer targetConn.Close()

// 	var wg sync.WaitGroup
// 	wg.Add(2)

// 	go func() {
// 		defer wg.Done()
// 		io.Copy(targetConn, channel)
// 	}()

// 	go func() {
// 		defer wg.Done()
// 		io.Copy(channel, targetConn)
// 	}()

// 	wg.Wait()
// }

// func (am *AgentManager) EstablishSSHProxy(ctx context.Context, agentCode string) (*ssh.Client, error) {
// 	am.mu.Lock()
// 	defer am.mu.Unlock()

// 	server, err := am.GetServer(ctx, agentCode)
// 	if err != nil {
// 		return nil, fmt.Errorf("server with ID %s not found: %v", agentCode, err)
// 	}

// 	sshConfig, err := am.getSSHConfig(server)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get SSH config: %v", err)
// 	}

// 	client, err := ssh.Dial("tcp", server.Address, sshConfig)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to establish SSH connection: %v", err)
// 	}

//		am.sshClients.Set(agentCode, client)
//		return client, nil
//	}

func (am *AgentManager) ExecuteCommandViaProxy(ctx context.Context, agentCode, command string, rmInfo *structs.L2DeviceRemoteInfo) (string, error) {

	if rmInfo == nil {
		return "", fmt.Errorf("rmInfo is nil")
	}

	xlog.Info("Attempting to connect to target server",
		xlog.String("agentCode", agentCode),
		xlog.String("targetIP", rmInfo.Ip),
		xlog.Int("targetPort", rmInfo.Meta.SSHPort))
	// 创建到目标服务器的 SSH 配置
	targetConfig := &ssh.ClientConfig{
		User: rmInfo.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(rmInfo.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// 使用带有超时的 context
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()

	// 使用 controller 作为跳板服务器连接到目标服务器
	targetConn, err := am.dialTargetThroughControllerWithContext(dialCtx, rmInfo.Ip, rmInfo.Meta.SSHPort)
	if err != nil {
		return "", fmt.Errorf("failed to connect to target server through controller: %v", err)
	}
	defer targetConn.Close()

	targetClient, chans, reqs, err := ssh.NewClientConn(targetConn, fmt.Sprintf("%s:%d", rmInfo.Ip, rmInfo.Meta.SSHPort), targetConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH client for target server: %v", err)
	}
	defer targetClient.Close()

	// 在连接成功后
	xlog.Info("Successfully connected to target server",
		xlog.String("agentCode", agentCode),
		xlog.String("targetIP", rmInfo.Ip),
		xlog.Int("targetPort", rmInfo.Meta.SSHPort))

	client := ssh.NewClient(targetClient, chans, reqs)

	// 创建 SSH 会话并执行命令
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// 使用 context 来控制命令执行
	type result struct {
		output string
		err    error
	}
	resultChan := make(chan result, 1)

	go func() {
		// 在执行命令之前
		xlog.Info("Executing command on target server",
			xlog.String("agentCode", agentCode),
			xlog.String("command", command))
		output, err := session.CombinedOutput(command)
		// 在函数返回之前
		xlog.Info("Command execution completed",
			xlog.String("agentCode", agentCode),
			xlog.String("command", command),
			xlog.Int("outputLength", len(output)),
			xlog.FieldErr(err))
		resultChan <- result{string(output), err}

	}()

	select {
	case <-ctx.Done():
		// 如果 context 被取消，尝试关闭会话
		session.Close()
		return "", ctx.Err()
	case res := <-resultChan:
		return res.output, res.err
	}
}

// dialTargetThroughController 通过 controller 连接到目标服务器
func (am *AgentManager) dialTargetThroughControllerWithContext(ctx context.Context, targetIP string, targetPort int) (net.Conn, error) {
	// 假设 controller 监听在 8022 端口
	controllerAddr := "localhost:8022"

	// 连接到 controller
	dialer := net.Dialer{}
	conn, err := dialer.Dial("tcp", controllerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to controller: %v", err)
	}

	// 发送连接目标服务器的请求
	_, err = fmt.Fprintf(conn, "CONNECT %s:%d\n", targetIP, targetPort)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %v", err)
	}

	// 读取响应
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if !strings.HasPrefix(response, "OK") {
		conn.Close()
		return nil, fmt.Errorf("connection to target server failed: %s", response)
	}

	return conn, nil
}

func (am *AgentManager) getAgentConnection(agentCode string) (*grpc.ClientConn, error) {
	// am.mu.RLock()
	conn, exists := am.agentConnections.Get(agentCode)
	// am.mu.RUnlock()

	if exists && am.isConnectionHealthy(conn) {
		return conn, nil
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	// Double-check after acquiring the write lock
	if conn, exists = am.agentConnections.Get(agentCode); exists && am.isConnectionHealthy(conn) {
		return conn, nil
	}

	// Get Agent address
	agentAddr, err := am.getAgentAddress(agentCode)
	if err != nil {
		return nil, err
	}

	// Create a new connection with retry mechanism
	var newConn *grpc.ClientConn

	err = retry.Do(
		func() error {
			var dialErr error
			newConn, dialErr = grpc.Dial(agentAddr, grpc.WithInsecure(), grpc.WithBackoffMaxDelay(5*time.Second))
			return dialErr
		},
		retry.Attempts(3),
		retry.Delay(1*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection after retries: %v", err)
	}

	am.agentConnections.Set(agentCode, newConn)
	return newConn, nil
}

func (am *AgentManager) isConnectionHealthy(conn *grpc.ClientConn) bool {
	return conn.GetState() == connectivity.Ready
}

func (am *AgentManager) GetAgentHost(ctx context.Context, agentCode string) (string, error) {
	agent, err := am.GetAgent(ctx, agentCode)
	if err != nil {
		return "", fmt.Errorf("agent with ID %s not found: %v", agentCode, err)
	}
	if agent.Status != models.AgentStatusOnline {
		return "", fmt.Errorf("agent %s is not online", agentCode)
	}

	host, _, err := parseHost(agent.Address)
	if err != nil {
		return "", err
	}

	return host, nil
}

func parseHost(addr string) (string, int, error) {
	parts := strings.SplitN(addr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address format: %s", addr)
	}

	host, portStr := parts[0], parts[1]
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port number: %s", portStr)
	}

	return host, port, nil
}

// PackageList 列出指定 agent 上的所有包
func (am *AgentManager) PackageList(ctx context.Context, agentCode string) ([]*pb.PackItem, error) {
	conn, err := am.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %v", err)
	}

	client := pb.NewPackageClient(conn)
	resp, err := client.PackageList(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, fmt.Errorf("failed to list packages: %v", err)
	}

	return resp.Packages, nil
}

// Start 启动指定 agent 上的特定包
func (am *AgentManager) StartPackage(ctx context.Context, agentCode, packageName string) error {
	xlog.Info("Attempting to start package",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))

	conn, err := am.getAgentConnection(agentCode)
	if err != nil {
		xlog.Error("Failed to get agent connection",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to get agent connection: %v", err)
	}

	client := pb.NewPackageClient(conn)
	_, err = client.Start(ctx, &pb.StartReq{Package: packageName})
	if err != nil {
		xlog.Error("Failed to start package",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to start package: %v", err)
	}

	xlog.Info("Successfully started package",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))
	return nil
}

// Stop 停止指定 agent 上的特定包
func (am *AgentManager) StopPackage(ctx context.Context, agentCode, packageName string) error {
	xlog.Info("Attempting to stop package",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))

	conn, err := am.getAgentConnection(agentCode)
	if err != nil {
		xlog.Error("Failed to get agent connection",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to get agent connection: %v", err)
	}

	client := pb.NewPackageClient(conn)
	_, err = client.Stop(ctx, &pb.StopReq{Package: packageName})
	if err != nil {
		xlog.Error("Failed to stop package",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to stop package: %v", err)
	}

	xlog.Info("Successfully stopped package",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))
	return nil
}

// GetConfigs 获取指定 agent 上特定包的配置
func (am *AgentManager) GetPackageConfigs(ctx context.Context, agentCode, packageName string) ([]*pb.ConfigItem, error) {
	conn, err := am.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %v", err)
	}

	client := pb.NewPackageClient(conn)
	resp, err := client.GetConfigs(ctx, &pb.GetConfigsReq{Package: packageName})
	if err != nil {
		return nil, fmt.Errorf("failed to get configs: %v", err)
	}

	return resp.Configs, nil
}

func (am *AgentManager) ApplyPackageConfigs(ctx context.Context, agentCode, packageName string, configs []*pb.ConfigItem) error {
	xlog.Info("Starting to apply package configs",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName),
		xlog.Int("configCount", len(configs)))

	// 检查 Agent 状态
	agent, err := am.GetAgent(ctx, agentCode)
	if err != nil || agent.Status != models.AgentStatusOnline {
		return fmt.Errorf("agent %s is not online or not found: %v", agentCode, err)
	}

	// 验证配置
	if err := am.validateConfigs(configs); err != nil {
		return fmt.Errorf("invalid configs: %v", err)
	}

	conn, err := am.getAgentConnection(agentCode)
	if err != nil {
		xlog.Error("Failed to get agent connection",
			xlog.String("agentCode", agentCode),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to get agent connection: %v", err)
	}
	defer conn.Close()

	client := pb.NewPackageClient(conn)
	resp, err := client.ApplyConfigs(ctx, &pb.ApplyConfigsReq{
		Package: packageName,
		Configs: configs,
	})

	if err != nil {
		xlog.Error("Error from ApplyConfigs call",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to apply configs: %v", err)
	}

	if !resp.Success {
		xlog.Error("Failed to apply configs",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.String("message", resp.Message))
		return fmt.Errorf("failed to apply configs: %s", resp.Message)
	}

	xlog.Info("Successfully applied package configs",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))

	return nil
}

func (am *AgentManager) validateConfigs(configs []*pb.ConfigItem) error {
	for _, config := range configs {
		if config.FileName == "" || config.Content == "" {
			return fmt.Errorf("invalid config: filename or content is empty")
		}
		// 可以添加更多的验证逻辑
	}
	return nil
}

func (am *AgentManager) cleanupConnections() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.mu.Lock()
			for _, agentCode := range am.agentConnections.Keys() {
				conn, _ := am.agentConnections.Get(agentCode)
				if !am.isConnectionHealthy(conn) {
					conn.Close()
					am.agentConnections.Delete(agentCode)
				}
			}
			am.mu.Unlock()
		case <-am.ctx.Done():
			return
		}
	}
}

func (am *AgentManager) DeleteConfigFromNacos(ctx context.Context, agentCode, packageName string) error {
	xlog.Info("Attempting to delete config from Nacos",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))

	// Construct the dataId for the Nacos config
	dataId := am.AgentConfigDataId(packageName, agentCode)

	// Delete the config from Nacos
	err := am.nacosManager.DeleteConfig(dataId, am.configManager.Config.Nacos.AgentGroup)
	if err != nil {
		if err == ErrNacosConfigNotFound {
			xlog.Warn("Config not found in Nacos, considering delete successful",
				xlog.String("agentCode", agentCode),
				xlog.String("packageName", packageName))
			return nil
		}
		xlog.Error("Failed to delete config from Nacos",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to delete config from Nacos: %v", err)
	}

	xlog.Info("Successfully deleted config from Nacos",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName))

	// Optionally, you might want to update the agent's local configuration as well
	// This depends on your specific requirements
	// For example:
	// err = am.DeletePackageConfig(ctx, agentCode, packageName)
	// if err != nil {
	//     xlog.Warn("Failed to delete local package config after Nacos deletion",
	//         xlog.String("agentCode", agentCode),
	//         xlog.String("packageName", packageName),
	//         xlog.FieldErr(err))
	// }

	return nil
}

func (am *AgentManager) GetPackageLogs(ctx context.Context, agentCode, packageName string, count int32) ([]string, error) {
	xlog.Info("Attempting to get package logs",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName),
		xlog.Int32("count", count))

	conn, err := am.getAgentConnection(agentCode)
	if err != nil {
		xlog.Error("Failed to get agent connection",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return nil, fmt.Errorf("failed to get agent connection: %v", err)
	}

	client := pb.NewPackageClient(conn)
	resp, err := client.GetRecentLogs(ctx, &pb.GetRecentLogsReq{
		Package: packageName,
		Count:   count,
	})
	if err != nil {
		xlog.Error("Failed to get package logs",
			xlog.String("agentCode", agentCode),
			xlog.String("packageName", packageName),
			xlog.FieldErr(err))
		return nil, fmt.Errorf("failed to get package logs: %v", err)
	}

	xlog.Info("Successfully retrieved package logs",
		xlog.String("agentCode", agentCode),
		xlog.String("packageName", packageName),
		xlog.Int("logCount", len(resp.Logs)))

	return resp.Logs, nil
}

// UninstallAgent 卸载Agent
func (am *AgentManager) UninstallAgent(ctx context.Context, agentCode string) error {
	// 获取 Agent 连接
	_, err := am.getAgentConnection(agentCode)
	if err != nil {
		return fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 通过 gRPC 调用 Agent 的卸载方法
	// 注意：这里需要根据实际的 Agent gRPC 服务定义来实现
	// 如果 Agent 没有 Uninstall 方法，可能需要通过 SSH 连接到目标服务器执行卸载命令
	// 暂时返回成功，实际卸载逻辑需要根据具体需求实现
	xlog.Info("Agent uninstall request received",
		xlog.String("agentCode", agentCode))

	// TODO: 实现实际的卸载逻辑
	// 可以通过以下方式之一：
	// 1. 通过 gRPC 调用 Agent 的 Uninstall 方法（如果存在）
	// 2. 通过 SSH 连接到目标服务器执行卸载命令
	// 3. 通过部署工具执行卸载操作

	return nil
}

// RestartAgent 重启Agent
func (am *AgentManager) RestartAgent(ctx context.Context, agentCode string) error {
	// 获取 Agent 连接
	conn, err := am.getAgentConnection(agentCode)
	if err != nil {
		return fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 通过 gRPC 调用 Agent 的重启方法
	// 注意：这里需要根据实际的 Agent gRPC 服务定义来实现
	xlog.Info("Agent restart request received",
		xlog.String("agentCode", agentCode))

	// TODO: 实现实际的重启逻辑
	// 可以通过以下方式之一：
	// 1. 通过 gRPC 调用 Agent 的 Restart 方法（如果存在）
	// 2. 通过 SSH 连接到目标服务器执行重启命令
	// 3. 通过 systemd 或其他服务管理工具重启 Agent

	_ = conn // 暂时使用 conn 避免未使用变量警告

	return nil
}
