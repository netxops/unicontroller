package controller

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/mwitkow/grpc-proxy/proxy"
	"github.com/netxops/utils/tools"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// const GrpcProxyServiceName = "controller-grpc-proxy"

type GrpcProxyManager struct {
	server           *grpc.Server
	config           *Config
	listener         net.Listener
	agentConnections *tools.SafeMap[string, *grpc.ClientConn]
	keyManager       *KeyManager
	registryManager  *RegistryManager
	agentManager     *AgentManager
	ctx              context.Context
	cancel           context.CancelFunc
	StreamDirector   proxy.StreamDirector
	serviceInfo      *models.ServiceInfo
}

func ProvideGrpcProxyManager(registryManager *RegistryManager, am *AgentManager, km *KeyManager, config *Config) *GrpcProxyManager {
	ctx, cancel := context.WithCancel(context.Background())
	gpm := &GrpcProxyManager{
		agentConnections: tools.NewSafeMap[string, *grpc.ClientConn](),
		registryManager:  registryManager,
		agentManager:     am,
		ctx:              ctx,
		cancel:           cancel,
		config:           config,
		keyManager:       km,
	}

	gpm.StreamDirector = gpm.director
	return gpm

}

func (gpm *GrpcProxyManager) Start() error {
	lis, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", gpm.config.BaseConfig.GrpcProxy))
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	gpm.listener = lis
	gpm.server = grpc.NewServer(
		grpc.UnknownServiceHandler(proxy.TransparentHandler(gpm.StreamDirector)),
	)

	go func() {
		if err := gpm.server.Serve(lis); err != nil {
			xlog.Default().Error("Failed to serve gRPC proxy", xlog.FieldErr(err))
		}
	}()

	xlog.Default().Info(fmt.Sprintf("gRPC proxy server started on port %d", gpm.config.BaseConfig.GrpcProxy))

	key, err := gpm.keyManager.GenerateServiceKey(string(models.ServiceNameGrpcProxy), gpm.registryManager.HostIdentifier, fmt.Sprintf("%d", gpm.config.BaseConfig.GrpcProxy))
	if err != nil {
		return fmt.Errorf("failed to generate service key: %v", err)
	}
	serviceInfo := &models.ServiceInfo{
		Key:      key,
		Name:     string(models.ServiceNameGrpcProxy),
		Protocol: "tcp",
		Address:  gpm.listener.Addr().String(),
	}
	gpm.serviceInfo = serviceInfo

	go gpm.periodicRegister()
	return nil
}

func (gpm *GrpcProxyManager) Stop() error {
	gpm.cancel() // 停止周期性注册

	if gpm.server != nil {
		gpm.server.GracefulStop()
	}
	if gpm.listener != nil {
		return gpm.listener.Close()
	}
	return nil
}

func (gpm *GrpcProxyManager) director(ctx context.Context, fullMethodName string) (context.Context, grpc.ClientConnInterface, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil, status.Errorf(codes.Internal, "failed to get metadata from context")
	}

	outCtx := metadata.NewOutgoingContext(ctx, md.Copy())

	agentCode, ok := gpm.getAgentCodeFromMetadata(md)
	if !ok {
		return nil, nil, status.Errorf(codes.InvalidArgument, "agent code not found in metadata")
	}

	conn, err := gpm.getAgentConnection(agentCode)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "failed to get agent connection: %v", err)
	}

	return outCtx, conn, nil
}

func (gpm *GrpcProxyManager) getAgentCodeFromMetadata(md metadata.MD) (string, bool) {
	agentCodes := md.Get("agent-code")
	if len(agentCodes) == 0 {
		return "", false
	}
	return agentCodes[0], true
}

func (gpm *GrpcProxyManager) getAgentConnection(agentCode string) (*grpc.ClientConn, error) {
	conn, exists := gpm.agentConnections.Get(agentCode)
	if exists {
		return conn, nil
	}

	agent, err := gpm.agentManager.GetAgent(context.Background(), agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent info: %v", err)
	}

	newConn, err := grpc.Dial(agent.Address, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("failed to dial agent: %v", err)
	}

	gpm.agentConnections.Set(agentCode, newConn)
	return newConn, nil
}

func (gpm *GrpcProxyManager) periodicRegister() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒注册一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gpm.registerService()
		case <-gpm.ctx.Done():
			xlog.Default().Info("Stopping gRPC proxy service registration")
			return
		}
	}
}

func (gpm *GrpcProxyManager) registerService() {
	err := gpm.registryManager.RegisterService(gpm.serviceInfo, 1*time.Minute) // TTL设置为1分钟
	if err != nil {
		xlog.Default().Error("Failed to register gRPC proxy service", xlog.FieldErr(err))
	}
}
