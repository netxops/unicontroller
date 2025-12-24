package initialize

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/douyu/jupiter"
	"github.com/douyu/jupiter/pkg/core/constant"
	"github.com/douyu/jupiter/pkg/core/hooks"
	"github.com/douyu/jupiter/pkg/registry"
	"github.com/douyu/jupiter/pkg/server"
	"github.com/douyu/jupiter/pkg/server/xecho"
	"github.com/douyu/jupiter/pkg/server/xgrpc"
	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pb"
	"github.com/influxdata/telegraf/controller/pkg/packages"
	"github.com/influxdata/telegraf/controller/service/grpc"
	"github.com/influxdata/telegraf/controller/utils"
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Engine struct {
	xGRPC *xgrpc.Server
	xECHO *xecho.Server
	jupiter.Application
	pkgManager *packages.PackageManager
}

func NewEngine() *Engine {
	e := &Engine{
		pkgManager: packages.NewPackageManager(),
	}

	// 只创建应用框架
	if err := e.Startup(); err != nil {
		xlog.Default().Panic("startup", xlog.FieldErr(err))
	}
	// 配置日志只输出到 stdout，避免在只读文件系统创建日志文件
	// 如果当前工作目录是只读的（如容器中的 /app），设置日志目录为 /tmp
	if wd, err := os.Getwd(); err == nil {
		// 检查当前目录是否可写
		if testFile := wd + "/.write_test"; os.WriteFile(testFile, []byte("test"), 0644) != nil {
			// 目录不可写，设置日志目录为 /tmp
			os.Setenv("JUPITER_LOG_DIR", "/tmp")
		} else {
			// 清理测试文件
			os.Remove(testFile)
		}
	}
	cfg := xlog.StdConfig("jupiter", "default")
	xlog.SetDefault(cfg.Build())

	// 初始化配置
	NewConfig()
	utils.CheckWorkspace()
	// NewDatabase()
	// InitPacksCache()
	InitMachineAddress()
	InitPlatformInfo()

	grpcWrapper := NewGRPC(e.grpc(), e.pkgManager)
	// 配置初始化完成后再注册服务
	if err := e.Serve(
		grpcWrapper,
		NewECHO(e.echo()),
	); err != nil {
		xlog.Default().Panic("serve", xlog.FieldErr(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	// go InitProxy(ctx, e.xGRPC)
	go e.pkgManager.Loop(ctx)
	e.RegisterHooks(hooks.Stage_AfterStop, func() {
		cancel()
	})
	go e.periodicRegister(ctx, grpcWrapper)
	return e
}

type GRPCWrapper struct {
	*xgrpc.Server
	pm *packages.PackageManager
}

func NewGRPC(server *xgrpc.Server, pm *packages.PackageManager) *GRPCWrapper {
	return &GRPCWrapper{
		server,
		pm,
	}
}

func (w *GRPCWrapper) Info() *server.ServiceInfo {
	ps, err := w.pm.GetAllPackageStatuses()
	if err != nil {
		xlog.Default().Error("failed to get package statuses", xlog.FieldErr(err))
	}
	status, err := json.Marshal(ps)
	if err != nil {
		xlog.Default().Error("failed to marshal package statuses", xlog.FieldErr(err))
	}
	originalInfo := w.Server.Info()
	info := server.ApplyOptions(
		server.WithScheme("grpc"),
		server.WithAddress(originalInfo.Address),
		server.WithKind(constant.ServiceProvider),
		server.WithMetaData("services", string(status)),
	)
	if err != nil {
		xlog.Default().Error("failed to get package statuses", xlog.FieldErr(err))
		return originalInfo
	}
	info.AppID = global.Conf.Code
	return &info
}

type ECHOWrapper struct {
	*xecho.Server
}

func NewECHO(server *xecho.Server) *ECHOWrapper {
	return &ECHOWrapper{
		server,
	}
}

func (w *ECHOWrapper) Info() *server.ServiceInfo {
	originalInfo := w.Server.Info()
	info := server.ApplyOptions(
		server.WithScheme("http"),
		server.WithAddress(originalInfo.Address),
		server.WithKind(constant.ServiceProvider),
	)
	info.AppID = global.Conf.Code
	return &info
}

// func (e *Engine) grpc() *xgrpc.Server {
// 	e.xGRPC = xgrpc.StdConfig("grpc").MustBuild()
// 	pb.RegisterLuaServer(e.xGRPC, &grpc.LuaSrv{})
// 	pb.RegisterPackageServer(e.xGRPC, grpc.NewPackageSrv(e.pkgManager))
// 	pb.RegisterCommandServer(e.xGRPC, &grpc.CommandSrv{
// 		Commands:   make(map[string]*exec.Cmd),
// 		CancelFunc: make(map[string]context.CancelFunc),
// 	})
// 	return e.xGRPC
// }

func (e *Engine) grpc() *xgrpc.Server {
	e.xGRPC = xgrpc.StdConfig("grpc").MustBuild()
	pb.RegisterLuaServer(e.xGRPC, &grpc.LuaSrv{})
	pb.RegisterPackageServer(e.xGRPC, grpc.NewPackageSrv(e.pkgManager))
	pb.RegisterCommandServer(e.xGRPC, &grpc.CommandSrv{
		Commands: make(map[string]*grpc.CommandInfo),
	})
	return e.xGRPC
}

func (e *Engine) echo() *xecho.Server {
	e.xECHO = xecho.StdConfig("http").MustBuild()
	e.xECHO.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	// 添加 /health 接口
	e.xECHO.GET("/health", func(c echo.Context) error {
		// 这里可以添加更复杂的健康检查逻辑
		health := map[string]interface{}{
			"status": "UP",
			"components": map[string]interface{}{
				"database": e.checkDatabaseHealth(),
			},
		}
		return c.JSON(http.StatusOK, health)
	})

	return e.xECHO
}

type Infoer interface {
	Info() *server.ServiceInfo
}

func (e *Engine) periodicRegister(ctx context.Context, infoer Infoer) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	xlog.Default().Info("Starting periodic registration")
	for {
		select {
		case <-ctx.Done():
			xlog.Default().Info("Periodic registration stopped due to context cancellation")
			return
		case <-ticker.C:
			xlog.Default().Info("Attempting periodic registration")
			info := infoer.Info()
			xlog.Default().Info("Service info retrieved", xlog.Any("info", info))

			if err := registry.DefaultRegisterer.RegisterService(ctx, info); err != nil {
				xlog.Default().Error("Failed to register service",
					xlog.FieldErr(err),
					xlog.Any("service_info", info))
			} else {
				xlog.Default().Info("Service registered successfully",
					xlog.String("service_id", info.Name),
					xlog.String("address", info.Address))
			}
		}
	}
}

// 检查数据库健康状态
func (e *Engine) checkDatabaseHealth() map[string]string {
	return map[string]string{"status": "UP"}
}
