package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/influxdata/telegraf/controller/agentv2/internal"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/utils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	configPath = flag.String("config", "configs/agentv2.yaml", "Path to configuration file")
)

func main() {
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化日志（根据配置）
	logger, err := initLogger(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	logger.Info("Starting Agent V2",
		zap.String("config", *configPath),
		zap.String("agent_code", cfg.Agent.Code),
		zap.Int("grpc_port", cfg.Server.GRPCPort),
		zap.Int("http_port", cfg.Server.HTTPPort),
	)

	// 初始化应用（使用 Wire 依赖注入）
	app, err := internal.InitializeApp(cfg, *configPath, logger)
	if err != nil {
		logger.Fatal("Failed to initialize app", zap.Error(err))
	}

	// 启动服务器
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := app.Server.Start(ctx); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}

	// 启动注册管理器
	if app.RegistryManager != nil {
		if err := app.RegistryManager.Start(); err != nil {
			logger.Fatal("Failed to start registry manager", zap.Error(err))
		}
	}

	// 启动服务发现
	if app.ServiceDiscovery != nil {
		go func() {
			if err := app.ServiceDiscovery.Start(ctx); err != nil {
				logger.Error("Service discovery stopped", zap.Error(err))
			}
		}()
		logger.Info("Service discovery started")
	}

	// 启动健康检查和自动恢复协调器
	if app.HealthCoordinator != nil {
		if err := app.HealthCoordinator.Start(); err != nil {
			logger.Error("Failed to start health coordinator", zap.Error(err))
		} else {
			logger.Info("Health check and auto recovery coordinator started")
		}
	}

	// 启动指标收集器
	if app.MetricsCollector != nil {
		go func() {
			if err := app.MetricsCollector.Start(ctx); err != nil {
				logger.Error("Metrics collector stopped", zap.Error(err))
			}
		}()
		logger.Info("Metrics collector started")
	}

	// 启动指标上报器
	if app.MetricsReporter != nil {
		if err := app.MetricsReporter.Start(ctx); err != nil {
			logger.Error("Failed to start metrics reporter", zap.Error(err))
		} else {
			logger.Info("Metrics reporter started")
		}
	}

	// 启动配置热重载器
	if app.ConfigReloader != nil {
		if err := app.ConfigReloader.Start(ctx); err != nil {
			logger.Error("Failed to start config reloader", zap.Error(err))
		} else {
			logger.Info("Config reloader started")
		}
	}

	// 启动策略同步器
	if app.StrategySyncer != nil {
		if err := app.StrategySyncer.Start(ctx); err != nil {
			logger.Error("Failed to start strategy syncer", zap.Error(err))
		} else {
			logger.Info("Strategy syncer started")
		}
	}

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))

	// 停止策略同步器
	if app.StrategySyncer != nil {
		app.StrategySyncer.Stop()
	}

	// 停止配置热重载器
	if app.ConfigReloader != nil {
		if err := app.ConfigReloader.Stop(); err != nil {
			logger.Error("Error stopping config reloader", zap.Error(err))
		}
	}

	// 停止指标上报器
	if app.MetricsReporter != nil {
		if err := app.MetricsReporter.Stop(); err != nil {
			logger.Error("Error stopping metrics reporter", zap.Error(err))
		}
	}

	// 停止指标收集器
	if app.MetricsCollector != nil {
		if err := app.MetricsCollector.Stop(); err != nil {
			logger.Error("Error stopping metrics collector", zap.Error(err))
		}
	}

	// 停止健康检查和自动恢复协调器
	if app.HealthCoordinator != nil {
		if err := app.HealthCoordinator.Stop(); err != nil {
			logger.Error("Error stopping health coordinator", zap.Error(err))
		}
	}

	// 停止服务发现
	if app.ServiceDiscovery != nil {
		if err := app.ServiceDiscovery.Stop(); err != nil {
			logger.Error("Error stopping service discovery", zap.Error(err))
		}
	}

	// 停止注册管理器
	if app.RegistryManager != nil {
		if err := app.RegistryManager.Stop(); err != nil {
			logger.Error("Error stopping registry manager", zap.Error(err))
		}
	}

	// 优雅关闭
	if err := app.Server.Shutdown(ctx); err != nil {
		logger.Error("Error during shutdown", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("Agent V2 shutdown complete")
}

// initLogger 初始化日志器，支持文件输出
func initLogger(cfg *config.Config) (*zap.Logger, error) {
	// 确定日志目录
	logDir := cfg.Logging.Directory
	if logDir == "" {
		logDir = utils.GetDefaultLogDirectory()
	}

	// 确保日志目录存在
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 解析 max_size
	maxSize := int64(100 * 1024 * 1024) // 默认 100MB
	if cfg.Logging.MaxSize != "" {
		if strings.HasSuffix(cfg.Logging.MaxSize, "MB") {
			var mb int64
			fmt.Sscanf(cfg.Logging.MaxSize, "%dMB", &mb)
			maxSize = mb * 1024 * 1024
		} else if strings.HasSuffix(cfg.Logging.MaxSize, "GB") {
			var gb int64
			fmt.Sscanf(cfg.Logging.MaxSize, "%dGB", &gb)
			maxSize = gb * 1024 * 1024 * 1024
		}
	}

	// 配置日志轮转
	logFile := filepath.Join(logDir, "agentv2.log")
	writer := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    int(maxSize / (1024 * 1024)), // 转换为 MB
		MaxBackups: cfg.Logging.MaxFiles,
		MaxAge:     30, // 保留 30 天
		Compress:   true,
	}

	// 配置编码器
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder

	// 根据日志级别设置编码器
	var encoder zapcore.Encoder
	if cfg.Logging.Level == "debug" {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// 设置日志级别
	var level zapcore.Level
	switch strings.ToLower(cfg.Logging.Level) {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	// 创建核心：同时输出到文件和控制台
	core := zapcore.NewTee(
		zapcore.NewCore(encoder, zapcore.AddSync(writer), level),
		zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), level),
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	// 记录日志文件位置
	logger.Info("Logger initialized",
		zap.String("log_file", logFile),
		zap.String("log_dir", logDir),
		zap.String("level", cfg.Logging.Level),
		zap.Int64("max_size", maxSize),
		zap.Int("max_files", cfg.Logging.MaxFiles))

	return logger, nil
}
