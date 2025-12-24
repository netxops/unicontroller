package api

import (
	"context"
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/logs"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"github.com/influxdata/telegraf/controller/pb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// PackageService Package gRPC 服务实现
type PackageService struct {
	pb.UnimplementedPackageServer
	serviceManager service.ServiceManager
	configManager  service.ConfigManager
	logManager     logs.LogManager
	logger         *zap.Logger
}

// NewPackageService 创建 Package 服务
func NewPackageService(
	serviceManager service.ServiceManager,
	configManager service.ConfigManager,
	logManager logs.LogManager,
	logger *zap.Logger,
) *PackageService {
	return &PackageService{
		serviceManager: serviceManager,
		configManager:  configManager,
		logManager:     logManager,
		logger:         logger,
	}
}

// Start 启动服务
func (s *PackageService) Start(ctx context.Context, req *pb.StartReq) (*emptypb.Empty, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	s.logger.Info("Received start request", zap.String("package", req.Package))

	// 异步启动服务
	go func() {
		service, err := s.serviceManager.GetStatus(ctx, req.Package)
		if err != nil {
			s.logger.Error("Failed to get service", zap.String("package", req.Package), zap.Error(err))
			return
		}

		if err := s.serviceManager.Start(ctx, service.ID); err != nil {
			s.logger.Error("Failed to start service", zap.String("package", req.Package), zap.Error(err))
		} else {
			s.logger.Info("Service started successfully", zap.String("package", req.Package))
		}
	}()

	return &emptypb.Empty{}, nil
}

// Stop 停止服务
func (s *PackageService) Stop(ctx context.Context, req *pb.StopReq) (*emptypb.Empty, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	s.logger.Info("Received stop request", zap.String("package", req.Package))

	go func() {
		service, err := s.serviceManager.GetStatus(ctx, req.Package)
		if err != nil {
			s.logger.Error("Failed to get service", zap.String("package", req.Package), zap.Error(err))
			return
		}

		if err := s.serviceManager.Stop(ctx, service.ID); err != nil {
			s.logger.Error("Failed to stop service", zap.String("package", req.Package), zap.Error(err))
		} else {
			s.logger.Info("Service stopped successfully", zap.String("package", req.Package))
		}
	}()

	return &emptypb.Empty{}, nil
}

// Restart 重启服务
func (s *PackageService) Restart(ctx context.Context, req *pb.RestartReq) (*emptypb.Empty, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	s.logger.Info("Received restart request", zap.String("package", req.Package))

	go func() {
		service, err := s.serviceManager.GetStatus(ctx, req.Package)
		if err != nil {
			s.logger.Error("Failed to get service", zap.String("package", req.Package), zap.Error(err))
			return
		}

		if err := s.serviceManager.Restart(ctx, service.ID); err != nil {
			s.logger.Error("Failed to restart service", zap.String("package", req.Package), zap.Error(err))
		} else {
			s.logger.Info("Service restarted successfully", zap.String("package", req.Package))
		}
	}()

	return &emptypb.Empty{}, nil
}

// PackageList 列出所有服务
func (s *PackageService) PackageList(ctx context.Context, _ *emptypb.Empty) (*pb.PackageListResp, error) {
	services, err := s.serviceManager.ListServices(ctx)
	if err != nil {
		s.logger.Error("Failed to list services", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to list services: %v", err)
	}

	packages := make([]*pb.PackItem, 0, len(services))
	for _, service := range services {
		item := &pb.PackItem{
			Package:   service.Name,
			IsRunning: service.IsRunning(),
			Version:   service.Version,
		}
		if service.StartedAt != nil {
			// 计算运行时长（秒）
			item.RunningDuration = int64(time.Since(*service.StartedAt).Seconds())
		}
		packages = append(packages, item)
	}

	return &pb.PackageListResp{
		Packages: packages,
	}, nil
}

// GetConfigs 获取配置
func (s *PackageService) GetConfigs(ctx context.Context, req *pb.GetConfigsReq) (*pb.GetConfigsResp, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	s.logger.Info("Received GetConfigs request", zap.String("package", req.Package))

	// 获取配置文件
	configFiles, err := s.configManager.GetConfigFiles(req.Package)
	if err != nil {
		s.logger.Error("Failed to get config files", zap.String("package", req.Package), zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to get config files: %v", err)
	}

	// 转换为 proto 格式
	configItems := make([]*pb.ConfigItem, 0, len(configFiles))
	for _, file := range configFiles {
		configItems = append(configItems, &pb.ConfigItem{
			FileName: file.Path,
			Content:  file.Content,
		})
	}

	s.logger.Info("Successfully retrieved configs",
		zap.String("package", req.Package),
		zap.Int("count", len(configItems)))

	return &pb.GetConfigsResp{
		Configs: configItems,
	}, nil
}

// ApplyConfigs 应用配置
func (s *PackageService) ApplyConfigs(ctx context.Context, req *pb.ApplyConfigsReq) (*pb.ApplyConfigsResp, error) {
	if req == nil || req.Package == "" {
		return &pb.ApplyConfigsResp{
			Success: false,
			Message: "package name cannot be empty",
		}, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	if len(req.Configs) == 0 {
		return &pb.ApplyConfigsResp{
			Success: false,
			Message: "no configs provided",
		}, status.Errorf(codes.InvalidArgument, "no configs provided")
	}

	s.logger.Info("Received ApplyConfigs request",
		zap.String("package", req.Package),
		zap.Int("config_count", len(req.Configs)))

	// 转换为内部格式
	configFiles := make([]service.ConfigFile, 0, len(req.Configs))
	for _, config := range req.Configs {
		configFiles = append(configFiles, service.ConfigFile{
			Path:    config.FileName,
			Content: config.Content,
		})
	}

	// 停止服务（如果需要）
	service, err := s.serviceManager.GetStatus(ctx, req.Package)
	if err == nil && service.IsRunning() {
		s.logger.Info("Stopping service before applying configs", zap.String("package", req.Package))
		if stopErr := s.serviceManager.Stop(ctx, req.Package); stopErr != nil {
			s.logger.Warn("Failed to stop service before applying configs",
				zap.String("package", req.Package),
				zap.Error(stopErr))
			// 继续执行，不因为停止失败而放弃
		}
	}

	// 更新配置文件
	updatedFiles, err := s.configManager.UpdateConfigFiles(req.Package, configFiles)
	if err != nil {
		s.logger.Error("Failed to update config files",
			zap.String("package", req.Package),
			zap.Error(err))
		return &pb.ApplyConfigsResp{
			Success: false,
			Message: fmt.Sprintf("failed to update config files: %v", err),
		}, nil
	}

	// 启动服务（如果之前是运行状态）
	if service != nil && service.IsRunning() {
		s.logger.Info("Starting service after applying configs", zap.String("package", req.Package))
		if startErr := s.serviceManager.Start(ctx, req.Package); startErr != nil {
			s.logger.Error("Failed to start service after applying configs",
				zap.String("package", req.Package),
				zap.Error(startErr))
			// 返回警告，但配置已成功应用
		}
	}

	// 转换为 proto 格式
	updatedFileDetails := make([]*pb.UpdatedFileDetail, 0, len(updatedFiles))
	for fileName, byteCount := range updatedFiles {
		updatedFileDetails = append(updatedFileDetails, &pb.UpdatedFileDetail{
			FileName:  fileName,
			ByteCount: int32(byteCount),
		})
	}

	s.logger.Info("Successfully applied configs",
		zap.String("package", req.Package),
		zap.Int("file_count", len(updatedFiles)))

	return &pb.ApplyConfigsResp{
		Success:      true,
		Message:      "Configs applied successfully",
		UpdatedFiles: updatedFileDetails,
	}, nil
}

// GetRecentLogs 获取最近日志
func (s *PackageService) GetRecentLogs(ctx context.Context, req *pb.GetRecentLogsReq) (*pb.GetRecentLogsResp, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	count := int(req.Count)
	if count <= 0 {
		count = 100 // 默认返回最近 100 行
	}

	s.logger.Info("Received GetRecentLogs request",
		zap.String("package", req.Package),
		zap.Int("count", count))

	// 使用 LogManager 获取日志
	logLines, err := s.logManager.CollectLogs(ctx, req.Package, count)
	if err != nil {
		s.logger.Error("Failed to get recent logs",
			zap.String("package", req.Package),
			zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to get recent logs: %v", err)
	}

	s.logger.Info("Successfully retrieved recent logs",
		zap.String("package", req.Package),
		zap.Int("line_count", len(logLines)))

	return &pb.GetRecentLogsResp{
		Logs: logLines,
	}, nil
}

// StreamLogs 流式传输日志
func (s *PackageService) StreamLogs(req *pb.StreamLogsReq, stream pb.Package_StreamLogsServer) error {
	if req == nil || req.Package == "" {
		return status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	tailLines := int(req.TailLines)
	follow := req.Follow

	s.logger.Info("Received StreamLogs request",
		zap.String("package", req.Package),
		zap.Int("tail_lines", tailLines),
		zap.Bool("follow", follow))

	// 创建日志 channel
	logChan := make(chan string, 100)

	// 启动流式读取
	ctx := stream.Context()
	errChan := make(chan error, 1)

	go func() {
		err := s.logManager.StreamLogs(ctx, req.Package, tailLines, follow, logChan)
		if err != nil {
			errChan <- err
		}
	}()

	// 从 channel 读取日志并发送到流
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("StreamLogs context cancelled",
				zap.String("package", req.Package))
			return nil
		case err := <-errChan:
			if err != nil {
				s.logger.Error("StreamLogs error",
					zap.String("package", req.Package),
					zap.Error(err))
				return status.Errorf(codes.Internal, "failed to stream logs: %v", err)
			}
		case logLine, ok := <-logChan:
			if !ok {
				// Channel 已关闭，发送 EOF
				s.logger.Info("StreamLogs completed",
					zap.String("package", req.Package))
				return stream.Send(&pb.StreamLogsResp{
					LogLine: "",
					IsEof:   true,
				})
			}

			// 发送日志行
			if err := stream.Send(&pb.StreamLogsResp{
				LogLine: logLine,
				IsEof:   false,
			}); err != nil {
				s.logger.Error("Failed to send log line",
					zap.String("package", req.Package),
					zap.Error(err))
				return err
			}
		}
	}
}

// QueryLogs 查询日志（支持搜索、过滤、分页）
func (s *PackageService) QueryLogs(ctx context.Context, req *pb.QueryLogsReq) (*pb.QueryLogsResp, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	// 构建查询选项
	options := logs.LogQueryOptions{
		Keyword: req.Keyword,
		Level:   req.Level,
		Limit:   int(req.Limit),
		Offset:  int(req.Offset),
		Reverse: req.Reverse,
	}

	// 解析时间范围
	if req.StartTime > 0 {
		startTime := time.Unix(req.StartTime, 0)
		options.StartTime = &startTime
	}
	if req.EndTime > 0 {
		endTime := time.Unix(req.EndTime, 0)
		options.EndTime = &endTime
	}

	s.logger.Info("Received QueryLogs request",
		zap.String("package", req.Package),
		zap.String("keyword", req.Keyword),
		zap.String("level", req.Level),
		zap.Int("limit", int(req.Limit)),
		zap.Int("offset", int(req.Offset)))

	// 执行查询
	result, err := s.logManager.QueryLogs(ctx, req.Package, options)
	if err != nil {
		s.logger.Error("Failed to query logs",
			zap.String("package", req.Package),
			zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to query logs: %v", err)
	}

	s.logger.Info("Successfully queried logs",
		zap.String("package", req.Package),
		zap.Int("total", result.Total),
		zap.Int("returned", len(result.Logs)),
		zap.Bool("has_more", result.HasMore))

	return &pb.QueryLogsResp{
		Logs:    result.Logs,
		Total:   int32(result.Total),
		HasMore: result.HasMore,
	}, nil
}
