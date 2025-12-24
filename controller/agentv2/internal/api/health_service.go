package api

import (
	"context"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/health"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"github.com/influxdata/telegraf/controller/pb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// HealthService 健康检查服务
type HealthService struct {
	pb.UnimplementedHealthServer
	healthChecker     health.HealthChecker
	healthCoordinator *health.Coordinator
	serviceManager    service.ServiceManager
	logger            *zap.Logger
}

// NewHealthService 创建健康检查服务
func NewHealthService(healthChecker health.HealthChecker, healthCoordinator *health.Coordinator, serviceManager service.ServiceManager, logger *zap.Logger) *HealthService {
	return &HealthService{
		healthChecker:     healthChecker,
		healthCoordinator: healthCoordinator,
		serviceManager:    serviceManager,
		logger:            logger,
	}
}

// GetHealthStatus 获取指定服务的健康状态
func (s *HealthService) GetHealthStatus(ctx context.Context, req *pb.GetHealthStatusReq) (*pb.GetHealthStatusResp, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	s.logger.Info("Received GetHealthStatus request", zap.String("package", req.Package))

	// 获取服务
	service, err := s.serviceManager.GetStatus(ctx, req.Package)
	if err != nil {
		s.logger.Error("Failed to get service", zap.String("package", req.Package), zap.Error(err))
		return nil, status.Errorf(codes.NotFound, "service %s not found", req.Package)
	}

	// 执行健康检查
	checkResult, err := s.healthChecker.Check(ctx, service)
	if err != nil {
		s.logger.Warn("Health check failed", zap.String("package", req.Package), zap.Error(err))
		// 即使检查失败，也返回状态
		checkResult = &domain.CheckResult{
			Healthy:   false,
			Message:   err.Error(),
			Error:     err,
			Timestamp: time.Now(),
		}
	}

	// 转换为 proto 格式
	healthProto := s.convertToServiceHealth(service, checkResult)

	return &pb.GetHealthStatusResp{
		Health: healthProto,
	}, nil
}

// ListHealthStatuses 列出所有服务的健康状态
func (s *HealthService) ListHealthStatuses(ctx context.Context, req *pb.ListHealthStatusesReq) (*pb.ListHealthStatusesResp, error) {
	s.logger.Info("Received ListHealthStatuses request")

	// 获取所有服务
	services, err := s.serviceManager.ListServices(ctx)
	if err != nil {
		s.logger.Error("Failed to list services", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to list services: %v", err)
	}

	healthStatuses := make([]*pb.ServiceHealth, 0, len(services))
	for _, service := range services {
		// 执行健康检查
		checkResult, err := s.healthChecker.Check(ctx, service)
		if err != nil {
			s.logger.Warn("Health check failed", zap.String("package", service.Name), zap.Error(err))
			checkResult = &domain.CheckResult{
				Healthy:   false,
				Message:   err.Error(),
				Error:     err,
				Timestamp: time.Now(),
			}
		}

		// 应用状态过滤
		if req != nil && len(req.FilterStatus) > 0 {
			statusProto := s.convertHealthStatus(checkResult)
			filtered := false
			for _, filterStatus := range req.FilterStatus {
				if statusProto == filterStatus {
					filtered = true
					break
				}
			}
			if !filtered {
				continue
			}
		}

		healthProto := s.convertToServiceHealth(service, checkResult)
		healthStatuses = append(healthStatuses, healthProto)
	}

	return &pb.ListHealthStatusesResp{
		HealthStatuses: healthStatuses,
	}, nil
}

// GetHealthHistory 获取服务的健康检查历史
func (s *HealthService) GetHealthHistory(ctx context.Context, req *pb.GetHealthHistoryReq) (*pb.GetHealthHistoryResp, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = 100 // 默认 100 条
	}

	s.logger.Info("Received GetHealthHistory request",
		zap.String("package", req.Package),
		zap.Int("limit", limit))

	// 获取服务
	service, err := s.serviceManager.GetStatus(ctx, req.Package)
	if err != nil {
		s.logger.Error("Failed to get service", zap.String("package", req.Package), zap.Error(err))
		return nil, status.Errorf(codes.NotFound, "service %s not found", req.Package)
	}

	// 执行健康检查获取当前状态
	checkResult, err := s.healthChecker.Check(ctx, service)
	if err != nil {
		s.logger.Warn("Health check failed", zap.String("package", req.Package), zap.Error(err))
		checkResult = &domain.CheckResult{
			Healthy:   false,
			Message:   err.Error(),
			Error:     err,
			Timestamp: time.Now(),
		}
	}

	// 从健康检查协调器获取历史记录
	var entries []*pb.HealthHistoryEntry
	if s.healthCoordinator != nil {
		historyEntries := s.healthCoordinator.GetHistory(req.Package, limit)
		entries = make([]*pb.HealthHistoryEntry, 0, len(historyEntries))
		for _, entry := range historyEntries {
			entryProto := &pb.HealthHistoryEntry{
				Status:         s.convertHealthStatusFromDomain(entry.Status),
				Message:        entry.Message,
				Timestamp:      timestamppb.New(entry.Timestamp),
				ResponseTimeMs: int64(entry.ResponseTime.Milliseconds()),
				CheckType:      entry.CheckType,
			}
			if entry.Error != nil {
				entryProto.Error = entry.Error.Error()
			}
			entries = append(entries, entryProto)
		}
	}

	// 如果没有历史记录，返回当前检查结果
	if len(entries) == 0 {
		entry := &pb.HealthHistoryEntry{
			Status:         s.convertHealthStatus(checkResult),
			Message:        checkResult.Message,
			Timestamp:      timestamppb.New(checkResult.Timestamp),
			ResponseTimeMs: int64(checkResult.ResponseTime.Milliseconds()),
		}
		if checkResult.Error != nil {
			entry.Error = checkResult.Error.Error()
		}

		// 确定检查类型
		if service.Spec != nil && service.Spec.Operations != nil && service.Spec.Operations.HealthCheck != nil {
			entry.CheckType = service.Spec.Operations.HealthCheck.Type
		}

		entries = []*pb.HealthHistoryEntry{entry}
	}

	return &pb.GetHealthHistoryResp{
		Package: req.Package,
		Entries: entries,
	}, nil
}

// convertToServiceHealth 转换为 ServiceHealth proto
func (s *HealthService) convertToServiceHealth(service *domain.Service, checkResult *domain.CheckResult) *pb.ServiceHealth {
	healthProto := &pb.ServiceHealth{
		Package:   service.Name,
		Status:    s.convertHealthStatus(checkResult),
		LastCheck: timestamppb.New(checkResult.Timestamp),
		Message:   checkResult.Message,
		Details:   make([]*pb.HealthStatusDetail, 0),
	}

	// 添加健康检查详情
	if service.Health != nil && len(service.Health.Details) > 0 {
		for _, detail := range service.Health.Details {
			detailProto := &pb.HealthStatusDetail{
				Status:         s.convertHealthStatusFromDomain(detail.Status),
				Message:        detail.Message,
				LastCheck:      timestamppb.New(detail.LastCheck),
				CheckType:      detail.CheckType,
				ResponseTimeMs: int64(detail.ResponseTime.Milliseconds()),
			}
			if detail.Error != nil {
				detailProto.Error = detail.Error.Error()
			}
			healthProto.Details = append(healthProto.Details, detailProto)
		}
	} else {
		// 如果没有详情，使用检查结果创建详情
		detailProto := &pb.HealthStatusDetail{
			Status:         s.convertHealthStatus(checkResult),
			Message:        checkResult.Message,
			LastCheck:      timestamppb.New(checkResult.Timestamp),
			ResponseTimeMs: int64(checkResult.ResponseTime.Milliseconds()),
		}
		if checkResult.Error != nil {
			detailProto.Error = checkResult.Error.Error()
		}
		// 确定检查类型
		if service.Spec != nil && service.Spec.Operations != nil && service.Spec.Operations.HealthCheck != nil {
			detailProto.CheckType = service.Spec.Operations.HealthCheck.Type
		}
		healthProto.Details = append(healthProto.Details, detailProto)
	}

	return healthProto
}

// convertHealthStatus 转换健康状态
func (s *HealthService) convertHealthStatus(checkResult *domain.CheckResult) pb.HealthStatus {
	if checkResult == nil {
		return pb.HealthStatus_HEALTH_STATUS_UNKNOWN
	}
	if checkResult.Healthy {
		return pb.HealthStatus_HEALTH_STATUS_HEALTHY
	}
	return pb.HealthStatus_HEALTH_STATUS_UNHEALTHY
}

// convertHealthStatusFromDomain 从 domain.HealthStatus 转换
func (s *HealthService) convertHealthStatusFromDomain(status domain.HealthStatus) pb.HealthStatus {
	switch status {
	case domain.HealthStatusHealthy:
		return pb.HealthStatus_HEALTH_STATUS_HEALTHY
	case domain.HealthStatusUnhealthy:
		return pb.HealthStatus_HEALTH_STATUS_UNHEALTHY
	case domain.HealthStatusDegraded:
		return pb.HealthStatus_HEALTH_STATUS_DEGRADED
	default:
		return pb.HealthStatus_HEALTH_STATUS_UNKNOWN
	}
}
