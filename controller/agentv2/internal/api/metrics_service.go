package api

import (
	"context"
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/metrics"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"github.com/influxdata/telegraf/controller/pb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MetricsService 指标服务
type MetricsService struct {
	pb.UnimplementedMetricsServer
	metricsCollector     metrics.MetricsCollector
	applicationCollector *metrics.ApplicationMetricsCollector
	serviceManager       service.ServiceManager
	logger               *zap.Logger
}

// NewMetricsService 创建指标服务
func NewMetricsService(
	metricsCollector metrics.MetricsCollector,
	applicationCollector *metrics.ApplicationMetricsCollector,
	serviceManager service.ServiceManager,
	logger *zap.Logger,
) *MetricsService {
	return &MetricsService{
		metricsCollector:     metricsCollector,
		applicationCollector: applicationCollector,
		serviceManager:       serviceManager,
		logger:               logger,
	}
}

// GetSystemMetrics 获取系统指标
func (s *MetricsService) GetSystemMetrics(ctx context.Context, req *pb.GetSystemMetricsReq) (*pb.GetSystemMetricsResp, error) {
	s.logger.Info("Received GetSystemMetrics request")

	systemMetrics := s.metricsCollector.GetSystemMetrics()
	if systemMetrics == nil {
		return nil, status.Errorf(codes.NotFound, "system metrics not available")
	}

	// 转换为 proto 格式
	metricsProto := s.convertSystemMetrics(systemMetrics)

	return &pb.GetSystemMetricsResp{
		Metrics: metricsProto,
	}, nil
}

// GetServiceMetrics 获取指定服务的指标
func (s *MetricsService) GetServiceMetrics(ctx context.Context, req *pb.GetServiceMetricsReq) (*pb.GetServiceMetricsResp, error) {
	if req == nil || req.Package == "" {
		return nil, status.Errorf(codes.InvalidArgument, "package name cannot be empty")
	}

	s.logger.Info("Received GetServiceMetrics request", zap.String("package", req.Package))

	serviceMetrics, exists := s.metricsCollector.GetServiceMetrics(req.Package)
	if !exists {
		return nil, status.Errorf(codes.NotFound, "metrics for service %s not found", req.Package)
	}

	// 转换为 proto 格式
	metricsProto := s.convertServiceMetrics(req.Package, serviceMetrics)

	return &pb.GetServiceMetricsResp{
		Metrics: metricsProto,
	}, nil
}

// ListServiceMetrics 列出所有服务的指标
func (s *MetricsService) ListServiceMetrics(ctx context.Context, req *pb.ListServiceMetricsReq) (*pb.ListServiceMetricsResp, error) {
	runningOnly := false
	if req != nil {
		runningOnly = req.RunningOnly
	}

	s.logger.Info("Received ListServiceMetrics request", zap.Bool("running_only", runningOnly))

	// 获取所有服务
	services, err := s.serviceManager.ListServices(ctx)
	if err != nil {
		s.logger.Error("Failed to list services", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to list services: %v", err)
	}

	metricsList := make([]*pb.ServiceMetrics, 0)
	for _, service := range services {
		// 如果只返回运行中的服务，跳过未运行的服务
		if runningOnly && !service.IsRunning() {
			continue
		}

		// 获取服务指标
		serviceMetrics, exists := s.metricsCollector.GetServiceMetrics(service.ID)
		if !exists {
			// 如果指标不存在，创建一个空指标
			serviceMetrics = &domain.ServiceMetrics{}
		}

		// 转换为 proto 格式
		metricsProto := s.convertServiceMetrics(service.Name, serviceMetrics)
		metricsList = append(metricsList, metricsProto)
	}

	return &pb.ListServiceMetricsResp{
		Metrics: metricsList,
	}, nil
}

// convertSystemMetrics 转换系统指标
func (s *MetricsService) convertSystemMetrics(metrics interface{}) *pb.SystemMetrics {
	// 从 domain.SystemMetrics 转换
	domainMetrics, ok := metrics.(*domain.SystemMetrics)
	if !ok || domainMetrics == nil {
		return &pb.SystemMetrics{
			LastUpdated: timestamppb.Now(),
		}
	}

	// 转换网络接口
	networkInterfaces := make([]*pb.NetworkInterface, 0, len(domainMetrics.NetworkInterfaces))
	for _, iface := range domainMetrics.NetworkInterfaces {
		networkInterfaces = append(networkInterfaces, &pb.NetworkInterface{
			Name:    iface.Name,
			RxBytes: iface.RxBytes,
			TxBytes: iface.TxBytes,
		})
	}

	return &pb.SystemMetrics{
		CpuUsage:          domainMetrics.CPUUsage,
		CpuCores:          int32(domainMetrics.CPUCores),
		MemoryUsage:       domainMetrics.MemoryUsage,
		MemoryTotal:       domainMetrics.MemoryTotal,
		MemoryFree:        domainMetrics.MemoryFree,
		DiskUsage:         domainMetrics.DiskUsage,
		DiskTotal:         domainMetrics.DiskTotal,
		DiskFree:          domainMetrics.DiskFree,
		NetworkIn:         domainMetrics.NetworkIn,
		NetworkOut:        domainMetrics.NetworkOut,
		NetworkInterfaces: networkInterfaces,
		LoadAvg_1:         domainMetrics.LoadAvg1,
		LoadAvg_5:         domainMetrics.LoadAvg5,
		LoadAvg_15:        domainMetrics.LoadAvg15,
		LastUpdated:       timestamppb.New(domainMetrics.LastUpdated),
	}
}

// convertServiceMetrics 转换服务指标
func (s *MetricsService) convertServiceMetrics(packageName string, metrics interface{}) *pb.ServiceMetrics {
	// 从 domain.ServiceMetrics 转换
	domainMetrics, ok := metrics.(*domain.ServiceMetrics)
	if !ok || domainMetrics == nil {
		return &pb.ServiceMetrics{
			Package:     packageName,
			LastUpdated: timestamppb.Now(),
		}
	}

	return &pb.ServiceMetrics{
		Package:        packageName,
		CpuUsage:       domainMetrics.CPUUsage,
		MemoryUsage:    domainMetrics.MemoryUsage,
		MemoryBytes:    domainMetrics.MemoryBytes,
		DiskUsage:      domainMetrics.DiskUsage,
		NetworkIn:      domainMetrics.NetworkIn,
		NetworkOut:     domainMetrics.NetworkOut,
		RequestCount:   domainMetrics.RequestCount,
		ErrorCount:     domainMetrics.ErrorCount,
		ResponseTimeMs: int64(domainMetrics.ResponseTime.Milliseconds()),
		LastUpdated:    timestamppb.New(domainMetrics.LastUpdated),
	}
}

// GetApplicationMetrics 获取应用指标
func (s *MetricsService) GetApplicationMetrics(ctx context.Context, req *pb.GetApplicationMetricsReq) (*pb.GetApplicationMetricsResp, error) {
	s.logger.Info("Received GetApplicationMetrics request", zap.String("service_name", req.ServiceName))

	if s.applicationCollector == nil {
		return nil, status.Errorf(codes.Unimplemented, "application metrics collector not available")
	}

	resp := &pb.GetApplicationMetricsResp{
		Services: make(map[string]*pb.ApplicationMetrics),
	}

	if req.ServiceName != "" {
		// 获取单个服务的应用指标
		appMetrics, exists := s.applicationCollector.GetApplicationMetrics(req.ServiceName)
		if !exists {
			return nil, status.Errorf(codes.NotFound, "application metrics for service %s not found", req.ServiceName)
		}

		resp.Metrics = s.convertApplicationMetrics(appMetrics)
	} else {
		// 获取所有服务的应用指标
		allMetrics := s.applicationCollector.GetAllApplicationMetrics()
		for serviceName, appMetrics := range allMetrics {
			resp.Services[serviceName] = s.convertApplicationMetrics(appMetrics)
		}
	}

	return resp, nil
}

// GetMetricsHistory 获取指标历史数据
func (s *MetricsService) GetMetricsHistory(ctx context.Context, req *pb.GetMetricsHistoryReq) (*pb.GetMetricsHistoryResp, error) {
	s.logger.Info("Received GetMetricsHistory request",
		zap.String("type", req.Type),
		zap.String("service_name", req.ServiceName))

	// 获取历史缓存（通过类型断言）
	var historyCache *metrics.MetricsHistoryCache
	if collector, ok := s.metricsCollector.(interface {
		GetHistoryCache() *metrics.MetricsHistoryCache
	}); ok {
		historyCache = collector.GetHistoryCache()
	}
	if historyCache == nil {
		return nil, status.Errorf(codes.Unimplemented, "metrics history cache not available")
	}

	var startTime, endTime time.Time
	if req.StartTime != nil {
		startTime = req.StartTime.AsTime()
	}
	if req.EndTime != nil {
		endTime = req.EndTime.AsTime()
	}

	resp := &pb.GetMetricsHistoryResp{
		Type:        req.Type,
		ServiceName: req.ServiceName,
		StartTime:   req.StartTime,
		EndTime:     req.EndTime,
		DataPoints:  make([]*pb.MetricsHistoryPoint, 0),
	}

	if req.Type == "system" {
		// 获取系统指标历史
		points := historyCache.GetSystemMetricsHistory(startTime, endTime)
		for _, point := range points {
			metricsJSON := s.marshalSystemMetrics(point.Metrics)
			resp.DataPoints = append(resp.DataPoints, &pb.MetricsHistoryPoint{
				Timestamp: timestamppb.New(point.Timestamp),
				Metrics:   metricsJSON,
			})
		}
	} else if req.Type == "service" {
		if req.ServiceName == "" {
			return nil, status.Errorf(codes.InvalidArgument, "service_name is required for service metrics history")
		}
		// 获取服务指标历史
		points := historyCache.GetServiceMetricsHistory(req.ServiceName, startTime, endTime)
		for _, point := range points {
			metricsJSON := s.marshalServiceMetrics(point.Metrics)
			resp.DataPoints = append(resp.DataPoints, &pb.MetricsHistoryPoint{
				Timestamp: timestamppb.New(point.Timestamp),
				Metrics:   metricsJSON,
			})
		}
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "invalid type: %s, must be 'system' or 'service'", req.Type)
	}

	return resp, nil
}

// convertApplicationMetrics 转换应用指标
func (s *MetricsService) convertApplicationMetrics(metrics *domain.ApplicationMetrics) *pb.ApplicationMetrics {
	if metrics == nil {
		return &pb.ApplicationMetrics{
			Timestamp: timestamppb.Now(),
		}
	}

	return &pb.ApplicationMetrics{
		ServiceName: metrics.ServiceName,
		Metrics:     metrics.Metrics,
		Labels:      metrics.Labels,
		Timestamp:   timestamppb.New(metrics.Timestamp),
	}
}

// marshalSystemMetrics 将系统指标序列化为 JSON 字符串
func (s *MetricsService) marshalSystemMetrics(metrics *domain.SystemMetrics) map[string]string {
	if metrics == nil {
		return make(map[string]string)
	}

	// 将指标转换为 JSON 字符串格式
	result := make(map[string]string)
	result["cpu_usage"] = fmt.Sprintf("%.2f", metrics.CPUUsage)
	result["memory_usage"] = fmt.Sprintf("%.2f", metrics.MemoryUsage)
	result["memory_total"] = fmt.Sprintf("%d", metrics.MemoryTotal)
	result["memory_free"] = fmt.Sprintf("%d", metrics.MemoryFree)
	result["disk_usage"] = fmt.Sprintf("%.2f", metrics.DiskUsage)
	result["disk_total"] = fmt.Sprintf("%d", metrics.DiskTotal)
	result["disk_free"] = fmt.Sprintf("%d", metrics.DiskFree)
	result["network_in"] = fmt.Sprintf("%d", metrics.NetworkIn)
	result["network_out"] = fmt.Sprintf("%d", metrics.NetworkOut)
	result["load_avg_1"] = fmt.Sprintf("%.2f", metrics.LoadAvg1)
	result["load_avg_5"] = fmt.Sprintf("%.2f", metrics.LoadAvg5)
	result["load_avg_15"] = fmt.Sprintf("%.2f", metrics.LoadAvg15)

	return result
}

// marshalServiceMetrics 将服务指标序列化为 JSON 字符串
func (s *MetricsService) marshalServiceMetrics(metrics *domain.ServiceMetrics) map[string]string {
	if metrics == nil {
		return make(map[string]string)
	}

	result := make(map[string]string)
	result["cpu_usage"] = fmt.Sprintf("%.2f", metrics.CPUUsage)
	result["memory_usage"] = fmt.Sprintf("%.2f", metrics.MemoryUsage)
	result["memory_bytes"] = fmt.Sprintf("%d", metrics.MemoryBytes)
	result["disk_usage"] = fmt.Sprintf("%.2f", metrics.DiskUsage)
	result["network_in"] = fmt.Sprintf("%d", metrics.NetworkIn)
	result["network_out"] = fmt.Sprintf("%d", metrics.NetworkOut)
	result["request_count"] = fmt.Sprintf("%d", metrics.RequestCount)
	result["error_count"] = fmt.Sprintf("%d", metrics.ErrorCount)
	result["response_time_ms"] = fmt.Sprintf("%d", metrics.ResponseTime.Milliseconds())

	return result
}
