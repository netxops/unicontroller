package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pb"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MetricsQuery 指标查询模块
type MetricsQuery struct {
	agentManager *AgentManager
}

// NewMetricsQuery 创建指标查询模块
func NewMetricsQuery(agentManager *AgentManager) *MetricsQuery {
	return &MetricsQuery{
		agentManager: agentManager,
	}
}

// GetSystemMetrics 获取系统指标
func (mq *MetricsQuery) GetSystemMetrics(ctx context.Context, agentCode string) (*pb.SystemMetrics, error) {
	conn, err := mq.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewMetricsClient(conn)
	resp, err := client.GetSystemMetrics(ctx, &pb.GetSystemMetricsReq{})
	if err != nil {
		return nil, fmt.Errorf("failed to get system metrics: %w", err)
	}

	return resp.Metrics, nil
}

// GetServiceMetrics 获取指定服务的指标
func (mq *MetricsQuery) GetServiceMetrics(ctx context.Context, agentCode, packageName string) (*pb.ServiceMetrics, error) {
	conn, err := mq.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewMetricsClient(conn)
	resp, err := client.GetServiceMetrics(ctx, &pb.GetServiceMetricsReq{
		Package: packageName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get service metrics: %w", err)
	}

	return resp.Metrics, nil
}

// ListServiceMetrics 获取 Agent 所有服务的指标
func (mq *MetricsQuery) ListServiceMetrics(ctx context.Context, agentCode string, runningOnly bool) ([]*pb.ServiceMetrics, error) {
	conn, err := mq.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewMetricsClient(conn)
	resp, err := client.ListServiceMetrics(ctx, &pb.ListServiceMetricsReq{
		RunningOnly: runningOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list service metrics: %w", err)
	}

	return resp.Metrics, nil
}

// GetAgentMetricsSummary 获取 Agent 指标摘要
func (mq *MetricsQuery) GetAgentMetricsSummary(ctx context.Context, agentCode string) (map[string]interface{}, error) {
	// 获取系统指标
	systemMetrics, err := mq.GetSystemMetrics(ctx, agentCode)
	if err != nil {
		xlog.Warn("Failed to get system metrics",
			xlog.String("agent", agentCode),
			xlog.FieldErr(err))
	}

	// 获取所有服务指标
	serviceMetrics, err := mq.ListServiceMetrics(ctx, agentCode, false)
	if err != nil {
		xlog.Warn("Failed to list service metrics",
			xlog.String("agent", agentCode),
			xlog.FieldErr(err))
		serviceMetrics = []*pb.ServiceMetrics{}
	}

	// 计算服务指标汇总
	var totalCPUUsage float64
	var totalMemoryBytes int64
	var totalRequestCount int64
	var totalErrorCount int64

	for _, metrics := range serviceMetrics {
		totalCPUUsage += metrics.CpuUsage
		totalMemoryBytes += metrics.MemoryBytes
		totalRequestCount += metrics.RequestCount
		totalErrorCount += metrics.ErrorCount
	}

	summary := map[string]interface{}{
		"system_metrics": systemMetrics,
		"service_count":  len(serviceMetrics),
		"services":       serviceMetrics,
		"summary": map[string]interface{}{
			"total_cpu_usage":    totalCPUUsage,
			"total_memory_bytes": totalMemoryBytes,
			"total_requests":     totalRequestCount,
			"total_errors":       totalErrorCount,
		},
	}

	return summary, nil
}

// GetApplicationMetrics 获取应用指标
func (mq *MetricsQuery) GetApplicationMetrics(ctx context.Context, agentCode, serviceName string) (map[string]interface{}, error) {
	conn, err := mq.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewMetricsClient(conn)
	resp, err := client.GetApplicationMetrics(ctx, &pb.GetApplicationMetricsReq{
		ServiceName: serviceName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get application metrics: %w", err)
	}

	result := make(map[string]interface{})
	if serviceName != "" && resp.Metrics != nil {
		result[serviceName] = resp.Metrics
	} else {
		for svcName, metrics := range resp.Services {
			result[svcName] = metrics
		}
	}

	return result, nil
}

// GetMetricsHistory 获取指标历史数据
func (mq *MetricsQuery) GetMetricsHistory(ctx context.Context, agentCode, metricType, serviceName string, startTime, endTime time.Time) (map[string]interface{}, error) {
	conn, err := mq.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewMetricsClient(conn)

	req := &pb.GetMetricsHistoryReq{
		Type:        metricType,
		ServiceName: serviceName,
	}

	if !startTime.IsZero() {
		req.StartTime = timestamppb.New(startTime)
	}
	if !endTime.IsZero() {
		req.EndTime = timestamppb.New(endTime)
	}

	resp, err := client.GetMetricsHistory(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics history: %w", err)
	}

	// 转换为 map
	result := map[string]interface{}{
		"type":         resp.Type,
		"service_name": resp.ServiceName,
		"data_points":  resp.DataPoints,
	}
	if resp.StartTime != nil {
		result["start_time"] = resp.StartTime.AsTime().Format(time.RFC3339)
	}
	if resp.EndTime != nil {
		result["end_time"] = resp.EndTime.AsTime().Format(time.RFC3339)
	}
	return result, nil
}
