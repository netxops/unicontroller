package controller

import (
	"context"
	"fmt"

	"github.com/influxdata/telegraf/controller/pb"
	"google.golang.org/grpc/metadata"
)

// HealthMonitor 健康监控模块
type HealthMonitor struct {
	agentManager *AgentManager
}

// NewHealthMonitor 创建健康监控模块
func NewHealthMonitor(agentManager *AgentManager) *HealthMonitor {
	return &HealthMonitor{
		agentManager: agentManager,
	}
}

// GetServiceHealth 获取指定服务的健康状态
func (hm *HealthMonitor) GetServiceHealth(ctx context.Context, agentCode, packageName string) (*pb.ServiceHealth, error) {
	conn, err := hm.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewHealthClient(conn)
	resp, err := client.GetHealthStatus(ctx, &pb.GetHealthStatusReq{
		Package: packageName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get health status: %w", err)
	}

	return resp.Health, nil
}

// ListAgentHealth 获取 Agent 所有服务的健康状态
func (hm *HealthMonitor) ListAgentHealth(ctx context.Context, agentCode string, filterStatus []pb.HealthStatus) ([]*pb.ServiceHealth, error) {
	conn, err := hm.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewHealthClient(conn)
	req := &pb.ListHealthStatusesReq{}
	if len(filterStatus) > 0 {
		req.FilterStatus = filterStatus
	}

	resp, err := client.ListHealthStatuses(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list health statuses: %w", err)
	}

	return resp.HealthStatuses, nil
}

// GetHealthHistory 获取服务的健康检查历史
func (hm *HealthMonitor) GetHealthHistory(ctx context.Context, agentCode, packageName string, limit int32) ([]*pb.HealthHistoryEntry, error) {
	conn, err := hm.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewHealthClient(conn)
	if limit <= 0 {
		limit = 100 // 默认 100 条
	}

	resp, err := client.GetHealthHistory(ctx, &pb.GetHealthHistoryReq{
		Package: packageName,
		Limit:   limit,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get health history: %w", err)
	}

	return resp.Entries, nil
}

// GetAgentOverallHealth 获取 Agent 整体健康状态
func (hm *HealthMonitor) GetAgentOverallHealth(ctx context.Context, agentCode string) (map[string]interface{}, error) {
	healthStatuses, err := hm.ListAgentHealth(ctx, agentCode, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list agent health: %w", err)
	}

	// 统计健康状态
	healthyCount := 0
	unhealthyCount := 0
	degradedCount := 0
	unknownCount := 0

	for _, health := range healthStatuses {
		switch health.Status {
		case pb.HealthStatus_HEALTH_STATUS_HEALTHY:
			healthyCount++
		case pb.HealthStatus_HEALTH_STATUS_UNHEALTHY:
			unhealthyCount++
		case pb.HealthStatus_HEALTH_STATUS_DEGRADED:
			degradedCount++
		default:
			unknownCount++
		}
	}

	// 判断整体健康状态
	overallStatus := pb.HealthStatus_HEALTH_STATUS_HEALTHY
	if unhealthyCount > 0 {
		overallStatus = pb.HealthStatus_HEALTH_STATUS_UNHEALTHY
	} else if degradedCount > 0 {
		overallStatus = pb.HealthStatus_HEALTH_STATUS_DEGRADED
	}

	return map[string]interface{}{
		"overall_status": overallStatus.String(),
		"total_services": len(healthStatuses),
		"healthy":        healthyCount,
		"unhealthy":      unhealthyCount,
		"degraded":       degradedCount,
		"unknown":        unknownCount,
		"services":       healthStatuses,
	}, nil
}
