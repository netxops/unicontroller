package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pb"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"golang.org/x/sync/errgroup"
)

// BatchOperator 批量操作模块
type BatchOperator struct {
	agentManager *AgentManager
}

// NewBatchOperator 创建批量操作模块
func NewBatchOperator(agentManager *AgentManager) *BatchOperator {
	return &BatchOperator{
		agentManager: agentManager,
	}
}

// BatchStartPackages 批量启动服务
func (bo *BatchOperator) BatchStartPackages(ctx context.Context, req *models.BatchOperationRequest) (*models.BatchOperationResult, error) {
	return bo.batchOperation(ctx, req, "start")
}

// BatchStopPackages 批量停止服务
func (bo *BatchOperator) BatchStopPackages(ctx context.Context, req *models.BatchOperationRequest) (*models.BatchOperationResult, error) {
	return bo.batchOperation(ctx, req, "stop")
}

// BatchRestartPackages 批量重启服务
func (bo *BatchOperator) BatchRestartPackages(ctx context.Context, req *models.BatchOperationRequest) (*models.BatchOperationResult, error) {
	return bo.batchOperation(ctx, req, "restart")
}

// batchOperation 执行批量操作
func (bo *BatchOperator) batchOperation(ctx context.Context, req *models.BatchOperationRequest, operation string) (*models.BatchOperationResult, error) {
	startTime := time.Now()

	// 生成操作列表
	operations := bo.generateOperations(req)

	result := &models.BatchOperationResult{
		Total:   len(operations),
		Results: make([]models.OperationResult, 0, len(operations)),
	}

	// 使用 errgroup 并发执行
	g, gCtx := errgroup.WithContext(ctx)

	// 限制并发数（避免过多并发导致资源耗尽）
	sem := make(chan struct{}, 10) // 最多 10 个并发操作

	// 使用 channel 收集结果，保证线程安全
	resultChan := make(chan models.OperationResult, len(operations))

	for _, op := range operations {
		op := op          // 避免闭包问题
		sem <- struct{}{} // 获取信号量

		g.Go(func() error {
			defer func() { <-sem }() // 释放信号量

			var err error
			var message string

			switch operation {
			case "start":
				err = bo.agentManager.StartPackage(gCtx, op.AgentCode, op.Package)
				message = "Started successfully"
			case "stop":
				err = bo.agentManager.StopPackage(gCtx, op.AgentCode, op.Package)
				message = "Stopped successfully"
			case "restart":
				// 先停止
				if stopErr := bo.agentManager.StopPackage(gCtx, op.AgentCode, op.Package); stopErr != nil {
					err = fmt.Errorf("failed to stop: %w", stopErr)
					break
				}
				// 等待一下
				time.Sleep(500 * time.Millisecond)
				// 再启动
				if startErr := bo.agentManager.StartPackage(gCtx, op.AgentCode, op.Package); startErr != nil {
					err = fmt.Errorf("failed to start: %w", startErr)
					break
				}
				message = "Restarted successfully"
			default:
				err = fmt.Errorf("unknown operation: %s", operation)
			}

			opResult := models.OperationResult{
				AgentCode: op.AgentCode,
				Package:   op.Package,
				Success:   err == nil,
				Message:   message,
			}

			if err != nil {
				opResult.Error = err.Error()
				xlog.Warn("Batch operation failed",
					xlog.String("operation", operation),
					xlog.String("agent", op.AgentCode),
					xlog.String("package", op.Package),
					xlog.FieldErr(err))
			}

			// 发送结果到 channel
			resultChan <- opResult

			return nil // 不返回错误，让所有操作都执行完
		})
	}

	// 等待所有操作完成
	if err := g.Wait(); err != nil {
		xlog.Warn("Some batch operations failed", xlog.FieldErr(err))
	}
	close(resultChan)

	// 收集结果
	for opResult := range resultChan {
		result.Results = append(result.Results, opResult)
	}

	// 统计结果
	result.DurationMs = time.Since(startTime).Milliseconds()
	for _, r := range result.Results {
		if r.Success {
			result.Success++
		} else {
			result.Failed++
		}
	}

	return result, nil
}

// operationItem 操作项
type operationItem struct {
	AgentCode string
	Package   string
}

// generateOperations 生成操作列表
func (bo *BatchOperator) generateOperations(req *models.BatchOperationRequest) []operationItem {
	operations := make([]operationItem, 0)

	// 如果指定了 packages，则对每个 agent 的每个 package 执行操作
	if len(req.Packages) > 0 {
		for _, agentCode := range req.Agents {
			for _, pkg := range req.Packages {
				operations = append(operations, operationItem{
					AgentCode: agentCode,
					Package:   pkg,
				})
			}
		}
	} else {
		// 如果没有指定 packages，需要从每个 agent 获取服务列表
		// 这里简化处理，返回错误提示需要指定 packages
		// 或者可以从 agent 获取所有服务
		for _, agentCode := range req.Agents {
			// 获取 agent 的服务列表
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			packages, err := bo.agentManager.PackageList(ctx, agentCode)
			cancel()

			if err != nil {
				xlog.Warn("Failed to get packages for agent",
					xlog.String("agent", agentCode),
					xlog.FieldErr(err))
				continue
			}

			for _, pkg := range packages {
				operations = append(operations, operationItem{
					AgentCode: agentCode,
					Package:   pkg.Package,
				})
			}
		}
	}

	return operations
}

// BatchUpdateConfigs 批量更新配置
func (bo *BatchOperator) BatchUpdateConfigs(ctx context.Context, req *models.BatchConfigRequest) (*models.BatchOperationResult, error) {
	startTime := time.Now()

	result := &models.BatchOperationResult{
		Total:   len(req.Agents),
		Results: make([]models.OperationResult, 0, len(req.Agents)),
	}

	// 转换配置格式
	configs := make([]*pb.ConfigItem, 0, len(req.Configs))
	for _, cfg := range req.Configs {
		configs = append(configs, &pb.ConfigItem{
			FileName: cfg.FileName,
			Content:  cfg.Content,
		})
	}

	// 使用 errgroup 并发执行
	g, gCtx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, 10) // 限制并发数

	// 使用 channel 收集结果
	resultChan := make(chan models.OperationResult, len(req.Agents))

	for _, agentCode := range req.Agents {
		agentCode := agentCode // 避免闭包问题
		sem <- struct{}{}

		g.Go(func() error {
			defer func() { <-sem }()

			err := bo.agentManager.ApplyPackageConfigs(gCtx, agentCode, req.Package, configs)

			opResult := models.OperationResult{
				AgentCode: agentCode,
				Package:   req.Package,
				Success:   err == nil,
				Message:   "Config updated successfully",
			}

			if err != nil {
				opResult.Error = err.Error()
				xlog.Warn("Failed to update config",
					xlog.String("agent", agentCode),
					xlog.String("package", req.Package),
					xlog.FieldErr(err))
			}

			resultChan <- opResult
			return nil
		})
	}

	// 等待所有操作完成
	if err := g.Wait(); err != nil {
		xlog.Warn("Some batch config updates failed", xlog.FieldErr(err))
	}
	close(resultChan)

	// 收集结果
	for opResult := range resultChan {
		result.Results = append(result.Results, opResult)
	}

	// 统计结果
	result.DurationMs = time.Since(startTime).Milliseconds()
	for _, r := range result.Results {
		if r.Success {
			result.Success++
		} else {
			result.Failed++
		}
	}

	return result, nil
}
