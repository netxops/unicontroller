package service

import (
	"fmt"
	"sort"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/errors"
)

// DependencyManager 依赖管理器
type DependencyManager struct {
	registry *ServiceRegistry
}

// NewDependencyManager 创建依赖管理器
func NewDependencyManager(registry *ServiceRegistry) *DependencyManager {
	return &DependencyManager{
		registry: registry,
	}
}

// ResolveDependencies 解析依赖关系，返回按依赖顺序排序的服务列表
func (d *DependencyManager) ResolveDependencies(serviceIDs []string) ([]string, error) {
	// 构建依赖图（使用服务 ID）
	graph := make(map[string][]string)
	services := make(map[string]*domain.Service)

	for _, serviceID := range serviceIDs {
		service, exists := d.registry.Get(serviceID)
		if !exists {
			return nil, errors.NewError(errors.ErrCodeServiceNotFound, fmt.Sprintf("service %s not found", serviceID))
		}
		services[serviceID] = service

		// 将依赖名称转换为服务 ID
		depIDs := make([]string, 0)
		if service.Spec.Operations != nil {
			for _, depName := range service.Spec.Operations.Dependencies {
				depService, exists := d.registry.GetByName(depName)
				if !exists {
					return nil, errors.NewError(
						errors.ErrCodeServiceNotFound,
						fmt.Sprintf("dependency service %s not found for service %s", depName, service.Name),
					)
				}
				depIDs = append(depIDs, depService.ID)
			}
		}
		graph[serviceID] = depIDs
	}

	// 拓扑排序
	sorted, err := d.topologicalSort(graph)
	if err != nil {
		return nil, errors.WrapError(errors.ErrCodeInternal, "failed to resolve dependencies", err)
	}

	return sorted, nil
}

// topologicalSort 拓扑排序
func (d *DependencyManager) topologicalSort(graph map[string][]string) ([]string, error) {
	// 构建反向图：reverseGraph[dep] = [nodes that depend on dep]
	// 这样我们可以快速找到哪些节点依赖于某个节点
	reverseGraph := make(map[string][]string)
	inDegree := make(map[string]int)

	// 初始化所有节点的入度为 0
	for node := range graph {
		inDegree[node] = 0
		reverseGraph[node] = make([]string, 0)
	}

	// 构建反向图和计算入度
	// graph[node] = deps 表示 node 依赖于 deps 中的服务
	// 所以对于每个 dep，node 是依赖于它的节点
	for node, deps := range graph {
		// node 依赖于 deps 中的服务，所以 node 的入度等于它依赖的服务数量
		inDegree[node] = len(deps)
		// 构建反向图：dep 被 node 依赖
		for _, dep := range deps {
			reverseGraph[dep] = append(reverseGraph[dep], node)
		}
	}

	// 找到所有入度为 0 的节点（没有依赖的服务）
	queue := make([]string, 0)
	for node, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, node)
		}
	}

	result := make([]string, 0)
	for len(queue) > 0 {
		// 排序以保证确定性
		sort.Strings(queue)
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)

		// 找到所有依赖 node 的服务，减少它们的入度
		for _, dependent := range reverseGraph[node] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	// 检查是否有循环依赖
	if len(result) != len(graph) {
		// 找出未处理的节点（这些节点在循环中）
		processed := make(map[string]bool)
		for _, node := range result {
			processed[node] = true
		}
		circularNodes := make([]string, 0)
		for node := range graph {
			if !processed[node] {
				circularNodes = append(circularNodes, node)
			}
		}
		return nil, fmt.Errorf("circular dependency detected involving services: %v", circularNodes)
	}

	return result, nil
}

// ValidateDependencies 验证依赖是否存在
func (d *DependencyManager) ValidateDependencies(service *domain.Service) error {
	if service.Spec.Operations == nil {
		return nil
	}

	for _, depName := range service.Spec.Operations.Dependencies {
		_, exists := d.registry.GetByName(depName)
		if !exists {
			return errors.NewError(errors.ErrCodeServiceNotFound, fmt.Sprintf("dependency service %s not found", depName))
		}
	}

	return nil
}

// GetDependents 获取依赖此服务的其他服务
func (d *DependencyManager) GetDependents(serviceID string) []*domain.Service {
	// 获取服务信息以获取名称
	service, exists := d.registry.Get(serviceID)
	if !exists {
		return []*domain.Service{}
	}

	dependents := make([]*domain.Service, 0)
	services := d.registry.List()
	for _, svc := range services {
		if svc.Spec.Operations != nil {
			for _, depName := range svc.Spec.Operations.Dependencies {
				// 依赖存储的是服务名称，需要与当前服务的名称比较
				if depName == service.Name {
					dependents = append(dependents, svc)
					break
				}
			}
		}
	}

	return dependents
}
