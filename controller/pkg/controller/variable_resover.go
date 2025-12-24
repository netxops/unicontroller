package controller

import (
	"context"
	"strings"
)

type LayerResolver interface {
	Resolve(ctx context.Context, agentID, appID string) (map[string]string, error)
}

type LayeredVariableResolver struct {
	layers []LayerResolver
}

func NewLayeredVariableResolver(rm *RegistryManager, cm *ConfigManager) *LayeredVariableResolver {
	return &LayeredVariableResolver{
		layers: []LayerResolver{
			&GlobalResolver{ConfigManager: cm},
			// &AgentResolver{RegistryManager: rm},
			&AppResolver{ConfigManager: cm},
			// 添加其他层级的 Resolver...
		},
	}
}

// func (lvr *LayeredVariableResolver) Resolve(ctx context.Context, agentID, appID string) (map[string]string, error) {
// 	result := make(map[string]string)
// 	for _, layer := range lvr.layers {
// 		layerVars, err := layer.Resolve(ctx, agentID, appID)
// 		if err != nil {
// 			return nil, err
// 		}
// 		// 合并变量，后面的层级会覆盖前面的
// 		for k, v := range layerVars {
// 			result[k] = v
// 		}
// 	}
// 	return result, nil
// }

type GlobalResolver struct {
	ConfigManager *ConfigManager
}

func ProvideGlobalResolver(cm *ConfigManager) *GlobalResolver {
	return &GlobalResolver{ConfigManager: cm}
}

func (gr *GlobalResolver) Resolve(ctx context.Context, agentID, appID string) (map[string]string, error) {
	// 实现全局变量的解析逻辑
	return gr.ConfigManager.GetGlobalVariables()
}


type AppResolver struct {
	ConfigManager *ConfigManager
}

func (ar *AppResolver) Resolve(ctx context.Context, agentID, appID string) (map[string]string, error) {
	appVars, err := ar.ConfigManager.GetAppVariables(appID)
	if err != nil {
		return nil, err
	}

	// 特殊处理 runtime_vars
	if runtimeVarsStr, ok := appVars["runtime_vars"]; ok {
		runtimeVars := strings.Split(runtimeVarsStr, ",")
		for _, v := range runtimeVars {
			appVars[v] = "" // 设置为空字符串，后续可能需要从其他地方获取实际值
		}
		delete(appVars, "runtime_vars") // 删除原始的 runtime_vars 键
	}

	return appVars, nil
}

func (lvr *LayeredVariableResolver) Resolve(ctx context.Context, agentID, appID string) (map[string]string, error) {
	result := make(map[string]string)
	for _, layer := range lvr.layers {
		layerVars, err := layer.Resolve(ctx, agentID, appID)
		if err != nil {
			return nil, err
		}
		// 合并变量，后面的层级会覆盖前面的
		for k, v := range layerVars {
			result[k] = v
		}
	}

	// // 处理 runtime_vars
	// if appVars, err := lvr.layers[1].Resolve(ctx, agentID, appID); err == nil {
	// 	for k, v := range appVars {
	// 		if v == "" {
	// 			// 这里可以添加逻辑来获取 runtime_vars 的实际值
	// 			// 例如：result[k] = getActualRuntimeValue(k)
	// 		}
	// 	}
	// }

	return result, nil
}
