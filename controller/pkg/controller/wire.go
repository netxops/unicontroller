//go:build wireinject
// +build wireinject

package controller

import (
	"github.com/google/wire"
)

// ProviderSet 是一个 Wire 提供者集合，包含了所有控制器组件的提供者
var ProviderSet = wire.NewSet(
	ProvideKeyManager,
	ProvideAgentManager,
	ProvideMinioManager,
	ProvideResourceManager,
	ProvideConfigManager,
	ProvideRegistryManager,
	ProvideEtcdClient,
	ProvideConfig,
	ProvideController,
	ProvideDeployManager,
	ProvideDBClient,
	ProvideJumperServerManager,
	ProvideGrpcProxyManager,
	ProvideLokiForwarder,
	ProvidePrometheusForwarder,
	ProvidePluginTemplateService,
	ProvideTelegrafConfigGenerator,
	ProvideTelegrafManager,
	ProvideMonitoringService,
	ProvideNacosManager,
	ProvideRedisManager,
)

// InitializeControllerComponents 初始化所有控制器组件
func InitializeControllerComponents(configPath string) (*Controller, error) {
	wire.Build(
		ProviderSet,
	)
	return nil, nil
}
