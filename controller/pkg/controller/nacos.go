package controller

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nacos-group/nacos-sdk-go/v2/clients"
	"github.com/nacos-group/nacos-sdk-go/v2/clients/config_client"
	"github.com/nacos-group/nacos-sdk-go/v2/common/constant"
	"github.com/nacos-group/nacos-sdk-go/v2/vo"
)

var ErrNacosConfigNotFound = errors.New("nacos config not found")

type NacosManager struct {
	client    config_client.IConfigClient
	namespace string
	cache     sync.Map
}

func ProvideNacosManager(config *Config) (*NacosManager, error) {
	// 创建clientConfig

	clientConfig := constant.ClientConfig{
		NamespaceId:         config.Nacos.Namespace,
		TimeoutMs:           5000,
		NotLoadCacheAtStart: true,
		LogDir:              config.Nacos.LogDir,
		CacheDir:            config.Nacos.CacheDir,
		LogLevel:            config.Nacos.LogLevel,
		Username:            config.Nacos.Username,
		Password:            config.Nacos.Password,
	}

	// 创建serverConfig
	serverConfigs := []constant.ServerConfig{
		{
			IpAddr: config.Nacos.Server,
			Port:   uint64(config.Nacos.Port),
		},
	}

	// 创建动态配置客户端
	configClient, err := clients.CreateConfigClient(map[string]interface{}{
		"serverConfigs": serverConfigs,
		"clientConfig":  clientConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("create config client error: %v", err)
	}

	return &NacosManager{
		client:    configClient,
		namespace: config.Nacos.Namespace,
	}, nil
}

func (nm *NacosManager) GetConfig(dataId, group string) (string, error) {
	content, err := nm.client.GetConfig(vo.ConfigParam{
		DataId: dataId,
		Group:  group,
	})
	if err != nil {
		if strings.Contains(err.Error(), "config not found") {
			return "", ErrNacosConfigNotFound
		}
		return "", err
	}
	return content, nil
}

func (nm *NacosManager) SetConfig(dataId, group, content string) error {
	success, err := nm.client.PublishConfig(vo.ConfigParam{
		DataId:  dataId,
		Group:   group,
		Content: content,
	})
	if err != nil {
		return err
	}
	if !success {
		return fmt.Errorf("failed to publish config")
	}

	nm.cache.Store(dataId+group, content)
	return nil
}
func (nm *NacosManager) DeleteConfig(dataId, group string) error {
	success, err := nm.client.DeleteConfig(vo.ConfigParam{
		DataId: dataId,
		Group:  group,
	})
	if err != nil {
		return err
	}
	if !success {
		return fmt.Errorf("failed to delete config")
	}

	nm.cache.Delete(dataId + group)
	return nil
}

func (nm *NacosManager) ListenConfig(dataId, group string, onChange func(string)) error {
	return nm.client.ListenConfig(vo.ConfigParam{
		DataId: dataId,
		Group:  group,
		OnChange: func(namespace, group, dataId, data string) {
			nm.cache.Store(dataId+group, data)
			onChange(data)
		},
	})
}

func (nm *NacosManager) BatchGetConfig(params []vo.ConfigParam) (map[string]string, error) {
	result := make(map[string]string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make(chan error, len(params))

	for _, param := range params {
		wg.Add(1)
		go func(p vo.ConfigParam) {
			defer wg.Done()
			content, err := nm.GetConfig(p.DataId, p.Group)
			if err != nil {
				errors <- err
				return
			}
			mu.Lock()
			result[p.DataId+p.Group] = content
			mu.Unlock()
		}(param)
	}

	wg.Wait()
	close(errors)

	if len(errors) > 0 {
		return nil, <-errors
	}

	return result, nil
}

func (nm *NacosManager) BatchSetConfig(configs map[string]vo.ConfigParam) error {
	var wg sync.WaitGroup
	errors := make(chan error, len(configs))

	for _, config := range configs {
		wg.Add(1)
		go func(c vo.ConfigParam) {
			defer wg.Done()
			if err := nm.SetConfig(c.DataId, c.Group, c.Content); err != nil {
				errors <- err
			}
		}(config)
	}

	wg.Wait()
	close(errors)

	if len(errors) > 0 {
		return <-errors
	}

	return nil
}

func (nm *NacosManager) GetConfigWithRetry(dataId, group string, maxRetries int) (string, error) {
	var content string
	var err error

	for i := 0; i < maxRetries; i++ {
		content, err = nm.GetConfig(dataId, group)
		if err == nil {
			return content, nil
		}
		time.Sleep(time.Second * time.Duration(i+1))
	}

	return "", fmt.Errorf("failed to get config after %d retries: %v", maxRetries, err)
}
