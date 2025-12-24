package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/tidwall/gjson"
)

const DefaultTelegrafResourceName = "telegraf"

var TelegrafContainerName = ""

type TelegrafManager struct {
	Config          *Config
	ResourceManager *ResourceManager
	RegistryManager *RegistryManager
	ConfigManager   *ConfigManager
	KeyManager      *KeyManager
	ConfigGenerator *TelegrafConfigGenerator
	ctx             context.Context
	cancel          context.CancelFunc
	tempConfigPath  string
	serviceInfo     *models.ServiceInfo
	configVersion   string
	lastReloadTime  *time.Time
}

func ProvideTelegrafManager(rm *ResourceManager, cm *ConfigManager, registry *RegistryManager, km *KeyManager, config *Config, configGen *TelegrafConfigGenerator) (*TelegrafManager, error) {
	// 检查配置是否启用TelegrafManager
	// 如果enable字段为nil（未设置），默认为true（向后兼容）
	// 如果enable字段明确设置为false，则禁用
	enable := true
	if config != nil && config.Telegraf.Enable != nil {
		enable = *config.Telegraf.Enable
	}

	// 如果禁用，返回nil
	if !enable {
		return nil, nil
	}

	return &TelegrafManager{
		ResourceManager: rm,
		ConfigManager:   cm,
		RegistryManager: registry,
		KeyManager:      km,
		Config:          config,
		ConfigGenerator: configGen,
	}, nil
}

func (tm *TelegrafManager) GetStatus() map[string]interface{} {
	status := make(map[string]interface{})

	// 获取Telegraf运行状态
	telegrafStatus, err := tm.GetTelegrafStatus()
	if err != nil {
		status["status_error"] = fmt.Sprintf("Failed to get Telegraf status: %v", err)
	} else {
		status["status"] = telegrafStatus
	}

	// 获取Telegraf配置
	config, err := tm.GetConfig()
	if err != nil {
		status["config_error"] = fmt.Sprintf("Failed to get Telegraf config: %v", err)
	} else {
		status["config"] = config
	}

	// 获取容器名称
	status["container_name"] = TelegrafContainerName

	// 获取临时配置文件路径
	status["temp_config_path"] = tm.tempConfigPath

	// 检查Telegraf健康状态
	isHealthy, err := tm.checkTelegrafHealth()
	if err != nil {
		status["health_check_error"] = fmt.Sprintf("Failed to check Telegraf health: %v", err)
	} else {
		status["is_healthy"] = isHealthy
	}

	// 获取Prometheus端口
	if config, ok := status["config"].(map[string]interface{}); ok {
		if prometheusPort, ok := config["prometheus_port"].(float64); ok {
			status["prometheus_port"] = int(prometheusPort)
		}
	}

	return status
}

func (tm *TelegrafManager) MultiLevelKey() string {
	key, _ := tm.KeyManager.GenerateResourceKey(string(models.ResourceTypeTelegraf), TelegrafContainerName)
	return key
}

func (tm *TelegrafManager) generateTelegrafConfigFile(configMap map[string]interface{}) (string, error) {
	// 读取默认配置文件模板
	defaultConfigPath := "cmd/client/uniops-telegraf.conf"
	defaultConfig, err := ioutil.ReadFile(defaultConfigPath)
	if err != nil {
		// 如果默认配置文件不存在，使用内置模板
		defaultConfig = []byte(`[global_tags]

[agent]
  interval = "10s"
  round_interval = true
  metric_batch_size = 1000
  metric_buffer_limit = 10000
  collection_jitter = "0s"
  flush_interval = "10s"
  flush_jitter = "0s"
  precision = "0s"
  hostname = ""
  omit_hostname = false

[[inputs.cpu]]
  percpu = true
  totalcpu = true
  collect_cpu_time = false
  report_active = false
  core_tags = false

[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]

[[inputs.diskio]]
[[inputs.kernel]]
[[inputs.mem]]
[[inputs.processes]]
  use_sudo = true
[[inputs.swap]]
[[inputs.system]]
[[inputs.net]]

[[outputs.prometheus_client]]
  listen = ":9273"
`)
	}

	configContent := string(defaultConfig)

	// 替换配置中的动态值
	lokiEndpoint := gjson.Get(fmt.Sprintf("%v", configMap), "loki_endpoint").String()
	if lokiEndpoint == "" {
		lokiEndpoint = tm.Config.BaseConfig.UpstreamLokiUrl
		if lokiEndpoint == "" {
			lokiEndpoint = "http://localhost:3100"
		}
	}

	prometheusEndpoint := gjson.Get(fmt.Sprintf("%v", configMap), "prometheus_endpoint").String()
	if prometheusEndpoint == "" {
		prometheusEndpoint = tm.Config.BaseConfig.UpstreamPrometheusUrl
		if prometheusEndpoint == "" {
			prometheusEndpoint = "http://localhost:8429/api/v1/write"
		}
	}

	prometheusPort := gjson.Get(fmt.Sprintf("%v", configMap), "prometheus_port").Int()
	if prometheusPort == 0 {
		prometheusPort = 9273
	}

	// 替换配置中的占位符
	configContent = strings.ReplaceAll(configContent, "http://192.168.100.122:8081", lokiEndpoint)
	configContent = strings.ReplaceAll(configContent, "http://192.168.100.122:8429/api/v1/write", prometheusEndpoint)
	configContent = strings.ReplaceAll(configContent, ":9273", fmt.Sprintf(":%d", prometheusPort))

	// 如果配置中有自定义配置内容，可以在这里添加
	// 目前使用默认配置模板

	// 创建临时配置文件
	tempFile, err := ioutil.TempFile("", "telegraf-config-*.conf")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary config file: %v", err)
	}
	tm.tempConfigPath = tempFile.Name()

	// 写入配置到临时文件
	if _, err := tempFile.WriteString(configContent); err != nil {
		tempFile.Close()
		os.Remove(tm.tempConfigPath)
		return "", fmt.Errorf("failed to write config to temporary file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		os.Remove(tm.tempConfigPath)
		return "", fmt.Errorf("failed to close temporary file: %v", err)
	}

	// 设置文件权限，使容器内的用户能够读取（0644 = rw-r--r--）
	if err := os.Chmod(tm.tempConfigPath, 0644); err != nil {
		os.Remove(tm.tempConfigPath)
		return "", fmt.Errorf("failed to set permissions on config file: %v", err)
	}

	return tm.tempConfigPath, nil
}

func (tm *TelegrafManager) Start() error {
	var err error
	// 尝试从 ConfigManager 获取容器名称
	TelegrafContainerName, err = tm.ConfigManager.GetContainerNameByResourceType(models.ResourceTypeTelegraf)
	if err != nil {
		// 如果获取失败，尝试从配置结构体中获取
		if tm.Config.Telegraf.Name != "" {
			TelegrafContainerName = tm.Config.Telegraf.Name
		} else {
			// 使用默认容器名称
			TelegrafContainerName = DefaultTelegrafResourceName
		}
	}

	// 尝试获取配置，如果不存在则使用默认配置
	telegrafConfig, err := tm.ConfigManager.GetConfig(models.ResourceTypeTelegraf, TelegrafContainerName)
	if err != nil {
		// 如果配置不存在，使用配置结构体中的值创建默认配置
		configMap := make(map[string]interface{})
		if tm.Config.Telegraf.Image != "" {
			configMap["image"] = tm.Config.Telegraf.Image
		} else {
			configMap["image"] = "telegraf:latest"
		}
		configMap["name"] = TelegrafContainerName
		if tm.Config.Telegraf.PrometheusPort > 0 {
			configMap["prometheus_port"] = tm.Config.Telegraf.PrometheusPort
		} else {
			configMap["prometheus_port"] = 9273
		}
		if tm.Config.Telegraf.LokiEndpoint != "" {
			configMap["loki_endpoint"] = tm.Config.Telegraf.LokiEndpoint
		}
		if tm.Config.Telegraf.PrometheusEndpoint != "" {
			configMap["prometheus_endpoint"] = tm.Config.Telegraf.PrometheusEndpoint
		}

		// 保存默认配置
		err = tm.ConfigManager.UpdateConfig(models.ResourceTypeTelegraf, TelegrafContainerName, configMap)
		if err != nil {
			return fmt.Errorf("failed to create default Telegraf config: %v", err)
		}
		telegrafConfig = configMap
	}

	telegrafJson, _ := json.Marshal(telegrafConfig)

	// 确保配置中包含必要的字段
	if gjson.Get(string(telegrafJson), "image").String() == "" {
		// 如果没有镜像，设置默认值
		if err := tm.ConfigManager.UpdateConfig(models.ResourceTypeTelegraf, TelegrafContainerName, map[string]interface{}{
			"image": "telegraf:latest",
		}); err != nil {
			return fmt.Errorf("failed to set default image: %v", err)
		}
		// 重新获取配置
		telegrafConfig, err = tm.ConfigManager.GetConfig(models.ResourceTypeTelegraf, TelegrafContainerName)
		if err != nil {
			return fmt.Errorf("failed to get Telegraf config after setting default: %v", err)
		}
		telegrafJson, _ = json.Marshal(telegrafConfig)
	}

	// 获取Prometheus端口用于服务注册
	prometheusPort := gjson.Get(string(telegrafJson), "prometheus_port").Int()
	if prometheusPort == 0 {
		prometheusPort = 9273
	}

	tm.ctx, tm.cancel = context.WithCancel(context.Background())
	key, err := tm.KeyManager.GenerateServiceKey(string(models.ServiceNameTelegraf), tm.RegistryManager.HostIdentifier, fmt.Sprintf("%d", prometheusPort))
	if err != nil {
		return fmt.Errorf("failed to generate resource key: %v", err)
	}
	tm.serviceInfo = &models.ServiceInfo{
		Key:     key,
		Name:    string(models.ServiceNameTelegraf),
		Address: fmt.Sprintf(":%d", prometheusPort),
	}
	go tm.periodicRegister()
	return tm.setupAndRunTelegraf(false)
}

func (tm *TelegrafManager) Restart() error {
	return tm.setupAndRunTelegraf(true)
}

func (tm *TelegrafManager) Stop() error {
	if tm.cancel != nil {
		tm.cancel()
	}

	status, err := tm.ResourceManager.GetResourceStatus(tm.MultiLevelKey())
	if err != nil {
		return fmt.Errorf("failed to get Telegraf status: %v", err)
	}
	if status == "stopped" || status == "exited" {
		return nil
	}

	err = tm.ResourceManager.StopResource(tm.MultiLevelKey())
	if err != nil {
		return fmt.Errorf("failed to stop Telegraf service: %v", err)
	}

	for i := 0; i < 30; i++ {
		status, err := tm.ResourceManager.GetResourceStatus(tm.MultiLevelKey())
		if err != nil {
			return fmt.Errorf("failed to get Telegraf status: %v", err)
		}
		if status == "stopped" || status == "exited" {
			// 清理临时配置文件
			if tm.tempConfigPath != "" {
				os.Remove(tm.tempConfigPath)
				tm.tempConfigPath = ""
			}
			return nil
		}
		time.Sleep(time.Second)
	}

	if tm.tempConfigPath != "" {
		err := os.Remove(tm.tempConfigPath)
		if err != nil {
			fmt.Printf("Warning: failed to remove temporary config file: %v\n", err)
		}
		tm.tempConfigPath = ""
	}

	return fmt.Errorf("failed to stop Telegraf service within timeout")
}

func (tm *TelegrafManager) setupAndRunTelegraf(isRestart bool) error {
	if isRestart {
		err := tm.Stop()
		if err != nil {
			return fmt.Errorf("failed to stop Telegraf service during restart: %v", err)
		}
	}

	configMap, err := tm.ConfigManager.GetConfig(models.ResourceTypeTelegraf, TelegrafContainerName)
	if err != nil {
		return fmt.Errorf("failed to get Telegraf config: %v", err)
	}

	// 生成配置文件
	configPath, err := tm.generateTelegrafConfigFile(configMap)
	if err != nil {
		return fmt.Errorf("failed to generate telegraf config file: %v", err)
	}

	telegrafConfig := tm.prepareTelegrafConfig(configMap, configPath)

	multiLevelKey, err := tm.KeyManager.GenerateResourceKey(string(models.ResourceTypeTelegraf), TelegrafContainerName)
	if err != nil {
		return fmt.Errorf("failed to generate key for Telegraf resource: %v", err)
	}

	if err := tm.ResourceManager.startOrCreateResource(models.ResourceTypeTelegraf, TelegrafContainerName, func() map[string]interface{} { return telegrafConfig }); err != nil {
		return fmt.Errorf("failed to start or create Telegraf: %v", err)
	}

	if err := tm.waitForTelegrafStart(multiLevelKey); err != nil {
		return err
	}

	isHealthy, err := tm.checkTelegrafHealth()
	if err != nil {
		return fmt.Errorf("telegraf started but health check failed: %v", err)
	}
	if !isHealthy {
		return fmt.Errorf("telegraf started but is not healthy")
	}

	return nil
}

func (tm *TelegrafManager) prepareTelegrafConfig(configMap map[string]interface{}, configPath string) map[string]interface{} {
	image := ""
	if img, ok := configMap["image"].(string); ok && img != "" {
		image = img
	} else {
		image = "telegraf:latest"
	}

	prometheusPort := 9273
	if port, ok := configMap["prometheus_port"].(float64); ok && port > 0 {
		prometheusPort = int(port)
	} else if port, ok := configMap["prometheus_port"].(int); ok && port > 0 {
		prometheusPort = port
	}

	// 获取配置文件绝对路径
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		absConfigPath = configPath
	}

	// 准备卷挂载
	volumes := []string{
		fmt.Sprintf("%s:/etc/telegraf/telegraf.conf:ro", absConfigPath),
	}

	// 准备端口映射
	ports := map[string]interface{}{
		fmt.Sprintf("%d/tcp", prometheusPort): prometheusPort,
	}

	return map[string]interface{}{
		"image":   image,
		"ports":   ports,
		"volumes": volumes,
		"command": []string{
			"--config", "/etc/telegraf/telegraf.conf",
		},
	}
}

func (tm *TelegrafManager) waitForTelegrafStart(multiLevelKey string) error {
	timeout := 60 // 增加到60秒
	for i := 0; i < timeout; i++ {
		status, err := tm.ResourceManager.GetResourceStatus(multiLevelKey)
		if err != nil {
			xlog.Default().Warn("Failed to get Telegraf status",
				xlog.String("key", multiLevelKey),
				xlog.Int("attempt", i+1),
				xlog.FieldErr(err))
			time.Sleep(time.Second)
			continue
		}

		xlog.Default().Info("Checking Telegraf status",
			xlog.String("key", multiLevelKey),
			xlog.String("status", status),
			xlog.Int("attempt", i+1),
			xlog.Int("timeout", timeout))

		if status == "running" {
			xlog.Default().Info("Telegraf started successfully",
				xlog.String("key", multiLevelKey),
				xlog.Int("elapsed_seconds", i+1))
			return nil
		}

		// 如果容器处于退出状态，立即返回错误并获取日志
		if status == "exited" || status == "dead" {
			// 尝试获取容器日志以便诊断问题
			logs, logErr := tm.ResourceManager.GetResourceLogs(multiLevelKey, 50)
			if logErr != nil {
				xlog.Default().Warn("Failed to get container logs",
					xlog.String("key", multiLevelKey),
					xlog.FieldErr(logErr))
				return fmt.Errorf("telegraf container exited with status: %s (failed to retrieve logs: %v)", status, logErr)
			}
			xlog.Default().Error("Telegraf container exited",
				xlog.String("key", multiLevelKey),
				xlog.String("status", status),
				xlog.String("logs", logs))
			return fmt.Errorf("telegraf container exited with status: %s\nContainer logs:\n%s", status, logs)
		}

		time.Sleep(time.Second)
	}

	// 获取最终状态用于错误报告
	finalStatus, err := tm.ResourceManager.GetResourceStatus(multiLevelKey)
	if err != nil {
		return fmt.Errorf("telegraf failed to start within %d seconds timeout (final status check failed: %v)", timeout, err)
	}
	return fmt.Errorf("telegraf failed to start within %d seconds timeout (final status: %s)", timeout, finalStatus)
}

func (tm *TelegrafManager) checkTelegrafHealth() (bool, error) {
	multipartKey, err := tm.KeyManager.GenerateResourceKey(string(models.ResourceTypeTelegraf), TelegrafContainerName)
	if err != nil {
		return false, err
	}
	status, err := tm.ResourceManager.GetResourceStatus(multipartKey)
	if err != nil {
		return false, err
	}
	return status == "running", nil
}

func (tm *TelegrafManager) UpdateTelegrafConfig(config map[string]interface{}) error {
	// 验证新配置
	if _, ok := config["image"]; !ok {
		return errors.New("image is required in the new configuration")
	}

	// 更新配置
	err := tm.ConfigManager.UpdateConfig(models.ResourceTypeTelegraf, TelegrafContainerName, config)
	if err != nil {
		return fmt.Errorf("failed to update Telegraf config: %v", err)
	}

	// 重启服务以应用新配置
	err = tm.Restart()
	if err != nil {
		return fmt.Errorf("failed to restart Telegraf service: %v", err)
	}

	return nil
}

func (tm *TelegrafManager) GetTelegrafStatus() (string, error) {
	key, err := tm.KeyManager.GenerateResourceKey(string(models.ResourceTypeTelegraf), TelegrafContainerName)
	if err != nil {
		return "", fmt.Errorf("failed to generate resource key: %v", err)
	}
	status, err := tm.ResourceManager.GetResourceStatus(key)
	if err != nil {
		return "", fmt.Errorf("failed to get Telegraf status: %v", err)
	}

	return status, nil
}

func (tm *TelegrafManager) GetConfig() (map[string]interface{}, error) {
	return tm.ConfigManager.GetConfig(models.ResourceTypeTelegraf, TelegrafContainerName)
}

func (tm *TelegrafManager) UpdateConfig(config map[string]interface{}) error {
	return tm.ConfigManager.UpdateConfig(models.ResourceTypeTelegraf, TelegrafContainerName, config)
}

func (tm *TelegrafManager) periodicRegister() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒注册一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := tm.registerService()
			if err != nil {
				xlog.Default().Error("Failed to register Telegraf service", xlog.FieldErr(err))
			}
		case <-tm.ctx.Done():
			xlog.Default().Info("Stopping Telegraf service registration")
			return
		}
	}
}

func (tm *TelegrafManager) registerService() error {
	config, err := tm.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get Telegraf config: %v", err)
	}

	prometheusPort := 9273
	if port, ok := config["prometheus_port"].(float64); ok && port > 0 {
		prometheusPort = int(port)
	} else if port, ok := config["prometheus_port"].(int); ok && port > 0 {
		prometheusPort = port
	}

	tm.serviceInfo.Address = fmt.Sprintf(":%d", prometheusPort)
	return tm.RegistryManager.RegisterService(tm.serviceInfo, 1*time.Minute) // TTL设置为1分钟
}

// UpdateConfigFromTasks 从监控任务更新配置
func (tm *TelegrafManager) UpdateConfigFromTasks(ctx context.Context, tasks []*models.MonitoringTask, standalonePlugins []*models.PluginConfig) error {
	if tm.ConfigGenerator == nil {
		return fmt.Errorf("config generator not available")
	}

	// 生成配置
	configStr, err := tm.ConfigGenerator.GenerateConfig(ctx, tasks, standalonePlugins)
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// 验证配置
	if err := tm.ConfigGenerator.ValidateConfig(configStr); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// 写入临时配置文件
	tempFile, err := ioutil.TempFile("", "telegraf-config-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create temporary config file: %w", err)
	}

	oldConfigPath := tm.tempConfigPath
	tm.tempConfigPath = tempFile.Name()

	if _, err := tempFile.WriteString(configStr); err != nil {
		tempFile.Close()
		os.Remove(tm.tempConfigPath)
		tm.tempConfigPath = oldConfigPath
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		os.Remove(tm.tempConfigPath)
		tm.tempConfigPath = oldConfigPath
		return fmt.Errorf("failed to close config file: %w", err)
	}

	// 设置文件权限，使容器内的用户能够读取（0644 = rw-r--r--）
	if err := os.Chmod(tm.tempConfigPath, 0644); err != nil {
		os.Remove(tm.tempConfigPath)
		tm.tempConfigPath = oldConfigPath
		return fmt.Errorf("failed to set permissions on config file: %w", err)
	}

	// 更新配置版本和时间
	tm.configVersion = fmt.Sprintf("%d", time.Now().Unix())
	now := time.Now()
	tm.lastReloadTime = &now

	// 热重载配置
	if err := tm.ReloadConfig(); err != nil {
		// 如果重载失败，恢复旧配置
		os.Remove(tm.tempConfigPath)
		tm.tempConfigPath = oldConfigPath
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// 删除旧配置文件
	if oldConfigPath != "" {
		os.Remove(oldConfigPath)
	}

	return nil
}

// ReloadConfig 重新加载 telegraf 配置
func (tm *TelegrafManager) ReloadConfig() error {
	// 获取容器信息
	multiLevelKey := tm.MultiLevelKey()
	resourceInfo, err := tm.ResourceManager.GetResourceInfo(multiLevelKey)
	if err != nil {
		return fmt.Errorf("failed to get resource info: %w", err)
	}

	// 尝试发送 SIGHUP 信号给容器内的 telegraf 进程
	// 如果容器支持，可以通过 exec 发送信号
	_ = resourceInfo // 暂时未使用

	// 暂时使用容器重启的方式
	return tm.Restart()
}

// GetConfigVersion 获取配置版本
func (tm *TelegrafManager) GetConfigVersion() string {
	return tm.configVersion
}

// GetLastReloadTime 获取最后重载时间
func (tm *TelegrafManager) GetLastReloadTime() *time.Time {
	return tm.lastReloadTime
}
