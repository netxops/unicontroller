package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/api"

	"github.com/gorilla/mux"
	"github.com/influxdata/telegraf/controller/pkg/controller"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// 解析命令行参数
	configPath := flag.String("config", "config.yaml", "Path to the configuration file")
	port := flag.String("port", "8081", "Port for the API server")
	useDockerEtcd := flag.Bool("use-docker-etcd", true, "Use Docker etcd container (true) or external etcd (false). Can be overridden by config file.")
	flag.Parse()

	portInt, err := strconv.Atoi(*port)
	if err != nil {
		log.Fatalf("Invalid port number: %v", err)
	}

	// 初始化控制器组件
	ctl, err := controller.InitializeControllerComponents(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize controller components: %v", err)
	}

	// 命令行参数可以覆盖配置文件中的设置
	// 如果命令行参数不是默认值（true），则覆盖配置
	if !*useDockerEtcd {
		ctl.ConfigManager.Config.UseDockerEtcd = false
		if ctl.ConfigManager.Config.EtcdConfig == nil {
			ctl.ConfigManager.Config.EtcdConfig = make(map[string]interface{})
		}
		ctl.ConfigManager.Config.EtcdConfig["use_docker_etcd"] = false
		log.Printf("Command line override: using external etcd (use-docker-etcd=false)")
	}

	// 创建API处理器
	// 获取 controller ID（从 RegistryManager 获取 HostIdentifier，因为 controller.id 在 Start 时才设置）
	controllerID := ctl.RegistryManager.HostIdentifier
	controllerAPI := api.NewControllerAPI(ctl, ctl.GetMongoClient(), controllerID)

	// 创建指标策略服务
	// 注意：logger可以为nil，服务会使用默认行为
	metricsStrategyService := controller.NewMetricsStrategyService(
		ctl.GetMongoClient(),
		ctl.AgentManager,
		ctl.RegistryManager,
		nil, // logger暂时为nil，后续可以添加zap logger
	)
	metricsStrategyAPI := api.NewMetricsStrategyAPI(metricsStrategyService, nil)

	// 设置路由
	r := mux.NewRouter()
	r.HandleFunc("/api/v1/status", controllerAPI.GetControllerStatus).Methods("GET")
	r.HandleFunc("/api/v1/deployments", controllerAPI.CreateDeployment).Methods("POST")
	r.HandleFunc("/api/v1/deployments/agent", controllerAPI.DeployAgent).Methods("POST")
	// r.HandleFunc("/api/v1/apps/{app_id}/variables", controllerAPI.GetAppVariables).Methods("GET")
	r.HandleFunc("/api/v1/assets", controllerAPI.GetAssets).Methods("GET")
	r.HandleFunc("/api/v1/packages", controllerAPI.GetAppPackageList).Methods("GET")
	r.HandleFunc("/api/v1/packages/{package_name}/url", controllerAPI.GetAppPackageURL).Methods("GET")
	r.HandleFunc("/api/v1/agents", controllerAPI.HandleListAgents).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}", controllerAPI.HandleGetAgent).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/packages", controllerAPI.HandleGetAgentPackages).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/health", controllerAPI.HandleGetAgentHealth).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/health/{package}", controllerAPI.HandleGetServiceHealth).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/metrics/system", controllerAPI.HandleGetSystemMetrics).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/metrics/services", controllerAPI.HandleGetServiceMetrics).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/metrics/application", controllerAPI.HandleGetApplicationMetrics).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/metrics/history", controllerAPI.HandleGetMetricsHistory).Methods("GET")

	// 文件操作 API
	r.HandleFunc("/api/v1/agents/{agent_id}/files", controllerAPI.HandleListFiles).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/files/info", controllerAPI.HandleGetFileInfo).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/files/upload", controllerAPI.HandleStartFileUpload).Methods("POST")
	r.HandleFunc("/api/v1/agents/{agent_id}/files/upload/{session_id}", controllerAPI.HandleUploadFileChunk).Methods("POST")
	r.HandleFunc("/api/v1/agents/{agent_id}/files/upload/{session_id}/status", controllerAPI.HandleGetUploadStatus).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/files/download", controllerAPI.HandleDownloadFile).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_id}/files/delete", controllerAPI.HandleDeleteFile).Methods("DELETE", "POST")
	r.HandleFunc("/api/v1/agents/{agent_id}/files/mkdir", controllerAPI.HandleCreateDirectory).Methods("POST")
	r.HandleFunc("/api/v1/agents/{agent_id}/uninstall", controllerAPI.HandleUninstallAgent).Methods("POST")
	r.HandleFunc("/api/v1/agents/{agent_id}/restart", controllerAPI.HandleRestartAgent).Methods("POST")
	r.HandleFunc("/api/v1/agents/batch/start", controllerAPI.HandleBatchStart).Methods("POST")
	r.HandleFunc("/api/v1/agents/batch/stop", controllerAPI.HandleBatchStop).Methods("POST")
	r.HandleFunc("/api/v1/agents/batch/restart", controllerAPI.HandleBatchRestart).Methods("POST")
	r.HandleFunc("/api/v1/agents/batch/configs", controllerAPI.HandleBatchUpdateConfigs).Methods("POST")
	r.HandleFunc("/api/v1/services", controllerAPI.HandleListService).Methods("GET")
	// r.HandleFunc("/api/v1/packages/install", controllerAPI.InstallPackage).Methods("POST")
	// r.HandleFunc("/api/v1/packages/install/{install_id}", controllerAPI.GetPackageInstallStatus).Methods("GET")
	r.HandleFunc("/api/v1/variables", controllerAPI.GetVariables).Methods("GET")
	r.HandleFunc("/api/v1/loki/write", ctl.LokiForwarder.ForwardHandler).Methods("POST")

	r.HandleFunc("/api/v1/deployments/{deployment_id}/status", controllerAPI.UpdateDeploymentStatusAndResults).Methods("POST")
	// r.HandleFunc("/api/v1/deployments/{deployment_id}/status", controllerAPI.UpdateDeploymentStatus).Methods("POST")
	r.HandleFunc("/api/v1/deployments/{deployment_id}", controllerAPI.GetDeployment).Methods("GET")
	r.HandleFunc("/api/v1/agents/{agent_code}/packages/{package_name}/start", controllerAPI.StartPackage).Methods("POST")
	r.HandleFunc("/api/v1/agents/{agent_code}/packages/{package_name}/stop", controllerAPI.StopPackage).Methods("POST")
	r.HandleFunc("/api/v1/prometheus/write", ctl.PrometheusForwarder.ForwardHandler).Methods("POST")
	r.HandleFunc("/api/v1/agents/{agent_code}/packages/{package_name}/logs", controllerAPI.GetPackageLogs).Methods("GET")

	r.HandleFunc("/api/v1/execute", controllerAPI.ExecuteCommand).Methods("POST")
	r.HandleFunc("/api/v1/push_config", controllerAPI.PushConfig).Methods("POST")
	r.HandleFunc("/api/v1/async_execute", controllerAPI.AsyncExecuteCommand).Methods("POST")
	r.HandleFunc("/api/v1/async_execute/result", controllerAPI.GetAsyncExecuteResult).Methods("POST")

	r.Handle("/metrics", promhttp.Handler())
	r.HandleFunc("/api/v1/metrics", controllerAPI.MetricsHandler).Methods("GET")

	// 指标策略API
	r.HandleFunc("/api/v1/platform/metrics/strategy/global", metricsStrategyAPI.GetGlobalStrategy).Methods("GET")
	r.HandleFunc("/api/v1/platform/metrics/strategy/global", metricsStrategyAPI.UpdateGlobalStrategy).Methods("PUT")
	r.HandleFunc("/api/v1/platform/metrics/strategy/instance/{agentCode}", metricsStrategyAPI.GetInstanceStrategy).Methods("GET")
	r.HandleFunc("/api/v1/platform/metrics/strategy/instance/{agentCode}", metricsStrategyAPI.UpdateInstanceStrategy).Methods("PUT")
	r.HandleFunc("/api/v1/platform/metrics/available", metricsStrategyAPI.GetAvailableMetrics).Methods("GET")
	r.HandleFunc("/api/v1/platform/metrics/strategy/preview", metricsStrategyAPI.PreviewRule).Methods("POST")
	r.HandleFunc("/api/v1/platform/metrics/strategy/status/{agentCode}", metricsStrategyAPI.GetConfigStatus).Methods("GET")

	// 应用指标策略API
	r.HandleFunc("/api/v1/platform/metrics/strategy/application/global", func(w http.ResponseWriter, r *http.Request) {
		metricsStrategyAPI.GetApplicationStrategy(w, r)
	}).Methods("GET")
	r.HandleFunc("/api/v1/platform/metrics/strategy/application/global", func(w http.ResponseWriter, r *http.Request) {
		metricsStrategyAPI.UpdateApplicationStrategy(w, r)
	}).Methods("PUT")
	r.HandleFunc("/api/v1/platform/metrics/strategy/application/instance/{agentCode}", func(w http.ResponseWriter, r *http.Request) {
		metricsStrategyAPI.GetApplicationStrategy(w, r)
	}).Methods("GET")
	r.HandleFunc("/api/v1/platform/metrics/strategy/application/instance/{agentCode}", func(w http.ResponseWriter, r *http.Request) {
		metricsStrategyAPI.UpdateApplicationStrategy(w, r)
	}).Methods("PUT")

	r.HandleFunc("/api/v1/make_l3_templates", controllerAPI.MakeL3Templates).Methods("POST")
	r.HandleFunc("/api/v1/firewall_policy_query", controllerAPI.FirewallPolicyQuery).Methods("POST")
	r.HandleFunc("/api/v1/compare_policy", controllerAPI.ComparePolicy).Methods("POST")
	r.HandleFunc("/api/v1/blacklist_whitelist/apply", controllerAPI.ApplyBlacklistWhitelist).Methods("POST")
	r.HandleFunc("/api/v1/blacklist_whitelist/check_preset", controllerAPI.CheckPresetConfig).Methods("POST")
	r.HandleFunc("/api/v1/stackup/execute", controllerAPI.StackUpExecute).Methods("POST")
	r.HandleFunc("/api/v1/device/detect", controllerAPI.DetectDevice).Methods("POST")

	// 监控能力平台 API
	monitoringAPI := api.NewMonitoringAPI(
		ctl.MonitoringService,
		ctl.PluginTemplateService,
		ctl.TelegrafManager,
	)

	// 监控任务管理
	r.HandleFunc("/api/v1/monitoring/tasks", monitoringAPI.ListTasks).Methods("GET")
	r.HandleFunc("/api/v1/monitoring/tasks", monitoringAPI.CreateTask).Methods("POST")
	r.HandleFunc("/api/v1/monitoring/tasks/{task_id}", monitoringAPI.GetTask).Methods("GET")
	r.HandleFunc("/api/v1/monitoring/tasks/{task_id}", monitoringAPI.UpdateTask).Methods("PUT")
	r.HandleFunc("/api/v1/monitoring/tasks/{task_id}", monitoringAPI.DeleteTask).Methods("DELETE")
	r.HandleFunc("/api/v1/monitoring/tasks/{task_id}/start", monitoringAPI.StartTask).Methods("POST")
	r.HandleFunc("/api/v1/monitoring/tasks/{task_id}/stop", monitoringAPI.StopTask).Methods("POST")
	r.HandleFunc("/api/v1/monitoring/tasks/{task_id}/pause", monitoringAPI.PauseTask).Methods("POST")

	// 插件管理
	r.HandleFunc("/api/v1/monitoring/plugins", monitoringAPI.ListPlugins).Methods("GET")
	r.HandleFunc("/api/v1/monitoring/plugins", monitoringAPI.CreatePlugin).Methods("POST")
	r.HandleFunc("/api/v1/monitoring/plugins/{plugin_id}", monitoringAPI.GetPlugin).Methods("GET")
	r.HandleFunc("/api/v1/monitoring/plugins/{plugin_id}", monitoringAPI.UpdatePlugin).Methods("PUT")
	r.HandleFunc("/api/v1/monitoring/plugins/{plugin_id}", monitoringAPI.DeletePlugin).Methods("DELETE")

	// 插件模板管理
	r.HandleFunc("/api/v1/monitoring/templates", monitoringAPI.ListTemplates).Methods("GET")
	r.HandleFunc("/api/v1/monitoring/templates", monitoringAPI.CreateTemplate).Methods("POST")
	r.HandleFunc("/api/v1/monitoring/templates/{template_id}", monitoringAPI.GetTemplate).Methods("GET")
	r.HandleFunc("/api/v1/monitoring/templates/{template_id}", monitoringAPI.UpdateTemplate).Methods("PUT")
	r.HandleFunc("/api/v1/monitoring/templates/{template_id}", monitoringAPI.DeleteTemplate).Methods("DELETE")
	r.HandleFunc("/api/v1/monitoring/templates/{template_id}/validate", monitoringAPI.ValidateTemplateParameters).Methods("POST")

	// 动作导向 API
	r.HandleFunc("/api/v1/monitoring/apply", monitoringAPI.ApplyConfig).Methods("POST")
	r.HandleFunc("/api/v1/monitoring/reload", monitoringAPI.ReloadConfig).Methods("POST")
	r.HandleFunc("/api/v1/monitoring/status", monitoringAPI.GetMonitoringStatus).Methods("GET")

	// 创建HTTP服务器
	srv := &http.Server{
		Addr:    ":" + *port,
		Handler: r,
	}

	// 在goroutine中启动服务器
	go func() {
		log.Printf("Starting API server on port %s", *port)
		if err = srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// 启动控制器
	if !ctl.ConfigManager.Config.SkipInit {
		if err := ctl.Start(controller.WithPort(portInt)); err != nil {
			log.Fatalf("Failed to start controller: %v", err)
		}
	}

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 等待终止信号
	sig := <-sigChan
	fmt.Printf("Received signal %v, shutting down...\n", sig)

	// 创建一个5秒的超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 优雅地关闭HTTP服务器
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	// 停止控制器
	if err := ctl.Stop(); err != nil {
		log.Printf("Error during controller shutdown: %v", err)
	}

	fmt.Println("Controller and API server shutdown complete.")
}
