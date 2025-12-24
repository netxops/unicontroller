package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap"
)

// ServiceDiscovery 服务发现接口
type ServiceDiscovery interface {
	Discover(ctx context.Context) ([]*domain.Service, error)
	Start(ctx context.Context) error
	Stop() error
}

// serviceDiscovery 服务发现实现
type serviceDiscovery struct {
	workspace  string
	interval   time.Duration
	registry   *ServiceRegistry
	logger     *zap.Logger
	stopChan   chan struct{}
	discovered map[string]string // package ID -> package.json path
}

// NewServiceDiscovery 创建服务发现器
func NewServiceDiscovery(workspace string, interval time.Duration, registry *ServiceRegistry, logger *zap.Logger) ServiceDiscovery {
	return &serviceDiscovery{
		workspace:  workspace,
		interval:   interval,
		registry:   registry,
		logger:     logger,
		stopChan:   make(chan struct{}),
		discovered: make(map[string]string),
	}
}

// packageSpec 用于解析 package.json
type packageSpec struct {
	Package     string `json:"package"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Binary      struct {
		Name string `json:"name"`
		Path string `json:"path"`
	} `json:"binary"`
	Startup struct {
		Method      string            `json:"method"`
		ServiceName string            `json:"service_name"`
		User        string            `json:"user"`
		Group       string            `json:"group"`
		Args        []string          `json:"args"`
		Environment map[string]string `json:"environment"`
	} `json:"startup"`
	Config struct {
		Format    string `json:"format"`
		MainFile  string `json:"main_file"`
		Directory string `json:"directory"`
		Templates []struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
			Type        string `json:"type"`
		} `json:"templates"`
	} `json:"config"`
	Healthcheck  map[string]interface{} `json:"healthcheck"`
	Logging      map[string]interface{} `json:"logging"`
	Dependencies []map[string]string    `json:"dependencies"`
}

// Discover 发现所有服务
func (sd *serviceDiscovery) Discover(ctx context.Context) ([]*domain.Service, error) {
	var services []*domain.Service

	// 检查工作目录是否存在
	info, err := os.Stat(sd.workspace)
	if err != nil {
		if os.IsNotExist(err) {
			// 目录不存在，尝试创建
			if err := os.MkdirAll(sd.workspace, 0755); err != nil {
				sd.logger.Warn("Workspace directory does not exist and cannot be created",
					zap.String("workspace", sd.workspace),
					zap.Error(err))
				// 返回空列表，不报错（允许目录稍后创建）
				return services, nil
			}
			sd.logger.Info("Created workspace directory",
				zap.String("workspace", sd.workspace))
			// 目录已创建，但为空，返回空列表
			return services, nil
		}
		// 其他错误（如权限问题）
		sd.logger.Warn("Cannot access workspace directory",
			zap.String("workspace", sd.workspace),
			zap.Error(err))
		return services, nil
	}

	// 确保是目录
	if !info.IsDir() {
		sd.logger.Warn("Workspace path is not a directory",
			zap.String("workspace", sd.workspace))
		return services, nil
	}

	// 扫描工作目录
	err = filepath.Walk(sd.workspace, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			sd.logger.Warn("Error accessing path",
				zap.String("path", path),
				zap.Error(err))
			return nil // 继续扫描其他路径
		}

		// 查找 package.json 文件
		if info.Name() == "package.json" && !info.IsDir() {
			service, err := sd.parsePackageJSON(path)
			if err != nil {
				sd.logger.Warn("Failed to parse package.json",
					zap.String("path", path),
					zap.Error(err))
				return nil // 继续扫描其他文件
			}

			services = append(services, service)
			sd.discovered[service.ID] = path
		}

		return nil
	})

	if err != nil {
		sd.logger.Warn("Error scanning workspace",
			zap.String("workspace", sd.workspace),
			zap.Error(err))
		// 不返回错误，返回已发现的服务
		return services, nil
	}

	return services, nil
}

// parsePackageJSON 解析 package.json 文件
func (sd *serviceDiscovery) parsePackageJSON(path string) (*domain.Service, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	// 解析 JSON（兼容原有的 PackageSpec 格式）
	var pkgSpec packageSpec

	if err := json.Unmarshal(data, &pkgSpec); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	if pkgSpec.Package == "" {
		return nil, fmt.Errorf("package name is required")
	}

	// 转换为 domain.Service
	service := &domain.Service{
		ID:      pkgSpec.Package,
		Name:    pkgSpec.Package,
		Version: pkgSpec.Version,
		Status:  domain.ServiceStatusStopped,
		Spec:    sd.convertToServiceSpec(&pkgSpec, path),
	}

	return service, nil
}

// convertToServiceSpec 转换为 ServiceSpec
func (sd *serviceDiscovery) convertToServiceSpec(pkgSpec *packageSpec, packageJSONPath string) *domain.ServiceSpec {
	spec := &domain.ServiceSpec{
		Package: pkgSpec.Package,
		Version: pkgSpec.Version,
	}

	// Binary
	if pkgSpec.Binary.Name != "" || pkgSpec.Binary.Path != "" {
		spec.Binary = &domain.BinarySpec{
			Name: pkgSpec.Binary.Name,
			Path: pkgSpec.Binary.Path,
		}
	}

	// Startup
	if pkgSpec.Startup.Method != "" {
		spec.Startup = &domain.StartupSpec{
			Method:      pkgSpec.Startup.Method,
			ServiceName: pkgSpec.Startup.ServiceName,
			User:        pkgSpec.Startup.User,
			Group:       pkgSpec.Startup.Group,
			Args:        pkgSpec.Startup.Args,
			Environment: pkgSpec.Startup.Environment,
		}
		// 如果 ServiceName 为空，使用 Package 名称
		if spec.Startup.ServiceName == "" {
			spec.Startup.ServiceName = pkgSpec.Package
		}
	}

	// Config
	if pkgSpec.Config.MainFile != "" || len(pkgSpec.Config.Templates) > 0 {
		templates := make([]domain.ConfigTemplate, 0, len(pkgSpec.Config.Templates))
		for _, t := range pkgSpec.Config.Templates {
			templates = append(templates, domain.ConfigTemplate{
				Source:      t.Source,
				Destination: t.Destination,
			})
		}

		spec.Config = &domain.ConfigSpec{
			Format:    pkgSpec.Config.Format,
			MainFile:  pkgSpec.Config.MainFile,
			Directory: pkgSpec.Config.Directory,
			Templates: templates,
		}
	}

	// Operations (健康检查、日志等)
	ops := &domain.OperationsConfig{}

	// 解析健康检查配置
	if pkgSpec.Healthcheck != nil {
		healthCheck := sd.parseHealthCheck(pkgSpec.Healthcheck)
		if healthCheck != nil {
			ops.HealthCheck = healthCheck
		}
	}

	// 解析日志配置
	if pkgSpec.Logging != nil {
		logging := sd.parseLogging(pkgSpec.Logging)
		if logging != nil {
			ops.Logging = logging
		}
	}

	// 解析依赖
	if len(pkgSpec.Dependencies) > 0 {
		deps := make([]string, 0, len(pkgSpec.Dependencies))
		for _, dep := range pkgSpec.Dependencies {
			if pkg, ok := dep["package"]; ok {
				deps = append(deps, pkg)
			}
		}
		ops.Dependencies = deps
	}

	if ops.HealthCheck != nil || ops.Logging != nil || len(ops.Dependencies) > 0 {
		spec.Operations = ops
	}

	return spec
}

// parseHealthCheck 解析健康检查配置
func (sd *serviceDiscovery) parseHealthCheck(healthcheck map[string]interface{}) *domain.HealthCheckConfig {
	config := &domain.HealthCheckConfig{}

	if typ, ok := healthcheck["type"].(string); ok {
		config.Type = typ
	} else {
		return nil // 没有类型，不创建健康检查配置
	}

	if interval, ok := healthcheck["interval"].(string); ok {
		if d, err := time.ParseDuration(interval); err == nil {
			config.Interval = d
		}
	}

	if timeout, ok := healthcheck["timeout"].(string); ok {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.Timeout = d
		}
	}

	if retries, ok := healthcheck["retries"].(float64); ok {
		config.Retries = int(retries)
	}

	if path, ok := healthcheck["http_path"].(string); ok {
		config.HTTPPath = path
	}

	if method, ok := healthcheck["http_method"].(string); ok {
		config.HTTPMethod = method
	}

	if port, ok := healthcheck["tcp_port"].(float64); ok {
		config.TCPPort = int(port)
	}

	if script, ok := healthcheck["script_path"].(string); ok {
		config.ScriptPath = script
	}

	return config
}

// parseLogging 解析日志配置
func (sd *serviceDiscovery) parseLogging(logging map[string]interface{}) *domain.LoggingConfig {
	config := &domain.LoggingConfig{}

	if dir, ok := logging["directory"].(string); ok {
		config.Directory = dir
	}

	if maxSize, ok := logging["max_size"].(string); ok {
		// 解析大小（如 "100MB"）
		if size, err := parseSize(maxSize); err == nil {
			config.MaxSize = size
		}
	}

	if maxFiles, ok := logging["max_files"].(float64); ok {
		config.MaxFiles = int(maxFiles)
	}

	if level, ok := logging["level"].(string); ok {
		config.Level = level
	}

	return config
}

// parseSize 解析大小字符串（如 "100MB", "1GB"）
func parseSize(sizeStr string) (int64, error) {
	var size int64
	var unit string

	_, err := fmt.Sscanf(sizeStr, "%d%s", &size, &unit)
	if err != nil {
		return 0, err
	}

	switch unit {
	case "KB", "kb":
		return size * 1024, nil
	case "MB", "mb":
		return size * 1024 * 1024, nil
	case "GB", "gb":
		return size * 1024 * 1024 * 1024, nil
	default:
		return size, nil
	}
}

// Start 启动服务发现（定期扫描）
func (sd *serviceDiscovery) Start(ctx context.Context) error {
	sd.logger.Info("Starting service discovery",
		zap.String("workspace", sd.workspace),
		zap.Duration("interval", sd.interval))

	// 立即执行一次发现
	if err := sd.discoverAndRegister(ctx); err != nil {
		sd.logger.Error("Initial discovery failed", zap.Error(err))
	}

	// 定期扫描
	ticker := time.NewTicker(sd.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			sd.logger.Info("Service discovery context cancelled")
			return ctx.Err()
		case <-sd.stopChan:
			sd.logger.Info("Service discovery stopped")
			return nil
		case <-ticker.C:
			if err := sd.discoverAndRegister(ctx); err != nil {
				sd.logger.Error("Discovery failed", zap.Error(err))
			}
		}
	}
}

// Stop 停止服务发现
func (sd *serviceDiscovery) Stop() error {
	close(sd.stopChan)
	return nil
}

// discoverAndRegister 发现并注册服务
func (sd *serviceDiscovery) discoverAndRegister(ctx context.Context) error {
	services, err := sd.Discover(ctx)
	if err != nil {
		return err
	}

	// 注册或更新服务
	for _, service := range services {
		// 检查服务是否已存在
		existing, exists := sd.registry.Get(service.ID)
		if exists {
			// 检查 package.json 是否有更新
			oldPath, hadPath := sd.discovered[service.ID]
			newPath := sd.discovered[service.ID]
			if hadPath && oldPath != newPath {
				// 路径变化，可能是文件移动，更新服务
				sd.logger.Info("Service path changed, updating",
					zap.String("service", service.ID),
					zap.String("old_path", oldPath),
					zap.String("new_path", newPath))
			}
			// 更新服务规格（保持状态不变）
			existing.Spec = service.Spec
			existing.Version = service.Version
		} else {
			// 新服务，注册
			sd.registry.Register(service)
			sd.logger.Info("Discovered new service",
				zap.String("service", service.ID),
				zap.String("version", service.Version))
		}
	}

	// 检查是否有服务被删除（package.json 文件不存在了）
	sd.checkRemovedServices(services)

	return nil
}

// checkRemovedServices 检查已删除的服务
func (sd *serviceDiscovery) checkRemovedServices(currentServices []*domain.Service) {
	currentIDs := make(map[string]bool)
	for _, service := range currentServices {
		currentIDs[service.ID] = true
	}

	// 获取所有已注册的服务
	allServices := sd.registry.List()
	for _, service := range allServices {
		if !currentIDs[service.ID] {
			// 服务不再存在，但保留在注册表中（可能只是暂时删除文件）
			// 可以选择注销或保留，这里选择保留以便恢复
			sd.logger.Warn("Service package.json not found, but keeping in registry",
				zap.String("service", service.ID))
		}
	}
}
