package domain

import (
	"time"
)

// ServiceStatus 服务状态
type ServiceStatus string

const (
	ServiceStatusUnknown   ServiceStatus = "unknown"
	ServiceStatusStopped   ServiceStatus = "stopped"
	ServiceStatusStarting  ServiceStatus = "starting"
	ServiceStatusRunning   ServiceStatus = "running"
	ServiceStatusStopping  ServiceStatus = "stopping"
	ServiceStatusFailed    ServiceStatus = "failed"
	ServiceStatusRestarting ServiceStatus = "restarting"
)

// Service 服务领域模型
type Service struct {
	ID          string
	Name        string
	Version     string
	Status      ServiceStatus
	Spec        *ServiceSpec
	Health      *ServiceHealth
	Metrics     *ServiceMetrics
	StartedAt   *time.Time
	StoppedAt   *time.Time
	RestartCount int
	LastError   error
}

// ServiceSpec 服务规格
type ServiceSpec struct {
	Package     string
	Version     string
	Binary      *BinarySpec
	Startup     *StartupSpec
	Config      *ConfigSpec
	Operations  *OperationsConfig
}

// BinarySpec 二进制文件规格
type BinarySpec struct {
	Name string
	Path string
}

// StartupSpec 启动配置
type StartupSpec struct {
	Method      string            // "systemd" or "direct"
	ServiceName string
	Args        []string
	Environment map[string]string
	User        string
	Group       string
}

// ConfigSpec 配置规格
type ConfigSpec struct {
	Format    string
	MainFile  string
	Directory string
	Templates []ConfigTemplate
}

// ConfigTemplate 配置模板
type ConfigTemplate struct {
	Source      string
	Destination string
}

// OperationsConfig 运维配置
type OperationsConfig struct {
	HealthCheck  *HealthCheckConfig
	AutoRecovery *AutoRecoveryConfig
	Metrics      *MetricsConfig
	Logging      *LoggingConfig
	Dependencies []string
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	Type     string        // "http", "tcp", "process", "script"
	Interval time.Duration
	Timeout  time.Duration
	Retries  int
	HTTPPath string
	HTTPMethod string
	TCPPort  int
	ScriptPath string
}

// AutoRecoveryConfig 自动恢复配置
type AutoRecoveryConfig struct {
	Enabled        bool
	MaxRestarts    int
	RestartDelay   time.Duration
	BackoffFactor  float64
	MaxBackoff     time.Duration
}

// MetricsConfig 指标配置
type MetricsConfig struct {
	Enabled     bool
	Interval    time.Duration
	CollectSystem bool
	CollectService bool
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Directory string
	MaxSize   int64
	MaxFiles  int
	Level     string
}

// IsRunning 检查服务是否运行中
func (s *Service) IsRunning() bool {
	return s.Status == ServiceStatusRunning
}

// IsHealthy 检查服务是否健康
func (s *Service) IsHealthy() bool {
	return s.Health != nil && s.Health.Status == HealthStatusHealthy
}

// UpdateStatus 更新服务状态
func (s *Service) UpdateStatus(status ServiceStatus) {
	s.Status = status
	now := time.Now()
	switch status {
	case ServiceStatusRunning:
		s.StartedAt = &now
	case ServiceStatusStopped, ServiceStatusFailed:
		s.StoppedAt = &now
	}
}

