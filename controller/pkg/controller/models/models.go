package models

import (
	"time"
)

type Metric struct {
	Name      string
	Value     float64
	Timestamp int64
	Labels    map[string]string
}

type ServiceInfo struct {
	Key       string                 `json:"key"`
	Name      string                 `json:"name"`
	Address   string                 `json:"address"`
	Protocol  string                 `json:"protocol"`
	Meta      map[string]interface{} `json:"meta"`
	Status    string                 `json:"status"`
	ExpiresAt time.Time              `json:"expires_at"`
}

type AgentAction int

const (
	AgentActionUnknown AgentAction = iota
	AgentActionStart
	AgentActionStop
	AgentActionRestart
)

type ServiceEventType int

const (
	ServiceEventTypeUnknown ServiceEventType = iota
	ServiceEventTypeRegistered
	ServiceEventTypeUpdated
	ServiceEventTypeUnregistered
)

type ServiceEvent struct {
	Type      ServiceEventType
	Service   *ServiceInfo
	Timestamp int64
}

type ResourceType string

const (
	ResourceTypeTelegraf   ResourceType = "telegraf"
	ResourceTypeEtcd       ResourceType = "etcd"
	ResourceTypeAgent      ResourceType = "agent"
	ResourceTypeRegistry   ResourceType = "registry"
	ResourceTypeMinio      ResourceType = "minio"
	ResourceTypeService    ResourceType = "service"
	ResourceTypeContainer  ResourceType = "container"
	ResourceTypeAnsible    ResourceType = "ansible"
	ResourceTypeTemplate   ResourceType = "template"
	ResourceTypeController ResourceType = "controller"
)

type ResourceInfo struct {
	ContainerID string
	Name        string
	Type        ResourceType
	Status      string
	Metadata    map[string]string
	Ports       map[string]string
	LastUpdated time.Time
}

// Log represents a single log entry
type Log struct {
	Timestamp time.Time         `json:"timestamp"`
	Labels    map[string]string `json:"labels"`
	Message   string            `json:"message"`
}

type LogConfig struct {
	Paths        []string          `json:"paths"`
	ExcludePaths []string          `json:"exclude_paths,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Format       string            `json:"format,omitempty"`
	MaxSize      int64             `json:"max_size,omitempty"`
	MaxAge       int               `json:"max_age,omitempty"`
	MaxBackups   int               `json:"max_backups,omitempty"`
	Compress     bool              `json:"compress,omitempty"`
}

type ResourceStatus string

const (
	ResourceStatusUnknown    ResourceStatus = "unknown"
	ResourceStatusCreated    ResourceStatus = "created"
	ResourceStatusStarting   ResourceStatus = "starting"
	ResourceStatusRunning    ResourceStatus = "running"
	ResourceStatusPaused     ResourceStatus = "paused"
	ResourceStatusRestarting ResourceStatus = "restarting"
	ResourceStatusRemoving   ResourceStatus = "removing"
	ResourceStatusExited     ResourceStatus = "exited"
	ResourceStatusDead       ResourceStatus = "dead"
	ResourceStatusStopped    ResourceStatus = "stopped"
	ResourceStatusFailed     ResourceStatus = "failed"
	ResourceStatusDegraded   ResourceStatus = "degraded"
)

type ControllerStatus struct {
	ControllerID string    `json:"controller_id"`
	StartTime    time.Time `json:"start_time"`
	Version      string    `json:"version"`
	FunctionArea string    `json:"function_area"`
	SystemInfo   struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
	} `json:"system_info"`
	MongoDBStatus string `json:"mongodb_status"`
	EtcdStatus    string `json:"etcd_status"`
}

type ServiceName string

const (
	ServiceNameTelegraf   ServiceName = "telegraf"
	ServiceNameEtcd       ServiceName = "etcd"
	ServiceNameAgent      ServiceName = "agent"
	ServiceNameRegistry   ServiceName = "registry"
	ServiceNameMinioProxy ServiceName = "minio"
	ServiceNameController ServiceName = "controller"
	ServiceNameAnsible    ServiceName = "ansible"
	ServiceNameSyslog     ServiceName = "syslog"
	ServiceNameMetrics    ServiceName = "metrics"
	ServiceNameGrpcProxy  ServiceName = "grpc_proxy"
	ServiceNameJumper     ServiceName = "jumper"
	// 如果还有其他服务，可以继续添加
)

// IsValidServiceName 检查给定的服务名称是否有效
func IsValidServiceName(name string) bool {
	switch ServiceName(name) {
	case ServiceNameTelegraf, ServiceNameEtcd, ServiceNameAgent,
		ServiceNameRegistry, ServiceNameMinioProxy, ServiceNameController, ServiceNameAnsible,
		ServiceNameSyslog, ServiceNameMetrics:
		return true
	default:
		return false
	}
}
