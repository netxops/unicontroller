package controller

import (
	"github.com/docker/docker/api/types"
)

type ServiceInfo struct {
	ID      string
	Name    string
	Image   string
	Status  string
	Ports   []types.Port
	Volumes []string
	Env     []string
}

type Manager interface {
	Start() error
	Stop() error
}

type ConfigProvider interface {
	GetConfig(serviceName string) (map[string]interface{}, error)
	SetConfig(serviceName string, config map[string]interface{}) error
}

type ResourceProvider interface {
	GetServiceInfo(serviceName string) (*ServiceInfo, error)
	StartService(serviceName string) error
	StopService(serviceName string) error
	RestartService(serviceName string) error
}
