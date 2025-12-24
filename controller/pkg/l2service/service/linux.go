package service

import (
	"github.com/influxdata/telegraf/controller/pkg/l2service/model"

	clitask "github.com/netxops/utils/task"
)

type LinuxTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s LinuxTaskConfig) NewExecutor(remote *model.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s LinuxTaskConfig) GetSubOid(key string) string {
	return ""
}
