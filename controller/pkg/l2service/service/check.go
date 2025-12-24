package service

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"

	clitask "github.com/netxops/utils/task"
)

type CheckTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s CheckTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s CheckTaskConfig) GetSubOid(key string) string {
	return ""
}
