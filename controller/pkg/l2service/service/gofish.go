package service

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"

	clitask "github.com/netxops/utils/task"
)

type GofishTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s GofishTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s GofishTaskConfig) GetSubOid(key string) string {
	return ""
}
