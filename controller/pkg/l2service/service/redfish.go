package service

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"

	clitask "github.com/netxops/utils/task"
)

type RedfishTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s RedfishTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s RedfishTaskConfig) GetSubOid(key string) string {
	return ""
}
