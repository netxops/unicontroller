package service

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"

	clitask "github.com/netxops/utils/task"
)

type RshellTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s RshellTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s RshellTaskConfig) GetSubOid(key string) string {
	return ""
}
