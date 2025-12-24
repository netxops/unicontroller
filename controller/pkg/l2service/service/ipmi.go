package service

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"

	clitask "github.com/netxops/utils/task"
)

type IPMITaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s IPMITaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s IPMITaskConfig) GetSubOid(key string) string {
	return ""
}
