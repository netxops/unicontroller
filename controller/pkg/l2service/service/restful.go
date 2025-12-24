package service

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"

	clitask "github.com/netxops/utils/task"
)

type RestfulTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s RestfulTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
}

func (s RestfulTaskConfig) GetSubOid(key string) string {
	return ""
}
