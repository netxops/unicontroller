package service

import (
	"github.com/influxdata/telegraf/controller/pkg/l2service/model"

	clitask "github.com/netxops/utils/task"
)

type RedfisnInfoTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s RedfisnInfoTaskConfig) NewExecutor(remote *model.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s RedfisnInfoTaskConfig) GetSubOid(key string) string {
	return ""
}
