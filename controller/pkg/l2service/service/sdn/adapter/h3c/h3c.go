package h3c

import (
	clitask "github.com/netxops/utils/task"

	"github.com/influxdata/telegraf/controller/pkg/structs"
)

type H3CSDN struct{}

func (s *H3CSDN) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	// func (s *H3CSDN) Process(remote *combin.DeviceRemoteInfo, taskConfig api.L2NodemapTaskConfigInterface) (result *clitask.Table, err error) {

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}
	return
}
