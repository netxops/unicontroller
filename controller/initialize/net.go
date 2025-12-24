package initialize

import (
	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/utils"
)

func InitMachineAddress() {
	address, err := utils.GetIPAddress()
	if err != nil {
		xlog.Default().Panic("failed get machine ip address", xlog.FieldErr(err))
	}
	global.MachineAddr = address
}
