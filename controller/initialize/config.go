package initialize

import (
	"github.com/douyu/jupiter/pkg/conf"
	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/config"
	"github.com/influxdata/telegraf/controller/global"
)

func NewConfig() {
	var cfg config.Config
	if err := conf.UnmarshalKey("jupiter.runtime.config", &cfg); err != nil {
		xlog.Default().Panic(err.Error())
	}
	global.Conf = &cfg
}
