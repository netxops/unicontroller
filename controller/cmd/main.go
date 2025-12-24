package main

import (
	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/initialize"
)

func main() {
	if err := initialize.NewEngine().Run(); err != nil {
		xlog.Default().Panic(err.Error())
	}
}
