package initialize

import (
	"path/filepath"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/glebarez/sqlite"
	"github.com/influxdata/telegraf/controller/consts"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/model"
	"gorm.io/gorm"
)

func NewDatabase() {
	// sqlite 驱动替换为纯 Golang 实现，避免了因为 CGO 依赖导致的跨平台问题，性能需验证。
	dsn := filepath.Join(global.Conf.Workspace, consts.AgentDir, consts.DatabaseFile)
	if global.Conf.UseDebugDb {
		dsn = filepath.Join("./", consts.DatabaseFile)
		xlog.Default().Warn("debug is enabled, overwrite dsn path", xlog.String("dsn", dsn))
		xlog.Default().Error("!!!调试模式已启用（实机环境请勿开启以避免导致不可预料的问题）!!!")
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		xlog.Default().Panic("failed init gorm conn", xlog.FieldErr(err))
	}
	if err = db.AutoMigrate(&model.Schema{}); err != nil {
		xlog.Default().Panic("failed auto migrate database table", xlog.FieldErr(err))
	}
	global.DB = db
}
