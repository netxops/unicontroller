package global

import (
	"github.com/douyu/jupiter/pkg/server"
	"github.com/influxdata/telegraf/controller/config"
	"github.com/influxdata/telegraf/controller/types"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

var (
	Conf *config.Config
	DB   *gorm.DB
	// PacksCache   map[string]*model.Schema
	MachineAddr  []string
	PlatformInfo *types.PlatformInfo
	AgentINFO    *server.ServiceInfo
	Redis        *redis.Client
)

type CmdExecuteStatusColor int

const (
	_ CmdExecuteStatusColor = iota
	RED
	YELLOW
	GREEN
)

func (cc CmdExecuteStatusColor) String() string {
	// return []string{"RED", "YELLOW", "GREEN"}[cc-1]
	return []string{"执行失败", "基本成功", "执行成功"}[cc-1]
}
