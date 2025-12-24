package global

// import (
// 	"github.com/influxdata/telegraf/controller/pkg/l2service/config"
// 	exp "github.com/netxops/l2service/internal/app/exception/service/impl"

//	"github.com/redis/go-redis/v9"
//	"github.com/spf13/viper"
//	"go.uber.org/zap"
//	"gorm.io/gorm"
//
// )
// var GVA_REDIS *redis.Client

// var (
// 	GVA_DB     *gorm.DB
// 	GVA_REDIS  *redis.Client
// 	GVA_CONFIG config.Server
// 	GVA_VP     *viper.Viper
// 	//GVA_LOG    *oplogging.Logger
// 	GVA_LOG *zap.Logger
// 	// GVA_LOG         *zap.SugaredLogger
// 	GVA_DESCRIBE           config.Infor
// 	GVA_PLUGIN_DESC        config.PluginInfor
// 	GVA_DESC               config.Desc
// 	GVA_SQLite             *gorm.DB
// 	GVA_EXCEPTION_RECORDER *exp.SimpleExceptionRecorder
// 	// GVA_Register    Register
// 	//CONFIG          *config.Server // 总配置信息
// 	//DB              *gorm.DB
// 	//RDB             *redis.Client
// )

// type CmdExecuteStatusColor int

// const (
// 	_ CmdExecuteStatusColor = iota
// 	RED
// 	YELLOW
// 	GREEN
// )

// func (cc CmdExecuteStatusColor) String() string {
// 	// return []string{"RED", "YELLOW", "GREEN"}[cc-1]
// 	return []string{"执行失败", "基本成功", "执行成功"}[cc-1]
// }
