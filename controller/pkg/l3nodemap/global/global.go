package global

import (
	"github.com/netxops/log"
	"go.uber.org/zap"
)

var (
	logger = log.NewLogger(nil, true).Logger
	// metaNodeMap map[string]meta.MetaNodeMap
)

func GetLogger() *zap.Logger {
	return logger
}

// func GetNodeMaps() map[string]meta.MetaNodeMap {
// 	return metaNodeMap
// }

// func InitNodeMaps(mnm map[string]meta.MetaNodeMap) {
// 	if len(metaNodeMap) != 0 {
// 		panic("l3 maybe have a dirty data and it can't be initialized")
// 	}
// 	metaNodeMap = mnm
// }
