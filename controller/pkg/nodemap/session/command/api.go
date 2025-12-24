package command

import (
	//"github.com/netxops/unify/global"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/netxops/utils/tools"
)

//
// type CmdExecuteStatusColor int
//
// const (
// _ CmdExecuteStatusColor = iota
// RED
// YELLOW
// GREEN
// )
//
// func (cc CmdExecuteStatusColor) String() string {
// return []string{"RED", "YELLOW", "GREEN"}[cc-1]
// }

type CmdList interface {
	Table() *tools.Table
	AddCmd(cmd Command)
	Get(key string) (cd *CacheData, err error)
}

type CmdExecuteStatus interface {
	Color() global.CmdExecuteStatusColor
	MainCmds() (cmdList []Command, total, success, failed int)
	Assist() (cmdList []Command, total, success, failed int)
	Error() error
	Cmd(key string) Command
	// Cmds() []Command
	// Time() (begin, end time.Time)
}
