package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/influxdata/telegraf/controller/global"

	//"github.com/netxops/unify/global"
	"github.com/netxops/utils/tools"

	"github.com/redis/go-redis/v9"
)

type CliCmd struct {
	cmd       string
	key       string
	ip        string
	timeout   int
	Force     bool
	cacheData *CacheData
	msg       string
	level     CommandLevel
	ok        bool
}

func NewCliCmd(cmd, key string, timeout int, force bool) *CliCmd {
	return &CliCmd{
		cmd:     cmd,
		key:     key,
		timeout: timeout,
		Force:   force,
	}
}

func (cc *CliCmd) WithOk(ok bool) {
	cc.ok = ok
}

func (cc *CliCmd) Ok() bool {
	return cc.ok
}

func (cc *CliCmd) WithLevel(level CommandLevel) {
	cc.level = level
}

func (cc *CliCmd) Level() CommandLevel {
	return cc.level
}

func (cc *CliCmd) WithIp(ip string) *CliCmd {
	cc.ip = ip
	return cc
}

func (cc *CliCmd) Cmd() string {
	return cc.cmd
}

func (cc *CliCmd) Key() string {
	return cc.key
}

func (cc *CliCmd) Msg() string {
	return cc.msg
}

func (cc *CliCmd) WithMsg(msg string) {
	cc.msg = msg
}

func (cc *CliCmd) Timeout() int {
	return cc.timeout
}

func (cc *CliCmd) Id(ip string) string {
	return fmt.Sprintf("%s_%s_%s", ip, cc.Cmd(), cc.Key())
}

func (cc *CliCmd) SetCacheData(data *CacheData) {
	cc.cacheData = data
}

func (cc *CliCmd) CacheData() *CacheData {
	return cc.cacheData
}

func (cc *CliCmd) Ip() string {
	return cc.ip
}

type CliCmdList struct {
	Cmds  []Command `json:"Cmds"`
	Ip    string    `json:"Ip"`
	Force bool      `json:"Force"`
}

func NewCliCmdList(ip string, force bool) *CliCmdList {
	return &CliCmdList{
		Cmds:  []Command{},
		Ip:    ip,
		Force: force,
	}
}

func (cl *CliCmdList) Table() *tools.Table {
	table := tools.Table{}
	for _, cmd := range cl.Cmds {
		row := map[string]interface{}{}
		row["Cmd"] = cmd.(*CliCmd).Cmd
		row["Ip"] = cmd.(*CliCmd).Ip
		row["Key"] = cmd.Key()

		table.Push(row)
	}

	return &table
}

func (cl *CliCmdList) AddCmd(cmd Command) {
	if cl.KeyExist(cmd.Key()) {
		return
	}
	cl.Cmds = append(cl.Cmds, cmd)
}

func (cl *CliCmdList) Add(cmd, key string, timeout int, force bool) {
	if cl.KeyExist(key) {
		return
	}
	c := NewCliCmd(cmd, key, timeout, force)
	cl.Cmds = append(cl.Cmds, c)

}

func (cl *CliCmdList) KeyExist(key string) bool {
	for _, cmd := range cl.Cmds {
		if cmd.Key() == key {
			return true
		}
	}
	return false
}

func (cl *CliCmdList) Id(ip string) string {
	return ""
}

func (cl *CliCmdList) Get(key string) (cd *CacheData, err error) {
	id := ""
	for _, cmd := range cl.Cmds {
		if cmd.Key() == key {
			id = cmd.Id(cl.Ip)
		}
	}

	if id == "" {
		err = fmt.Errorf("can not find command key: %s", key)
		return
	}

	cd = &CacheData{}
	client := global.Redis
	if client == nil {
		err = errors.New("redis client is nil")
		return
	}

	var val string
	val, err = client.Get(context.Background(), id).Result()
	if err == redis.Nil {
		return
	} else if err != nil {
		return
	}

	if val == "" {
		return
	}

	byteData := []byte(val)

	err = json.Unmarshal(byteData, cd)
	if err != nil {
		return
	}
	return
}

// Color() CmdExecuteStatusColor
// MainCmds() (cmdList []Command, total, success, failed int)
// Assist() (cmdList []Command, total, success, failed int)
// Cmds() []Command
// Time() (begin, end time.Time)

func (cl *CliCmdList) Color() global.CmdExecuteStatusColor {
	color := global.GREEN
	for _, cmd := range cl.Cmds {
		if cmd.Level() == MUST && !cmd.Ok() {
			return global.RED
		}
		if cmd.Level() == OPTION && !cmd.Ok() {
			color = global.YELLOW
		}
	}

	return color
}

func (cl *CliCmdList) Cmd(key string) Command {
	for _, cmd := range cl.Cmds {
		if cmd.Key() == key {
			return cmd
		}
	}

	return nil
}

func (cl *CliCmdList) MainCmds() (cmdList []Command, total, success, failed int) {
	for _, cmd := range cl.Cmds {
		if cmd.Level() == MUST {
			cmdList = append(cmdList, cmd)
			if cmd.Ok() {
				success++
			} else {
				failed++
			}

		}
	}

	total = len(cmdList)

	return
}

func (cl *CliCmdList) Assist() (cmdList []Command, total, success, failed int) {
	for _, cmd := range cl.Cmds {
		if cmd.Level() == OPTION {
			cmdList = append(cmdList, cmd)
			if cmd.Ok() {
				success++
			} else {
				failed++
			}

		}
	}

	total = len(cmdList)

	return
}

func (cl *CliCmdList) Error() error {
	for _, cmd := range cl.Cmds {
		if !cmd.Ok() {
			return errors.New(cmd.Msg())
		}
	}
	return nil
}
