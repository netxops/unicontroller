package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/influxdata/telegraf/controller/global"

	//"github.com/netxops/unify/global"
	"strings"

	"github.com/netxops/utils/tools"

	"github.com/redis/go-redis/v9"
)

type HttpCmd struct {
	Method    string
	Ip        string
	Url       string
	key       string
	timeout   int
	Data      []byte
	cacheData *CacheData
	Force     bool
	msg       string
	level     CommandLevel
	ok        bool
}

func (cmd HttpCmd) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Method string `json:"method"`
		Url    string `json:"url"`
		Data   string `json:"data"`
		Msg    string `json:"msg"`
	}{
		Method: cmd.Method,
		Url:    cmd.Url,
		Data:   string(cmd.Data),
		Msg:    cmd.Msg(),
	})
}

func NewHttpCmd(method, url, key string, timeout int, force bool) *HttpCmd {
	return &HttpCmd{
		Method:  method,
		Url:     url,
		key:     key,
		timeout: timeout,
		Force:   force,
	}
}

func (hc *HttpCmd) WithOk(ok bool) {
	hc.ok = ok
}

func (hc *HttpCmd) Ok() bool {
	return hc.ok
}

func (hc *HttpCmd) WithLevel(level CommandLevel) {
	hc.level = level
}

func (hc *HttpCmd) Level() CommandLevel {
	return hc.level
}

func (hc *HttpCmd) WithIp(ip string) *HttpCmd {
	hc.Ip = ip
	return hc
}

func (hc *HttpCmd) WithData(data []byte) *HttpCmd {
	hc.Data = make([]byte, len(data))
	copy(hc.Data, data)
	return hc
}

func (hc *HttpCmd) Id(ip string) string {
	return fmt.Sprintf("%s_%s_%s", ip, hc.Url, hc.Key())
}

func (hc *HttpCmd) SetCacheData(data *CacheData) {
	hc.cacheData = data
}

func (hc *HttpCmd) WithMsg(msg string) {
	hc.msg = msg
}

func (hc *HttpCmd) CacheData() *CacheData {
	return hc.cacheData
}

func (hc *HttpCmd) Cmd() string {
	byteS, err := json.Marshal(&struct {
		Method string
		Url    string
		Data   string
	}{
		Method: hc.Method,
		Url:    hc.Url,
		Data:   string(hc.Data),
	})
	if err != nil {
		panic(err)
	}
	return string(byteS)
}

func (hc *HttpCmd) Msg() string {
	return hc.msg
}

func (hc *HttpCmd) Timeout() int {
	return hc.timeout
}

func (hc *HttpCmd) Key() string {
	return hc.key
}

//
// func (hc *HttpCmd) IsCacheTimeout() bool {
// if hc.CacheData == nil {
// return true
// } else {
// return hc.CacheData.IsTimeout()
// }
// }

type HttpCmdList struct {
	Clis  []string  `json:"clis"`
	Cmds  []Command `json:"Cmds"`
	Ip    string    `json:"Ip"`
	Force bool      `json:"Force"`
}

func NewHttpCmdList(ip string, force bool) *HttpCmdList {
	return &HttpCmdList{
		Cmds:  []Command{},
		Ip:    ip,
		Force: force,
	}
}

// Method    string     `json:"method"`
// Ip        string     `json:"ip"`
// Url       string     `json:"url"`
// Key       string     `json:"key"`
// Timeout   int        `json:"timeout"`
// Data      []byte     `json:"data"`
// CacheData *CacheData `json:"cache_data"`
// Force     bool       `json:"force"`
// Msg       string     `json:"msg"`
// Ip    string     `json:"Ip"`
// Force bool       `json:"Force"`

func (cl *HttpCmdList) Table() *tools.Table {
	table := tools.Table{}

	for _, cmd := range cl.Cmds {
		row := map[string]interface{}{}
		row["IP"] = cl.Ip
		// row["Method"] = cmd.Method
		row["Url"] = cmd.(*HttpCmd).Url
		// row["Key"] = cmd.Key
		row["Data"] = string(cmd.(*HttpCmd).Data)

		table.Push(row)
	}

	return &table
}

func (cl *HttpCmdList) AddCmd(cmd Command) {
	cl.Cmds = append(cl.Cmds, cmd)
}

func (cl *HttpCmdList) Add(method, url string, data []byte, timeout int, force bool) {
	// c := NewCli(cmd, key, timeout, force)
	key := "POST_" + strings.ReplaceAll(url, "/", "_")
	c := NewHttpCmd(method, url, key, timeout, force)
	c.WithData(data)
	cl.Cmds = append(cl.Cmds, c)
}

func (cl *HttpCmdList) AddCli(cli string) {
	if cli != "" {
		cl.Clis = append(cl.Clis, cli)
	}
}

func (cl *HttpCmdList) Id(ip string) string {
	return ""
}

func (cl *HttpCmdList) Get(key string) (cd *CacheData, err error) {
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

func (cl *HttpCmdList) Color() global.CmdExecuteStatusColor {
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

func (cl *HttpCmdList) MainCmds() (cmdList []Command, total, success, failed int) {
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

func (cl *HttpCmdList) Assist() (cmdList []Command, total, success, failed int) {
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

func (cl *HttpCmdList) Error() error {
	for _, cmd := range cl.Cmds {
		if !cmd.Ok() {
			return errors.New(cmd.Msg())
		}
	}
	return nil
}

func (cl *HttpCmdList) Cmd(key string) Command {
	for _, cmd := range cl.Cmds {
		if cmd.Key() == key {
			return cmd
		}
	}

	return nil
}
