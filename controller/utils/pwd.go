package utils

import (
	"os"
	"path/filepath"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/consts"
	"github.com/influxdata/telegraf/controller/global"
)

func CheckWorkspace() {
	if global.Conf.Code == "ExampleCode" {
		return
	}
	pwd, err := os.Executable()
	if err != nil {
		xlog.Default().Panic(err.Error())
	}
	dir := filepath.Join(global.Conf.Workspace, consts.AgentDir)
	if filepath.Dir(pwd) != dir {
		xlog.Default().Error("workspace check failed", xlog.String("current", pwd), xlog.String("def", dir))
		xlog.Default().Panic("the running dir of the agent program is inconsistent with the def of the uniops-agent.toml workspace")
	}
}
