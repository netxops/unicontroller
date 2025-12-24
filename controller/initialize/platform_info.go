package initialize

import (
	"context"
	"encoding/json"
	"time"

	"github.com/douyu/jupiter/pkg/client/etcdv3"
	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/types"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func InitPlatformInfo() {
	info := &types.PlatformInfo{}
	client := etcdv3.StdConfig("default").MustBuild()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	resp, err := client.Get(ctx, "/UniOPS-PLATFORM", clientv3.WithPrefix())
	if err != nil || resp == nil || len(resp.Kvs) == 0 {
		xlog.Default().Error("failed get uniops platform info from etcd")
		global.PlatformInfo = info
		return
	}
	if err = json.Unmarshal(resp.Kvs[0].Value, info); err != nil {
		xlog.Default().Error("failed parse uniops platform info")
	}
	global.PlatformInfo = info
	xlog.Default().Info("platform info", xlog.Any("info", info))
	return
}
