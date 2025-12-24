package session

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"

	//"github.com/netxops/unify/global"
	"github.com/netxops/utils/snmp"

	"go.uber.org/zap"
)

type SnmpSession struct {
	Session
	Info *DeviceBaseInfo
	log  *zap.Logger
}

func NewSnmpSession(info *DeviceBaseInfo) *SnmpSession {
	log := zap.NewNop()
	if info.Community == "" {
		log.Error("community is empty", zap.Any("BaseInfo", info))
		panic("community is empty")
	}

	return &SnmpSession{
		Info: info,
		log:  log,
	}
}

func (ss *SnmpSession) Run(cmd *command.SnmpCmd) (*command.CacheData, error) {
	var cd *command.CacheData
	if !cmd.Force {
		cd, err := ss.Session.Get(ss.Info.BaseInfo.Host, cmd)
		if cd != nil {
			if !cd.IsTimeout() {
				ss.log.Info("using cache data, ", zap.Any("id", cmd.Id(ss.Info.BaseInfo.Host)))
				return cd, err
			}
		}
	}

	plan := cmd.Plan

	st, err := snmp.NewSnmpTask(
		ss.Info.BaseInfo.Host,
		ss.Info.Community,
		cmd.Oid,
		plan.Index,
		plan.Prefix,
		plan.PrefixMap,
		plan.PrefixCallMap,
		plan.IndexCall)
	if err != nil {
		return nil, err
	}
	result := st.Run(true)
	if result.Error() != nil {
		return nil, result.Error()
	}

	if len(result.Output) > 1 || len(result.Output[0].Value) > 1 {
		ss.log.Info("multiple result, there can be some error")
	}

	cd = command.NewCacheData([]byte(result.Output[0].Value[0]))
	cmd.SetCacheData(cd)
	return cd, nil
}
