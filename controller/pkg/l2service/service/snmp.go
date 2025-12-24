package service

import (
	"github.com/influxdata/telegraf/controller/pkg/structs"

	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"

	"github.com/mohae/deepcopy"
)

type SnmpTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
	Oid            string `yaml:"oid" mapstructure:"oid"`

	OidMap    map[string]string `yaml:"oidmap"  mapstructure:"oidmap"`
	IndexAll  []int             `yaml:"indexall" mapstructure:"indexall"`
	Prefix    []int             `yaml:"prefix" mapstructure:"prefix"`
	PrefixMap map[string]string `yaml:"prefixmap" mapstructure:"prefixmap"`
}

// func (s SnmpTaskConfig) NewSSHTask(remote *structs.L2DeviceRemoteInfo) (*terminal.Execute, error) {
// return nil, nil
// }

// func (s SnmpTaskConfig) NewSnmpTask(host, community string) *snmp.SnmpTask {
// return &snmp.SnmpTask{
// Host:      host,
// Community: community,
// Oid:       s.Oid,
// IndexAll:  deepcopy.Copy(s.IndexAll).([]int),
// Prefix:    deepcopy.Copy(s.Prefix).([]int),
// PrefixMap: deepcopy.Copy(s.PrefixMap).(map[string]string),
// }
// }
//

func (s SnmpTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return &snmp.SnmpTask{
		Host:      remote.Ip,
		Community: remote.Community[0],
		Oid:       s.Oid,
		IndexAll:  deepcopy.Copy(s.IndexAll).([]int),
		Prefix:    deepcopy.Copy(s.Prefix).([]int),
		PrefixMap: deepcopy.Copy(s.PrefixMap).(map[string]string),
	}, nil
}

func (s SnmpTaskConfig) GetSubOid(key string) string {
	return s.OidMap[key]
}

//
// func (s SnmpTaskConfig) NewRedfishTask(remote *structs.L2DeviceRemoteInfo) *redfish.RedfishTask {
// return nil
// }
