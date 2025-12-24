package service

import (
	"context"
	"fmt"
	"time"

	"github.com/netxops/log"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"go.uber.org/zap"

	clitask "github.com/netxops/utils/task"
)

type VmwareTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s VmwareTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s VmwareTaskConfig) GetSubOid(key string) string {
	return ""
}

type VMWARE struct{}

func (vm *VMWARE) VmwareMainService(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	var err error
	logger := log.NewLogger(args.Remote.ActionID, true)
	session := NewWorkContext(vm, args)
	logger.Debug("VMWARE", zap.Any("args", args))

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType

	switch args.ServiceType {
	case structs.VMWARE_RESOURCES:
		result, err = session.resources(args)
	case structs.VMWARE_VM:
		result, err = session.vm(args)
	case structs.VMWARE_TEMPLATE:
		result, err = session.template(args)
	case structs.VMWARE_DATASTORE:
		result, err = session.datastore(args)
	case structs.VMWARE_INFO:
		result, err = session.info(args)
	case structs.VMWARE_HOST:
		result, err = session.vmhost(args)
	case structs.VMWARE_CLUSTER:
		result, err = session.vmcluster(args)
	case structs.VMWARE_INTERFACES:
		result, err = session.interfaces(args)
	case structs.VMHOST_BASE_VALUE:
		result, err = session.host_base_value(args)
	case structs.VMWARE_IPDATA:
		result, err = session.vmware_ip_data(args)
	default:
		logger.Error("unknown function selector:", zap.Any("serviceType", args.ServiceType))
		reply.Table = &clitask.Table{}
		reply.Error = err
		return fmt.Errorf("unknown function selector: '%s'", args.ServiceType)
		//panic(fmt.Sprintf("unknown function selector: '%s'", args.ServiceType))
	}
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	return err
}
