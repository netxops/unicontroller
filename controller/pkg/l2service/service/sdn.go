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

type SdnTaskConfig struct {
	BaseTaskConfig `mapstructure:",squash"`
}

func (s SdnTaskConfig) NewExecutor(remote *structs.L2DeviceRemoteInfo) (clitask.Executor, error) {
	return nil, nil
	// return &redfish.RedfishTask{}
}

func (s SdnTaskConfig) GetSubOid(key string) string {
	return ""
}

type SDN struct{}

func (sdn *SDN) SdnMainService(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	var err error
	session := NewWorkContext(sdn, args)
	logger := log.NewLogger(args.Remote.ActionID, true)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	switch args.ServiceType {
	case structs.SDN_FABRIC:
		result, err = session.sdnFabric(args)
	case structs.SDN_VPC:
		result, err = session.sdnVpc(args)
	case structs.SDN_LOGICROUTER:
		result, err = session.sdnLogicRouter(args)
	case structs.SDN_LOGICSWITCH:
		result, err = session.sdnLogicSwitch(args)
	case structs.SDN_LOGICPORT:
		result, err = session.sdnLogicPort(args)
	case structs.SDN_DEVICE:
		result, err = session.sdnDevice(args)
	case structs.SDN_DEVICEPORT:
		result, err = session.sdnDevicePort(args)
	case structs.SDN_SUBNET:
		result, err = session.sdnSubnet(args)
	case structs.SDN_CREATEPORT:
		result, err = session.sdnCreatePort(args)
	case structs.SDN_DELETEPORT:
		result, err = session.sdnDeletePort(args)
	case structs.SWITCH_CONFIG:
		result, err = session.switchConfig(args)
	case structs.SWITCH_CONFIG_TERMINAL:
		result, err = session.switchConfigTerminal(args)
	case structs.SWITCH_CONFIG_WITH_COMMAND:
		result, err = session.switchConfigWithCommand(args)
	default:
		err = fmt.Errorf("unsupport servie type = %s, ip = %s", args.ServiceType, args.Ip)
		logger.Warn("SDN ", zap.Any("error", err))
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

	logger.Debug("SdnMainService TOPO",
		// zap.Any("id", session.Uuid),
		zap.Any("args", args),
		// zap.Any("method", "TOPO"),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *WorkContext) sdnFabric(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "fabric")
}

func (ts *WorkContext) sdnVpc(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "vpc")
}

func (ts *WorkContext) sdnLogicRouter(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "logic_router")
}

func (ts *WorkContext) sdnLogicSwitch(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "logic_switch")
}

func (ts *WorkContext) sdnLogicPort(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "logic_port")
}

func (ts *WorkContext) sdnDevice(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "device")
}

func (ts *WorkContext) sdnDevicePort(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "device_port")
}

func (ts *WorkContext) sdnSubnet(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "subnet")
}

func (ts *WorkContext) sdnCreatePort(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "create_port")
}

func (ts *WorkContext) sdnDeletePort(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "delete_port")
}

func (ts *WorkContext) switchConfig(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_config")
}

func (ts *WorkContext) switchConfigTerminal(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_config_terminal")
}

func (ts *WorkContext) switchConfigWithCommand(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_config_with_command")
}

func (ts *WorkContext) switchExec(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_exec")
}

func (ts *WorkContext) switch_version(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_version")
}
func (ts *WorkContext) switch_exec_timeout(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_exec_timeout")
}
func (ts *WorkContext) switch_snmp_version(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_snmp_version")
}
func (ts *WorkContext) switch_reboot(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_reboot")
}
func (ts *WorkContext) switch_patch_version(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_patch_version")
}

func (ts *WorkContext) switch_dir(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_dir")
}

func (ts *WorkContext) switch_status(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_status")
}

func (ts *WorkContext) switch_install(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_install")
}
func (ts *WorkContext) switch_install_hotfix(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_install_hotfix")
}

func (ts *WorkContext) switch_boot(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_boot")
}

func (ts *WorkContext) switch_impact(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_impact")
}
func (ts *WorkContext) switch_import(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_import")
}
func (ts *WorkContext) switch_exec_map(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_exec_map")
}
