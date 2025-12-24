package service

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/k-sone/ipmigo"
	"github.com/netxops/log"
	"github.com/netxops/utils/reachable"
	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/tools"
	"go.uber.org/zap"
)

const (
// REDFISH_CPU          = "REDFISH_CPU"
// REDFISH_MEM          = "REDFISH_MEM"
// REDFISH_DISK         = "REDFISH_DISK"
// REDFISH_BMC          = "REDFISH_BMC"
// REDFISH_NETWORKINTERFACE = "REDFISH_NETWORKINTERFACE"
// REDFISH_NETWORK      = "REDFISH_NETWORK"
// REDFISH_VERSION      = "REDFISH_VERSION"
// REDFISH_BASEINFO     = "REDFISH_BASEINFO"
// REDFISH_POWER        = "REDFISH_POWER"

// REDFISH_CPU              = "RedfishCpu"
// REDFISH_MEM              = "RedfishMem"
// REDFISH_DISK             = "RedfishDisk"
// REDFISH_BMC              = "RedfishBmc"
// REDFISH_NETWORKINTERFACE = "RedfishNetworkinterface"
// REDFISH_NETWORK          = "RedfishNetwork"
// REDFISH_VERSION          = "RedfishVersion"
// REDFISH_BASEINFO         = "RedfishBaseInfo"
// REDFISH_POWER            = "RedfishPower"
// OOB_VERSION              = "OOBVersion"
)

var oobLogger *zap.Logger

func init() {
	oobLogger, _ = zap.NewDevelopment(zap.AddCallerSkip(1))
}

type SERVEROOB struct{}

func (ts *WorkContext) base2(arg *structs.Args, serviceType string) (*clitask.Table, error) {
	logger := log.NewLogger(arg.Remote.ActionID, true)

	var resultTable *clitask.Table
	var err error
	remote := arg.Remote
	meta := arg.Meta
	if meta != nil && (meta.Meta.Enable == nil || !*meta.Meta.Enable) {
		if arg.IsRedfish && remote.RedfishVersion != "" {

		} else {
			err = fmt.Errorf("Meta is disable, ip=%s", arg.Ip)
			logger.Debug("TOPO", zap.Any("phase", "检查Meta状态"), zap.Error(err))
			return resultTable, err
		}
	}

	logger.Debug(
		"TOPO",
		zap.Any("phase", "获取远程连接信息"),
		log.Tag("remote", remote),
	)

	// remote.WithTaskId(ts.Uuid)
	l2nodemapService, desc := Config.Select(context.TODO(), remote, serviceType)
	if !desc.Ok() {
		err = desc.Error()
		return resultTable, err
	}
	if l2nodemapService == nil {
		err = fmt.Errorf("service Select failed, manufacturer:%s, platform:%s, redfish:%t,servicetype:%s", remote.Manufacturer, remote.Platform, remote.IsRedfish, serviceType)
		logger.Error("TOPO", zap.Any("method", "Select"), zap.Error(err))
		return resultTable, err
	}
	logger.Debug("TOPO", zap.Any("method", "Select"), zap.Any("serviceName", l2nodemapService.ServiceName()))
	resultTable, err = l2nodemapService.Run(remote, arg.Options...)
	if err != nil {
		logger.Error("TOPO", zap.Any("method", "RUN"), zap.Any("serviceName", l2nodemapService.ServiceName()), zap.Error(err))
		return resultTable, err
	}

	if resultTable == nil || resultTable.IsEmpty() {
		logger.Debug("TOPO", zap.Any("count", 0))
		return resultTable, nil
	} else {
		logger.Debug("TOPO", zap.Any("count", resultTable.RowCount()))
		return resultTable, nil
	}
}

func (ts *WorkContext) cpu2(arg *structs.Args) (*clitask.Table, error) {
	return ts.base2(arg, "cpu")
}

func CheckRedfishVersion2(remote *structs.L2DeviceRemoteInfo) (result string, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	if tools.IsContain([]string{"h3c"}, strings.ToLower(remote.Manufacturer)) {
		if len(remote.Community) != 0 {
			st, err := snmp.NewSnmpTask(
				remote.Ip,
				remote.Community[0],
				"1.3.6.1.4.1.25506.13.1.2.2.7.1",
				[]int{1},
				[]int{0},
				map[string]string{"0": "version"},
				map[string]func(byte, string, interface{}) (string, error){},
				nil)

			st.Run(true)
			table, err := st.Table()
			if err != nil {
				logger.Warn("h3c snmp获取Redfish版本失败,尝试其他方法", zap.Any("error", err))
			} else {
				result, ok := table.IndexToValue("version", "0")
				if ok != true {
					err := errors.New("Snmp方式获取h3c Redfish版本失败")
					logger.Warn("CheckRedfishVersion2", zap.Any("error", err))
					// return "", err
				} else {
					result = strings.TrimSpace(strings.Split(result, " ")[0])
					// logger.Debug("check version ok ", zap.Any("result", result))
					return result, nil
				}
			}
		}
	} else if tools.IsContain([]string{"hp"}, strings.ToLower(remote.Manufacturer)) {
		if len(remote.Community) != 0 {
			st, err := snmp.NewSnmpTask(
				remote.Ip,
				remote.Community[0],
				".1.3.6.1.4.1.232.11.2.14.1.1.5",
				[]int{1},
				[]int{0},
				map[string]string{"0": "version"},
				map[string]func(byte, string, interface{}) (string, error){},
				nil)

			st.Run(true)
			table, err := st.Table()
			if err != nil {
				logger.Warn("hp snmp获取Redfish版本失败,尝试其他方法", zap.Error(err))
			} else {
				result, ok := table.IndexToValue("version", "0")
				if ok != true {
					err := errors.New("Snmp方式获取hp Redfish版本失败")
					logger.Warn("hp Snmp 获取版本失败table.IndexToValue failed", zap.Error(err))
					// return "", err
				} else {
					result = strings.TrimSpace(strings.Split(result, " ")[0])
					// logger.Info("check version ok ", zap.Any("result", result))
					return result, nil
				}
			}
		} else {
			logger.Warn("snmp获hp取Redfish版本失败,Community为空,尝试其他方法")
		}
	} else if tools.IsContain([]string{"ibm"}, strings.ToLower(remote.Manufacturer)) {
		if len(remote.Community) != 0 {
			st, err := snmp.NewSnmpTask(
				remote.Ip,
				remote.Community[0],
				".1.3.6.1.4.1.25506.13.1.2.2.7.1",
				[]int{1},
				[]int{0},
				map[string]string{"0": "version"},
				map[string]func(byte, string, interface{}) (string, error){},
				nil)

			st.Run(true)
			table, err := st.Table()
			if err != nil {
				logger.Warn("ibm snmp获取Redfish版本失败,尝试其他方法", zap.Error(err))
			} else {
				result, ok := table.IndexToValue("version", "0")
				if ok != true {
					err := errors.New("Snmp方式获取ibm Redfish版本失败")
					logger.Warn("ibm snmp获取Redfish版本失败table.IndexToValue failed,尝试其他方法", zap.Error(err))

					// return "", err
				} else {
					result = strings.TrimSpace(strings.Split(result, " ")[0])
					// logger.Info("check version ok ", zap.Any("result", result))
					return result, nil
				}
			}
		} else {
			// logger.Info("hp commuinty 为空", zap.Any("remote", remote.Community), zap.Any("remote.Manufacturer", remote.Manufacturer))
			logger.Warn("snmp获取ibm Redfish版本失败,Community为空")

		}
	}
	// else if tools.IsContain([]string{"lenovo"}, strings.ToLower(remote.Manufacturer)) {
	//	server := redfishClient(remote)
	//	defer server.OutC.Logout()
	//	result = gofishRedfishVersionV1Collect(remote, server)
	//	return result
	// }
	server, err := redfishClient2(remote)
	if err == nil {
		result = server.GetRedfishVersion()
		result = strings.TrimSpace(result)
		if result != "" {
			return result, nil
		} else {
			logger.Error("Redfish和SNMP获取Redfish版本失败", zap.Error(err), log.Tag("remote", remote))
			return result, fmt.Errorf("获取Redfish版本失败")
		}
		// err2 := redfishVersionV1Collect2(remote, server)
		// if err2 == nil {
		//	// fmt.Println("===ggg")
		//	jsonInterface := server.GetRedfishVersion()
		//	if jsonInterface == "" {
		//		result = ""
		//	} else {
		//		result = strings.TrimSpace(jsonInterface)
		//	}
		//	return result, nil
		// } else {
		//	// logger.Info("getRedfishVersion 失败", zap.Any("error", err))
		//	logger.Info("CheckRedfishVersion2", zap.Any("msg", "获取Redfish版本失败"), zap.Any("ip", remote.Ip), zap.Any("error", err))
		//	return result, err2
		//
		// }
	} else {
		a := CheckRedfishVersion(remote)
		result = strings.TrimSpace(fmt.Sprintf("%s", a))
		return result, nil
		// logger.Info("CheckRedfishVersion2 失败", zap.Any("error", err))
		// logger.Info("CheckRedfishVersion", zap.Any("msg", "获取Redfish版本失败"), zap.Any("ip", remote.Ip), zap.Any("error", err))

	}
}

func CheckRedfishSerial2(remote *structs.L2DeviceRemoteInfo) (result string, err error) {
	logger := log.NewLogger(remote.ActionID, true)
	if tools.IsContain([]string{"h3c"}, strings.ToLower(remote.Manufacturer)) {
		if len(remote.Community) != 0 {
			st, err := snmp.NewSnmpTask(
				remote.Ip,
				remote.Community[0],
				"1.3.6.1.2.1.47.1.1.1.1.11",
				[]int{1},
				[]int{0},
				map[string]string{"0": "SerialNumber"},
				map[string]func(byte, string, interface{}) (string, error){},
				nil)

			st.Run(true)
			table, err := st.Table()
			if err != nil {
				logger.Warn("h3c snmp方式获取Serial失败,尝试其他方法", zap.Error(err))
			} else {
				result, ok := table.IndexToValue("SerialNumber", "0")
				if ok != true {
					err := errors.New("Snmp方式获取h3c序列号失败")
					logger.Warn("h3c snmp方式获取Serial失败,尝试其他方法", zap.Error(err), log.Tag("remote", remote))
					// return "", err
				} else {
					result = strings.TrimSpace(strings.Split(result, " ")[0])
					// logger.Debug("check version ok ", zap.Any("result", result))
					return result, nil
				}
			}
		}
	} else if tools.IsContain([]string{"hp"}, strings.ToLower(remote.Manufacturer)) {
		if len(remote.Community) != 0 {
			st, err := snmp.NewSnmpTask(
				remote.Ip,
				remote.Community[0],
				".1.3.6.1.4.1.232.2.2.2.1",
				[]int{1},
				[]int{0},
				map[string]string{"0": "SerialNumber"},
				map[string]func(byte, string, interface{}) (string, error){},
				nil)

			st.Run(true)
			table, err := st.Table()
			if err != nil {
				logger.Warn("snmp hp 方式获取Serial失败,尝试其他方法", zap.Error(err))
			} else {
				result, ok := table.IndexToValue("SerialNumber", "0")
				if ok != true {
					err := errors.New("Snmp方式获取hp序列号失败")
					logger.Warn("hp Snmp方式获取序列号失败,尝试其他方法", zap.Error(err))
					// return "", err
				} else {
					result = strings.TrimSpace(strings.Split(result, " ")[0])
					// logger.Info("check version ok ", zap.Any("result", result))
					return result, nil
				}
			}
		} else {
			logger.Warn("hp获取Redfish版本失败,Community为空")
		}
	} else if tools.IsContain([]string{"ibm"}, strings.ToLower(remote.Manufacturer)) {
		if len(remote.Community) != 0 {
			st, err := snmp.NewSnmpTask(
				remote.Ip,
				remote.Community[0],
				".1.3.6.1.4.1.25506.13.1.2.2.7.1",
				[]int{1},
				[]int{0},
				map[string]string{"0": "SerialNumber"},
				map[string]func(byte, string, interface{}) (string, error){},
				nil)

			st.Run(true)
			table, err := st.Table()
			if err != nil {
				logger.Warn("ibm snmp方式获取Serial失败,尝试其他方法", zap.Error(err))
			} else {
				result, ok := table.IndexToValue("SerialNumber", "0")
				if ok != true {
					err := errors.New("Snmp方式获取ibm序列号失败")
					logger.Warn("ibm snmp方式获取Serial失败,尝试其他方法", zap.Error(err))
					// return "", err
				} else {
					result = strings.TrimSpace(strings.Split(result, " ")[0])
					// logger.Info("check version ok ", zap.Any("result", result))
					return result, nil
				}
			}
		} else {
			logger.Warn("ibm snmp获取Serial失败,Community为空", log.Tag("remote", remote))

		}
	}
	// else if tools.IsContain([]string{"lenovo"}, strings.ToLower(remote.Manufacturer)) {
	//	server := redfishClient(remote)
	//	defer server.OutC.Logout()
	//	result = gofishRedfishVersionV1Collect(remote, server)
	//	return result
	// }
	server, err := redfishClient2(remote)
	if err == nil {
		result = strings.TrimSpace(server.GetSKU())
		if result == "" {
			result = strings.TrimSpace(server.GetSerialNumber())
		}
		if result != "" {
			return result, nil
		} else {
			// logger.Info("getRedfishVersion 失败", zap.Any("error", err))
			logger.Error("CheckRedfishSerial2 snmp和redfish获取Serial失败", zap.Error(err), log.Tag("remote", remote))
			return result, fmt.Errorf("获取Serial失败")
		}
	} else {
		a := CheckRedfishSerial(remote)
		result = strings.TrimSpace(fmt.Sprintf("%s", a))
		return result, nil
		// logger.Info("CheckRedfishSerial2 失败", zap.Any("error", err))
		// logger.Info("CheckRedfishVersion", zap.Any("msg", "获取Redfish版本失败"), zap.Any("ip", remote.Ip), zap.Any("error", err))

	}
}

func (ts *WorkContext) updateRedfishRemoteInfo(arg *structs.Args) (remoteInfo *structs.L2DeviceRemoteInfo, err error) {
	logger := log.NewLogger(arg.Remote.ActionID, true)

	remoteInfo = arg.Remote
	if !reachable.IsAlive(arg.Ip) {
		remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(false)
		// fmt.Printf("%s is unreachable", arg.Ip)
		err = fmt.Errorf("%s is unreachable", arg.Ip)
		logger.Error("目标不可达", zap.Any("method", "IsAlive"), zap.Error(err))
		return remoteInfo, err
	}

	// meta.Meta = remoteInfo.Meta
	// meta.ID = remoteInfo.MetaID
	if remoteInfo.Meta.SSHPort == 0 {
		remoteInfo.Meta.SSHPort = 22
	}
	if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.SSHPort)) {
		remoteInfo.Meta.EnableSSH = func(b bool) *bool { return &b }(true)
	} else {
		remoteInfo.Meta.EnableSSH = func(b bool) *bool { return &b }(false)
	}

	if remoteInfo.Meta.TelnetPort == 0 {
		remoteInfo.Meta.TelnetPort = 23
	}
	if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.TelnetPort)) {
		remoteInfo.Meta.EnableTelnet = func(b bool) *bool { return &b }(true)
	} else {
		remoteInfo.Meta.EnableTelnet = func(b bool) *bool { return &b }(false)
	}

	if remoteInfo.Meta.RestfullPort == 0 {
		remoteInfo.Meta.RestfullPort = 8443
	}
	if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.RestfullPort)) {
		remoteInfo.Meta.EnableRestfull = func(b bool) *bool { return &b }(true)
	} else {
		remoteInfo.Meta.EnableRestfull = func(b bool) *bool { return &b }(false)
	}

	if remoteInfo.Meta.NetconfPort == 0 {
		remoteInfo.Meta.NetconfPort = 830
	}
	if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.NetconfPort)) {
		remoteInfo.Meta.EnableNetconf = func(b bool) *bool { return &b }(true)
	} else {
		remoteInfo.Meta.EnableNetconf = func(b bool) *bool { return &b }(false)
	}

	if remoteInfo.Meta.RedfishPort == 0 {
		remoteInfo.Meta.RedfishPort = 830
	}
	// if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.RedfishPort)) {
	//	//meta.EnableRedfish = func(b bool) *bool { return &b }(true)
	// } else {
	//	meta.EnableRedfish = func(b bool) *bool { return &b }(false)
	// }
	// global.GVA_LOG.Info("META.gatherMeta", zap.Any("device", device))

	// Todo: 可能需要专门进行版本分析的方法，而且需要考虑具体位置
	if arg.IsRedfish {
		redfishversion, _ := CheckRedfishVersion2(remoteInfo)
		if redfishversion == "" {
			remoteInfo.Meta.EnableRedfish = func(b bool) *bool { return &b }(false)
		} else {
			remoteInfo.Meta.RedfishVersion = redfishversion
			remoteInfo.Meta.EnableRedfish = func(b bool) *bool { return &b }(true)
		}
		logger.Debug("updateRedfishRemoteInfo", zap.Any("Redfish Version:", redfishversion))
	} else {
		version := ""
		switch strings.ToUpper(remoteInfo.Platform) {
		case "CENTOS":
			version, err = checkCentosVersionSSH(arg.Ip, remoteInfo)
		case "REDHAT":
			version, err = checkRedhatVersionSSH(arg.Ip, remoteInfo)
		case "ACI":
			version, err = checkAciVersion(arg.Ip, arg.Remote)
		default:
			version, err = checkServerVersionSSH(arg.Ip, remoteInfo)
		}
		if err != nil {
			// fmt.Println(err)
			remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(false)
		} else {
			remoteInfo.Meta.Version = version
			remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(true)
		}
	}
	return

}
func (ts *WorkContext) gatherRedfishMeta(arg *structs.Args) (*structs.Meta, error) {
	// remoteInfo := arg.Remote
	remoteInfo, err := ts.updateRedfishRemoteInfo(arg)
	if err != nil {
		return nil, err
	}

	meta := &remoteInfo.Meta
	return meta, err
}
func (ts *SERVEROOB) RedfishMeta(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)
	var result *clitask.Table
	reply.StartTime = time.Now()
	// reply.Method = args.ServiceType
	reply.Meta, err = session.gatherRedfishMeta(args)
	reply.Method = args.ServiceType
	// result, err = session.cpu(args)
	result = &clitask.Table{}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishMeta",
		// zap.Any("method", "TOPO"),
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("Meta", reply.Meta),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) RedfishCpu(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)
	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.cpu2(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishCpu",
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) RedfishMem(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.mem(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishMem",
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) RedfishDisk(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.disk(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishDisk",
		// zap.Any("method", "TOPO"),
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) RedfishBmc(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.bmc(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishBmc",
		// zap.Any("method", "TOPO"),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Any("err", err))
	return err
}

func (ts *SERVEROOB) RedfishNetworkinterface(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.networkinterface(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishNetworkinterface",
		// zap.Any("method", "TOPO"),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Any("err", err))
	return err
}

func (ts *SERVEROOB) RedfishNetwork(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.network(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishNetwork",
		// zap.Any("method", "TOPO"),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Any("err", err))
	return err
}

func (ts *SERVEROOB) OOBVersionSNMPANDREDFISH(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	reply.StartTime = time.Now()
	version, err := CheckRedfishVersion2(args.Remote)
	if err != nil {
		return err
	}
	result := clitask.NewEmptyTableWithKeys([]string{"redfish_version"})
	err = result.PushRow("", map[string]string{"redfish_version": version}, false, "")

	reply.EndTime = time.Now()
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("OOBVersionSNMPANDREDFISH",
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("err", err))
	return err
}

func (ts *SERVEROOB) OOBSerialNumberSNMPANDREDFISH(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	reply.StartTime = time.Now()
	serial, err := CheckRedfishSerial2(args.Remote)
	if err != nil {
		return err
	}
	result := clitask.NewEmptyTableWithKeys([]string{"serial_number"})
	err = result.PushRow("", map[string]string{"serial_number": serial}, false, "")

	reply.EndTime = time.Now()
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("OOBSerialNumberSNMPANDREDFISH",
		// zap.Any("method", "TOPO"),
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("err", err))
	return err
}

func (ts *SERVEROOB) IsAlive(ctx context.Context, arg *structs.Args, reply *structs.Reply) (err error) {
	reply.StartTime = time.Now()
	var result *clitask.Table
	result, err = checkIsAlive(arg.Ip, arg.Remote)
	reply.Table = result
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	return
}

func (ts *SERVEROOB) OOBVersion(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	reply.StartTime = time.Now()
	version, err := checkFirmwareVersion(args.Remote)
	if err != nil {
		version, err = CheckRedfishVersion2(args.Remote)
		if err != nil {
			return err
		}
	}
	result := clitask.NewEmptyTableWithKeys([]string{"redfish_version"})
	err = result.PushRow("", map[string]string{"redfish_version": version}, false, "")

	reply.EndTime = time.Now()
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("OOBVersion",
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) OOBSerialNumber(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	reply.StartTime = time.Now()
	serial, err := checkSerialNumber(args.Remote)
	if err != nil {
		serial, err = CheckRedfishSerial2(args.Remote)
		if err != nil {
			return err
		}
	}
	result := clitask.NewEmptyTableWithKeys([]string{"serial_number"})
	err = result.PushRow("", map[string]string{"serial_number": serial}, false, "")

	reply.EndTime = time.Now()
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("OOBSerialNumber",
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Error(err))
	return err
}

func checkFirmwareVersion(remote *structs.L2DeviceRemoteInfo) (string, error) {
	c, err := ipmigo.NewClient(ipmigo.Arguments{
		Version:       ipmigo.V2_0,
		Address:       fmt.Sprintf("%s:%d", remote.Ip, remote.Meta.IPMIPort),
		Timeout:       2 * time.Second,
		Retries:       1,
		Username:      remote.Username,
		Password:      remote.Password,
		CipherSuiteID: 3,
	})
	if err != nil {
		return "", err
	}

	if err := c.Open(); err != nil {
		return "", err
	}
	defer c.Close()

	cmd := &ipmigo.GetDeviceIDCommand{}
	if err := c.Execute(cmd); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x.%x", cmd.FirmwareMajorRevision, cmd.FirmwareMinorRevision), nil
}

func checkSerialNumber(remote *structs.L2DeviceRemoteInfo) (string, error) {
	ipmiCmd := fmt.Sprintf("ipmitool -I lanplus -H %s -U %s -P %s fru", remote.Ip, remote.Username, remote.Password)
	cmd := exec.Command("bash", "-c", ipmiCmd)
	output, _ := cmd.Output()
	// fmt.Println("3333")
	lines := strings.Split(string(output), "\n")
	productSerial, boardSerial := "", ""
	for _, line := range lines {
		if strings.Index(line, "Product Serial") >= 0 {
			// if len(strings.Split(line, ":")) != 2 {
			//	err := fmt.Errorf("parser serial number failed, output: %s", line)
			//	//return "", err
			// }
			version := strings.TrimSpace(strings.Split(line, ":")[1])
			productSerial = version
			break
			// return version, nil
		}
	}
	for _, line := range lines {
		if strings.Index(line, "Board Serial") >= 0 {
			// if len(strings.Split(line, ":")) != 2 {
			//	err := fmt.Errorf("parser serial number failed, output: %s", line)
			//	return "", err
			// }
			boardSerial = strings.TrimSpace(strings.Split(line, ":")[1])
			break
			// return version, nil
		}
	}
	if productSerial != "" {
		return productSerial, nil
	} else if boardSerial != "" {
		return boardSerial, nil
	} else if productSerial == "" && boardSerial == "" {
		return "", fmt.Errorf("get serial number failed.")
	}
	// if err != nil {
	//	return "", err
	// }
	return "", fmt.Errorf("get serial number failed.")
}

func (ts *SERVEROOB) RedfishVersion(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)
	logger.Debug("RedfishVersion 开始", zap.Any("args", args))

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.redfishversion(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishVersion",
		// zap.Any("method", "TOPO"),
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) RedfishBaseInfo(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)
	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.baseinfo(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishBaseInfo",
		// zap.Any("method", "TOPO"),
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) RedfishPower(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.power(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishPower",
		// zap.Any("method", "TOPO"),
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) RedfishPowerControl(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.powercontrol(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("RedfishPower Control",
		// zap.Any("method", "TOPO"),
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func (ts *SERVEROOB) OOBGPU(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)
	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	result, err = session.gpu(args)
	if result == nil {
		result = &clitask.Table{}
	}
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	logger.Debug("OOBGPU",
		log.Tag("remote", args.Remote),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}
