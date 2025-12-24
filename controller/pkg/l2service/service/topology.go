package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"

	// "github.com/influxdata/telegraf/controller/pkg/l2service/model"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/log"

	clitask "github.com/netxops/utils/task"

	"time"

	u2 "github.com/gofrs/uuid"
	"go.uber.org/zap"
)

//
// type DeviceWithPlatform interface {
// Catalog() string
// Platform() string
// Manufacturer() string
// DeviceType() string
// DeviceID() uint
// OutOfBound() string
// InBound() string
// DeviceName() string
// StructType() string
// Meta() *model.DeviceMeta
// }
//

// var zapLogger *zap.Logger

var topoLogger *zap.Logger

func init() {
	topoLogger, _ = zap.NewDevelopment(zap.AddCallerSkip(1))
}

const (
	DcimInterface                = "DcimInterface"
	DcimRearport                 = "DcimRearport"
	DcimFrontport                = "DcimFrontport"
	DcimDevice                   = "DcimDevice"
	VirtualizationCluster        = "VirtualizationCluster"
	SdnController                = "SdnController"
	VirtualizationVirtualmachine = "VirtualizationVirtualmachine"
	DcimInputDevice              = "DcimInputDevice"
	DeviceAndVirtualmachine      = "deviceAndVirtualmachine"
)

type WorkContext struct {
	Uuid    string
	Service interface{}
	// SnmpRole    string
	// SecretRole  string
	// RedfishRole string
	// VmwareRole  string
	// InbandRole  string
}

func NewWorkContext(ts interface{}, arg interface{}) *WorkContext {
	id := uuid.New()

	return &WorkContext{
		Uuid:    id.String(),
		Service: ts,
		// SnmpRole:    tools.Conditional(arg.IsRedfish, global.GVA_CONFIG.RoleConfig.OutbandSnmp.Name, global.GVA_CONFIG.RoleConfig.InbandSnmp.Name).(string),
		// SecretRole:  global.GVA_CONFIG.RoleConfig.InbandSecret.Name,
		// RedfishRole: global.GVA_CONFIG.RoleConfig.OutbandRedfish.Name,
		// VmwareRole:  global.GVA_CONFIG.RoleConfig.VmwareSecret.Name,
		// InbandRole:  ts.InbandRole,
	}
}

type SnmpServiceType int

type SSHServerType int

type TOPO struct {
	Data string
	// SnmpRole        string
	// SecretRole      string
	// RedfishRole     string
	// VmwareRole      string
	// InbandRole      string
	// OutbandSnmpRole string
	// Sdns    string
	// Switchs string
	// Servers string
	// Metas   string
	// Region  string
	// Env     string
}

type KwArgs struct {
	ServiceType SSHServerType
	Ip          string
	Community   string
	Oid         string
	Username    string
	PassWord    string
	AuthPass    string
	Tp          string
	Telnet      bool
}

// func (a *structs.Args) Device() (DeviceWithPlatform, error) {
// var err error
// switch a.StructType {
// case DcimDevice:
// var d model.DcimDevice
// tx := global.GVA_DB1.Where("id = ?", a.Id).Preload("DcimPlatform").Preload("DcimDevicetype.DcimManufacturer").Preload("DcimCatalog").Find(&d)
// err = tx.Error
// return &d, err
// case VirtualizationCluster:
// var d model.VirtualizationCluster
// tx := global.GVA_DB1.Where("id = ?", a.Id).Preload("DcimPlatform").Preload("DcimCatalog").Find(&d)
// err = tx.Error
// return &d, err
// case SdnController:
// var d model.SdnController
// tx := global.GVA_DB1.Where("id = ?", a.Id).Preload("DcimPlatform").Preload("DcimCatalog").Find(&d)
// err = tx.Error
// return &d, err
// case VirtualizationVirtualmachine:
// var d model.VirtualizationVirtualmachine
// tx := global.GVA_DB1.Where("id = ?", a.Id).Preload("DcimPlatform").Preload("DcimCatalog").Find(&d)
// err = tx.Error
// return &d, err
// }
//
// return nil, fmt.Errorf("unsupport struct type: %s", a.StructType)
// }
func (ts *TOPO) TopoMainService(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	var err error
	session := NewWorkContext(ts, args)

	var result *clitask.Table
	reply.StartTime = time.Now()
	reply.Method = args.ServiceType
	switch args.ServiceType {
	case structs.SYSTEM_NAME:
		result, err = session.systemName(args)
	case structs.IFTABLE:
		result, err = session.ifTable(args)
	case structs.DOT1DPORTS:
		result, err = session.yamlDot1d(args)
	case structs.PORTIP:
		result, err = session.yamlPortIp(args)
	case structs.VLAN:
		result, err = session.yamlVlan(args)
	case structs.STP:
		result, err = session.yamlStp(args)
	case structs.MACTABLE:
		result, err = session.yamlMacTable(args)
	case structs.PORT_STATISTICS:
		result, err = session.yamlPortStatistics(args)
	case structs.PORT_CHANNEL:
		result, err = session.yamlPortChannel(args)
	case structs.SH_RUN:
		result, err = session.yamlShRun(args)
	case structs.PORT_INFO:
		result, err = session.yamlPortInfo(args)
	case structs.IPV6_NEIGHBOR:
		result, err = session.yamlIpv6Neighbor(args)
	case structs.NEIGHBOR:
		result, err = session.yamlCdp(args)
		if err != nil || result == nil || result.IsEmpty() {
			result, err = session.yamlLldp1(args)
		}
	case structs.NEIGHBOR_CDP2:
		result, err = session.yamlCdp2(args)
	case structs.NEIGHBOR_CDP:
		result, err = session.yamlCdp(args)
	case structs.NEIGHBOR_LLDP:
		result, err = session.yamlLldp1(args)
	case structs.YAML_ARP:
		result, err = session.yamlARP(args)
	case structs.SWITCH_CONFIG:
		result, err = session.yamlSwitchConfig(args)
	case structs.SWITCH_CONFIG_TERMINAL:
		result, err = session.yamlSwitchConfigTerminal(args)
	case structs.SWITCH_EXEC_TERMINAL:
		result, err = session.yamlSwitchExecTerminal(args)
	case structs.SWITCH_EXEC:
		result, err = session.switchExec(args)
	case structs.ASA_CONFIG:
		result, err = session.yamlAsaConfig(args)
	case structs.F5_CONFIG:
		result, err = session.yamlF5Config(args)
	case structs.FORTI_CONFIG:
		result, err = session.yamlFortiGateConfig(args)
	case structs.SECPATH_CONFIG:
		result, err = session.yamlSecPathConfig(args)
	case structs.DPTECH_CONFIG:
		result, err = session.yamlDptechConfig(args)
	case structs.SANGFOROS_CONFIG:
		result, err = session.yamlSangforOsConfig(args)
	case structs.USG_CONFIG:
		result, err = session.yamlUsgConfig(args)
	case structs.SWITCH_CONFIG_WITH_COMMAND:
		result, err = session.yamlSwitchConfigWithCommand(args)
	case structs.SWITCH_VERSION:
		result, err = session.switch_version(args)
	case structs.SWITCH_SNMP_VERSION:
		result, err = session.switch_snmp_version(args)
	case structs.SWITCH_EXEC_TIMEOUT:
		result, err = session.switch_exec_timeout(args)
	case structs.SWITCH_REBOOT:
		result, err = session.switch_reboot(args)
	case structs.SWITCH_PATCH_VERSION:
		result, err = session.switch_patch_version(args)
	case structs.SWITCH_DIR:
		result, err = session.switch_dir(args)
	case structs.SWITCH_STATUS:
		result, err = session.switch_status(args)
	case structs.SWITCH_INSTALL:
		result, err = session.switch_install(args)
	case structs.SWITCH_INSTALL_HOTFIX:
		result, err = session.switch_install_hotfix(args)
	case structs.SWITCH_BOOT:
		result, err = session.switch_boot(args)
	case structs.SWITCH_IMPACT:
		result, err = session.switch_impact(args)
	case structs.SWITCH_EXEC_MAP:
		result, err = session.switch_exec_map(args)
	case structs.SWITCH_IMPORT:
		result, err = session.switch_import(args)
	// case structs.SDN_FABRIC:
	// result, err = session.sdnFabric(args)
	// case structs.SDN_VPC:
	// result, err = session.sdnVpc(args)
	// case structs.SDN_LOGICPORT:
	// result, err = session.sdnLogicPort(args)
	//
	case structs.REDFISH_CPU:
		result, err = session.cpu(args)
	case structs.REDFISH_MEM:
		result, err = session.mem(args)
	case structs.REDFISH_DISK:
		result, err = session.disk(args)
	case structs.REDFISH_BMC:
		result, err = session.bmc(args)
	case structs.REDFISH_NETWORKINTERFACE:
		result, err = session.networkinterface(args)
	case structs.REDFISH_NETWORK:
		result, err = session.network(args)
	case structs.REDFISH_VERSION:
		result, err = session.redfishversion(args)
	case structs.REDFISH_BASEINFO:
		result, err = session.baseinfo(args)
	case structs.REDFISH_POWER:
		result, err = session.power(args)
	case structs.OOB_GPU:
		result, err = session.gpu(args)
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
	case structs.VMWARE_INTERFACES:
		result, err = session.interfaces(args)
	case structs.LINUX_STACKUP_CMD:
		result, err = session.linux_stackup_cmd(args)
	case structs.LINUX_BATCH_CMD:
		result, err = session.linux_batch_cmd(args)
	case structs.LINUX_STEP_CMD:
		result, err = session.linux_step_cmd(args)
	case structs.LINUX_STEP_WITH_COMMAND:
		result, err = session.linux_step_with_command(args)
	case structs.VZENTRY:
		result, err = session.vzEntry(args)

	case structs.SDN_GET:
		result, err = session.sdn_get(args)
	case structs.SDN_FABRICAPATHEP:
		result, err = session.sdn_fabricapathep(args)
	case structs.SDN_FABRICINST:
		result, err = session.sdn_fabricinst(args)
	case structs.SDN_EPTRACKER:
		result, err = session.sdn_eptracker(args)
	case structs.SDN_VZBRCP:
		result, err = session.sdn_vzbrcp(args)
	case structs.SDN_FABRICPATHEP:
		result, err = session.sdn_fabricpathep(args)
	case structs.SDN_CONTROLLER:
		result, err = session.sdn_controller(args)
	case structs.SDN_CONTROLLERSSIZE:
		result, err = session.sdn_controllerssize(args)
	case structs.SDN_FVAP:
		result, err = session.sdn_fvap(args)
	case structs.SDN_FVSUBNET:
		result, err = session.sdn_fvsubnet(args)
	case structs.SDN_FORTIPOLICY:
		result, err = session.sdn_fortypolicy(args)
	case structs.SDN_FORTISUBNET:
		result, err = session.sdn_fortisubnet(args)
	case structs.SDN_FORTISERVICE:
		result, err = session.sdn_fortiservice(args)
	case structs.SDN_FIRMWARE:
		result, err = session.sdn_firmware(args)
	case structs.SDN_VZFILTER:
		result, err = session.sdn_vzfilter(args)
	case structs.SDN_VZENTRY:
		result, err = session.sdn_vzentry(args)
	case structs.SDN_INFRA:
		result, err = session.sdn_infra(args)
	case structs.SDN_FABRIC2:
		result, err = session.sdn_fabric2(args)
	case structs.SDN_CONTRACT:
		result, err = session.sdn_contract(args)

	// ib net相关命令请求
	case structs.IB_NET_COMMAND:
		result, err = session.ibnet_command(args)

	default:
		// err = fmt.Errorf("unsupport servie type = %s, ip = %s", args.ServiceType, args.Ip)
		logger.ErrorNoStack("unsupport servie type", log.Tag("arg", args))
	}

	if result == nil {
		result = &clitask.Table{}
	}

	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	if reply.Table != nil {
		// fmt.Println("/////", reply.Table.RawData)
		reply.Table.RawData = result.GetRawData()
		reply.RawData = result.GetRawData()
	}
	reply.Error = err

	logger.Debug("Topo Service执行完成",
		log.Tag("arg", args),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

func checkInbandSerialNumber(remote *structs.L2DeviceRemoteInfo) (result string, err error) {
	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		Telnet:     false,
		Port:       remote.Meta.SSHPort,
	}

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	exec.Id = u2.Must(u2.NewV4()).String()
	exec.Add("sudo dmidecode -t system | grep Serial", "", 10, "lsb", "")
	exec.Prepare(false)
	data := exec.Run(false)
	if data.Error() != nil {
		err = data.Error()
		return
	}
	ok, lines := data.GetResult("lsb")
	if !ok {
		err = fmt.Errorf("get cmd result failed, cmd=%s", "lsb_release -a")
		return
	}
	for _, line := range lines {
		if strings.Index(line, "Number") >= 0 {
			version := strings.TrimSpace(strings.Split(line, ":")[1])
			result = version
			break
			// return version, nil
		}
	}
	if result != "" {
		return result, nil
	}
	return result, fmt.Errorf("get serial number failed.")
}
func (ts *TOPO) InbandSerialNumber(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
	logger := log.NewLogger(args.Remote.ActionID, true)

	reply.StartTime = time.Now()
	serial, err := checkInbandSerialNumber(args.Remote)
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
	logger.Debug("InbandSerialNumber",
		log.Tag("arg", args),
		zap.Any("completed", true),
		zap.Any("total", reply.Total),
		zap.Any("duration", reply.Duration),
		zap.Error(err))
	return err
}

// func (ts *WorkContext) base(arg *structs.Args, serviceType string) ([]map[string]string, error) {
func (ts *WorkContext) base(arg *structs.Args, serviceType string) (*clitask.Table, error) {
	logger := log.NewLogger(arg.Remote.ActionID, true)

	var resultTable *clitask.Table
	var err error

	remote := arg.Remote
	meta := arg.Meta

	if meta != nil && (meta.Meta.Enable == nil || !*meta.Meta.Enable) {
		if arg.IsRedfish && remote.RedfishVersion != "" {

		} else {
			logger.ErrorNoStack("meta is disable", log.Tag("arg", arg))
			return resultTable, err
		}
	}

	logger.Debug("获取远程连接信息", log.Tag("remote", remote))

	var ctx context.Context
	if _, ok := ts.Service.(*TOPO); ok {
		ctx = context.WithValue(context.Background(), "local_data_path", ts.Service.(*TOPO).Data)
	} else {
		ctx = context.TODO()
	}

	l2nodemapService, desc := Config.Select(ctx, remote, serviceType)
	if !desc.Ok() {
		err = desc.Error()
		logger.ErrorNoStack("config.select failed", log.Tag("arg", arg), zap.Error(err))
		return resultTable, err
	}

	logger.Debug("phase 1, config.select ok", zap.Any("serviceName", l2nodemapService.ServiceName()))
	// if l2nodemapService != nil {
	// }
	resultTable, err = l2nodemapService.Run(remote, arg.Options...)
	if err != nil {
		logger.ErrorNoStack("phase 2, 远程服务执行失败", zap.Any("serviceName", l2nodemapService.ServiceName()), log.Tag("remote", remote), zap.Error(err))
		return resultTable, err
	}

	if resultTable == nil || resultTable.IsEmpty() {
		logger.Warn("phase 2, 远程服务执行完成", zap.Any("count", 0))
		return resultTable, nil
	} else {
		logger.Warn("phase 2, 远程服务执行完成", zap.Any("count", resultTable.RowCount()))
		return resultTable, nil
	}
}

// func (ts *WorkContext) ifTable(arg *structs.Args) ([]map[string]string, error) {
func (ts *WorkContext) ifTable(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "iftable")
}

// func (ts *WorkContext) systemName(arg *structs.Args) ([]map[string]string, error) {
func (ts *WorkContext) systemName(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "system_name")
}

func (ts *WorkContext) yamlDot1d(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "dot1dport")
}

func (ts *WorkContext) yamlPortIp(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "portip")
}

func (ts *WorkContext) yamlARP(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "arp")
}

func (ts *WorkContext) yamlSwitchConfig(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_config")
}
func (ts *WorkContext) yamlSwitchConfigTerminal(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_config_terminal")
}
func (ts *WorkContext) yamlSwitchExecTerminal(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_exec_terminal")
}
func (ts *WorkContext) yamlAsaConfig(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "asa_config")
}

func (ts *WorkContext) yamlF5Config(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "f5_config")
}

func (ts *WorkContext) yamlFortiGateConfig(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "forti_config")
}

func (ts *WorkContext) yamlSecPathConfig(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "secpath_config")
}

func (ts *WorkContext) yamlUsgConfig(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "usg_config")
}

func (ts *WorkContext) yamlSangforOsConfig(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sangforos_config")
}

func (ts *WorkContext) yamlDptechConfig(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "dptech_config")
}

func (ts *WorkContext) yamlSwitchConfigWithCommand(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "switch_config_with_command")
}

func (ts *WorkContext) yamlVlan(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "vlan")
}

func (ts *WorkContext) yamlMacTable(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "mactable")
}

func (ts *WorkContext) yamlCdp(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "cdp")
}
func (ts *WorkContext) yamlCdp2(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "cdp2")
}

func (ts *WorkContext) yamlLldp2(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "lldp2")
}

func (ts *WorkContext) yamlLldp1(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "lldp")
}

func (ts *WorkContext) yamlStp(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "stp")
}

func (ts *WorkContext) yamlPortStatistics(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "port_statistics")
}

func (ts *WorkContext) yamlPortChannel(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "port_channel")
}

func (ts *WorkContext) yamlShRun(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sh_run")
}
func (ts *WorkContext) yamlPortInfo(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "port_info")
}
func (ts *WorkContext) yamlIpv6Neighbor(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "ipv6_neighbor")
}

func (ts *WorkContext) cpu(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "cpu")
}

//
// func (ts *WorkContext) sdnFabric(arg *structs.Args) (*clitask.Table, error) {
// return ts.base(arg, "fabric")
// }
//
// func (ts *WorkContext) sdnVpc(arg *structs.Args) (*clitask.Table, error) {
// return ts.base(arg, "vpc")
// }
//
// func (ts *WorkContext) sdnLogicPort(arg *structs.Args) (*clitask.Table, error) {
// return ts.base(arg, "logic_port")
// }

func (ts *WorkContext) mem(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "mem")
}

func (ts *WorkContext) bmc(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "bmc")
}
func (ts *WorkContext) disk(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "disk")
}

func (ts *WorkContext) networkinterface(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "networkinterface")
}
func (ts *WorkContext) gpu(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "gpu")
}
func (ts *WorkContext) baseinfo(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "baseinfo")
}

func (ts *WorkContext) network(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "network")
}

func (ts *WorkContext) redfishversion(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "redfishversion")
}

func (ts *WorkContext) power(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "power")
}
func (ts *WorkContext) powercontrol(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "powercontrol")
}
func (ts *WorkContext) resources(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "resources")
	// return ts.vmwareBase(arg, "resources")
}

func (ts *WorkContext) vm(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "vm")
	return ts.base(arg, "vm")
}

func (ts *WorkContext) template(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "template")
	return ts.base(arg, "template")
}

func (ts *WorkContext) datastore(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "datastore")
	return ts.base(arg, "datastore")
}

func (ts *WorkContext) info(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "info")
	return ts.base(arg, "info")
}

func (ts *WorkContext) vmhost(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "info")
	return ts.base(arg, "vmhost")
}
func (ts *WorkContext) vmcluster(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "info")
	return ts.base(arg, "vmcluster")
}
func (ts *WorkContext) interfaces(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "interfaces")
	return ts.base(arg, "interfaces")
}

func (ts *WorkContext) host_base_value(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "interfaces")
	return ts.base(arg, "host_base_value")
}

func (ts *WorkContext) vmware_ip_data(arg *structs.Args) (*clitask.Table, error) {
	// return ts.vmwareBase(arg, "interfaces")
	return ts.base(arg, "vmware_ip_data")
}

func (ts *WorkContext) linux_stackup_cmd(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "stackup")
}

func (ts *WorkContext) linux_batch_cmd(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "batch")
}

func (ts *WorkContext) linux_step_cmd(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "step")
}

func (ts *WorkContext) inband_serial(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "inband_serial")
}
func (ts *WorkContext) linux_step_with_command(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "step_with_command")
}

func (ts *WorkContext) vzEntry(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "VzEntry")
}

func (ts *WorkContext) sdn_tenant(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_tenant")
}

func (ts *WorkContext) sdn_fvaepg(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fvaepg")
}

func (ts *WorkContext) sdn_fvbd(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fvbd")
}

func (ts *WorkContext) sdn_eptracker(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_eptracker")
}

func (ts *WorkContext) sdn_get(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_get")
}

func (ts *WorkContext) sdn_fabricapathep(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fabricapathep")
}

func (ts *WorkContext) sdn_fabricinst(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fabricinst")
}

func (ts *WorkContext) sdn_vzbrcp(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_vzbrcp")
}

func (ts *WorkContext) sdn_fabricpathep(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fabricpathep")
}

func (ts *WorkContext) sdn_controller(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_controller")
}

func (ts *WorkContext) sdn_controllerssize(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_controllerssize")
}

func (ts *WorkContext) sdn_fvap(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fvap")
}

func (ts *WorkContext) sdn_fvsubnet(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fvsubnet")
}

func (ts *WorkContext) sdn_fortypolicy(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fortypolicy")
}

func (ts *WorkContext) sdn_fortisubnet(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fortisubnet")
}

func (ts *WorkContext) sdn_fortiservice(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fortiservice")
}

func (ts *WorkContext) sdn_firmware(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_firmware")
}

func (ts *WorkContext) sdn_vzfilter(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_vzfilter")
}

func (ts *WorkContext) sdn_vzentry(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_vzentry")
}

func (ts *WorkContext) sdn_infra(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_infra")
}

func (ts *WorkContext) sdn_fabric2(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_fabric2")
}

func (ts *WorkContext) sdn_contract(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "sdn_contract")
}

func (ts *WorkContext) check_devices(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "check_device")
}

func (ts *WorkContext) ibnet_command(arg *structs.Args) (*clitask.Table, error) {
	return ts.base(arg, "ibnet_command")
}

//
// func (ts *WorkContext) meta(arg *structs.Args) ([]map[string]string, error) {
// return ts.base(arg, "mata")
// }

// func (ts *WorkContext) ifconfig(arg *structs.Args) ([]map[string]string, error) {
//	return ts.vmwareBase(arg, "ifconfig")
// }
