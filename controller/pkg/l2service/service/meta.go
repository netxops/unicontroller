package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	RedfishBase "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish"
	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/log"
	"github.com/netxops/utils/mygofish"
	"github.com/netxops/utils/reachable"
	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/text"
	"go.uber.org/zap"
)

// import (
// 	"bytes"
// 	"context"
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"net"
// 	"os/exec"
// 	"regexp"
// 	"strconv"
// 	"strings"
// 	"time"
// 	"unicode"

// 	"github.com/influxdata/telegraf/controller/pkg/structs/l2struct"
// 	"golang.org/x/crypto/ssh"

// 	"github.com/netxops/l2service/internal/app/service/l2service/adapter/lb"
// 	v2 "github.com/netxops/l2service/internal/app/service/l2service/redfish/v2"
// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
// 	"github.com/netxops/l2service/pkg/sshtool"

// 	// "gorm.io/gorm/logger"

// 	// "github.com/netxops/l2service/internal/app/model"

// 	"github.com/netxops/l2service/internal/app/service/l2service/aci"
// 	RedfishBase "github.com/netxops/l2service/internal/app/service/l2service/adapter/redfish"
// 	"github.com/influxdata/telegraf/controller/pkg/structs"
// 	"github.com/netxops/log"

// 	"github.com/mohae/deepcopy"
// 	"github.com/netxops/cli/terminal"
// 	"github.com/netxops/cli/terminalmode"

// 	// storeService "github.com/netxops/unify/app/store/service"
// 	"github.com/netxops/utils/mygofish"
// 	"github.com/netxops/utils/network"
// 	portname "github.com/netxops/utils/port_name"
// 	"github.com/netxops/utils/reachable"
// 	"github.com/netxops/utils/snmp"
// 	clitask "github.com/netxops/utils/task"
// 	"github.com/netxops/utils/text"

// 	"github.com/gofrs/uuid"
// 	g "github.com/gosnmp/gosnmp"
// 	"go.uber.org/zap"
// )

// var metaLogger *zap.Logger

// func init() {
// 	metaLogger, _ = zap.NewDevelopment(zap.AddCallerSkip(1))
// }

// const (
// 	TENANT           = "TENANT"
// 	NODEMAP          = "NODEMAP"
// 	SITE             = "SITE"
// 	RACK             = "RACK"
// 	TAG              = "TAG"
// 	CATALOG_SDN      = "SDN"
// 	CATALOG_SWITCH   = "SWITCH"
// 	CATALOG_ROUTER   = "ROUTER"
// 	CATALOG_SERVER   = "SERVER"
// 	CATALOG_FIREWALL = "FIREWALL"
// 	CATALOG_VCENTER  = "VCENTER"
// 	IPSELECT_OOB     = "OOB"
// 	IPSELECT_INBOUND = "INBOUND"
// )

var rfFuncMap map[string]func(*structs.L2DeviceRemoteInfo) (string, error)

func init() {
	rfFuncMap = map[string]func(*structs.L2DeviceRemoteInfo) (string, error){}

	rfFuncMap["h3c"] = h3cRedfishVersion
	rfFuncMap["hp"] = hpRedfishVersion
	rfFuncMap["ibm"] = hpRedfishVersion
}

// type META struct{}

// func (ts *META) Ping(ctx context.Context, arg *structs.Args, reply *bool) (err error) {
// 	ok := false
// 	reply = &ok
// 	if reachable.IsAlive(arg.Ip) {
// 		*reply = true
// 	}

// 	return nil
// }

// type TCPPort struct {
// 	Ip   string
// 	Port string
// }

// func (ts *META) Open(ctx context.Context, arg *TCPPort, reply *bool) (err error) {
// 	ok := false
// 	reply = &ok
// 	if reachable.TCPPortAlive(arg.Ip, arg.Port) {
// 		*reply = true
// 	}

// 	return nil
// }

// func (ts *META) SdnVersion(ctx context.Context, arg *structs.Args, reply *string) error {
// 	version, err := checkAciVersion(arg.Ip, arg.Remote)
// 	if err != nil {
// 		return err
// 	}
// 	reply = &version
// 	return nil
// }

// func (ts *META) LinuxVersion(ctx context.Context, arg *structs.Args, reply *string) error {
// 	var version string
// 	var err error
// 	switch strings.ToUpper(arg.Platform) {
// 	case "CENTOS":
// 		version, err = checkCentosVersionSSH(arg.Ip, arg.Remote)
// 	case "REDHAT":
// 		version, err = checkRedhatVersionSSH(arg.Ip, arg.Remote)
// 	case "ACI":
// 		version, err = checkAciVersion(arg.Ip, arg.Remote)
// 	default:
// 		version, err = checkServerVersionSSH(arg.Ip, arg.Remote)
// 	}
// 	if err != nil {
// 		return err
// 	}

// 	reply = &version
// 	return nil
// }

// func (ts *META) NetworkDeviceSerialTable(ctx context.Context, arg *structs.Args, reply *structs.Reply) error {
// 	logger := log.NewLogger(nil, true).Logger.With(zap.String("method", "NetworkDeviceSerialTable"), zap.String("ip", arg.Ip), zap.String("platform", arg.Platform))

// 	logger.Info("Starting NetworkDeviceSerialTable collection")
// 	reply.StartTime = time.Now()

// 	var result *clitask.Table
// 	var err error

// 	switch arg.Platform {
// 	case "HWGpon":
// 		result, _, err = checkHWGponSNSSH(arg.Ip, arg.Remote, logger)
// 	case "Ubuntu", "Centos":
// 		result, _, err = parseLinuxSN(arg.Ip, arg.Remote, logger)
// 	case "FortiGate":
// 		result, _, err = checkFortiGateSNSSH(arg.Ip, arg.Remote, logger)
// 	case "ASA":
// 		fallthrough
// 	default:
// 		result, err = networkDeviceSerialTable(arg, logger)
// 	}

// 	if err != nil {
// 		logger.Error("NetworkDeviceSerialTable failed", zap.Error(err))
// 		result = &clitask.Table{}
// 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 		reply.Error = err
// 		return err
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()

// 	logger.Info("NetworkDeviceSerialTable collection completed",
// 		zap.Int("total_rows", reply.Total),
// 		zap.Float64("duration_seconds", reply.Duration))

// 	return nil
// }

// func checkASASerialSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, serial string, err error) {
// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.AuthPass,
// 		// PrivateKey: remote.PrivateKey,
// 		Telnet: false,
// 		Port:   remote.Meta.SSHPort,
// 	}

// 	// if remote.ActionID != nil {
// 	base.WithActionID(remote.ActionID)
// 	// }

// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.ASA, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("show inventory", "", 10, "sh_inventory", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		err = data.Error()
// 		return
// 	}
// 	var m map[string]string
// 	ok, lines := data.GetResult("sh_inventory")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "show inventory")
// 		return
// 	}

// 	m, err = text.GetFieldByRegex(`PID.*ASA.*SN:\s+(?P<serial>\S+)`, strings.Join(lines, "\n"), []string{"serial"})
// 	if err != nil {
// 		return
// 	}

// 	result = clitask.NewEmptyTableWithKeys([]string{"serial"})
// 	result.PushRow("0", map[string]string{"serial": m["serial"]}, false, "")
// 	serial = m["serial"]
// 	return
// }

// func (ts *META) SnmpIpAddrEntry(ctx context.Context, arg *structs.Args, reply *structs.Reply) error {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("method", "SnmpIpAddrEntry"),
// 		zap.String("ip", arg.Ip),
// 		zap.String("platform", arg.Platform),
// 	)
// 	logger.Info("Starting SnmpIpAddrEntry collection")

// 	reply.StartTime = time.Now()
// 	result := &clitask.Table{}
// 	var err error
// 	ip := arg.Ip
// 	community := arg.Remote.Community[0]

// 	logger.Debug("Creating SNMP task",
// 		zap.String("oid", "1.3.6.1.2.1.4.20.1"),
// 		zap.String("community", community))

// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.4.20.1",
// 		[]int{1, 2, 3, 4},
// 		[]int{0},
// 		map[string]string{"2": "interface", "3": "mask"},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	if err != nil {
// 		logger.Error("Failed to create SNMP task", zap.Error(err))
// 		reply.Error = err
// 		return err
// 	}

// 	logger.Debug("Running SNMP task")
// 	st.Run(true)
// 	result, err = st.Table()
// 	if err != nil {
// 		logger.Error("SnmpIpAddrEntry collection failed",
// 			zap.Error(err),
// 			log.Tag("arg", arg))
// 	} else {
// 		logger.Info("SnmpIpAddrEntry collection successful",
// 			zap.Int("row_count", result.RowCount()))
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Error = err

// 	logger.Info("SnmpIpAddrEntry collection completed",
// 		zap.Int("total_entries", reply.Total),
// 		zap.Float64("duration_seconds", reply.Duration),
// 		zap.Error(err))

// 	return err
// }

// func HexPDU(asntype byte, _ string, data interface{}) (result string, err error) {
// 	s := fmt.Sprintf("%x", data.([]byte))
// 	// spew.Dump(data)
// 	// fmt.Println("/////", fmt.Sprintf("%x", data.([]byte)))
// 	return s, nil
// }
// func (ts *META) SnmpIfEntry(ctx context.Context, arg *structs.Args, reply *structs.Reply) error {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("method", "SnmpIfEntry"),
// 		zap.String("ip", arg.Ip),
// 		zap.String("platform", arg.Platform),
// 	)
// 	logger.Info("Starting SnmpIfEntry collection")

// 	reply.StartTime = time.Now()
// 	result := &clitask.Table{}
// 	var err error
// 	ip := arg.Ip
// 	community := arg.Remote.Community[0]

// 	logger.Debug("Creating SNMP task",
// 		zap.String("oid", "1.3.6.1.2.1.2.2.1"),
// 		zap.String("community", community))

// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.2.2.1",
// 		[]int{1},
// 		[]int{0},
// 		map[string]string{"2": "name", "3": "phy_protocol", "6": "mac", "8": "status"},
// 		map[string]func(byte, string, interface{}) (string, error){"6": HexPDU},
// 		nil)

// 	if err != nil {
// 		logger.Error("Failed to create SNMP task", zap.Error(err))
// 		reply.Error = err
// 		return err
// 	}

// 	logger.Debug("Running SNMP task")
// 	st.Run(true)
// 	result, err = st.Table()
// 	if err != nil {
// 		logger.Error("SnmpIfEntry collection failed",
// 			zap.Error(err),
// 			log.Tag("arg", arg))
// 	} else {
// 		logger.Info("SnmpIfEntry collection successful",
// 			zap.Int("row_count", result.RowCount()))
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Error = err

// 	logger.Info("SnmpIfEntry collection completed",
// 		zap.Int("total_entries", reply.Total),
// 		zap.Float64("duration_seconds", reply.Duration),
// 		zap.Error(err))

// 	return err
// }

// func (ts *META) SnmpIfHighSpeed(ctx context.Context, arg *structs.Args, reply *structs.Reply) error {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("method", "SnmpIfHighSpeed"),
// 		zap.String("ip", arg.Ip),
// 		zap.String("platform", arg.Platform),
// 	)
// 	logger.Info("Starting SnmpIfHighSpeed collection")

// 	reply.StartTime = time.Now()
// 	result := &clitask.Table{}
// 	var err error
// 	ip := arg.Ip
// 	community := arg.Remote.Community[0]

// 	logger.Debug("Creating SNMP task",
// 		zap.String("oid", "1.3.6.1.2.1.31.1.1.1.15"),
// 		zap.String("community", community))

// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.31.1.1.1.15",
// 		[]int{0},
// 		[]int{},
// 		map[string]string{},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	if err != nil {
// 		logger.Error("Failed to create SNMP task", zap.Error(err))
// 		reply.Error = err
// 		return err
// 	}

// 	logger.Debug("Running SNMP task")
// 	st.Run(true)
// 	result, err = st.Table()
// 	if err != nil {
// 		logger.Error("SnmpIfHighSpeed collection failed",
// 			zap.Error(err),
// 			log.Tag("arg", arg))
// 	} else {
// 		logger.Info("SnmpIfHighSpeed collection successful",
// 			zap.Int("row_count", result.RowCount()))
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Error = err

// 	logger.Info("SnmpIfHighSpeed collection completed",
// 		zap.Int("total_entries", reply.Total),
// 		zap.Float64("duration_seconds", reply.Duration),
// 		zap.Error(err))

// 	return err
// }

// func (ts *META) TelnetNetworkPorts(ctx context.Context, arg *structs.Args, reply *structs.Reply) error {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("function", "TelnetNetworkPorts"),
// 		zap.String("ip", arg.Ip),
// 		zap.String("platform", arg.Remote.Platform),
// 	)
// 	logger.Info("Starting Telnet network ports collection")

// 	reply.StartTime = time.Now()
// 	result := &clitask.Table{}
// 	var err error

// 	if arg.Remote.Platform != "Comware" {
// 		logger.Warn("Unsupported platform for Telnet network ports collection", zap.String("platform", arg.Remote.Platform))
// 		result = &clitask.Table{}
// 	} else {
// 		logger.Debug("Collecting Comware network ports via Telnet")
// 		result, _, err = getTelnetNetworkPorts(arg.Ip, arg.Remote, logger)
// 		if err != nil {
// 			logger.Error("Failed to collect ports via Telnet", zap.Error(err))
// 			result = &clitask.Table{}
// 		} else {
// 			logger.Info("Successfully collected network ports via Telnet", zap.Int("portCount", result.RowCount()))
// 		}
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()

// 	logger.Info("Completed Telnet network ports collection",
// 		zap.Int("totalPorts", reply.Total),
// 		zap.Float64("duration", reply.Duration),
// 		zap.Error(err))

// 	reply.Error = err
// 	return err
// }

// func (ts *META) NetworkDevicePorts(ctx context.Context, arg *structs.Args, reply *structs.Reply) error {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("method", "NetworkDevicePorts"),
// 		zap.String("ip", arg.Ip),
// 		zap.String("platform", arg.Platform),
// 	)
// 	logger.Info("Starting NetworkDevicePorts collection")
// 	reply.StartTime = time.Now()
// 	result := &clitask.Table{}
// 	var err error
// 	var vlans []lb.Vlan

// 	switch arg.Platform {
// 	case "F5":
// 		logger.Info("Collecting F5 device ports")
// 		result, vlans, err = checkF5SelfWeb(arg.Ip, arg.Remote, logger)
// 		if err != nil {
// 			logger.Error("Failed to collect F5 device ports", zap.Error(err))
// 			result = &clitask.Table{}
// 			reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 			reply.Error = err
// 			return err
// 		}
// 		logger.Info("F5 VLANs collected", zap.Int("vlan_count", len(vlans)))
// 		table := clitask.NewEmptyTableWithKeys([]string{"mac", "name", "ip", "ip6"})
// 		for _, vlan := range vlans {
// 			data := make(map[string]string)
// 			var ips, ip6s []string
// 			for _, v := range vlan.Ipv4 {
// 				ips = append(ips, v.(string))
// 			}
// 			for _, v := range vlan.Ipv6 {
// 				ip6s = append(ip6s, v.(string))
// 			}
// 			data["mac"] = strings.TrimSpace(vlan.MacAddress)
// 			data["ip6"] = strings.TrimSpace(strings.Join(ip6s, ","))
// 			data["name"] = strings.TrimSpace(vlan.Name)
// 			data["ip"] = strings.TrimSpace(strings.Join(ips, ","))
// 			table.PushRow("", data, false, "")
// 		}
// 		result = table
// 		logger.Info("F5 device ports collection completed", zap.Int("port_count", result.RowCount()))

// 	case "FortiGate":
// 		logger.Info("Collecting FortiGate device ports")
// 		result, err = checkFortiGateSSHInterface(arg.Ip, arg.Remote, logger)
// 		if err != nil {
// 			logger.Error("Failed to collect FortiGate device ports", zap.Error(err))
// 		} else {
// 			logger.Info("FortiGate device ports collection completed", zap.Int("port_count", result.RowCount()))
// 		}

// 	default:
// 		logger.Info("Collecting network device ports using SNMP")
// 		result, err = checkNetworkDevicePorts(arg, logger)
// 		if err != nil || result.IsEmpty() {
// 			logger.Warn("SNMP collection failed, attempting Telnet method", zap.Error(err))
// 			result, _, err = getTelnetNetworkPorts(arg.Ip, arg.Remote, logger)
// 			if err != nil {
// 				logger.Error("Telnet collection failed", zap.Error(err))
// 				result = &clitask.Table{}
// 			} else {
// 				logger.Info("Telnet collection successful", zap.Int("port_count", result.RowCount()))
// 			}
// 		} else {
// 			logger.Info("SNMP collection successful", zap.Int("port_count", result.RowCount()))
// 		}
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Error = err

// 	logger.Info("NetworkDevicePorts collection completed",
// 		zap.Int("total_ports", reply.Total),
// 		zap.Float64("duration_seconds", reply.Duration),
// 		zap.Error(err))

// 	return nil
// }

// func nexusShowInIntBriefAll(arg *structs.Args) (results []map[string]string, err error) {
// 	ip := arg.Ip
// 	remote := arg.Remote
// 	// tb := clitask.NewEmptyTableWithKeys([]string{"port", "ip","subnet"})

// 	port := remote.Meta.SSHPort
// 	isTelenet := false
// 	if remote.Meta.EnableTelnet != nil && *remote.Meta.EnableTelnet {
// 		isTelenet = true
// 		port = remote.Meta.TelnetPort
// 	}

// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		Telnet:   isTelenet,
// 		Port:     port,
// 	}

// 	base.WithActionID(remote.ActionID)

// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Nexus, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("show ip int vrf all", "", 10, "ip_ports", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)
// 	// tb.PushRawData(data)
// 	if data.Error() != nil {
// 		err = data.Error()
// 		return
// 	}
// 	ok, lines := data.GetResult("ip_ports")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd= show ip int brief all")
// 		return
// 	}

// 	regmap := map[string]string{
// 		"regex": `(?P<port>\S+),\s+Interface status: protocol-up\/link-up\/admin-up, iod: \d+,[\n\r]+  IP address: (?P<ip>[\d\.]+), IP subnet: (?P<subnet>[\d\.\/]+)`,
// 		"flags": "m",
// 		"name":  "ip_ports",
// 		"pcre":  "false",
// 	}

// 	splitResult, err := text.SplitterProcessOneTime(regmap, strings.Join(lines, "\n"))
// 	if err != nil {
// 		return results, err
// 	}

// 	// result = []map[string]string
// 	for it := splitResult.Iterator(); it.HasNext(); {
// 		_, _, m := it.Next()
// 		results = append(results, m)
// 	}

// 	return
// }
// func (ts *META) NetworkDevicePortsRate(ctx context.Context, arg *structs.Args, reply *structs.Reply) error {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("function", "NetworkDevicePortsRate"),
// 		zap.String("ip", arg.Ip),
// 		zap.String("platform", arg.Platform),
// 	)
// 	logger.Info("Starting NetworkDevicePortsRate collection")

// 	reply.StartTime = time.Now()

// 	result, err := checkNetworkDevicePortsRate(arg.Ip, arg.Remote.Community[0], arg.Platform, logger)
// 	if err != nil {
// 		logger.Warn("SNMP get NetworkDevicePortsRate failed, attempting Telnet method",
// 			zap.Error(err),
// 			log.Tag("arg", arg))

// 		result, _, err = getTelnetNetworkPorts(arg.Ip, arg.Remote, logger)
// 		if err != nil {
// 			logger.Error("Telnet get NetworkDevicePortsRate also failed",
// 				log.Tag("arg", arg),
// 				zap.Error(err))
// 			result = &clitask.Table{}
// 			reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 			reply.Error = err
// 			logger.Info("NetworkDevicePortsRate collection failed",
// 				zap.Float64("duration_seconds", reply.Duration),
// 				zap.Error(err))
// 			return err
// 		}
// 		logger.Info("Successfully collected NetworkDevicePortsRate via Telnet")
// 	} else {
// 		logger.Info("Successfully collected NetworkDevicePortsRate via SNMP")
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Error = err

// 	logger.Info("NetworkDevicePortsRate collection completed",
// 		zap.Int("total_ports", reply.Total),
// 		zap.Float64("duration_seconds", reply.Duration),
// 		zap.Error(err))

// 	return nil
// }

// func (ts *META) IpBrief(ctx context.Context, arg *structs.Args, reply *structs.Reply) error {
// 	// logger := log.NewLogger(arg.Remote.ActionID, true)
// 	reply.StartTime = time.Now()
// 	tb := clitask.NewEmptyTableWithKeys([]string{"port", "ip", "subnet"})
// 	var err error
// 	if strings.ToUpper(arg.Remote.Platform) == "NEXUS" {
// 		ip := arg.Ip
// 		remote := arg.Remote

// 		port := remote.Meta.SSHPort
// 		isTelenet := false
// 		if remote.Meta.EnableTelnet != nil && *remote.Meta.EnableTelnet {
// 			isTelenet = true
// 			port = remote.Meta.TelnetPort
// 		}

// 		base := &terminal.BaseInfo{
// 			Host:     ip,
// 			Username: remote.Username,
// 			Password: remote.Password,
// 			Telnet:   isTelenet,
// 			Port:     port,
// 		}

// 		base.WithActionID(remote.ActionID)

// 		exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Nexus, base)
// 		exec.Id = uuid.Must(uuid.NewV4()).String()
// 		exec.Add("show ip int vrf all", "", 10, "ip_ports", "")
// 		exec.Prepare(false)
// 		data := exec.Run(false)
// 		tb.PushRawData(data)
// 		if data.Error() != nil {
// 			err = data.Error()
// 			reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 			reply.Error = err
// 			return err
// 		}
// 	}
// 	// result.Pretty()
// 	reply.Table = tb
// 	reply.Result = tb.ToSliceMap()
// 	reply.Total = tb.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Error = err

// 	return nil
// }
// func (ts *META) IsAlive(ctx context.Context, arg *structs.Args, reply *structs.Reply) (err error) {
// 	// logger := log.NewLogger(arg.Remote.ActionID, true)
// 	reply.StartTime = time.Now()
// 	// logger.Debug("IsAlive开始联通行测试", zap.Any("args", arg))
// 	var result *clitask.Table
// 	result, err = checkIsAlive(arg.Ip, arg.Remote)
// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Table = result
// 	reply.Error = err

// 	// result.Pretty()
// 	return
// }

// func (ts *META) NetworkDeviceVersion(ctx context.Context, arg *structs.Args, reply *structs.Reply) (err error) {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("function", "NetworkDeviceVersion"),
// 		zap.String("ip", arg.Ip),
// 		zap.String("platform", arg.Platform),
// 	)
// 	logger.Info("Starting NetworkDeviceVersion collection")

// 	reply.StartTime = time.Now()

// 	var result *clitask.Table
// 	var f5Info lb.F5DeviceInfo

// 	logger.Debug("Determining collection method based on platform")
// 	switch arg.Platform {
// 	case "ASA":
// 		logger.Debug("Using CheckNetworkDeviceVersion for ASA")
// 		result, err = CheckNetworkDeviceVersion(arg.Ip, arg.Remote.Community[0], arg.Platform, logger)
// 	case "F5":
// 		logger.Debug("Using checkF5InfoWeb for F5")
// 		result, f5Info, err = checkF5InfoWeb(arg.Ip, arg.Remote, logger)
// 	case "HWGpon":
// 		logger.Debug("Using checkHWGponVersionSSH for HWGpon")
// 		result, _, err = checkHWGponVersionSSH(arg.Ip, arg.Remote, logger)
// 	case "Ubuntu", "Centos":
// 		logger.Debug("Using linuxVersionAndHostnameSSH for Ubuntu/Centos")
// 		result, _, err = linuxVersionAndHostnameSSH(arg.Ip, arg.Remote, logger)
// 	case "MLNXOS":
// 		logger.Debug("Using checkMlnxosVersionSSH for MLNXOS")
// 		result, _, err = checkMlnxosVersionSSH(arg.Ip, arg.Remote, logger)
// 	case "Ruijie":
// 		logger.Debug("Using checkRuijieVersionSSH for Ruijie")
// 		result, _, err = checkRuijieVersionSSH(arg.Ip, arg.Remote, logger)
// 	case "FortiGate":
// 		logger.Debug("Using checkFortiGateVersionSSH for FortiGate")
// 		result, _, err = checkFortiGateVersionSSH(arg.Ip, arg.Remote, logger)
// 	default:
// 		logger.Debug("Using CheckNetworkDeviceVersion for default case")
// 		result, err = CheckNetworkDeviceVersion(arg.Ip, arg.Remote.Community[0], arg.Platform, logger)
// 	}

// 	if err != nil {
// 		logger.Error("NetworkDeviceVersion collection failed", zap.Error(err))
// 		reply.EndTime = time.Now()
// 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 		reply.Error = err
// 		return err
// 	}

// 	if arg.Platform == "F5" {
// 		logger.Debug("Processing F5 specific information")
// 		result = clitask.NewEmptyTableWithKeys([]string{"version", "serial", "sysName"})
// 		result.PushRow("", map[string]string{"version": f5Info.Version, "serial": strings.Join(f5Info.Sn, ","), "sysName": f5Info.HostName}, false, "")
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Error = err

// 	logger.Info("NetworkDeviceVersion collection completed",
// 		zap.Int("total_rows", reply.Total),
// 		zap.Float64("duration_seconds", reply.Duration),
// 		zap.Error(err))

// 	return nil
// }

// func (ts *META) DeviceMeta(ctx context.Context, args *structs.Args, reply *structs.Reply) (err error) {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("function", "DeviceMeta"),
// 		zap.String("ip", args.Ip),
// 		zap.String("platform", args.Platform),
// 	)
// 	logger.Info("Starting DeviceMeta collection")

// 	reply.StartTime = time.Now()
// 	session := NewWorkContext(ts, args)

// 	logger.Debug("Updating remote info")
// 	var remote *structs.L2DeviceRemoteInfo
// 	remote, err = session.updateRemoteInfo(args, logger)

// 	if err != nil {
// 		logger.Error("Failed to collect basic META",
// 			zap.Error(err),
// 			log.Tag("args", args))
// 		reply.EndTime = time.Now()
// 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 		reply.Error = err
// 		return
// 	}

// 	logger.Debug("Executing SSH commands", zap.Int("command_count", len(args.Options)))
// 	result, err := sshtool.ExecuteSSHCommands(remote, args.Options)
// 	if err != nil {
// 		logger.Error("Failed to execute commands",
// 			zap.Error(err),
// 			log.Tag("args", args))
// 		reply.EndTime = time.Now()
// 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 		reply.Table = result
// 		reply.Error = err
// 	} else {
// 		logger.Info("Successfully executed commands",
// 			zap.Int("result_count", result.RowCount()))
// 		reply.Result = result.ToSliceMap()
// 		reply.Total = result.RowCount()
// 		reply.EndTime = time.Now()
// 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 		reply.Table = result
// 		reply.Error = err
// 	}

// 	logger.Debug("Prettifying result table")
// 	result.Pretty()

// 	logger.Info("DeviceMeta collection completed",
// 		zap.Float64("duration_seconds", reply.Duration),
// 		zap.Int("total_results", reply.Total),
// 		zap.Error(err))

// 	return
// }

// // func executeSSHCommands(remote *structs.L2DeviceRemoteInfo, options []interface{}) (*clitask.Table, error) {
// // 	config := &ssh.ClientConfig{
// // 		User: remote.Username,
// // 		Auth: []ssh.AuthMethod{
// // 			ssh.Password(remote.Password),
// // 		},
// // 		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
// // 	}

// // 	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", remote.Ip, remote.Meta.SSHPort), config)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to dial: %v", err)
// // 	}
// // 	defer client.Close()

// // 	result := clitask.NewEmptyTableWithKeys([]string{"command", "key", "output", "msg", "status"})

// // 	for index, ops := range options {
// // 		cmd := ops.(string)
// // 		key := strings.Join(strings.Fields(cmd), "_")
// // 		key = fmt.Sprintf("%s_%d", key, index+1)

// // 		session, err := client.NewSession()
// // 		if err != nil {
// // 			return result, fmt.Errorf("failed to create session: %v", err)
// // 		}
// // 		defer session.Close()

// // 		var b bytes.Buffer
// // 		session.Stdout = &b
// // 		if err := session.Run(cmd); err != nil {
// // 			result.PushRow(fmt.Sprint(index+1), map[string]string{
// // 				"command": cmd,
// // 				"key":     key,
// // 				"output":  b.String(),
// // 				"msg":     err.Error(),
// // 				"status":  "false",
// // 			}, true, "")
// // 		} else {
// // 			result.PushRow(fmt.Sprint(index+1), map[string]string{
// // 				"command": cmd,
// // 				"key":     key,
// // 				"output":  b.String(),
// // 				"msg":     "",
// // 				"status":  "true",
// // 			}, true, "")
// // 		}
// // 	}

// // 	return result, nil
// // }

// // func (ts *META) DeviceMeta(ctx context.Context, args *structs.Args, reply *structs.Reply) (err error) {
// // 	logger := log.NewLogger(args.Remote.ActionID, true)

// // 	session := NewWorkContext(ts, args)

// // 	var remote *structs.L2DeviceRemoteInfo
// // 	// remote = args.Remote
// // 	remote, err = session.updateRemoteInfo(args)

// // 	// remote, err = session.gatherDeviceMeta(args)
// // 	if err != nil {
// // 		logger.ErrorNoStack("采集基础META失败", log.Tag("args", args), zap.Error(err))
// // 		reply.EndTime = time.Now()
// // 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// // 		// reply.Table = result
// // 		reply.Error = err
// // 		return
// // 	}

// // 	var result *clitask.Table
// // 	_, result, err = session.baseWithDeviceRemoteInfo(args, "step", remote)
// // 	if err != nil {
// // 		reply.EndTime = time.Now()
// // 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// // 		reply.Table = result
// // 		reply.Error = err
// // 	} else {
// // 		reply.Result = result.ToSliceMap()
// // 		reply.Total = result.RowCount()
// // 		reply.EndTime = time.Now()
// // 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// // 		reply.Table = result
// // 		// logger.Info("DeviceMeta", zap.Any("msg", "采集带内接口信息成功"), zap.Any("id", session.Uuid), zap.Any("error", err))
// // 		reply.Error = err
// // 	}

// // 	// fmt.Println("33333", resMap)
// // 	// a:=structs.L2DeviceRemoteInfo(resMap)
// // 	// *reply=structs.L2DeviceRemoteInfo()
// // 	// *reply = resMap
// // 	return
// // }

// func getIpmiLog(arg *structs.Args) (result *clitask.Table, err error) {
// 	cmd := fmt.Sprintf("ipmitool -I lanplus -H %s -U %s -P %s sel elist", arg.Ip, arg.Remote.Username, arg.Remote.Password)
// 	// cmd3 := exec.Command("bash", "-c", cmd)
// 	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
// 	defer cancel()
// 	cmd3 := exec.CommandContext(ctx, "bash", "-c", cmd)
// 	// output, err := cmd3.Output()
// 	output, err := cmd3.CombinedOutput()
// 	if ctx.Err() == context.DeadlineExceeded {
// 		return result, fmt.Errorf("command timed out,cmd:%s", cmd)
// 	} else if err != nil {
// 		return result, fmt.Errorf("getIpmiLog执行错误,err:%s,cmd:%s", err, cmd)
// 	}
// 	// lines := strings.Split(string(output), "\n")
// 	tb := clitask.NewEmptyTableWithKeys([]string{
// 		l2struct.IpmiLogDate, l2struct.IpmiLogID, l2struct.IpmiLogTime,
// 		l2struct.IpmiLogStatus, l2struct.IpmiLogDescription, l2struct.IpmiLogSensorName})
// 	tb.PushRawData(string(output))
// 	// for _, v := range lines {
// 	// 	if strings.Contains(v, "|") {
// 	// 		sp := strings.Split(v, "|")
// 	// 		m := make(map[string]string)
// 	// 		if len(sp) == 6 {
// 	// 			m[l2struct.IpmiLogID] = strings.TrimSpace(sp[0])
// 	// 			m[l2struct.IpmiLogDate] = strings.TrimSpace(sp[1])
// 	// 			m[l2struct.IpmiLogTime] = strings.TrimSpace(sp[2])
// 	// 			m[l2struct.IpmiLogSensorName] = strings.TrimSpace(sp[3])
// 	// 			m[l2struct.IpmiLogDescription] = strings.TrimSpace(sp[4])
// 	// 			m[l2struct.IpmiLogStatus] = strings.TrimSpace(sp[5])
// 	// 			err = tb.PushRow("", m, false, "")
// 	// 		}
// 	// 	}
// 	// }
// 	return tb, err
// }
// func (ts *META) IpmiLog(ctx context.Context, args *structs.Args, reply *structs.Reply) (err error) {
// 	logger := log.NewLogger(nil, true)
// 	var result *clitask.Table
// 	result, err = getIpmiLog(args)
// 	if err != nil {
// 		reply.EndTime = time.Now()
// 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 		reply.Table = result
// 		reply.Error = err
// 		logger.ErrorNoStack("采集日志信息信息失败", log.Tag("arg", args), zap.Error(err))
// 	} else {
// 		reply.Result = result.ToSliceMap()
// 		reply.Total = result.RowCount()
// 		reply.EndTime = time.Now()
// 		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 		reply.Table = result
// 		// logger.Info("DeviceMeta", zap.Any("msg", "采集带内接口信息成功"), zap.Any("id", session.Uuid), zap.Any("error", err))
// 		reply.Error = err
// 		// result.Pretty()
// 	}
// 	return
// }

// func (ts *WorkContext) updateRemoteInfo(arg *structs.Args, logger *zap.Logger) (remoteInfo *structs.L2DeviceRemoteInfo, err error) {
// 	// logger = logger.With(zap.String("function", "updateRemoteInfo"), zap.String("ip", arg.Ip))
// 	// logger.Info("Starting remote info update")

// 	remoteInfo = arg.Remote

// 	if !reachable.IsAlive(arg.Ip) {
// 		remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(false)
// 		logger.Error("Device is unreachable", zap.String("ip", arg.Ip))
// 		return remoteInfo, fmt.Errorf("%s is unreachable", arg.Ip)
// 	}

// 	logger.Debug("Checking SSH port")
// 	if remoteInfo.Meta.SSHPort == 0 {
// 		remoteInfo.Meta.SSHPort = 22
// 		logger.Debug("SSH port not set, using default", zap.Int("port", remoteInfo.Meta.SSHPort))
// 	}
// 	remoteInfo.Meta.EnableSSH = func(b bool) *bool { return &b }(reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.SSHPort)))
// 	logger.Info("SSH port status", zap.Bool("enabled", *remoteInfo.Meta.EnableSSH), zap.Int("port", remoteInfo.Meta.SSHPort))

// 	logger.Debug("Checking Telnet port")
// 	if remoteInfo.Meta.TelnetPort == 0 {
// 		remoteInfo.Meta.TelnetPort = 23
// 		logger.Debug("Telnet port not set, using default", zap.Int("port", remoteInfo.Meta.TelnetPort))
// 	}
// 	remoteInfo.Meta.EnableTelnet = func(b bool) *bool { return &b }(reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.TelnetPort)))
// 	logger.Info("Telnet port status", zap.Bool("enabled", *remoteInfo.Meta.EnableTelnet), zap.Int("port", remoteInfo.Meta.TelnetPort))

// 	logger.Debug("Checking Restful port")
// 	if remoteInfo.Meta.RestfullPort == 0 {
// 		remoteInfo.Meta.RestfullPort = 8443
// 		logger.Debug("Restful port not set, using default", zap.Int("port", remoteInfo.Meta.RestfullPort))
// 	}
// 	remoteInfo.Meta.EnableRestfull = func(b bool) *bool { return &b }(reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.RestfullPort)))
// 	logger.Info("Restful port status", zap.Bool("enabled", *remoteInfo.Meta.EnableRestfull), zap.Int("port", remoteInfo.Meta.RestfullPort))

// 	logger.Debug("Checking Netconf port")
// 	if remoteInfo.Meta.NetconfPort == 0 {
// 		remoteInfo.Meta.NetconfPort = 830
// 		logger.Debug("Netconf port not set, using default", zap.Int("port", remoteInfo.Meta.NetconfPort))
// 	}
// 	remoteInfo.Meta.EnableNetconf = func(b bool) *bool { return &b }(reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.NetconfPort)))
// 	logger.Info("Netconf port status", zap.Bool("enabled", *remoteInfo.Meta.EnableNetconf), zap.Int("port", remoteInfo.Meta.NetconfPort))

// 	logger.Debug("Checking Redfish port")
// 	if remoteInfo.Meta.RedfishPort == 0 {
// 		remoteInfo.Meta.RedfishPort = 830
// 		logger.Debug("Redfish port not set, using default", zap.Int("port", remoteInfo.Meta.RedfishPort))
// 	}
// 	// Note: Redfish port check is commented out in the original code

// 	logger.Info("Creating DeviceInfoProvider")
// 	de, err := NewDeviceInfoProvider(remoteInfo)
// 	if err != nil {
// 		logger.Error("Failed to create DeviceInfoProvider", zap.Error(err))
// 		remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(false)
// 		return remoteInfo, err
// 	}

// 	logger.Info("Getting device version")
// 	version, err := de.GetVersion(arg, remoteInfo)
// 	if err != nil {
// 		logger.Error("Failed to get device version", zap.Error(err))
// 		remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(false)
// 		return remoteInfo, err
// 	}

// 	logger.Info("Getting child version")
// 	childVersion, childErr := de.GetChildVersion(arg, remoteInfo)
// 	if childErr != nil {
// 		logger.Warn("Failed to get child version", zap.Error(childErr))
// 	}

// 	remoteInfo.Meta.PatchVersion = childVersion
// 	remoteInfo.Meta.Version = version
// 	remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(true)

// 	logger.Info("Remote info update completed successfully",
// 		zap.String("version", version),
// 		zap.String("childVersion", childVersion))

// 	return remoteInfo, nil
// }

// func (ts *WorkContext) baseWithDeviceRemoteInfo(arg *structs.Args, serviceType string, remote *structs.L2DeviceRemoteInfo) ([]map[string]string, *clitask.Table, error) {
// 	logger := log.NewLogger(remote.ActionID, true)

// 	var err error
// 	service, desc := Config.Select(context.TODO(), remote, serviceType)
// 	if !desc.Ok() {
// 		return []map[string]string{}, nil, desc.Error()
// 	}
// 	var resultTable *clitask.Table

// 	// logger.Debug(
// 	// 	"baseWithDeviceRemoteInfo 选择服务实例",
// 	// 	log.Tag("remote", remote),
// 	// )

// 	resultTable, err = service.Run(remote, arg.Options...)
// 	if err != nil {
// 		logger.Warn("baseWithDeviceRemoteInfo failed", zap.Any("method", "RUN"), zap.Any("serviceName", service.ServiceName()), log.Tag("arg", arg), zap.Error(err))
// 		return []map[string]string{}, resultTable, err
// 	}

// 	if resultTable != nil {
// 		logger.Debug("baseWithDeviceRemoteInfo", zap.Any("count", resultTable.RowCount()))
// 		return resultTable.ToSliceMap(), resultTable, nil
// 	} else {
// 		logger.Debug("baseWithDeviceRemoteInfo", zap.Any("count", 0), log.Tag("arg", arg))
// 		return []map[string]string{}, resultTable, nil
// 	}
// }

// // func (ts *WorkContext) gatherDeviceMeta(arg *Args) (remoteInfo *model.structs.L2DeviceRemoteInfo, err error) {
// // remoteInfo = arg.Remote
// // var meta *model.DeviceMeta
// // var platformName string
// // switch arg.StructType {
// // case VirtualizationVirtualmachine:
// // var device model.DeviceWithPlatform
// // device, err = deviceService.GetDevice(arg.Id, arg.StructType)
// // if err != nil {
// // global.GVA_LOG.Info("DeviceMeta", zap.Any("id", ts.Uuid), zap.Any("method", "Device"), zap.Any("err", err))
// // return
// // }
// //
// // platformName = arg.Platform
// //
// // withMeta := true
// // if arg.IsRedfish {
// // remoteInfo, meta, err = deviceService.GetRemoteInfo(device, arg.Ip, arg.Platform, ts.SnmpRole, ts.RedfishRole, withMeta)
// // } else {
// // remoteInfo, meta, err = deviceService.GetRemoteInfo(device, arg.Ip, arg.Platform, ts.SnmpRole, ts.SecretRole, withMeta)
// // }
// // if err != nil {
// // global.GVA_LOG.Info("DeviceMeta", zap.Any("id", ts.Uuid), zap.Any("method", "GetRemoteInfo"), zap.Any("err", err))
// // return
// // }
// // case SdnController:
// // var sdnController model.SdnController
// // var secret model.SecretsSecret
// //
// // tx := global.GVA_DB.Model(&sdnController).Where("id = ?", arg.Id).Preload("ShareSecrets").Preload("DcimPlatform").First(&sdnController)
// // if tx.RowsAffected == 0 {
// // err = tx.Error
// // if err == nil {
// // err = fmt.Errorf("get sdn controller failed, id=%d", arg.Id)
// // global.GVA_LOG.Debug("DeviceMeta", zap.Any("id", ts.Uuid), zap.Any("phase", "GetSdnController"), zap.Any("err", err))
// // }
// // return
// // }
// // if len(sdnController.ShareSecrets) != 0 {
// // secret = *sdnController.ShareSecrets[0]
// // }
// // platformName = sdnController.DcimPlatform.Name
// // remoteInfo.Ip = arg.Ip
// // remoteInfo.Username = secret.Username
// // remoteInfo.Password = secret.PlainText
// // remoteInfo.AuthPass = secret.AuthPlainText
// // remoteInfo.PrivateKey = secret.Key
// // remoteInfo.Platform = platformName
// //
// // case DcimInputDevice:
// // var dcimDeviceInput model.DcimInputDevice
// // var secret model.SecretsSecret
// // var platformModel *model.DcimPlatform
// // tx := global.GVA_DB.Model(&dcimDeviceInput).Where("id = ?", arg.Id).First(&dcimDeviceInput)
// // if tx.RowsAffected == 0 {
// // err = tx.Error
// // if err == nil {
// // err = fmt.Errorf("get dcim input device failed, id=%d", arg.Id)
// // global.GVA_LOG.Debug("DeviceMeta", zap.Any("id", ts.Uuid), zap.Any("phase", "GetInputDevice"), zap.Any("err", err))
// // }
// // return
// // }
// // secret, err = deviceService.GetSecretDataModel(dcimDeviceInput.InRole, ts.Uuid)
// // if err != nil {
// // global.GVA_LOG.Info("DeviceMeta", zap.Any("id", ts.Uuid), zap.Any("method", "GetSecretDataModel"), zap.Any("err", err))
// // return
// // }
// //
// // platformModel, err = deviceService.GetDevicePlatform(dcimDeviceInput.Version)
// //
// // if err != nil {
// // global.GVA_LOG.Info("DeviceMeta", zap.Any("id", ts.Uuid), zap.Any("method", "GetPlatformFromString"), zap.Any("err", err))
// // return
// // }
// // platformName = platformModel.Name
// // remoteInfo.Ip = arg.Ip
// // remoteInfo.Username = secret.Username
// // remoteInfo.Password = secret.PlainText
// // remoteInfo.AuthPass = secret.AuthPlainText
// // remoteInfo.PrivateKey = secret.Key
// // remoteInfo.Manufacturer = dcimDeviceInput.Manufacturer
// // remoteInfo.Platform = platformName
// // }
// // if !reachable.IsAlive(arg.Ip) {
// // remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(false)
// // err = fmt.Errorf("%s is unreachable", arg.Ip)
// // global.GVA_LOG.Info("DeviceMeta", zap.Any("id", ts.Uuid), zap.Any("method", "IsAlive"), zap.Any("err", err))
// // return remoteInfo, err
// // }
// //
// // meta.Meta = remoteInfo.Meta
// // meta.ID = remoteInfo.MetaID
// // if remoteInfo.Meta.SSHPort == 0 {
// // remoteInfo.Meta.SSHPort = 22
// // }
// // if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.SSHPort)) {
// // remoteInfo.Meta.EnableSSH = func(b bool) *bool { return &b }(true)
// // } else {
// // remoteInfo.Meta.EnableSSH = func(b bool) *bool { return &b }(false)
// // }
// //
// // if remoteInfo.Meta.TelnetPort == 0 {
// // remoteInfo.Meta.TelnetPort = 23
// // }
// // if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.TelnetPort)) {
// // remoteInfo.Meta.EnableTelnet = func(b bool) *bool { return &b }(true)
// // } else {
// // remoteInfo.Meta.EnableTelnet = func(b bool) *bool { return &b }(false)
// // }
// //
// // if remoteInfo.Meta.RestfullPort == 0 {
// // remoteInfo.Meta.RestfullPort = 8443
// // }
// // if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.RestfullPort)) {
// // remoteInfo.Meta.EnableRestfull = func(b bool) *bool { return &b }(true)
// // } else {
// // remoteInfo.Meta.EnableRestfull = func(b bool) *bool { return &b }(false)
// // }
// //
// // if remoteInfo.Meta.NetconfPort == 0 {
// // remoteInfo.Meta.NetconfPort = 830
// // }
// // if reachable.TCPPortAlive(arg.Ip, fmt.Sprint(remoteInfo.Meta.NetconfPort)) {
// // remoteInfo.Meta.EnableNetconf = func(b bool) *bool { return &b }(true)
// // } else {
// // remoteInfo.Meta.EnableNetconf = func(b bool) *bool { return &b }(false)
// // }
// //
// // if remoteInfo.Meta.RedfishPort == 0 {
// // remoteInfo.Meta.RedfishPort = 830
// // }
// // meta.EnableRedfish = func(b bool) *bool { return &b }(true)
// //
// // Todo: 可能需要专门进行版本分析的方法，而且需要考虑具体位置
// // global.GVA_LOG.Debug("DeviceMeta", zap.Any("platformName", platformName))
// // version := ""
// // switch strings.ToUpper(platformName) {
// // case "CENTOS":
// // version, err = checkCentosVersionSSH(arg.Ip, remoteInfo)
// // case "REDHAT":
// // version, err = checkRedhatVersionSSH(arg.Ip, remoteInfo)
// // case "ACI":
// // version, err = checkAciVersion(arg.Ip, remoteInfo.Username, remoteInfo.Password)
// // default:
// // version, err = checkServerVersionSSH(arg.Ip, remoteInfo)
// // }
// // if err != nil {
// // remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(false)
// // } else {
// // remoteInfo.Meta.Version = version
// // remoteInfo.Meta.Enable = func(b bool) *bool { return &b }(true)
// // }
// // global.GVA_LOG.Debug("DeviceMeta", zap.Any("id", ts.Uuid), zap.Any("meta", remoteInfo.Meta), zap.Any("error", err))
// // return
// //
// // }

// // func GetPlatformFromString(name string) (platformName string, err error) {
// // var platformList []model.DcimPlatform
// // if strings.Contains(strings.ToLower(name), "red") || strings.Contains(strings.ToLower(name), "rhel") {
// // name = "redhat"
// // }
// //
// // tx := global.GVA_DB.Model(&platformList).Find(&platformList)
// // err = tx.Error
// // if tx.RowsAffected < 1 {
// // if err == nil {
// // err = fmt.Errorf("get platform list failed, %+v\n", platformList)
// // }
// // return
// // }
// //
// // for _, platform := range platformList {
// // if strings.Contains(strings.ToLower(name), strings.ToLower(platform.Name)) {
// // platformName = platform.Name
// // break
// // }
// // }
// // if platformName == "" {
// // err = fmt.Errorf("platformName is not find")
// //
// // }
// // return
// // }
// // func (ts *META) Meta(ctx context.Context, args *structs.Args, reply *structs.Reply) (err error) {
// // 	session := NewWorkContext(ts, args)
// // 	logger := log.NewLogger(args.Remote.ActionID, true)
// //
// // 	logger.Debug("开始采集Meta", zap.Any("args", args.KeyMap()))
// //
// // 	// global.GVA_LOG.Debug("开始采集META", zap.Any("id", session.Uuid), zap.Any("args", args))
// //
// // 	// mr := structs.MetaReply{}
// // 	// var meta model.DeviceMeta
// // 	reply.StartTime = time.Now()
// // 	reply.Meta, err = session.gatherMeta(args)
// // 	reply.EndTime = time.Now()
// // 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// // 	if err != nil {
// // 		reply.Total = 0
// // 	} else {
// // 		reply.Total = 1
// // 	}
// // 	reply.Error = err
// //
// // 	if err != nil {
// // 		// global.GVA_LOG.Info("JSON序列化失败", zap.Any("id", session.Uuid), zap.Any("arg", args), zap.Any("error", err))
// // 	}
// //
// // 	logger.Info("采集Meta完成", zap.Error(err))
// // 	return
// // }

// func (ts *META) Meta(ctx context.Context, args *structs.Args, reply *structs.Reply) error {
// 	logger := log.NewLogger(nil, true).With(
// 		zap.String("function", "Meta"),
// 		zap.String("ip", args.Ip),
// 		zap.String("platform", args.Platform),
// 	)
// 	logger.Info("Starting Meta collection")

// 	session := NewWorkContext(ts, args)
// 	reply.StartTime = time.Now()

// 	logger.Debug("Gathering meta information")
// 	result, err := session.gatherMeta2(args, logger)
// 	if err != nil {
// 		logger.Error("Failed to gather meta information",
// 			zap.Error(err),
// 			log.Tag("arg", args))
// 		result = &clitask.Table{}
// 		reply.Duration = time.Since(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 		reply.Error = err
// 		logger.Info("Meta collection failed",
// 			zap.Float64("duration_seconds", reply.Duration),
// 			zap.Error(err))
// 		return err
// 	}

// 	reply.Table = result
// 	reply.Result = result.ToSliceMap()
// 	reply.Total = result.RowCount()
// 	reply.EndTime = time.Now()
// 	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
// 	reply.Error = err

// 	logger.Info("Meta collection completed successfully",
// 		zap.Int("total_rows", reply.Total),
// 		zap.Float64("duration_seconds", reply.Duration))

// 	// Optionally, you can log the result details if needed
// 	// logger.Debug("Meta collection result", zap.Any("result", reply.Result))

// 	return nil
// }

// const (
// 	GET_DEVICE = "GET_DEVICE"
// 	GET_META   = "GET_META"
// 	GET_REMOTE = "GET_REMOTE"
// 	Ping       = "Ping"
// 	SSH        = "SSH"
// 	TELNET     = "TELNET"
// 	RESTFUL    = "RESTFUL"
// 	NETCONF    = "NETCONF"
// 	REDFISH    = "REDFISH"
// )

// // const (
// // META       = "META"
// // DeviceMeta = "DeviceMeta"
// // )

// const (
// 	UNREACHABLIE = 1
// 	PORT_CLOSE   = 2
// 	PORT_OPEN    = 3
// )

// type state struct {
// 	phase   string
// 	success bool
// 	err     error
// 	ip      string
// }

// func checkPing(ip string) (s *state) {
// 	s = &state{
// 		success: false,
// 		ip:      ip,
// 	}

// 	if reachable.IsAlive(ip) {
// 		s.success = true
// 	} else {
// 		s.err = fmt.Errorf("%s is unreachable\n", ip)
// 	}

// 	return
// }

// func checkPort(ip string, port string) (s *state) {
// 	s = &state{
// 		success: false,
// 		ip:      ip,
// 	}

// 	if reachable.TCPPortAlive(ip, port) {
// 		s.success = true
// 	} else {
// 		s.err = fmt.Errorf("tcp %s:%s is unreachable\n", ip, port)
// 	}

// 	return
// }

// func checkSnmpEanble(ip string, community string, username, password string) (v2, v3 bool) {
// 	v2State := checkSnmp(ip, community, false, username, password)
// 	v3State := checkSnmp(ip, community, true, username, password)

// 	return v2State.success, v3State.success
// }

// func checkSnmp(ip string, community string, v3 bool, username, password string) (s *state) {
// 	s = &state{
// 		success: false,
// 		ip:      ip,
// 	}

// 	snmp := deepcopy.Copy(g.Default).(*g.GoSNMP)

// 	snmp.Target = ip
// 	snmp.Community = community
// 	if v3 {
// 		snmp.Version = g.Version3
// 		snmp.SecurityModel = g.UserSecurityModel
// 		snmp.MsgFlags = g.AuthNoPriv
// 		snmp.SecurityParameters = &g.UsmSecurityParameters{
// 			UserName:                 username,
// 			AuthenticationProtocol:   g.MD5,
// 			AuthenticationPassphrase: password,
// 		}
// 	}
// 	// g.Default.Logger = g.NewLogger(log.New(os.Stdout, "", 0))

// 	err := snmp.Connect()
// 	if err != nil {
// 		s.err = err
// 		return
// 	}
// 	defer snmp.Conn.Close()
// 	_, err = snmp.Get([]string{"1.3.6.1.2.1.1"})
// 	if err != nil {
// 		s.err = err
// 	} else {
// 		s.success = true
// 	}

// 	return
// }

// //
// // func (ts *WorkContext) checkVersion(arg *structs.Args) (version string, err error) {
// // meta := arg.Meta
// // remoteInfo := arg.Remote
// //
// // switch arg.StructType {
// // case SdnController:
// // if meta.Meta.EnableRestfull != nil && *meta.Meta.EnableRestfull {
// // meta.Meta.Enable = func(b bool) *bool { return &b }(true)
// // }
// // var version string
// // version, err = checkAciVersion(arg.Ip, arg.Remote)
// // meta.Meta.Version = version
// // case VirtualizationCluster:
// // if meta.Meta.EnableRestfull != nil && *meta.Meta.EnableRestfull {
// // meta.Meta.Enable = func(b bool) *bool { return &b }(true)
// // }
// // case DcimDevice, VirtualizationVirtualmachine:
// // if arg.IsRedfish {
// // redfishversion, _ := checkRedfishVersion2(remoteInfo)
// // if redfishversion == "" {
// // meta.Meta.EnableRedfish = func(b bool) *bool { return &b }(false)
// // } else {
// // meta.Meta.RedfishVersion = redfishversion
// // meta.Meta.EnableRedfish = func(b bool) *bool { return &b }(true)
// // }
// //
// // } else {
// // if arg.Remote.Catalog == CATALOG_SWITCH {
// // for _, c := range remoteInfo.Community {
// // version, err = checkNetworkDeviceVersion(arg.Ip, c, arg.Remote.Platform)
// // if err != nil {
// // logger.Info("checkVersion", zap.Any("msg", "获取版本失败"), zap.Any("ip", arg.Ip), zap.Any("error", err))
// // } else {
// // meta.Meta.Version = version
// // meta.Meta.EnableSnmp = func(b bool) *bool { return &b }(true)
// // meta.Meta.Enable = func(b bool) *bool { return &b }(true)
// // logger.Debug("checkVersion", zap.Any("msg", "获取版本成功"), zap.Any("ip", arg.Ip), zap.Any("version", version))
// // break
// // }
// // }
// // } else if arg.Remote.Catalog == CATALOG_SERVER {
// // switch strings.ToUpper(arg.Remote.Platform) {
// // case "CENTOS":
// // version, err = checkCentosVersionSSH(arg.Ip, remoteInfo)
// // case "REDHAT":
// // version, err = checkRedhatVersionSSH(arg.Ip, remoteInfo)
// // case "EXSI":
// //
// // default:
// // version, err = checkServerVersionSSH(arg.Ip, remoteInfo)
// // }
// // if err != nil {
// // meta.Meta.Enable = func(b bool) *bool { return &b }(false)
// // logger.Info("checkVersion", zap.Any("msg", "获取版本失败"), zap.Any("ip", arg.Ip), zap.Any("error", err))
// // } else {
// // meta.Meta.Version = version
// // meta.Meta.Enable = func(b bool) *bool { return &b }(true)
// // logger.Debug("checkVersion", zap.Any("msg", "获取版本成功"), zap.Any("ip", arg.Ip), zap.Any("version", version))
// // }
// // }
// // }
// //
// // }
// // return "", nil
// // }

// // func (ts *WorkContext) gatherMeta(arg *structs.Args) (*structs.Meta, error) {
// // 	// remoteInfo := arg.Remote
// // 	remoteInfo, err := ts.updateRemoteInfo(arg)

// // 	if err != nil {
// // 		meta := &remoteInfo.Meta
// // 		return meta, err
// // 	}

// // 	meta := &remoteInfo.Meta
// // 	return meta, err
// // }

// func boolToString(b *bool) string {
// 	if b == nil {
// 		return "false"
// 	}
// 	if *b == true {
// 		return "true"
// 	} else {
// 		return "false"
// 	}
// }

// func (ts *WorkContext) gatherMeta2(arg *structs.Args, logger *zap.Logger) (result *clitask.Table, err error) {
// 	// remoteInfo := arg.Remote
// 	remoteInfo, err := ts.updateRemoteInfo(arg, logger)
// 	if err != nil {
// 		return
// 	}
// 	result = clitask.NewEmptyTableWithKeys(
// 		[]string{l2struct.MetaRestfullPort,
// 			l2struct.MetaNetconfPort, l2struct.MetaTelnetPort, l2struct.MetaSShPort, l2struct.MetaIpmiPort,
// 			l2struct.MetaRedfishPort, l2struct.MetaEnable, l2struct.MetaEnableSSh,
// 			l2struct.MetaEnableTelnet, l2struct.MetaEnableNetconf, l2struct.MetaEnableRestfull, l2struct.MetaEnableIpmi,
// 			l2struct.MetaEnableSnmp, l2struct.MetaEnableRedfish, l2struct.MetaVersion, l2struct.MetaRedfishVersion, l2struct.MetaPatchVersion})
// 	if remoteInfo != nil {
// 		data := map[string]string{
// 			l2struct.MetaNetconfPort:    strconv.Itoa(remoteInfo.Meta.NetconfPort),
// 			l2struct.MetaRestfullPort:   strconv.Itoa(remoteInfo.Meta.RestfullPort),
// 			l2struct.MetaTelnetPort:     strconv.Itoa(remoteInfo.Meta.TelnetPort),
// 			l2struct.MetaSShPort:        strconv.Itoa(remoteInfo.Meta.SSHPort),
// 			l2struct.MetaIpmiPort:       strconv.Itoa(remoteInfo.Meta.IPMIPort),
// 			l2struct.MetaRedfishPort:    strconv.Itoa(remoteInfo.Meta.RedfishPort),
// 			l2struct.MetaEnable:         boolToString(remoteInfo.Meta.Enable),
// 			l2struct.MetaEnableSSh:      boolToString(remoteInfo.Meta.EnableSSH),
// 			l2struct.MetaEnableTelnet:   boolToString(remoteInfo.Meta.EnableTelnet),
// 			l2struct.MetaEnableNetconf:  boolToString(remoteInfo.Meta.EnableNetconf),
// 			l2struct.MetaEnableRestfull: boolToString(remoteInfo.Meta.EnableRestfull),
// 			l2struct.MetaEnableIpmi:     boolToString(remoteInfo.Meta.EnableIPMI),
// 			l2struct.MetaEnableSnmp:     boolToString(remoteInfo.Meta.EnableSnmp),
// 			l2struct.MetaEnableRedfish:  boolToString(remoteInfo.Meta.EnableRedfish),
// 			l2struct.MetaVersion:        remoteInfo.Meta.Version,
// 			l2struct.MetaRedfishVersion: remoteInfo.Meta.RedfishVersion,
// 			l2struct.MetaPatchVersion:   remoteInfo.Meta.PatchVersion,
// 		}
// 		result.PushRow("1", data, true, "")
// 	}

// 	return
// }

// func networkDeviceSerialTable(arg *structs.Args, logger *zap.Logger) (result *clitask.Table, err error) {
// 	ip := arg.Ip
// 	community := arg.Remote.Community[0]
// 	manufacturer := arg.Remote.Manufacturer
// 	platformName := arg.Platform

// 	logger.Info("Starting network device serial table collection",
// 		zap.String("manufacturer", manufacturer))

// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.47.1.1.1.1.2",
// 		[]int{0},
// 		[]int{},
// 		map[string]string{},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	if err != nil {
// 		logger.Error("Failed to create SNMP task for device name", zap.Error(err))
// 		return nil, err
// 	}

// 	st.Run(true)
// 	table, err := st.Table()
// 	if err != nil {
// 		logger.Error("Failed to get device name table", zap.Error(err))
// 		return nil, err
// 	}

// 	if table.IsEmpty() {
// 		logger.Info("Device name table is empty")
// 		return nil, fmt.Errorf("No serial number found")
// 	}

// 	st, err = snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.47.1.1.1.1.11",
// 		[]int{0},
// 		[]int{},
// 		map[string]string{},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	if err != nil {
// 		logger.Error("Failed to create SNMP task for serial number", zap.Error(err))
// 		return nil, err
// 	}

// 	st.Run(true)
// 	table2, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get serial number table", zap.Error(err))
// 		return nil, err
// 	}

// 	err = table.AddKeyFromTable("serial", "", "value", "", table2, "")
// 	if err != nil {
// 		logger.Error("Failed to add serial number to table", zap.Error(err))
// 		return table, err
// 	}

// 	table.RenameColumn("value", "name")
// 	newTable := table.Grep(func(t *clitask.Table, index string, row map[string]string) bool {
// 		return row["serial"] != ""
// 	})

// 	switch strings.ToUpper(manufacturer) {
// 	case "H3C", "SECPATH":
// 		newTable = newTable.Grep(h3cSerialGrep(platformName))
// 	}

// 	logger.Info("Network device serial table collection completed",
// 		zap.Int("rows", newTable.RowCount()))

// 	return newTable, nil
// }

// type grepFunc func(*clitask.Table, string, map[string]string) bool

// func h3cSerialGrep(platformName string) grepFunc {
// 	return func(t *clitask.Table, index string, row map[string]string) bool {
// 		if strings.Index(row["name"], "Software") >= 0 || strings.Index(row["name"], "Router") > 0 || strings.Index(row["name"], "SecPath") >= 0 {
// 			return true
// 		}
// 		return false
// 	}
// }

// func checkASAVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, version string, err error) {
// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.AuthPass,
// 		// PrivateKey: remote.PrivateKey,
// 		Telnet: false,
// 		Port:   remote.Meta.SSHPort,
// 	}
// 	//
// 	// if remote.CtxID != "" {
// 	// ctx := context.Background()
// 	// ctx = context.WithValue(ctx, "ctx_id", remote.CtxID)
// 	// base.WithContext(ctx)
// 	// }

// 	// if remote.ActionID != nil {
// 	base.WithActionID(remote.ActionID)
// 	// }

// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.ASA, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("show version", "", 10, "sh_ver", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)
// 	fmt.Println("version data : =====", data)

// 	if data.Error() != nil {
// 		err = data.Error()
// 		return
// 	}
// 	var m map[string]string
// 	ok, lines := data.GetResult("sh_ver")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "lsb_release -a")
// 		return
// 	}

// 	// m, err = text.GetFieldByRegex(`Release:\s+(?P<version>\S+)`, strings.Join(lines, "\n"), []string{"version"})
// 	m, err = text.GetFieldByRegex(`Appliance Software Version\s+(?P<version>\S+)`, strings.Join(lines, "\n"), []string{"version"})
// 	if err != nil {
// 		return
// 	}

// 	result = clitask.NewEmptyTableWithKeys([]string{"version"})
// 	result.PushRow("0", map[string]string{"version": m["version"]}, false, "")
// 	version = m["version"]
// 	return
// }

// func checkMlnxosVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	// logger = logger.With(zap.String("function", "checkMlnxosVersionSSH"), zap.String("ip", ip))
// 	// logger.Info("Starting Mlnxos version check via SSH")

// 	var sysName string
// 	if len(remote.Community) > 0 {
// 		logger.Debug("Attempting to get sysName via SNMP")
// 		st, _ := snmp.NewSnmpTask(
// 			ip,
// 			remote.Community[0],
// 			"1.3.6.1.2.1.1",
// 			[]int{1},
// 			[]int{0},
// 			map[string]string{"3": "uptime", "5": "sysName"},
// 			map[string]func(byte, string, interface{}) (string, error){},
// 			nil)

// 		st.Run(true)
// 		table, err := st.Table()
// 		if err != nil {
// 			logger.Warn("Failed to get sysName via SNMP", zap.Error(err))
// 		} else {
// 			for _, v := range table.ToSliceMap() {
// 				sysName = v["sysName"]
// 				logger.Debug("Retrieved sysName via SNMP", zap.String("sysName", sysName))
// 			}
// 		}
// 	}

// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.Password,
// 		Telnet:   false,
// 		Port:     remote.Meta.SSHPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	logger.Debug("Initializing SSH execution")
// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.MLMNOS, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("sh version", "", 3, "sh_version", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		err = data.Error()
// 		logger.Error("Failed to execute SSH command", zap.Error(err))
// 		return
// 	}

// 	ok, lines := data.GetResult("sh_version")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "sh version")
// 		logger.Error("Failed to get command result", zap.Error(err))
// 		return
// 	}

// 	logger.Debug("Processing version information")
// 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName", "patchVersion"})
// 	for _, line := range lines {
// 		if strings.Contains(line, "Product release:") {
// 			versionSplit := strings.Split(line, ":")
// 			if len(versionSplit) > 1 {
// 				version = strings.TrimSpace(versionSplit[1])
// 				logger.Info("Found version", zap.String("version", version))
// 				result.PushRow("0", map[string]string{"version": version, "sysName": sysName}, false, "")
// 				break
// 			}
// 		}
// 	}

// 	if result.RowCount() == 0 {
// 		logger.Warn("No version information found")
// 	} else {
// 		logger.Info("Successfully retrieved Mlnxos version information",
// 			zap.String("version", version),
// 			zap.String("sysName", sysName))
// 	}

// 	return
// }

// func checkRuijieVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	// logger = logger.With(zap.String("function", "checkRuijieVersionSSH"), zap.String("ip", ip))
// 	// logger.Info("Starting Ruijie version check via SSH")

// 	var sysName string
// 	if len(remote.Community) > 0 {
// 		logger.Debug("Attempting to get sysName via SNMP")
// 		st, _ := snmp.NewSnmpTask(
// 			ip,
// 			remote.Community[0],
// 			"1.3.6.1.2.1.1",
// 			[]int{1},
// 			[]int{0},
// 			map[string]string{"3": "uptime", "5": "sysName"},
// 			map[string]func(byte, string, interface{}) (string, error){},
// 			nil)

// 		st.Run(true)
// 		table, err := st.Table()
// 		if err != nil {
// 			logger.Warn("Failed to get sysName via SNMP", zap.Error(err))
// 		} else {
// 			for _, v := range table.ToSliceMap() {
// 				sysName = v["sysName"]
// 				logger.Debug("Retrieved sysName via SNMP", zap.String("sysName", sysName))
// 			}
// 		}
// 	}

// 	logger.Debug("Initializing SSH connection")
// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.AuthPass,
// 		Telnet:   false,
// 		Port:     remote.Meta.SSHPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	logger.Debug("Creating SSH execute instance")
// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Ruijie, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("sh version", "", 3, "sh_version", "")
// 	exec.Prepare(false)

// 	logger.Debug("Executing SSH command: sh version")
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		err = data.Error()
// 		logger.Error("Failed to execute SSH command", zap.Error(err))
// 		return
// 	}

// 	ok, lines := data.GetResult("sh_version")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "sh version")
// 		logger.Error("Failed to get command result", zap.Error(err))
// 		return
// 	}

// 	logger.Debug("Processing version information")
// 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName", "patchVersion"})
// 	for _, line := range lines {
// 		if strings.Contains(line, "System software version :") {
// 			versionSplit := strings.Split(line, ":")
// 			if len(versionSplit) > 1 {
// 				var m map[string]string
// 				m, err = text.GetFieldByRegex(`\s(?P<version>[\d\.\(\)]+)`, versionSplit[1], []string{"version"})
// 				if err != nil {
// 					logger.Error("Failed to parse version", zap.Error(err))
// 					return
// 				}
// 				version = strings.TrimSpace(m["version"])
// 				logger.Info("Found version", zap.String("version", version))
// 				result.PushRow("0", map[string]string{"version": version, "sysName": sysName}, false, "")
// 				break
// 			}
// 		}
// 	}

// 	if result.RowCount() == 0 {
// 		logger.Warn("No version information found")
// 	} else {
// 		logger.Info("Successfully retrieved Ruijie version information",
// 			zap.String("version", version),
// 			zap.String("sysName", sysName))
// 	}

// 	return
// }

// func checkHuaWeiVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	logger = logger.With(zap.String("function", "checkHuaWeiVersionSSH"), zap.String("ip", ip))
// 	logger.Info("Starting HuaWei version check via SSH")

// 	var sysName string
// 	if len(remote.Community) > 0 {
// 		logger.Debug("Attempting to get sysName via SNMP")
// 		st, _ := snmp.NewSnmpTask(
// 			ip,
// 			remote.Community[0],
// 			"1.3.6.1.2.1.1",
// 			[]int{1},
// 			[]int{0},
// 			map[string]string{"3": "uptime", "5": "sysName"},
// 			map[string]func(byte, string, interface{}) (string, error){},
// 			nil)

// 		st.Run(true)
// 		table, err := st.Table()
// 		if err != nil {
// 			logger.Warn("Failed to get sysName via SNMP", zap.Error(err))
// 		} else {
// 			for _, v := range table.ToSliceMap() {
// 				sysName = v["sysName"]
// 				logger.Debug("Retrieved sysName via SNMP", zap.String("sysName", sysName))
// 			}
// 		}
// 	}

// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.AuthPass,
// 		Telnet:   false,
// 		Port:     remote.Meta.SSHPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	logger.Debug("Initializing SSH execution")
// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.HuaWei, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("display version", "", 3, "display_version", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		err = data.Error()
// 		logger.Error("Failed to execute SSH command", zap.Error(err))
// 		return
// 	}

// 	ok, lines := data.GetResult("display_version")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "display version")
// 		logger.Error("Failed to get command result", zap.Error(err))
// 		return
// 	}

// 	logger.Debug("Processing version information")
// 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName", "patchVersion"})
// 	for _, line := range lines {
// 		if strings.Contains(line, "Version") {
// 			var m map[string]string
// 			m, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.\w\(\)]+)\s\((?P<patchVersion>.*)\)`, line, []string{"version", "patchVersion"})
// 			if err != nil {
// 				logger.Warn("Failed to parse version line", zap.Error(err), zap.String("line", line))
// 				continue
// 			}
// 			version = strings.TrimSpace(m["version"])
// 			if version == "" {
// 				logger.Debug("Empty version string parsed", zap.String("line", line))
// 				continue
// 			}
// 			patchVersion := strings.TrimSpace(m["patchVersion"])
// 			logger.Info("Found version information",
// 				zap.String("version", version),
// 				zap.String("patchVersion", patchVersion),
// 				zap.String("sysName", sysName))
// 			result.PushRow("0", map[string]string{"version": version, "sysName": sysName, "patchVersion": patchVersion}, false, "")
// 			break
// 		}
// 	}

// 	if result.RowCount() == 0 {
// 		logger.Warn("No version information found")
// 	} else {
// 		logger.Info("Successfully retrieved HuaWei version information",
// 			zap.String("version", version),
// 			zap.String("sysName", sysName))
// 	}

// 	return
// }

// // func checkUbuntuVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, version string, err error) {
// // 	base := &terminal.BaseInfo{
// // 		Host:     ip,
// // 		Username: remote.Username,
// // 		Password: remote.Password,
// // 		AuthPass: remote.Password,
// // 		// PrivateKey: remote.PrivateKey,
// // 		Telnet: false,
// // 		Port:   remote.Meta.SSHPort,
// // 	}
// // 	base.WithActionID(remote.ActionID)
// // 	// }

// // 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
// // 	exec.Id = uuid.Must(uuid.NewV4()).String()
// // 	exec.Add("lsb_release -a", "", 3, "lsb_release", "")
// // 	// exec.Add("uname -n", "", 3, "uname", "")
// // 	exec.Prepare(false)
// // 	data := exec.Run(false)

// // 	if data.Error() != nil {
// // 		err = data.Error()
// // 		return
// // 	}
// // 	ok, lines := data.GetResult("lsb_release")
// // 	if !ok {
// // 		err = fmt.Errorf("get cmd result failed, cmd=%s", "lsb_release")
// // 		return
// // 	}

// // 	// ok, hostnameLines := data.GetResult("uname")
// // 	// if !ok {
// // 	//	err = fmt.Errorf("get cmd result failed, cmd=%s", "uname -n")
// // 	//	return
// // 	// }
// // 	//
// // 	// var hostname string
// // 	// if len(hostnameLines) > 1 {
// // 	//	hostname = hostnameLines[1]
// // 	//	fmt.Println("aaaa ====", hostname)
// // 	// }

// // 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName"})
// // 	for _, line := range lines {
// // 		if strings.Contains(line, "Release:") {
// // 			versionSplit := strings.Split(line, ":")
// // 			if len(versionSplit) > 1 {
// // 				version = strings.TrimSpace(versionSplit[1])
// // 				result.PushRow("0", map[string]string{"version": version}, false, "")
// // 				break
// // 			}
// // 		}
// // 	}

// // 	// if version == "" {
// // 	//	result.PushRow("0", map[string]string{"sysName": hostname}, false, "")
// // 	// }
// // 	return
// // }

// func checkFortiGateVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	// logger = logger.With(zap.String("function", "checkFortiGateVersionSSH"), zap.String("ip", ip))
// 	// logger.Info("Starting FortiGate version check via SSH")

// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.Password,
// 		Telnet:   false,
// 		Port:     remote.Meta.SSHPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	logger.Debug("Initializing SSH execution")
// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.FortiGate, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("get system status", "", 3, "system", "")
// 	exec.Prepare(false)

// 	logger.Debug("Executing SSH command: get system status")
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		err = data.Error()
// 		logger.Error("Failed to execute SSH command", zap.Error(err))
// 		return
// 	}

// 	ok, lines := data.GetResult("system")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "get system status")
// 		logger.Error("Failed to get command result", zap.Error(err))
// 		return
// 	}

// 	logger.Debug("Processing system status information")
// 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName"})
// 	var hostName string
// 	for _, line := range lines {
// 		if strings.Contains(line, "Version:") {
// 			var m map[string]string
// 			m, err = text.GetFieldByRegex(`v(?P<version>[\d\.\w\(\)]+)`, line, []string{"version"})
// 			if err != nil {
// 				logger.Warn("Failed to parse version", zap.Error(err), zap.String("line", line))
// 				continue
// 			}
// 			version = strings.TrimSpace(m["version"])
// 			if version == "" {
// 				logger.Warn("Empty version string parsed")
// 				continue
// 			}
// 			logger.Info("Found version", zap.String("version", version))
// 			break
// 		} else if strings.Contains(line, "Hostname:") {
// 			hostNameSplit := strings.Split(line, ":")
// 			if len(hostNameSplit) > 1 {
// 				hostName = strings.TrimSpace(hostNameSplit[1])
// 				logger.Info("Found hostname", zap.String("hostname", hostName))
// 				break
// 			}
// 		}
// 	}

// 	if version == "" {
// 		logger.Warn("No version information found")
// 	}
// 	if hostName == "" {
// 		logger.Warn("No hostname information found")
// 	}

// 	result.PushRow("0", map[string]string{"version": version, "sysName": hostName}, false, "")
// 	logger.Info("Completed FortiGate version check",
// 		zap.String("version", version),
// 		zap.String("hostname", hostName))

// 	return
// }

// func checkFortiGateSNSSH(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	logger.Info("Starting FortiGate SN check via SSH")

// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.Password,
// 		Telnet:   false,
// 		Port:     remote.Meta.SSHPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.FortiGate, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("get system status", "", 3, "system", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		logger.Error("Failed to execute command", zap.Error(data.Error()))
// 		return nil, "", data.Error()
// 	}

// 	ok, lines := data.GetResult("system")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "get system status")
// 		logger.Error("Failed to get command result", zap.Error(err))
// 		return nil, "", err
// 	}

// 	result = clitask.NewEmptyTableWithKeys([]string{"serial"})
// 	for _, line := range lines {
// 		if strings.Contains(line, "Serial-Number:") {
// 			serialSplit := strings.Split(line, ":")
// 			if len(serialSplit) > 0 {
// 				serialNumber := strings.TrimSpace(serialSplit[1])
// 				result.PushRow("0", map[string]string{"serial": serialNumber}, false, "")
// 				logger.Info("Found FortiGate serial number", zap.String("serial", serialNumber))
// 				break
// 			}
// 		}
// 	}

// 	if result.RowCount() == 0 {
// 		logger.Warn("No serial number found for FortiGate device")
// 	}

// 	logger.Info("Completed FortiGate SN check via SSH", zap.String("ip", ip))
// 	return
// }
// func checkFortiGateSSHInterface(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, err error) {
// 	logger = logger.With(zap.String("function", "checkFortiGateSSHInterface"))
// 	logger.Info("Starting FortiGate SSH interface check")

// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.Password,
// 		Telnet:   false,
// 		Port:     remote.Meta.SSHPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	logger.Debug("Executing SSH command", zap.String("command", "show system interface"))
// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.FortiGate, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("show system interface", "", 3, "interface", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		logger.Error("Failed to execute SSH command", zap.Error(data.Error()))
// 		return nil, data.Error()
// 	}

// 	ok, lines := data.GetResult("interface")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "show system interface")
// 		logger.Error("Failed to get command result", zap.Error(err))
// 		return nil, err
// 	}

// 	logger.Debug("Parsing interface data")
// 	tx := strings.Join(lines[1:], "\n")
// 	reSplit := regexp.MustCompile(`edit\s+"[^"]+"\s*[\s\S]*?next`)
// 	paragraphs := reSplit.FindAllString(tx, -1)

// 	reMatch := regexp.MustCompile(`edit\s+"([^"]+)"[\s\S]*?set\s+snmp-index\s+(\d+)`)
// 	interfaceMap := make(map[string]string)
// 	for _, paragraph := range paragraphs {
// 		matches := reMatch.FindStringSubmatch(paragraph)
// 		if len(matches) > 2 {
// 			editValue := matches[1]
// 			snmpIndex := matches[2]
// 			interfaceMap[snmpIndex] = editValue
// 			logger.Debug("Parsed interface", zap.String("interface", editValue), zap.String("snmpIndex", snmpIndex))
// 		}
// 	}

// 	if len(interfaceMap) == 0 {
// 		logger.Error("No FortiGate interface information collected via SSH")
// 		return nil, fmt.Errorf("ssh未采集到FortiGate接口信息")
// 	}

// 	logger.Info("Successfully parsed interface data", zap.Int("interfaceCount", len(interfaceMap)))

// 	community := remote.Community[0]
// 	logger.Debug("Starting SNMP tasks", zap.String("community", community))

// 	// SNMP Task 1: Interface information
// 	logger.Debug("Executing SNMP task for interface information")
// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.2.2.1",
// 		[]int{1},
// 		[]int{0},
// 		map[string]string{"2": "name", "3": "phy_protocol", "6": "mac", "8": "status"},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	st.Run(true)
// 	table, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get interface information via SNMP", zap.Error(err))
// 		return nil, err
// 	}

// 	logger.Debug("Processing interface information")
// 	table.ForEach(
// 		func(t *clitask.Table, index string, row map[string]string) (e error) {
// 			row["name"] = interfaceMap[index]
// 			row["__index__"] = index
// 			return nil
// 		})

// 	// SNMP Task 2: IP information
// 	logger.Debug("Executing SNMP task for IP information")
// 	st, err = snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.4.20.1",
// 		[]int{1, 2, 3, 4},
// 		[]int{0},
// 		map[string]string{"2": "interface", "3": "mask"},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	st.Run(true)
// 	table2, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get IP information via SNMP", zap.Error(err))
// 		return nil, err
// 	}

// 	// SNMP Task 3: Rate information
// 	logger.Debug("Executing SNMP task for rate information")
// 	st, err = snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.31.1.1.1.15",
// 		[]int{0},
// 		[]int{},
// 		map[string]string{},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	st.Run(true)
// 	table3, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get rate information via SNMP", zap.Error(err))
// 		return nil, err
// 	}

// 	logger.Debug("Merging SNMP data tables")
// 	err = table.AddKeyFromTable("ip", "", "", "interface", table2, "")
// 	err = table.AddKeyFromTable("mask", "", "mask", "interface", table2, "")
// 	err = table.AddKeyFromTable("rate", "", "value", "", table3, "")

// 	if err != nil {
// 		logger.Error("Failed to merge SNMP data tables", zap.Error(err))
// 		return nil, err
// 	}

// 	logger.Debug("Processing final interface data")
// 	table.ForEach(
// 		func(t *clitask.Table, index string, row map[string]string) (e error) {
// 			vi := net.HardwareAddr(row["mac"]).String()
// 			row["mac"] = vi
// 			sp := strings.Split(strings.TrimSpace(row[l2struct.IfTableName]), " ")
// 			row[l2struct.IfTableName] = strings.Join(sp, "")
// 			if row["ip"] != "" && row["mac"] == "" {
// 				logger.Debug("Fetching additional interface information via SSH", zap.String("interface", row[l2struct.IfTableName]))
// 				base = &terminal.BaseInfo{
// 					Host:     ip,
// 					Username: remote.Username,
// 					Password: remote.Password,
// 					AuthPass: remote.Password,
// 					Telnet:   false,
// 					Port:     remote.Meta.SSHPort,
// 				}
// 				base.WithActionID(remote.ActionID)

// 				exec2 := terminal.NewExecute(terminalmode.VIEW, terminalmode.FortiGate, base)
// 				exec2.Id = uuid.Must(uuid.NewV4()).String()
// 				cmd := fmt.Sprintf("get hardware nic %s", row[l2struct.IfTableName])
// 				exec2.Add(cmd, "", 3, "nic", "")
// 				exec2.Prepare(false)
// 				data2 := exec2.Run(false)

// 				if data2.Error() != nil {
// 					logger.Error("Failed to get additional interface information", zap.Error(data2.Error()))
// 					return data2.Error()
// 				}
// 				ok, lines = data2.GetResult("nic")
// 				if !ok {
// 					err = fmt.Errorf("get cmd result failed, cmd=%s", cmd)
// 					logger.Error("Failed to get NIC information", zap.Error(err))
// 					return err
// 				}
// 				for _, line := range lines {
// 					if strings.Contains(line, "Current_HWaddr") {
// 						b := strings.Split(line, "Current_HWaddr")
// 						c := strings.TrimSpace(b[1])
// 						row["mac"] = c
// 						logger.Debug("Updated MAC address", zap.String("interface", row[l2struct.IfTableName]), zap.String("mac", c))
// 						break
// 					}
// 				}
// 			}

// 			if row["phy_protocol"] == "199" {
// 				row["phy_protocol"] = "Infiniband"
// 			} else {
// 				row["phy_protocol"] = "Ethernet"
// 			}
// 			return nil
// 		})

// 	logger.Info("Completed FortiGate SSH interface check", zap.Int("interfaceCount", table.RowCount()))
// 	return table, nil
// }

// func checkHWGponVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	// logger = logger.With(zap.String("function", "checkHWGponVersionSSH"), zap.String("ip", ip))
// 	// logger.Info("Starting HWGpon version check via SSH")

// 	var sysName string
// 	if len(remote.Community) > 0 {
// 		logger.Debug("Attempting to get sysName via SNMP")
// 		st, _ := snmp.NewSnmpTask(
// 			ip,
// 			remote.Community[0],
// 			"1.3.6.1.2.1.1",
// 			[]int{1},
// 			[]int{0},
// 			map[string]string{"3": "uptime", "5": "sysName"},
// 			map[string]func(byte, string, interface{}) (string, error){},
// 			nil)

// 		st.Run(true)
// 		table, err := st.Table()
// 		if err != nil {
// 			logger.Warn("Failed to get sysName via SNMP", zap.Error(err))
// 		} else {
// 			for _, v := range table.ToSliceMap() {
// 				sysName = v["sysName"]
// 				logger.Debug("Retrieved sysName via SNMP", zap.String("sysName", sysName))
// 			}
// 		}
// 	}

// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.Password,
// 		Telnet:   false,
// 		Port:     remote.Meta.SSHPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	logger.Debug("Initializing SSH execution")
// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.HWGpon, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("display version", "", 3, "display_version", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		err = data.Error()
// 		logger.Error("Failed to execute SSH command", zap.Error(err))
// 		return
// 	}

// 	ok, lines := data.GetResult("display_version")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "display version")
// 		logger.Error("Failed to get command result", zap.Error(err))
// 		return
// 	}

// 	logger.Debug("Processing version information")
// 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName", "patchVersion"})
// 	for _, line := range lines {
// 		if strings.Contains(line, "VERSION :") {
// 			versionSplit := strings.Split(line, ":")
// 			if len(versionSplit) > 1 {
// 				version = strings.TrimSpace(versionSplit[1])
// 				logger.Debug("Found version", zap.String("version", version))
// 				continue
// 			}
// 		}
// 		if strings.Contains(line, "PATCH   :") {
// 			patchSplit := strings.Split(line, ":")
// 			if len(patchSplit) > 1 {
// 				patchVersion := strings.TrimSpace(patchSplit[1])
// 				logger.Debug("Found patch version", zap.String("patchVersion", patchVersion))
// 				result.PushRow("0", map[string]string{"version": version, "sysName": sysName, "patchVersion": patchVersion}, false, "")
// 				break
// 			}
// 		}
// 	}

// 	if result.RowCount() == 0 {
// 		logger.Warn("No version information found")
// 	} else {
// 		logger.Info("Successfully retrieved HWGpon version information",
// 			zap.String("version", version),
// 			zap.String("sysName", sysName))
// 	}

// 	return
// }

// // func checkUbuntuSNSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, version string, err error) {
// // 	base := &terminal.BaseInfo{
// // 		Host:     ip,
// // 		Username: remote.Username,
// // 		Password: remote.Password,
// // 		AuthPass: remote.Password,
// // 		// PrivateKey: remote.PrivateKey,
// // 		Telnet: false,
// // 		Port:   remote.Meta.SSHPort,
// // 	}
// // 	base.WithActionID(remote.ActionID)
// // 	// }
// //
// // 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
// // 	exec.Id = uuid.Must(uuid.NewV4()).String()
// // 	exec.Add("dmidecode", "", 3, "dmidecode_sn", "")
// // 	exec.Prepare(false)
// // 	data := exec.Run(false)
// //
// // 	if data.Error() != nil {
// // 		err = data.Error()
// // 		return
// // 	}
// // 	ok, lines := data.GetResult("dmidecode_sn")
// // 	if !ok {
// // 		err = fmt.Errorf("get cmd result failed, cmd=%s", "dmidecode")
// // 		return
// // 	}
// // 	result = clitask.NewEmptyTableWithKeys([]string{"serial"})
// // 	foundBaseBoardInformation := false
// // 	for _, line := range lines {
// // 		if strings.Contains(line, "Base Board Information") {
// // 			foundBaseBoardInformation = true
// // 		}
// //
// // 		if !foundBaseBoardInformation {
// // 			continue
// // 		}
// //
// // 		fmt.Printf("%s\n", line)
// // 		if strings.Contains(line, "Serial Number:") {
// // 			serialSplit := strings.Split(line, ":")
// // 			if len(serialSplit) > 0 {
// // 				serialNumber := strings.TrimSpace(serialSplit[1])
// // 				result.PushRow("0", map[string]string{"serial": serialNumber}, false, "")
// // 				break
// // 			}
// // 		}
// //
// // 	}
// //
// // 	return
// // }

// // func parseLinuxSN(ip string, remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, version string, err error) {
// // 	base := &terminal.BaseInfo{
// // 		Host:     ip,
// // 		Username: remote.Username,
// // 		Password: remote.Password,
// // 		AuthPass: remote.Password,
// // 		Telnet:   false,
// // 		Port:     remote.Meta.SSHPort,
// // 	}
// // 	base.WithActionID(remote.ActionID)

// // 	commands := []struct {
// // 		cmd    string
// // 		parser func([]string) string
// // 		sudo   bool
// // 	}{
// // 		{
// // 			cmd: "dmidecode -t system",
// // 			parser: func(lines []string) string {
// // 				for _, line := range lines {
// // 					if strings.Contains(line, "Serial Number:") {
// // 						parts := strings.SplitN(line, ":", 2)
// // 						if len(parts) > 1 {
// // 							return strings.TrimSpace(parts[1])
// // 						}
// // 					}
// // 				}
// // 				return ""
// // 			},
// // 			sudo: true,
// // 		},
// // 		{
// // 			cmd: "cat /sys/class/dmi/id/product_serial",
// // 			parser: func(lines []string) string {
// // 				if len(lines) > 0 {
// // 					return strings.TrimSpace(lines[0])
// // 				}
// // 				return ""
// // 			},
// // 			sudo: false,
// // 		},
// // 		{
// // 			cmd: "hostnamectl",
// // 			parser: func(lines []string) string {
// // 				for _, line := range lines {
// // 					if strings.Contains(line, "Hardware UUID:") {
// // 						parts := strings.SplitN(line, ":", 2)
// // 						if len(parts) > 1 {
// // 							return strings.TrimSpace(parts[1])
// // 						}
// // 					}
// // 				}
// // 				return ""
// // 			},
// // 			sudo: false,
// // 		},
// // 	}

// // 	result = clitask.NewEmptyTableWithKeys([]string{"serial"})

// // 	for _, command := range commands {
// // 		cmdStr := command.cmd
// // 		if command.sudo {
// // 			cmdStr = "sudo " + cmdStr
// // 		}

// // 		execute := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
// // 		execute.Id = uuid.Must(uuid.NewV4()).String()
// // 		execute.Add(cmdStr, "", 3, "get_sn", "")
// // 		execute.Prepare(false)
// // 		data := execute.Run(false)

// // 		if data.Error() != nil {
// // 			continue
// // 		}

// // 		ok, lines := data.GetResult("get_sn")
// // 		if !ok {
// // 			continue
// // 		}

// // 		if serialNumber := command.parser(lines); serialNumber != "" {
// // 			result.PushRow("0", map[string]string{"serial": serialNumber}, false, "")
// // 			return
// // 		}
// // 	}
// // 	return
// // }

// func parseLinuxSN(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	logger.Info("Starting Linux SN parsing")

// 	sshClient, err := sshtool.NewSSHClient(remote)
// 	if err != nil {
// 		logger.Error("Failed to create SSH client", zap.Error(err))
// 		return nil, "", fmt.Errorf("failed to create SSH client: %v", err)
// 	}
// 	defer sshClient.Close()

// 	commands := []struct {
// 		cmd    string
// 		parser func(string) string
// 		sudo   bool
// 	}{
// 		{
// 			cmd: "dmidecode -t system",
// 			parser: func(output string) string {
// 				lines := strings.Split(output, "\n")
// 				for _, line := range lines {
// 					if strings.Contains(line, "Serial Number:") {
// 						parts := strings.SplitN(line, ":", 2)
// 						if len(parts) > 1 {
// 							return strings.TrimSpace(parts[1])
// 						}
// 					}
// 				}
// 				return ""
// 			},
// 			sudo: true,
// 		},
// 		{
// 			cmd: "cat /sys/class/dmi/id/product_serial",
// 			parser: func(output string) string {
// 				return strings.TrimSpace(output)
// 			},
// 			sudo: false,
// 		},
// 		{
// 			cmd: "hostnamectl",
// 			parser: func(output string) string {
// 				lines := strings.Split(output, "\n")
// 				for _, line := range lines {
// 					if strings.Contains(line, "Hardware UUID:") {
// 						parts := strings.SplitN(line, ":", 2)
// 						if len(parts) > 1 {
// 							return strings.TrimSpace(parts[1])
// 						}
// 					}
// 				}
// 				return ""
// 			},
// 			sudo: false,
// 		},
// 	}

// 	result = clitask.NewEmptyTableWithKeys([]string{"serial"})

// 	for _, command := range commands {
// 		cmdStr := command.cmd
// 		if command.sudo {
// 			cmdStr = "sudo " + cmdStr
// 		}

// 		logger.Info("Executing command", zap.String("command", cmdStr))
// 		output, err := sshClient.ExecuteCommand(cmdStr)
// 		if err != nil {
// 			logger.Warn("Command execution failed", zap.String("command", cmdStr), zap.Error(err))
// 			continue
// 		}

// 		if serialNumber := command.parser(output); serialNumber != "" {
// 			logger.Info("Serial number found", zap.String("serial", serialNumber))
// 			result.PushRow("0", map[string]string{"serial": serialNumber}, false, "")
// 			return result, "", nil
// 		}
// 	}

// 	logger.Warn("Unable to find serial number")
// 	return result, "", fmt.Errorf("unable to find serial number")
// }
// func checkHWGponSNSSH(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	logger.Info("Starting HWGpon SN check via SSH")

// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.Password,
// 		Telnet:   false,
// 		Port:     remote.Meta.SSHPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.HWGpon, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("display frame serial-number", "", 3, "display_sn", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)

// 	if data.Error() != nil {
// 		logger.Error("Failed to execute command", zap.Error(data.Error()))
// 		return nil, "", data.Error()
// 	}

// 	ok, lines := data.GetResult("display_sn")
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "display frame serial-number")
// 		logger.Error("Failed to get command result", zap.Error(err))
// 		return nil, "", err
// 	}

// 	result = clitask.NewEmptyTableWithKeys([]string{"serial"})
// 	serialNumber := ""
// 	for _, line := range lines {
// 		if strings.Contains(line, "Serial Number") {
// 			parts := strings.Fields(line)
// 			if len(parts) >= 3 {
// 				serialNumber = parts[2]
// 				result.PushRow("0", map[string]string{"serial": serialNumber}, false, "")
// 				logger.Info("Found HWGpon serial number", zap.String("serial", serialNumber))
// 				break
// 			}
// 		}
// 	}

// 	if serialNumber == "" {
// 		err = fmt.Errorf("未找到Serial Number")
// 		logger.Warn("No serial number found for HWGpon device")
// 	}

// 	logger.Info("Completed HWGpon SN check via SSH", zap.String("ip", ip))
// 	return result, version, err
// }

// // func checkIsAlive(ip string, remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
// // 	logger := log.NewLogger(nil, true)
// // 	b := ""
// // 	if ip == "" {
// // 		b = "false"
// // 		result = clitask.NewEmptyTableWithKeys([]string{"alive"})
// // 		result.PushRow("0", map[string]string{"alive": b}, false, "")
// // 		logger.ErrorNoStack("ip为空checkIsAlive err")
// // 		return
// // 	}
// // 	if !reachable.IsAlive(ip) {
// // 		b = "false"
// // 	} else {
// // 		b = "true"
// // 	}
// // 	result = clitask.NewEmptyTableWithKeys([]string{"alive"})
// // 	result.PushRow("0", map[string]string{"alive": b}, false, "")
// // 	if b == "false" {
// // 		logger.ErrorNoStack("目标不可达", zap.Any("ip", ip))
// // 	}
// // 	return
// // }

func checkIsAlive(ip string, remote *structs.L2DeviceRemoteInfo) (*clitask.Table, error) {
	result := clitask.NewEmptyTableWithKeys([]string{"ip", "alive", "message"})

	if reachable.IsAlive(ip) {
		result.PushRow("0", map[string]string{
			"ip":      ip,
			"alive":   "true",
			"message": "Device is reachable",
		}, false, "")
		return result, nil
	} else {
		err := fmt.Errorf("%s is unreachable", ip)
		result.PushRow("0", map[string]string{
			"ip":      ip,
			"alive":   "false",
			"message": err.Error(),
		}, false, "")
		return result, nil
	}
}

// func checkF5InfoWeb(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, info lb.F5DeviceInfo, err error) {
// 	device := structs.DeviceBase{
// 		Host:      ip,
// 		Username:  remote.Username,
// 		Password:  remote.Password,
// 		Port:      remote.Meta.RestfullPort,
// 		Community: "public",
// 	}

// 	if device.Port == 0 || device.Port == 8443 {
// 		device.Port = 443
// 	}

// 	hs, err := newF5HttpSession(device)
// 	if err != nil {
// 		logger.Error("Failed to create F5 HTTP session", zap.Error(err))
// 		return
// 	}

// 	info, err = lb.F5Info(hs)
// 	return
// }

// func checkF5SelfWeb(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, vlans []lb.Vlan, err error) {
// 	logger = logger.With(zap.String("function", "checkF5SelfWeb"))
// 	logger.Info("Starting F5 self web check")

// 	device := structs.DeviceBase{
// 		Host:      ip,
// 		Username:  remote.Username,
// 		Password:  remote.Password,
// 		Port:      remote.Meta.RestfullPort,
// 		Community: "public",
// 	}

// 	if device.Port == 0 {
// 		device.Port = 443
// 		logger.Debug("Setting default port to 443")
// 	}

// 	logger.Debug("Initializing F5 HTTP session")
// 	hs, err := newF5HttpSession(device)
// 	if err != nil {
// 		logger.Error("Failed to create F5 HTTP session", zap.Error(err))
// 		return
// 	}

// 	logger.Debug("Fetching F5 interface information")
// 	intfs, err := lb.F5Interface(hs)
// 	if err != nil {
// 		logger.Error("Failed to get F5 interface information", zap.Error(err))
// 		return
// 	}
// 	logger.Debug("Successfully fetched F5 interface information", zap.Int("interfaceCount", len(intfs)))

// 	logger.Debug("Fetching F5 VLAN information")
// 	vlans, err = lb.F5Vlan(hs)
// 	if err != nil {
// 		logger.Error("Failed to get F5 VLAN information", zap.Error(err))
// 		return
// 	}
// 	logger.Debug("Successfully fetched F5 VLAN information", zap.Int("vlanCount", len(vlans)))

// 	logger.Debug("Fetching F5 partition information")
// 	partitions, err := lb.F5Partition(hs)
// 	if err != nil {
// 		logger.Error("Failed to get F5 partition information", zap.Error(err))
// 		return
// 	}
// 	logger.Debug("Successfully fetched F5 partition information", zap.Int("partitionCount", len(partitions)))

// 	logger.Debug("Fetching F5 route domain information")
// 	routeDomain, err := lb.F5RouteDomain(hs)
// 	if err != nil {
// 		logger.Error("Failed to get F5 route domain information", zap.Error(err))
// 		return
// 	}
// 	logger.Debug("Successfully fetched F5 route domain information")

// 	logger.Debug("Processing F5 self information")
// 	vlans, routeDomain, err = lb.F5Self(hs, intfs, vlans, routeDomain, partitions)
// 	if err != nil {
// 		logger.Error("Failed to process F5 self information", zap.Error(err))
// 		return
// 	}
// 	logger.Info("Successfully processed F5 self information",
// 		zap.Int("updatedVlanCount", len(vlans)),
// 		zap.Any("updatedRouteDomain", routeDomain))

// 	logger.Debug("F5 self information",
// 		zap.Any("vlans", vlans),
// 		zap.Any("routeDomain", routeDomain))

// 	logger.Info("Completed F5 self web check")
// 	return
// }

// func CheckNetworkDeviceVersion(ip, community string, platformName string, logger *zap.Logger) (result *clitask.Table, err error) {
// 	logger.Info("Starting network device version check")

// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.1",
// 		[]int{1},
// 		[]int{0},
// 		map[string]string{"1": "version", "3": "uptime", "5": "sysName"},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	if err != nil {
// 		logger.Error("Failed to create SNMP task", zap.Error(err))
// 		return nil, err
// 	}

// 	logger.Debug("Running SNMP task")
// 	st.Run(true)
// 	table, err := st.Table()
// 	if err != nil {
// 		logger.Error("Failed to get SNMP table", zap.Error(err))
// 		return nil, err
// 	}

// 	table.Keys = append(table.Keys, "device_type")
// 	logger.Debug("Added 'device_type' to table keys")

// 	err = table.ForEach(func(t *clitask.Table, index string, row map[string]string) error {
// 		value := row["version"]
// 		row["device_type"] = ""
// 		if terminalmode.IsSupport(platformName) {
// 			mode := terminalmode.NewDeviceType(platformName)
// 			vers, device_type, patchVersion, err := snmpVersionParser(value, mode)
// 			if err == nil {
// 				row["version"] = vers
// 				row["device_type"] = device_type
// 				row["patch_version"] = patchVersion
// 				logger.Debug("Parsed device information",
// 					zap.String("version", vers),
// 					zap.String("device_type", device_type),
// 					zap.String("patch_version", patchVersion))
// 			} else {
// 				logger.Warn("Failed to parse device information", zap.Error(err))
// 			}
// 			return err
// 		} else {
// 			err = fmt.Errorf("unsupported mode = %s", platformName)
// 			logger.Error("Unsupported platform", zap.String("platform", platformName))
// 			return err
// 		}
// 	})

// 	if err != nil {
// 		logger.Error("Error processing device information", zap.Error(err))
// 		return table, err
// 	}

// 	logger.Info("Completed network device version check",
// 		zap.Int("rowCount", table.RowCount()))
// 	return table, nil
// }

// func parseNetworkInfo(input string) (resultMap map[string]string) {
// 	// 按行切分字符串
// 	// var name, status, ip, mac string
// 	resultMap = make(map[string]string)
// 	lines := strings.Split(input, "\n")
// 	if len(lines) < 3 {
// 		return
// 	}

// 	for index, line := range lines {
// 		line = strings.TrimFunc(line, func(r rune) bool {
// 			return !unicode.IsGraphic(r)
// 		})

// 		if len(line) == 0 {
// 			continue
// 		}

// 		tokens := strings.Split(line, ":")
// 		if len(tokens) == 1 && index <= 1 {
// 			resultMap["name"] = tokens[0]
// 			continue
// 		}

// 		if len(tokens) <= 1 {
// 			continue
// 		}

// 		switch strings.TrimSpace(tokens[0]) {
// 		case "Current state":
// 			resultMap["status"] = strings.TrimSpace(tokens[1])
// 		case "Internet address":
// 			resultMap["ip"] = strings.Fields(tokens[1])[0]
// 		case "IP packet frame type":
// 			resultMap["mac"] = strings.TrimSpace(tokens[2])
// 		}

// 	}
// 	return
// }

// func parseTenantNetworkPorts(txt string) ([]map[string]string, error) {
// 	var results []map[string]string
// 	sections := text.RegexSplit(`[\n\r][\n\r]`, txt)
// 	for _, section := range sections {
// 		if section != "" {
// 			portMap := parseNetworkInfo(section)
// 			if len(portMap) == 0 {
// 				continue
// 			}
// 			data := make(map[string]string)
// 			data["name"] = portMap["name"]
// 			data["ip"] = portMap["ip"]
// 			if portMap["status"] != "" {
// 				if strings.ToLower(portMap["status"]) == "up" {
// 					data["status"] = "1"
// 				} else if strings.ToLower(portMap["status"]) == "down" {
// 					data["status"] = "2"
// 				} else {
// 					data["status"] = "3"
// 				}
// 			}
// 			if portMap["mac"] != "" {
// 				data["mac"] = strings.Replace(portMap["mac"], "-", "", -1)
// 			}
// 			results = append(results, data)
// 		}
// 	}
// 	return results, nil
// }

// // func parseTenantNetworkPorts(txt string) ([]map[string]string, error) {
// // 	var results []map[string]string
// // 	shportRegexMap := map[string]string{
// // 		"regex": `\x0?\s?(?P<name>\S+)[\x0\n\r]+Current state: (?P<status>\S+).*?Internet address: (?P<ip>[\d\./]+) .*?hardware address: (?P<mac>[-\w\d]+)`,
// // 		"name":  "shport",
// // 		"flags": "s",
// // 		"pcre":  "true",
// // 	}
// //
// // 	sections := text.RegexSplit(`[\n\r][\n\r]`, txt)
// //
// // 	shportSplitter, err := text.NewSplitterFromMap(shportRegexMap)
// // 	if err != nil {
// // 		panic(err)
// // 	}
// // 	for _, section := range sections {
// // 		if strings.Index(section, "Internet address") < 0 {
// // 			continue
// // 		}
// //
// // 		section = strings.TrimSpace(section)
// //
// // 		fmt.Println("------------>>>: ", section[0:30])
// // 		fmt.Printf("%x\n", section[0:30])
// //
// // 		shportResult, err := shportSplitter.Input(section)
// // 		fmt.Println("-----aaaa", shportResult)
// // 		if err != nil {
// // 			return []map[string]string{}, err
// // 		}
// //
// // 		p, err := text.SplitterProcessOneTime(shportRegexMap, section)
// // 		if err != nil {
// // 			if err == text.ErrNoMatched {
// // 				continue
// // 			}
// // 			return results, err
// // 		}
// // 		if portMap, ok := p.One(); !ok {
// // 			continue
// // 		} else {
// // 			data := make(map[string]string)
// // 			data["name"] = portMap["name"]
// // 			data["ip"] = portMap["ip"]
// // 			if portMap["status"] != "" {
// // 				if strings.ToLower(portMap["status"]) == "up" {
// // 					data["status"] = "1"
// // 				} else if strings.ToLower(portMap["status"]) == "down" {
// // 					data["status"] = "2"
// // 				} else {
// // 					data["status"] = "3"
// // 				}
// // 			}
// // 			if portMap["mac"] != "" {
// // 				data["mac"] = strings.Replace(portMap["mac"], "-", "", -1)
// // 			}
// // 			results = append(results, data)
// // 		}
// //
// // 		// for it := shportResult.Iterator(); it.HasNext(); {
// // 		// _, _, portMap := it.Next()
// // 		// var data map[string]string
// // 		// data = make(map[string]string)
// // 		//
// // 		// data["name"] = portMap["name"]
// // 		// data["ip"] = portMap["ip"]
// // 		// if portMap["status"] != "" {
// // 		// if strings.ToLower(portMap["status"]) == "up" {
// // 		// data["status"] = "1"
// // 		// } else if strings.ToLower(portMap["status"]) == "down" {
// // 		// data["status"] = "2"
// // 		// } else {
// // 		// data["status"] = "3"
// // 		// }
// // 		// }
// // 		// fmt.Println("aaaaadddd", portMap["mac"])
// // 		// if portMap["mac"] != "" {
// // 		// data["mac"] = strings.Replace(portMap["mac"], "-", "", -1)
// // 		// }
// // 		// results = append(results, data)
// // 		// }
// //
// // 	}
// // 	return results, err
// // }

// func getTelnetNetworkPorts(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	logger.Info("Starting Telnet network ports check")

// 	table := clitask.NewEmptyTableWithKeys([]string{"name", "status", "ip", "mac"})
// 	base := &terminal.BaseInfo{
// 		Host:     ip,
// 		Username: remote.Username,
// 		Password: remote.Password,
// 		AuthPass: remote.AuthPass,
// 		Telnet:   true,
// 		Port:     remote.Meta.TelnetPort,
// 	}
// 	base.WithActionID(remote.ActionID)

// 	if remote.Platform == "Comware" {
// 		logger.Debug("Executing Comware specific commands")
// 		exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Comware, base)
// 		exec.Id = uuid.Must(uuid.NewV4()).String()
// 		exec.Add("dis interface", "", 10, "dis_interface", "")
// 		exec.Prepare(false)
// 		data := exec.Run(false)

// 		if data.Error() != nil {
// 			err = data.Error()
// 			logger.Error("Failed to execute Telnet command", zap.Error(err))
// 			return
// 		}

// 		ok, lines := data.GetResult("dis_interface")
// 		if !ok {
// 			err = fmt.Errorf("get cmd result failed, cmd=%s", "dis interface")
// 			logger.Error("Failed to get command result", zap.Error(err))
// 			return
// 		}

// 		logger.Debug("Successfully retrieved interface data", zap.Int("lineCount", len(lines)))
// 		table.PushRawData(data)
// 		txt := strings.Join(lines, "\n")

// 		resultList, err2 := parseTenantNetworkPorts(txt)
// 		if err2 != nil {
// 			logger.Error("Failed to parse tenant network ports", zap.Error(err2))
// 			return nil, "", err2
// 		}

// 		logger.Debug("Parsed tenant network ports", zap.Int("portCount", len(resultList)))
// 		for _, r := range resultList {
// 			table.PushRow("", r, false, "")
// 		}
// 	} else {
// 		logger.Warn("Unsupported platform for Telnet network ports check", zap.String("platform", remote.Platform))
// 	}

// 	logger.Info("Completed Telnet network ports check", zap.Int("totalPorts", table.RowCount()))
// 	return table, "", err
// }

// // func checkNetworkDeviceIftable(ip, community string, platformName string) {
// func checkNetworkDevicePorts(arg *structs.Args, logger *zap.Logger) (*clitask.Table, error) {
// 	logger = logger.With(zap.String("function", "checkNetworkDevicePorts"))
// 	logger.Info("Starting network device ports check")

// 	ip := arg.Ip
// 	community := arg.Remote.Community[0]

// 	logger.Debug("Initializing SNMP task for interface information", zap.String("oid", "1.3.6.1.2.1.2.2.1"))
// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.2.2.1",
// 		[]int{1},
// 		[]int{0},
// 		map[string]string{"2": "name", "3": "phy_protocol", "6": "mac", "8": "status"},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	st.Run(true)
// 	table, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get interface information via SNMP", zap.Error(err))
// 		return nil, err
// 	}
// 	logger.Debug("Successfully retrieved interface information", zap.Int("rowCount", table.RowCount()))

// 	logger.Debug("Initializing SNMP task for IP information", zap.String("oid", "1.3.6.1.2.1.4.20.1"))
// 	st, err = snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.4.20.1",
// 		[]int{1, 2, 3, 4},
// 		[]int{0},
// 		map[string]string{"2": "interface", "3": "mask"},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	st.Run(true)
// 	table2, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get IP information via SNMP", zap.Error(err))
// 		return nil, err
// 	}

// 	if table2.IsEmpty() {
// 		logger.Warn("IP information table is empty, attempting alternative methods")
// 		switch strings.ToLower(arg.Platform) {
// 		case "comware":
// 			logger.Info("Using Telnet for Comware platform")
// 			table, _, err = getTelnetNetworkPorts(ip, arg.Remote, logger)
// 			if err != nil {
// 				logger.Error("Failed to get network ports via Telnet", zap.Error(err))
// 			}
// 		default:
// 			logger.Warn("No alternative method available for this platform")
// 		}
// 		return table, err
// 	}

// 	logger.Debug("Initializing SNMP task for rate information", zap.String("oid", "1.3.6.1.2.1.31.1.1.1.15"))
// 	st, err = snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.31.1.1.1.15",
// 		[]int{0},
// 		[]int{},
// 		map[string]string{},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	st.Run(true)
// 	table3, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get rate information via SNMP", zap.Error(err))
// 		return nil, err
// 	}

// 	logger.Debug("Merging tables")
// 	err = table.AddKeyFromTable("ip", "", "", "interface", table2, "")
// 	err = table.AddKeyFromTable("mask", "", "mask", "interface", table2, "")
// 	err = table.AddKeyFromTable("rate", "", "value", "", table3, "")

// 	if err != nil {
// 		logger.Error("Failed to merge tables", zap.Error(err))
// 		return nil, err
// 	}

// 	logger.Debug("Processing table data")
// 	table.ForEach(
// 		func(t *clitask.Table, index string, row map[string]string) (e error) {
// 			sp := strings.Split(strings.TrimSpace(row[l2struct.IfTableName]), " ")
// 			row[l2struct.IfTableName] = strings.Join(sp, "")
// 			vi := net.HardwareAddr(row["mac"]).String()
// 			row["mac"] = vi
// 			if row["phy_protocol"] == "199" {
// 				row["phy_protocol"] = "Infiniband"
// 			} else {
// 				row["phy_protocol"] = "Ethernet"
// 			}
// 			return nil
// 		})

// 	if strings.ToUpper(arg.Remote.Platform) == "NEXUS" {
// 		logger.Info("Processing Nexus platform specific information")
// 		portBriefList, err := nexusShowInIntBriefAll(arg)

// 		if err != nil {
// 			logger.Error("Failed to get Nexus port brief information", zap.Error(err))
// 		} else {
// 			table.ForEach(
// 				func(t *clitask.Table, index string, row map[string]string) (e error) {
// 					for _, p := range portBriefList {
// 						if portname.MatchPortName(p["port"], row["name"]) {
// 							net, err := network.ParseIPNet(p["subnet"])
// 							if err != nil {
// 								logger.Error("Failed to parse IP network", zap.Error(err), zap.String("subnet", p["subnet"]))
// 								return err
// 							}
// 							row["mask"] = net.Mask.String()
// 							row["ip"] = p["ip"]
// 						}
// 					}
// 					return nil
// 				})
// 		}
// 	}

// 	logger.Info("Completed network device ports check", zap.Int("totalPorts", table.RowCount()))
// 	return table, nil
// }

// func checkNetworkDevicePortsRate(ip, community string, platformName string, logger *zap.Logger) (*clitask.Table, error) {
// 	logger = logger.With(zap.String("function", "checkNetworkDevicePortsRate"))
// 	logger.Info("Starting network device ports rate check")

// 	logger.Debug("Initializing SNMP task for interface information", zap.String("oid", "1.3.6.1.2.1.2.2.1"))
// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.2.2.1",
// 		[]int{1},
// 		[]int{0},
// 		map[string]string{"2": "name", "6": "mac"},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	st.Run(true)
// 	table, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get interface information via SNMP", zap.Error(err))
// 		return nil, err
// 	}
// 	logger.Debug("Successfully retrieved interface information", zap.Int("rowCount", table.RowCount()))

// 	logger.Debug("Initializing SNMP task for rate information", zap.String("oid", "1.3.6.1.2.1.31.1.1.1.15"))
// 	st, err = snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.31.1.1.1.15",
// 		[]int{0},
// 		[]int{},
// 		map[string]string{},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)

// 	st.Run(true)
// 	table2, err := st.Table()

// 	if err != nil {
// 		logger.Error("Failed to get rate information via SNMP", zap.Error(err))
// 		return nil, err
// 	}
// 	logger.Debug("Successfully retrieved rate information", zap.Int("rowCount", table2.RowCount()))

// 	logger.Debug("Merging interface and rate information")
// 	err = table.AddKeyFromTable("rate", "", "value", "", table2, "")
// 	if err != nil {
// 		logger.Error("Failed to merge interface and rate information", zap.Error(err))
// 		return nil, err
// 	}

// 	logger.Info("Completed network device ports rate check", zap.Int("totalPorts", table.RowCount()))
// 	return table, nil
// }

// func checkNetworkDeviceVersion2(ip, community string, platformName string) (string, error) {
// 	st, err := snmp.NewSnmpTask(
// 		ip,
// 		community,
// 		"1.3.6.1.2.1.4.20.1",
// 		// "1.3.6.1.2.1.1",
// 		[]int{1, 2, 3, 4},
// 		[]int{0},
// 		map[string]string{"2": "interface", "3": "mask"},
// 		map[string]func(byte, string, interface{}) (string, error){},
// 		nil)
// 	// indexall: [1,2,3,4]
// 	// prefix: [0]
// 	// prefixmap:
// 	// 2: interface
// 	// 3: mask

// 	st.Run(true)
// 	_, err = st.Table()

// 	if err != nil {
// 		fmt.Println("============>>>", err)
// 		return "", err
// 	} else {
// 		// table.Pretty()
// 	}
// 	//
// 	// value, ok := table.IndexToValue("description", "0")
// 	// if !ok {
// 	// return "", fmt.Errorf("ip=%s, IndexToValue failed", ip)
// 	// }
// 	//
// 	// if terminalmode.IsSupport(platformName) {
// 	// mode := terminalmode.NewDeviceType(platformName)
// 	// return snmpVersionParser(value, mode)
// 	// } else {
// 	// return "", fmt.Errorf("unspport mode = %s", platformName)
// 	// }
// 	return "", err
// }

// func snmpVersionParser(desc string, mode terminalmode.DeviceType) (version, deviceType, patchVersion string, err error) {
// 	var result map[string]string
// 	switch mode {
// 	case terminalmode.MLMNOS:
// 		result, err = text.GetFieldByRegex(`(?i)v(?P<version>[\d\.]+)`, desc, []string{"version", "patchVersion"})
// 	case terminalmode.IOS:
// 		// Version 12.2(20100802:165548)
// 		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version", "patchVersion"})
// 		// version = result["version"]
// 	// case terminalmode.IOS:
// 	//	// Version 12.2(20100802:165548)
// 	//	result, err := text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.:\w\(\)]+)[,|\s]`, desc, []string{"version"})
// 	//	if err != nil {
// 	//		return "", err
// 	//	}
// 	//	return result["version"], nil
// 	case terminalmode.Nexus:
// 		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.\w\(\)]+),`, desc, []string{"version", "patchVersion"})
// 		// if err != nil {
// 		// return "", err
// 		// }
// 		// version = result["version"]
// 	case terminalmode.Comware:
// 		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.]+),?`, desc, []string{"version", "patchVersion"})
// 		// if err != nil {
// 		// return "", err
// 		// }
// 		// version = result["version"]
// 	case terminalmode.VRP:
// 		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.]+),?`, desc, []string{"version", "patchVersion"})
// 		// if err != nil {
// 		// return "", err
// 		// }
// 		// return result["version"], nil
// 	case terminalmode.HuaWei:
// 		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.\w\(\)]+)\s\((?P<patchVersion>.*)\)`, desc, []string{"version", "patchVersion"})
// 		lines := strings.Split(strings.TrimSpace(desc), "\n")
// 		if len(lines) > 0 {
// 			deviceType = lines[0]
// 		}
// 	case terminalmode.ASA:
// 		result, err = text.GetFieldByRegex(`(?i)Version (?P<version>[\d\.\w]+)\((?P<patchVersion>.*)\)`, desc, []string{"version", "patchVersion"})
// 		lines := strings.Split(strings.TrimSpace(desc), "\n")
// 		if len(lines) > 0 {
// 			deviceType = lines[0]
// 		}
// 	default:
// 		err = fmt.Errorf("unsupport platform")
// 		// return "", fmt.Errorf("unsupport platform")
// 	}

// 	if err == nil {
// 		version = result["version"]
// 		patchVersion = result["patchVersion"]
// 	}
// 	return
// }

// // Ip             string        `yaml:"ip" mapstructure:"ip" json:"ip"`
// // Username       string        `yaml:"username" mapstructure:"username" json:"username"`
// // Password       string        `yaml:"password" mapstructure:"password" json:"password"`
// // AuthPass       string        `yaml:"auth_pass" mapstructure:"auth_pass" json:"auth_pass"`
// // Community      []string      `yaml:"community" mapstructure:"community" json:"community"`
// // Platform       string        `yaml:"platform" mapstructure:"platform" json:"platform"`
// // RedfishVersion string        `yaml:"redfish_version" mapstructure:"redfish_version" json:"redfish_version"`
// // META           internal.Meta `yaml:"meta" mapstructure:"meta" json:"meta"`
// //

func checkServerVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result string, err error) {
	base := &terminal.BaseInfo{
		Host:       ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		Telnet:     false,
		Port:       remote.Meta.SSHPort,
	}
	//
	// if remote.CtxID != "" {
	// ctx := context.Background()
	// ctx = context.WithValue(ctx, "ctx_id", remote.CtxID)
	// base.WithContext(ctx)
	// }

	// if remote.ActionID != nil {
	base.WithActionID(remote.ActionID)
	// }

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	exec.Add("lsb_release -a", "", 10, "lsb", "")
	exec.Prepare(false)
	data := exec.Run(false)
	if data.Error() != nil {
		err = data.Error()
		return
	}
	var m map[string]string
	ok, lines := data.GetResult("lsb")
	if !ok {
		err = fmt.Errorf("get cmd result failed, cmd=%s", "lsb_release -a")
		return
	}
	m, err = text.GetFieldByRegex(`Release:\s+(?P<version>\S+)`, strings.Join(lines, "\n"), []string{"version"})
	if err != nil {
		return
	}
	result = m["version"]
	return
}

func checkAciVersion(host string, remoteInfo *structs.L2DeviceRemoteInfo) (version string, err error) {
	// ct := aci.NewAci(host, remoteInfo.Username, remoteInfo.Password)
	// version, err = ct.Firmware()
	return
}

func checkRedhatVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result string, err error) {
	base := &terminal.BaseInfo{
		Host:       ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		Telnet:     false,
		Port:       remote.Meta.SSHPort,
	}
	//
	// if remote.CtxID != "" {
	// ctx := context.Background()
	// ctx = context.WithValue(ctx, "ctx_id", remote.CtxID)
	// base.WithContext(ctx)
	// }
	base.WithActionID(remote.ActionID)

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	exec.Add("cat /etc/*elease", "", 10, "cat_release", "")
	exec.Prepare(false)
	data := exec.Run(false)
	if data.Error() != nil {
		err = data.Error()
		return
	}
	var m map[string]string
	ok, lines := data.GetResult("cat_release")
	// fmt.Println("======>lines:", lines)
	if !ok {
		err = fmt.Errorf("get cmd result failed, cmd=%s", "cat /etc/*elease")
		return
	}
	m, err = text.GetFieldByRegex(`VERSION_ID="(?P<version>[\d\.]+)"`, strings.Join(lines, "\n"), []string{"version"})
	if err != nil {
		m, err = text.GetFieldByRegex(`Linux\s+Server\s+release\s+(?P<version>[\d\.]+)`, strings.Join(lines, "\n"), []string{"version"})
		if err != nil {
			return
		}
	}
	result = m["version"]
	return
}

// func checkAlmaLinuxVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result string, err error) {
// 	base := &terminal.BaseInfo{
// 		Host:       ip,
// 		Username:   remote.Username,
// 		Password:   remote.Password,
// 		PrivateKey: remote.PrivateKey,
// 		Telnet:     false,
// 		Port:       remote.Meta.SSHPort,
// 	}
// 	//
// 	// if remote.CtxID != "" {
// 	// ctx := context.Background()
// 	// ctx = context.WithValue(ctx, "ctx_id", remote.CtxID)
// 	// base.WithContext(ctx)
// 	// }
// 	base.WithActionID(remote.ActionID)

// 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
// 	exec.Id = uuid.Must(uuid.NewV4()).String()
// 	exec.Add("cat /etc/*elease", "", 10, "cat_release", "")
// 	exec.Prepare(false)
// 	data := exec.Run(false)
// 	if data.Error() != nil {
// 		err = data.Error()
// 		return
// 	}
// 	var m map[string]string
// 	ok, lines := data.GetResult("cat_release")
// 	// fmt.Println("======>lines:", lines)
// 	if !ok {
// 		err = fmt.Errorf("get cmd result failed, cmd=%s", "cat /etc/*elease")
// 		return
// 	}
// 	m, err = text.GetFieldByRegex(`VERSION_ID="(?P<version>[\d\.]+)"`, strings.Join(lines, "\n"), []string{"version"})
// 	if err != nil {
// 		m, err = text.GetFieldByRegex(`AlmaLinux\s+release\s+(?P<version>[\d\.]+)`, strings.Join(lines, "\n"), []string{"version"})
// 		if err != nil {
// 			return
// 		}
// 	}
// 	result = m["version"]
// 	return
// }

func checkCentosVersionSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result string, err error) {
	base := &terminal.BaseInfo{
		Host:       ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		Telnet:     false,
		Port:       remote.Meta.SSHPort,
	}

	// if remote.CtxID != "" {
	// ctx := context.Background()
	// ctx = context.WithValue(ctx, "ctx_id", remote.CtxID)
	// base.WithContext(ctx)
	// }

	// if lenremote.ActionID != nil {
	base.WithActionID(remote.ActionID)
	// }

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	exec.Add("cat /etc/*elease", "", 10, "cat_release", "")
	exec.Prepare(false)
	data := exec.Run(false)
	if data.Error() != nil {
		err = data.Error()
		return
	}
	var m map[string]string
	ok, lines := data.GetResult("cat_release")
	if !ok {
		err = fmt.Errorf("get cmd result failed, cmd=%s", "cat /etc/*elease")
		return
	}
	m, err = text.GetFieldByRegex(`CentOS Linux release\s+(?P<version>\S+)`, strings.Join(lines, "\n"), []string{"version"})
	if err != nil {
		return
	}
	result = m["version"]
	return
}

// // func checkCentosVersionAndHostnameSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, version string, err error) {
// // 	base := &terminal.BaseInfo{
// // 		Host:       ip,
// // 		Username:   remote.Username,
// // 		Password:   remote.Password,
// // 		PrivateKey: remote.PrivateKey,
// // 		Telnet:     false,
// // 		Port:       remote.Meta.SSHPort,
// // 	}

// // 	// if remote.CtxID != "" {
// // 	// ctx := context.Background()
// // 	// ctx = context.WithValue(ctx, "ctx_id", remote.CtxID)
// // 	// base.WithContext(ctx)
// // 	// }

// // 	// if lenremote.ActionID != nil {
// // 	base.WithActionID(remote.ActionID)
// // 	// }

// // 	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)
// // 	exec.Id = uuid.Must(uuid.NewV4()).String()
// // 	exec.Add("cat /etc/*elease", "", 10, "cat_release", "")
// // 	exec.Add("hostname", "", 10, "hostname", "")
// // 	exec.Prepare(false)
// // 	data := exec.Run(false)
// // 	if data.Error() != nil {
// // 		err = data.Error()
// // 		return
// // 	}
// // 	var m map[string]string
// // 	ok, lines := data.GetResult("cat_release")
// // 	if !ok {
// // 		err = fmt.Errorf("get cmd result failed, cmd=%s", "cat /etc/*elease")
// // 		return
// // 	}
// // 	ok2, lines2 := data.GetResult("hostname")
// // 	if !ok2 {
// // 		err = fmt.Errorf("get cmd result failed, cmd=%s", "hostname")
// // 		return
// // 	}
// // 	var sysName string
// // 	if len(lines2) > 1 {
// // 		sysName = lines2[1]
// // 	}
// // 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName"})
// // 	m, err = text.GetFieldByRegex(`CentOS Linux release\s+(?P<version>\S+)`, strings.Join(lines, "\n"), []string{"version"})
// // 	if err != nil {
// // 		return
// // 	}
// // 	result.PushRow("0", map[string]string{"version": m["version"], "sysName": sysName}, false, "")
// // 	return
// // }

// func executeSSHCommand(client *ssh.Client, command string) (string, error) {
// 	session, err := client.NewSession()
// 	if err != nil {
// 		return "", fmt.Errorf("failed to create session: %v", err)
// 	}
// 	defer session.Close()

// 	var stdoutBuf bytes.Buffer
// 	session.Stdout = &stdoutBuf
// 	err = session.Run(command)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to run command: %v", err)
// 	}

// 	return stdoutBuf.String(), nil
// }

// // func linuxVersionAndHostnameSSH(ip string, remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, version string, err error) {
// // 	config := &ssh.ClientConfig{
// // 		User: remote.Username,
// // 		Auth: []ssh.AuthMethod{
// // 			ssh.Password(remote.Password),
// // 		},
// // 		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
// // 		Config: ssh.Config{
// // 			Ciphers: []string{
// // 				"aes128-ctr", "aes192-ctr", "aes256-ctr",
// // 				"aes128-gcm@openssh.com",
// // 				"arcfour256", "arcfour128", "arcfour",
// // 				"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
// // 			},
// // 			KeyExchanges: []string{
// // 				"diffie-hellman-group-exchange-sha256",
// // 				"diffie-hellman-group-exchange-sha1",
// // 				"diffie-hellman-group14-sha1",
// // 				"diffie-hellman-group1-sha1",
// // 			},
// // 			MACs: []string{
// // 				"hmac-sha2-256-etm@openssh.com",
// // 				"hmac-sha2-256",
// // 				"hmac-sha1",
// // 				"hmac-sha1-96",
// // 			},
// // 		},
// // 	}

// // 	// 设置连接超时
// // 	timeout := time.Duration(30) * time.Second
// // 	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, remote.Meta.SSHPort), timeout)
// // 	if err != nil {
// // 		return nil, "", fmt.Errorf("failed to connect: %v", err)
// // 	}

// // 	c, chans, reqs, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", ip, remote.Meta.SSHPort), config)
// // 	if err != nil {
// // 		return nil, "", fmt.Errorf("failed to create client connection: %v", err)
// // 	}

// // 	client := ssh.NewClient(c, chans, reqs)
// // 	defer client.Close()

// // 	// 执行命令获取系统信息
// // 	osInfoCmd := "cat /etc/*release 2>/dev/null || cat /etc/*version 2>/dev/null || uname -a"
// // 	osInfo, err := executeSSHCommand(client, osInfoCmd)
// // 	if err != nil {
// // 		return nil, "", err
// // 	}

// // 	osVersionCmd := "lsb_release -a 2>/dev/null || cat /etc/os-release 2>/dev/null || oslevel -s 2>/dev/null"
// // 	osVersion, err := executeSSHCommand(client, osVersionCmd)
// // 	if err != nil {
// // 		return nil, "", err
// // 	}

// // 	hostnameCmd := "hostname"
// // 	hostname, err := executeSSHCommand(client, hostnameCmd)
// // 	if err != nil {
// // 		return nil, "", err
// // 	}

// // 	// 解析系统版本信息
// // 	version = parseOSVersion(osInfo, osVersion)

// // 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName"})
// // 	result.PushRow("0", map[string]string{"version": version, "sysName": strings.TrimSpace(hostname)}, false, "")

// // 	result.Pretty()
// // 	return result, version, nil
// // }

// // func parseOSVersion(osInfo, osVersion string) string {
// // 	versionRegexes := []string{
// // 		`VERSION="?(\d+\.?\d*)"?`,
// // 		`VERSION_ID="?(\d+\.?\d*)"?`,
// // 		`release\s+(\d+\.?\d*)`,
// // 		`(\d+\.?\d*)\s+\(.*\)`,
// // 	}

// // 	for _, regex := range versionRegexes {
// // 		if match := regexp.MustCompile(regex).FindStringSubmatch(osInfo); len(match) > 1 {
// // 			return match[1]
// // 		}
// // 	}

// // 	if strings.Contains(osVersion, "DISTRIB_RELEASE") {
// // 		if match := regexp.MustCompile(`DISTRIB_RELEASE=(\d+\.?\d*)`).FindStringSubmatch(osVersion); len(match) > 1 {
// // 			return match[1]
// // 		}
// // 	} else if strings.Contains(osVersion, "VERSION_ID") {
// // 		if match := regexp.MustCompile(`VERSION_ID="?(\d+\.?\d*)"?`).FindStringSubmatch(osVersion); len(match) > 1 {
// // 			return match[1]
// // 		}
// // 	}

// // 	if match := regexp.MustCompile(`^(\d+\-\d+\-\d+\-\d+)$`).FindStringSubmatch(strings.TrimSpace(osVersion)); len(match) > 1 {
// // 		return match[1]
// // 	}

// //		return strings.TrimSpace(osInfo)
// //	}
// func linuxVersionAndHostnameSSH(ip string, remote *structs.L2DeviceRemoteInfo, logger *zap.Logger) (result *clitask.Table, version string, err error) {
// 	// logger = logger.With(zap.String("function", "linuxVersionAndHostnameSSH"), zap.String("ip", ip))
// 	// logger.Info("Starting Linux version and hostname check via SSH")

// 	sshClient, err := sshtool.NewSSHClient(remote)
// 	if err != nil {
// 		logger.Error("Failed to create SSH client", zap.Error(err))
// 		return nil, "", err
// 	}
// 	defer sshClient.Close()

// 	result = clitask.NewEmptyTableWithKeys([]string{"version", "sysName"})

// 	// 执行命令获取系统信息
// 	osInfoCmd := "cat /etc/*release 2>/dev/null || cat /etc/*version 2>/dev/null || uname -a"
// 	logger.Debug("Executing command to get OS info", zap.String("command", osInfoCmd))
// 	osInfo, err := sshClient.ExecuteCommand(osInfoCmd)
// 	if err != nil {
// 		logger.Error("Failed to execute OS info command", zap.Error(err))
// 		return nil, "", err
// 	}

// 	osVersionCmd := "lsb_release -a 2>/dev/null || cat /etc/os-release 2>/dev/null || oslevel -s 2>/dev/null"
// 	logger.Debug("Executing command to get OS version", zap.String("command", osVersionCmd))
// 	osVersion, err := sshClient.ExecuteCommand(osVersionCmd)
// 	if err != nil {
// 		logger.Error("Failed to execute OS version command", zap.Error(err))
// 		return nil, "", err
// 	}

// 	hostnameCmd := "hostname"
// 	logger.Debug("Executing command to get hostname", zap.String("command", hostnameCmd))
// 	hostname, err := sshClient.ExecuteCommand(hostnameCmd)
// 	if err != nil {
// 		logger.Error("Failed to execute hostname command", zap.Error(err))
// 		return nil, "", err
// 	}

// 	// 解析系统版本信息
// 	logger.Debug("Parsing OS version information")
// 	version = parseOSVersion(osInfo, osVersion)
// 	logger.Info("Parsed OS version", zap.String("version", version))

// 	sysName := strings.TrimSpace(hostname)
// 	logger.Info("Retrieved system name", zap.String("sysName", sysName))

// 	result.PushRow("0", map[string]string{"version": version, "sysName": sysName}, false, "")

// 	logger.Info("Completed Linux version and hostname check",
// 		zap.String("version", version),
// 		zap.String("sysName", sysName))
// 	return result, version, nil
// }

// func parseOSVersion(osInfo, osVersion string) string {
// 	versionRegexes := []string{
// 		`VERSION="?(\d+\.?\d*)"?`,
// 		`VERSION_ID="?(\d+\.?\d*)"?`,
// 		`release\s+(\d+\.?\d*)`,
// 		`(\d+\.?\d*)\s+\(.*\)`,
// 	}

// 	for _, regex := range versionRegexes {
// 		if match := regexp.MustCompile(regex).FindStringSubmatch(osInfo); len(match) > 1 {
// 			return match[1]
// 		}
// 	}

// 	if strings.Contains(osVersion, "DISTRIB_RELEASE") {
// 		if match := regexp.MustCompile(`DISTRIB_RELEASE=(\d+\.?\d*)`).FindStringSubmatch(osVersion); len(match) > 1 {
// 			return match[1]
// 		}
// 	} else if strings.Contains(osVersion, "VERSION_ID") {
// 		if match := regexp.MustCompile(`VERSION_ID="?(\d+\.?\d*)"?`).FindStringSubmatch(osVersion); len(match) > 1 {
// 			return match[1]
// 		}
// 	}

// 	if match := regexp.MustCompile(`^(\d+\-\d+\-\d+\-\d+)$`).FindStringSubmatch(strings.TrimSpace(osVersion)); len(match) > 1 {
// 		return match[1]
// 	}

// 	return strings.TrimSpace(osInfo)
// }

func CheckRedfishVersion(remote *structs.L2DeviceRemoteInfo) (result string) {
	server := redfishClient(remote)
	if server.CollectErr != nil {
		return result
	}
	defer server.OutC.Logout()
	result = gofishRedfishVersionV1Collect(remote, server)
	return result
}

func CheckRedfishSerial(remote *structs.L2DeviceRemoteInfo) (result string) {
	server := redfishClient(remote)
	if server.CollectErr != nil {
		return result
	} else {
		defer server.OutC.Logout()
		result = gofishRedfishSeralV1Collect(remote, server)
	}
	return result
}

func redfishClient(remote *structs.L2DeviceRemoteInfo) *mygofish.HardCollect {
	// endpointip := fmt.Sprintf("https://%s", remote.Ip)
	logger := log.NewLogger(nil, true)

	endpointip := remote.Ip
	server := mygofish.CollectInit(endpointip, remote.Username, remote.Password, true)
	if server.CollectErr != nil {
		logger.Error("Redfish初始化链接失败", log.Tag("remote", remote), zap.Any("error", server.CollectErr))
		return server
	}
	return server
}

func gofishRedfishVersionV1Collect(remote *structs.L2DeviceRemoteInfo, server *mygofish.HardCollect) (result string) {
	result = server.GetRedfishVersion()
	return result
}

func gofishRedfishSeralV1Collect(remote *structs.L2DeviceRemoteInfo, server *mygofish.HardCollect) (result string) {
	info, err := server.GetSN()
	if err != nil {
		result = ""
	} else {
		if info.SKU != "" {
			result = info.SKU
			return result
		} else if info.SN != "" {
			result = info.SN
			return result
		} else {
			result = info.SN
			return result
		}
	}
	return result
}

func h3cRedfishVersion(remote *structs.L2DeviceRemoteInfo) (string, error) {
	return snmpRedfishVersion(remote, "1.3.6.1.4.1.25506.13.1.2.2.7.1")
}

func hpRedfishVersion(remote *structs.L2DeviceRemoteInfo) (string, error) {
	return snmpRedfishVersion(remote, "1.3.6.1.4.1.232.11.2.14.1.1.5")
}

func ibmRedfishVersion(remote *structs.L2DeviceRemoteInfo) (string, error) {
	return snmpRedfishVersion(remote, "1.3.6.1.4.1.25506.13.1.2.2.7.1")
}

func snmpRedfishVersion(remote *structs.L2DeviceRemoteInfo, oid string) (string, error) {
	logger := log.NewLogger(nil, true)

	if len(remote.Community) != 0 {
		st, err := snmp.NewSnmpTask(
			remote.Ip,
			remote.Community[0],
			oid,
			[]int{1},
			[]int{0},
			map[string]string{"0": "version"},
			map[string]func(byte, string, interface{}) (string, error){},
			nil)

		st.Run(true)
		table, err := st.Table()
		if err != nil {
			logger.Warn("snmpRedfishVersion 获取Redfish版本失败", zap.Error(err), log.Tag("remote", remote))
		} else {
			var ok bool
			version, ok := table.IndexToValue("version", "0")
			if ok != true {
				err = errors.New("table.IndexToValue 返回结果为空")
				logger.Warn("snmpRedfishVersion 获取Redfish版本失败", zap.Error(err), log.Tag("remote", remote))
				return version, err
			} else {
				version = strings.TrimSpace(strings.Split(version, " ")[0])
				// global.GVA_LOG.Debug("check version ok ", zap.Any("result", result))
				return version, nil
			}
		}
	}

	server, err := redfishClient2(remote)
	if err == nil {
		err2 := redfishVersionV1Collect2(remote, server)
		if err2 == nil {
			// fmt.Println("===ggg")
			jsonInterface := strings.TrimSpace(server.GetRedfishVersion())
			if jsonInterface == "" {
				// version = ""

				err = fmt.Errorf("RedfishVersion is emtpy")
				logger.Warn("Redfish链接成功但采集方法获取版本失败", zap.Error(err), log.Tag("remote", remote))
				return "", err
			} else {
				version := strings.TrimSpace(fmt.Sprintf("%s", jsonInterface))
				return version, nil
			}
		} else {
			// global.GVA_LOG.Info("getRedfishVersion 失败", zap.Any("error", err))
			logger.Warn("Redfish链接成功但采集方法获取版本失败", zap.Any("error", err), log.Tag("remote", remote))
			return "", err2
		}
	} else {
		// global.GVA_LOG.Info("checkRedfishVersion2 失败", zap.Any("error", err))
		logger.Warn("snmp和redfish获取版本都失败", zap.Any("error", err), log.Tag("remote", remote))
	}

	return "", err

	// return "", fmt.Errorf("current only support snmp get version")
}

func checkRedfishVersion2(remote *structs.L2DeviceRemoteInfo) (result string, err error) {
	if f, ok := rfFuncMap[strings.ToLower(remote.Manufacturer)]; ok {
		return f(remote)
	} else {
		return "", fmt.Errorf("redfish version: unsupport manufacturer '%s'", remote.Manufacturer)
	}
}

// // func checkRedfishVersion2(remote *structs.L2DeviceRemoteInfo) (result string) {
// // if tools.IsContain([]string{"h3c"}, strings.ToLower(remote.Manufacturer)) {
// // if len(remote.Community) != 0 {
// // st, err := snmp.NewSnmpTask(
// // remote.Ip,
// // remote.Community[0],
// // "1.3.6.1.4.1.25506.13.1.2.2.7.1",
// // []int{1},
// // []int{0},
// // map[string]string{"0": "version"},
// // map[string]func(byte, string, interface{}) (string, error){},
// // nil)
// //
// // st.Run(true)
// // table, err := st.Table()
// // if err != nil {
// // global.GVA_LOG.Info("获取Redfish版本失败", zap.Any("ip", remote.Ip), zap.Any("error", err))
// // } else {
// // result, ok := table.IndexToValue("version", "0")
// // if ok != true {
// // err := errors.New("table.IndexToValue 返回结果为空")
// // global.GVA_LOG.Info("获取Redfish版本失败", zap.Any("ip", remote.Ip), zap.Any("error", err))
// // return ""
// // } else {
// // result = strings.TrimSpace(strings.Split(result, " ")[0])
// // // global.GVA_LOG.Debug("check version ok ", zap.Any("result", result))
// // return result
// // }
// // }
// // }
// // } else if tools.IsContain([]string{"hp"}, strings.ToLower(remote.Manufacturer)) {
// // if len(remote.Community) != 0 {
// // st, err := snmp.NewSnmpTask(
// // remote.Ip,
// // remote.Community[0],
// // ".1.3.6.1.4.1.232.11.2.14.1.1.5",
// // []int{1},
// // []int{0},
// // map[string]string{"0": "version"},
// // map[string]func(byte, string, interface{}) (string, error){},
// // nil)
// //
// // st.Run(true)
// // table, err := st.Table()
// // if err != nil {
// // global.GVA_LOG.Info("获取Redfish版本失败", zap.Any("ip", remote.Ip), zap.Any("error", err))
// // } else {
// // result, ok := table.IndexToValue("version", "0")
// // if ok != true {
// // err := errors.New("table.IndexToValue 返回结果为空")
// // global.GVA_LOG.Info("获取Redfish版本失败", zap.Any("ip", remote.Ip), zap.Any("error", err))
// // return ""
// // } else {
// // result = strings.TrimSpace(strings.Split(result, " ")[0])
// // // global.GVA_LOG.Info("check version ok ", zap.Any("result", result))
// // return result
// // }
// // }
// // } else {
// // global.GVA_LOG.Info("获取Redfish版本失败,Community为空", zap.Any("ip", remote.Ip), zap.Any("remote.Manufacturer", remote.Manufacturer))
// // }
// // } else if tools.IsContain([]string{"ibm"}, strings.ToLower(remote.Manufacturer)) {
// // if len(remote.Community) != 0 {
// // st, err := snmp.NewSnmpTask(
// // remote.Ip,
// // remote.Community[0],
// // ".1.3.6.1.4.1.25506.13.1.2.2.7.1",
// // []int{1},
// // []int{0},
// // map[string]string{"0": "version"},
// // map[string]func(byte, string, interface{}) (string, error){},
// // nil)
// //
// // st.Run(true)
// // table, err := st.Table()
// // if err != nil {
// // global.GVA_LOG.Info("获取Redfish版本失败", zap.Any("ip", remote.Ip), zap.Any("error", err))
// // } else {
// // result, ok := table.IndexToValue("version", "0")
// // if ok != true {
// // err := errors.New("table.IndexToValue 返回结果为空")
// // global.GVA_LOG.Info("获取Redfish版本失败", zap.Any("ip", remote.Ip), zap.Any("error", err))
// // return ""
// // } else {
// // result = strings.TrimSpace(strings.Split(result, " ")[0])
// // // global.GVA_LOG.Info("check version ok ", zap.Any("result", result))
// // return result
// // }
// // }
// // } else {
// // // global.GVA_LOG.Info("hp commuinty 为空", zap.Any("remote", remote.Community), zap.Any("remote.Manufacturer", remote.Manufacturer))
// // global.GVA_LOG.Info("获取Redfish版本失败,Community为空", zap.Any("ip", remote.Ip), zap.Any("remote.Manufacturer", remote.Manufacturer))
// // }
// // }
// // // else if tools.IsContain([]string{"lenovo"}, strings.ToLower(remote.Manufacturer)) {
// // // server := redfishClient(remote)
// // // defer server.OutC.Logout()
// // // result = gofishRedfishVersionV1Collect(remote, server)
// // // return result
// // //}
// // server, err := redfishClient2(remote)
// // if err == nil {
// // err2 := redfishVersionV1Collect2(remote, server)
// // if err2 == nil {
// // //fmt.Println("===ggg")
// // jsonInterface := server.Json["RedfishVersion"]
// // if jsonInterface == nil {
// // result = ""
// // } else {
// // result = strings.TrimSpace(fmt.Sprintf("%s", jsonInterface))
// // }
// // } else {
// // // global.GVA_LOG.Info("getRedfishVersion 失败", zap.Any("error", err))
// // global.GVA_LOG.Info("获取Redfish版本失败", zap.Any("ip", remote.Ip), zap.Any("error", err))
// // }
// // } else {
// // // global.GVA_LOG.Info("checkRedfishVersion2 失败", zap.Any("error", err))
// // global.GVA_LOG.Info("获取Redfish版本失败", zap.Any("ip", remote.Ip), zap.Any("error", err))
// // }
// // return result
// // }
func redfishClient2(remote *structs.L2DeviceRemoteInfo) (red *v2.Client, err error) {
	// red = redfish.NewRedFish()
	// _, err = red.RedfishCollect(remote.Ip, remote.Username, remote.Password, remote.Platform)
	// return red, err
	red, err = RedfishBase.NormalRedfishClient(remote)
	return red, err
}

func redfishVersionV1Collect2(remote *structs.L2DeviceRemoteInfo, server *v2.Client) (err error) {
	server.GetRedfishVersion()
	return
}

func redfishSerialV1Collect2(remote *structs.L2DeviceRemoteInfo, server *v2.Client) (err error) {
	server.GetSerialNumber()
	return
}

// func newF5HttpSession(device structs.DeviceBase) (session.HttpSession, error) {
// 	host := device.Host
// 	user := device.Username
// 	password := device.Password
// 	community := device.Community
// 	port := device.Port
// 	// bi := session.NewDeviceBaseInfo("192.168.100.7", "admin", "!@AsiaLink@2020", "F5", "public", 443)
// 	bi := session.NewDeviceBaseInfo(host, user, password, "F5", community, port)
// 	auth_url := lb.AUTH.String()
// 	auth_data, _ := json.Marshal(map[string]string{
// 		"username":          user,
// 		"password":          password,
// 		"loginProviderName": "tmos",
// 	})

// 	if auth_data == nil || len(auth_data) == 0 {
// 		return session.HttpSession{}, errors.New("Auth data is empty ...")
// 	}

// 	hs := session.NewHttpSession(bi, auth_url)
// 	hs.WithAuthData(auth_data)
// 	hs.WithTokenField("X-F5-Auth-Token")
// 	return *hs, nil
// }
