package redfish

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/exec"
	"reflect"
	"regexp"
	"strings"

	"github.com/netxops/log"

	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"

	"github.com/spf13/cast"

	"github.com/iancoleman/strcase"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/structs/oob"
	"github.com/netxops/utils/mygofish"
	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	"go.uber.org/zap"
)

func RunSnmpTask(task *snmp.SnmpTask, remote *structs.L2DeviceRemoteInfo) (*clitask.Table, error) {
	result := task.Run(true)
	if result.Error() != nil {
		return nil, result.Error()
	}
	return task.Table()
}
func InterfaceToList(obj interface{}) (list []interface{}) {
	if reflect.TypeOf(obj).Kind() == reflect.Slice {
		s := reflect.ValueOf(obj)
		for i := 0; i < s.Len(); i++ {
			ele := s.Index(i)
			list = append(list, ele.Interface().(interface{}))
		}
	}
	return
}

// bytesToGib calculation
func bytesToGib(v uint64) uint64 {
	return v / 1024 / 1024 / 1024
}

// mibToGiB calculation
func mibToGiB(v uint64) uint64 {
	return v * 8388608 / 8589934592
}

// Gofish🔗
func NormalGofishClient(remote *structs.L2DeviceRemoteInfo) *mygofish.HardCollect {
	logger := log.NewLogger(remote.ActionID, true)

	endpointip := fmt.Sprintf("https://%s", remote.Ip)
	server := mygofish.CollectInit(endpointip, remote.Username, remote.Password, true)
	if server.CollectErr != nil {
		logger.Warn("NormalGofishClient", zap.Any("error", server.CollectErr))
		return server
	}
	return server
}

func IpmiGetSn(remote *structs.L2DeviceRemoteInfo) (result string, err error) {
	content := "ipmitool -I lanplus -H " + remote.Ip + " -U admin -P " + remote.Password + " fru"
	fmt.Println("====cmd", content)
	// cmd := exec.Command("cmd", "ipmitool", "-I","lanplus","-H",remote.Ip,"-U","admin")
	cmd := exec.Command("bash", "-c", content)
	if stdout, err := cmd.StdoutPipe(); err != nil { // 获取输出对象，可以从该对象中读取输出结果
		fmt.Println("====输出err", err)
		return "", err
	} else {
		defer stdout.Close()
		if err := cmd.Start(); err != nil { // 运行命令
			fmt.Println("运行err", err)
			return "", err
		}
		if opBytes, err := ioutil.ReadAll(stdout); err != nil { // 读取输出结果
			fmt.Println("读取err", err)
			return "", err
		} else {
			result = string(opBytes)
		}
	}
	return result, nil
}

func NormalRedfishClient(remote *structs.L2DeviceRemoteInfo) (c *v2.Client, err error) {
	if !strings.HasPrefix(remote.Ip, "http") {
		remote.Ip = fmt.Sprintf("https://%s", remote.Ip)
	}
	config := &v2.Config{
		Host:     remote.Ip,
		Username: remote.Username,
		Password: remote.Password,
		ActionID: remote.ActionID,
		Insecure: true,
	}
	if remote.Username == "test" && remote.Password == "test" {
		config.SkipAuth = true
	}
	c, err = v2.Connect(config)
	return
}

func CpuField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"manufacture", "structs", "socket", "totalThreads", "totalEnabledCores", "name"})
	return
}

func SNField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"serialNumber"})
	return
}

func MemField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"manufacture", "name", "partNumber", "cacheSizeMiB", "memoryDeviceType", "serialNumber"})
	return
}

func DiskField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"manufacture", "name", "structs", "partNumber", "serialNumber", "protocol", "capacityBytes"})
	return
}

func BaseInfoField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"manufacture", "sku", "modelType", "partNumber", "serialNumber", "name"})
	return
}

func NetworkFiled() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"manufacture", "name", "structs", "serialNumber", "partNumber"})
	return
}

func RedfishVersionField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"redfishVersion"})
	return
}

func PowerField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"manufacture", "structs", "serialNumber", "partNumber"})
	return
}

func PowerControlField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"powerCapacityWatts", "powerConsumedWatts"})
	return
}
func NetworkInterfaceField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"interfaceName", "macAddress"})
	return
}

func BmcField() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"ipv4Addresses", "iPv6Addresses", "speedMbps"})
	return
}

const (
	CAST_SAME   = "CAST_SAME"
	CAST_SNAKE  = "CAST_SNAKE"
	CAST_CAMEL  = "CAST_CAMEL"
	CAST_LCAMEL = "CAST_LCAMEL"
	CAST_TAG    = "CAST_TAG"
)

func structsFields(data interface{}, flag string, tag string) ([]string, error) {
	t := reflect.TypeOf(data)
	fields := []string{}
	if t.Kind() == reflect.Struct {
	} else if t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct {
		t = t.Elem()
	} else {
		return []string{}, fmt.Errorf("current not support struct to fields")
	}

	for i := 0; i < t.NumField(); i++ {
		switch flag {
		case CAST_SAME:
			fields = append(fields, t.Field(i).Name)
		case CAST_SNAKE:
			fields = append(fields, strcase.ToSnake(t.Field(i).Name))
		case CAST_CAMEL:
			fields = append(fields, strcase.ToCamel(t.Field(i).Name))
		case CAST_LCAMEL:
			fields = append(fields, strcase.ToLowerCamel(t.Field(i).Name))
		case CAST_TAG:
			if tag == "" {
				return fields, fmt.Errorf("'tag' param is emtpy")
			}
			tagV, ok := t.Field(i).Tag.Lookup(tag)
			if ok {
				fields = append(fields, tagV)
			} else {
				return fields, fmt.Errorf("tag '%s' is not exits", tag)
				// fields = append(fields, strcase.ToCamel(t.Field(i).Name))
			}
		default:
			fields = append(fields, strcase.ToCamel(t.Field(i).Name))

		}
	}

	return fields, nil
}

func structToMapByJsonTag(data interface{}) (map[string]string, error) {
	m := map[string]string{}
	byteS, err := json.Marshal(data)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(byteS, &m)

	return m, err
}

func TableBuilder(data interface{}) (tb *clitask.Table, err error) {
	fields, err := structsFields(data, CAST_TAG, "json")
	if err != nil {
		return
	}

	tb = clitask.NewEmptyTableWithKeys(fields)

	return
}

// func CheckSN() (tb *clitask.Table) {
//	tb = clitask.NewEmptyTableWithKeys([]string{"deviceName", "SnDatabase", "SnCollect"})
//	return
// }
// func CheckRedfish() (tb *clitask.Table) {
//	tb = clitask.NewEmptyTableWithKeys([]string{"deviceName", "oob", "redfishVersion", "deviceType", "cpu", "mem", "disk", "network", "power"})
//	return
// }
//
// func CheckNeighbors() (tb *clitask.Table) {
//	tb = clitask.NewEmptyTableWithKeys([]string{"deviceName", "interfaceName", "deviceIp", "interfaceId", "PeerNeighborAllList", "PeerCableAllList", "check"})
//	return
// }
//
// func CheckDeviceInterface() (tb *clitask.Table) {
//	tb = clitask.NewEmptyTableWithKeys([]string{"deviceName", "countInterface", "metaVersion", "neighbors"})
//	return
// }

func CheckSwitchInfo() (tb *clitask.Table) {
	tb = clitask.NewEmptyTableWithKeys([]string{"switchId", "switchName", "errorInfo"})
	return
}

// func CpuBaseInfo(infoList []*gofish.Processor)(tb *clitask.Table,err error){
//	tb = clitask.NewEmptyTableWithKeys([]string{"manufacture", "structs", "socket", "totalThreads", "totalEnabledCores", "name"})
//	for _, each := range infoList {
//		p := map[string]string{}
//		p["manufacture"] = each.Manufacturer
//		p["structs"] = each.Model
//		p["socket"] = each.Socket
//		p["name"] = each.Name
//		p["totalThreads"] = fmt.Sprintf("%f", each.TotalThreads)
//		p["totalEnabledCores"] = fmt.Sprintf("%f", each.TotalEnabledCores)
//		err = tb.PushRow("", p, false, "")
//		if err != nil {
//			return nil, err
//		}
//	}
//	return tb,err
// }

func GofishcpuV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	infoList, err := server.GetCpuInfo()
	if err != nil {
		logger.Warn("gofishcpuV1Collect", zap.String("GetCpuInfo", "获取Cpu失败"), zap.Error(err))
		return
	}
	tb, err := TableBuilder(oob.Cpu{})
	if err != nil {
		logger.Warn("gofishcpuV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	for _, each := range infoList {
		p := oob.Cpu{}
		p.Manufacture = each.Manufacturer
		p.Model = each.Model
		p.Socket = each.Socket
		p.Name = each.Name
		p.TotalThreads = fmt.Sprintf("%d", each.TotalThreads)
		p.TotalCores = fmt.Sprintf("%d", each.TotalCores)
		m, err := structToMapByJsonTag(p)
		err = tb.PushRow("", m, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, err
}

func GofishmemV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	infoList, err := server.GetMemInfo()
	if err != nil {
		logger.Warn("GofishmemV1Collect", zap.String("GetMemInfo", "获取Mem失败"), zap.Error(err))
		return
	}
	tb, err := TableBuilder(oob.Mem{})
	if err != nil {
		logger.Warn("GofishmemV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	// tb := clitask.NewEmptyTableWithKeys([]string{"manufacture", "name", "partNumber", "cacheSizeMiB", "memoryDeviceType", "serialNumber"})
	for _, each := range infoList {
		p := oob.Mem{}
		if each.Manufacturer != "" {
			p.Manufacture = each.Manufacturer
			p.SizeGiB = fmt.Sprintf("%d", mibToGiB(uint64(each.CapacityMiB)))
			p.Name = each.Name
			p.SerialNumber = each.SerialNumber
			p.PartNumber = each.PartNumber
			p.MemoryDeviceType = fmt.Sprintf("%s", each.MemoryDeviceType)
			m, err := structToMapByJsonTag(p)
			err = tb.PushRow("", m, false, "")
			if err != nil {
				return nil, err
			}
		}
	}
	// tb.Pretty()
	return tb, err
}

func GofishdiskV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	infoList, err := server.GetDiskInfo()
	if err != nil {
		logger.Warn("GofishdiskV1Collect", zap.String("GetInfo", "采集数据失败"), zap.Error(err))
		return
	}
	tb, err := TableBuilder(oob.Disk{})
	if err != nil {
		logger.Warn("GofishdiskV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	for _, each := range infoList {
		p := oob.Disk{}
		if each.Manufacturer != "" {
			p.CapacityGB = fmt.Sprintf("%d", bytesToGib(uint64(each.CapacityBytes)))
			p.Manufacture = each.Manufacturer
			p.PartNumber = each.PartNumber
			p.SerialNumber = each.SerialNumber
			p.Name = each.Name
			p.Model = each.Model
			p.Protocol = fmt.Sprintf("%s", each.Protocol)
			m, err := structToMapByJsonTag(p)
			err = tb.PushRow("", m, false, "")
			if err != nil {
				return nil, err
			}
		}
	}
	return tb, err
}

func GofishRedfishVersionV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	infoList := server.GetRedfishVersion()
	tb, err := TableBuilder(oob.RedfishVersion{})
	p := oob.RedfishVersion{}
	p.RedfishVersion = infoList
	m, err := structToMapByJsonTag(p)
	err = tb.PushRow("", m, false, "")
	if err != nil {
		return nil, err
	}
	// tb.Pretty()
	return tb, err
}

func GofishNetworkInterfaceV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	infoList, err := server.GetDeviceNetworkData()
	if err != nil {
		logger.Warn("GofishNetworkInterfaceV1Collect", zap.String("GetInfo", "采集数据失败"), zap.Error(err))
		return
	}
	tb, err := TableBuilder(oob.NetworkInterface{})
	if err != nil {
		logger.Warn("GofishNetworkInterfaceV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	// tb := clitask.NewEmptyTableWithKeys([]string{"interfaceName", "macAddress"})
	for _, each := range infoList {
		p := oob.NetworkInterface{}
		p.InterfaceName = each.InterfaceName
		p.MacAddress = fmt.Sprintf("%s", each.MacAddress)
		m, err := structToMapByJsonTag(p)
		err = tb.PushRow("", m, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, err
}

func GofishPowerControlV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	infoList, err := server.GetPowerControlInfo()
	if err != nil {
		logger.Warn("GofishPowerControlV1Collect", zap.String("GetInfo", "采集数据失败"), zap.Error(err))
		return
	}
	tb, err := TableBuilder(oob.PowerControl{})
	if err != nil {
		logger.Warn("GofishPowerControlV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	// tb := clitask.NewEmptyTableWithKeys([]string{"manufacture", "structs", "serialNumber", "partNumber"})
	for _, each := range infoList {
		p := oob.PowerControl{}
		p.PowerCapacityWatts = strings.TrimSpace(fmt.Sprintf("%f", each.PowerCapacityWatts))
		p.PowerConsumedWatts = strings.TrimSpace(fmt.Sprintf("%f", each.PowerConsumedWatts))
		m, err := structToMapByJsonTag(p)
		err = tb.PushRow("", m, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, err
}

func GofishPowerV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	infoList, err := server.GetPowerInfo()
	if err != nil {
		logger.Warn("GofishPowerV1Collect", zap.String("GetInfo", "采集数据失败"), zap.Error(err))
		return
	}
	tb, err := TableBuilder(oob.Power{})
	if err != nil {
		logger.Warn("GofishPowerV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	for _, each := range infoList {
		p := oob.Power{}
		p.Manufacture = each.Manufacturer
		p.Model = each.Model
		p.SerialNumber = each.SerialNumber
		p.PartNumber = each.PartNumber
		p.PowerCapacityWatts = fmt.Sprintf("%f", each.PowerCapacityWatts)
		m, err := structToMapByJsonTag(p)
		err = tb.PushRow("", m, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, err
}

func GofishNetworkV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	infoList, err := server.GetNetWorkInterfaceInfo()
	if err != nil {
		logger.Warn("GofishNetworkV1Collect", zap.String("GetInfo", "采集数据失败"), zap.Error(err))
		return
	}
	tb, err := TableBuilder(oob.Network{})
	if err != nil {
		logger.Warn("GofishNetworkV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	for _, each := range infoList {
		p := oob.Network{}
		p.Manufacture = each.Manufacturer
		p.Model = each.Model
		p.SerialNumber = each.SerialNumber
		p.PartNumber = each.PartNumber
		p.Name = each.Name
		m, err := structToMapByJsonTag(p)
		err = tb.PushRow("", m, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, err
}

func RedfishPowerControlV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	// ok, _ := server.GetPowerControl()
	// if ok != false {
	// 	jsonInterface := server.Json["PowerControlInfo"]
	// 	infoList := InterfaceToList(jsonInterface)
	// 	tb, err := TableBuilder(oob.PowerControl{})
	// 	if err != nil {
	// 		logger.Info("RedfishPowerControlV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error( err))
	// 		return tb, err
	// 	}
	// 	// tb := clitask.NewEmptyTableWithKeys([]string{"manufacture", "structs", "serialNumber", "partNumber"})
	// 	for _, each := range infoList {
	// 		m := map[string]interface{}{}
	// 		odataJson, _ := json.Marshal(each)
	// 		if err := json.Unmarshal(odataJson, &m); err == nil {
	// 			p := oob.PowerControl{}
	// 			// fmt.Println("ggggg",m)
	// 			p.PowerCapacityWatts = strings.TrimSpace(fmt.Sprintf("%f", m["PowerCapacityWatts"]))
	// 			p.PowerConsumedWatts = strings.TrimSpace(fmt.Sprintf("%f", m["PowerConsumedWatts"]))
	// 			k, err := structToMapByJsonTag(p)
	// 			err = tb.PushRow("", k, false, "")
	// 			if err != nil {
	// 				return nil, err
	// 			}
	// 		}
	// 	}
	// 	return tb, err
	// }
	return
}

func RedfishNetWorkV1Collect(c *v2.Client) (*clitask.Table, error) {
	logger := log.NewLogger(nil, true)

	adapters := c.GetNetworkAdapters()
	if len(adapters) <= 0 {
		return nil, fmt.Errorf("network adapter is empty")
	}

	t, err := TableBuilder(oob.Network{})
	if err != nil {
		logger.Warn("RedfishNetWorkV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}

	for _, v := range adapters {
		network := oob.Network{
			Name:         v.Name,
			Manufacture:  v.Manufacturer,
			Model:        v.Model,
			PartNumber:   v.PartNumber,
			SerialNumber: v.SerialNumber,
		}
		m, err := structToMapByJsonTag(network)
		if err = t.PushRow("", m, false, ""); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func GofishbaseinfoV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	info, err := server.GetSN()
	if err != nil {
		logger.Warn("GofishbaseinfoV1Collect", zap.String("GetInfo", "采集数据失败"), zap.Error(err))
		return
	}
	tb, err := TableBuilder(oob.BaseInfo{})
	if err != nil {
		logger.Warn("GofishbaseinfoV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	p := oob.BaseInfo{}
	p.Manufacture = info.Manufacture
	p.SKU = info.SKU
	p.SerialNumber = info.SN
	p.PartNumber = info.PN
	p.HostName = info.Name
	p.ModelType = info.ModelType
	m, err := structToMapByJsonTag(p)
	err = tb.PushRow("", m, false, "")
	if err != nil {
		return nil, err
	}
	return tb, err
}

func RedfishCpuV1Collect(c *v2.Client) (*clitask.Table, error) {
	logger := log.NewLogger(nil, true)

	processors := c.GetProcessors()
	if len(processors) <= 0 {
		return nil, fmt.Errorf("processors is empty")
	}

	t, err := TableBuilder(oob.Cpu{})
	if err != nil {
		logger.Warn("RedfishCpuV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}

	for _, v := range processors {
		cpu := oob.Cpu{
			Name:         v.Name,
			Model:        v.Model,
			Manufacture:  v.Manufacturer,
			Arch:         v.Arch,
			TotalThreads: fmt.Sprintf("%d", v.TotalThreads),
			TotalCores:   fmt.Sprintf("%d", v.TotalCores),
		}
		m, err := structToMapByJsonTag(cpu)
		if err = t.PushRow("", m, false, ""); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func RedfishMEMV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)

	memory := c.GetMemory()
	if len(memory) <= 0 {
		return nil, fmt.Errorf("memory is empty")
	}

	t, err := TableBuilder(oob.Mem{})
	if err != nil {
		logger.Warn("RedfishMEMV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}

	for _, v := range memory {
		mem := oob.Mem{
			Name:              v.Name,
			Manufacture:       v.Manufacturer,
			PartNumber:        v.PartNumber,
			SerialNumber:      v.SerialNumber,
			MemoryDeviceType:  v.MemoryDeviceType,
			SizeGiB:           fmt.Sprintf("%d", v.SizeGiB),
			OperatingSpeedMhz: fmt.Sprintf("%d", v.OperatingSpeedMhz),
		}
		m, err := structToMapByJsonTag(mem)
		if err = t.PushRow("", m, false, ""); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func RedfishBaseInfoV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)

	t, err := TableBuilder(oob.BaseInfo{})
	if err != nil {
		logger.Warn("RedfishBaseInfoV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}

	baseInfo := oob.BaseInfo{
		HostName:     c.GetManagerNic().HostName,
		ModelType:    c.GetChassisType(),
		SKU:          c.GetSKU(),
		Manufacture:  c.GetDeviceManufacturer(),
		SerialNumber: c.GetSerialNumber(),
		PartNumber:   c.GetPartNumber(),
	}

	m, err := structToMapByJsonTag(baseInfo)
	if err = t.PushRow("", m, false, ""); err != nil {
		return nil, err
	}
	return t, nil
}

func FilterDisk(plt string) (out string) {
	if plt == "" || plt == "%!s(<nil>)" || plt == "nil" || plt == "%!f(<nil>)" || plt == "%!d(<nil>)" {
		return out
	}
	reg := regexp.MustCompile("^0.0|^0$|^0mb$|^0bytes$｜nil")
	res := reg.FindStringSubmatch(strings.ToLower(plt))
	if len(res) < 1 {
		return plt
	} else {
		return out
	}
}

func RedfishVersionV1Collect(c *v2.Client) (*clitask.Table, error) {
	logger := log.NewLogger(nil, true)

	t, err := TableBuilder(oob.RedfishVersion{})
	if err != nil {
		logger.Warn("RedfishVersionV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}
	version := oob.RedfishVersion{
		RedfishVersion: c.GetRedfishVersion(),
	}
	m, err := structToMapByJsonTag(version)
	if err = t.PushRow("", m, false, ""); err != nil {
		return nil, err
	}
	return t, nil
}

func RedfishBMCV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)

	nic := c.GetManagerNic()
	t, err := TableBuilder(oob.BMC{})
	if err != nil {
		logger.Warn("RedfishBMCV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}

	bmc := oob.BMC{
		Ipv4Addresses: nic.IPv4.Address,
		SpeedMbps:     fmt.Sprintf("%d", nic.SpeedMbps),
	}
	m, err := structToMapByJsonTag(bmc)
	if err = t.PushRow("", m, false, ""); err != nil {
		return nil, err
	}
	return t, nil
}

func GofishBMCV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	infoList, err := server.GetBMCInfo()
	// tb := clitask.NewEmptyTableWithKeys([]string{"ipv4Addresses", "iPv6Addresses", "speedMbps"})
	tb, err := TableBuilder(oob.BMC{})
	if err != nil {
		logger.Warn("GofishBMCV1Collect", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
		return
	}
	for _, each := range infoList {
		p := oob.BMC{}
		ipv4address, _ := json.Marshal(each.IPv4Addresses)
		ipv6address, _ := json.Marshal(each.IPv6Addresses)
		p.Ipv4Addresses = fmt.Sprintf("%s", string(ipv4address))
		p.IPv6Addresses = fmt.Sprintf("%s", string(ipv6address))
		p.SpeedMbps = fmt.Sprintf("%d", each.SpeedMbps)
		m, err := structToMapByJsonTag(p)
		err = tb.PushRow("", m, false, "")
		if err != nil {
			return nil, err
		}
	}
	return tb, err
}

func RedfishNetworkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)

	adapters := c.GetNetworkAdapters()
	if len(adapters) <= 0 {
		return nil, fmt.Errorf("network adapter is empty")
	}

	t, err := TableBuilder(oob.NetworkInterface{})
	if err != nil {
		logger.Warn("RedfishNetworkV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}

	for _, v := range adapters {
		for _, port := range v.Port {
			network := oob.NetworkInterface{
				InterfaceName: port.Name,
				MacAddress:    port.MacAddress,
			}
			m, err := structToMapByJsonTag(network)
			if err = t.PushRow("", m, false, ""); err != nil {
				return nil, err
			}
		}
	}
	return t, nil
}

func RedfishPowerV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)

	powers := c.GetPowerSupplies()
	if len(powers) <= 0 {
		return nil, fmt.Errorf("powers is empty")
	}

	t, err := TableBuilder(oob.Power{})
	if err != nil {
		logger.Error("RedfishPowerV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}

	for _, v := range powers {
		power := oob.Power{
			Model:              v.Model,
			Manufacture:        v.Manufacturer,
			SerialNumber:       v.SerialNumber,
			PowerCapacityWatts: v.PowerCapacityWatts,
		}
		m, err := structToMapByJsonTag(power)
		if err = t.PushRow("", m, false, ""); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func RedfishDiskV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	logger := log.NewLogger(nil, true)

	disks := c.GetPhysicalDisk()
	if len(disks) <= 0 {
		return nil, fmt.Errorf("disks is empty")
	}

	t, err := TableBuilder(oob.Disk{})
	if err != nil {
		logger.Error("RedfishDiskV1Collect", zap.String("host", c.Config.Host), zap.Error(err))
		return nil, err
	}

	for _, v := range disks {
		disk := oob.Disk{
			Name:         v.Name,
			Model:        v.Model,
			Manufacture:  v.Manufacturer,
			PartNumber:   v.PartNumber,
			SerialNumber: v.SerialNumber,
			Protocol:     v.Protocol,
			CapacityGB:   fmt.Sprintf("%d", v.CapacityGB),
		}
		m, err := structToMapByJsonTag(disk)
		if err = t.PushRow("", m, false, ""); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func SnmpGetCpuV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	snmpTask, err := taskConfig.NewExecutor(remote)
	if err != nil {
		return nil, err
	}
	type f func(*clitask.Table, string, map[string]string) error
	table, err := RunSnmpTask(snmpTask.(*snmp.SnmpTask), remote)
	table.ForEach(
		func() f {
			return func(t *clitask.Table, index string, row map[string]string) (e error) {
				row["name"] = "CPU" + fmt.Sprintf("%d", cast.ToInt(index)+1)
				row["manufacture"] = strings.TrimSpace(row["manufacture"])
				row["socket"] = ""
				if !t.IsContainKey("name") {
					t.Keys = append(t.Keys, "name")
				}
				if !t.IsContainKey("socket") {
					t.Keys = append(t.Keys, "socket")
				}
				return e
			}
		}())
	// table, err := switchs.RunSnmpTask(taskConfig.NewSnmpTask(remote.Ip, remote.Community[0]), remote)

	return table, err
}

func IPMIGetSNV1(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (ipmiresult *clitask.Table, err error) {
	logger := log.NewLogger(remote.ActionID, true)

	result, err := IpmiGetSn(remote)
	if result != "" {
		content := strings.Split(result, "\n")
		for _, eachLine := range content {
			match, _ := regexp.MatchString(`Chassis Serial`, eachLine)
			if match {
				snsplit := strings.Split(eachLine, ":")
				if len(snsplit) >= 1 {
					result = strings.TrimSpace(snsplit[1])
					tb, err := TableBuilder(oob.SNField{})
					if err != nil {
						logger.Warn("IPMIGetSNV1", zap.String("TableBuilder", "获取Tabpe失败"), zap.Error(err))
						return tb, err
					}
					p := oob.SNField{}
					p.SerialNumber = result
					m, err := structToMapByJsonTag(p)
					err = tb.PushRow("", m, false, "")
					if err != nil {
						return nil, err
					} else {
						return tb, err
					}
				}
			}
		}
	}
	return nil, err
}
