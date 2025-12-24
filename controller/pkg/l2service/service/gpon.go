package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gofrs/uuid"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/structs/gpon_enum"
	"github.com/influxdata/telegraf/controller/pkg/structs/l2struct"
	"github.com/influxdata/telegraf/controller/pkg/tol"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/log"
	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/text"
	"go.uber.org/zap"
)

type GPON struct{}

func onuSummaryKeyValuePairs(showOnt string) (resultList []map[string]string, err error) {
	dataRegex := `Please wait\s(?P<data>(\n|([^\n]+\s))+)`

	m, err := text.GetFieldByRegex(dataRegex, showOnt, []string{"data"})
	if err != nil {
		return resultList, err
	}
	// data := strings.TrimRightFunc(m["data"], func())
	data := m["data"]
	data = strings.TrimRightFunc(data, func(r rune) bool {
		return unicode.IsSpace(r)
	})

	tableString := text.RegexSplit(`\n\s+\n`, data)
	for _, ts := range tableString {
		portRegex := `In\sport\s(?P<port>[\d\/]+)`
		d, err := text.GetFieldByRegex(portRegex, ts, []string{"port"})
		if err != nil {
			return resultList, err
		}
		port := d["port"]
		ttp := text.NewTextTableParser()
		ttp.Joins = "ont_id"
		ttp.SectionSpliter = func(data string) ([]string, error) {
			return text.RegexSplit(`[ ]{2}[-]{78}`, data), nil
		}
		// ONT  Run     Last                Last                Last
		// ID   State   UpTime              DownTime            DownCause
		// ------------------------------------------------------------------------------
		// 0    online  2023-12-19 08:42:06 -                   -
		// ------------------------------------------------------------------------------
		// ONT        SN        Type          Distance Rx/Tx power  Description
		// ID                                    (m)      (dBm)

		one := text.NewTableSection(2, 3)
		ttp.SectionMap[2] = one
		ttp.SectionMap[3] = one
		one.Positions = []text.Pos{
			{Name: "ont_id", Start: 0, End: 4},
			{Name: "run_state", Start: 6, End: 14},
			{Name: "last_uptime", Start: 15, End: 34},
			{Name: "last_downtime", Start: 36, End: 55},
			{Name: "last_downcause", Start: 56, End: 79}}

		two := text.NewTableSection(4, 5)
		ttp.SectionMap[4] = two
		ttp.SectionMap[5] = two
		two.Positions = []text.Pos{
			{Name: "ont_id", Start: 0, End: 4},
			{Name: "sn", Start: 6, End: 22},
			{Name: "type", Start: 23, End: 36},
			{Name: "distance", Start: 37, End: 44},
			{Name: "tx_rx_power", Start: 45, End: 57},
			{Name: "description", Start: 59, End: 79}}

		// ttp.Parse(ts)
		tb, err := ttp.GetResult(ts)
		if err != nil {
			return resultList, err
		} else {
			for _, v := range tb.ToSliceMap() {
				v["port"] = port
				resultList = append(resultList, v)
			}
		}
	}
	return
}

// onuExtractKeyValuePairs 函数接受一个字符串文本，并返回一个包含键值对的切片
func onuExtractKeyValuePairs(text string) []map[string]string {
	lines := strings.Split(text, "\n")

	var keyValuePairs []map[string]string
	var keyValueMap map[string]string

	// 遍历每一行
	for _, line := range lines {
		// 跳过第一行命令
		if strings.Contains(line, "display ont autofind all") {
			continue
		}
		// 跳过最后一行统计
		if strings.Contains(line, "GPON autofind ONT") {
			continue
		}
		if strings.Contains(line, "is saved completely") {
			continue
		}
		// 如果当前行包含"-------"，表示段落结束，将当前的键值对map存入切片并初始化一个新的map
		if strings.Contains(line, "-------") {
			if keyValueMap != nil {
				keyValuePairs = append(keyValuePairs, keyValueMap)
			}
			keyValueMap = make(map[string]string)
			continue
		}

		// 按":"分割键值对
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// 将键值对存入当前的map
			keyValueMap[key] = value
		} else if len(parts) == 1 {
			// 处理只有键没有值的情况
			key := strings.TrimSpace(parts[0])
			// 将键设为空字符串
			keyValueMap[key] = ""
		}
	}

	// 将最后一个段落的键值对map存入切片
	if keyValueMap != nil {
		keyValuePairs = append(keyValuePairs, keyValueMap)
	}

	return keyValuePairs
}

func snmpGetOnuSummary(remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
	if len(remote.Community) == 0 {
		return result, fmt.Errorf("团体字为空")
	}
	st, err := snmp.NewSnmpTask(
		remote.Ip,
		remote.Community[0],
		"1.3.6.1.2.1.2.2.1",
		[]int{1},
		[]int{0},
		map[string]string{"2": "name"},
		map[string]func(byte, string, interface{}) (string, error){},
		nil)

	st.Run(true)
	ifTable, err := st.Table()
	// table.Keys = append(table.Keys, "name")
	//
	fmt.Println("==============ifTable===============")
	// result = clitask.NewEmptyTableWithKeys([]string{"version"})
	if err != nil {
		fmt.Println("ifTable err", err)
		return
	}
	//
	err = ifTable.ForEach(func(t *clitask.Table, index string, row map[string]string) error {
		nameSplit := strings.Split(strings.TrimSpace(row["name"]), " ")
		if len(nameSplit) > 1 {
			row["port"] = nameSplit[1]
		}
		if !t.IsContainKey("port") {
			t.Keys = append(t.Keys, "port")
		}
		return nil
	})
	// ifTable.Pretty()

	fmt.Println("==============time===============")
	st, err = snmp.NewSnmpTask(
		remote.Ip,
		remote.Community[0],
		".1.3.6.1.4.1.2011.6.128.1.1.2.101.1",
		[]int{1, 2, 3},
		[]int{0},
		map[string]string{"6": "up_time", "7": "down_time", "8": "down_cause"},
		map[string]func(byte, string, interface{}) (string, error){"3": tol.HexPDU},
		nil)

	st.Run(true)
	tm, err := st.Table()
	err = tm.ForEach(func(t *clitask.Table, index string, row map[string]string) error {
		row["index2"] = index
		if !t.IsContainKey("index2") {
			t.Keys = append(t.Keys, "index2")
		}
		return nil
	})
	if err != nil {
		fmt.Println("////time get err", err)
		return
	}
	// tm.Pretty()
	timeMap := make(map[string]map[string]string)
	timeHistoryMap := make(map[string]map[string]string)
	for _, v := range tm.ToSliceMap() {
		t2 := make(map[string]string)
		idexSplit := strings.Split(v["index2"], ".")
		devIndex := idexSplit[0] + "." + idexSplit[1]
		if _, ok := timeHistoryMap[devIndex]; !ok {
			g := make(map[string]string)
			g["down_time"] = ""
			g["down_cause"] = "-1"
			timeHistoryMap[devIndex] = g
		}
		if v["up_time"] == "" {
			// lastDownCause, lastDownTime = "", "-1"
			continue
		}
		t2["index2"] = devIndex
		t2["up_time"] = v["up_time"]
		t2["down_time"] = timeHistoryMap[devIndex]["down_time"]
		t2["down_cause"] = timeHistoryMap[devIndex]["down_cause"]
		timeMap[devIndex] = t2
		// lastDownCause = v["down_cause"]
		// lastDownTime = v["down_time"]
		timeHistoryMap[devIndex]["down_time"] = v["down_time"]
		timeHistoryMap[devIndex]["down_cause"] = v["down_cause"]
	}
	timeTable := clitask.NewEmptyTableWithKeys([]string{"up_time", "down_time", "down_cause", "index2"})
	for _, v := range timeMap {
		timeTable.PushRow("", v, false, "")
	}
	fmt.Println("==============new time table=======")
	// timeTable.Pretty()
	fmt.Println("==============ip===============")
	st, err = snmp.NewSnmpTask(
		remote.Ip,
		remote.Community[0],
		".1.3.6.1.4.1.2011.6.145.1.1.1.17.1",
		[]int{1, 2},
		[]int{0},
		map[string]string{"7": "ip_address"},
		map[string]func(byte, string, interface{}) (string, error){},
		nil)

	st.Run(true)
	ipTable, err := st.Table()
	if err != nil {
		fmt.Println("////ip get err", err)
		return
	}
	// ipTable.Pretty()
	fmt.Println("==============base===============")
	st, err = snmp.NewSnmpTask(
		remote.Ip,
		remote.Community[0],
		".1.3.6.1.4.1.2011.6.128.1.1.2.45.1",
		[]int{1, 2},
		[]int{0},
		map[string]string{"4": "device_model", "5": "firmware_version", "10": "mac"},
		map[string]func(byte, string, interface{}) (string, error){"10": tol.HexPDU},
		nil)

	st.Run(true)
	baseTable, err := st.Table()
	if err != nil {
		fmt.Println("////base get err", err)
		return
	}
	// baseTable.Pretty()

	fmt.Println("==============prof===============")
	st, err = snmp.NewSnmpTask(
		remote.Ip,
		remote.Community[0],
		".1.3.6.1.4.1.2011.6.128.1.1.2.43.1",
		[]int{1, 2},
		[]int{0},
		map[string]string{"3": "sn", "6": "management_mode", "7": "line_prof_name", "8": "srv_prof_name", "9": "desc"},
		map[string]func(byte, string, interface{}) (string, error){"3": tol.HexPDU},
		nil)

	st.Run(true)
	profTable, err := st.Table()
	if err != nil {
		fmt.Println("////prof get err", err)
		return
	}
	err = profTable.ForEach(func(t *clitask.Table, index string, row map[string]string) error {
		splitIndex := strings.Split(index, ".")
		if len(splitIndex) > 1 {
			row["loc"] = splitIndex[1]
			// row["index2"] = splitIndex[0] + "." + row["loc"]
			row["port_index"] = splitIndex[0]
			if !t.IsContainKey("loc") {
				t.Keys = append(t.Keys, "loc")
			}
			// if !t.IsContainKey("index2") {
			// 	t.Keys = append(t.Keys, "index2")
			// }
			if !t.IsContainKey("port_index") {
				t.Keys = append(t.Keys, "port_index")
			}
			return nil
		} else {
			return fmt.Errorf("解析序列号index错误,index:%s", index)
		}
	})
	// profTable.Pretty()

	fmt.Println("==============status===============")
	st, err = snmp.NewSnmpTask(
		remote.Ip,
		remote.Community[0],
		".1.3.6.1.4.1.2011.6.128.1.1.2.46.1",
		[]int{1, 2},
		[]int{0},
		map[string]string{"1": "active_status", "16": "config_status", "27": "battery_status", "18": "match_status", "15": "run_status", "25": "dying_gasp_time"},
		map[string]func(byte, string, interface{}) (string, error){"25": tol.HexPDU},
		nil)

	st.Run(true)
	statusTable, err := st.Table()
	statusTable.Pretty()
	if err != nil {
		fmt.Println("////prof get err", err)
		return
	}
	// statusTable.Pretty()
	fmt.Println("=================last======")
	profTable.AddKeyFromTable("ip_address", "", "ip_address", "", ipTable, "")
	profTable.AddKeyFromTable("device_model", "", "device_model", "", baseTable, "")
	profTable.AddKeyFromTable("firmware_version", "", "firmware_version", "", baseTable, "")
	profTable.AddKeyFromTable("mac", "index", "mac", "", baseTable, "")
	profTable.AddKeyFromTable("line_prof_name", "", "line_prof_name", "", profTable, "")
	profTable.AddKeyFromTable("srv_prof_name", "", "srv_prof_name", "", profTable, "")
	profTable.AddKeyFromTable("desc", "", "desc", "", profTable, "")
	profTable.AddKeyFromTable("management_mode", "", "management_mode", "", profTable, "")
	profTable.AddKeyFromTable("port", "port_index", "port", "", ifTable, "")
	profTable.AddKeyFromTable("run_status", "", "run_status", "", statusTable, "")
	profTable.AddKeyFromTable("active_status", "", "active_status", "", statusTable, "")
	profTable.AddKeyFromTable("config_status", "", "config_status", "", statusTable, "")
	profTable.AddKeyFromTable("battery_status", "", "battery_status", "", statusTable, "")
	profTable.AddKeyFromTable("match_status", "", "match_status", "", statusTable, "")
	profTable.AddKeyFromTable("up_time", "", "up_time", "index2", timeTable, "")
	profTable.AddKeyFromTable("down_time", "", "down_time", "index2", timeTable, "")
	profTable.AddKeyFromTable("down_cause", "", "down_cause", "index2", timeTable, "")
	// profTable.Pretty()
	return profTable, err
}
func getOnuSSH(remote *structs.L2DeviceRemoteInfo) (result *clitask.Table, err error) {
	// var rs *clitask.Table
	// var ok bool
	tb := clitask.NewEmptyTableWithKeys([]string{
		l2struct.OnuSn, l2struct.OnuRunStatus, l2struct.OnuIp,
		l2struct.OnuEquipmentID, l2struct.OnuMac, l2struct.OnuName, l2struct.OnuSrvProfName,
		l2struct.OnuSoftwareVersion, l2struct.OnuManagementMode, l2struct.OnuLineProfName,
		l2struct.OnuDesc, l2struct.OnuUpTime, l2struct.OnuDownTime, l2struct.OnuDownCause,
		l2struct.OnuActiveStatus, l2struct.OnuConfigStatus, l2struct.OnuBatteryStatus,
		l2struct.OnuMatchStatus, l2struct.OnuDyingGaspTime,
	})
	base := &terminal.BaseInfo{
		Host:     remote.Ip,
		Username: remote.Username,
		Password: remote.Password,
		AuthPass: remote.Password,
		Telnet:   false,
		Port:     remote.Meta.SSHPort,
	}
	base.WithActionID(remote.ActionID)
	// }

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.HWGpon, base)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	exec.Add("display ont autofind all", "", 5, "display_ont_autofind", "")
	// exec.Add("display ont info summary 0", "", 5, "display_ont_summary", "")
	exec.Prepare(false)
	data := exec.Run(false)

	if data.Error() != nil {
		err = data.Error()
		return
	}
	ok, lines := data.GetResult("display_ont_autofind")
	if !ok {
		err = fmt.Errorf("get cmd result failed, cmd=%s", "display ont autofind all")
		return
	} else {
		var unregisterTag bool
		for _, line := range lines {
			if strings.Contains(line, "do not exist") {
				unregisterTag = true
			}
		}
		if unregisterTag == false {
			oldStr := strings.Join(lines, "\n")
			keyValuePairs := onuExtractKeyValuePairs(oldStr)
			for _, kv := range keyValuePairs {
				// fmt.Printf("段落 %d:\n", i+1)
				if len(kv) > 0 {
					each := make(map[string]string)
					for key, value := range kv {
						each[key] = strings.TrimSpace(value)
						// fmt.Printf("%s: %s\n", key, value)
					}
					fmt.Println("onuline---", each)
					if len(each) == 0 {
						continue
					}
					m := make(map[string]string)
					if each["Ont SN"] != "" {
						b := strings.Split(each["Ont SN"], "(")
						sn := strings.TrimSpace(b[0])
						m[l2struct.OnuSn] = sn
					}
					m[l2struct.OnuSoftwareVersion] = strings.TrimSpace(each["Ont SoftwareVersion"])
					m[l2struct.OnuMac] = strings.TrimSpace(each["Ont MAC"])
					m[l2struct.OnuEquipmentID] = strings.TrimSpace(each["Ont EquipmentID"])
					m[l2struct.OnuName] = strings.TrimSpace(each["F/S/P"])
					m[l2struct.OnuRunStatus] = "Unregistered"
					if m[l2struct.OnuMac] == "" && m[l2struct.OnuName] == "" && m[l2struct.OnuSoftwareVersion] == "" && m[l2struct.OnuSn] == "" {
						continue
					}
					err = tb.PushRow("", m, false, "")
				}
				// fmt.Println("----------------------------------------------------------------------------")
			}
		}
	}
	summaryResult, err := snmpGetOnuSummary(remote)
	if err != nil {
		return
	} else {
		for _, v := range summaryResult.ToSliceMap() {
			m := make(map[string]string)
			if strings.TrimSpace(v["sn"]) == "" {
				continue
			}
			m[l2struct.OnuSoftwareVersion] = strings.TrimSpace(v["firmware_version"])
			m[l2struct.OnuMac] = strings.TrimSpace(v["mac"])
			m[l2struct.OnuIp] = strings.TrimSpace(v["ip_address"])
			m[l2struct.OnuSn] = strings.TrimSpace(v["sn"])
			m[l2struct.OnuEquipmentID] = strings.TrimSpace(v["device_model"])
			m[l2struct.OnuName] = strings.TrimSpace(v["port"]) + "/" + strings.TrimSpace(v["loc"])
			activeStatusNum, err := strconv.Atoi(strings.TrimSpace(v["active_status"]))
			if err != nil {
				fmt.Println("active status 转换int错误", v["active_status"])
				m[l2struct.OnuActiveStatus] = gpon_enum.NoInformation
			} else {
				m[l2struct.OnuActiveStatus] = gpon_enum.GetActiveStatus(gpon_enum.ActiveStatus(activeStatusNum))
			}
			batteryStatusNum, err := strconv.Atoi(strings.TrimSpace(v["battery_status"]))
			if err != nil {
				fmt.Println("battery status 转换int错误", v["battery_status"])
				m[l2struct.OnuBatteryStatus] = gpon_enum.NoInformation
			} else {
				m[l2struct.OnuBatteryStatus] = gpon_enum.GetBatteryStatus(gpon_enum.BatteryStatus(batteryStatusNum))
			}
			configStatusNum, err := strconv.Atoi(strings.TrimSpace(v["config_status"]))
			if err != nil {
				fmt.Println("config status 转换int错误", v["config_status"])
				m[l2struct.OnuConfigStatus] = gpon_enum.NoInformation
			} else {
				m[l2struct.OnuConfigStatus] = gpon_enum.GetConfigStatus(gpon_enum.ConfigStatus(configStatusNum))
			}
			matchStatusNum, err := strconv.Atoi(strings.TrimSpace(v["match_status"]))
			if err != nil {
				fmt.Println("match status 转换int错误", v["match_status"])
				m[l2struct.OnuMatchStatus] = gpon_enum.NoInformation
			} else {
				m[l2struct.OnuMatchStatus] = gpon_enum.GetMatchStatus(gpon_enum.MatchStatus(matchStatusNum))
			}
			if strings.ToLower(v["run_status"]) == "1" {
				m[l2struct.OnuRunStatus] = "PowerON"
			} else {
				m[l2struct.OnuRunStatus] = "PowerOFF"
			}
			mgModeNum, err := strconv.Atoi(strings.TrimSpace(v["management_mode"]))
			if err != nil {
				fmt.Println("management mode 转换int错误", v["management_mode"])
				m[l2struct.OnuManagementMode] = gpon_enum.NoInformation
			} else {
				m[l2struct.OnuManagementMode] = gpon_enum.GetManagementModeStatus(gpon_enum.ManagementMode(mgModeNum))
			}
			m[l2struct.OnuLineProfName] = strings.TrimSpace(v["line_prof_name"])
			m[l2struct.OnuSrvProfName] = strings.TrimSpace(v["srv_prof_name"])
			m[l2struct.OnuDesc] = strings.TrimSpace(v["desc"])
			m[l2struct.OnuUpTime] = strings.TrimSpace(v["up_time"])
			m[l2struct.OnuDownTime] = strings.TrimSpace(v["down_time"])
			m[l2struct.OnuDyingGaspTime] = strings.TrimSpace(v["dying_gasp_time"])
			downCauseNum, err := strconv.Atoi(strings.TrimSpace(v["down_cause"]))
			if err != nil {
				fmt.Println("down_cause 转换int错误", v["down_cause"])
				m[l2struct.OnuDownCause] = gpon_enum.NoInformation
			} else {
				m[l2struct.OnuDownCause] = gpon_enum.GetDownCause(gpon_enum.DownCause(downCauseNum))
			}
			err = tb.PushRow("", m, false, "")
		}
	}
	tb.Pretty()
	return tb, err
}
func (ts *GPON) OnuCollect(ctx context.Context, arg *structs.Args, reply *structs.Reply) (err error) {
	logger := log.NewLogger(arg.Remote.ActionID, true)

	reply.StartTime = time.Now()
	logger.Debug("OnuCollect 开始Onu采集", zap.Any("args", arg))

	var result *clitask.Table
	if arg.Platform == "HWGpon" {
		result, err = getOnuSSH(arg.Remote)
	}

	if err != nil {
		reply.EndTime = time.Now()
		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
		// reply.Table = result
		reply.Error = err
		logger.Error("Onu采集失败", zap.Any("args", arg), zap.Error(err))
		return err
	}

	reply.Table = result
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err

	result.Pretty()

	logger.Debug("Onu完成采集", zap.Any("reply", reply))
	return nil
}
