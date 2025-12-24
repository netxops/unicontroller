package nodemap

import (
	"encoding/json"
	"fmt"

	"github.com/hpcloud/tail"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/log"
	"go.uber.org/zap"
)

type IntentMap struct {
	Src          string `json:"src"`
	Dst          string `json:"dst"`
	Protocol     string `json:"protocol"`
	Dport        string `json:"dport"`
	Vrf          string `json:"vrf"`
	RealIp       string `json:"realIp"`
	RealPort     string `json:"realPort"`
	Area         string `json:"area"`
	Snat         string `json:snat`
	Gw6          string `json:"gw_6"`
	TicketNumber string `json:"ticketNumber"`
	SubTicket    string `json:"subTicket"`
	TraverseOnly bool   `json:"traverseOnly"`
	ItemId       uint   `json:"item_id"`
}

type executeResult struct {
	msg    string
	cli    string
	status global.CmdExecuteStatusColor
	device string
}

// var deviceConfigDataList = []map[string]interface{}{
// {
// "base": map[string]interface{}{
// "host":     "192.168.100.232",
// "username": "admin",
// "password": "12345@qwer",
// "auth_pass": "bisco",
// "port": 443,
// "community": "public",
// "mode":   "SecPath",
// "telnet": true,
// },
// "connection": []map[string]interface{}{},
// "vs_range":   []map[string]interface{}{},
// "ipv4_area": []map[string]interface{}{
// map[string]interface{}{
// "name":      "Internet",
// "interface": "GigabitEthernet1/0/0",
// },
// },
// "ipv6_area": []map[string]interface{}{},
// },
// }
type ipv4Area struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
}

type ipv6Area struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
}

type deviceConnection struct {
}

type deviceVsrange struct {
}
type deviceBase struct {
	Host     string `json:"host" mapstructure:"host"`
	Username string `json:"username" mapstructure:"username"`
	Password string `json:"password" mapstructure:"password"`
	AuthPass string `json:"auth_pass" mapstructure:"auth_pass"`
	Port     int    `json:"port" mapstructure:"port"`
	Mode     string `json:"mode" mapstructure:"mode"`
	Telnet   bool   `json:"telnet" mapstructure:"telnet"`
}

type deviceConfigDataList struct {
	List []deviceConfigData
}

type deviceConfigData struct {
	Base        deviceBase         `json:"base" mapstructure:"base"`
	Connection  []deviceConnection `json:"Connection" mapstructure:"connection"`
	VsRange     []deviceVsrange    `json:"vs_range" mapstructure:"vs_range"`
	Ipv4Area    []ipv4Area         `json:"ipv4_area" mapstructure:"ipv4_area"`
	Ipv6Area    []ipv6Area         `json:"ipv6_area" mapstructure:"ipv6_area"`
	DevTablesID uint               `json:"dev_tables_id" mapstructure:"dev_tables_id"`
}

//func DeviceConfigListFromDb(db *gorm.DB) ([]*config.DeviceConfig, error) {
//	// var deviceConfigList []deviceConfigData
//	var deviceList []*config.DeviceConfig
//	var dev_tables []model.DcimDevice
//	err := global.GVA_DB.Preload("DcimPlatform").Preload("Connection").Preload("Area").Preload("PrimaryIp4").Find(&dev_tables).Error
//
//	if err == nil {
//		for _, oneDev := range dev_tables {
//			byteS, err := json.Marshal(&oneDev)
//			if err != nil {
//				panic(err)
//			}
//
//			m := map[string]interface{}{}
//			err = json.Unmarshal(byteS, &m)
//			if err != nil {
//				panic(err)
//			}
//
//			// mapstructure.Decode()
//			var cfg config.DeviceConfig
//			err = mapstructure.WeakDecode(m, &cfg)
//			if err != nil {
//				panic(err)
//			}
//
//			cfg.DevTablesID = oneDev.ID
//			if oneDev.PrimaryIp4 != nil {
//				cfg.Host = oneDev.PrimaryIp4.Address
//			}
//			deviceList = append(deviceList, &cfg)
//
//		}
//	} else {
//		return nil, err
//	}
//	// b, err3 := json.Marshal(dl)
//	// if err3 != nil {
//	// return nil, err3
//	// }
//	// var devStruct []map[string]interface{}
//	// _ = json.Unmarshal(b, &devStruct)
//	// if len(devStruct) == 0 {
//	// errMsg := errors.New("devStruct is none")
//	// return nil, errMsg
//	// }
//	// for _, conf := range devStruct {
//	// fmt.Println(conf)
//	// dc := CONFIG.NewDeviceConfig(conf["base"])
//	// dc.WithConnection(conf["connection"])
//	// dc.WithVsRange(conf["VsRange"])
//	// dc.WithArea(conf["ipv4_area"], network.IPv4)
//	// dc.WithArea(conf["ipv6_area"], network.IPv6)
//	//
//	// deviceList = append(deviceList, dc)
//	//
//	// }
//
//	return deviceList, nil
//
//}

//func InitNodeRun(nodeMapId *uint) (nodemap *NodeMap, err error) {
//	//nodemapTask = model.LastNodeMapTask(global.GVA_SQLite)
//	nodemapTask := model.NewNodeMapTask(global.GVA_DB)
//	// nodemapTask := &model.NodeMapTask{}
//	// nodemapTask.Uuid = uuid.Must(uuid.NewV4()).String()
//	// global.GVA_DB.Save(nodemapTask)
//	//nodemapTask = model.LastNodeMapTask(global.GVA_SQLite)
//	deviceList, err := DeviceConfigListFromDb(global.GVA_DB)
//	if err != nil {
//		panic(err)
//	}
//
//	nm := NewNodeMapFromNetwork("nodemap1", deviceList, false, nodemapTask.ID, nodeMapId)
//	nm.WithLogger(logger)
//
//	return nm, nil
//}

//func InitNodeRunConfig(nodeMapId *uint) (nodemap *NodeMap, err error) {
//	//nodemapTask := model.LastNodeMapTask(global.GVA_DB)
//	nodemapTask := model.NewNodeMapTask(global.GVA_DB)
//	//nodemapTask := &model.NodeMapTask{}
//	//nodemapTask.Uuid = uuid.Must(uuid.NewV4()).String()
//	//global.GVA_DB.Save(nodemapTask)
//	//nodemapTask = model.LastNodeMapTask(global.GVA_SQLite)
//	// var deviceConfigList []deviceConfigData
//
//	var deviceList []*config.DeviceConfig
//	var dev_tables []model.DcimDevice
//	// err = global.GVA_DB.Preload("DcimPlatform").Find(&dev_tables).Error
//	err = global.GVA_DB.Preload("DcimPlatform").Preload("Connection").Preload("Area").Preload("PrimaryIp4").Find(&dev_tables).Error
//	if err == nil {
//		for _, oneDev := range dev_tables {
//			byteS, err := json.Marshal(&oneDev)
//			if err != nil {
//				panic(err)
//			}
//
//			m := map[string]interface{}{}
//			err = json.Unmarshal(byteS, &m)
//			if err != nil {
//				panic(err)
//			}
//
//			// mapstructure.Decode()
//			var cfg config.DeviceConfig
//			err = mapstructure.WeakDecode(m, &cfg)
//			if err != nil {
//				panic(err)
//			}
//
//			cfg.DevTablesID = oneDev.ID
//			if oneDev.PrimaryIp4 != nil {
//				cfg.Host = oneDev.PrimaryIp4.Address
//			} else {
//				cfg.Host = ""
//				fmt.Println("oneDev.PrimaryIp4 is empty", oneDev.Name)
//				continue
//			}
//			dataMap := map[string]string{}
//			dataMap["device"] = fmt.Sprintf("%d", oneDev.ID)
//			dataMap["IN_BOUND"] = "true"
//			dataMap["catalog"] = "SERVER"
//			remote, _, err := service.GetRemoteInfoList(dataMap, global.GVA_CONFIG.RoleConfig.InbandSnmp.Name, global.GVA_CONFIG.RoleConfig.InbandSecret.Name, false)
//			cfg.Mode = oneDev.Platform()
//			if len(remote) > 0 {
//				cfg.Password = remote[0].Password
//				cfg.Community = remote[0].Community[0]
//				cfg.Username = remote[0].Username
//				cfg.Port = remote[0].Meta.SSHPort
//				cfg.Telnet = *remote[0].Meta.EnableTelnet
//				cfg.AuthPass = remote[0].AuthPass
//
//			} else {
//				fmt.Println("-----GetRemoteInfoList err", err)
//				continue
//			}
//			deviceList = append(deviceList, &cfg)
//
//			// fmt.Println("++=======================================>>>>>>", oneDev.Ipv4Area)
//			// var areaAllList []model.TArea
//			// eachHost := oneDev.SystemIp
//			// eachUserName := oneDev.Username
//			// eachPassWord := oneDev.Password
//			// eachAuthPass := oneDev.AuthPass
//			// eachPort := oneDev.Port
//			// eachMode := oneDev.DcimPlatform.Name
//			// eachTelnet := oneDev.Telnet
//			// var eachTelnetBool bool
//			// if eachTelnet == 1 {
//			// eachTelnetBool = true
//			// } else {
//			// eachTelnetBool = false
//			// }
//			// intPort, _ := strconv.Atoi(eachPort)
//			// var eachDevice deviceConfigData
//			// eachDevice.Base = deviceBase{
//			// Host:     eachHost,
//			// Username: eachUserName,
//			// Password: eachPassWord,
//			// AuthPass: eachAuthPass,
//			// Port:     intPort,
//			// Mode:     eachMode,
//			// Telnet:   eachTelnetBool,
//			// }
//			//
//
//			// global.GVA_DB.Where("dev_tables_id = ?", oneDev.ID).Find(&areaAllList)
//			// ipv4List := []ipv4Area{}
//			// for _, eachArea := range areaAllList {
//			// eachIpv4 := ipv4Area{
//			// Name:      eachArea.Name,
//			// Interface: eachArea.Interface,
//			// }
//			// ipv4List = append(ipv4List, eachIpv4)
//			// }
//			// eachDevice.Ipv4Area = ipv4List
//			// eachDevice.DevTablesID = oneDev.ID
//			// eachDevice.DevTables = &oneDev
//			//eachDevice["connection"] = []map[string]interface{}{}
//			//eachDevice["vs_range"] = []map[string]interface{}{}
//			//eachDevice["ipv6_area"] = []map[string]interface{}{}
//			// dl.List = append(dl.List, eachDevice)
//		}
//	} else {
//		return nil, err
//	}
//	// b, err3 := json.Marshal(dl)
//	// if err3 != nil {
//	// return nil, err3
//	// }
//	// var devStruct []map[string]interface{}
//	// _ = json.Unmarshal(b, &devStruct)
//	// fmt.Println("+++++++11111", devStruct)
//	// fmt.Println("=======11111", deviceConfigDataList)
//	// if len(devStruct) == 0 {
//	// errMsg := errors.New("devStruct is none")
//	// return nil, errMsg
//	// }
//	// for _, conf := range devStruct {
//	// fmt.Println(conf)
//	// dc := CONFIG.NewDeviceConfig(conf["base"])
//	// dc.WithConnection(conf["connection"])
//	// dc.WithVsRange(conf["VsRange"])
//	// dc.WithArea(conf["ipv4_area"], network.IPv4)
//	// dc.WithArea(conf["ipv6_area"], network.IPv6)
//	// id := uint(conf["dev_tables_id"].(int))
//	// dc.DevTablesID = &id
//	//
//	// fmt.Println("================>", dc)
//	//
//	// deviceList = append(deviceList, dc)
//	//
//	// }
//
//	nm := NewNodeMapFromNetwork("nodemap1", deviceList, true, nodemapTask.ID, nodeMapId)
//	nm.WithLogger(logger)
//
//	for _, oneDev := range dev_tables {
//		var eachHost string
//		if oneDev.PrimaryIp4 != nil {
//			eachHost = oneDev.PrimaryIp4.Address
//		} else {
//			fmt.Println("====eachHost is empty", oneDev.Name)
//		}
//		//eachHost := oneDev.SystemIp
//		extract_task_result := map[string]interface{}{}
//		fmt.Println("111333", eachHost)
//		global.GVA_DB.Table("extract_task").Where("node_ip = ?", eachHost).Order("created_at DESC").Take(&extract_task_result)
//		fmt.Println("===11111555", extract_task_result)
//		if extract_task_result != nil {
//			extract_task_id := extract_task_result["id"]
//			config_extract_result := map[string]interface{}{}
//			global.GVA_DB.Table("config_extract_entity").Where("extract_task_id = ? and cmd_key = ?", extract_task_id, "sh_run").Take(&config_extract_result)
//			//fmt.Println("======2", extract_task_id, config_extract_result["data"])
//			if config_extract_result != nil {
//				config_data := config_extract_result["data"]
//				//fmt.Println("===1111113333", eachHost, config_data)
//				configstrfmt := fmt.Sprintf("%v", config_data)
//				utf8Encoder := mahonia.NewEncoder("UTF-8")
//				configstr := utf8Encoder.ConvertString(configstrfmt)
//				var ipam_ipaddress model.IpamIpaddress
//				ipResult := global.GVA_DB.Where("address = ?", eachHost).First(&ipam_ipaddress)
//				if ipResult.RowsAffected > 0 {
//					global.GVA_DB.Model(&model.DcimDevice{}).Where("primary_ip4_id = ?", ipam_ipaddress.ID).Update("lastconfig", configstr)
//				} else {
//					fmt.Printf("ipv4:%s未找到,未更新 lastconfig", eachHost)
//				}
//				//fmt.Println("======1113333", eachHost, config_err)
//
//			}
//		}
//	}
//
//	return nm, nil
//}

//
// func ExecuateData(result *TraverseResult, deviceList []*config.DeviceConfig, nodemap_task_id uint) {
// for _, item := range result.Items {
// ip := item.Node.CmdIp()
// for _, dc := range deviceList {
// if ip == dc.Host {
// adapter := NewAdapter(dc, nodemap_task_id, true)
//
// _, err := adapter.BatchRun(item.CmdListList)
// if err != nil {
// panic(err)
// }
// for _, cl := range item.CmdListList {
// byteS, err := json.MarshalIndent(cl, "", "  ")
// if err != nil {
// panic(err)
// }
//
// fmt.Println("执行结果")
// fmt.Println(string(byteS))
// }
//
// }
// }
// }
// }

type deviceColor struct {
	DeviceIp string
	Color    string
}

func ExecuteItem(result *TraverseResult, deviceList []*config.DeviceConfig, item_id uint, nodemap_task_id uint) (resultList []executeResult, deviceStatusList []deviceColor) {
	logger := log.NewLogger(nil, true)
	for _, item := range result.Items {
		ip := item.Node.CmdIp()

		for _, dc := range deviceList {
			if ip == dc.Host {
				fmt.Println("++++host", dc.Host)
				adapter := NewAdapter(dc)

				// 在某一台防火墙设备上执行配置推送
				cmdList, err := adapter.BatchConfig(item.CmdListList, item.AdditionCli)
				if err != nil {
					panic(err)
				}

				// color: 显示当前设备推送配置的亮灯状态，GREEN、YELLOW(表示必须执行的命令都成功了，但是部分选命令执行出错)、RED(表示有必须命名执行出错)
				color := cmdList.(command.CmdExecuteStatus).Color()
				fmt.Println(color)
				eachDeviceStatus := deviceColor{
					DeviceIp: dc.Host,
					Color:    color.String(),
				}
				deviceStatusList = append(deviceStatusList, eachDeviceStatus)
				// 所有的必须命令
				mainCmdList, _, _, _ := cmdList.(command.CmdExecuteStatus).MainCmds()
				for _, c := range mainCmdList {
					// 如果c.Ok()为true, 表示执行成功
					// 但是c.Ok()为false，并不一定表示执行设备，因为golang的默认bool类型为false，要结合c.Msg()，来判定该命令是否执行。
					// c.Cmd()，表示执行具体命令是什么
					// c.Msg(), 如果成功，Msg中可能包含成功命令的返回结果，但是有的命令可能是不返回内容的，此时Msg为空字符串。执行失败，Msg中包含失败内容或原因。

					if c.Ok() {
						logger.Info(c.Cmd())
						eachResult := executeResult{
							cli: c.Cmd(),
							// msg:    c.Msg(),
							status: color,
							device: ip,
						}
						resultList = append(resultList, eachResult)
					} else {
						// c.Msg()不为空字符串
						if c.Msg() != "" {
							logger.Error(c.Cmd(), zap.Any("Msg", c.Msg()))

							eachResult := executeResult{
								// msg:    string(byteStr),
								cli:    c.Cmd(),
								msg:    c.Msg(),
								status: color,
								device: ip,
							}
							resultList = append(resultList, eachResult)
						}
					}

				}
			}
		}
	}
	return

}

func ExecuteItem2(result *TraverseResult, deviceList []*config.DeviceConfig, item_id uint, nodemap_task_id uint) (resultList []executeResult, deviceStatusList []deviceColor) {
	logger := log.NewLogger(nil, true)
	for _, item := range result.Items {
		ip := item.Node.CmdIp()

		for _, dc := range deviceList {
			if ip == dc.Host {
				fmt.Println("++++host", dc.Host)
				adapter := NewAdapter(dc)

				// 在某一台防火墙设备上执行配置推送
				cmdList, err := adapter.BatchConfig(item.CmdListList, item.AdditionCli)
				if err != nil {
					panic(err)
				}

				// color: 显示当前设备推送配置的亮灯状态，GREEN、YELLOW(表示必须执行的命令都成功了，但是部分选命令执行出错)、RED(表示有必须命名执行出错)
				color := cmdList.(command.CmdExecuteStatus).Color()
				fmt.Println(color)
				eachDeviceStatus := deviceColor{
					DeviceIp: dc.Host,
					Color:    color.String(),
				}
				deviceStatusList = append(deviceStatusList, eachDeviceStatus)
				// 所有的必须命令
				mainCmdList, _, _, _ := cmdList.(command.CmdExecuteStatus).MainCmds()
				for _, c := range mainCmdList {
					// 如果c.Ok()为true, 表示执行成功
					// 但是c.Ok()为false，并不一定表示执行设备，因为golang的默认bool类型为false，要结合c.Msg()，来判定该命令是否执行。
					// c.Cmd()，表示执行具体命令是什么
					// c.Msg(), 如果成功，Msg中可能包含成功命令的返回结果，但是有的命令可能是不返回内容的，此时Msg为空字符串。执行失败，Msg中包含失败内容或原因。

					if c.Ok() {
						logger.Info(c.Cmd())
						eachResult := executeResult{
							cli: c.Cmd(),
							// msg:    c.Msg(),
							status: color,
							device: ip,
						}
						resultList = append(resultList, eachResult)
					} else {
						// c.Msg()不为空字符串
						if c.Msg() != "" {
							logger.Error(c.Cmd(), zap.Any("Msg", c.Msg()))

							eachResult := executeResult{
								// msg:    string(byteStr),
								cli:    c.Cmd(),
								msg:    c.Msg(),
								status: color,
								device: ip,
							}
							resultList = append(resultList, eachResult)
						}
					}

				}
			}
		}
	}
	return
}

//func ItemRun(workorderId uint, workNum string, nodemapRun *NodeMap, screen chan string) (err error) {
//	log := logger
//
//	log.Info("准备开始执行配置推送", zap.Any("workNum", workNum), zap.Any("ID", workorderId))
//	var workOrderItem []model.TWorkorderItem
//	err = global.GVA_DB.Where("t_workorder_id = ?", workorderId).Find(&workOrderItem).Error
//	if err != nil {
//		return
//	}
//
//	// workorderStatusMap := map[model.WorkorderStatus]int{}
//	// colorMap := map[global.CmdExecuteStatusColor]int{}
//	statusMap := map[model.WorkorderStatus]int{}
//	for _, intentObj := range workOrderItem {
//		log.Info("0. 工单项信息", zap.Any("Item", intentObj))
//		intentMap := intentObj.ToIntentParamMap()
//		params, err := policy.MakeIntentParams(intentMap)
//		if err != nil {
//			return err
//		}
//		intent := policy.NewIntent(params)
//		intent.WithTicketNumber(intentMap["ticketNumber"].(string))
//		intent.WithSubTicket(intentMap["subTicket"].(string))
//		log.Info("1. 生成Intent对象", zap.Any("Intent", intent))
//
//		// itemStatusMap := map[model.WorkorderStatus]int{}
//		// 调用MakeTemplates生成配置模板
//		log.Info("2. 调用MakeTemplates生成模板")
//		tp := nodemapRun.MakeTemplates(intent,
//			intentObj.Vrf,
//			intentObj.Area,
//			"",
//			"",
//			intentObj.TraverseOnly)
//
//		log.Info("3. MakeTemplates运行完毕，准备开始解析模板信息", zap.Any("Result", tp.Results))
//
//		deviceList, err := DeviceConfigListFromDb(global.GVA_DB)
//		if err != nil {
//			panic(err)
//		}
//		//
//		// 打印最新MakeTemplates结果
//		for _, item := range tp.Results.Items {
//			var existConfigObj model.TWorkorderConfig
//
//			configExistResult := global.GVA_DB.Model(&existConfigObj).Where(
//				&model.TWorkorderConfig{
//					// WorkNum:  workNum,
//					TWorkorderID: workorderId,
//					ItemId:       intentObj.ID,
//					DeviceIp:     item.Node.CmdIp(),
//				}).Find(&existConfigObj)
//			//
//			// if configExistResult.RowsAffected == 0 {
//			// panic("unknown error")
//			//
//			// }
//			if configExistResult.RowsAffected != 1 {
//				log.Error("获取Config对象失败", zap.Any("WorkNum", workNum),
//					zap.Any("WorkorderId", workorderId),
//					zap.Any("ItemId", intentObj.ID),
//					zap.Any("Ip", item.Node.CmdIp()),
//					// zap.Any("Color", color.String()),
//					// zap.Any("执行错误", err),
//					zap.Any("Error", configExistResult.Error))
//				panic("unknown error")
//			}
//
//			newGenCli := strings.Join(item.GenerateCli(), "\n")
//			// oldGenCli := existConfigObj.GeneratedCli
//
//			// if newGenCli != oldGenCli {
//			if len(item.GenerateCli()) == 0 {
//
//				if existConfigObj.GeneratedCli != "" {
//					log.Error("配置冲突", zap.Any("Config.GeneratedCli", existConfigObj.GeneratedCli))
//					existConfigObj.ConfigStatus = model.WORKORDER_STATUS_15_CONFLICT
//					statusMap[model.WORKORDER_STATUS_15_CONFLICT] = 1
//					intentObj.ItemStatus = model.WORKORDER_ITEM_STATUS_9_CONFLICT
//				} else {
//					existConfigObj.ConfigStatus = model.WORKORDER_STATUS_7_POLICY_EXIST
//					statusMap[model.WORKORDER_STATUS_7_POLICY_EXIST] = 1
//					intentObj.ItemStatus = model.WORKORDER_ITEM_STATUS_1_POLICY_EXIST
//				}
//
//				existConfigObj.RunCli = newGenCli
//
//				log.Info("更新CONFIG数据库", zap.Any("ConfigObj", existConfigObj))
//				tx := global.GVA_DB.Model(&model.TWorkorderConfig{}).Where("id = ?", existConfigObj.ID).Updates(map[string]interface{}{
//					"run_cli":       newGenCli,
//					"config_status": existConfigObj.ConfigStatus,
//				})
//				// tx := global.GVA_DB.Save(&existConfigObj)
//				if tx.Error != nil {
//					panic(tx.Error)
//				}
//
//				log.Info("更新WorkItem", zap.Any("WorkItem", intentObj))
//				// tx = global.GVA_DB.Save(&intentObj)
//				tx = global.GVA_DB.Model(&model.TWorkorderItem{}).Where("id = ? ", intentObj.ID).
//					Update("item_status", intentObj.ItemStatus)
//
//				if tx.Error != nil {
//					panic(tx.Error)
//				}
//
//			} else {
//				// screen <- fmt.Sprintf("Time: %s, Node: %s, NodeIp: %s, Cli: %s\n", time.Now(), item.Node.Name(), item.Node.CmdIp(), item.GenerateCli())
//				log.Info("开始执行配置推送----->>>")
//				color, before, after, err := item.Execute(deviceList, nodemapRun.taskId, screen)
//				if err != nil {
//					panic(err)
//				}
//
//				// existConfigObj.RunCli = strings.Join(item.GenerateCli(), "\n")
//				existConfigObj.RunCli = newGenCli
//				existConfigObj.CmdStatus = color
//				existConfigObj.Before = before
//				existConfigObj.After = after
//
//				// colorMap[color] = 1
//
//				if color == global.RED {
//					intentObj.ItemStatus = model.WORKORDER_ITEM_STATUS_3_RUN_FAILED
//					existConfigObj.ConfigStatus = model.WORKORDER_STATUS_1_FAILED
//					statusMap[model.WORKORDER_STATUS_1_FAILED] = 1
//				} else if color == global.YELLOW {
//					intentObj.ItemStatus = model.WORKORDER_ITEM_STATUS_8_RUN_HAS_ERROR
//					existConfigObj.ConfigStatus = model.WORKORDER_STATUS_14_HAS_ERROR
//					statusMap[model.WORKORDER_STATUS_14_HAS_ERROR] = 1
//				} else if color == global.GREEN {
//					intentObj.ItemStatus = model.WORKORDER_ITEM_STATUS_4_RUN_OK
//					existConfigObj.ConfigStatus = model.WORKORDER_STATUS_2_SUCCESS
//					statusMap[model.WORKORDER_STATUS_2_SUCCESS] = 1
//				} else {
//					panic("unknown error")
//				}
//
//				log.Info("将执行结果保存到数据库", zap.Any("ConfigObj", existConfigObj))
//				tx := global.GVA_DB.Save(&existConfigObj)
//				if tx.Error != nil {
//					panic(tx.Error)
//				}
//
//				log.Info("更新WorkItem", zap.Any("WorkItem", intentObj))
//				// tx = global.GVA_DB.Save(&intentObj)
//
//				tx = global.GVA_DB.Model(&model.TWorkorderItem{}).Where("id = ? ", intentObj.ID).
//					Update("item_status", intentObj.ItemStatus)
//				if tx.Error != nil {
//					panic(tx.Error)
//				}
//			}
//		}
//	}
//
//	var tx *gorm.DB
//
//	log.Info("更新工单TWorkorder", zap.Any("WorkNum", workNum), zap.Any("WorkorderId", workorderId), zap.Any("StatusMap", statusMap))
//	if statusMap[model.WORKORDER_STATUS_1_FAILED] == 1 {
//		tx = global.GVA_DB.Model(&model.TWorkorder{}).Where("id = ? ", workorderId).
//			Update("workorder_status", model.WORKORDER_STATUS_1_FAILED)
//	} else if statusMap[model.WORKORDER_STATUS_15_CONFLICT] == 1 {
//		tx = global.GVA_DB.Model(&model.TWorkorder{}).Where("id = ? ", workorderId).
//			Update("workorder_status", model.WORKORDER_STATUS_15_CONFLICT)
//	} else if statusMap[model.WORKORDER_STATUS_14_HAS_ERROR] == 1 {
//		tx = global.GVA_DB.Model(&model.TWorkorder{}).Where("id = ? ", workorderId).
//			Update("workorder_status", model.WORKORDER_STATUS_14_HAS_ERROR)
//	} else if statusMap[model.WORKORDER_STATUS_2_SUCCESS] == 1 {
//		tx = global.GVA_DB.Model(&model.TWorkorder{}).Where("id = ? ", workorderId).
//			Update("workorder_status", model.WORKORDER_STATUS_2_SUCCESS)
//	} else if statusMap[model.WORKORDER_STATUS_15_CONFLICT] == 1 {
//		tx = global.GVA_DB.Model(&model.TWorkorder{}).Where("id = ? ", workorderId).
//			Update("workorder_status", model.WORKORDER_STATUS_15_CONFLICT)
//	} else {
//		panic("unknown error")
//	}
//
//	if tx.Error != nil {
//		panic(tx.Error)
//	}
//
//	// log.Info("更新工单TWorkorder", zap.Any("WorkNum", workNum), zap.Any("ColorMap", colorMap))
//	// if colorMap[global.RED] == 1 {
//	// tx := global.GVA_DB.Model(&model.TWorkorder{}).Where("work_num = ? ", workNum).
//	// Update("workorder_status", model.WORKORDER_STATUS_1_FAILED)
//	// if tx.Error != nil {
//	// panic(err)
//	// }
//	// } else if colorMap[global.YELLOW] == 1 {
//	// tx := global.GVA_DB.Model(&model.TWorkorder{}).Where("work_num = ? ", workNum).
//	// Update("workorder_status", model.WORKORDER_STATUS_14_HAS_ERROR)
//	// if tx.Error != nil {
//	// panic(err)
//	// }
//	// } else if colorMap[global.GREEN] == 1 {
//	// tx := global.GVA_DB.Model(&model.TWorkorder{}).Where("work_num = ? ", workNum).
//	// Update("workorder_status", model.WORKORDER_STATUS_2_SUCCESS)
//	// if tx.Error != nil {
//	// panic(err)
//	// }
//	// } else {
//	// panic("unknown error")
//	//
//	// }
//
//	return nil
//}

//func ItemRun2(workNum string, nodemapRun *NodeMap) (err error) {
//	var workOrderItem []model.TWorkorderItem
//	err = global.GVA_DB.Where("work_num = ?", workNum).Find(&workOrderItem).Error
//	if err != nil {
//		return
//	}
//	var intentMap map[string]interface{}
//	// allItemStatus := []string{}
//	allItemCmdExecuteStatus := []global.CmdExecuteStatusColor{}
//	for _, intentObj := range workOrderItem {
//		global.GVA_DB.Model(&model.TWorkorder{}).Where("work_num = ? ", workNum).Updates(map[string]interface{}{"workorder_status": model.WORKORDER_STATUS_5_RUNNING, "execute_tiem": time.Now()})
//		im := IntentMap{
//			Src:          intentObj.Src,
//			Dst:          intentObj.Dst,
//			Protocol:     intentObj.Protocol,
//			Dport:        intentObj.Dport,
//			Vrf:          intentObj.Vrf,
//			RealIp:       intentObj.RealIp,
//			RealPort:     intentObj.RealPort,
//			Area:         intentObj.Area,
//			Snat:         intentObj.Snat,
//			Gw6:          "",
//			TicketNumber: intentObj.WorkNum,
//			SubTicket:    intentObj.SubTicket,
//			TraverseOnly: intentObj.TraverseOnly,
//			ItemId:       intentObj.ID,
//		}
//		fmt.Println("+++11", intentObj.Src, intentObj.Type)
//		resByre, _ := json.Marshal(im)
//		_ = json.Unmarshal(resByre, &intentMap)
//
//		fmt.Println(intentMap)
//		params, err := policy.MakeIntentParams(intentMap)
//		if err != nil {
//			panic(err)
//		}
//		intent := policy.NewIntent(params)
//		intent.WithTicketNumber(intentMap["ticketNumber"].(string))
//		intent.WithSubTicket(intentMap["subTicket"].(string))
//		//if nodemapRun != nil {
//		tp := nodemapRun.MakeTemplates(intent,
//			intentMap["vrf"].(string),
//			intentMap["area"].(string),
//			"",
//			"",
//			intentMap["traverseOnly"].(bool))
//
//		deviceList, err := DeviceConfigListFromDb(global.GVA_DB)
//		if err != nil {
//			panic(err)
//		}
//		//
//		// 打印最新MakeTemplates结果
//		for _, item := range tp.Results.Items {
//			for it := item.StepProcess.Iterator(); it.HasNext(); {
//				_, step := it.Next()
//
//				byteS, _ := json.MarshalIndent(step, "", "  ")
//				fmt.Println(string(byteS))
//			}
//		}
//
//		result, deviceStatusList := ExecuteItem(tp.Results, deviceList, intentObj.ID, nodemapRun.taskId)
//		fmt.Println("++++", deviceStatusList)
//		// resultStatus := "执行成功"
//		resultStatus := global.GREEN
//		msg := ""
//		for _, e := range result {
//			itemId := int(intentObj.ID)
//			var work_config model.TWorkorderConfig
//			work_result := global.GVA_DB.Where("item_id=? and device_ip=?", intentObj.ID, e.device).First(&work_config)
//			if work_result.Error == nil {
//				config_id := int(work_config.ID)
//				fmt.Println("+++config", config_id)
//				global.GVA_DB.Create(&model.TWorkorderitemResult{
//					Status:             e.status,
//					Msg:                e.msg,
//					Cli:                e.cli,
//					TWorkorderItemID:   &itemId,
//					TWorkorderConfigID: &config_id,
//					WorkNum:            workNum,
//					Name:               e.device,
//				})
//				if e.status < resultStatus {
//					// resultStatus = "执行失败"
//					resultStatus = e.status
//					msg = e.msg
//				}
//
//			} else {
//				fmt.Println("TWorkorderConfig find null", work_result.Error)
//				fmt.Println("======", intentObj.ID, e.device)
//				panic(work_result.Error)
//			}
//		}
//		if len(result) > 0 {
//			var idStatus model.WorkorderItemStatus
//			var configStatus model.WorkorderStatus
//			// if resultStatus == "执行失败" {
//			if resultStatus == global.RED {
//				idStatus = model.WORKORDER_ITEM_STATUS_3_RUN_FAILED
//				allItemCmdExecuteStatus = append(allItemCmdExecuteStatus, resultStatus)
//				configStatus = model.WORKORDER_STATUS_1_FAILED
//				// } else if resultStatus == "执行成功" {
//			} else if resultStatus == global.GREEN {
//				idStatus = model.WORKORDER_ITEM_STATUS_4_RUN_OK
//				allItemCmdExecuteStatus = append(allItemCmdExecuteStatus, resultStatus)
//				configStatus = model.WORKORDER_STATUS_2_SUCCESS
//			} else if resultStatus == global.YELLOW {
//				idStatus = model.WORKORDER_ITEM_STATUS_8_RUN_HAS_ERROR
//				allItemCmdExecuteStatus = append(allItemCmdExecuteStatus, resultStatus)
//				configStatus = model.WORKORDER_STATUS_14_HAS_ERROR
//			} else {
//				panic("unknown error")
//			}
//
//			global.GVA_DB.Model(&model.TWorkorderConfig{}).Where("item_id = ? and work_num = ?", intentObj.ID, workNum).Updates(model.TWorkorderConfig{
//				CmdStatus:    resultStatus,
//				ErrInfo:      msg,
//				ConfigStatus: configStatus,
//			})
//			global.GVA_DB.Model(&model.TWorkorderItem{}).Where("id = ? ", intentObj.ID).Update("item_status", idStatus)
//		}
//	}
//
//	status := global.GREEN
//
//	for _, s := range allItemCmdExecuteStatus {
//		if s < status {
//			status = s
//		}
//	}
//
//	if len(allItemCmdExecuteStatus) > 0 {
//		if status == global.RED {
//			global.GVA_DB.Model(&model.TWorkorder{}).Where("work_num = ? ", workNum).Updates(map[string]interface{}{"workorder_status": model.WORKORDER_STATUS_1_FAILED, "EXECUTE_END_TIME": time.Now().Format("2006-01-02 15:04:05")})
//		} else if status == global.YELLOW {
//			global.GVA_DB.Model(&model.TWorkorder{}).Where("work_num = ? ", workNum).Updates(map[string]interface{}{"workorder_status": model.WORKORDER_STATUS_14_HAS_ERROR, "EXECUTE_END_TIME": time.Now().Format("2006-01-02 15:04:05")})
//		} else if status == global.GREEN {
//			global.GVA_DB.Model(&model.TWorkorder{}).Where("work_num = ? ", workNum).Updates(map[string]interface{}{"workorder_status": model.WORKORDER_STATUS_2_SUCCESS, "EXECUTE_END_TIME": time.Now().Format("2006-01-02 15:04:05")})
//		} else {
//			panic("unknown error")
//		}
//	}
//	return nil
//}

func ReadLogData() {
	fileName := "/Users/Pjt/Library/Mobile Documents/com~apple~CloudDocs/Go项目/probemanager/server/nodemap/log/2021-07-19.log"
	t, _ := tail.TailFile(fileName, tail.Config{Follow: true})
	for line := range t.Lines {
		fmt.Println(line.Text)
	}
}

//func NodeRun(workorderId uint, workNum string, nodemapRun *NodeMap) (err error) {
//	log := logger
//
//	log.Info("准备开始生产配置模板", zap.Any("workNum", workNum), zap.Any("ID", workorderId))
//	var workOrderItem []model.TWorkorderItem
//	err = global.GVA_DB.Where("t_workorder_id = ?", workorderId).Find(&workOrderItem).Error
//	if err != nil {
//		return
//	}
//	workorderStatusMap := map[model.WorkorderStatus]int{}
//	for _, intentObj := range workOrderItem {
//		log.Info("0. 工单项信息", zap.Any("Item", intentObj))
//		intentMap := intentObj.ToIntentParamMap()
//		params, err := policy.MakeIntentParams(intentMap)
//		if err != nil {
//			return err
//		}
//		intent := policy.NewIntent(params)
//		intent.WithTicketNumber(intentMap["ticketNumber"].(string))
//		intent.WithSubTicket(intentMap["subTicket"].(string))
//		log.Info("1. 生成Intent对象", zap.Any("Intent", intent))
//
//		itemStatusMap := map[model.WorkorderStatus]int{}
//		// 调用MakeTemplates生成配置模板
//		log.Info("2. 调用MakeTemplates生成模板")
//		tp := nodemapRun.MakeTemplates(intent,
//			intentObj.Vrf,
//			intentObj.Area,
//			"",
//			"",
//			intentObj.TraverseOnly)
//
//		log.Info("3. MakeTemplates运行完毕，准备开始i解析模板信息", zap.Any("Result", tp.Results))
//
//		configStatusMap := map[model.WorkorderStatus]int{}
//		for _, node := range tp.Results.NodeList() {
//			var ipam_ipaddress model.IpamIpaddress
//			ipResult := global.GVA_DB.Where("address = ?", node.CmdIp()).First(&ipam_ipaddress)
//			var ipv4ID *int
//			if ipResult.RowsAffected > 0 {
//				ipid := int(ipam_ipaddress.ID)
//				ipv4ID = &ipid
//			} else {
//				panic("NodeRun 未找到 ip")
//			}
//			dev := model.DcimDevice{
//				Name: node.Name(),
//				//SystemIp:   node.CmdIp(),
//				PrimaryIp4ID: ipv4ID,
//			}
//
//			devResult := global.GVA_DB.Preload("DcimPlatform").Find(&dev)
//			if devResult.RowsAffected != 1 {
//				fmt.Println(devResult)
//				panic("设备IP和名称必须唯一的选中一台设备")
//			}
//
//			matchedCli, generateCli := tp.Results.GetTraverseResult(node.CmdIp())
//			log.Info("4. 模板信息", zap.Any("Node", node.Name()), zap.Any("NodeIp", node.CmdIp()), zap.Any("Matched", matchedCli), zap.Any("Generate", generateCli))
//
//			var existConfigObj model.TWorkorderConfig
//
//			configExistResult := global.GVA_DB.Model(&model.TWorkorderConfig{}).Where(
//				&model.TWorkorderConfig{
//					// WorkNum:  workNum,
//					TWorkorderID: workorderId,
//					ItemId:       intentObj.ID,
//					DeviceIp:     node.CmdIp(),
//				}).Find(&existConfigObj)
//
//			configStatus := tools.Conditional(len(generateCli) == 0, model.WORKORDER_STATUS_7_POLICY_EXIST, model.WORKORDER_STATUS_3_PENDING_APPROVAL).(model.WorkorderStatus)
//			configObj := model.TWorkorderConfig{
//				ItemId:           intentObj.ID, // 工作项的ID
//				TWorkorderItemID: intentObj.ID,
//				Uuid:             uuid.Must(uuid.NewV4()).String(),
//				//Type:             dev.Mode,
//				Type:         dev.Platform(),
//				ConfigStatus: configStatus,
//				WorkNum:      workNum,
//				TWorkorderID: workorderId,
//				// TWorkorderID:     intentObj.TWorkorderID,
//				DeviceName:   node.Name(),
//				DeviceIp:     node.CmdIp(),
//				DevTables:    &dev,
//				MatchedCli:   strings.Join(matchedCli, "\n"),
//				GeneratedCli: strings.Join(generateCli, "\n"),
//			}
//			if configExistResult.RowsAffected == 0 {
//				log.Info("5. 将Config信息入库", zap.Any("Config", configObj))
//				tx := global.GVA_DB.Create(&configObj)
//				if tx.Error != nil {
//					panic(tx.Error)
//				}
//			} else {
//				existConfigObj.MatchedCli = strings.Join(matchedCli, "\n")
//				existConfigObj.GeneratedCli = strings.Join(generateCli, "\n")
//				existConfigObj.ConfigStatus = configStatus
//				log.Info("6. 更新已有Config信息", zap.Any("Config", existConfigObj))
//				tx := global.GVA_DB.Save(&existConfigObj)
//
//				if tx.Error != nil {
//					panic(tx.Error)
//				}
//			}
//
//			configStatusMap[configStatus] = 1
//			itemStatusMap[configStatus] = 1
//			workorderStatusMap[configStatus] = 1
//		}
//
//		log.Info("7. 更新Item状态信息", zap.Any("ItemStatusMap", itemStatusMap))
//		if len(itemStatusMap) > 0 {
//			if itemStatusMap[model.WORKORDER_STATUS_3_PENDING_APPROVAL] == 1 {
//				tx := global.GVA_DB.Model(&model.TWorkorderItem{}).Where("id = ? ", int(intentObj.ID)).Update("item_status", model.WORKORDER_ITEM_STATUS_7_PENDING_APPROVAL)
//				if tx.Error != nil {
//					panic(tx.Error)
//				}
//			} else if itemStatusMap[model.WORKORDER_STATUS_7_POLICY_EXIST] == 1 {
//				tx := global.GVA_DB.Model(&model.TWorkorderItem{}).Where("id = ? ", int(intentObj.ID)).Update("item_status", model.WORKORDER_ITEM_STATUS_1_POLICY_EXIST)
//				if tx.Error != nil {
//					panic(tx.Error)
//				}
//			} else {
//				panic("unknown error")
//			}
//		}
//
//	}
//
//	log.Info("更新WorkOrder状态信息", zap.Any("WorkorderStatusMap", workorderStatusMap))
//	if len(workorderStatusMap) > 0 {
//		if workorderStatusMap[model.WORKORDER_STATUS_3_PENDING_APPROVAL] == 1 {
//			tx := global.GVA_DB.Model(&model.TWorkorder{}).Where("id = ? ", workorderId).Update("workorder_status", model.WORKORDER_STATUS_3_PENDING_APPROVAL)
//			if tx.Error != nil {
//				panic(tx.Error)
//			}
//		} else if workorderStatusMap[model.WORKORDER_STATUS_7_POLICY_EXIST] == 1 {
//			tx := global.GVA_DB.Model(&model.TWorkorder{}).Where("id = ? ", workorderId).Update("workorder_status", model.WORKORDER_STATUS_7_POLICY_EXIST)
//			if tx.Error != nil {
//				panic(tx.Error)
//			}
//		} else {
//			panic("unknown error")
//		}
//	} else {
//		tx := global.GVA_DB.Model(&model.TWorkorder{}).Where("id = ? ", workorderId).Update("workorder_status", model.WORKORDER_STATUS_10_INIT_FAILED)
//
//		if tx.Error != nil {
//			panic(tx.Error)
//		}
//	}
//
//	return nil
//}

func JsonToMap(jsonStr string) (map[string]string, error) {
	m := make(map[string]string)
	err := json.Unmarshal([]byte(jsonStr), &m)
	if err != nil {
		fmt.Printf("Unmarshal with error: %+v\n", err)
		return nil, err
	}

	for k, v := range m {
		fmt.Printf("%v: %v\n", k, v)
	}

	return m, nil
}

//
// type WorkorderItemFieldValidator struct{}
//
// func (wv *WorkorderItemFieldValidator) Validate(data map[string]interface{}) validator.Result {
// }
