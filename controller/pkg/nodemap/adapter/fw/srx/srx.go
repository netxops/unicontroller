package srx

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	SRX "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/srx"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"

	"github.com/gofrs/uuid"
)

type SRXAdapter struct {
	Type       api.AdapterType
	DeviceType terminalmode.DeviceType
	info       *session.DeviceBaseInfo
	//Task        *model.ExtractTask
	// DevTablesID *uint
	// DumpDb      bool
	CliCmdList *command.CliCmdList
}

func NewSRXAdapter(info *session.DeviceBaseInfo, config string) *SRXAdapter {

	return &SRXAdapter{
		Type:       tools.ConditionalT(info == nil || info.Host == "", api.StringAdapter, api.LiveAdapter),
		DeviceType: terminalmode.SRX,
		info:       info,
	}

}

func (bia *SRXAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	cmdList := command.NewCliCmdList(bia.info.Host, force)
	cmdList.Add("show version", "sh_ver", 2, force)
	cmdList.Add("show chassis hardware", "sh_c_h", 2, force)

	cli := session.NewCliSession(bia.info)
	err := cli.BatchRun(cmdList, true)
	if err != nil {
		return nil, err
	}

	var data string
	dataCache, err := cmdList.Get("sh_ver")
	if err != nil {
		return nil, err
	}
	data = string(dataCache.Data)

	dataCache, err = cmdList.Get("sh_c_h")
	if err != nil {
		return nil, err
	}
	data = data + "\n" + string(dataCache.Data)

	result, err := text.GetFieldByRegex(`Release\s+\[(?P<ver>\S+)\]`, data, []string{"ver"})
	if err != nil {
		return nil, err
	}
	version := result["ver"]

	result, err = text.GetFieldByRegex(`Hostname:\s+(?P<hostname>\S+)`, string(dataCache.Data), []string{"hostname"})
	if err != nil {
		return nil, err
	}
	hostname := result["ver"]

	result, err = text.GetFieldByRegex(`Chassis\s+(?P<sn>\S+)`, string(dataCache.Data), []string{"sn"})
	serial := result["sn"]

	result, err = text.GetFieldByRegex(`Model:\s+(?P<model>\S+)`, string(dataCache.Data), []string{"model"})
	md := result["model"]

	info := &device.DeviceBaseInfo{
		Hostname: hostname,
		Version:  version,
		Model:    md,
		SN:       serial,
	}

	return info, nil
}

func (adapter *SRXAdapter) TaskId() uint {
	//return adapter.Task.ID
	return 1
}

func (adapter *SRXAdapter) RunCmdListAndSave(cl *command.CliCmdList) {
	adapter.CliCmdList = cl
	cli := session.NewCliSession(adapter.info)
	err := cli.BatchRun(cl, true)
	if err != nil {
		fmt.Println(err)
	}

	//for _, cmd := range cl.Cmds {
	//	enitiy := model.ConfigExtractEntity{
	//		ExtractTaskID: &adapter.Task.ID,
	//		Cmd:           cmd.Cmd(),
	//		CmdKey:        cmd.Key(),
	//		Timeout:       cmd.Timeout(),
	//		Data:          cmd.Msg(),
	//		Md5:           tools.Md5(cmd.Msg()),
	//		DevTablesID:   adapter.DevTablesID,
	//	}
	//
	//	result := global.GVA_DB.Save(&enitiy)
	//	if result.Error != nil {
	//		panic(result.Error)
	//	}
	//
	//	lines := strings.Split(cmd.Msg(), "\n")
	//	if len(lines) > 10 {
	//		fmt.Println(lines[len(lines)-10:])
	//	}
	//
	//	global.GVA_LOG.Info("dump data to db", zap.Any("cmd", cmd.Cmd()), zap.Any("key", cmd.Key()))
	//}
}

func (adapter *SRXAdapter) get(key string) string {
	//db := global.GVA_DB
	//entity := model.ConfigExtractEntity{}
	//db.Where("extract_task_id = ?", adapter.Task.ID).Where("cmd_key = ?", key).Find(&entity)
	//
	//return entity.Data
	data, err := adapter.CliCmdList.Get(key)
	if err != nil {
		panic(err)
	}
	return string(data.Data)
}

func (adapter *SRXAdapter) Prepare(force bool) *command.CliCmdList {
	// cli := session.NewCliSession(adapter.Info)

	cmdList := command.NewCliCmdList(adapter.info.Host, force)
	cmdList.Add("run show version", "sh_name", 2, force)
	cmdList.Add("show groups junos-defaults applications | display set", "sh_default", 3, force)
	cmdList.Add("run show configuration | display set", "sh_run", 4, force)
	cmdList.Add("run show configuration interface | display set", "sh_run_int", 4, force)
	cmdList.Add("run show interfaces brief", "sh_int", 4, force)
	cmdList.Add("run show route table inet.0", "sh_ipv4", 2, force)
	cmdList.Add("run show route table inet6.0", "sh_ipv6", 2, force)

	adapter.RunCmdListAndSave(cmdList)
	return cmdList
}

func (adapter *SRXAdapter) GetConfig(force bool) interface{} {
	// cmdList := adapter.Prepare(force)
	//
	// cd, err := cmdList.Get("sh_run")
	// if err != nil {
	// panic(err)
	// }
	// shrunText := string(cd.Data)
	shrunText := adapter.get("sh_run")
	// cd, err = cmdList.Get("sh_default")
	// if err != nil {
	// panic(err)
	// }
	// shrunText = shrunText + "\n" + string(cd.Data)
	shrunText = shrunText + "\n" + adapter.get("sh_default")

	return shrunText
}

func (adapter *SRXAdapter) PortList(force bool) []api.Port {
	adapter.Prepare(force)
	shruninterfaceText := adapter.get("sh_run_int")
	// shrunText := adapter.GetConfig(force).(string)
	shrunText := adapter.get("sh_run")
	shintText := adapter.get("sh_int")
	portList := adapter.parseShowRunPort(shruninterfaceText)
	adapter.parseZone(shrunText, portList)
	adapter.parseShowInterfaceBrief(shintText, portList)

	return portList

}

func (adapter *SRXAdapter) parseShowRunPort(shruninterfaceText string) []api.Port {
	portList := []api.Port{}

	shrunportRegexMap := map[string]string{
		"regex": `interfaces\s+(?P<name>\S+)\s[a-zA-Z]+\s(?P<name2>\d+)\sfamily\s+(?P<type>inet\d?)\saddress\s(?P<address>\S+)`,
		"name":  "runport",
		"flags": "m",
		"pcre":  "true",
	}

	portResult, err := text.SplitterProcessOneTime(shrunportRegexMap, shruninterfaceText)
	if err != nil {
		panic(err)
	}

	portListMap := map[string]map[network.IPFamily][]string{}

	for it := portResult.Iterator(); it.HasNext(); {
		_, _, portMap := it.Next()
		portName := portMap["name"] + "." + portMap["name2"]
		if _, ok := portListMap[portName]; !ok {
			portListMap[portName] = map[network.IPFamily][]string{}
		}

		if portMap["address"] != "" {
			ip, err := network.ParseIPNet(portMap["address"])
			if err != nil {
				panic(err)
			}
			if ip.Type() == network.IPv4 {
				portListMap[portName][network.IPv4] = append(portListMap[portName][network.IPv4], portMap["address"])
			} else {
				portListMap[portName][network.IPv6] = append(portListMap[portName][network.IPv6], portMap["address"])
			}
		}
	}

	for name, ipList := range portListMap {
		// func NewSRXPort(name, tenant string, ip_list map[string][]string, members []*node.Member) *SRXPort {
		port := SRX.NewSRXPort(name, "", ipList, []api.Member{})
		port.WithVrf(enum.DefaultVrf)
		portList = append(portList, port)
	}

	return portList
}

func (adapter *SRXAdapter) parseShowInterfaceBrief(shintText string, portList []api.Port) {
	sectionRegexMap := map[string]string{
		"regex": `(?P<all>Logical interface (?P<interface>\S+)\s(\n[ ]+[^\n]+)+)`,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	localipv6RegexMap := map[string]string{
		"regex": `\s+(?P<address>fe80::\S+)$`,
		"name":  "ipv6",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, shintText)
	if err != nil {
		panic(err)
	}

	for sectionIt := sectionResult.Iterator(); sectionIt.HasNext(); {
		_, _, sectionMap := sectionIt.Next()
		for _, port := range portList {
			if port.Name() == sectionMap["interface"] {
				localipv6Result, err := text.SplitterProcessOneTime(localipv6RegexMap, sectionMap["all"])
				if err != nil {
					panic(err)
				}
				if localipv6Result == nil {
					continue
				}

				for it := localipv6Result.Iterator(); it.HasNext(); {
					_, _, localMap := it.Next()
					port.AddIpv6(localMap["address"])
				}

			}
		}
	}
}

func (adapter *SRXAdapter) parseZone(shrunText string, portList []api.Port) {
	zoneRegexMap := map[string]string{
		"regex": `set security zones security-zone (?P<zone>\S+) interfaces (?P<name>\S+)[^\n]*`,
		"name":  "zone",
		"flags": "m",
		"pcre":  "true",
	}

	zoneResult, err := text.SplitterProcessOneTime(zoneRegexMap, shrunText)
	if err != nil {
		panic(err)
	}

	for it := zoneResult.Iterator(); it.HasNext(); {
		_, _, zoneMap := it.Next()
		for _, port := range portList {
			if port.Name() == zoneMap["name"] {
				port.(*SRX.SRXPort).WithZone(zoneMap["zone"])
				port.WithAliasName(zoneMap["zone"])
			}
		}
	}
}

func (adapter *SRXAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	// cmdList := adapter.Prepare(force)
	//
	// cd, err := cmdList.Get("sh_ipv4")
	// if err != nil {
	// panic(err)
	// }
	// shipv4Txt := string(cd.Data)
	shipv4Txt := adapter.get("sh_ipv4")
	//
	// cd, err = cmdList.Get("sh_ipv6")
	// if err != nil {
	// panic(err)
	// }
	// shipv6Txt := string(cd.Data)
	shipv6Txt := adapter.get("sh_ipv6")

	ipv4routeTable := adapter.parseIpv4Route(shipv4Txt)
	ipv6routeTable := adapter.parseIpv6Route(shipv6Txt)
	ipv4TableMap = map[string]*network.AddressTable{
		enum.DefaultVrf: ipv4routeTable,
	}
	ipv6TableMap = map[string]*network.AddressTable{
		enum.DefaultVrf: ipv6routeTable,
	}

	return ipv4TableMap, ipv6TableMap

}

func (adapter *SRXAdapter) parseIpv4Route(shipv4Text string) *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv4)

	sectionRegexMap := map[string]string{
		"regex": `(?<=\n)(?P<all>(\d+\.\d+\.\d+\.\d+\/\d+)\s+\*\[\S+\][^\n]+(\n\s+[^\n]+)+)`,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}
	//
	routeRegexMap := map[string]string{
		"regex": `(?P<all>^(?P<net>\d+\.\d+\.\d+\.\d+\/\d+)\s+\*\[(?P<type>\w+)\/(?P<distance>\d+)\][^\n]*?(,metric (?P<metric>\d+))?[^\n]+\n[^\n]+)`,
		"name":  "route",
		"flags": "m",
		"pcre":  "true",
	}

	hopRegexMap := map[string]string{
		"regex": `(?P<connected>Reject|Receive|MultiRecv)|((to (?P<nhop>\d+\.\d+\.\d+\.\d+) )?via (?P<interface>\S+))`,
		"name":  "hop",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, shipv4Text)
	if err != nil {
		panic(err)
	}

	for sectionIt := sectionResult.Iterator(); sectionIt.HasNext(); {
		_, _, sectionMap := sectionIt.Next()
		routeResult, err := text.SplitterProcessOneTime(routeRegexMap, sectionMap["all"])
		if err != nil {
			panic(err)
		}

		routeMap, ok := routeResult.One()
		if !ok {
			panic("route result is empty")
		}

		hopResult, err := text.SplitterProcessOneTime(hopRegexMap, routeMap["all"])
		if err != nil {
			panic(err)
		}

		nextHop := &network.NextHop{}
		for it := hopResult.Iterator(); it.HasNext(); {
			_, _, hopMap := it.Next()
			connected := false
			if hopMap["connected"] == "Reject" || hopMap["connected"] == "MultiRecv" || routeMap["type"] == "Local" {
			} else {
				if hopMap["connected"] == "Receive" {
					connected = true
				}
				if routeMap["type"] == "Direct" {
					connected = true
				}
				// func (nh *NextHop) AddHop(it string, ip string, connect, defaultGw bool, vs interface{}) (*Hop, error)
				nextHop.AddHop(hopMap["interface"], hopMap["nhop"], connected, false, nil)
			}
		}

		net, err := network.ParseIPNet(routeMap["net"])
		if nextHop.Count() > 0 {
			routeTable.PushRoute(net, nextHop)
		} else {
			fmt.Printf("ignore route: %+v\n", routeMap["all"])
		}

	}

	return routeTable

}

func (adapter *SRXAdapter) parseIpv6Route(shipv6Text string) *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv6)

	sectionRegexMap := map[string]string{
		"regex": `(?P<all>^([a-fA-F\d:]+\/\d+)\s*\*\[\S+\][^\n]+(\n\s+[^\n]+)+)`,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}
	//
	routeRegexMap := map[string]string{
		"regex": `^(?P<net>[a-fA-F\d:]+\/\d+)\s*\*\[(?P<type>\w+)\/`,
		"name":  "route",
		"flags": "m",
		"pcre":  "true",
	}

	hopRegexMap := map[string]string{
		"regex": `(?P<connected>Reject|Receive|MultiRecv)|((to (?P<nhop>[a-fA-F\d:]+) )?via (?P<interface>\S+))`,
		"name":  "hop",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, shipv6Text)
	if err != nil {
		panic(err)
	}

	for sectionIt := sectionResult.Iterator(); sectionIt.HasNext(); {
		_, _, sectionMap := sectionIt.Next()
		routeResult, err := text.SplitterProcessOneTime(routeRegexMap, sectionMap["all"])
		if err != nil {
			panic(err)
		}

		routeMap, ok := routeResult.One()
		if !ok {
			panic("route result is empty")
		}

		hopResult, err := text.SplitterProcessOneTime(hopRegexMap, sectionMap["all"])
		if err != nil {
			panic(err)
		}

		nextHop := &network.NextHop{}
		for it := hopResult.Iterator(); it.HasNext(); {
			_, _, hopMap := it.Next()
			connected := false
			if hopMap["connected"] == "Reject" || hopMap["connected"] == "MultiRecv" || routeMap["type"] == "Local" {
			} else {
				if hopMap["connected"] == "Receive" {
					connected = true
				}
				if routeMap["type"] == "Direct" {
					connected = true
				}
				// func (nh *NextHop) AddHop(it string, ip string, connect, defaultGw bool, vs interface{}) (*Hop, error)
				nextHop.AddHop(hopMap["interface"], hopMap["nhop"], connected, false, nil)
			}
		}

		net, err := network.ParseIPNet(routeMap["net"])
		if nextHop.Count() > 0 {
			routeTable.PushRoute(net, nextHop)
		} else {
			fmt.Printf("ignore route: %+v\n", routeMap["all"])
		}

	}

	return routeTable

}

func (adapter *SRXAdapter) ParseName(force bool) string {
	// cmdList := adapter.Prepare(force)
	//
	// cd, err := cmdList.Get("sh_name")
	// if err != nil {
	// panic(err)
	// }
	//
	// shverText := string(cd.Data)
	shverText := adapter.get("sh_name")
	nameRegexMap := map[string]string{
		"regex": `Hostname: (?P<name>\S+)`,
		"name":  "version",
		"flags": "m",
	}

	// nameResult, err := text.SplitterProcessOneTime(nameRegexMap, shverText)
	// if err != nil {
	// panic(err)
	// }
	//
	// for it := nameResult.Iterator(); it.HasNext(); {
	// _, _, nameMap := it.Next()
	// return nameMap["name"]
	// }
	//

	fields, err := text.GetFieldByRegex(nameRegexMap["regex"], shverText, []string{"name"})
	if err != nil {
		panic(err)
	}
	if fields["name"] == "" {
		panic(fmt.Errorf("ParseName failed, %s", shverText))
	}
	//if adapter.DumpDb {
	//	dev := model.DcimDevice{}
	//	//result := global.GVA_DB.Where("system_ip = ?", adapter.info.Host).Where("system_name = ?", fields["name"]).Find(&dev)
	//	var ipaddress model.IpamIpaddress
	//	ipResult := global.GVA_DB.Where("address = ?", adapter.info.Host).First(&ipaddress)
	//	if ipResult.RowsAffected > 0 {
	//		result := global.GVA_DB.Where("primary_ip4_id = ?", ipaddress.ID).Where("name = ?", fields["name"]).Find(&dev)
	//		if result.Error != nil {
	//			panic(result.Error)
	//
	//		}
	//		// bia.Task.DevTablesID = dev.ID
	//		global.GVA_DB.Model(&model.ExtractTask{}).Where("id = ?", adapter.Task.ID).Update("dev_tables_id", dev.ID)
	//	} else {
	//		fmt.Println("ParseName err not found,address :", adapter.info.Host)
	//	}
	//}
	return fields["name"]

	// return ""
}

func (adapter *SRXAdapter) BatchRun(p interface{}) (interface{}, error) {
	return 0, nil
}

// 为了避免多次登录设备执行命令，需要将所有待执行命令合并到一起执行
// 但是为了前端显示方便区分阶段性执行结果，又需要将执行结果按照输入时的顺序进行保存
func (adapter *SRXAdapter) BatchConfig(p ...interface{}) (interface{}, error) {

	info := adapter.info.BaseInfo

	base := terminal.BaseInfo{
		Host:     info.Host,
		Username: info.Username,
		Password: info.Password,
		AuthPass: info.AuthPass,
		Telnet:   info.Telnet,
	}

	exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.SRX, &base)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	cmdList := []command.Command{}

	// var hasError bool
	var err error

	// p为需要进行批量执行的命令主体
	for _, cll := range p {
		switch cll.(type) {
		case []interface{}:
			// cl其实是[]*CliCmdList
			for _, cl := range cll.([]interface{}) {
				for _, cmd := range cl.(*command.CliCmdList).Cmds {
					key := cmd.Key()
					if cmd.Key() == "" {
						key = strings.ReplaceAll(cmd.Cmd(), " ", "_")
					}
					exec.Add(cmd.Cmd(), "", 2, key, "")
					c := command.NewCliCmd(cmd.Cmd(), key, 2, true)
					c.WithLevel(command.MUST)
					cmdList = append(cmdList, c)
				}
			}
		case []string:
			for _, cmd := range cll.([]string) {
				key := strings.ReplaceAll(cmd, " ", "_")
				c := command.NewCliCmd(cmd, key, 2, true)
				c.WithLevel(command.MUST)
				exec.Add(cmd, "", 2, key, "")
				cmdList = append(cmdList, c)
			}
		default:
			panic("unsupoort data type")
		}
	}

	// 需要自动填充First和Last命令
	exec.Prepare(false)
	result := exec.Run(true)

	for _, cmd := range cmdList {
		ok, data := result.GetResult(cmd.Key())
		cmd.WithMsg(strings.Join(data, "\n"))
		if !ok {
			cmd.WithOk(false)
			err = fmt.Errorf("get result failed, key:%s", cmd.Key())
			// hasError = true
		} else {
			cmd.WithOk(true)
		}
	}

	firstCmdList := []command.Command{}
	for _, fc := range exec.DeviceMode.First_Chain {
		c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
		if fc.Status == terminalmode.CMD_COMPLETED {
			c.WithOk(true)
		}
		c.WithMsg(fc.Msg)
		c.WithLevel(command.OPTION)
		firstCmdList = append(firstCmdList, c)
	}

	lastCmdList := []command.Command{}
	for _, fc := range exec.DeviceMode.Last_Chain {
		c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
		if fc.Status == terminalmode.CMD_COMPLETED {
			c.WithOk(true)
		}
		c.WithMsg(fc.Msg)
		c.WithLevel(command.OPTION)
		lastCmdList = append(lastCmdList, c)
	}

	cliCmdList := command.NewCliCmdList(base.Host, true)
	for _, cmd := range cmdList {
		cliCmdList.AddCmd(cmd)
	}

	return cliCmdList, err

}

func (srx *SRXAdapter) AttachChannel(out chan string) bool {
	return false
}

func (srx *SRXAdapter) GetRawConfig(_ string, force bool) (any, error) {
	return srx.GetConfig(force), nil
}
