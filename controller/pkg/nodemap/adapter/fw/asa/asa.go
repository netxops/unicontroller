package asa

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	ASA "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/asa"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"

	//"github.com/netxops/unify/global"
	//"github.com/netxops/unify/model"

	"strings"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"

	"github.com/gofrs/uuid"
)

type ASAAdapter struct {
	Type       api.AdapterType
	DeviceType terminalmode.DeviceType
	info       *session.DeviceBaseInfo
	//Task        *model.ExtractTask
	// DevTablesID *uint
	// DumpDb      bool
	CliCmdList *command.CliCmdList
}

func NewASAAdapter(info *session.DeviceBaseInfo, config string) *ASAAdapter {
	return &ASAAdapter{
		Type:       tools.ConditionalT(info == nil || info.Host == "", api.StringAdapter, api.LiveAdapter),
		DeviceType: terminalmode.ASA,
		info:       info,
	}
}

func (bia *ASAAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	cmdList := command.NewCliCmdList(bia.info.Host, force)

	cmdList.Add("sh ver", "sh_ver", 2, force)

	cli := session.NewCliSession(bia.info)
	err := cli.BatchRun(cmdList, true)
	if err != nil {
		return nil, err
	}

	dataCache, err := cmdList.Get("sh_ver")
	if err != nil {
		return nil, err
	}

	result, err := text.GetFieldByRegex(`Version\s+(?P<ver>\S+)`, string(dataCache.Data), []string{"ver"})
	if err != nil {
		return nil, err
	}
	version := result["ver"]

	result, err = text.GetFieldByRegex(`\n\s?(?P<hostname>\S+)\s+up(time)?\s+`, string(dataCache.Data), []string{"hostname"})
	if err != nil {
		return nil, err
	}
	hostname := result["ver"]

	result, err = text.GetFieldByRegex(`Serial Number:\s+(?P<sn>\S+)`, string(dataCache.Data), []string{"sn"})
	// if err != nil {
	// panic(err)
	// }
	serial := result["sn"]

	result, err = text.GetFieldByRegex(`Hardware:\s+(?P<model>\S+)`, string(dataCache.Data), []string{"model"})
	// if err != nil {
	// panic(err)
	// }
	md := result["model"]

	info := &device.DeviceBaseInfo{
		Hostname: hostname,
		Version:  version,
		Model:    md,
		SN:       serial,
	}

	return info, nil
}

func (adapter *ASAAdapter) TaskId() uint {
	//return adapter.Task.ID
	return 1
}

func (adapter *ASAAdapter) RunCmdListAndSave(cl *command.CliCmdList) {
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
	//	global.GVA_LOG.Info("dump data to db", zap.Any("cmd", cmd.Cmd()), zap.Any("key", cmd.Key()))
	//}
}

// func (adapter *ASAAdapter) get(key string) string {
//db := global.GVA_DB
//entity := model.ConfigExtractEntity{}
//db.Where("extract_task_id = ?", adapter.Task.ID).Where("cmd_key = ?", key).Find(&entity)
//
//return entity.Data
// return ""
// }

func (adapter *ASAAdapter) Prepare(force bool) *command.CliCmdList {
	// cli := session.NewCliSession(adapter.Info)

	cmdList := command.NewCliCmdList(adapter.info.Host, force)
	cmdList.Add("sh run", "sh_run", 10, force)
	cmdList.Add("sh run interface", "sh_run_interface", 5, force)
	cmdList.Add("sh interface", "sh_int", 2, force)
	cmdList.Add("sh ipv6 interface", "sh_ipv6_int", 2, force)
	cmdList.Add("sh route", "sh_ipv4", 2, force)
	cmdList.Add("sh ipv6 route", "sh_ipv6", 2, force)
	cmdList.Add("sh ver", "sh_ver", 2, force)
	cmdList.Add("sh access-list", "sh_acl", 2, force)
	adapter.RunCmdListAndSave(cmdList)
	return cmdList
}

func (adapter *ASAAdapter) GetConfig(force bool) interface{} {

	// shrunText := adapter.get("sh_run")
	// return shrunText
	//cmdList := adapter.Prepare(force)
	cmdList := adapter.CliCmdList
	cd, err := cmdList.Get("sh_run")
	if err != nil {
		panic(err)
	}
	shrunText := string(cd.Data)

	return shrunText
}

func (adapter *ASAAdapter) PortList(force bool) []api.Port {
	adapter.Prepare(force)
	//cmdList := adapter.Prepare(force)
	cmdList := adapter.CliCmdList

	cd, err := cmdList.Get("sh_run_interface")
	if err != nil {
		panic(err)
	}
	shruninterfaceText := string(cd.Data)
	// shruninterfaceText := adapter.get("sh_run_interface")

	cd, err = cmdList.Get("sh_int")
	if err != nil {
		panic(err)
	}
	shportText := string(cd.Data)
	// shportText := adapter.get("sh_int")

	cd, err = cmdList.Get("sh_ipv6_int")
	if err != nil {
		panic(err)
	}
	shipv6Text := string(cd.Data)
	// shipv6Text := adapter.get("sh_ipv6_int")

	cd, err = cmdList.Get("sh_run")
	if err != nil {
		panic(err)
	}
	shrunText := string(cd.Data)
	// shrunText := adapter.get("sh_run")

	portList := adapter.parseShowPort(shportText)
	adapter.parseIpv6Interface(shipv6Text, portList)
	adapter.parseAccessGroup(shrunText, portList)
	adapter.parseLevel(shruninterfaceText, portList)

	return portList

}

// func (adapter *ASAAdapter) parseIpv4Interface(shportText string) []*node.Port {
//
// }
func (adapter *ASAAdapter) parseShowPort(shportText string) []api.Port {
	// portlistMap := map[string]map[string][]string{}
	var portList []api.Port

	shportRegexMap := map[string]string{
		"regex": `Interface (?P<interface>\S+) \"(?P<nameif>\S+)?\",.*?IP address ((unassigned)|((?P<ip>\S+), subnet mask (?P<mask>\S+)))`,
		"name":  "shport",
		"flags": "s",
		"pcre":  "true",
	}

	sections := text.IndentSection(shportText)

	shportSplitter, err := text.NewSplitterFromMap(shportRegexMap)
	if err != nil {
		panic(err)
	}

	for sectionIt := sections.Iterator(); sectionIt.HasNext(); {
		_, _, sectionMap := sectionIt.Next()
		shportResult, err := shportSplitter.Input(sectionMap["section"])
		if err != nil {
			panic(err)
		}

		// 因为每个sh interface的section，只会有一个ip地址，
		// 所以将解析ip地址的代码放到循环当中，也不会有问题

		ipMap := map[network.IPFamily][]string{}
		ipMap[network.IPv4] = []string{}
		ipMap[network.IPv6] = []string{}
		var portName, nameifName string
		for it := shportResult.Iterator(); it.HasNext(); {
			_, _, portMap := it.Next()
			portName = portMap["interface"]
			nameifName = portMap["nameif"]
			if portMap["ip"] != "" {
				net, err := network.ParseIPNet(portMap["ip"] + "/" + portMap["mask"])
				if err != nil {
					panic(err)
				}

				ip := fmt.Sprintf("%s/%d", net.IP.String(), net.Prefix())
				ipMap[network.IPv4] = append(ipMap[network.IPv4], ip)
			}
		}

		if len(ipMap[network.IPv4]) > 0 {
			port := ASA.NewASAPort(nameifName, "", ipMap, []api.Member{})
			port.WithAliasName(portName)
			port.WithVrf(enum.DefaultVrf)
			port.WithMainIpv4(ipMap[network.IPv4][0])
			portList = append(portList, port)
		}
	}

	return portList
}

func (adapter *ASAAdapter) parseAccessGroup(shrunText string, portList []api.Port) {
	accessgroupRegexMap := map[string]string{
		"regex": `access-group (?P<acl_name>\S+) (?P<direction>in|out) interface (?P<nameif>\S+)`,
		"name":  "acl",
		"flags": "m",
	}

	accessgroupSplitter, err := text.NewSplitterFromMap(accessgroupRegexMap)
	if err != nil {
		panic(err)
	}

	accessgroupResult, err := accessgroupSplitter.Input(shrunText)
	if err != nil {
		panic(err)
	}

	for it := accessgroupResult.Iterator(); it.HasNext(); {
		_, _, accessgroupMap := it.Next()
		for _, port := range portList {
			if port.HitByName(accessgroupMap["nameif"]) {
				if accessgroupMap["direction"] == "in" {
					port.(*ASA.ASAPort).WithInAcl(accessgroupMap["acl_name"])
				} else {
					port.(*ASA.ASAPort).WithOutAcl(accessgroupMap["acl_name"])
				}
			}
		}
	}
}

func (adapter *ASAAdapter) parseLevel(shrunportText string, portList []api.Port) {
	sections := text.IndentSection(shrunportText)

	for it := sections.Iterator(); it.HasNext(); {
		_, _, sectionMap := it.Next()

		for _, port := range portList {
			p := fmt.Sprintf("nameif %s", port.Name())
			if strings.Index(sectionMap["section"], p) > -1 {
				regexMap := map[string]string{
					"regex": `security-level (?P<level>\S+)`,
					"name":  "level",
					"flags": "m",
				}

				levelResult, err := text.SplitterProcessOneTime(regexMap, sectionMap["section"])
				if err != nil {
					panic(err)
				}
				result, ok := levelResult.One()
				if ok {
					port.(*ASA.ASAPort).WithLevel(result["level"])
				}

			}
		}
	}
}

func (adapter *ASAAdapter) parseIpv6Interface(shipv6Text string, portList []api.Port) {
	if strings.Index(shipv6Text, "link-local") == -1 {
		return
	}

	sections := text.IndentSection(shipv6Text)

	shipv6RegexMap := map[string]string{
		"regex": `(?P<nameif>\S+) is \S+,.*?link-local address is (?P<local>[a-f\d:]+)\s.*?(?P<ip>[a-f\d:]+), subnet is (?P<subnet>[a-f\d:]+)/(?P<prefix>\d+)`,
		"name":  "shipv6",
		"flags": "s",
		"pcre":  "true",
	}

	shipv6Splitter, err := text.NewSplitterFromMap(shipv6RegexMap)
	if err != nil {
		panic(err)
	}

	for sectionIt := sections.Iterator(); sectionIt.HasNext(); {
		_, _, sectionMap := sectionIt.Next()

		shipv6Result, err := shipv6Splitter.Input(sectionMap["section"])
		if err != nil {
			panic(err)
		}
		// fmt.Println(shipv6Result)

		for it := shipv6Result.Iterator(); it.HasNext(); {
			_, _, ipv6Map := it.Next()

			for _, port := range portList {
				if ipv6Map["nameif"] == port.Name() {
					ipv6 := ipv6Map["ip"] + "/" + ipv6Map["prefix"]
					ipv6Local := ipv6Map["local"] + "/10"
					if port.(*ASA.ASAPort).MainIpv6() == "" {
						port.(*ASA.ASAPort).WithMainIpv6(ipv6)
					}
					port.AddIpv6(ipv6)
					port.AddIpv6(ipv6Local)
				}
			}
		}

	}

}

func (adapter *ASAAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {

	cmdList := adapter.CliCmdList
	//
	cd, err := cmdList.Get("sh_ipv4")
	if err != nil {
		panic(err)
	}
	shipv4Txt := string(cd.Data)
	// shipv4Txt := adapter.get("sh_ipv4")

	cd, err = cmdList.Get("sh_ipv6")
	if err != nil {
		panic(err)
	}
	shipv6Txt := string(cd.Data)
	// shipv6Txt := adapter.get("sh_ipv6")

	ipv4routeTable := adapter.parseIpv4Route(shipv4Txt)
	fmt.Println("ipv4routeTable  ---------- ", ipv4routeTable.String())
	fmt.Println("======shipv6Txt========", shipv6Txt)
	ipv6routeTable := adapter.parseIpv6Route(shipv6Txt)
	ipv4TableMap = map[string]*network.AddressTable{
		enum.DefaultVrf: ipv4routeTable,
	}
	ipv6TableMap = map[string]*network.AddressTable{
		enum.DefaultVrf: ipv6routeTable,
	}

	return ipv4TableMap, ipv6TableMap

}

func (adapter *ASAAdapter) parseIpv4Route(shrouteText string) *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv4)

	sectionRegexMap := map[string]string{
		"regex": `(?P<all>(C|S|I|R|M|B|D|EX|O|IA|N1|N2|E1|E2|E|i|(L\d*)|ia|\*|U|o|P)\s*[^\n]+(via|directly)[^\n]+\n([ ]+\[\d+\/\d+\] via [^\n]+\n)*)`,
		"name":  "section",
		"flags": "s",
		"pcre":  "true",
	}

	routeRegexMap := map[string]string{
		"regex": `(?P<type>\S+)\s+(?P<net>[\d\.]+) (?P<mask>[\d\.]+)`,
		"name":  "route",
		"flags": "m",
		"pcre":  "true",
	}

	hopRegexMap := map[string]string{
		"regex": `(via (?P<nhop>[\d\.]+)|(?P<connected>connected))(, \S+)?, (?P<interface>\S+)`,
		"name":  "hop",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, shrouteText)
	if err != nil {
		return routeTable
	}
	for sectionIt := sectionResult.Iterator(); sectionIt.HasNext(); {
		_, _, sectionMap := sectionIt.Next()
		routeResult, err := text.SplitterProcessOneTime(routeRegexMap, sectionMap["all"])
		if err != nil {
			panic(err)
		}

		hopResult, err := text.SplitterProcessOneTime(hopRegexMap, sectionMap["all"])
		if err != nil {
			panic(err)
		}

		r, ok := routeResult.One()
		if !ok {
			panic("route result match failed")
		}
		net, err := network.ParseIPNet(r["net"] + "/" + r["mask"])

		nextHop := &network.NextHop{}
		for it := hopResult.Iterator(); it.HasNext(); {
			_, _, hopMap := it.Next()
			nextHop.AddHop(hopMap["interface"], hopMap["nhop"], hopMap["connected"] == "connected", false, nil)

		}
		err = routeTable.PushRoute(net, nextHop)
	}
	return routeTable
}

func (adapter *ASAAdapter) parseIpv6Route(shrouteText string) *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv6)

	routeRegexMap := map[string]string{
		"regex": `(?P<type>C|L|S|OI|OE[12]|ON[12]|O)\s+(?P<ipv6>\S+)\s+(?P<info>\S+)(?P<hops>(\s+via\s+[^,]+,\s+\S+)+)`,
		"name":  "section",
		"flags": "s",
		"pcre":  "true",
	}

	hopRegexMap := map[string]string{
		"regex": `(via (?P<nhop>[a-fA-F\d\.:]+)|(?P<connected>connected))(, \S+)?, (?P<interface>\S+)`,
		"name":  "hop",
		"flags": "m",
		"pcre":  "true",
	}

	routeResult, err := text.SplitterProcessOneTime(routeRegexMap, shrouteText)
	if err != nil {
		if err == text.ErrNoMatched {
			return routeTable
		} else {
			panic(err)
		}
	}
	for routeIt := routeResult.Iterator(); routeIt.HasNext(); {
		_, _, routeMap := routeIt.Next()
		hopResult, err := text.SplitterProcessOneTime(hopRegexMap, routeMap["hops"])
		if err != nil {
			panic(err)
		}

		net, err := network.ParseIPNet(routeMap["ipv6"])

		nextHop := &network.NextHop{}
		for it := hopResult.Iterator(); it.HasNext(); {
			_, _, hopMap := it.Next()
			connected := false
			if routeMap["type"] == "L" || routeMap["type"] == "C" {
				connected = true
			}
			nextHop.AddHop(hopMap["interface"], hopMap["nhop"], connected, false, nil)
		}
		err = routeTable.PushRoute(net, nextHop)
	}
	return routeTable
}

func (adapter *ASAAdapter) ParseName(force bool) string {
	//cmdList := adapter.Prepare(force)
	cmdList := adapter.CliCmdList

	cd, err := cmdList.Get("sh_ver")
	if err != nil {
		panic(err)
	}

	shverText := string(cd.Data)
	// shverText := adapter.get("sh_ver")

	nameRegexMap := map[string]string{
		"regex": `(?P<name>\S+) up `,
		"name":  "ver",
		"flags": "m",
	}
	//
	// nameSplitter, err := text.NewSplitterFromMap(nameRegexMap)
	// if err != nil {
	// panic(err)
	// }
	//
	// nameResult, err := nameSplitter.Input(shverText)
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
	//	result := global.GVA_DB.Where("system_ip = ?", adapter.info.Host).Where("name = ?", fields["name"]).Find(&dev)
	//	if result.Error != nil {
	//		panic(result.Error)
	//
	//	}
	//	// bia.Task.DevTablesID = dev.ID
	//	global.GVA_DB.Model(&model.ExtractTask{}).Where("id = ?", adapter.Task.ID).Update("dev_tables_id", dev.ID)
	//}
	return fields["name"]

}

// 批量执行，输入[]*command.CliCmdList，就是命令列表的列表
// 这就意味着需要多次登录网络设备执行
func (adapter *ASAAdapter) BatchRun(p interface{}) (interface{}, error) {
	cmds := p.([]interface{})
	var err error

	cliSession := session.NewCliSession(adapter.info)

	var mustStop bool
	for _, cmdList := range cmds {
		if !mustStop {
			for _, cmd := range cmdList.(*command.CliCmdList).Cmds {
				cmd.(*command.HttpCmd).Force = true
			}

			err = cliSession.BatchRun(cmdList.(*command.CliCmdList), true)
			if err != nil {
				return nil, err
			}
			for _, c := range cmdList.(*command.CliCmdList).Cmds {
				if c.Level() == command.MUST && !c.Ok() {
					// 如果关键命令执行出错，则停止后续命令的执行
					mustStop = true
				}
			}
		}
	}

	return p, err
}

// 为了避免多次登录设备执行命令，需要将所有待执行命令合并到一起执行
// 但是为了前端显示方便区分阶段性执行结果，又需要将执行结果按照输入时的顺序进行保存
func (adapter *ASAAdapter) BatchConfig(p ...interface{}) (interface{}, error) {

	info := adapter.info.BaseInfo

	base := terminal.BaseInfo{
		Host:     info.Host,
		Username: info.Username,
		Password: info.Password,
		AuthPass: info.AuthPass,
		Telnet:   info.Telnet,
	}

	exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.ASA, &base)
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

func (bia *ASAAdapter) AttachChannel(out chan string) bool {
	return false
}

func (bia *ASAAdapter) GetRawConfig(_ string, force bool) (any, error) {
	return bia.GetConfig(force), nil
}
