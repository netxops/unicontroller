package router

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminalmode"

	//"github.com/netxops/unify/global"
	//"github.com/netxops/unify/model"
	"strconv"
	"strings"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"
)

var _ api.Adapter = &BaseIosAdapter{}

type BaseIosAdapter struct {
	Type       api.AdapterType
	DeviceType terminalmode.DeviceType
	info       *session.DeviceBaseInfo
	CliCmdList *command.CliCmdList
}

func NewBaseIosAdapter(info *session.DeviceBaseInfo, config string) *BaseIosAdapter {
	return &BaseIosAdapter{
		Type:       tools.ConditionalT(info == nil || info.Host == "", api.StringAdapter, api.LiveAdapter),
		DeviceType: terminalmode.IOS,
		info:       info,
	}

}

// func (bia *BaseIosAdapter) WithDumpDb(dump bool) {
// 	bia.DumpDb = dump
// }

func (bia *BaseIosAdapter) TaskId() uint {
	//return bia.Task.ID
	return 0
}

// func (bia *BaseIosAdapter)NodeMapTaskId() uint {
//
// }

func (bia *BaseIosAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {

	cmdList := command.NewCliCmdList(bia.info.Host, force)
	cmdList.Add("sh ver", "sh_ver", 2, force)

	cli := session.NewCliSession(bia.info)
	err := cli.BatchRun(cmdList, true)
	if err != nil {
		return nil, err
	}

	cmd := cmdList.Cmd("sh_ver")
	data := cmd.Msg()
	// dataCache, err := cmdList.Get("sh_ver")
	// if err != nil {
	// return nil, err
	// }

	result, err := text.GetFieldByRegex(`Version\s+(?P<ver>\S+)`, data, []string{"ver"})
	if err != nil {
		return nil, err
	}
	version := result["ver"]

	result, err = text.GetFieldByRegex(`\n\s?(?P<hostname>\S+)\s+up(time)?\s+`, data, []string{"hostname"})
	if err != nil {
		return nil, err
	}
	hostname := result["hostname"]

	result, err = text.GetFieldByRegex(`Serial Number:\s+(?P<sn>\S+)`, data, []string{"sn"})
	// if err != nil {
	// panic(err)
	// }
	serial := result["sn"]

	result, err = text.GetFieldByRegex(`Hardware:\s+(?P<model>\S+)`, data, []string{"model"})
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
	fmt.Println("===================>", info)

	return info, nil
}

func (bia *BaseIosAdapter) RunCmdListAndSave(cl *command.CliCmdList) {
	if len(cl.Cmds) == 0 {
		return
	}
	bia.CliCmdList = cl
	cli := session.NewCliSession(bia.info)
	err := cli.BatchRun(cl, true)
	if err != nil {
		fmt.Println(err)
	}

	//if bia.DumpDb {
	//	for _, cmd := range cl.Cmds {
	//		enitiy := model.ConfigExtractEntity{
	//			ExtractTaskID: &bia.Task.ID,
	//			Cmd:           cmd.Cmd(),
	//			CmdKey:        cmd.Key(),
	//			Timeout:       cmd.Timeout(),
	//			Data:          cmd.Msg(),
	//			Md5:           tools.Md5(cmd.Msg()),
	//			DevTablesID:   bia.DevTablesID,
	//		}
	//
	//		result := global.GVA_DB.Save(&enitiy)
	//		if result.Error != nil {
	//			panic(result.Error)
	//		}
	//
	//		global.GVA_LOG.Info("dump data to db", zap.Any("cmd", cmd.Cmd()), zap.Any("key", cmd.Key()))
	//	}
	//}
}

func (bia *BaseIosAdapter) Prepare(force bool) *command.CliCmdList {
	cmdList := command.NewCliCmdList(bia.info.Host, force)

	//shRun, _ := cmdList.Get("sh_run")
	//shVer, _ := cmdList.Get("sh_ver")
	//shInt, _ := cmdList.Get("sh_int")
	//shStandby, _ := cmdList.Get("sh_standby")
	//shIpv6Int, _ := cmdList.Get("sh_ipv6_int")
	//shIntBrief, _ := cmdList.Get("sh_int_brief")
	//shVrf, _ := cmdList.Get("sh_vrf")
	cmdList.Add("sh run", "sh_run", 10, force)
	cmdList.Add("sh ver", "sh_ver", 2, force)
	cmdList.Add("sh interface", "sh_int", 4, force)
	cmdList.Add("sh standby", "sh_standby", 4, force)
	cmdList.Add("sh ipv6 interface", "sh_ipv6_int", 4, force)
	cmdList.Add("sh ip int brief", "sh_int_brief", 2, force)
	cmdList.Add("sh vrf brief", "sh_vrf", 2, force)
	bia.RunCmdListAndSave(cmdList)
	return cmdList
}

func (bia *BaseIosAdapter) get(key string) string {
	//db := global.GVA_DB
	//entity := model.ConfigExtractEntity{}
	//db.Where("extract_task_id = ?", bia.Task.ID).Where("cmd_key = ?", key).Find(&entity)
	//
	//return entity.Data
	return ""
}

func (bia *BaseIosAdapter) GetConfig(force bool) interface{} {
	cmdList := bia.CliCmdList
	shrun, _ := cmdList.Get("sh_run")
	return string(shrun.Data)
}

func (bia *BaseIosAdapter) ParseShowRunPort(shrunText string) map[string]map[network.IPFamily][]string {
	sectionMap := map[string]string{
		"regex": `(?P<section>[\r\n]interface\s(?P<name>\S+)([\r\n]+[ ]+[^\n]+)+)`,
		"name":  "section",
		"flags": "m",
	}

	shrunMap := map[string]string{
		"regex": `(?P<type>ip(v6)?) address( (?P<address>\S+)( (?P<mask>\S+)( (?P<second>secondary))?)?)?`,
		"name":  "shrun",
		"flags": "m",
	}

	sectionSplitter, err := text.NewSplitterFromMap(sectionMap)
	shrunSplitter, err := text.NewSplitterFromMap(shrunMap)

	resultSection, err := sectionSplitter.Input(shrunText)
	if err != nil {
		panic(err)
	}

	portlistMap := map[string]map[network.IPFamily][]string{}

	for it := resultSection.Iterator(); it.HasNext(); {
		_, _, m := it.Next()
		resultRun, err := shrunSplitter.Input(m["section"])
		if err != nil {
			panic(err)
		}
		portMap := map[network.IPFamily][]string{}
		portMap[network.IPv4] = []string{}
		portMap[network.IPv6] = []string{}
		for it2 := resultRun.Iterator(); it2.HasNext(); {
			_, _, port := it2.Next()
			ip := port["address"]
			if ip == "" {
				continue
			}
			if port["mask"] != "" {
				ip = ip + "/" + port["mask"]
			}

			net, err := network.ParseIPNet(ip)
			if err != nil {
				panic(err)
			}
			if net.Type() == network.IPv4 {
				portMap[network.IPv4] = append(portMap[network.IPv4], fmt.Sprintf("%s/%d", net.IP, net.Prefix()))
			} else {
				portMap[network.IPv6] = append(portMap[network.IPv6], fmt.Sprintf("%s/%d", net.IP, net.Prefix()))
			}

		}
		if len(portMap[network.IPv4]) > 0 || len(portMap[network.IPv6]) > 0 {
			portlistMap[m["name"]] = portMap
		}
	}

	return portlistMap

}

func (bia *BaseIosAdapter) ParseVrf(shrunText string, portList []api.Port) []api.Port {
	sectionMap := map[string]string{
		"regex": `(?P<section>[\r\n]interface\s(?P<name>\S+)([\r\n]+[ ]+[^\n]+)+)`,
		"name":  "section",
		"flags": "m",
	}

	sectionSplitter, err := text.NewSplitterFromMap(sectionMap)

	resultSection, err := sectionSplitter.Input(shrunText)
	if err != nil {
		panic(err)
	}

	vrfMap := map[string]string{
		"regex": `vrf forwarding (?P<vrf>\S+)`,
		"name":  "shvrf",
		"flags": "m",
	}

	for it := resultSection.Iterator(); it.HasNext(); {
		_, _, m := it.Next()
		vrfSplitter, err := text.NewSplitterFromMap(vrfMap)
		if err != nil {
			panic(err)
		}

		if strings.Index(m["section"], "vrf forwarding") > -1 {
			vrfResult, err := vrfSplitter.Input(m["section"])
			if err != nil {
				panic(err)
			}
			for it2 := vrfResult.Iterator(); it2.HasNext(); {
				_, _, vrfMap := it2.Next()
				for _, port := range portList {
					if port.Name() == m["name"] {
						port.WithVrf(vrfMap["vrf"])

					}
				}
			}
		}
	}

	for _, port := range portList {
		if port.Vrf() == "" {
			port.WithVrf(enum.DefaultVrf)
		}
	}

	return portList

}

func (bia *BaseIosAdapter) ParseShowPort(shportText string) []map[string]string {

	shintMap := map[string]string{
		"regex": `(?P<name>\S+)\sis\s([\w ]+)?(?P<phy_status>(up|down)),\sline\sprotocol\sis\s(?P<protocol_status>(up|down))`,
		"name":  "shint",
		"flags": "m",
	}

	shintSplitter, err := text.NewSplitterFromMap(shintMap)
	if err != nil {
		panic(err)
	}
	rest2, err := shintSplitter.Input(shportText)
	if err != nil {
		panic(err)
	}
	port_list := []map[string]string{}
	for it := rest2.Iterator(); it.HasNext(); {
		_, _, m := it.Next()
		port_list = append(port_list, m)
	}

	return port_list

}

func (bia *BaseIosAdapter) ParseIpv6Port(shportText string) []map[string]string {
	sectionMap := map[string]string{
		"regex": `(?P<section>^(?P<name>\S+)\sis\s[^\n]+\n([ ]+\S[^\n]+\n?)+)`,
		"name":  "ipv6_int",
		"flags": "m",
	}
	sectionSplitter, err := text.NewSplitterFromMap(sectionMap)
	if err != nil {
		panic(err)
	}
	sectionResult, err := sectionSplitter.Input(shportText)
	if err != nil {
		panic(err)
	}

	ipv6Map := map[string]string{
		"regex": `(?P<name>^\S+)\sis[^\n]+\n^\s+IPv6.*?, link-local address is (?P<address>[A-F\d:]+)`,
		"name":  "ipv6",
		"flags": "m",
	}

	ipv6Spliter, err := text.NewSplitterFromMap(ipv6Map)
	if err != nil {
		panic(err)
	}

	portList := []map[string]string{}
	for it := sectionResult.Iterator(); it.HasNext(); {
		_, _, port := it.Next()
		// portList = append(portList, port)
		res2, err := ipv6Spliter.Input(port["section"])
		if err != nil {
			panic(err)
		}
		for it2 := res2.Iterator(); it2.HasNext(); {
			_, attrs, ipv6PortMap := it2.Next()
			mp := map[string]string{}
			for _, attr := range attrs {
				mp[attr] = ipv6PortMap[attr]
			}
			portList = append(portList, mp)
		}
	}
	return portList
}

func (bia *BaseIosAdapter) ParseFhrpGroup(shfhrpText, mode string) []api.Member {
	sectionRegexMap := map[string]string{
		"regex": `(?P<section>^\w[^\n]+(\n[\s]+[^\n]+)+)`,
		"name":  "fhrp",
		"flags": "m",
		"pcre":  "true",
	}

	sectionSplitter, err := text.NewSplitterFromMap(sectionRegexMap)
	if err != nil {
		panic(err)
	}

	fhrpRegexMap := map[string]string{
		"regex": `(?P<name>\S+)[^\n]+Group\s(?P<id>\d+)\s+
				   State\sis\s(?P<state>\S+)
		           \s+(.*?)
		           Virtual\sIP\saddress\sis\s(?P<ip>\S+)
		           .*?
		           Priority\s(is\s)?(?P<priority>\d+)`,
		"name":  "fhrp",
		"flags": "sx",
		"pcre":  "true",
	}

	fhrpSplitter, err := text.NewSplitterFromMap(fhrpRegexMap)
	if err != nil {
		panic(err)
	}

	sectionResult, err := sectionSplitter.Input(shfhrpText)
	if err != nil {
		panic(err)
	}

	fhrpGroupList := []api.Member{}
	for sectionIt := sectionResult.Iterator(); sectionIt.HasNext(); {
		_, _, dataMap := sectionIt.Next()
		fhrpResult, err := fhrpSplitter.Input(dataMap["section"])
		if err != nil {
			panic(err)
		}

		for it := fhrpResult.Iterator(); it.HasNext(); {
			_, attrs, fhrpMap := it.Next()
			groupMap := map[string]string{}
			for _, attr := range attrs {
				if strings.Index(attr, "__") > -1 {
					continue
				}
				groupMap[attr] = fhrpMap[attr]
			}
			// groupMap["mode"] = mode
			// fhrpGroupList = append(fhrpGroupList, groupMap)
			groupId, err := strconv.Atoi(fhrpMap["id"])
			if err != nil {
				panic(err)
			}
			priority, err := strconv.Atoi(fhrpMap["priority"])
			if err != nil {
				panic(err)
			}
			member := node.NewMember(fhrpMap["name"], fhrpMap["ip"], fhrpMap["state"], mode, groupId, priority)
			fhrpGroupList = append(fhrpGroupList, member)
		}

	}

	return fhrpGroupList
}

func (bia *BaseIosAdapter) PortList(force bool) []api.Port {
	cmdList := bia.Prepare(force)
	shrun, _ := cmdList.Get("sh_run")
	shport, _ := cmdList.Get("sh_int")
	shipv6port, _ := cmdList.Get("sh_ipv6_int")
	shfhrp, _ := cmdList.Get("sh_standby")
	shrunText := string(shrun.Data)
	shipv6portText := string(shipv6port.Data)
	shportText := string(shport.Data)
	shfhrpText := string(shfhrp.Data)

	// 首先解析FHRP信息
	fhrpList := bia.ParseFhrpGroup(shfhrpText, "HSRP")

	shrunPortListMap := bia.ParseShowRunPort(shrunText)

	portList := []api.Port{}
	for name, portMap := range shrunPortListMap {
		// func NewPort(name, tenant string, ip_list map[string][]string, members []*Member) *Port {
		members := []api.Member{}
		for _, member := range fhrpList {
			if member.PortName() == name {
				members = append(members, member.(*node.Member))
			}
		}
		port := node.NewPort(name, "", portMap, members)
		portList = append(portList, port)
	}

	shintPortList := bia.ParseShowPort(shportText)
	for _, port := range portList {
		for _, portMap := range shintPortList {
			if port.HitByName(portMap["name"]) {
				if portMap["phy_status"] == "up" && portMap["protocol_status"] == "up" {
					port.WithStatus("up")
				} else {
					port.WithStatus("down")
				}
				break
			}
		}
	}

	if strings.Index(shipv6portText, "link-local") > -1 {
		shipv6PortList := bia.ParseIpv6Port(shipv6portText)
		for _, portMap := range shipv6PortList {
			for _, port := range portList {
				if port.HitByName(portMap["name"]) {
					port.AddIpv6(portMap["address"] + "/10")
					break
				}
			}
		}
	}

	bia.ParseVrf(shrunText, portList)

	return portList
}

func (bia *BaseIosAdapter) ParseIpv6Route(shrouteText string) *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv6)

	sectionRegexMape := map[string]string{
		"regex": `(?P<type>C|L|S|OI|OE[12]|ON[12]|O)\s+(?P<ipv6>\S+)\s+(?P<info>\S+)(?P<hops>(\s+via[^\n]+)+)`,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	hopRegexMap := map[string]string{
		"regex": `via ((?P<nhop>[A-F0-9:]{3,})(, (?P<interface>\S+))?)|((?P<local_interface>\S+), (((?P<connected>directly)( (connected))?)|(?P<receive>receive)))`,
		"name":  "hops",
		"flags": "m",
		"pcre":  "true",
	}

	sectionSplitter, err := text.NewSplitterFromMap(sectionRegexMape)
	if err != nil {
		panic(err)
	}

	hopSplitter, err := text.NewSplitterFromMap(hopRegexMap)
	if err != nil {
		panic(err)
	}

	sectionResult, err := sectionSplitter.Input(shrouteText)
	if err != nil {
		panic(err)
	}
	for it := sectionResult.Iterator(); it.HasNext(); {
		_, _, sectionMap := it.Next()
		hopResult, err := hopSplitter.Input(sectionMap["hops"])
		if err != nil {
			panic(err)
		}
		nextHop := &network.NextHop{}
		for it2 := hopResult.Iterator(); it2.HasNext(); {
			_, _, hopMap := it2.Next()
			if hopMap["receive"] != "receive" {
				var portName = hopMap["local_interface"]
				if hopMap["interface"] != "" {
					portName = hopMap["interface"]
				}
				nextHop.AddHop(portName, hopMap["nhop"], hopMap["connected"] == "directly", false, nil)
			}
		}

		if nextHop.Count() > 0 {
			net, err := network.ParseIPNet(sectionMap["ipv6"])
			if err != nil {
				panic(err)
			}

			routeTable.PushRoute(net, nextHop)
		}

	}

	routeTable.RecursionRouteProcess()
	return routeTable

}

func CiscoRouteSection(shrouteText string) []string {
	sectionMapRegex := map[string]string{
		"regex": `(?P<all>^(?P<prefix>[\*\w]*[ ]+)\d+\.\d+\.\d+\.\d+[^\n]+)`,
		"name":  "all",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionMapRegex, shrouteText)
	if err != nil {
		if err == text.ErrNoMatched {
			return []string{}
		}
		panic(err)
	}

	var result []string
	var records []string
	var prefixLen int
	for i := 0; i < len(sectionResult.Result); {
		sm := sectionResult.Result[i]

		if i != 0 {
			result = append(result, strings.Join(records, "\n"))
		}
		records = []string{}
		records = append(records, sm["all"])
		prefixLen = len(sm["prefix"])

		for j := i + 1; j < len(sectionResult.Result); {
			child := sectionResult.Result[j]
			if len(child["prefix"]) > prefixLen {
				records = append(records, child["all"])
			} else {
				i = j - 1
				break
			}
			// 防止最后一条数据数据可能重复记录的情况
			// 116.0.0.0/25 is subnetted, 1 subnets
			// S        116.58.1.0 [1/0] via 11.98.1.98

			i = j
			j += 1

		}
		i += 1
	}

	if len(records) > 0 {
		result = append(result, strings.Join(records, "\n"))
	}

	return result
}

func (bia *BaseIosAdapter) ParseIpv4Route(shrouteText string) *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv4)

	sections := CiscoRouteSection(shrouteText)

	// sectionRegexMape := map[string]string{
	// "regex": `
	// (?P<all>
	// (^\S+\s+\d+\.\d+\.\d+\.\d+\/\d+\s\[\d+\/\d+\]\svia\s\d+\.\d+\.\d+\.\d+)|
	// (((^\s+\d+\.\d+\.\d+\.\d+\/(?P<prefix>\d+)\sis\s(variably\s)?subnetted)[^\n]+\s)(([^\n]+,\s[\S]+)\n)+)
	// )
	// `,
	// "name":  "one",
	// "flags": "mx",
	// "pcre":  "true",
	// }

	// sectionSplitter, err := text.NewSplitterFromMap(sectionRegexMape)
	// if err != nil {
	// panic(err)
	// }

	// routeRegexMap := map[string]string{
	// "regex": `
	// ^(?P<all>
	// (?P<type>\S+)((\s|\*)E2)?\s+(?P<net>[\d\.]+)(\/(?P<prefix>\d+))?[^\n]+
	// ([ ]+(via|connected)[^\n]+)
	// (\n[ ]+\[\d+\/\d+\]\svia\s[\d\.]+,\s\S+,\s\S+)*
	// )
	// `,
	// "name":  "route",
	// "flags": "mx",
	// "pcre":  "true",
	// }

	routeRegexMap := map[string]string{
		"regex": `^(?P<all>(?P<type>\S+)((\s|\*)E2)?\s+(?P<net>[\d\.]+)(\/(?P<prefix>\d+))?\s.*(connected|via).*)`,
		"name":  "route",
		"flags": "mx",
		"pcre":  "true",
	}

	hopRegexMap := map[string]string{
		"regex": `(via (?P<nhop>[\d\.]+)|(?P<connected>connected))((, \S+)?, (?P<interface>\S+))?`,
		"name":  "hop",
		"flags": "m",
		"pcre":  "true",
	}

	routeSplitter, err := text.NewSplitterFromMap(routeRegexMap)
	if err != nil {
		panic(err)
	}

	hopSplitter, err := text.NewSplitterFromMap(hopRegexMap)
	if err != nil {
		panic(err)
	}

	// sectionResult, err := sectionSplitter.Input(shrouteText)
	if err != nil {
		panic(err)
	}
	for _, all := range sections {
		// for sectionIt := sectionResult.Iterator(); sectionIt.HasNext(); {
		// _, _, sectionMap := sectionIt.Next()
		// routeResult, err := routeSplitter.Input(sectionMap["all"])
		routeResult, err := routeSplitter.Input(all)
		if err != nil {
			panic(err)
		}
		prefixRegexMap := map[string]string{
			// "regex": `[\d.]+/(?P<prefix>\d+)\s(is\s(variably\s)?subnetted)|(\S+\s+via)`,
			// "regex": `[\d.]+/(?P<prefix>\d+)\s((is\s(variably\s)?subnetted)|(\S+\s+via))`,
			"regex": `(\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+).*`,
			"name":  "prefix",
			"flags": "m",
			"pcre":  "true",
		}
		// prefixResult, err := text.SplitterProcessOneTime(prefixRegexMap, sectionMap["all"])
		prefixResult, err := text.SplitterProcessOneTime(prefixRegexMap, all)
		if err != nil {
			panic(err)
		}

		prefix := ""
		if len(prefixResult.Result) == 1 {
			prefix = prefixResult.Result[0]["prefix"]
		} else if len(prefixResult.Result) == 0 {

			panic(fmt.Sprintf("unknow error: %+v, all: %s", prefixResult, all))
		}

		for it := routeResult.Iterator(); it.HasNext(); {
			_, _, routeMap := it.Next()

			hopResult, err := hopSplitter.Input(routeMap["all"])
			if err != nil {
				panic(err)
			}

			if routeMap["prefix"] != "" {
				prefix = routeMap["prefix"]
			} else if routeMap["prefix"] == "" {
				if prefix == "" {
					panic("unknown prefix")
				}
			}

			net, err := network.ParseIPNet(routeMap["net"] + "/" + prefix)
			if err != nil {
				panic(err)
			}

			nextHop := &network.NextHop{}
			for it2 := hopResult.Iterator(); it2.HasNext(); {
				_, _, hopMap := it2.Next()
				nextHop.AddHop(hopMap["interface"], hopMap["nhop"], hopMap["connected"] == "connected", false, nil)
			}
			err = routeTable.PushRoute(net, nextHop)
			if err != nil {
				panic(err)
			}
		}
	}
	routeTable.RecursionRouteProcess()
	return routeTable
}

func (bia *BaseIosAdapter) Vrfs(shvrfText string) []map[string]string {
	vrfRegexMap := map[string]string{
		"regex": `^\s+(?P<vrf>\S+)\s+((\d+:\d+)|(<not set>))\s*(?P<type>ipv\d+(,ipv\d+)?)`,
		"name":  "vrf",
		"flags": "m",
	}

	if strings.Index(shvrfText, "Default RD") == -1 {
		return []map[string]string{}
	}

	vrfSplitter, err := text.NewSplitterFromMap(vrfRegexMap)
	if err != nil {
		panic(err)
	}

	vrfList := []map[string]string{}
	vrfResult, err := vrfSplitter.Input(shvrfText)
	for it := vrfResult.Iterator(); it.HasNext(); {
		_, _, vrfMap := it.Next()
		vrfList = append(vrfList, map[string]string{"vrf": vrfMap["vrf"], "type": vrfMap["type"]})
	}

	return vrfList
}

func (bia *BaseIosAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {

	cmdList := bia.CliCmdList
	shvrf, _ := cmdList.Get("sh_vrf")
	vrfList := bia.Vrfs(string(shvrf.Data))

	ipv4Cmds := []map[string]string{}
	ipv6Cmds := []map[string]string{}

	for _, vrfMap := range vrfList {
		if strings.Index(vrfMap["type"], "ipv4") > -1 {
			m := map[string]string{
				"cmd": fmt.Sprintf("sh ip route vrf %s", vrfMap["vrf"]),
				"key": fmt.Sprintf("sh_ipv4_route_vrf_%s", vrfMap["vrf"]),
				"vrf": vrfMap["vrf"],
			}
			ipv4Cmds = append(ipv4Cmds, m)
		}
		if strings.Index(vrfMap["type"], "ipv6") > -1 {
			m := map[string]string{
				"cmd": fmt.Sprintf("sh ipv6 route vrf %s", vrfMap["vrf"]),
				"key": fmt.Sprintf("sh_ipv6_route_vrf_%s", vrfMap["vrf"]),
				"vrf": vrfMap["vrf"],
			}
			ipv6Cmds = append(ipv6Cmds, m)
		}
	}

	ipv4Cmds = append(ipv4Cmds, map[string]string{
		"cmd": "sh ip route",
		"key": "sh_ipv4_route",
		"vrf": enum.DefaultVrf,
	})

	ipv6Cmds = append(ipv6Cmds, map[string]string{
		"cmd": "sh ipv6 route",
		"key": "sh_ipv6_route",
		"vrf": enum.DefaultVrf,
	})

	cmdList = command.NewCliCmdList(bia.info.Host, force)
	for _, cmdMap := range ipv4Cmds {
		cacheData, _ := cmdList.Get(cmdMap["key"])
		if cacheData == nil {
			cmdList.Add(cmdMap["cmd"], cmdMap["key"], 10, force)
		}
	}

	for _, cmdMap := range ipv6Cmds {
		cacheData, _ := cmdList.Get(cmdMap["key"])
		if cacheData == nil {
			cmdList.Add(cmdMap["cmd"], cmdMap["key"], 10, force)
		}
	}

	bia.RunCmdListAndSave(cmdList)

	ipv4TableMap = map[string]*network.AddressTable{}
	ipv6TableMap = map[string]*network.AddressTable{}

	for _, cmdMap := range ipv4Cmds {
		data, _ := cmdList.Get(cmdMap["key"])

		routeTable := bia.ParseIpv4Route(string(data.Data))
		ipv4TableMap[cmdMap["vrf"]] = routeTable
	}

	for _, cmdMap := range ipv6Cmds {
		data, _ := cmdList.Get(cmdMap["key"])
		routeTable := bia.ParseIpv6Route(string(data.Data))
		ipv6TableMap[cmdMap["vrf"]] = routeTable
	}

	return ipv4TableMap, ipv6TableMap

}

func (bia *BaseIosAdapter) ParseName(force bool) string {
	//cmdList := bia.Prepare(force)
	cmdList := bia.CliCmdList
	shver, _ := cmdList.Get("sh_ver")
	shverText := string(shver.Data)

	nameRegexMap := map[string]string{
		"regex": `(?P<name>\S+) uptime`,
		"name":  "ver",
		"flags": "m",
	}
	fields, err := text.GetFieldByRegex(nameRegexMap["regex"], shverText, []string{"name"})
	if err != nil {
		panic(err)
	}
	if fields["name"] == "" {
		panic(fmt.Errorf("ParseName failed, %s", shverText))
	}
	//if bia.DumpDb {
	//	dev := model.DcimDevice{}
	//	//result := global.GVA_DB.Where("system_ip = ?", bia.info.Host).Where("system_name = ?", fields["name"]).Find(&dev)
	//	var ipaddress model.IpamIpaddress
	//	ipResult := global.GVA_DB.Where("address = ?", bia.info.Host).First(&ipaddress)
	//	if ipResult.RowsAffected > 0 {
	//		result := global.GVA_DB.Where("primary_ip4_id = ?", ipaddress.ID).Where("name = ?", fields["name"]).Find(&dev)
	//		if result.Error != nil {
	//			panic(result.Error)
	//
	//		}
	//		// bia.Task.DevTablesID = dev.ID
	//		global.GVA_DB.Model(&model.ExtractTask{}).Where("id = ?", bia.Task.ID).Update("dev_tables_id", dev.ID)
	//	} else {
	//		fmt.Println("ParseName err not found,address :", bia.info.Host)
	//	}
	//}
	return fields["name"]
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

	// dev := model.DevTables{}
	// result := global.GVA_DB.Where("system_ip = ?", info.Host).Where("system_name = ?", )

	return ""
}

func (bia *BaseIosAdapter) BatchRun(p interface{}) (interface{}, error) {
	cmdList := p.(*command.CliCmdList)

	cli := session.NewCliSession(bia.info)
	err := cli.BatchRun(&cmdList, true)

	if err != nil {
		return nil, err
	}

	return p, nil
}

func (bia *BaseIosAdapter) BatchConfig(p ...interface{}) (interface{}, error) {
	// cmdList := p.(*command.CliCmdList)
	//
	// cli := session.NewCliSession(bia.Info)
	// err := cli.BatchConfig(&cmdList, true)
	//
	// if err != nil {
	// return nil, err
	// }

	return p, nil

}

func (bia *BaseIosAdapter) AttachChannel(out chan string) bool {
	return false
}

func (bia *BaseIosAdapter) GetRawConfig(_ string, force bool) (any, error) {
	return bia.GetConfig(force), nil
}
