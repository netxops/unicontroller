package dptech

import (
	"fmt"
	"regexp"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/dptech"
	"github.com/netxops/gotextfsm"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"

	//"github.com/netxops/unify/global"
	//"github.com/netxops/unify/model"

	"strings"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/text"

	"github.com/gofrs/uuid"
)

var _ api.Adapter = &DptechAdapter{}

type DptechAdapter struct {
	Type       api.AdapterType
	DeviceType terminalmode.DeviceType
	info       *session.DeviceBaseInfo
	CliCmdList *command.CliCmdList
	current    string
}

func NewDptechAdapter(info *session.DeviceBaseInfo, config string) *DptechAdapter {
	if info == nil || info.Host == "" {
		adapter := &DptechAdapter{
			Type:       api.StringAdapter,
			DeviceType: terminalmode.Dptech,
			current:    config,
		}
		return adapter
	}

	return &DptechAdapter{
		Type:       api.LiveAdapter,
		DeviceType: terminalmode.Dptech,
		info:       info,
	}
}

func (adapter *DptechAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	if adapter.Type == api.LiveAdapter {
		return adapter.liveAdapterInfo(force)
	} else if adapter.Type == api.StringAdapter {
		return adapter.stringAdapterInfo()
	}
	return nil, fmt.Errorf("unsupported adapter type")
}

func (adapter *DptechAdapter) liveAdapterInfo(force bool) (*device.DeviceBaseInfo, error) {
	return adapter.parseInfo()
}

func (adapter *DptechAdapter) stringAdapterInfo() (*device.DeviceBaseInfo, error) {
	return adapter.parseInfo()
}

func (adapter *DptechAdapter) parseInfo() (*device.DeviceBaseInfo, error) {
	// Define the TextFSM template
	template := `Value VERSION (\S+)
Value RELEASE (\S+)
Value HOSTNAME (\S+)
Value MODEL (DP\d+)

Start
  ^!Software Release ${VERSION}${RELEASE}
  ^sysname ${HOSTNAME}
  ^! -> Record`

	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(template)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TextFSM template: %v", err)
	}

	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(adapter.GetConfig(false).(string), fsm, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %v", err)
	}

	if len(parser.Dict) == 0 {
		return nil, fmt.Errorf("no matching records found in the configuration")
	}

	// Extract the information from the first record
	record := parser.Dict[0]

	info := &device.DeviceBaseInfo{
		Hostname: getString(record, "HOSTNAME"),
		Version:  getString(record, "VERSION") + getString(record, "RELEASE"),
		Model:    getString(record, "MODEL"),
		SN:       "Unknown", // Serial number is not available in the given configuration
	}

	// If MODEL is not found in the configuration, extract it from the hostname
	if info.Model == "" {
		parts := strings.Split(info.Hostname, ".")
		for _, part := range parts {
			if strings.HasPrefix(part, "DP") {
				info.Model = part
				break
			}
		}
	}

	return info, nil
}

func getString(record map[string]interface{}, key string) string {
	if value, ok := record[key]; ok {
		return value.(string)
	}
	return ""
}

func (adapter *DptechAdapter) TaskId() uint {
	//return adapter.Task.ID
	return 1
}

func (adapter *DptechAdapter) RunCmdListAndSave(cl *command.CliCmdList) {
	adapter.CliCmdList = cl
	cli := session.NewCliSession(adapter.info)
	err := cli.BatchRun(cl, true)
	if err != nil {
		fmt.Println(err)
	}
}

func (adapter *DptechAdapter) Prepare(force bool) *command.CliCmdList {
	// cli := session.NewCliSession(adapter.Info)

	cmdList := command.NewCliCmdList(adapter.info.Host, force)
	cmdList.Add("sh run", "sh_run", 10, force)
	cmdList.Add("sh ip route", "sh_ipv4", 2, force)
	cmdList.Add("sh ipv6 route", "sh_ipv6", 2, force)
	adapter.RunCmdListAndSave(cmdList)
	return cmdList
}

func (adapter *DptechAdapter) GetConfig(force bool) interface{} {
	if adapter.Type == api.StringAdapter {
		return adapter.current
	}

	cmdList := command.NewCliCmdList(adapter.info.Host, force)
	cmdList.Add("sh run", "sh_run", 10, force)
	cmdList.Add("sh ip route", "sh_ipv4", 2, force)
	cmdList.Add("sh ipv6 route", "sh_ipv6", 2, force)
	cmdList.Add("sh ver", "sh_ver", 2, force)

	adapter.RunCmdListAndSave(cmdList)

	cd, err := adapter.CliCmdList.Get("sh_run")
	if err != nil {
		panic(err)
	}

	return string(cd.Data)
}

func (adapter *DptechAdapter) PortList(force bool) []api.Port {
	// 首先将配置分段
	interfaces := splitInterfaces(adapter.GetConfig(force).(string))

	var portList []api.Port

	// 遍历每个接口配置
	for _, interfaceConfig := range interfaces {
		port := parseInterface(interfaceConfig)
		if port != nil {
			portList = append(portList, port)
		}
	}

	// 获取安全区域信息
	zones, err := adapter.Zones(false)
	if err != nil {
		fmt.Printf("Failed to get zones: %v\n", err)
	} else {
		// 将安全区域信息应用到端口列表
		applyZonesToPorts(portList, zones)
	}

	// 确保所有端口都有 VRF
	ensureDefaultVrf(portList)

	return portList
}

func splitInterfaces(config string) []string {
	var interfaces []string
	lines := strings.Split(config, "\n")
	var currentInterface strings.Builder

	for _, line := range lines {
		if strings.HasPrefix(line, "interface ") {
			if currentInterface.Len() > 0 {
				interfaces = append(interfaces, currentInterface.String())
				currentInterface.Reset()
			}
		}
		currentInterface.WriteString(line + "\n")
	}

	if currentInterface.Len() > 0 {
		interfaces = append(interfaces, currentInterface.String())
	}

	return interfaces
}

func parseInterface(interfaceConfig string) api.Port {
	lines := strings.Split(interfaceConfig, "\n")
	var name, description, vrf string
	var ipv4, ipv6 []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "interface "):
			name = strings.TrimPrefix(line, "interface ")
		case strings.HasPrefix(line, "description "):
			description = strings.TrimPrefix(line, "description ")
		case strings.HasPrefix(line, "bind vrf "):
			vrf = strings.TrimPrefix(line, "bind vrf ")
		case strings.HasPrefix(line, "ip address "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ipv4 = append(ipv4, parts[2])
			}
		case strings.HasPrefix(line, "ipv6 address "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ipv6 = append(ipv6, parts[2])
			}
			// case strings.HasPrefix(line, "bond group "):
			//     bondGroup = strings.TrimPrefix(line, "bond group ")
		}
	}

	if name == "" {
		return nil
	}

	port := dptech.NewDptechPort(
		name,
		vrf,
		map[network.IPFamily][]string{
			network.IPv4: ipv4,
			network.IPv6: ipv6,
		},
		[]api.Member{},
	)
	port.WithVrf(vrf)
	port.WithAliasName(description)

	// if bondGroup != "" {
	//     port.WithBondGroup(bondGroup)
	// }

	return port
}

func applyZonesToPorts(portList []api.Port, zones []interface{}) {
	for _, zoneInterface := range zones {
		zone := zoneInterface.(map[string]interface{})
		zoneName := zone["ZoneName"].(string)
		interfaceName := zone["IfName"].(string)
		for i, port := range portList {
			if port.Name() == interfaceName {
				portList[i].(*dptech.DptechPort).WithZone(zoneName)
				break
			}
		}
	}
}

func ensureDefaultVrf(portList []api.Port) {
	for _, port := range portList {
		if port.Vrf() == "" {
			port.WithVrf(enum.DefaultVrf)
		}
	}
}

// func (adapter *DptechAdapter) Zones(force bool) ([]interface{}, error) {
// 	if adapter.Type == api.LiveAdapter {
// 		return adapter.liveAdapterZones(force)
// 	} else if adapter.Type == api.StringAdapter {
// 		return adapter.stringAdapterZones()
// 	}
// 	return nil, fmt.Errorf("unsupported adapter type")
// }

func (adapter *DptechAdapter) Zones(force bool) ([]interface{}, error) {
	template := `Value ZONE_NAME (\S+)
Value INTERFACE (\S+)
Value PRIORITY (\d+)
Value DESCRIPTION (.*)

Start
  ^security-zone ${ZONE_NAME}( interface ${INTERFACE})?( priority ${PRIORITY})?( description ${DESCRIPTION})? -> Record

EOF`

	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(template)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TextFSM template: %v", err)
	}

	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(adapter.GetConfig(force).(string), fsm, false)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %v", err)
	}

	var zones []interface{}
	for _, record := range parser.Dict {
		zone := map[string]interface{}{
			"ZoneName":    getString(record, "ZONE_NAME"),
			"IfName":      getString(record, "INTERFACE"),
			"Priority":    getString(record, "PRIORITY"),
			"Description": getString(record, "DESCRIPTION"),
		}
		zones = append(zones, zone)
	}

	return zones, nil
}

func (adapter *DptechAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	if adapter.Type == api.LiveAdapter {
		cmdList := adapter.CliCmdList
		cd, err := cmdList.Get("sh_ipv4")
		if err != nil {
			panic(err)
		}
		shipv4Txt := string(cd.Data)

		cd, err = cmdList.Get("sh_ipv6")
		if err != nil {
			panic(err)
		}
		shipv6Txt := string(cd.Data)

		ipv4TableMap = adapter.parseIpv4Route(shipv4Txt)
		ipv6TableMap = adapter.parseIpv6Route(shipv6Txt)

		return ipv4TableMap, ipv6TableMap
	} else {
		config := adapter.GetConfig(force).(string)

		return adapter.parseRouteFromConfig(config)

		// // 合并从 show 命令和配置文件中解析的路由表
		// for vrf, table := range configIpv4TableMap {
		// 	if _, exists := ipv4TableMap[vrf]; !exists {
		// 		ipv4TableMap[vrf] = network.NewAddressTable(network.IPv4)
		// 	}
		// 	for _, route := range table.Routes() {
		// 		ipv4TableMap[vrf].PushRoute(route.Net, route.NextHop)
		// 	}
		// }

		// for vrf, table := range configIpv6TableMap {
		// 	if _, exists := ipv6TableMap[vrf]; !exists {
		// 		ipv6TableMap[vrf] = network.NewAddressTable(network.IPv6)
		// 	}
		// 	for _, route := range table.Routes() {
		// 		ipv6TableMap[vrf].PushRoute(route.Net, route.NextHop)
		// 	}
		// }
		// return ipv4TableMap, ipv6TableMap
	}

}

func (adapter *DptechAdapter) parseRouteFromConfig(config string) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	ipv4TableMap = make(map[string]*network.AddressTable)
	ipv6TableMap = make(map[string]*network.AddressTable)

	// 定义 TextFSM 模板
	template := `Value PROTOCOL (ip|ipv6)
Value DESTINATION (\S+)
Value INTERFACE (\S+)
Value NEXTHOP (((\d{1,3}\.){3}\d{1,3})|(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))
Value VRF (\S+)
Value DESCRIPTION (.*)

Start
  ^${PROTOCOL}\s+route\s+${DESTINATION}(\s+${INTERFACE})?\s+${NEXTHOP}(\s+vrf\s+${VRF})?(\s+description\s+${DESCRIPTION})? -> Record
  ^${PROTOCOL}\s+route\s+vrf\s+${VRF}\s+${DESTINATION}(\s+${INTERFACE})?\s+${NEXTHOP}(\s+description\s+${DESCRIPTION})? -> Record`

	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(template)
	if err != nil {
		fmt.Printf("Error parsing TextFSM template: %v\n", err)
		return
	}

	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(config, fsm, false)
	if err != nil {
		fmt.Printf("Error parsing configuration: %v\n", err)
		return
	}

	// 用于存储等价路由
	equivalentRoutes := make(map[string]*network.NextHop)

	// 缓存端口列表，用于通过 nexthop IP 查找接口
	var portList []api.Port
	var portListCached bool

	for _, record := range parser.Dict {
		protocol := getString(record, "PROTOCOL")
		destination := getString(record, "DESTINATION")
		interface_ := getString(record, "INTERFACE")
		nexthop := getString(record, "NEXTHOP")
		vrf := getString(record, "VRF")
		// description := getString(record, "DESCRIPTION")

		if vrf == "" {
			vrf = enum.DefaultVrf
		}

		if protocol == "ip" {
			if _, exists := ipv4TableMap[vrf]; !exists {
				ipv4TableMap[vrf] = network.NewAddressTable(network.IPv4)
			}
		} else {
			if _, exists := ipv6TableMap[vrf]; !exists {
				ipv6TableMap[vrf] = network.NewAddressTable(network.IPv6)
			}
		}

		_, err := network.ParseIPNet(destination)
		if err != nil {
			fmt.Printf("Error parsing destination %s: %v\n", destination, err)
			continue
		}

		// 如果 interface_ 为空且 nexthop 不为空，通过 nexthop IP 地址查找匹配的接口
		if interface_ == "" && nexthop != "" {
			if !portListCached {
				portList = adapter.PortList(false)
				portListCached = true
			}
			for _, port := range portList {
				if port.HitByIpWithoutPrefix(nexthop, vrf) {
					interface_ = port.Name()
					break
				}
			}
		}

		key := fmt.Sprintf("%s|||%s", vrf, destination)
		if _, exists := equivalentRoutes[key]; !exists {
			equivalentRoutes[key] = &network.NextHop{}
		}
		equivalentRoutes[key].AddHop(interface_, nexthop, nexthop == "", false, nil)
	}

	// 合并等价路由并添加到路由表
	for key, hops := range equivalentRoutes {
		parts := strings.SplitN(key, "|||", 2)
		vrf, destination := parts[0], parts[1]
		net, _ := network.ParseIPNet(destination)

		if net.Type() == network.IPv4 {
			ipv4TableMap[vrf].PushRoute(net, hops)
		} else {
			ipv6TableMap[vrf].PushRoute(net, hops)
		}
	}

	return ipv4TableMap, ipv6TableMap
}

func (adapter *DptechAdapter) parseIpv4Route(shrouteText string) map[string]*network.AddressTable {
	return adapter.parseRoute(shrouteText, network.IPv4)
}

func (adapter *DptechAdapter) parseIpv6Route(shrouteText string) map[string]*network.AddressTable {
	return adapter.parseRoute(shrouteText, network.IPv6)
}

// func (adapter *DptechAdapter) parseRoute(shrouteText string, ipFamily network.IPFamily) map[string]*network.AddressTable {
//     routeTables := make(map[string]*network.AddressTable)

//     // 1. 以 "Route in VRF" 第一次出现的位置截取文本
//     index := strings.Index(shrouteText, "Route in VRF")
//     if index == -1 {
//         return routeTables
//     }
//     shrouteText = shrouteText[index:]

//     // 2. 以空行分割得到多个 section
//     sections := strings.Split(shrouteText, "\n\n")

//     // 3. 针对每个 section，提取 vrf 以及路由表
//     for _, section := range sections {
//         lines := strings.Split(section, "\n")
//         if len(lines) == 0 {
//             continue
//         }

//         // 提取 VRF 名称
//         vrfMatch := regexp.MustCompile(`Route in VRF\( (\S+) \):`).FindStringSubmatch(lines[0])
//         if len(vrfMatch) < 2 {
//             continue
//         }
//         vrf := vrfMatch[1]
//         if vrf == "VRF_0" {
//             vrf = enum.DefaultVrf
//         }

//         routeTable := network.NewAddressTable(ipFamily)
//         routeTables[vrf] = routeTable

//         // 解析路由
//         var lastFmap string
//         var lastNet *network.IPNet

//         for i := 1; i < len(lines); i++ {
//             line := strings.TrimSpace(lines[i])
//             if line == "" {
//                 continue
//             }

//             routeMatch := regexp.MustCompile(`([CSIBDEXOIANULP*>]+)\s*(\S+/\d+)(\s+\[[\d/]+\])?\s+(fmap : (\S+)\s+)?(.*)`).FindStringSubmatch(line)
//             if len(routeMatch) < 6 {
//                 // 处理多行路由条目
//                 if strings.HasPrefix(line, "*") && lastNet != nil {
//                     if !strings.Contains(line, "fmap :") && lastFmap != "" {
//                         line = lastFmap + " " + line
//                     }
//                     hopInfo := parseHopInfo(line)
//                     if hopInfo != nil {
//                         nextHop := &network.NextHop{}
//                         nextHop.AddHop(hopInfo.interface_, hopInfo.via, hopInfo.connected, false, nil)
//                         routeTable.PushRoute(lastNet, nextHop)
//                     }
//                 }
//                 continue
//             }

//             net, err := network.ParseIPNet(routeMatch[2])
//             if err != nil {
//                 continue
//             }
//             lastNet = net

//             if routeMatch[5] != "" {
//                 lastFmap = "fmap : " + routeMatch[5]
//             }

//             routeInfo := routeMatch[6]
//             nextHop := &network.NextHop{}

//             hopInfoList := parseHopInfoList(routeInfo)
//             for _, hopInfo := range hopInfoList {
//                 nextHop.AddHop(hopInfo.interface_, hopInfo.via, hopInfo.connected, false, nil)
//             }

//             if nextHop.Count() > 0 {
//                 routeTable.PushRoute(net, nextHop)
//             }
//         }
//     }

//     return routeTables
// }

func (adapter *DptechAdapter) parseVrfFromConfig(config string) map[string]string {
	vrfMap := make(map[string]string)
	lines := strings.Split(config, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "vrf ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				vrfName := parts[1]
				vrfMap[vrfName] = vrfName
			}
		}
	}

	// 确保默认 VRF 总是存在
	if _, exists := vrfMap["default"]; !exists {
		vrfMap["default"] = "default"
	}

	return vrfMap
}

func contains(slice []network.IPFamily, item network.IPFamily) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

func (adapter *DptechAdapter) parseRoute(shrouteText string, ipFamily network.IPFamily) map[string]*network.AddressTable {
	routeTables := make(map[string]*network.AddressTable)

	// 1. 以 "Route in VRF" 第一次出现的位置截取文本
	index := strings.Index(shrouteText, "Route in VRF")
	if index == -1 {
		return routeTables
	}
	shrouteText = shrouteText[index:]

	// 2. 以空行分割得到多个 section
	sections := strings.Split(shrouteText, "\n\n")

	// 3. 针对每个 section，提取 vrf 以及路由表
	for _, section := range sections {
		lines := strings.Split(section, "\n")
		if len(lines) == 0 {
			continue
		}

		// 提取 VRF 名称
		vrfMatch := regexp.MustCompile(`Route in VRF\( (\S+) \):`).FindStringSubmatch(lines[0])
		if len(vrfMatch) < 2 {
			continue
		}
		vrf := vrfMatch[1]
		if vrf == "VRF_0" {
			vrf = enum.DefaultVrf
		}

		routeTable := network.NewAddressTable(ipFamily)
		routeTables[vrf] = routeTable

		// 用于收集路由信息的临时map
		routeInfoMap := make(map[string][]*hopInfo)

		// 解析路由
		var lastFmap string
		var lastNet *network.IPNet
		for i := 1; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}

			if strings.Contains(line, "Null0") {
				continue
			}

			routeMatch := regexp.MustCompile(`([CSIBDEXOIANULP*>]+)\s*(\S+/\d+)(\s+\[[\d/]+\])?\s+(fmap : (\S+)\s+)?(.*)`).FindStringSubmatch(line)
			if len(routeMatch) < 6 {
				// 处理多行路由条目
				if strings.HasPrefix(line, "*") && lastNet != nil {
					if !strings.Contains(line, "fmap :") && lastFmap != "" {
						line = lastFmap + " " + line
					}
					hopInfoList := parseHopInfoList(line)
					routeInfoMap[lastNet.String()] = append(routeInfoMap[lastNet.String()], hopInfoList...)
				}
				continue
			}

			net, err := network.ParseIPNet(routeMatch[2])
			if err != nil {
				continue
			}
			lastNet = net

			if routeMatch[5] != "" {
				lastFmap = "fmap : " + routeMatch[5]
			}

			routeInfo := routeMatch[6]
			hopInfoList := parseHopInfoList(routeInfo)
			routeInfoMap[net.String()] = append(routeInfoMap[net.String()], hopInfoList...)
		}

		// 将收集到的路由信息添加到路由表中
		for netStr, hopInfoList := range routeInfoMap {
			net, _ := network.ParseIPNet(netStr)
			nextHop := &network.NextHop{}
			addedHops := make(map[string]bool) // 用于跟踪已添加的下一跳

			for _, hopInfo := range hopInfoList {
				// 创建唯一标识符
				hopKey := fmt.Sprintf("%s-%s-%v", hopInfo.interface_, hopInfo.via, hopInfo.connected)

				// 如果这个下一跳还没有被添加，则添加它
				if !addedHops[hopKey] {
					nextHop.AddHop(hopInfo.interface_, hopInfo.via, hopInfo.connected, false, nil)
					addedHops[hopKey] = true
				}
			}

			if nextHop.Count() > 0 {
				routeTable.PushRoute(net, nextHop)
			}
		}
	}

	return routeTables
}

type hopInfo struct {
	via        string
	interface_ string
	connected  bool
}

func parseHopInfo(line string) *hopInfo {
	if strings.Contains(line, "is directly connected") {
		match := regexp.MustCompile(`is directly connected, (\S+)`).FindStringSubmatch(line)
		if len(match) > 1 {
			return &hopInfo{interface_: match[1], connected: true}
		}
	} else {
		match := regexp.MustCompile(`via (\S+), (\S+)`).FindStringSubmatch(line)
		if len(match) > 2 {
			return &hopInfo{via: match[1], interface_: match[2]}
		}
	}
	return nil
}

func parseHopInfoList(routeInfo string) []*hopInfo {
	var hopInfoList []*hopInfo

	// 处理直连路由
	if strings.Contains(routeInfo, "is directly connected") {
		hopInfo := parseHopInfo(routeInfo)
		if hopInfo != nil {
			hopInfoList = append(hopInfoList, hopInfo)
		}
		return hopInfoList
	}

	// 处理多行路由条目
	lines := strings.Split(routeInfo, "\n")
	var lastInterface string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 匹配主要的路由信息
		match := regexp.MustCompile(`via (\S+),\s*(\S+)(?:\s+via\s+(\S+)\s*,\s*(\S+))?`).FindStringSubmatch(line)
		if len(match) > 2 {
			via := match[1]
			intf := match[4] // 使用最后一个接口名称
			if intf == "" {
				intf = match[2]
			}
			lastInterface = intf
			hopInfoList = append(hopInfoList, &hopInfo{via: via, interface_: intf})

			// 处理同一行中的第二个 via
			if match[3] != "" {
				hopInfoList = append(hopInfoList, &hopInfo{via: match[3], interface_: match[4]})
			}
		} else {
			// 匹配额外的下一跳信息
			matches := regexp.MustCompile(`via (\S+),\s*(\S+)`).FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				if len(m) > 2 {
					via := m[1]
					intf := m[2]
					if intf == "internel" {
						intf = lastInterface
					}
					hopInfoList = append(hopInfoList, &hopInfo{via: via, interface_: intf})
				}
			}
		}
	}

	return hopInfoList
}

// func (adapter *DptechAdapter) parseIpv4Route(shrouteText string) map[string]*network.AddressTable {
// 	routeTables := make(map[string]*network.AddressTable)

// 	// 1. 以 "Route in VRF" 第一次出现的位置截取文本
// 	index := strings.Index(shrouteText, "Route in VRF")
// 	if index == -1 {
// 		return routeTables
// 	}
// 	shrouteText = shrouteText[index:]

// 	// 2. 以空行分割得到多个 section
// 	sections := strings.Split(shrouteText, "\n\n")

// 	// 3. 针对每个 section，提取 vrf 以及路由表
// 	for _, section := range sections {
// 		lines := strings.Split(section, "\n")
// 		if len(lines) == 0 {
// 			continue
// 		}

// 		// 提取 VRF 名称
// 		vrfMatch := regexp.MustCompile(`Route in VRF\( (\S+) \):`).FindStringSubmatch(lines[0])
// 		if len(vrfMatch) < 2 {
// 			continue
// 		}
// 		vrf := vrfMatch[1]
// 		if vrf == "VRF_0" {
// 			vrf = enum.DefaultVrf
// 		}

// 		routeTable := network.NewAddressTable(network.IPv4)
// 		routeTables[vrf] = routeTable

// 		// 解析路由
// 		var lastFmap string
// 		var lastNet *network.IPNet
// 		for i := 1; i < len(lines); i++ {
// 			line := strings.TrimSpace(lines[i])
// 			if line == "" {
// 				continue
// 			}

// 			routeMatch := regexp.MustCompile(`([CSIBDEXOIANULP*>]+)\s*(\S+/\d+)(\s+\[[\d/]+\])?\s+(fmap : (\S+)\s+)?(via (\S+)|is directly connected),\s*(\S+)(.*)$`).FindStringSubmatch(line)
// 			if len(routeMatch) < 9 {
// 				// 处理多行路由条目
// 				if strings.HasPrefix(line, "*") && lastNet != nil {
// 					lastLine := lines[i-1]
// 					if strings.Contains(lastLine, "fmap :") {
// 						line = lastFmap + " " + line
// 					}
// 					routeMatch = regexp.MustCompile(`(fmap : (\S+)\s+)?(via (\S+)|is directly connected),\s*(\S+)(.*)$`).FindStringSubmatch(line)
// 					if len(routeMatch) < 6 {
// 						continue
// 					}
// 					nextHop := &network.NextHop{}
// 					if routeMatch[3] == "is directly connected" {
// 						nextHop.AddHop(routeMatch[5], "", true, false, nil)
// 					} else {
// 						nextHop.AddHop(routeMatch[5], routeMatch[4], false, false, nil)
// 					}
// 					routeTable.PushRoute(lastNet, nextHop)
// 				}
// 				continue
// 			}

// 			net, err := network.ParseIPNet(routeMatch[2])
// 			if err != nil {
// 				continue
// 			}
// 			lastNet = net

// 			nextHop := &network.NextHop{}
// 			if routeMatch[6] == "is directly connected" {
// 				nextHop.AddHop(routeMatch[8], "", true, false, nil)
// 			} else {
// 				nextHop.AddHop(routeMatch[8], routeMatch[7], false, false, nil)
// 			}

// 			routeTable.PushRoute(net, nextHop)

// 			if routeMatch[5] != "" {
// 				lastFmap = "fmap : " + routeMatch[5]
// 			}
// 		}
// 	}

// 	return routeTables
// }

// func (adapter *DptechAdapter) parseIpv6Route(shrouteText string) map[string]*network.AddressTable {
// 	routeTables := make(map[string]*network.AddressTable)

// 	// 1. 以 "Route in VRF" 第一次出现的位置截取文本
// 	index := strings.Index(shrouteText, "Route in VRF")
// 	if index == -1 {
// 		return routeTables
// 	}
// 	shrouteText = shrouteText[index:]

// 	// 2. 以空行分割得到多个 section
// 	sections := strings.Split(shrouteText, "\n\n")

// 	// 3. 针对每个 section，提取 vrf 以及路由表
// 	for _, section := range sections {
// 		lines := strings.Split(section, "\n")
// 		if len(lines) == 0 {
// 			continue
// 		}

// 		// 提取 VRF 名称
// 		vrfMatch := regexp.MustCompile(`Route in VRF\( (\S+) \):`).FindStringSubmatch(lines[0])
// 		if len(vrfMatch) < 2 {
// 			continue
// 		}
// 		vrf := vrfMatch[1]
// 		if vrf == "VRF_0" {
// 			vrf = enum.DefaultVrf
// 		}

// 		routeTable := network.NewAddressTable(network.IPv6)
// 		routeTables[vrf] = routeTable

// 		// 解析路由
// 		var lastFmap string
// 		var lastNet *network.IPNet
// 		for i := 1; i < len(lines); i++ {
// 			line := strings.TrimSpace(lines[i])
// 			if line == "" {
// 				continue
// 			}

// 			routeMatch := regexp.MustCompile(`([CSIBDEXOIANULP*>]+)\s*(\S+/\d+)(\s+\[[\d/]+\])?\s+(fmap : (\S+)\s+)?(via (\S+)|is directly connected),\s*(\S+)(.*)$`).FindStringSubmatch(line)
// 			if len(routeMatch) < 9 {
// 				// 处理多行路由条目
// 				if strings.HasPrefix(line, "*") && lastNet != nil {
// 					lastLine := lines[i-1]
// 					if strings.Contains(lastLine, "fmap :") {
// 						line = lastFmap + " " + line
// 					}
// 					routeMatch = regexp.MustCompile(`(fmap : (\S+)\s+)?(via (\S+)|is directly connected),\s*(\S+)(.*)$`).FindStringSubmatch(line)
// 					if len(routeMatch) < 6 {
// 						continue
// 					}
// 					nextHop := &network.NextHop{}
// 					if routeMatch[3] == "is directly connected" {
// 						nextHop.AddHop(routeMatch[5], "", true, false, nil)
// 					} else {
// 						nextHop.AddHop(routeMatch[5], routeMatch[4], false, false, nil)
// 					}
// 					routeTable.PushRoute(lastNet, nextHop)
// 				}
// 				continue
// 			}

// 			net, err := network.ParseIPNet(routeMatch[2])
// 			if err != nil {
// 				continue
// 			}
// 			lastNet = net

// 			nextHop := &network.NextHop{}
// 			if routeMatch[6] == "is directly connected" {
// 				nextHop.AddHop(routeMatch[8], "", true, false, nil)
// 			} else {
// 				nextHop.AddHop(routeMatch[8], routeMatch[7], false, false, nil)
// 			}

// 			routeTable.PushRoute(net, nextHop)

// 			if routeMatch[5] != "" {
// 				lastFmap = "fmap : " + routeMatch[5]
// 			}
// 		}
// 	}

// 	return routeTables
// }

func (adapter *DptechAdapter) ParseName(force bool) string {
	//cmdList := adapter.Prepare(force)
	// cmdList := adapter.CliCmdList

	// cd, err := cmdList.Get("sh_run")
	// if err != nil {
	// 	panic(err)
	// }

	// shverText := string(cd.Data)
	shverText := adapter.GetConfig(force).(string)
	// shverText := adapter.get("sh_ver")

	nameRegexMap := map[string]string{
		"regex": `^sysname (?P<name>\S+)`,
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

	return fields["name"]

}

// 批量执行，输入[]*command.CliCmdList，就是命令列表的列表
// 这就意味着需要多次登录网络设备执行
func (adapter *DptechAdapter) BatchRun(p interface{}) (interface{}, error) {
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
func (adapter *DptechAdapter) BatchConfig(p ...interface{}) (interface{}, error) {

	info := adapter.info.BaseInfo

	base := terminal.BaseInfo{
		Host:     info.Host,
		Username: info.Username,
		Password: info.Password,
		AuthPass: info.AuthPass,
		Telnet:   info.Telnet,
	}

	exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.Dptech, &base)
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

func (bia *DptechAdapter) AttachChannel(out chan string) bool {
	return false
}

func (bia *DptechAdapter) GetRawConfig(_ string, force bool) (any, error) {
	return bia.GetConfig(force), nil
}
