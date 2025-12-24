package usg

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/influxdata/telegraf/controller/pkg/l2service/utils/text"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/usg"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/gotextfsm"
	"github.com/netxops/utils/network"
)

var _ api.Adapter = &UsgAdapter{}
var defaultVrf = "default"

type UsgAdapter struct {
	Type       api.AdapterType
	DeviceType terminalmode.DeviceType
	info       *session.DeviceBaseInfo
	CliCmdList *command.CliCmdList
	current    string
}

func NewUsgAdapter(info *session.DeviceBaseInfo, config string) *UsgAdapter {
	if info == nil || info.Host == "" {
		adapter := &UsgAdapter{
			Type:       api.StringAdapter,
			DeviceType: terminalmode.HuaWei,
			current:    config,
		}
		return adapter
	}

	return &UsgAdapter{
		Type:       api.LiveAdapter,
		DeviceType: terminalmode.HuaWei,
		info:       info,
	}
}

func (adapter *UsgAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	if adapter.Type == api.LiveAdapter {
		return adapter.liveAdapterInfo(force)
	} else if adapter.Type == api.StringAdapter {
		return adapter.stringAdapterInfo()
	}
	return nil, fmt.Errorf("unsupported adapter type")
}

func (adapter *UsgAdapter) liveAdapterInfo(force bool) (*device.DeviceBaseInfo, error) {
	return adapter.parseInfo()
}

func (adapter *UsgAdapter) stringAdapterInfo() (*device.DeviceBaseInfo, error) {
	return adapter.parseInfo()
}

func (adapter *UsgAdapter) parseInfo() (*device.DeviceBaseInfo, error) {
	// Define the TextFSM template
	template := `Value VERSION (\S+)
Value HOSTNAME (\S+)

Start
  ^!Software Version ${VERSION}
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
		Version:  getString(record, "VERSION"),
		SN:       "Unknown", // Serial number is not available in the given configuration
	}

	// If MODEL is not found in the configuration, extract it from the hostname

	return info, nil
}

func getString(record map[string]interface{}, key string) string {
	if value, ok := record[key]; ok {
		return value.(string)
	}
	return ""
}

func (adapter *UsgAdapter) TaskId() uint {
	//return adapter.Task.ID
	return 1
}

func (adapter *UsgAdapter) RunCmdListAndSave(cl *command.CliCmdList) {
	adapter.CliCmdList = cl
	cli := session.NewCliSession(adapter.info)
	err := cli.BatchRun(cl, true)
	if err != nil {
		fmt.Println(err)
	}
}

// func (adapter *UsgAdapter) get(key string) string {
//db := global.GVA_DB
//entity := model.ConfigExtractEntity{}
//db.Where("extract_task_id = ?", adapter.Task.ID).Where("cmd_key = ?", key).Find(&entity)
//
//return entity.Data
// return ""
// }

func (adapter *UsgAdapter) Prepare(force bool) *command.CliCmdList {
	// cli := session.NewCliSession(adapter.Info)

	cmdList := command.NewCliCmdList(adapter.info.Host, force)
	cmdList.Add("sh run", "sh_run", 10, force)
	cmdList.Add("sh ip route", "sh_ipv4", 2, force)
	cmdList.Add("sh ipv6 route", "sh_ipv6", 2, force)
	adapter.RunCmdListAndSave(cmdList)
	return cmdList
}

// func (adapter *UsgAdapter) GetConfig(force bool) interface{} {

// 	// shrunText := adapter.get("sh_run")
// 	// return shrunText
// 	//cmdList := adapter.Prepare(force)
// 	cmdList := adapter.CliCmdList
// 	cd, err := cmdList.Get("sh_run")
// 	if err != nil {
// 		panic(err)
// 	}
// 	shrunText := string(cd.Data)

// 	return shrunText
// }

func (adapter *UsgAdapter) GetConfig(force bool) interface{} {
	if adapter.Type == api.StringAdapter {
		return adapter.current
	}

	cmdList := command.NewCliCmdList(adapter.info.Host, force)
	cmdList.Add("display current", "sh_run", 5, force)
	cmdList.Add("display ip vpn-instance", "sh_vrf", 2, force)
	cmdList.Add("display version", "sh_ver", 2, force)

	adapter.RunCmdListAndSave(cmdList)

	cd, err := adapter.CliCmdList.Get("sh_run")
	if err != nil {
		panic(err)
	}

	return string(cd.Data)
}

func (adapter *UsgAdapter) PortList(force bool) []api.Port {
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
	var name, description, vrf, alias string
	var ipv4, ipv6 []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "interface "):
			name = strings.TrimPrefix(line, "interface ")
		case strings.HasPrefix(line, "description "):
			description = strings.TrimPrefix(line, "description ")
		case strings.HasPrefix(line, "alias "):
			alias = strings.TrimPrefix(line, "alias ")
		case strings.HasPrefix(line, "ip binding vpn-instance"):
			vrf = strings.TrimPrefix(line, "ip binding vpn-instance ")
		case strings.HasPrefix(line, "ip address "):
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				ipv4 = append(ipv4, strings.Join([]string{parts[2], "/", parts[3]}, ""))
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

	port := usg.NewUsgPort(
		name,
		vrf,
		map[network.IPFamily][]string{
			network.IPv4: ipv4,
			network.IPv6: ipv6,
		},
		[]api.Member{},
	)
	port.WithVrf(vrf)
	port.WithAliasName(alias)
	port.WithDescription(description)

	// if bondGroup != "" {
	//     port.WithBondGroup(bondGroup)
	// }

	return port
}

func applyZonesToPorts(portList []api.Port, zones []interface{}) {
	for _, zoneInterface := range zones {
		zone := zoneInterface.(map[string]interface{})
		zoneName := zone["ZoneName"].(string)
		interfaces, ok := zone["Interfaces"].([]string)
		if !ok {
			continue
		}

		for _, interfaceName := range interfaces {
			for i, port := range portList {
				if port.Name() == interfaceName {
					portList[i].(*usg.UsgPort).WithZone(zoneName)
					break
				}
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

func (adapter *UsgAdapter) Zones(force bool) ([]interface{}, error) {
	template := `Value ZONE_NAME (\S+)
Value PRIORITY (\d+)
Value INTERFACE (\S+)

Start
  ^firewall zone( name)? ${ZONE_NAME}( id \d+)?
  ^\s+set priority ${PRIORITY}
  ^\s+add interface ${INTERFACE} -> Record
  ^# -> Record

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
	currentZone := make(map[string]interface{})

	for _, record := range parser.Dict {
		zoneName := getString(record, "ZONE_NAME")
		priority := getString(record, "PRIORITY")
		interfaceName := getString(record, "INTERFACE")

		if zoneName != "" {
			// Start a new zone
			if len(currentZone) > 0 {
				zones = append(zones, currentZone)
			}
			currentZone = map[string]interface{}{
				"ZoneName":   zoneName,
				"Priority":   priority,
				"Interfaces": []string{},
			}
		}

		if interfaceName != "" {
			interfaces, _ := currentZone["Interfaces"].([]string)
			currentZone["Interfaces"] = append(interfaces, interfaceName)
		}
	}

	// Add the last zone
	if len(currentZone) > 0 {
		zones = append(zones, currentZone)
	}

	return zones, nil
}

func (adapter *UsgAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	cmdList := adapter.CliCmdList

	var vrfList map[string][]network.IPFamily
	if adapter.Type == api.LiveAdapter {
		cd, err := cmdList.Get("sh_vrf")
		if err != nil {
			panic(err)
		}
		vrfTxt := string(cd.Data)
		vrfList = adapter.parseVrf(vrfTxt)
		fmt.Println("vrfList:", vrfList)
		cmdList = command.NewCliCmdList(adapter.info.Host, force)
		for vrfName, families := range vrfList {
			for _, family := range families {
				switch family {
				case network.IPv4:
					if vrfName == enum.DefaultVrf {
						cmdList.Add("display ip routing-table", "sh_ipv4", 2, force)
					} else {
						cmdList.Add(fmt.Sprintf("display ip routing-table vpn-instance %s", vrfName), fmt.Sprintf("sh_ipv4_%s", vrfName), 2, force)
					}
				case network.IPv6:
					if vrfName == enum.DefaultVrf {
						cmdList.Add("display ipv6 routing-table", "sh_ipv6", 2, force)
					} else {
						cmdList.Add(fmt.Sprintf("display ipv6 routing-table vpn-instance %s", vrfName), fmt.Sprintf("sh_ipv6_%s", vrfName), 2, force)
					}
				}
			}
			adapter.RunCmdListAndSave(cmdList)
		}

		ipv4TableMap = make(map[string]*network.AddressTable)
		ipv6TableMap = make(map[string]*network.AddressTable)

		for vrfName, families := range vrfList {
			for _, family := range families {
				var cmdKey string
				var parseFunc func(string, string) map[string]*network.AddressTable

				switch family {
				case network.IPv4:
					if vrfName == enum.DefaultVrf {
						cmdKey = "sh_ipv4"
					} else {
						cmdKey = fmt.Sprintf("sh_ipv4_%s", vrfName)
					}
					parseFunc = adapter.parseIpv4Route
				case network.IPv6:
					if vrfName == enum.DefaultVrf {
						cmdKey = "sh_ipv6"
					} else {
						cmdKey = fmt.Sprintf("sh_ipv6_%s", vrfName)
					}
					parseFunc = adapter.parseIpv6Route
				}

				cd, err := cmdList.Get(cmdKey)
				if err != nil {
					fmt.Printf("Error getting command result for %s: %v\n", cmdKey, err)
					continue
				}

				routeTables := parseFunc(string(cd.Data), vrfName)
				for parsedVrf, table := range routeTables {
					if family == network.IPv4 {
						ipv4TableMap[parsedVrf] = table
					} else {
						ipv6TableMap[parsedVrf] = table
					}
				}
			}
		}

		return ipv4TableMap, ipv6TableMap
	} else {
		config := adapter.GetConfig(force).(string)
		vrfList := adapter.parseVrfFromConfig(config)

		ipv4TableMap = make(map[string]*network.AddressTable)
		ipv6TableMap = make(map[string]*network.AddressTable)

		for vrfName, families := range vrfList {
			for _, family := range families {
				switch family {
				case network.IPv4:
					ipv4Routes := adapter.parseIpv4RouteFromConfig(config, vrfName)
					for vrf, table := range ipv4Routes {
						ipv4TableMap[vrf] = table
					}
				case network.IPv6:
					ipv6Routes := adapter.parseIpv6RouteFromConfig(config, vrfName)
					for vrf, table := range ipv6Routes {
						ipv6TableMap[vrf] = table
					}
				}
			}
		}
		return ipv4TableMap, ipv6TableMap
	}
}

func (adapter *UsgAdapter) parseIpv4RouteFromConfig(config string, vrfName string) map[string]*network.AddressTable {
	routeTables := make(map[string]*network.AddressTable)
	routeTable := network.NewAddressTable(network.IPv4)
	routeTables[vrfName] = routeTable

	// 定义TextFSM模板
	template := `Value Filldown VRF (\S+)
Value Required DESTINATION (\d+\.\d+\.\d+\.\d+)
Value MASK (\d+\.\d+\.\d+\.\d+)
Value INTERFACE (\S+)
Value NEXTHOP (\d+\.\d+\.\d+\.\d+)
Value DESCRIPTION (.+)
	
Start
	^ip route-static( vpn-instance ${VRF})?\s+${DESTINATION}\s+${MASK}\s+${INTERFACE}\s+${NEXTHOP}(\s+description\s+${DESCRIPTION})? -> Record
`

	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(template)
	if err != nil {
		fmt.Printf("Error parsing TextFSM template: %v\n", err)
		return routeTables
	}

	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(config, fsm, false)
	if err != nil {
		fmt.Printf("Error parsing configuration: %v\n", err)
		return routeTables
	}

	// 用于聚合相同目标网段的路由
	routeAggregation := make(map[string]*network.NextHop)

	for _, record := range parser.Dict {
		vrf := getString(record, "VRF")
		if vrf == "" {
			vrf = defaultVrf
		}

		if vrf != vrfName {
			continue
		}

		destination := getString(record, "DESTINATION")
		mask := getString(record, "MASK")
		interface_ := getString(record, "INTERFACE")
		nextHop := getString(record, "NEXTHOP")

		netKey := fmt.Sprintf("%s/%s", destination, mask)

		if _, exists := routeAggregation[netKey]; !exists {
			routeAggregation[netKey] = &network.NextHop{}
		}

		routeAggregation[netKey].AddHop(interface_, nextHop, false, false, nil)
	}

	// 将聚合后的路由添加到路由表
	for netKey, nextHopObj := range routeAggregation {
		net, err := network.ParseIPNet(netKey)
		if err != nil {
			fmt.Printf("Error parsing IPv4 network %s: %v\n", netKey, err)
			continue
		}

		err = routeTable.PushRoute(net, nextHopObj)
		if err != nil {
			fmt.Printf("Error adding IPv4 route %s: %v\n", net.String(), err)
		}
	}

	return routeTables
}

func (adapter *UsgAdapter) parseIpv6RouteFromConfig(config string, vrfName string) map[string]*network.AddressTable {
	routeTables := make(map[string]*network.AddressTable)
	routeTable := network.NewAddressTable(network.IPv6)
	routeTables[vrfName] = routeTable

	// 定义TextFSM模板
	template := `Value VRF (\S+)
Value Required DESTINATION (\S+)
Value Required PREFIX_LENGTH (\d+)
Value INTERFACE (\S+)
Value NEXTHOP (\S+)

Start
  ^ipv6 route-static vpn-instance ${VRF} ${DESTINATION} ${PREFIX_LENGTH}( ${INTERFACE})? ${NEXTHOP} -> Record
  ^ipv6 route-static ${DESTINATION} ${PREFIX_LENGTH}( ${INTERFACE})? ${NEXTHOP} -> Record
`

	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(template)
	if err != nil {
		fmt.Printf("Error parsing TextFSM template: %v\n", err)
		return routeTables
	}

	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(config, fsm, false)
	if err != nil {
		fmt.Printf("Error parsing configuration: %v\n", err)
		return routeTables
	}

	// 用于聚合相同目标网段的路由
	routeAggregation := make(map[string]*network.NextHop)

	for _, record := range parser.Dict {
		vrf := getString(record, "VRF")
		if vrf == "" {
			vrf = vrfName
		}

		if vrf != vrfName {
			continue
		}

		destination := getString(record, "DESTINATION")
		prefixLength := getString(record, "PREFIX_LENGTH")
		interface_ := getString(record, "INTERFACE")
		nextHop := getString(record, "NEXTHOP")

		netKey := fmt.Sprintf("%s/%s", destination, prefixLength)

		if _, exists := routeAggregation[netKey]; !exists {
			routeAggregation[netKey] = &network.NextHop{}
		}

		routeAggregation[netKey].AddHop(interface_, nextHop, false, false, nil)
	}

	// 将聚合后的路由添加到路由表
	for netKey, nextHopObj := range routeAggregation {
		net, err := network.ParseIPNet(netKey)
		if err != nil {
			fmt.Printf("Error parsing IPv6 network %s: %v\n", netKey, err)
			continue
		}

		err = routeTable.PushRoute(net, nextHopObj)
		if err != nil {
			fmt.Printf("Error adding IPv6 route %s: %v\n", net.String(), err)
		}
	}

	return routeTables
}

func (adapter *UsgAdapter) parseVrf(vrfTxt string) map[string][]network.IPFamily {
	vrfMap := make(map[string][]network.IPFamily)
	lines := strings.Split(vrfTxt, "\n")

	startParsing := false
	for _, line := range lines {
		if strings.Contains(line, "VPN-Instance Name") {
			startParsing = true
			continue
		}

		if startParsing {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				vrfName := fields[0]
				if vrfName == "default" {
					continue
				}
				addressFamily := fields[len(fields)-1]

				// 排除空行和可能的分隔线
				if vrfName != "" && !strings.Contains(vrfName, "-") {
					if _, exists := vrfMap[vrfName]; !exists {
						vrfMap[vrfName] = []network.IPFamily{}
					}

					switch addressFamily {
					case "IPv4":
						vrfMap[vrfName] = append(vrfMap[vrfName], network.IPv4)
					case "IPv6":
						vrfMap[vrfName] = append(vrfMap[vrfName], network.IPv6)
					}
				}
			}
		}
	}

	vrfMap["default"] = append(vrfMap["default"], network.IPv4, network.IPv6)

	return vrfMap
}

func (adapter *UsgAdapter) parseVrfFromConfig(config string) map[string][]network.IPFamily {
	vrfMap := make(map[string][]network.IPFamily)
	lines := strings.Split(config, "\n")

	var currentVrf string
	// var currentFamily network.IPFamily

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "ip vpn-instance ") {
			currentVrf = strings.TrimPrefix(line, "ip vpn-instance ")
			vrfMap[currentVrf] = []network.IPFamily{}
		} else if line == "ipv4-family" {
			// currentFamily = network.IPv4
			if !contains(vrfMap[currentVrf], network.IPv4) {
				vrfMap[currentVrf] = append(vrfMap[currentVrf], network.IPv4)
			}
		} else if line == "ipv6-family" {
			// currentFamily = network.IPv6
			if !contains(vrfMap[currentVrf], network.IPv6) {
				vrfMap[currentVrf] = append(vrfMap[currentVrf], network.IPv6)
			}
		} else if line == "#" {
			currentVrf = ""
			// currentFamily = ""
		}
	}

	// 确保默认VRF包含IPv4和IPv6
	if defaultVrf, exists := vrfMap["default"]; exists {
		if !contains(defaultVrf, network.IPv4) {
			vrfMap["default"] = append(vrfMap["default"], network.IPv4)
		}
		if !contains(defaultVrf, network.IPv6) {
			vrfMap["default"] = append(vrfMap["default"], network.IPv6)
		}
	} else {
		vrfMap["default"] = []network.IPFamily{network.IPv4, network.IPv6}
	}

	return vrfMap
}

// 辅助函数：检查切片是否包含特定元素
func contains(slice []network.IPFamily, item network.IPFamily) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

func (adapter *UsgAdapter) parseIpv4Route(shrouteText, vrfName string) map[string]*network.AddressTable {
	routeTables := make(map[string]*network.AddressTable)
	routeTable := network.NewAddressTable(network.IPv4)
	routeTables[vrfName] = routeTable

	lines := strings.Split(shrouteText, "\n")
	startParsing := false
	var currentRoutes []*struct {
		net     *network.IPNet
		nextHop *network.NextHop
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Destination/Mask") {
			startParsing = true
			continue
		}

		if !startParsing || line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 7 {
			// This is a new route entry
			destMask := fields[0]
			proto := fields[1]
			nextHop := fields[5]
			intf := fields[6]

			net, err := network.ParseIPNet(destMask)
			if err != nil {
				fmt.Printf("Error parsing IP network %s: %v\n", destMask, err)
				continue
			}

			currentNextHop := &network.NextHop{}

			if proto == "Direct" {
				currentNextHop.AddHop(intf, "", true, false, nil)
			} else {
				currentNextHop.AddHop(intf, nextHop, false, false, nil)
			}

			currentRoutes = append(currentRoutes, &struct {
				net     *network.IPNet
				nextHop *network.NextHop
			}{net, currentNextHop})

		} else if len(fields) >= 6 && len(currentRoutes) > 0 {
			// This is an additional next hop for the current route
			nextHop := fields[4]
			intf := fields[5]

			lastRoute := currentRoutes[len(currentRoutes)-1]
			lastRoute.nextHop.AddHop(intf, nextHop, false, false, nil)
		}
	}

	// Now push all collected routes to the route table
	for _, route := range currentRoutes {
		err := routeTable.PushRoute(route.net, route.nextHop)
		if err != nil {
			fmt.Printf("Error adding route %s: %v\n", route.net.String(), err)
		}
	}

	return routeTables
}

func (adapter *UsgAdapter) parseIpv6Route(shrouteText, vrfName string) map[string]*network.AddressTable {
	routeTables := make(map[string]*network.AddressTable)
	currentTable := network.NewAddressTable(network.IPv6)
	routeTables[vrfName] = currentTable

	// 使用正则表达式匹配整个路由条目
	routeEntryRegex := regexp.MustCompile(`(?m)^\sDestination\s+:[^\n]+((\s\s\w[^\n]+)+)`)

	// 查找所有匹配的路由条目
	routeEntries := routeEntryRegex.FindAllString(shrouteText, -1)

	// 用于存储等价路由的map
	equivalentRoutes := make(map[string][]*RouteEntry)

	for _, entry := range routeEntries {
		routeEntry := parseRouteEntry(entry)
		if routeEntry != nil {
			key := fmt.Sprintf("%s/%s", routeEntry.Destination, routeEntry.PrefixLength)
			equivalentRoutes[key] = append(equivalentRoutes[key], routeEntry)
		}
	}

	// 处理并添加合并后的路由
	for _, entries := range equivalentRoutes {
		addMergedRouteToTable(currentTable, entries)
	}

	return routeTables
}

func addMergedRouteToTable(table *network.AddressTable, entries []*RouteEntry) {
	if len(entries) == 0 {
		return
	}

	firstEntry := entries[0]
	net, err := network.ParseIPNet(fmt.Sprintf("%s/%s", firstEntry.Destination, firstEntry.PrefixLength))
	if err != nil {
		fmt.Printf("Error parsing IP network %s/%s: %v\n", firstEntry.Destination, firstEntry.PrefixLength, err)
		return
	}

	nextHop := &network.NextHop{}
	for _, entry := range entries {
		if entry.Protocol == "Direct" {
			nextHop.AddHop(entry.Interface, "", true, false, nil)
		} else {
			nextHop.AddHop(entry.Interface, entry.NextHop, false, false, nil)
		}
	}

	err = table.PushRoute(net, nextHop)
	if err != nil {
		fmt.Printf("Error adding route %s: %v\n", net.String(), err)
	}
}

func parseRouteEntry(entry string) *RouteEntry {
	lines := strings.Split(entry, "\n")
	if len(lines) < 2 {
		return nil
	}

	routeEntry := &RouteEntry{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 使用正则表达式匹配每行中的两个键值对
		re := regexp.MustCompile(`(\S+)\s+:\s*(\S+)\s+(\S+)\s+:\s*(.+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) != 5 {
			continue
		}

		key1, value1 := matches[1], strings.TrimSpace(matches[2])
		key2, value2 := matches[3], strings.TrimSpace(matches[4])

		assignValue := func(key, value string) {
			switch key {
			case "Destination":
				routeEntry.Destination = value
			case "PrefixLength":
				routeEntry.PrefixLength = value
			case "NextHop":
				routeEntry.NextHop = value
			case "Preference":
				routeEntry.Preference = value
			case "Cost":
				routeEntry.Cost = value
			case "Protocol":
				routeEntry.Protocol = value
			case "RelayNextHop":
				routeEntry.RelayNextHop = value
			case "TunnelID":
				routeEntry.TunnelID = value
			case "Interface":
				routeEntry.Interface = value
			case "Flags":
				routeEntry.Flags = value
			}
		}

		assignValue(key1, value1)
		assignValue(key2, value2)
	}

	return routeEntry
}

type RouteEntry struct {
	Destination  string
	PrefixLength string
	NextHop      string
	Preference   string
	Cost         string
	Protocol     string
	RelayNextHop string
	TunnelID     string
	Interface    string
	Flags        string
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

func (adapter *UsgAdapter) ParseName(force bool) string {
	//cmdList := adapter.Prepare(force)
	// 	var shverText string
	// 	if adapter.Type == api.LiveAdapter {

	// 	cmdList := adapter.CliCmdList

	// 	cd, err := cmdList.Get("sh_run")
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	shverText = string(cd.Data)
	// } else {
	// 	shverText = adapter.GetConfig(force).(string)
	// }

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
func (adapter *UsgAdapter) BatchRun(p interface{}) (interface{}, error) {
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
func (adapter *UsgAdapter) BatchConfig(p ...interface{}) (interface{}, error) {

	info := adapter.info.BaseInfo

	base := terminal.BaseInfo{
		Host:     info.Host,
		Username: info.Username,
		Password: info.Password,
		AuthPass: info.AuthPass,
		Telnet:   info.Telnet,
	}

	exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.HuaWei, &base)
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

func (bia *UsgAdapter) AttachChannel(out chan string) bool {
	return false
}

func (bia *UsgAdapter) GetRawConfig(_ string, force bool) (any, error) {
	return bia.GetConfig(force), nil
}
