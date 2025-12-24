package dptech

// import (
// 	"bytes"
// 	"fmt"
// 	"regexp"
// 	"strings"
// 	"text/template"

// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
// 	"github.com/netxops/utils/network"
// 	"github.com/netxops/utils/policy"
// 	"github.com/netxops/utils/service"
// 	"github.com/netxops/utils/tools"
// )

// const staticNatDefaultSuffix = "SERVER"

// var (
// 	staticNatTemplate = ConfigTemplate{
// 		CommandPrefix: "nat static",
// 		NameFormat:    "%s_%s_%s_%s",
// 		Keys:          []string{"ToZone", "SystemName", "AppName", "ServerName"},
// 		Sections: []ConfigSection{
// 			{Name: "base", Template: "{{.CommandPrefix}} {{.Name}} interface {{.FromInterface}} global-address {{.GlobalIP}} local-address {{.LocalIP}}"},
// 			// {Name: "service", Template: "{{.CommandPrefix}} {{.Name}} service {{.Protocol}} global-port {{.GlobalPort}} local-port {{.LocalPort}}", Optional: true},
// 			// {Name: "description", Template: "{{.CommandPrefix}} {{.Name}} description {{.Description}}"},
// 		},
// 	}

// 	destinationNatTemplate = ConfigTemplate{
// 		CommandPrefix: "nat destination-nat",
// 		NameFormat:    "%s_%s_%s_%s",
// 		Keys:          []string{"ToZone", "SystemName", "AppName", "ServerName"},
// 		Sections: []ConfigSection{
// 			{Name: "base", Template: "{{.CommandPrefix}} {{.Name}} interface {{.FromInterface}} global-address {{.GlobalIP}} local-address {{.LocalIP}}"},
// 			{Name: "service", Template: "{{.CommandPrefix}} {{.Name}} service {{.Protocol}} global-port {{.GlobalPort}} local-port {{.LocalPort}}", Optional: true},
// 			{Name: "description", Template: "{{.CommandPrefix}} {{.Name}} description {{.Description}}"},
// 		},
// 	}

// 	policyTemplate = ConfigTemplate{
// 		CommandPrefix: "security-policy",
// 		NameFormat:    "%s_%s_%s_policy01",
// 		Keys:          []string{"FromZone", "SystemName", "AppName"},
// 		Sections: []ConfigSection{
// 			// {Name: "base", Template: "{{.CommandPrefix}} {{.Name}} src-zone {{.SrcZone}} dst-zone {{.DstZone}}"},
// 			{Name: "src-address", Template: "{{.CommandPrefix}} {{.Name}} src-zone {{.FromZone}} dst-zone {{.ToZone}} src-address address-object {{.SrcAddr}}"},
// 			{Name: "dst-address", Template: "{{.CommandPrefix}} {{.Name}} src-zone {{.FromZone}} dst-zone {{.ToZone}} dst-address address-object {{.DstAddr}}"},
// 			{Name: "service", Template: "{{.CommandPrefix}} {{.Name}} src-zone {{.FromZone}} dst-zone {{.ToZone}} service {{.Service}}"},
// 			{Name: "action", Template: "{{.CommandPrefix}} {{.Name}} src-zone {{.FromZone}} dst-zone {{.ToZone}} action {{.Action}}"},
// 			{Name: "description", Template: "{{.CommandPrefix}} {{.Name}} src-zone {{.FromZone}} dst-zone {{.ToZone}} description {{.Description}}"},
// 		},
// 	}

// 	snatTemplate = ConfigTemplate{
// 		CommandPrefix: "nat source-nat",
// 		NameFormat:    "NAT_%s_to_%s_dynamic",
// 		Keys:          []string{"FromZone", "ToZone"},
// 		Sections: []ConfigSection{
// 			{Name: "base", Template: "{{.CommandPrefix}} {{.Name}} interface {{.Interface}}"},
// 			{Name: "src-address", Template: "{{.CommandPrefix}} {{.Name}} src-address address-object {{.SrcAddr}}"},
// 			{Name: "dst-address", Template: "{{.CommandPrefix}} {{.Name}} dst-address address-object {{.DstAddr}}", Optional: true},
// 			{Name: "service", Template: "{{.CommandPrefix}} {{.Name}} service {{.Service}}"},
// 			{Name: "action", Template: "{{.CommandPrefix}} {{.Name}} action address-pool {{.AddressPool}}"},
// 			// {Name: "port", Template: "{{.CommandPrefix}} {{.Name}} port {{.PortStart}} to {{.PortEnd}}", Optional: true},
// 		},
// 	}
// )

// type ConfigTemplate struct {
// 	CommandPrefix string
// 	NameFormat    string
// 	Sections      []ConfigSection
// 	Keys          []string
// }

// type ConfigSection struct {
// 	Name     string
// 	Template string
// 	Optional bool
// }

// type DptechTemplates struct {
// 	Node        firewall.FirewallNode
// 	PolicyNamer *naming.Namer
// 	NatNamer    *naming.Namer
// 	SnatNamer   *naming.Namer
// }

// func NewDptechTemplates(node firewall.FirewallNode) *DptechTemplates {
// 	return &DptechTemplates{
// 		Node:        node,
// 		PolicyNamer: naming.NewNamer("%s_%s_%s_policy01", []string{"FromZone", "SystemName", "AppName"}),
// 		NatNamer:    naming.NewNamer("%s_%s_%s_%s", []string{"ToZone", "SystemName", "AppName", "ServerName"}),
// 		SnatNamer:   naming.NewNamer("NAT_%s_to_%s_dynamic", []string{"FromZone", "ToZone"}),
// 	}
// }

// func (at *DptechTemplates) getUniqueName(parts []string, prefix string, maxLength int) string {
// 	baseName := strings.Join(parts, "_")
// 	if len(baseName) > maxLength {
// 		baseName = baseName[:maxLength]
// 	}

// 	name := prefix + "_" + baseName
// 	counter := 1

// 	for at.Node.HasObjectName(name) ||
// 		at.Node.HasPolicyName(name) ||
// 		at.Node.HasNatName(name) ||
// 		at.Node.HasPoolName(name) {

// 		counterStr := fmt.Sprintf("_%d", counter)
// 		name = prefix + "_" + baseName[:maxLength-len(prefix)-len(counterStr)] + counterStr
// 		counter++
// 	}

// 	return name
// }

// func (at *DptechTemplates) getUniqueAddressName(baseName string) string {
// 	counter := 1
// 	maxLength := 63 // 假设最大长度为63个字符
// 	name := baseName

// 	for at.Node.HasObjectName(name) {
// 		// 去除结尾的数字部分
// 		baseNameWithoutSuffix := regexp.MustCompile(`\d+$`).ReplaceAllString(baseName, "")

// 		// 如果名称已存在，添加计数器
// 		suffix := fmt.Sprintf("%02d", counter)

// 		// 确保名称长度不超过最大长度
// 		if len(baseNameWithoutSuffix)+len(suffix) > maxLength {
// 			// 如果超过最大长度，截断baseName
// 			truncatedLength := maxLength - len(suffix)
// 			name = baseNameWithoutSuffix[:truncatedLength] + suffix
// 		} else {
// 			name = baseNameWithoutSuffix + suffix
// 		}

// 		counter++
// 	}

// 	return name
// }

// func (at *DptechTemplates) getUniqueServiceName(baseName string) string {
// 	counter := 1
// 	maxLength := 63 // 假设最大长度为63个字符
// 	name := baseName

// 	for at.Node.HasObjectName(name) {
// 		suffix := fmt.Sprintf("_%02d", counter)
// 		if len(baseName)+len(suffix) > maxLength {
// 			truncatedLength := maxLength - len(suffix)
// 			name = baseName[:truncatedLength] + suffix
// 		} else {
// 			name = baseName + suffix
// 		}
// 		counter++
// 	}

// 	return name
// }

// func (at *DptechTemplates) getUniquePolicyName(baseName string) string {
// 	counter := 1
// 	maxLength := 63 // 假设最大长度为63个字符
// 	name := baseName

// 	for at.Node.HasPolicyName(name) {
// 		suffix := fmt.Sprintf("_%02d", counter)
// 		if len(baseName)+len(suffix) > maxLength {
// 			truncatedLength := maxLength - len(suffix)
// 			name = baseName[:truncatedLength] + suffix
// 		} else {
// 			name = baseName + suffix
// 		}
// 		counter++
// 	}

// 	return name
// }

// func (at *DptechTemplates) getUniquePoolName(baseName string) string {
// 	counter := 1
// 	maxLength := 63 // 假设最大长度为63个字符
// 	name := baseName

// 	for at.Node.HasPoolName(name) {
// 		suffix := fmt.Sprintf("_%02d", counter)
// 		if len(baseName)+len(suffix) > maxLength {
// 			truncatedLength := maxLength - len(suffix)
// 			name = baseName[:truncatedLength] + suffix
// 		} else {
// 			name = baseName + suffix
// 		}
// 		counter++
// 	}

// 	return name
// }

// func (at *DptechTemplates) getUniqueNatName(baseName string) string {
// 	counter := 1
// 	maxLength := 63 // 假设最大长度为63个字符
// 	name := baseName

// 	for at.Node.HasNatName(name) {
// 		// 如果名称已存在，添加计数器
// 		suffix := fmt.Sprintf("_%02d", counter)

// 		// 确保名称长度不超过最大长度
// 		if len(baseName)+len(suffix) > maxLength {
// 			// 如果超过最大长度，截断baseName
// 			truncatedLength := maxLength - len(suffix)
// 			name = baseName[:truncatedLength] + suffix
// 		} else {
// 			name = baseName + suffix
// 		}

// 		counter++
// 	}

// 	return name
// }

// // func (at *DptechTemplates) MakePolicy(from, to api.Port, intent *policy.Intent) string {
// // 	data := map[string]interface{}{
// // 		"FromZone":      from.(firewall.ZoneFirewall).Zone(),
// // 		"ToZone":        to.(firewall.ZoneFirewall).Zone(),
// // 		"SystemName":    intent.MetaData["system_name"],
// // 		"AppName":       intent.MetaData["app_name"],
// // 		"CommandPrefix": policyTemplate.CommandPrefix,
// // 		"Action":        "permit",
// // 		"Description":   fmt.Sprintf("NETACC_%s_%s", intent.TicketNumber, intent.SubTicket),
// // 	}

// // 	policyName := at.PolicyNamer.GenerateUniqueName(data, at.Node.HasPolicyName)
// // 	data["Name"] = policyName

// // 	var clis []string

// // 	// Source address
// // 	srcAddr, srcCli := at.MakeNetworkObjectCli(intent, intent.Src(), policyName, data, true)
// // 	data["SrcAddr"] = srcAddr

// // 	// Destination address
// // 	dstAddr, dstCli := at.MakeNetworkObjectCli(intent, intent.Dst(), policyName, data, false)
// // 	data["DstAddr"] = dstAddr

// // 	// Service
// // 	if intent.Service().IsEmpty() {
// // 		data["Service"] = "any"
// // 	} else {
// // 		groupName, serviceClis, groupCli := at.MakeServiceObjectCli(intent, intent.Service(), policyName)
// // 		if groupName != "" {
// // 			data["Service"] = groupName
// // 			clis = append(clis, serviceClis...)
// // 			clis = append(clis, groupCli)
// // 		} else {
// // 			data["Service"] = "any"
// // 		}
// // 	}

// // 	policyConfig := at.generateConfig(policyTemplate, data)

// // 	return strings.Join([]string{srcCli, dstCli, strings.Join(clis, "\n"), policyConfig}, "\n")
// // }

// func (at *DptechTemplates) MakeSnatCli(from, out api.Port, intent *policy.Intent) string {
// 	data := map[string]interface{}{
// 		"FromZone":      from.(firewall.ZoneFirewall).Zone(),
// 		"ToZone":        out.(firewall.ZoneFirewall).Zone(),
// 		"CommandPrefix": snatTemplate.CommandPrefix,
// 		"Interface":     out.Name(),
// 		"Description":   fmt.Sprintf("NETACC_%s_%s", intent.TicketNumber, intent.SubTicket),
// 	}

// 	natName := at.SnatNamer.GenerateUniqueName(data, at.Node.HasNatName)
// 	data["Name"] = natName

// 	// Source address
// 	srcAddr, _ := at.MakeNetworkObjectCli(intent, intent.Src(), natName, data, true)
// 	data["SrcAddr"] = srcAddr

// 	// Destination address
// 	if !intent.Dst().IsEmpty() {
// 		dstAddr, _ := at.MakeNetworkObjectCli(intent, intent.Dst(), natName, data, false)
// 		data["DstAddr"] = dstAddr
// 	}

// 	// Service
// 	if intent.Service().IsEmpty() || intent.Service().Protocol() == service.IP {
// 		data["Service"] = "any"
// 	} else {
// 		srvObj, _, _ := at.MakeServiceObjectCli(intent, intent.Service(), natName)
// 		data["Service"] = srvObj
// 	}

// 	// Address pool
// 	addressPool, ok := intent.MetaData["address_pool"]
// 	if !ok || addressPool == "" {
// 		addressPool = fmt.Sprintf("Dynamic-PAT-%s-IN-%s-Address-Pool", out.Name(), from.Name())
// 	}
// 	data["AddressPool"] = addressPool

// 	return at.generateConfig(snatTemplate, data)
// }

// func (at *DptechTemplates) MakeDestinationNatCli(from, out api.Port, intent *policy.Intent) string {
// 	data := map[string]interface{}{
// 		"CommandPrefix": destinationNatTemplate.CommandPrefix,
// 		"FromZone":      from.(firewall.ZoneFirewall).Zone(),
// 		"ToZone":        out.(firewall.ZoneFirewall).Zone(),
// 		"FromInterface": from.Name(),
// 		"ToInterface":   out.Name(),
// 		"SystemName":    intent.MetaData["system_name"],
// 		"AppName":       intent.MetaData["app_name"],
// 		"ServerName":    intent.MetaData["server_name"],
// 		"GlobalIP":      intent.Dst().GenerateNetwork().First().String(),
// 		"LocalIP":       intent.RealIp,
// 		"Description":   fmt.Sprintf("NETACC_%s_%s", intent.TicketNumber, intent.SubTicket),
// 	}

// 	natName := at.NatNamer.GenerateUniqueName(data, at.Node.HasNatName)
// 	data["Name"] = natName

// 	if !intent.Service().IsEmpty() {
// 		srv := intent.Service().MustOneServiceEntry()
// 		if srv.Protocol() == service.TCP || srv.Protocol() == service.UDP {
// 			l4srv := srv.(*service.L4Service)
// 			dport := l4srv.DstPort()
// 			if dport != nil && !dport.IsFull() {
// 				port := dport.List()[0]
// 				data["Protocol"] = strings.ToLower(srv.Protocol().String())
// 				data["GlobalPort"] = port.Low()
// 				data["LocalPort"] = port.Low()
// 			}
// 		}
// 	}

// 	return at.generateConfig(destinationNatTemplate, data)
// }

// func (at *DptechTemplates) MakeStaticNatCli(from, out api.Port, intent *policy.Intent) string {
// 	data := map[string]interface{}{
// 		"CommandPrefix": staticNatTemplate.CommandPrefix,
// 		"FromZone":      from.(firewall.ZoneFirewall).Zone(),
// 		"ToZone":        out.(firewall.ZoneFirewall).Zone(),
// 		"FromInterface": from.Name(),
// 		"ToInterface":   out.Name(),
// 		"SystemName":    intent.MetaData["system_name"],
// 		"AppName":       intent.MetaData["app_name"],
// 		"ServerName":    intent.MetaData["server_name"],
// 		"GlobalIP":      intent.Dst().GenerateNetwork().First().String(),
// 		"LocalIP":       intent.RealIp,
// 		"Description":   fmt.Sprintf("NETACC_%s_%s", intent.TicketNumber, intent.SubTicket),
// 	}

// 	natName := at.NatNamer.GenerateUniqueName(data, at.Node.HasNatName)
// 	data["Name"] = natName

// 	if !intent.Service().IsEmpty() {
// 		srv := intent.Service().MustOneServiceEntry()
// 		if srv.Protocol() == service.TCP || srv.Protocol() == service.UDP {
// 			l4srv := srv.(*service.L4Service)
// 			dport := l4srv.DstPort()
// 			if dport != nil && !dport.IsFull() {
// 				port := dport.List()[0]
// 				data["Protocol"] = strings.ToLower(srv.Protocol().String())
// 				data["GlobalPort"] = port.Low()
// 				data["LocalPort"] = port.Low()
// 			}
// 		}
// 	}

// 	return at.generateConfig(staticNatTemplate, data)
// }

// func (at *DptechTemplates) MakePolicy(from, to api.Port, intent *policy.Intent) string {
// 	data := map[string]interface{}{
// 		"FromZone":            from.(firewall.ZoneFirewall).Zone(),
// 		"ToZone":              to.(firewall.ZoneFirewall).Zone(),
// 		"SystemName":          intent.MetaData["system_name"],
// 		"AppName":             intent.MetaData["app_name"],
// 		"CommandPrefix":       policyTemplate.CommandPrefix,
// 		"Action":              "permit",
// 		"Description":         fmt.Sprintf("NETACC_%s_%s", intent.TicketNumber, intent.SubTicket),
// 		"IsUserDefineService": "true",
// 	}

// 	policyName := at.PolicyNamer.GenerateUniqueName(data, at.Node.HasPolicyName)
// 	data["Name"] = policyName

// 	var clis []string

// 	// Source address
// 	srcAddr, srcCli := at.MakeNetworkObjectCli(intent, intent.Src(), policyName, data, true)
// 	data["SrcAddr"] = srcAddr

// 	// Destination address
// 	dstAddr, dstCli := at.MakeNetworkObjectCli(intent, intent.Dst(), policyName, data, false)
// 	data["DstAddr"] = dstAddr

// 	// Service
// 	if intent.Service().IsEmpty() {
// 		data["Service"] = "any"
// 	} else {
// 		isUserDefineService := strings.ToLower(intent.MetaData["IsUserDefineService"])
// 		s := intent.Service()
// 		fmt.Println(s.HasProtocol("tcp"), s.HasProtocol("udp"), s.HasProtocol("icmp"), !intent.Service().HasRange(true), ((s.HasProtocol("tcp") || s.HasProtocol("udp") || s.HasProtocol("icmp")) || !intent.Service().HasRange(true)))
// 		if isUserDefineService == "true" && ((s.HasProtocol("tcp") || s.HasProtocol("udp") || s.HasProtocol("icmp")) || !intent.Service().HasRange(true)) {
// 			// 使用用户定义的服务
// 			serviceClis := at.MakeUserDefinedServiceCli(intent.Service(), policyName, data)
// 			clis = append(clis, serviceClis...)
// 			data["Service"] = ""
// 		} else {
// 			// 使用原来的服务对象逻辑
// 			groupName, serviceClis, groupCli := at.MakeServiceObjectCli(intent, intent.Service(), policyName)
// 			if groupName != "" {
// 				data["Service"] = fmt.Sprintf("service-group %s", groupName)
// 				clis = append(clis, serviceClis...)
// 				clis = append(clis, groupCli)
// 			} else {
// 				data["Service"] = "any"
// 			}
// 		}
// 	}

// 	policyConfig := at.generateConfig(policyTemplate, data)

// 	// 如果是用户定义的服务，我们需要修改策略配置
// 	if isUserDefineService := strings.ToLower(intent.MetaData["IsUserDefineService"]); isUserDefineService == "true" {
// 		policyConfig = at.modifyPolicyForUserDefinedService(policyConfig, intent.Service())
// 	}

// 	return strings.Join([]string{srcCli, dstCli, strings.Join(clis, "\n"), policyConfig}, "\n")
// }

// func (at *DptechTemplates) MakeUserDefinedServiceCli(sg *service.Service, policyName string, data map[string]interface{}) []string {
// 	var serviceClis []string
// 	prefix := fmt.Sprintf("{{.CommandPrefix}} {{.Name}} src-zone {{.FromZone}} dst-zone {{.ToZone}} service")

// 	// 使用模板渲染前缀
// 	tmpl, err := template.New("prefix").Parse(prefix)
// 	if err != nil {
// 		panic(err)
// 	}
// 	var buf bytes.Buffer
// 	err = tmpl.Execute(&buf, data)
// 	if err != nil {
// 		panic(err)
// 	}
// 	renderedPrefix := buf.String()

// 	if sg.HasProtocol("tcp") {
// 		serviceClis = append(serviceClis, fmt.Sprintf("%s user-define-service TCP", renderedPrefix))
// 	}
// 	if sg.HasProtocol("udp") {
// 		serviceClis = append(serviceClis, fmt.Sprintf("%s user-define-service UDP", renderedPrefix))
// 	}
// 	if sg.HasProtocol("icmp") {
// 		serviceClis = append(serviceClis, fmt.Sprintf("%s user-define-service ICMP", renderedPrefix))
// 	}

// 	list := []*service.L4Service{}
// 	list = append(list, sg.TCPList...)
// 	list = append(list, sg.UDPList...)

// 	for _, l4 := range list {
// 		protocol := strings.ToLower(l4.Protocol().String())
// 		dstPort := l4.DstPort()
// 		if dstPort == nil {
// 			continue
// 		}

// 		for it := dstPort.Iterator(); it.HasNext(); {
// 			_, f := it.Next()
// 			serviceCli := fmt.Sprintf("%s user-define-service %s dst-port %d", renderedPrefix, strings.ToUpper(protocol), f.Low())
// 			serviceClis = append(serviceClis, serviceCli)
// 		}
// 	}

// 	return serviceClis
// }

// func (at *DptechTemplates) modifyPolicyForUserDefinedService(policyConfig string, sg *service.Service) string {
// 	// 移除原有的 service 行
// 	lines := strings.Split(policyConfig, "\n")
// 	var newLines []string
// 	for _, line := range lines {
// 		if !strings.Contains(line, "service") {
// 			newLines = append(newLines, line)
// 		}
// 	}
// 	return strings.Join(newLines, "\n")
// }

// // func (at *DptechTemplates) generateConfig(confTemp ConfigTemplate, data map[string]interface{}) string {
// // 	var clis []string

// // 	var serverName string
// // 	if s, ok := data["ServerName"]; ok {
// // 		serverName = s.(string)
// // 	}
// // 	if serverName == "" {
// // 		serverName = "SERVER"
// // 	}
// // 	name := fmt.Sprintf(confTemp.NameFormat, data["ZoneName"], data["SystemName"], data["AppName"], serverName)
// // 	name = at.getUniqueNatName(name)
// // 	data["Name"] = name

// // 	for _, section := range confTemp.Sections {
// // 		if section.Optional && data[section.Name] == nil {
// // 			continue
// // 		}

// // 		tmpl, err := template.New(section.Name).Parse(section.Template)
// // 		if err != nil {
// // 			panic(err)
// // 		}

// // 		var buf bytes.Buffer
// // 		err = tmpl.Execute(&buf, data)
// // 		if err != nil {
// // 			panic(err)
// // 		}

// // 		clis = append(clis, buf.String())
// // 	}

// // 	return strings.Join(clis, "\n")
// // }

// func (at *DptechTemplates) generateConfig(confTemp ConfigTemplate, data map[string]interface{}) string {
// 	var clis []string

// 	// 生成名称
// 	var nameArgs []interface{}
// 	for _, key := range confTemp.Keys {
// 		if value, ok := data[key]; ok {
// 			nameArgs = append(nameArgs, value)
// 		} else {
// 			// 如果缺少必要的键，使用默认值或返回错误
// 			nameArgs = append(nameArgs, "DEFAULT")
// 		}
// 	}
// 	name := fmt.Sprintf(confTemp.NameFormat, nameArgs...)
// 	name = at.getUniqueNatName(name)
// 	data["Name"] = name

// 	// 生成配置
// 	for _, section := range confTemp.Sections {
// 		if section.Optional {
// 			// 检查是否所有必要的字段都存在
// 			allFieldsPresent := true
// 			for _, field := range getTemplateFields(section.Template) {
// 				if _, ok := data[field]; !ok {
// 					allFieldsPresent = false
// 					break
// 				}
// 			}
// 			if !allFieldsPresent {
// 				continue
// 			}
// 		}

// 		tmpl, err := template.New(section.Name).Parse(section.Template)
// 		if err != nil {
// 			// 处理错误，可能是记录日志或返回错误
// 			continue
// 		}

// 		var buf bytes.Buffer
// 		err = tmpl.Execute(&buf, data)
// 		if err != nil {
// 			// 处理错误，可能是记录日志或返回错误
// 			continue
// 		}

// 		clis = append(clis, buf.String())
// 	}

// 	return strings.Join(clis, "\n")
// }

// // 辅助函数：从模板字符串中提取字段名
// func getTemplateFields(tmpl string) []string {
// 	var fields []string
// 	re := regexp.MustCompile(`{{\.(\w+)}}`)
// 	matches := re.FindAllStringSubmatch(tmpl, -1)
// 	for _, match := range matches {
// 		fields = append(fields, match[1])
// 	}
// 	return fields
// }

// // func (at *DptechTemplates) MakeNetworkObjectCli(intent *policy.Intent, ng *network.NetworkGroup, policyName string) (objectName, cli string) {
// // 	// 生成唯一的对象名称
// // 	objectName = fmt.Sprintf("%s_addr01", policyName)
// // 	objectName = at.getUniqueAddressName(objectName)

// // 	net := ng.GenerateNetwork()

// // 	var address string
// // 	switch net.AddressType() {
// // 	// case network.HOST:
// // 	// objectType = "host"
// // 	// address = net.String()
// // 	case network.SUBNET, network.HOST:
// // 		// objectType = "subnet"
// // 		ipNet, _ := net.IPNet()
// // 		// if net.Type() == network.IPv4 {
// // 		// 	address = fmt.Sprintf("%s %s", ipNet.IP, network.MasktoIP(ipNet.Mask))
// // 		// } else {
// // 		address = fmt.Sprintf("%s/%d", ipNet.IP, ipNet.Prefix())
// // 		// }
// // 	case network.RANGE:
// // 		// objectType = "range"
// // 		address = fmt.Sprintf("range %s %s", net.First().String(), net.Last().String())
// // 	default:
// // 		panic(fmt.Sprintf("Unsupported network type: %v", net.AddressType()))
// // 	}

// // 	cli = fmt.Sprintf("address-object %s %s", objectName, address)

// // 	return objectName, cli
// // }

// func (at *DptechTemplates) MakeNetworkObjectCli(intent *policy.Intent, ng *network.NetworkGroup, policyName string, metaData map[string]interface{}, isSource bool) (objectName, cli string) {
// 	var baseName string
// 	if isSource {
// 		// For source address
// 		fromZone := tools.ConditionalT(metaData["FromZone"] == nil, "", metaData["FromZone"])
// 		systemName := tools.ConditionalT(metaData["SystemName"] == nil, "", metaData["SystemName"])
// 		appName := tools.ConditionalT(metaData["AppName"] == nil, "", metaData["AppName"])
// 		serverName := tools.ConditionalT(metaData["ServerName"] == nil, "", metaData["ServerName"])
// 		siteName := tools.ConditionalT(metaData["SiteName"] == nil, "", metaData["SiteName"])

// 		if serverName != "" {
// 			baseName = fmt.Sprintf("%s_%s_%s_%s", fromZone, systemName, appName, serverName)
// 		} else if siteName != "" {
// 			baseName = fmt.Sprintf("%s_%s_%s", siteName, fromZone, "Address")
// 		} else {
// 			baseName = fmt.Sprintf("%s_%s_%s", fromZone, systemName, appName)
// 		}
// 	} else {
// 		// For destination address
// 		baseName = fmt.Sprintf("%s_addr01", policyName)
// 	}

// 	// Generate unique object name
// 	objectName = at.getUniqueAddressName(baseName)

// 	net := ng.GenerateNetwork()

// 	var address string
// 	switch net.AddressType() {
// 	case network.SUBNET, network.HOST:
// 		ipNet, _ := net.IPNet()
// 		address = fmt.Sprintf("%s/%d", ipNet.IP, ipNet.Prefix())
// 	case network.RANGE:
// 		address = fmt.Sprintf("range %s %s", net.First().String(), net.Last().String())
// 	default:
// 		panic(fmt.Sprintf("Unsupported network type: %v", net.AddressType()))
// 	}

// 	cli = fmt.Sprintf("address-object %s %s", objectName, address)

// 	return objectName, cli
// }

// func (at *DptechTemplates) MakeServiceObjectCli(intent *policy.Intent, sg *service.Service, policyName string) (groupName string, serviceClis []string, groupCli string) {
// 	var serviceObjects []string

// 	// Generate unique group name
// 	groupName = fmt.Sprintf("%s_service01", policyName)
// 	groupName = at.getUniqueServiceName(groupName)

// 	// Handle L3Protocol
// 	for _, l3 := range sg.L3Protocol {
// 		objectName := fmt.Sprintf("IP_%d", l3.Protocol())
// 		serviceCli := fmt.Sprintf("service-object %s protocol %d", objectName, l3.Protocol())
// 		serviceClis = append(serviceClis, serviceCli)
// 		serviceObjects = append(serviceObjects, objectName)
// 	}

// 	// Handle ICMPProto
// 	for _, icmp := range sg.ICMPProto {
// 		protocol := strings.ToUpper(icmp.Protocol().String())
// 		objectName := protocol

// 		if icmp.IcmpType == service.ICMP_DEFAULT_TYPE {
// 			serviceCli := fmt.Sprintf("service-object %s protocol %s", objectName, strings.ToLower(protocol))
// 			serviceClis = append(serviceClis, serviceCli)
// 		} else if icmp.IcmpCode == service.ICMP_DEFAULT_CODE {
// 			objectName = fmt.Sprintf("%s_%d", protocol, icmp.IcmpType)
// 			serviceCli := fmt.Sprintf("service-object %s protocol %s type %d", objectName, strings.ToLower(protocol), icmp.IcmpType)
// 			serviceClis = append(serviceClis, serviceCli)
// 		} else {
// 			objectName = fmt.Sprintf("%s_%d_%d", protocol, icmp.IcmpType, icmp.IcmpCode)
// 			serviceCli := fmt.Sprintf("service-object %s protocol %s type %d code %d", objectName, strings.ToLower(protocol), icmp.IcmpType, icmp.IcmpCode)
// 			serviceClis = append(serviceClis, serviceCli)
// 		}
// 		serviceObjects = append(serviceObjects, objectName)
// 	}

// 	// Handle TCPList and UDPList
// 	for _, l4List := range []struct {
// 		protocol string
// 		services []*service.L4Service
// 	}{
// 		{"tcp", sg.TCPList},
// 		{"udp", sg.UDPList},
// 	} {
// 		for _, l4 := range l4List.services {
// 			dstPort := l4.DstPort()
// 			if dstPort == nil || dstPort.IsFull() {
// 				continue
// 			}

// 			var portRanges []string
// 			for it := dstPort.Iterator(); it.HasNext(); {
// 				_, f := it.Next()
// 				if f.Low().Cmp(f.High()) == 0 {
// 					portRanges = append(portRanges, fmt.Sprintf("%d", f.Low()))
// 				} else {
// 					portRanges = append(portRanges, fmt.Sprintf("%d-%d", f.Low(), f.High()))
// 				}
// 			}

// 			objectName := fmt.Sprintf("%s_%s", strings.ToUpper(l4List.protocol), strings.Join(portRanges, "_"))
// 			serviceCli := fmt.Sprintf("service-object %s protocol %s src-port 0 to 65535 dst-port %s",
// 				objectName,
// 				l4List.protocol,
// 				strings.Replace(strings.Join(portRanges, ","), "-", " to ", -1))

// 			serviceClis = append(serviceClis, serviceCli)
// 			serviceObjects = append(serviceObjects, objectName)
// 		}
// 	}

// 	// Generate service group CLI
// 	if len(serviceObjects) > 0 {
// 		// groupCli = fmt.Sprintf("service-group %s", groupName)
// 		for _, obj := range serviceObjects {
// 			groupCli += fmt.Sprintf("\nservice-group %s service-object %s", groupName, obj)
// 		}
// 	}

// 	return groupName, serviceClis, groupCli
// }
