package secpath

// const staticNatDefaultSuffix = "SERVER"
// const SectionSeparator = "#"

// var globalIntentLayout = `{set:intent.src_template="source address {cidr}"}
// {set:intent.dst_template="{ip}"}
// {set:intent.service_template="{full_service}"}
// {set:intent.separator={newline}}
// {set:service.range_format=" "}
// {set:service.l3_format.template="protocol {protocol:lower};"}
// {set:service.icmp_format.template="{protocol:lower} type {type} code {code};"}
// {set:service.tcp_format.template="{protocol:lower} src_port {if:src_port=='0-65535'}any{else}{src_port:range}{endif} dst_port {dst_port:range}"}
// {set:service.udp_format.template="{protocol:lower} src_port {if:src_port=='0-65535'}any{else}{src_port:range}{endif} dst_port {dst_port:range}"}
// {set:service.separator={newline}}`

// type SecPathNamer struct {
// 	aclCounter   int
// 	usedAclNames map[string]bool
// }

// // PolicyResult 是一个统一的返回结构体，用于简化策略相关函数的返回值处理
// type PolicyResult struct {
// 	Keys        []string          // 存储生成的键列表
// 	CLIs        []string          // 生成的CLI命令列表
// 	FlyObject   map[string]string // 飞对象（用于存储额外的对象信息）
// 	CLIString   string            // CLI命令的字符串形式
// 	Error       error             // 如果发生错误，则存储错误信息
// 	IsGlobalNat bool              // 标识是否为全局NAT策略
// }

// // NewPolicyResult 创建一个新的 PolicyResult 实例
// func NewPolicyResult() *PolicyResult {
// 	return &PolicyResult{
// 		CLIs:      []string{},
// 		FlyObject: make(map[string]string),
// 	}
// }

// // SetCLIs 设置 CLI 命令列表
// func (pr *PolicyResult) SetCLIs(clis []string) {
// 	pr.CLIs = clis
// 	pr.CLIString = strings.Join(clis, "\n")
// }

// // AddCLI 添加单个 CLI 命令
// func (pr *PolicyResult) AddCLI(cli string) {
// 	pr.CLIs = append(pr.CLIs, cli)
// 	pr.CLIString = strings.Join(pr.CLIs, "\n")
// }

// // SetFlyObject 设置飞对象
// func (pr *PolicyResult) SetFlyObject(key, value string) {
// 	pr.FlyObject[key] = value
// }

// // SetError 设置错误信息
// func (pr *PolicyResult) SetError(err error) {
// 	pr.Error = err
// }

// // IsValid 检查结果是否有效（没有错误）
// func (pr *PolicyResult) IsValid() bool {
// 	return pr.Error == nil
// }

// // MergeFlyObjects 合并另一个 PolicyResult 的 FlyObject 到当前的 PolicyResult
// func (pr *PolicyResult) MergeFlyObjects(otherFlyObjects map[string]string) {
// 	if pr.FlyObject == nil {
// 		pr.FlyObject = make(map[string]string)
// 	}
// 	for key, value := range otherFlyObjects {
// 		if existingValue, exists := pr.FlyObject[key]; exists {
// 			// 如果键已存在，则将值合并，用换行符分隔
// 			pr.FlyObject[key] = existingValue + "\n" + value
// 		} else {
// 			// 如果键不存在，直接添加
// 			pr.FlyObject[key] = value
// 		}
// 	}
// }

// // MergeCLIs 合并另一个 PolicyResult 的 CLIs 到当前的 PolicyResult
// func (pr *PolicyResult) MergeCLIs(otherCLIs []string) {
// 	pr.CLIs = append(pr.CLIs, otherCLIs...)
// 	pr.CLIString = strings.Join(pr.CLIs, "\n")
// }

// // // CLIs 返回当前 PolicyResult 的 CLI 命令列表
// // func (pr *PolicyResult) CLIs() []string {
// //     return pr.CLIs
// // }

// type NameGenerator func(data interface{}, attempt int) string
// type CheckFunction func(name string) bool

// // type NameManager struct {
// // 	nameGen     NameGenerator
// // 	check       CheckFunction
// // 	maxAttempts int
// // 	retryDelay  time.Duration
// // }

// // func NewNameManager(nameGen NameGenerator, check CheckFunction, maxAttempts int, retryDelay time.Duration) *NameManager {
// // 	return &NameManager{
// // 		nameGen:     nameGen,
// // 		check:       check,
// // 		maxAttempts: maxAttempts,
// // 		retryDelay:  retryDelay,
// // 	}
// // }

// // func (nm *NameManager) GenerateUniqueName(data interface{}) (string, error) {
// // 	for attempt := 0; attempt < nm.maxAttempts; attempt++ {
// // 		name := nm.nameGen(data, attempt)
// // 		if nm.check(name) {
// // 			return name, nil
// // 		}
// // 		time.Sleep(nm.retryDelay)
// // 	}
// // 	return "", fmt.Errorf("failed to generate a unique name after %d attempts", nm.maxAttempts)
// // }

// func NewSecPathNamer() *SecPathNamer {
// 	return &SecPathNamer{
// 		aclCounter:   1000, // 从1000开始计数
// 		usedAclNames: make(map[string]bool),
// 	}
// }

// // func (n *SecPathNamer) PolicyName(fromZone, systemName, appName string) string {
// // 	n.policyCounter++
// // 	return fmt.Sprintf("%s_%s_%s_policy%02d", fromZone, systemName, appName, n.policyCounter)
// // }

// // func (n *SecPathNamer) GlobalNatName(fromZone, toZone, appName string) string {
// // 	n.natCounter++
// // 	return fmt.Sprintf("GNAT_%s_to_%s_%s_%02d", fromZone, toZone, appName, n.natCounter)
// // }

// // func (n *SecPathNamer) AddressObjectName(zone, systemName, appName string) string {
// // 	n.addrCounter++
// // 	return fmt.Sprintf("ADDR_%s_%s_%s_%02d", zone, systemName, appName, n.addrCounter)
// // }

// // func (n *SecPathNamer) ServiceObjectName(appName, protocol string) string {
// // 	n.srvCounter++
// // 	return fmt.Sprintf("SRV_%s_%s_%02d", appName, protocol, n.srvCounter)
// // }

// // func (n *SecPathNamer) NatAddressGroupName(fromZone, toZone string) string {
// // 	n.nagCounter++
// // 	return fmt.Sprintf("NAG_%s_to_%s_%02d", fromZone, toZone, n.nagCounter)
// // }

// func (n *SecPathNamer) AclName() string {
// 	// n.mutex.Lock()
// 	// defer n.mutex.Unlock()

// 	var aclName string
// 	for {
// 		aclName = fmt.Sprintf("%d", n.aclCounter)
// 		if !n.usedAclNames[aclName] {
// 			n.usedAclNames[aclName] = true
// 			break
// 		}
// 		n.aclCounter++
// 	}

// 	return aclName
// }

// type SecPathTemplates struct {
// 	Node              firewall.FirewallNode
// 	policyIDGenerator *common.PolicyIDGenerator
// 	aclIDGenerator    *common.PolicyIDGenerator
// 	om                *common.ObjectNameManager
// }

// func NewSecPathTemplates(node firewall.FirewallNode, ctx *firewall.PolicyContext) *SecPathTemplates {
// 	spt := &SecPathTemplates{
// 		Node: node,
// 		om:   common.NewObjectNameManager(),
// 	}

// 	template, _ := ctx.GetStringValue("policyNameTemplate")
// 	site, _ := ctx.GetStringValue("site")
// 	placeholders := map[string]func() string{
// 		"site": func() string {
// 			return site
// 		},
// 	}

// 	spt.policyIDGenerator = common.NewPolicyIDGenerator(template, func() firewall.NamerIterator {
// 		return node.(*SecPathNode).PolicyIterator()
// 	}, placeholders)

// 	template, _ = ctx.GetStringValue("aclNameTemplate")
// 	template = tools.ConditionalT(template == "", template, "{SEQ:4}")
// 	spt.aclIDGenerator = common.NewPolicyIDGenerator(template, func() firewall.NamerIterator {
// 		return node.(*SecPathNode).AclIterator()
// 	}, placeholders)

// 	return spt
// }

// // getPolicyIDGenerator 是一个新方法，用于获取或初始化 policyIDGenerator
// func (spt *SecPathTemplates) generatePolicyName(ctx *firewall.PolicyContext) (int, string) {
// 	id, policyName := spt.policyIDGenerator.GenerateID()

// 	// 使用 ctx 中的 Variables 进行占位符替换
// 	for key, value := range ctx.Variables {
// 		placeholder := fmt.Sprintf("{%s}", key)
// 		v := fmt.Sprintf("%v", value)
// 		policyName = strings.ReplaceAll(policyName, placeholder, v)
// 	}

// 	return id, policyName
// }

// func (spt *SecPathTemplates) generateUniqueObjectName(auto *keys.AutoIncrementKeys, obj interface{}, itFunc func() firewall.NamerIterator, templates *common.NamingTemplates, retryMethod string) (keys.Keys, bool, error) {
// 	return common.GenerateObjectName(auto, obj, itFunc, spt.Node, templates, retryMethod, spt.om)
// }

// // func NameResolve(keyList []string, ctx firewall.PolicyContext) (keys.Keys, error) {
// // 	var keys keys.Keys
// // 	for _, key := range keyList {
// // 		value, ok := ctx.GetStringValue(key)
// // 		if !ok {
// // 			return nil, fmt.Errorf("key %s not found in data", key)
// // 		}
// // 		keys = keys.Add(fmt.Sprintf("%v", value))
// // 	}

// // 	return keys.Ignore("").Separator("_"), nil
// // }

// // func (at *SecPathTemplates) getUniqueName(parts []string, prefix string, maxLength int) string {
// // 	baseName := strings.Join(parts, "_")
// // 	if len(baseName) > maxLength {
// // 		baseName = baseName[:maxLength]
// // 	}

// // 	name := prefix + "_" + baseName
// // 	counter := 1

// // 	for at.Node.HasObjectName(name) ||
// // 		at.Node.HasPolicyName(name) ||
// // 		at.Node.HasNatName(name) ||
// // 		at.Node.HasPoolName(name) {

// // 		counterStr := fmt.Sprintf("_%d", counter)
// // 		name = prefix + "_" + baseName[:maxLength-len(prefix)-len(counterStr)] + counterStr
// // 		counter++
// // 	}

// // 	return name
// // }

// // func (spt *SecPathTemplates) getUniqueAddressName(baseName string) string {
// // 	counter := 1
// // 	maxLength := 63 // 假设最大长度为63个字符
// // 	name := baseName

// // 	for spt.Node.HasObjectName(name) {
// // 		// 去除结尾的数字部分
// // 		baseNameWithoutSuffix := regexp.MustCompile(`\d+$`).ReplaceAllString(baseName, "")

// // 		// 如果名称已存在，添加计数器
// // 		suffix := fmt.Sprintf("%02d", counter)

// // 		// 确保名称长度不超过最大长度
// // 		if len(baseNameWithoutSuffix)+len(suffix) > maxLength {
// // 			// 如果超过最大长度，截断baseName
// // 			truncatedLength := maxLength - len(suffix)
// // 			name = baseNameWithoutSuffix[:truncatedLength] + suffix
// // 		} else {
// // 			name = baseNameWithoutSuffix + suffix
// // 		}

// // 		counter++
// // 	}

// // 	return name
// // }

// // func (spt *SecPathTemplates) getUniqueNatName(baseName string) string {
// // 	counter := 1
// // 	maxLength := 63 // 假设最大长度为63个字符
// // 	name := baseName

// // 	for spt.Node.HasNatName(name) {
// // 		// 如果名称已存在，添加计数器
// // 		suffix := fmt.Sprintf("_%02d", counter)

// // 		// 确保名称长度不超过最大长度
// // 		if len(baseName)+len(suffix) > maxLength {
// // 			// 如果超过最大长度，截断baseName
// // 			truncatedLength := maxLength - len(suffix)
// // 			name = baseName[:truncatedLength] + suffix
// // 		} else {
// // 			name = baseName + suffix
// // 		}

// // 		counter++
// // 	}

// // 	return name
// // }

// // func (spt *SecPathTemplates) getUniqueServiceName(baseName string) string {
// // 	counter := 1
// // 	maxLength := 63 // 假设最大长度为63个字符
// // 	name := baseName

// // 	for spt.Node.HasObjectName(name) {
// // 		suffix := fmt.Sprintf("_%02d", counter)
// // 		if len(baseName)+len(suffix) > maxLength {
// // 			truncatedLength := maxLength - len(suffix)
// // 			name = baseName[:truncatedLength] + suffix
// // 		} else {
// // 			name = baseName + suffix
// // 		}
// // 		counter++
// // 	}

// // 	return name
// // }

// func (spt *SecPathTemplates) MakeAddressGroupCliOrReuse(intent *policy.Intent, snat string) (objectName string, cmdList *command.CliCmdList, flyObjectsMap map[string]string) {

// 	ng, _ := network.NewNetworkGroupFromString(snat)
// 	cmdList = command.NewCliCmdList(spt.Node.(api.Node).CmdIp(), true)
// 	ag, ok := spt.Node.GetPoolByNetworkGroup(ng, firewall.DYNAMIC_NAT)
// 	if ok {
// 		objectName = ag.Name()
// 		return
// 	}
// 	flyObjectsMap = map[string]string{}

// 	net := ng.GenerateNetwork()

// 	id := spt.Node.(firewall.PoolIdFirewall).NextPoolId()

// 	// Todo: 目前简化处理，不支持复杂地址结构，而且不支持Exclude地址
// 	clis := []string{
// 		fmt.Sprintf("nat address-group %d", id),
// 		fmt.Sprintf(" address %s %s", net.First().String(), net.Last().String()),
// 	}
// 	for _, cli := range clis {
// 		key := strings.ReplaceAll(cli, " ", "_")
// 		cmdList.Add(cli, key, 1, true)
// 	}

// 	flyObjectsMap["POOL"] = strings.Join(clis, "\n")

// 	objectName = fmt.Sprintf("%d", id)
// 	return
// }

// // type Namer struct {
// // 	Format string
// // 	Keys   []string
// // }

// // func NewNamer(format string, keys []string) *Namer {
// // 	return &Namer{
// // 		Format: format,
// // 		Keys:   keys,
// // 	}
// // }

// // func (n *Namer) GenerateName(data map[string]interface{}) string {
// // 	values := make([]interface{}, len(n.Keys))
// // 	for i, key := range n.Keys {
// // 		if value, ok := data[key]; ok {
// // 			values[i] = value
// // 		} else {
// // 			values[i] = "DEFAULT"
// // 		}
// // 	}
// // 	return fmt.Sprintf(n.Format, values...)
// // }

// // func (n *Namer) GenerateUniqueName(data map[string]interface{}, checkUnique func(string) bool) string {
// // 	baseName := n.GenerateName(data)
// // 	name := baseName
// // 	counter := 1

// // 	for checkUnique(name) {
// // 		name = fmt.Sprintf("%s_%02d", baseName, counter)
// // 		counter++
// // 	}

// // 	return name
// // }

// // const (
// // 	NetworkNamer = "network"
// // 	ServerNamer  = "server"
// // )

// // const (
// // 	ListSytyle = "list"
// // 	GroupStyle = "group"
// // )

// // type ObjectNamer struct {
// // 	ObjectType string
// // 	Error      string
// // 	Style      string
// // }

// // func NewObjectNamer(objectType, error, style string) *ObjectNamer {
// // 	return &ObjectNamer{
// // 		ObjectType: objectType,
// // 		Error:      error,
// // 		Style:      style,
// // 	}
// // }

// // func (on *ObjectNamer) GenerateName(data map[string]interface{}) string {
// // 	return on.ObjectType
// // }

// func (spt *SecPathTemplates) MakeServiceObjectCli(intent *policy.Intent, sg *service.Service, policyName string) *PolicyResult {
// 	result := NewPolicyResult()

// 	layout := `{set:service.range_format=" "}` +
// 		`{set:service.l3_format.template=" service {protocol:number}"}` +
// 		`{set:service.icmp_format.template=" service {protocol:number}"}` +
// 		`{set:service.tcp_format.template=" service {protocol:lower} {if:src_port!='0 65535'}source {src_port:range} {endif}destination {if:dst_port:count==1}eq {dst_port:compact}{else}range {dst_port:compact}{endif}"}` +
// 		`{full_service}`

// 	clis := []string{}
// 	keyList := []string{}

// 	if policyName == "" {
// 		keyList, clis = spt.processIndividualServices(sg, result)
// 	} else {
// 		keyList, clis = spt.processServiceGroup(sg, policyName, layout, result)
// 	}

// 	if result.Error != nil {
// 		return result
// 	}

// 	result.SetCLIs(clis)
// 	result.Keys = keyList
// 	result.SetFlyObject("SERVICE", strings.Join(clis, "\n"))
// 	for _, key := range keyList {
// 		result.AddCLI(key)
// 	}

// 	return result
// }

// func (spt *SecPathTemplates) processIndividualServices(sg *service.Service, result *PolicyResult) ([]string, []string) {
// 	srv := sg.Aggregate()
// 	nameKeys := keys.NewKeyBuilder().Separator("_")
// 	keyList := []string{}
// 	clis := []string{}

// 	srv.EachDetailed(func(s service.ServiceEntry) bool {
// 		key, isNew, err := spt.generateServiceObjectName(s, nameKeys)
// 		if err != nil {
// 			result.SetError(fmt.Errorf("failed to generate service object name: %v", err))
// 			return false
// 		}

// 		if isNew {
// 			clis = append(clis, spt.generateServiceObjectCli(s, key))
// 		}
// 		keyList = append(keyList, key.String())
// 		return true
// 	})

// 	return keyList, clis
// }

// func (spt *SecPathTemplates) processServiceGroup(sg *service.Service, policyName, layout string, result *PolicyResult) ([]string, []string) {
// 	srv := sg.Aggregate()
// 	nameKeys := keys.NewKeyBuilder(policyName).Separator("_")
// 	auto := keys.NewAutoIncrementKeys(nameKeys.Add("SERVICE"), 2)

// 	key, isNew, err := spt.generateUniqueObjectName(auto, srv, func() firewall.NamerIterator {
// 		return spt.Node.(*SecPathNode).ServiceIterator()
// 	}, nil, RetryMethodNext)

// 	if err != nil {
// 		result.SetError(fmt.Errorf("failed to generate object name for service group: %v", err))
// 		return nil, nil
// 	}

// 	clis := []string{}
// 	if isNew {
// 		clis = append(clis, fmt.Sprintf("object-group service %s", key.String()))
// 		clis = append(clis, dsl.ServiceFormat(srv, layout))
// 		clis = append(clis, SectionSeparator)
// 	}

// 	return []string{key.String()}, clis
// }

// func (spt *SecPathTemplates) generateServiceObjectName(s service.ServiceEntry, nameKeys keys.Keys) (keys.Keys, bool, error) {
// 	var key keys.Keys
// 	switch v := s.(type) {
// 	case *service.L3Protocol:
// 		if tools.ContainsT([]int{service.IP, service.TCP, service.UDP, service.ICMP, service.ICMP6}, int(s.Protocol())) {
// 			key = nameKeys.Add("SERVICE", strings.ToUpper(s.Protocol().String()))
// 		} else {
// 			key = nameKeys.Add("SERVICE", fmt.Sprintf("%d", s.Protocol()))
// 		}
// 	case *service.ICMPProto:
// 		key = nameKeys.Add("SERVICE", strings.ToUpper(s.Protocol().String()))
// 	case *service.L4Service:
// 		layout := `{set:service.range_format="_"}{if:dst_port:count==1}{dst_port:compact}{else}{dst_port:compact}{endif}`
// 		key = nameKeys.Add(strings.ToUpper(s.Protocol().String()), dsl.ServiceEntryFormat(v, layout))
// 	}

// 	return spt.generateUniqueObjectName(keys.NewAutoIncrementKeys(key, 2), s, func() firewall.NamerIterator {
// 		return spt.Node.(*SecPathNode).ServiceIterator()
// 	}, nil, RetryMethodNext)
// }

// func (spt *SecPathTemplates) generateServiceObjectCli(s service.ServiceEntry, key keys.Keys) string {
// 	clis := []string{fmt.Sprintf("object-group service %s", key.String())}

// 	switch tp := s.(type) {
// 	case *service.L3Protocol, *service.ICMPProto:
// 		clis = append(clis, fmt.Sprintf(" service %d", s.Protocol()))
// 	case *service.L4Service:
// 		tp.EachDst(func(se *service.L4Service) bool {
// 			layout := `{set:service.range_format=" "} service {protocol:lower}{if:src_port!="0 65535"} source range {start} {end}{endif} destination{if:dst_port:count==1} eq {dst_port:compact}{else} range {dst_port:compact}{endif}`
// 			clis = append(clis, dsl.ServiceEntryFormat(se, layout))
// 			return true
// 		})
// 	}
// 	clis = append(clis, SectionSeparator)
// 	return strings.Join(clis, "\n")
// }

// // nat server protocol tcp global 192.168.0.142 6081 inside 192.168.22.17 6081 rule ServerRule_16 description For_DMZ_Financial_YouChu_01_6081
// // nat server protocol tcp global 58.217.205.15 22 inside 192.168.35.83 22 rule ServerRule_53 description For_OUT_SEC_PC_Protect_M.Plat22
// func (spt *SecPathTemplates) MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (s string, cmdList command.CmdList) {
// 	data := map[string]interface{}{}
// 	data["static_nat_rule"] = ctx.Variables["static_nat_rule"]
// 	data["static_nat_description"] = ctx.Variables["static_nat_description"]

// 	clis := []string{
// 		fmt.Sprintf("interface %s", out.Name()),
// 	}
// 	layout := `nat server protoocl {protocol:lower} global {dst_network} ` +
// 		`{if:dst_port:count==1}{dst_port}{endif} local {real_ip} {if:dst_port:count==1}{real_port}{endif}` +
// 		`{if:exist:static_nat_rule=="true"}rule {static_nat_rule}{endif}` +
// 		`{if:exist:static_nat_description=="true"}description {static_nat_description}{endif}`

// 	clis = append(clis, dsl.IntentFormat(intent, globalIntentLayout+layout))
// 	s = strings.Join(clis, "\n")
// 	ctx.WithValue("static_nat_cli", s)
// 	return s, cmdList
// }

// func (spt *SecPathTemplates) generateAdvancedAclContent(from, to api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) ([]string, error) {
// 	metaData := intent.MetaData
// 	systemName := metaData["SystemName"]
// 	appName := metaData["AppName"]
// 	srcObjName := metaData["srcObjName"]
// 	dstObjName := metaData["dstObjName"]

// 	cliBuilder := []string{}

// 	// Generate or update source address object-group
// 	if srcObjName == "" {
// 		srcObjName = fmt.Sprintf("%s_%s_%s_src", from.(firewall.ZoneFirewall).Zone(), systemName, appName)
// 	}

// 	// srcZone := from.(firewall.ZoneFirewall).Zone()

// 	srcResult := spt.MakeNetworkObjectCli(from, to, intent.Src(), srcObjName, "", true, ctx)
// 	if srcResult.Error != nil {
// 		return nil, fmt.Errorf("failed to generate/update source network object: %w", srcResult.Error)
// 	}
// 	if len(srcResult.CLIs) > 0 {
// 		cliBuilder = append(cliBuilder, srcResult.CLIs...)
// 	}
// 	srcObjName = srcResult.Keys[0]

// 	// Generate or update destination address object-group
// 	if dstObjName == "" {
// 		dstObjName = fmt.Sprintf("%s_%s_%s_dst", to.(firewall.ZoneFirewall).Zone(), systemName, appName)
// 	}

// 	dstResult := spt.MakeNetworkObjectCli(from, to, intent.Dst(), dstObjName, "", false, ctx)
// 	if dstResult.Error != nil {
// 		return nil, fmt.Errorf("failed to generate/update destination network object: %w", dstResult.Error)
// 	}
// 	if len(dstResult.CLIs) > 0 {
// 		cliBuilder = append(cliBuilder, dstResult.CLIs...)
// 	}
// 	dstObjName = dstResult.Keys[0]

// 	// Generate ACL rules
// 	addressCliTemplate := fmt.Sprintf("source object-group %s destination object-group %s", srcObjName, dstObjName)

// 	serviceLayout := `{set:service.l3_format.template="rule permit {protocol:lower} {address_cli}"}
//     {set:service.icmp_format.template="rule permit {protocol:lower} {address_cli} icmp-type {type}"}
//     {set:service.tcp_format.template="rule permit {protocol:lower} {address_cli}{if:src_port!='0-65535'} source-port range {src_port:range}{endif} destination-port range {dst_port:range}"}
//     {full_service}
//     `

// 	serviceRules := dsl.ServiceFormat(intent.Service(), serviceLayout, map[string]interface{}{
// 		"address_cli": addressCliTemplate,
// 	})
// 	cliBuilder = append(cliBuilder, serviceRules)

// 	return cliBuilder, nil
// }

// func (spt *SecPathTemplates) MakeAdvancedAclCli(from, to api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (aclName string, cli string, err error) {
// 	namer := NewSecPathNamer()
// 	aclName = namer.AclName()
// 	spt.generatePolicyName(ctx)

// 	cliBuilder, err := spt.generateAdvancedAclContent(from, to, intent, ctx)
// 	if err != nil {
// 		return "", "", err
// 	}

// 	// Prepend ACL creation command
// 	cliBuilder = append([]string{fmt.Sprintf("acl advanced %s", aclName)}, cliBuilder...)
// 	ctx.WithValue("aclNumber", aclName)

// 	return aclName, strings.Join(cliBuilder, "\n"), nil
// }

// func (spt *SecPathTemplates) UpdateAdvancedAcl(from, to api.Port, intent *policy.Intent, aclName string, ctx *firewall.PolicyContext) (string, error) {
// 	cliBuilder, err := spt.generateAdvancedAclContent(from, to, intent, ctx)
// 	if err != nil {
// 		return "", err
// 	}

// 	// Prepend ACL update commands
// 	cliBuilder = append([]string{
// 		fmt.Sprintf("acl advanced %s", aclName),
// 	}, cliBuilder...)

// 	return strings.Join(cliBuilder, "\n"), nil
// }

// func IsExist(node firewall.FirewallNode, ctx *firewall.PolicyContext, objectName string) bool {
// 	// 检查指定的对象是否存在
// 	if objectName != "" {
// 		_, exists := node.Network("", objectName)
// 		return exists
// 	}

// 	// 如果没有指定对象名，则检查源地址和目标地址对象
// 	srcObjName := ctx.GetSrcAddrObjName()
// 	if srcObjName != "" {
// 		_, srcExists := node.Network("", srcObjName)
// 		if srcExists {
// 			return true
// 		}
// 	}

// 	dstObjName := ctx.GetDstAddrObjName()
// 	if dstObjName != "" {
// 		_, dstExists := node.Network("", dstObjName)
// 		if dstExists {
// 			return true
// 		}
// 	}

// 	// 如果都不存在，返回 false
// 	return false
// }

// // MakeNetworkObjectCli 生成网络对象的CLI命令。
// //
// // 参数:
// //   - from: api.Port 源端口
// //   - out: api.Port 目标端口
// //   - net: *network.NetworkGroup 网络组
// //   - policeName: string 策略名称
// //   - isSource: bool 是否为源地址
// //   - ctx: *firewall.PolicyContext 策略上下文
// //
// // 返回值:
// //   - []string: 生成的对象名称列表
// //   - string: 生成的CLI命令
// //   - error: 如果有错误发生则返回，否则为nil
// //
// // 功能描述:
// //  1. 调用objectStyleSelector方法来决定对象创建的风格（单一规则或复杂规则）
// //  2. 基于选定的风格，调用makeNetworkObjectCli方法来生成实际的CLI命令
// //  3. 这个方法作为一个高层接口，封装了对象风格的选择和CLI命令的生成过程

// func (spt *SecPathTemplates) MakeNetworkObjectCli(from, out api.Port, net *network.NetworkGroup, objName, policeName string, isSource bool, ctx *firewall.PolicyContext) *PolicyResult {
// 	result := NewPolicyResult()

// 	style := spt.objectStyleSelector(from, out, net, isSource, ctx)
// 	objectResult := spt.makeNetworkObjectCli(net, objName, policeName, isSource, style, ctx)

// 	if objectResult.Error != nil {
// 		return objectResult
// 	}

// 	result.MergeCLIs(objectResult.CLIs)
// 	result.Keys = objectResult.Keys
// 	result.SetFlyObject("NETWORK", objectResult.CLIString)

// 	return result
// }

// const (
// 	SingleRule  = "SingleRule"
// 	ComplexRule = "ComplexRule"
// )

// // objectStyleSelector 决定如何创建网络对象的策略选择器。
// //
// // 参数:
// //   - from: api.Port 源端口
// //   - out: api.Port 目标端口
// //   - net: *network.NetworkGroup 网络组
// //   - isSource: bool 是否为源地址
// //   - ctx: *firewall.PolicyContext 策略上下文
// //
// // 返回值:
// //
// //	string: 返回 "SingleRule" 或 "ComplexRule"，表示选择的对象创建风格
// //
// // 功能描述:
// //  1. 根据给定的参数决定是使用单一规则还是复杂规则来创建网络对象
// //  2. 考虑因素包括：是否为外部网络，网络组中的地址数量
// //  3. 简而言之，外部网络使用复杂规则，内部网络倾向于单一规则
// func (spt *SecPathTemplates) objectStyleSelector(from, out api.Port, net *network.NetworkGroup, isSource bool, ctx *firewall.PolicyContext) string {
// 	// 从上下文中获取外部网络信息
// 	outsideMap, ok := ctx.GetValue("outside")

// 	// 根据是源地址还是目标地址，选择相应的区域名称
// 	zoneName := tools.ConditionalT(isSource, from.(firewall.ZoneFirewall).Zone(), out.(firewall.ZoneFirewall).Zone())

// 	var isOutside bool
// 	if ok {
// 		// 检查当前区域是否为外部网络
// 		_, isOutside = outsideMap.(map[string]string)[zoneName]
// 	}

// 	// 判断网络组中的地址数量是否大于16
// 	isLarge := tools.ConditionalT(net.Count().Int64() > 16, true, false)

// 	// 如果不是外部网络且地址数量不大，则使用单一规则
// 	if !isOutside && !isLarge {
// 		return SingleRule
// 	}

// 	// 否则使用复杂规则
// 	return ComplexRule
// }

// func (spt *SecPathTemplates) makeNetworkObjectCli(net *network.NetworkGroup, objName string, policeName string, isSource bool, style string, ctx *firewall.PolicyContext) *PolicyResult {
// 	result := NewPolicyResult()

// 	layout := ` network {if:isRange=="true"}range {start} {end}{else if:isHost=="true"}host address {ip}{else}subnet {ip} {mask:dotted}{endif}`
// 	clis := []string{}

// 	if objName != "" {
// 		key := keys.NewKeyBuilder(objName)
// 		key, isNew, err := spt.generateUniqueObjectName(keys.NewAutoIncrementKeys(key, 2), net, func() firewall.NamerIterator {
// 			return spt.Node.(*SecPathNode).NetworkIterator()
// 		}, nil, RetryMethodNext)
// 		if err != nil {
// 			result.SetError(err)
// 			return result
// 		}

// 		if isNew {
// 			clis = append(clis, fmt.Sprintf("object-group ip address %s", key.String()))
// 			net.Each(func(n network.AbbrNet) bool {
// 				clis = append(clis, dsl.NetworkFormat(n, layout))
// 				return true
// 			})
// 			clis = append(clis, SectionSeparator)
// 		}

// 		result.SetCLIs(clis)
// 		result.Keys = append(result.Keys, key.String())
// 		result.CLIString = strings.Join(clis, "\n")
// 		return result
// 	}

// 	keyList := []string{}
// 	if style == SingleRule {
// 		nameKeys := keys.NewKeyBuilder()
// 		net.EachIP(func(ip *network.IP) bool {
// 			key := nameKeys.Add(ip.String()).Separator("_")

// 			if !spt.Node.(firewall.FirewallNode).HasObjectName(key.String()) {
// 				clis = append(clis, fmt.Sprintf("object-group ip address %s", key.String()))
// 				clis = append(clis, fmt.Sprintf(" network host address %s", ip.String()))
// 				keyList = append(keyList, key.String())
// 			} else {
// 				key, isNew, err := spt.generateUniqueObjectName(keys.NewAutoIncrementKeys(key, 2), ip, func() firewall.NamerIterator {
// 					return spt.Node.(*SecPathNode).NetworkIterator()
// 				}, nil, RetryMethodSuffix)
// 				if err != nil {
// 					result.SetError(err)
// 					return false
// 				}
// 				if isNew {
// 					clis = append(clis, fmt.Sprintf("object-group ip address %s", key.String()))
// 					clis = append(clis, fmt.Sprintf(" network host address %s", ip.String()))
// 					clis = append(clis, SectionSeparator)
// 				}
// 				keyList = append(keyList, key.String())
// 			}
// 			return true
// 		})
// 	} else {
// 		nameKeys := keys.NewKeyBuilder(policeName).Separator("_")

// 		auto := keys.NewAutoIncrementKeys(nameKeys, 2)
// 		key, isNew, err := spt.generateUniqueObjectName(auto, net, func() firewall.NamerIterator {
// 			return spt.Node.(*SecPathNode).NetworkIterator()
// 		}, nil, RetryMethodNext)

// 		if err != nil {
// 			result.SetError(err)
// 			return result
// 		}

// 		if isNew {
// 			clis = append(clis, fmt.Sprintf("object-group ip address %s", key.String()))
// 			net.Each(func(n network.AbbrNet) bool {
// 				clis = append(clis, dsl.NetworkFormat(n, layout))
// 				return true
// 			})
// 			clis = append(clis, SectionSeparator)
// 		}

// 		keyList = append(keyList, key.String())
// 	}

// 	result.SetCLIs(clis)
// 	result.Keys = keyList
// 	result.CLIString = strings.Join(clis, "\n")
// 	return result
// }

// func (spt *SecPathTemplates) MakeSnatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (string, error) {
// 	// om := NewObjectManager(spt)

// 	// Step 1: 查找适合改造的 NAT 规则
// 	natRule, err := spt.findSuitableNatRule(out, intent)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to find suitable NAT rule: %w", err)
// 	}

// 	// Step 2: 处理 NAT 规则
// 	if natRule != nil {
// 		// 改造现有 NAT 规则
// 		return spt.modifyExistingNatRule(natRule, from, out, intent, ctx)
// 	} else {
// 		// 检查 address group 是否已被使用
// 		if spt.isAddressGroupUsed(intent.Snat) {
// 			return "", fmt.Errorf("address group %s is already in use", intent.Snat)
// 		}
// 		// 创建新的 SNAT 规则
// 		return spt.createNewSnatRule(from, out, intent, ctx)
// 	}
// }

// func (spt *SecPathTemplates) findSuitableNatRule(out api.Port, intent *policy.Intent) (*NatRule, error) {
// 	for _, nat := range spt.Node.(*SecPathNode).nats.outboundDynamic {
// 		if nat.outboundPortName == out.Name() && nat.mappedSrc == intent.Snat {
// 			return nat, nil
// 		}
// 	}
// 	return nil, nil
// }

// func (spt *SecPathTemplates) modifyExistingNatRule(natRule *NatRule, from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (string, error) {
// 	// 更新 NAT 规则对应的 ACL
// 	_, aclCli, err := spt.createOrUpdateAdvancedAcl(from, out, intent, natRule.aclName, ctx)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to update ACL: %w", err)
// 	}

// 	return aclCli, nil
// }

// func (spt *SecPathTemplates) createNewSnatRule(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (string, error) {
// 	// // 创建新的 ACL

// 	clis := []string{}

// 	// Step 1: Create or Update Advanced ACL
// 	aclName, aclCli, err := spt.createOrUpdateAdvancedAcl(from, out, intent, "", ctx)
// 	if err != nil {
// 		return "", err
// 	}
// 	clis = append(clis, aclCli)

// 	data := intent.MetaData
// 	// Step 2: Create or Update Address Group

// 	poolId, addrGroupCli, err := spt.createOrReuseNatAddressGroup(intent, ctx)
// 	if err != nil {
// 		return "", err
// 	}
// 	clis = append(clis, addrGroupCli)
// 	data["poolId"] = fmt.Sprintf("%d", poolId)

// 	// Step 3: Generate NAT Outbound command
// 	natOutboundCmd, err := spt.generateNatOutboundCommand(fmt.Sprintf("%d", poolId), aclName, ctx)
// 	if err != nil {
// 		return "", err
// 	}
// 	clis = append(clis, natOutboundCmd)

// 	return strings.Join(clis, "\n"), nil

// }

// func (spt *SecPathTemplates) isAddressGroupUsed(addressGroup string) bool {
// 	// 实现检查 address group 是否已被使用的逻辑
// 	// 这可能需要遍历现有的 NAT 规则或查询设备配置
// 	return false
// }

// func (spt *SecPathTemplates) createOrUpdateAdvancedAcl(from, out api.Port, intent *policy.Intent, aclName string, ctx *firewall.PolicyContext) (acl, cli string, err error) {
// 	if aclName != "" {
// 		cli, err := spt.UpdateAdvancedAcl(from, out, intent, aclName, ctx)
// 		return aclName, cli, err
// 	}
// 	aclName, cli, err = spt.MakeAdvancedAclCli(from, out, intent, ctx)
// 	return aclName, cli, err
// }

// func (spt *SecPathTemplates) createOrReuseNatAddressGroup(intent *policy.Intent, ctx *firewall.PolicyContext) (int, string, error) {
// 	ng, err := network.NewNetworkGroupFromString(intent.Snat)
// 	if err != nil {
// 		return -1, "", fmt.Errorf("failed to create network group from SNAT: %w", err)
// 	}

// 	// 检查是否存在匹配的地址组
// 	existingGroup, found := spt.Node.(*SecPathNode).nats.matchAddressGroupByNetworkGroup(ng)
// 	if found {
// 		// 重用现有的地址组
// 		ctx.WithValue("addressGroupIndex", existingGroup.GroupNumber)
// 		return existingGroup.GroupNumber, fmt.Sprintf("# Reusing existing address group: %s", existingGroup.Name()), nil
// 	}

// 	// 如果没有找到匹配的地址组，创建新的
// 	return spt.CreatePool(ng)
// }

// func (spt *SecPathTemplates) CreatePool(ng *network.NetworkGroup) (int, string, error) {
// 	id := spt.Node.(firewall.PoolIdFirewall).NextPoolId()
// 	clis := []string{
// 		fmt.Sprintf("nat address-group %d", id),
// 	}

// 	net := ng.GenerateNetwork()
// 	clis = append(clis, fmt.Sprintf(" address %s %s", net.First().String(), net.First().String()))

// 	return id, strings.Join(clis, "\n"), nil
// }

// func (spt *SecPathTemplates) generateNatOutboundCommand(addressGroupIndex, aclNumber string, ctx *firewall.PolicyContext) (string, error) {

// 	snatDescription, exists := ctx.GetStringValue("snatDescription")
// 	if !exists {
// 		return "", fmt.Errorf("snat description not found in context")
// 	}

// 	if exists {
// 		return fmt.Sprintf("nat outbound %s address-group %s", aclNumber, addressGroupIndex), nil
// 	}

// 	return fmt.Sprintf("nat outbound %s address-group %s description %s", aclNumber, addressGroupIndex, snatDescription), nil
// }

// // nat address-group 9 name Snat-DMZ_EOP-access-ZhaoHang
// //
// //	address 192.168.0.138 192.168.0.138
// func (spt *SecPathTemplates) MakeNatAddressGroupCli(intent *policy.Intent, ng *network.NetworkGroup) (string, error) {
// 	addrGroupName := intent.MetaData["addressGroupName"]
// 	index := intent.MetaData["addressGroupIndex"]
// 	clis := []string{
// 		fmt.Sprintf("nat address-group %s name %s", index, addrGroupName),
// 	}
// 	ng.Each(func(n network.AbbrNet) bool {
// 		clis = append(clis, dsl.NetworkFormat(n, ` address {start} {end}`))
// 		return true
// 	})

// 	return strings.Join(clis, "\n"), nil
// }

// // nat static outbound 61.147.19.32 192.168.1.201 description 163_RZGLPT_CSJieKou01
// // nat static outbound local-ip global-ip
// // 1. 确定本地地址，就是intent的src地址
// // 2. 确定映射后（全局）地址，就是snat ip
// // 3. 确定description
// // 4. 确定nat static outbound
// func (spt *SecPathTemplates) MakeStaticOutboundCli(from, out api.Port, intent *policy.Intent) (string, error) {
// 	clis := []string{}
// 	srcNet, err := intent.Src().Aggregate()
// 	if err != nil {
// 		return "", err
// 	}
// 	srcNet.Each(func(n network.AbbrNet) bool {
// 		clis = append(clis, dsl.NetworkFormat(n, `nat static outbound local-ip {ip} global-ip {snat} description {description}`, map[string]interface{}{
// 			"snat": intent.Snat}))
// 		return true
// 	})

// 	return strings.Join(clis, "\n"), nil
// }

// // 1. 确定本地地址
// // 2. 确定映射后（全局）地址，就是intent的dst地址
// // 3. 确定description
// // 4. 确定nat static inbound
// func (spt *SecPathTemplates) MakeStaticInboundCli(from, out api.Port, intent *policy.Intent) (string, error) {
// 	clis := []string{}
// 	srcNet, err := intent.Src().Aggregate()
// 	if err != nil {
// 		return "", err
// 	}
// 	srcNet.Each(func(n network.AbbrNet) bool {
// 		clis = append(clis, dsl.NetworkFormat(n, `nat static inbound global-ip {ip} local-ip {real_ip} description {description}`, map[string]interface{}{
// 			"real_ip": intent.RealIp}))
// 		return true
// 	})

// 	return strings.Join(clis, "\n"), nil
// }

// func (spt *SecPathTemplates) MakePolicyRuleCli(from, to api.Port, intent *policy.Intent, isObjectStyle bool, ctx *firewall.PolicyContext) *PolicyResult {
// 	result := spt.makeCommonPolicyRuleCli(from, to, intent, ctx, WithObjectStyle(isObjectStyle))
// 	if !result.IsValid() {
// 		return result
// 	}

// 	result.SetFlyObject("SECURITY_POLICY", result.CLIString)
// 	return result
// }

// func (spt *SecPathTemplates) MakeGlobalNatPolicyRuleCli(from, to api.Port, intent *policy.Intent, natType firewall.NatType) *PolicyResult {
// 	result := spt.makeCommonPolicyRuleCli(from, to, intent, nil, WithGlobalNat(true), WithNatType(natType))
// 	if !result.IsValid() {
// 		return result
// 	}

// 	result.IsGlobalNat = true
// 	return result
// }

// func (spt *SecPathTemplates) makeCommonPolicyRuleCli(from, to api.Port, intent *policy.Intent, ctx *firewall.PolicyContext, options ...PolicyOption) *PolicyResult {
// 	result := NewPolicyResult()

// 	opts := &policyOptions{
// 		isObjectStyle: false,
// 		isGlobalNat:   false,
// 	}
// 	for _, option := range options {
// 		option(opts)
// 	}

// 	data := map[string]interface{}{
// 		"FromZone":            from.(firewall.ZoneFirewall).Zone(),
// 		"ToZone":              to.(firewall.ZoneFirewall).Zone(),
// 		"SystemName":          intent.MetaData["system_name"],
// 		"AppName":             intent.MetaData["app_name"],
// 		"Description":         fmt.Sprintf("NETACC_%s_%s", intent.TicketNumber, intent.SubTicket),
// 		"IsUserDefineService": "true",
// 	}

// 	var clis []string
// 	if opts.isGlobalNat {
// 		clis = append(clis, "nat global-policy")
// 	} else {
// 		clis = append(clis, "security-policy ip")
// 	}

// 	// Generate policy name
// 	var policyName string
// 	var policyId int
// 	// if !opts.isGlobalNat {
// 	policyId, policyName = spt.generatePolicyName(ctx)
// 	clis = append(clis, fmt.Sprintf(" rule %d name %s", policyId, policyName))
// 	// }

// 	// Add source and destination zones
// 	clis = append(clis, fmt.Sprintf("  source-zone %s", data["FromZone"]))
// 	if !opts.isGlobalNat || opts.natType == firewall.DYNAMIC_NAT || opts.natType == firewall.TWICE_NAT {
// 		clis = append(clis, fmt.Sprintf("  destination-zone %s", data["ToZone"]))
// 	}

// 	// Handle object style or non-object style
// 	if opts.isObjectStyle {
// 		objResult := spt.generateObjectStyleCli(from, to, intent, policyName, ctx)
// 		if !objResult.IsValid() {
// 			return objResult
// 		}
// 		clis = append(clis, objResult.CLIs...)
// 		result.MergeFlyObjects(objResult.FlyObject)
// 	} else {
// 		nonObjClis := spt.generateNonObjectStyleCli(intent, data)
// 		clis = append(clis, nonObjClis...)
// 	}

// 	// Handle action
// 	if opts.isGlobalNat {
// 		natResult := spt.generateNatActionCli(intent, opts.natType)
// 		if !natResult.IsValid() {
// 			return natResult
// 		}
// 		clis = append(clis, natResult.CLIs...)
// 		result.MergeFlyObjects(natResult.FlyObject)
// 	} else {
// 		clis = append(clis, "  action pass")
// 	}

// 	clis = append(clis, SectionSeparator)
// 	result.SetCLIs(clis)
// 	result.CLIString = strings.Join(clis, "\n")
// 	return result
// }

// type policyOptions struct {
// 	isObjectStyle bool
// 	isGlobalNat   bool
// 	natType       firewall.NatType
// }

// type PolicyOption func(*policyOptions)

// func WithObjectStyle(isObjectStyle bool) PolicyOption {
// 	return func(po *policyOptions) {
// 		po.isObjectStyle = isObjectStyle
// 	}
// }

// func WithGlobalNat(isGlobalNat bool) PolicyOption {
// 	return func(po *policyOptions) {
// 		po.isGlobalNat = isGlobalNat
// 	}
// }

// func WithNatType(natType firewall.NatType) PolicyOption {
// 	return func(po *policyOptions) {
// 		po.natType = natType
// 	}
// }

// func (spt *SecPathTemplates) generateObjectStyleCli(from, to api.Port, intent *policy.Intent, policyName string, ctx *firewall.PolicyContext) *PolicyResult {
// 	result := NewPolicyResult()
// 	var clis []string

// 	src := intent.Src()
// 	srcResult := spt.MakeNetworkObjectCli(from, to, src, "", policyName, true, ctx)
// 	if !srcResult.IsValid() {
// 		result.SetError(fmt.Errorf("failed to create source object cli: %v", srcResult.Error))
// 		return result
// 	}
// 	result.MergeFlyObjects(srcResult.FlyObject)

// 	dst := intent.Dst()
// 	dstResult := spt.MakeNetworkObjectCli(from, to, dst, "", policyName, false, ctx)
// 	if !dstResult.IsValid() {
// 		result.SetError(fmt.Errorf("failed to create destination object cli: %v", dstResult.Error))
// 		return result
// 	}
// 	result.MergeFlyObjects(dstResult.FlyObject)

// 	srvResult := spt.MakeServiceObjectCli(intent, intent.Service(), "")
// 	if !srvResult.IsValid() {
// 		result.SetError(fmt.Errorf("failed to create service object cli: %v", srvResult.Error))
// 		return result
// 	}
// 	result.MergeFlyObjects(srvResult.FlyObject)

// 	for _, k := range srcResult.Keys {
// 		clis = append(clis, fmt.Sprintf("  source-ip %s", k))
// 	}
// 	for _, k := range dstResult.Keys {
// 		clis = append(clis, fmt.Sprintf("  destination-ip %s", k))
// 	}
// 	for _, k := range srvResult.Keys {
// 		clis = append(clis, fmt.Sprintf("  service %s", k))
// 	}

// 	result.SetCLIs(clis)
// 	result.CLIString = strings.Join(clis, "\n")
// 	return result
// }

// func (spt *SecPathTemplates) generateNonObjectStyleCli(intent *policy.Intent, data map[string]interface{}) []string {
// 	layout := `{set:intent.src_template="{if:isHost=='true'}source-ip-host {ip}{else if:isRange=='true'}source-ip-range {start} {end}{else}source-ip-subnet {ip} {mask:dotted}{endif}"}
// {set:intent.dst_template="{if:isHost=='true'}destination-ip-host {ip}{else if:isRange=='true'}destination-ip-range {start} {end}{else}destination-ip-subnet {ip} {mask:dotted}{endif}"}
// {set:intent.separator={newline}}
// {set:service.range_format=" "}
// {set:service.l3_format.template="service-port {protocol:number}"}
// {set:service.icmp_format.template="service-port {protocol:lower}"}
// {set:service.tcp_format.template="service-port {protocol:lower}{if:src_port!='0 65535'} source range {src_port:range}{endif}{if:dst_port!='0 65535'} destination range {dst_port:range}{endif}"}
// {set:service.udp_format.template="service-port {protocol:lower}{if:src_port!='0 65535'} source range {src_port:range}{endif}{if:dst_port!='0 65535'} destination range {dst_port:range}{endif}"}
// {set:service.separator={newline}}
// {src_network}{newline}{dst_network}{newline}{service}`

// 	result := dsl.IntentFormat(intent, layout, data)
// 	return strings.Split(result, "\n")
// }

// func (spt *SecPathTemplates) generateNatActionCli(intent *policy.Intent, natType firewall.NatType) *PolicyResult {
// 	result := NewPolicyResult()

// 	switch natType {
// 	case firewall.DYNAMIC_NAT:
// 		snat := intent.Snat
// 		groupid, _, flyObjMap := spt.MakeAddressGroupCliOrReuse(intent, snat)
// 		clis := []string{}
// 		if flyObjMap != nil && flyObjMap["POOL"] != "" {
// 			clis = append(clis, flyObjMap["POOL"])
// 		}
// 		clis = append(clis, fmt.Sprintf("  action snat address-group %s", groupid))
// 		result.SetCLIs(clis)
// 		result.CLIString = strings.Join(clis, "\n")
// 		for k, v := range flyObjMap {
// 			result.SetFlyObject(k, v)
// 		}

// 	case firewall.STATIC_NAT:
// 		net, err := intent.GenerateIntentPolicyEntry().Dst().GenerateNetworkE()
// 		if err != nil {
// 			result.SetError(err)
// 			return result
// 		}
// 		cli := fmt.Sprintf("  action dnat ip-address %s", net.First().String())
// 		if intent.RealPort != "" {
// 			cli += fmt.Sprintf(" local-port %s", intent.RealPort)
// 		}
// 		result.SetCLIs([]string{cli})
// 		result.CLIString = cli

// 	// case firewall.TWICE_NAT:
// 	//     cli := fmt.Sprintf("  action dnat snat address-group %s", groupid)
// 	//     result.SetCLIs([]string{cli})
// 	//     result.CLIString = cli

// 	default:
// 		result.SetError(fmt.Errorf("unsupported NAT type: %v", natType))
// 	}

// 	return result
// }

// func (spt *SecPathTemplates) generateObjectClis(from, to api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) *PolicyResult {
// 	result := NewPolicyResult()

// 	// Generate network object CLIs
// 	src := intent.Src()
// 	srcResult := spt.MakeNetworkObjectCli(from, to, src, "", "", true, ctx)
// 	if !srcResult.IsValid() {
// 		result.SetError(fmt.Errorf("failed to create source object cli: %v", srcResult.Error))
// 		return result
// 	}
// 	result.MergeFlyObjects(srcResult.FlyObject)
// 	result.MergeCLIs(srcResult.CLIs)

// 	dst := intent.Dst()
// 	dstResult := spt.MakeNetworkObjectCli(from, to, dst, "", "", false, ctx)
// 	if !dstResult.IsValid() {
// 		result.SetError(fmt.Errorf("failed to create destination object cli: %v", dstResult.Error))
// 		return result
// 	}
// 	result.MergeFlyObjects(dstResult.FlyObject)
// 	result.MergeCLIs(dstResult.CLIs)

// 	// Generate service object CLIs
// 	srvResult := spt.MakeServiceObjectCli(intent, intent.Service(), "")
// 	if !srvResult.IsValid() {
// 		result.SetError(fmt.Errorf("failed to create service object cli: %v", srvResult.Error))
// 		return result
// 	}
// 	result.MergeFlyObjects(srvResult.FlyObject)
// 	result.MergeCLIs(srvResult.CLIs)

// 	// Combine all CLIs
// 	result.CLIString = strings.Join(result.CLIs, "\n")

// 	return result
// }

// // Merge 将 src map 合并到 dst map 中。
// // 如果 key 已存在，则使用 "\n" 连接值。
// func Merge(dst, src map[string]string) {
// 	for key, value := range src {
// 		if existingValue, exists := dst[key]; exists {
// 			// 如果 key 已存在，使用 "\n" 连接值
// 			dst[key] = strings.Join([]string{existingValue, value}, "\n")
// 		} else {
// 			// 如果 key 不存在，直接添加
// 			dst[key] = value
// 		}
// 	}
// }

// // type SecPathDnatTargetServiceValidator struct{}

// // func (dp SecPathDnatTargetServiceValidator) Validate(data map[string]interface{}) validator.Result {
// // 	var intent *policy.Intent
// // 	var genPe policy.PolicyEntryInf
// // 	var result validator.Result
// // 	func() {
// // 		defer func() {
// // 			if r := recover(); r != nil {
// // 				result = validator.NewValidateResult(false, fmt.Sprint(r))
// // 			}
// // 		}()

// // 		intent = data["intent"].(*policy.Intent)
// // 		genPe = intent.GenerateIntentPolicyEntry()
// // 	}()

// // 	if result != nil {
// // 		return result
// // 	}

// // 	s := genPe.Service().MustSimpleServiceEntry()
// // 	if !(s.Protocol() == service.IP || s.Protocol() == service.TCP || s.Protocol() == service.UDP) {
// // 		return validator.NewValidateResult(false, fmt.Sprint("static nat not support portocol: ", s.Protocol()))
// // 	}

// // 	// var addition string
// // 	switch s.(type) {
// // 	case *service.L3Protocol:
// // 		// addition = fmt.Sprint(s.Protocol())
// // 		if s.Protocol() != service.IP {
// // 			return validator.NewValidateResult(false, fmt.Sprint("static nat not support L3 portocol: ", s.Protocol()))
// // 		}
// // 	case *service.L4Service:
// // 		e := s.(*service.L4Service).DstPort().List()[0]
// // 		if e.Count().Cmp(big.NewInt(1)) != 0 {
// // 			return validator.NewValidateResult(false, fmt.Sprint("static nat not support multiple port: ", s.(*service.L4Service).DstPort()))
// // 		}
// // 		// default:
// // 		// return validator.NewValidateResult(false, fmt.Sprint("unknown error"))
// // 		// panic("unknown error")
// // 	}

// // 	return validator.NewValidateResult(true, "")
// // }

// // type SecPathDnatTargetIsExistValidator struct{}

// // func (dv SecPathDnatTargetIsExistValidator) Validate(data map[string]interface{}) validator.Result {
// // 	node := data["node"].(firewall.FirewallNode)
// // 	intent := data["intent"].(*policy.Intent)
// // 	inPort := data["inPort"].(api.Port)
// // 	outPort := data["outPort"].(api.Port)
// // 	ok, rule := node.InputNatTargetCheck(intent, inPort, outPort)
// // 	if ok {
// // 		return validator.NewValidateResult(false, fmt.Sprint("target server nat is exist. ", rule))
// // 	}

// // 	return validator.NewValidateResult(true, "")
// // }

// // type SecPathDnatMppaedAddressValidator struct{}

// // func (dv SecPathDnatMppaedAddressValidator) Validate(data map[string]interface{}) validator.Result {
// // 	intent := data["intent"].(*policy.Intent)
// // 	dst := intent.Dst()

// // 	if !(dst.AddressType() == network.HOST || dst.AddressType() == network.SUBNET) {
// // 		return validator.NewValidateResult(false, fmt.Sprint("dnat only support host and subnet, dst: ", dst))
// // 	}

// // 	return validator.NewValidateResult(true, "")
// // }
