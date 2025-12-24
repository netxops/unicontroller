package asa

import (
	"strings"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	v4 "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common/v4"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NewTestASANode 创建用于v4测试的ASA节点
func NewTestASANode() *ASANode {
	// 先创建 DeviceNode，然后创建 ASANode
	deviceNode := node.NewDeviceNode("test-asa-id", "test-asa", api.FIREWALL)
	asa := &ASANode{
		DeviceNode: deviceNode,
		objectSet:  NewASAObjectSet(nil),
		policySet: &PolicySet{
			objects:   nil,
			node:      nil,
			policySet: make(map[string][]*Policy),
		},
		nats: &Nats{
			TwiceNat:  []*NatRule{},
			ObjectNat: []*NatRule{},
			AfterAuto: []*NatRule{},
			objects:   nil,
			node:      nil,
		},
		matrix: &Matrix{
			policySet:   nil,
			node:        nil,
			globalAcl:   "",
			sameLevel:   NO_SAME_LEVEL_TRAFFIC,
			natControl:  false,
			accessGroup: make(map[string]map[string]string),
		},
		snatDesignInfo: []*config.SnatDesignInfo{},
	}

	// 设置关联关系
	asa.objectSet = NewASAObjectSet(asa)
	asa.policySet.objects = asa.objectSet
	asa.policySet.node = asa
	asa.nats.objects = asa.objectSet
	asa.nats.node = asa
	asa.matrix.policySet = asa.policySet
	asa.matrix.node = asa

	return asa
}

// newTestPolicyIntent 创建测试用的策略意图
func newTestPolicyIntent(src, dst, protocol, port string) *policy.Intent {
	intent := &policy.Intent{}

	if src != "" {
		srcNg, _ := network.NewNetworkGroupFromString(src)
		if srcNg != nil {
			intent.SetSrc(srcNg)
		}
	}

	if dst != "" {
		dstNg, _ := network.NewNetworkGroupFromString(dst)
		if dstNg != nil {
			intent.SetDst(dstNg)
		}
	}

	if protocol != "" && port != "" {
		svc, _ := service.NewServiceFromString(protocol + ":" + port)
		if svc != nil {
			intent.SetService(svc)
		}
	}

	return intent
}

// verifyInputPolicyResult 验证InputPolicy返回的数据
func verifyInputPolicyResult(t *testing.T, result processor.AbstractMatchResult, intent *policy.Intent, from, to api.Port, expectedAction firewall.Action) {
	t.Helper()

	if !assert.NotNil(t, result, "InputPolicy不应该返回空，策略应该匹配") {
		t.Fatalf("InputPolicy返回nil，测试失败")
		return
	}

	// 验证类型
	policyResult, ok := result.(*firewall.PolicyMatchResult)
	if !assert.True(t, ok, "InputPolicy应该返回PolicyMatchResult类型") {
		t.Fatalf("InputPolicy返回类型错误，测试失败")
		return
	}

	// 验证Action
	action := policyResult.Action()
	if !assert.Equal(t, int(expectedAction), action, "策略Action应该匹配") {
		t.Logf("InputPolicy result: Action=%d (期望=%d)", action, int(expectedAction))
		rule := policyResult.Rule()
		if rule != nil {
			t.Logf("匹配的策略规则: %s", rule.Cli())
		}
		if zonePort, ok := from.(firewall.ZoneFirewall); ok {
			t.Logf("源Zone: %s", zonePort.Zone())
		}
		if zonePort, ok := to.(firewall.ZoneFirewall); ok {
			t.Logf("目标Zone: %s", zonePort.Zone())
		}
	}

	// 验证Intent匹配
	if !policyResult.Src().IsEmpty() {
		t.Logf("匹配的Intent: Src=%s, Dst=%s, Service=%s",
			policyResult.Src().String(), policyResult.Dst().String(), policyResult.Service().String())
	}
}

// verifyInputNatResult 验证InputNat返回的数据
func verifyInputNatResult(t *testing.T, result processor.AbstractMatchResult, intent *policy.Intent, to api.Port, expectedAction firewall.Action) {
	t.Helper()

	if !assert.NotNil(t, result, "InputNat不应该返回空") {
		t.Fatalf("InputNat返回nil，测试失败")
		return
	}

	// 验证类型
	natResult, ok := result.(*firewall.NatMatchResult)
	if !assert.True(t, ok, "InputNat应该返回NatMatchResult类型") {
		t.Fatalf("InputNat返回类型错误，测试失败")
		return
	}

	// 验证Action
	action := natResult.Action()
	if !assert.Equal(t, int(expectedAction), action, "NAT匹配状态应该匹配") {
		t.Logf("InputNat result: Action=%d (期望=%d)", action, int(expectedAction))
	}

	// 如果匹配成功，验证转换后的Intent
	if action != int(expectedAction) {
		t.Logf("InputNat result: Action=%d (期望=%d)", action, int(expectedAction))
		// translateTo := natResult.TranslateTo()
		// if translateTo != nil {
		// 	// t.Logf("原始Intent: Src=%s, Dst=%s, Service=%s",
		// 	// 	intent.Src().String(), intent.Dst().String(), intent.Service().String())
		// 	// t.Logf("  转换后Intent: Src=%s, Dst=%s, Service=%s",
		// 	// 	translateTo.Src().String(), translateTo.Dst().String(), translateTo.Service().String())

		// 	// 验证目标地址转换（DNAT）
		// 	if intent.RealIp != "" {
		// 		if translateTo.Dst() != nil {
		// 			expectedDst := intent.RealIp
		// 			actualDst := translateTo.Dst().String()
		// 			t.Logf("DNAT地址转换: %s -> %s", intent.Dst().String(), actualDst)
		// 			assert.Contains(t, actualDst, expectedDst, "DNAT应该转换到正确的目标地址")
		// 		}
		// 	}
		// }
	}
}

// applyAsaPolicyAndConfigureInterfaces 应用ASA策略并配置接口
// ASA策略需要：
// 1. 将ACL绑定到接口（access-group命令）
// 2. 设置接口的Security Level
// 3. 设置接口的InAcl/OutAcl
func applyAsaPolicyAndConfigureInterfaces(t *testing.T, node *ASANode, result *v4.PolicyResult, from, to *ASAPort) {
	t.Helper()

	// 使用FlyConfig解析生成的CLI并添加到节点
	// ASA的FlyConfig接受字符串，需要将所有CLI合并
	allCLI := strings.Builder{}
	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
		allCLI.WriteString(networkCLI)
		allCLI.WriteString("\n")
	}
	if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
		allCLI.WriteString(serviceCLI)
		allCLI.WriteString("\n")
	}
	// 先应用对象CLI
	if allCLI.Len() > 0 {
		node.FlyConfig(allCLI.String())
	}
	// 再应用策略CLI
	if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
		node.FlyConfig(policyCLI + "\n")

		// ASA策略需要绑定到接口：生成 access-group 命令
		// 将 ACL 绑定到源接口的输入方向（inbound traffic）
		accessGroupCLI := "access-group " + result.PolicyName + " in interface " + from.Name() + "\n"
		node.FlyConfig(accessGroupCLI)
	}

	// 配置接口的Security Level和InAcl/OutAcl
	// 设置源接口的Security Level（inside通常为100，outside通常为0）
	fromLevel := "100"
	toLevel := "0"
	if from.Zone() == "outside" {
		fromLevel = "0"
	}
	if to.Zone() == "inside" {
		toLevel = "100"
	}

	from.WithLevel(fromLevel)
	from.WithInAcl(result.PolicyName)
	to.WithLevel(toLevel)
}

// TestAsaV4PolicyGeneration 测试基础策略生成
func TestAsaV4PolicyGeneration(t *testing.T) {
	node := NewTestASANode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
	to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
	intent.TicketNumber = "TEST001"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	metaData := map[string]interface{}{
		"policy_name_template": "TEST_policy_{SEQ:id:4:1:1:MAIN}",
		"service_object_name_template": `
result = ""
if service.protocol.Equal("IP"):
	pass
elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
    result = str(service.protocol)
	if service.hasDstPort:
		if service.dst_port.count == 1:
			result = result + "_" + service.dst_port.compact
		else:
			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
elif service.protocol.Equal("ICMP"):
	result = str(service.protocol)
	if service.hasType:
		result = result + "_" + str(service.type)
		if service.hasCode:
			result = result + "_" + str(service.code)
else:
	result = str(service.protocol) + "_" + str(service.protocol.number)
result
`,
		"network_object_name_template": `
result = "DMZ_"
if network.type=="RANGE":
    result = result + network.first + "_" + network.last
elif network.type=="SUBNET":
    result = result + network.cidr
elif network.type=="HOST":
    result = result + network.ip
result
`,
		"securitypolicy.use_source_address_object":      false,
		"securitypolicy.use_destination_address_object": false,
		"securitypolicy.use_service_object":             false,
		"action":                                        "permit",
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 应用ASA策略并配置接口
	applyAsaPolicyAndConfigureInterfaces(t, node, result, from, to)

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestAsaV4PolicyWithObjectStyle 测试使用对象模式的策略生成
func TestAsaV4PolicyWithObjectStyle(t *testing.T) {
	node := NewTestASANode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
	to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
	intent.TicketNumber = "TEST001"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	metaData := map[string]interface{}{
		"policy_name_template": "TEST_policy_{SEQ:id:4:1:1:MAIN}",
		"service_object_name_template": `
result = ""
if service.protocol.Equal("IP"):
	pass
elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
    result = str(service.protocol)
	if service.hasDstPort:
		if service.dst_port.count == 1:
			result = result + "_" + service.dst_port.compact
		else:
			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
elif service.protocol.Equal("ICMP"):
	result = str(service.protocol)
	if service.hasType:
		result = result + "_" + str(service.type)
		if service.hasCode:
			result = result + "_" + str(service.code)
else:
	result = str(service.protocol) + "_" + str(service.protocol.number)
result
`,
		"network_object_name_template": `
result = "DMZ_"
if network.type=="RANGE":
    result = result + network.first + "_" + network.last
elif network.type=="SUBNET":
    result = result + network.cidr
elif network.type=="HOST":
    result = result + network.ip
result
`,
		"securitypolicy.use_source_address_object":      true,
		"securitypolicy.use_destination_address_object": true,
		"securitypolicy.use_service_object":             true,
		"reuse_policy":                                  true,
		"action":                                        "permit",
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Source objects: %v", result.SourceObjects)
	t.Logf("Destination objects: %v", result.DestinationObjects)
	t.Logf("Service objects: %v", result.ServiceObjects)
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 应用ASA策略并配置接口
	applyAsaPolicyAndConfigureInterfaces(t, node, result, from, to)

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestAsaV4MultipleNetworks 测试多个网络地址的策略生成
func TestAsaV4MultipleNetworks(t *testing.T) {
	node := NewTestASANode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
	to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

	// 创建包含多个网络的策略意图
	intent := &policy.Intent{}
	srcNg := network.NewNetworkGroup()
	srcNg.AddGroup(network.NewNetworkGroupFromStringMust("192.168.1.0/24"))
	srcNg.AddGroup(network.NewNetworkGroupFromStringMust("192.168.3.0/24"))
	intent.SetSrc(srcNg)

	dstNg := network.NewNetworkGroup()
	dstNg.AddGroup(network.NewNetworkGroupFromStringMust("10.0.0.0/24"))
	dstNg.AddGroup(network.NewNetworkGroupFromStringMust("10.0.3.0/24"))
	intent.SetDst(dstNg)

	svc, _ := service.NewServiceFromString("tcp:80,443")
	intent.SetService(svc)
	intent.TicketNumber = "TEST001"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	metaData := map[string]interface{}{
		"policy_name_template": "TEST_policy_{SEQ:id:4:1:1:MAIN}",
		"service_object_name_template": `
result = ""
if service.protocol.Equal("IP"):
	pass
elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
    result = str(service.protocol)
	if service.hasDstPort:
		if service.dst_port.count == 1:
			result = result + "_" + service.dst_port.compact
		else:
			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
elif service.protocol.Equal("ICMP"):
	result = str(service.protocol)
	if service.hasType:
		result = result + "_" + str(service.type)
		if service.hasCode:
			result = result + "_" + str(service.code)
else:
	result = str(service.protocol) + "_" + str(service.protocol.number)
result
`,
		"network_object_name_template": `
result = "DMZ_"
if network.type=="RANGE":
    result = result + network.first + "_" + network.last
elif network.type=="SUBNET":
    result = result + network.cidr
elif network.type=="HOST":
    result = result + network.ip
result
`,
		"address_group_name_template": `
result = ""
if meta.get("policy_name") and meta.get("policy_name") != "":
    result = meta.get("policy_name", "") + ("_src_group" if meta.get("is_source") == "true" or meta.get("is_source") == True else "_dst_group")
else:
    result = ("SRC_GROUP" if meta.get("is_source") == "true" or meta.get("is_source") == True else "DST_GROUP")
result
`,
		"service_group_name_template": `
result = ""
if meta.get("policy_name") and meta.get("policy_name") != "":
    result = meta.get("policy_name", "") + "_srv_group"
result
`,
		"securitypolicy.use_source_address_object":       true,
		"securitypolicy.use_destination_address_object":  true,
		"securitypolicy.use_service_object":              true,
		"securitypolicy.source_address_group_style":      "member", // 需要生成地址组成员对象
		"securitypolicy.destination_address_group_style": "member", // 需要生成地址组成员对象
		"securitypolicy.service_group_style":             "member", // 需要生成服务组成员对象
		"action":                                         "permit",
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Source objects: %v", result.SourceObjects)
	t.Logf("Destination objects: %v", result.DestinationObjects)
	t.Logf("Service objects: %v", result.ServiceObjects)
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 验证生成了地址组（多个网络时）
	if len(result.SourceObjects) > 0 {
		// 多个网络时应该创建地址组
		t.Logf("Source object (should be group): %s", result.SourceObjects[0])
	}

	// 应用ASA策略并配置接口
	applyAsaPolicyAndConfigureInterfaces(t, node, result, from, to)

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestAsaV4NetworkObjectNameTemplate 测试网络对象名称模板
func TestAsaV4NetworkObjectNameTemplate(t *testing.T) {
	node := NewTestASANode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
	to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

	// 测试单个 IP 的情况（single_rule == true）
	intent := newTestPolicyIntent("192.168.1.10/32", "10.0.0.10/32", "tcp", "80")
	intent.TicketNumber = "TEST001"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	metaData := map[string]interface{}{
		"policy_name_template": "TEST_policy_{SEQ:id:4:1:1:MAIN}",
		"network_object_name_template": `
result = "DMZ_"
if network.type=="RANGE":
    result = result + network.first + "_" + network.last
elif network.type=="SUBNET":
    result = result + network.cidr
elif network.type=="HOST":
    result = result + network.ip
result
`,
		"securitypolicy.use_source_address_object":      true,
		"securitypolicy.use_destination_address_object": true,
		"securitypolicy.use_service_object":             false,
		"action":                                        "permit",
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Source objects: %v", result.SourceObjects)
	t.Logf("Destination objects: %v", result.DestinationObjects)
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 验证网络对象名称
	if len(result.SourceObjects) > 0 {
		assert.Contains(t, result.SourceObjects[0], "DMZ_", "源地址对象名称应该包含 DMZ_ 前缀")
		t.Logf("Source object name: %s", result.SourceObjects[0])
	}
	if len(result.DestinationObjects) > 0 {
		assert.Contains(t, result.DestinationObjects[0], "DMZ_", "目标地址对象名称应该包含 DMZ_ 前缀")
		t.Logf("Destination object name: %s", result.DestinationObjects[0])
	}

	// 应用ASA策略并配置接口
	applyAsaPolicyAndConfigureInterfaces(t, node, result, from, to)

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestAsaV4ServiceObjectNameTemplate 测试服务对象名称模板
func TestAsaV4ServiceObjectNameTemplate(t *testing.T) {
	node := NewTestASANode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
	to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
	intent.TicketNumber = "TEST001"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	metaData := map[string]interface{}{
		"policy_name_template": "TEST_policy_{SEQ:id:4:1:1:MAIN}",
		"service_object_name_template": `
result = ""
if service.protocol.Equal("IP"):
	pass
elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
    result = str(service.protocol)
	if service.hasDstPort:
		if service.dst_port.count == 1:
			result = result + "_" + service.dst_port.compact
		else:
			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
elif service.protocol.Equal("ICMP"):
	result = str(service.protocol)
	if service.hasType:
		result = result + "_" + str(service.type)
		if service.hasCode:
			result = result + "_" + str(service.code)
else:
	result = str(service.protocol) + "_" + str(service.protocol.number)
result
`,
		"securitypolicy.use_source_address_object":      false,
		"securitypolicy.use_destination_address_object": false,
		"securitypolicy.use_service_object":             true,
		"action":                                        "permit",
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Service objects: %v", result.ServiceObjects)
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 验证服务对象名称
	if len(result.ServiceObjects) > 0 {
		assert.Contains(t, result.ServiceObjects[0], "TCP", "服务对象名称应该包含协议")
		assert.Contains(t, result.ServiceObjects[0], "80", "服务对象名称应该包含端口")
		t.Logf("Service object name: %s", result.ServiceObjects[0])
	}

	// 应用ASA策略并配置接口
	applyAsaPolicyAndConfigureInterfaces(t, node, result, from, to)

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestAsaV4NatPolicyDNAT 测试 DNAT 策略生成
// TestAsaV4NatPolicyUnified 统一的NAT策略测试，支持多种场景
func TestAsaV4NatPolicyUnified(t *testing.T) {
	tests := []struct {
		name           string
		natType        string // "DNAT", "SNAT", "TWICE"
		natStyle       string // "object" 或 "twice"
		mappingType    string // "address" 或 "address_port"
		src            string
		dst            string
		protocol       string
		port           string
		realIp         string
		realPort       string
		snat           string
		dnatObjectType string
		snatObjectType string
		expectKeywords []string // 期望在CLI中出现的关键字
	}{
		// DNAT - Object NAT - 地址映射
		{
			name:        "DNAT_Object_AddressOnly",
			natType:     "DNAT",
			natStyle:    "object",
			mappingType: "address",
			src:         "0.0.0.0/0",
			dst:         "10.0.0.1/32",
			// protocol:       "tcp",
			// port:           "8080",
			realIp:         "192.168.1.10",
			realPort:       "",
			dnatObjectType: "NETWORK_OBJECT",
			expectKeywords: []string{"object network", "nat (inside,outside)"},
		},
		// DNAT - Object NAT - 地址+端口映射
		{
			name:           "DNAT_Object_AddressPort",
			natType:        "DNAT",
			natStyle:       "object",
			mappingType:    "address_port",
			src:            "0.0.0.0/0",
			dst:            "10.0.0.1/32",
			protocol:       "tcp",
			port:           "8080",
			realIp:         "192.168.1.10",
			realPort:       "80",
			dnatObjectType: "NETWORK_OBJECT",
			expectKeywords: []string{"object network", "nat (outside,inside)", "service"},
		},
		// DNAT - Twice NAT - 地址映射
		{
			name:        "DNAT_Twice_AddressOnly",
			natType:     "DNAT",
			natStyle:    "twice",
			mappingType: "address",
			src:         "0.0.0.0/0",
			dst:         "10.0.0.1/32",
			// protocol:       "tcp",
			// port:           "8080",
			realIp:         "192.168.1.10",
			realPort:       "",
			dnatObjectType: "NETWORK_OBJECT",
			expectKeywords: []string{"source static", "destination static"},
		},
		// // DNAT - Twice NAT - 地址+端口映射
		{
			name:           "DNAT_Twice_AddressPort",
			natType:        "DNAT",
			natStyle:       "twice",
			mappingType:    "address_port",
			src:            "0.0.0.0/0",
			dst:            "10.0.0.1/32",
			protocol:       "tcp",
			port:           "8080",
			realIp:         "192.168.1.10",
			realPort:       "80",
			dnatObjectType: "NETWORK_OBJECT",
			expectKeywords: []string{"source static", "destination static", "service"},
		},
		// // SNAT - Object NAT - 地址映射
		// {
		// 	name:           "SNAT_Object_AddressOnly",
		// 	natType:        "SNAT",
		// 	natStyle:       "object",
		// 	mappingType:    "address",
		// 	src:            "192.168.1.0/24",
		// 	dst:            "10.0.0.0/24",
		// 	protocol:       "tcp",
		// 	port:           "80",
		// 	snat:           "203.0.113.1",
		// 	snatObjectType: "NETWORK_OBJECT",
		// 	expectKeywords: []string{"object network", "nat (inside,outside)", "source dynamic"},
		// },
		// Twice NAT - 地址映射
		// {
		// 	name:           "Twice_AddressOnly",
		// 	natType:        "TWICE",
		// 	natStyle:       "twice",
		// 	mappingType:    "address",
		// 	src:            "192.168.1.0/24",
		// 	dst:            "10.0.0.1/32",
		// 	protocol:       "tcp",
		// 	port:           "8080",
		// 	realIp:         "192.168.1.10",
		// 	realPort:       "",
		// 	snat:           "203.0.113.1",
		// 	dnatObjectType: "NETWORK_OBJECT",
		// 	snatObjectType: "NETWORK_OBJECT",
		// 	expectKeywords: []string{"source static", "destination static", "source dynamic"},
		// },
		// // Twice NAT - 地址+端口映射
		// {
		// 	name:           "Twice_AddressPort",
		// 	natType:        "TWICE",
		// 	natStyle:       "twice",
		// 	mappingType:    "address_port",
		// 	src:            "192.168.1.0/24",
		// 	dst:            "10.0.0.1/32",
		// 	protocol:       "tcp",
		// 	port:           "8080",
		// 	realIp:         "192.168.1.10",
		// 	realPort:       "80",
		// 	snat:           "203.0.113.1",
		// 	dnatObjectType: "NETWORK_OBJECT",
		// 	snatObjectType: "NETWORK_OBJECT",
		// 	expectKeywords: []string{"source static", "destination static", "source dynamic", "service"},
		// },
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := NewTestASANode()

			templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
			require.NoError(t, err)

			outside := NewASAPort("outside", "tenant1", nil, nil).WithZone("outside")
			inside := NewASAPort("inside", "tenant1", nil, nil).WithZone("inside")

			// 创建 Intent
			intent := newTestPolicyIntent(tc.src, tc.dst, tc.protocol, tc.port)
			intent.TicketNumber = "TEST001"

			// 设置 NAT 相关字段
			if tc.realIp != "" {
				intent.RealIp = tc.realIp
			}
			if tc.realPort != "" {
				intent.RealPort = tc.realPort
			}
			if tc.snat != "" {
				intent.Snat = tc.snat
			}

			ctx := &firewall.PolicyContext{
				Node:      node,
				Intent:    intent,
				Variables: make(map[string]interface{}),
			}

			// 构建 metaData
			metaData := map[string]interface{}{
				"natpolicy.name_template": "NAT_{SEQ:id:4:1:1:MAIN}",
				"service_object_name_template": `
result = str(service.protocol)
is_source_port = meta.get("is_source_port", False)

# 根据协议类型添加端口或类型信息
if service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
	# 根据 is_source_port 标志使用源端口或目标端口
	if is_source_port:
		# 使用源端口生成命名
		if hasattr(service, "src_port") and not service.src_port.isFull:
			if service.src_port.count == 1:
				result += "_" + service.src_port.compact
			else:
				result += "_" + service.src_port.first + "_" + service.src_port.last
		result += "_NAT"
	else:
		# 使用目标端口生成命名
		if hasattr(service, "dst_port") and not service.dst_port.isFull:
			if service.dst_port.count == 1:
				result += "_" + service.dst_port.compact
			else:
				result += "_" + service.dst_port.first + "_" + service.dst_port.last
elif service.protocol.Equal("ICMP"):
	if hasattr(service, "hasType") and service.hasType:
		result += "_" + str(service.type)
		if hasattr(service, "hasCode") and service.hasCode:
			result += "_" + str(service.code)
elif not service.protocol.Equal("IP"):
	# 其他协议使用协议号
	result += "_" + str(service.protocol.number)

result
`,
				"network_object_name_template": `
result = "DMZ_"
if network.type=="RANGE":
    result += network.first + "_" + network.last
elif network.type=="SUBNET":
    result += network.cidr
elif network.type=="HOST":
    result += network.ip
result
`,
				"action": "permit",
			}

			// 根据 natType 和 natStyle 设置配置
			if tc.natType == "DNAT" {
				metaData["natpolicy.asa.nat_style"] = tc.natStyle
				metaData["natpolicy.dnat.source_object"] = true
				metaData["natpolicy.dnat.destination_object"] = true
				metaData["natpolicy.dnat.service_object"] = true

				if tc.natStyle == "twice" {
					metaData["natpolicy.asa.is_source_port"] = true
					metaData["natpolicy.asa.real_port_service_object"] = true
				} else {
					metaData["natpolicy.asa.is_source_port"] = false
					metaData["natpolicy.asa.real_port_service_object"] = false
				}
			}
			if tc.natType == "SNAT" {
				metaData["natpolicy.asa.nat_style"] = tc.natStyle
				metaData["natpolicy.snat.source_object"] = true
				metaData["natpolicy.snat.destination_object"] = true
				metaData["natpolicy.snat.service_object"] = true
			}

			// 根据 natType 选择端口顺序
			var fromPort, toPort api.Port
			if tc.natType == "DNAT" {
				fromPort = outside
				toPort = inside
			} else {
				fromPort = inside
				toPort = outside
			}

			result, err := templates.MakeNatPolicyV4(fromPort, toPort, intent, ctx, metaData)

			require.NoError(t, err)
			require.NotNil(t, result)

			// t.Logf("Test: %s", tc.name)
			// t.Logf("NAT Type: %s, Style: %s, Mapping: %s", tc.natType, tc.natStyle, tc.mappingType)
			// t.Logf("Generated NAT CLI:\n%s", result.CLIString)

			// // 验证期望的关键字
			// cliStr := result.CLIString
			// for _, keyword := range tc.expectKeywords {
			// 	assert.Contains(t, cliStr, keyword, "CLI应该包含关键字: %s", keyword)
			// }

			// 使用FlyConfig解析生成的CLI并添加到节点
			allCLI := strings.Builder{}
			if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
				allCLI.WriteString(networkCLI)
				allCLI.WriteString("\n")
			}
			if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
				allCLI.WriteString(serviceCLI)
				allCLI.WriteString("\n")
			}
			if natCLI, exists := result.FlyObject["NAT"]; exists && natCLI != "" {
				allCLI.WriteString(natCLI)
				allCLI.WriteString("\n")
			}

			// 应用所有CLI
			if allCLI.Len() > 0 {
				node.FlyConfig(allCLI.String())
			}

			// 验证NAT匹配
			if tc.natType == "DNAT" {
				matchResult := node.InputNat(intent, fromPort)
				verifyInputNatResult(t, matchResult, intent, toPort, firewall.NAT_MATCHED)
			}
		})
	}
}

// TestAsaV4NatPolicySNAT 测试 SNAT 策略生成
func TestAsaV4NatPolicySNAT(t *testing.T) {
	node := NewTestASANode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewASAPort("inside", "tenant1", nil, nil).WithZone("inside")
	to := NewASAPort("outside", "tenant1", nil, nil).WithZone("outside")

	// 创建 SNAT 意图
	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
	intent.Snat = "203.0.113.1"
	intent.TicketNumber = "TEST001"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	metaData := map[string]interface{}{
		"output.nat":                        "natpolicy.snat",
		"snat_object_type":                  "NETWORK_OBJECT",
		"natpolicy.name_template":           "SNAT_{SEQ:id:4:1:1:MAIN}",
		"natpolicy.snat.object_style":       "true",
		"natpolicy.snat.source_object":      "true",
		"natpolicy.snat.destination_object": "true",
		"natpolicy.snat.service_object":     "true",

		"service_object_name_template": `
result = ""
result = str(service.protocol)
is_source_port = meta.get("is_source_port", False)

# 根据协议类型添加端口或类型信息
if service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
	# 根据 is_source_port 标志使用源端口或目标端口
	if is_source_port:
		# 使用源端口生成命名
		if hasattr(service, "src_port") and not service.src_port.isFull:
			if service.src_port.count == 1:
				result += "_" + service.src_port.compact
			else:
				result += "_" + service.src_port.first + "_" + service.src_port.last
		result += "_NAT"
	else:
		# 使用目标端口生成命名
		if hasattr(service, "dst_port") and not service.dst_port.isFull:
			if service.dst_port.count == 1:
				result += "_" + service.dst_port.compact
			else:
				result += "_" + service.dst_port.first + "_" + service.dst_port.last
elif service.protocol.Equal("ICMP"):
	if hasattr(service, "hasType") and service.hasType:
		result += "_" + str(service.type)
		if hasattr(service, "hasCode") and service.hasCode:
			result += "_" + str(service.code)
elif not service.protocol.Equal("IP"):
	# 其他协议使用协议号
	result += "_" + str(service.protocol.number)

result
`,
		"network_object_name_template": `
result = "DMZ_"
if network.type=="RANGE":
    result = result + network.first + "_" + network.last
elif network.type=="SUBNET":
    result = result + network.cidr
elif network.type=="HOST":
    result = result + network.ip
result
`,
		"action": "permit",
	}

	result, err := templates.MakeNatPolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Generated NAT CLI:\n%s", result.CLIString)

	// 使用FlyConfig解析生成的CLI并添加到节点
	allCLI := strings.Builder{}
	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
		allCLI.WriteString(networkCLI)
		allCLI.WriteString("\n")
	}
	if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
		allCLI.WriteString(serviceCLI)
		allCLI.WriteString("\n")
	}
	if natCLI, exists := result.FlyObject["NAT"]; exists && natCLI != "" {
		allCLI.WriteString(natCLI)
		allCLI.WriteString("\n")
	}
	// 应用所有CLI
	if allCLI.Len() > 0 {
		node.FlyConfig(allCLI.String())
	}

	// 使用OutputNat验证NAT匹配
	matchResult := node.OutputNat(intent, from, to)
	verifyInputNatResult(t, matchResult, intent, to, firewall.NAT_MATCHED)
}

// TestAsaV4NetworkTypes 测试不同类型的网络对象（host, range, subnet）
func TestAsaV4NetworkTypes(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		dst      string
		expected string
	}{
		{
			name:     "Host网络",
			src:      "192.168.1.10/32",
			dst:      "10.0.0.10/32",
			expected: "host",
		},
		{
			name:     "Subnet网络",
			src:      "192.168.1.0/24",
			dst:      "10.0.0.0/24",
			expected: "subnet",
		},
		{
			name:     "Range网络",
			src:      "192.168.1.10-192.168.1.20",
			dst:      "10.0.0.10-10.0.0.20",
			expected: "range",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := NewTestASANode()

			templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
			require.NoError(t, err)

			from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
			to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

			intent := newTestPolicyIntent(tc.src, tc.dst, "tcp", "80")
			intent.TicketNumber = "TEST001"

			ctx := &firewall.PolicyContext{
				Node:      node,
				Intent:    intent,
				Variables: make(map[string]interface{}),
			}

			metaData := map[string]interface{}{
				"policy_name_template": "TEST_policy_{SEQ:id:4:1:1:MAIN}",
				"service_object_name_template": `
result = ""
if service.protocol.Equal("IP"):
	pass
elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
    result = str(service.protocol)
	if service.hasDstPort:
		if service.dst_port.count == 1:
			result = result + "_" + service.dst_port.compact
		else:
			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
elif service.protocol.Equal("ICMP"):
	result = str(service.protocol)
	if service.hasType:
		result = result + "_" + str(service.type)
		if service.hasCode:
			result = result + "_" + str(service.code)
else:
	result = str(service.protocol) + "_" + str(service.protocol.number)
result
`,
				"network_object_name_template": `
result = "DMZ_"
if network.type=="RANGE":
    result = result + network.first + "_" + network.last
elif network.type=="SUBNET":
    result = result + network.cidr
elif network.type=="HOST":
    result = result + network.ip
result
`,
				"securitypolicy.use_source_address_object":      true,
				"securitypolicy.use_destination_address_object": true,
				"securitypolicy.use_service_object":             true,
				"action":                                        "permit",
			}

			result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

			require.NoError(t, err)
			require.NotNil(t, result)

			t.Logf("Generated CLI:\n%s", result.CLIString)

			// 验证CLI中包含对应的网络类型关键字
			cliStr := result.CLIString
			if tc.expected == "host" {
				assert.Contains(t, cliStr, "host", "Host网络应该包含'host'关键字")
			} else if tc.expected == "subnet" {
				assert.Contains(t, cliStr, "subnet", "Subnet网络应该包含'subnet'关键字")
			} else if tc.expected == "range" {
				assert.Contains(t, cliStr, "range", "Range网络应该包含'range'关键字")
			}

			// 应用ASA策略并配置接口
			applyAsaPolicyAndConfigureInterfaces(t, node, result, from, to)

			// 使用InputPolicy验证策略匹配
			matchResult := node.InputPolicy(intent, from, to)
			verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
		})
	}
}

// TestAsaV4ComplexService 测试复杂服务对象（多个端口、端口范围等）
func TestAsaV4ComplexService(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		expected string
	}{
		{
			name:     "多个端口",
			service:  "tcp:80,443,8080",
			expected: "多个服务对象",
		},
		{
			name:     "端口范围",
			service:  "tcp:8000-8010",
			expected: "端口范围",
		},
		{
			name:     "TCP和UDP混合",
			service:  "tcp:80;udp:53",
			expected: "混合协议",
		},
		{
			name:     "ICMP协议",
			service:  "icmp",
			expected: "ICMP",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := NewTestASANode()

			templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
			require.NoError(t, err)

			from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
			to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

			intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "", "")
			svc, _ := service.NewServiceFromString(tc.service)
			intent.SetService(svc)
			intent.TicketNumber = "TEST001"

			ctx := &firewall.PolicyContext{
				Node:      node,
				Intent:    intent,
				Variables: make(map[string]interface{}),
			}

			metaData := map[string]interface{}{
				"policy_name_template": "TEST_policy_{SEQ:id:4:1:1:MAIN}",
				"service_object_name_template": `
result = ""
if service.protocol.Equal("IP"):
	pass
elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
    result = str(service.protocol)
	if service.hasDstPort:
		if service.dst_port.count == 1:
			result = result + "_" + service.dst_port.compact
		else:
			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
elif service.protocol.Equal("ICMP"):
	result = str(service.protocol)
	if service.hasType:
		result = result + "_" + str(service.type)
		if service.hasCode:
			result = result + "_" + str(service.code)
else:
	result = str(service.protocol) + "_" + str(service.protocol.number)
result
`,
				"network_object_name_template": `
result = "DMZ_"
if network.type=="RANGE":
    result = result + network.first + "_" + network.last
elif network.type=="SUBNET":
    result = result + network.cidr
elif network.type=="HOST":
    result = result + network.ip
result
`,
				"securitypolicy.use_source_address_object":      false,
				"securitypolicy.use_destination_address_object": false,
				"securitypolicy.use_service_object":             true,
				"securitypolicy.service_group_member":           true,
				"action":                                        "permit",
			}

			result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

			require.NoError(t, err)
			require.NotNil(t, result)

			t.Logf("Service objects: %v", result.ServiceObjects)
			t.Logf("Generated CLI:\n%s", result.CLIString)

			// 验证生成了服务对象
			if len(result.ServiceObjects) > 0 {
				t.Logf("Service object names: %v", result.ServiceObjects)
			}

			// 应用ASA策略并配置接口
			applyAsaPolicyAndConfigureInterfaces(t, node, result, from, to)

			// 使用InputPolicy验证策略匹配
			matchResult := node.InputPolicy(intent, from, to)
			verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
		})
	}
}

// // TestAsaV4TwiceNat 测试两次NAT（同时进行SNAT和DNAT）
// func TestAsaV4TwiceNat(t *testing.T) {
// 	node := NewTestASANode()

// 	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
// 	require.NoError(t, err)

// 	from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
// 	to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

// 	// 创建Twice NAT意图（同时进行SNAT和DNAT）
// 	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.1/32", "tcp", "8080")
// 	intent.RealIp = "192.168.1.10" // DNAT目标地址
// 	intent.RealPort = "80"         // DNAT目标端口
// 	intent.Snat = "203.0.113.1"    // SNAT源地址
// 	intent.TicketNumber = "TEST001"

// 	ctx := &firewall.PolicyContext{
// 		Node:      node,
// 		Intent:    intent,
// 		Variables: make(map[string]interface{}),
// 	}

// 	metaData := map[string]interface{}{
// 		"input.nat":                         "natpolicy.dnat",
// 		"output.nat":                        "natpolicy.snat",
// 		"dnat_object_type":                  "NETWORK_OBJECT",
// 		"snat_object_type":                  "NETWORK_OBJECT",
// 		"natpolicy.name_template":           "TWICE_NAT_{SEQ:id:4:1:1:MAIN}",
// 		"natpolicy.dnat.object_style":       "true",
// 		"natpolicy.dnat.source_object":      "true",
// 		"natpolicy.dnat.destination_object": "true",
// 		"natpolicy.dnat.service_object":     "true",
// 		"natpolicy.snat.object_style":       "true",
// 		"natpolicy.snat.source_object":      "true",
// 		"natpolicy.snat.destination_object": "true",
// 		"natpolicy.snat.service_object":     "true",
// 		"service_object_name_template": `
// result = ""
// if service.protocol.Equal("IP"):
// 	pass
// elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
//     result = str(service.protocol)
// 	if service.hasDstPort:
// 		if service.dst_port.count == 1:
// 			result = result + "_" + service.dst_port.compact
// 		else:
// 			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
// elif service.protocol.Equal("ICMP"):
// 	result = str(service.protocol)
// 	if service.hasType:
// 		result = result + "_" + str(service.type)
// 		if service.hasCode:
// 			result = result + "_" + str(service.code)
// else:
// 	result = str(service.protocol) + "_" + str(service.protocol.number)
// result
// `,
// 		"network_object_name_template": `
// result = "DMZ_"
// if network.type=="RANGE":
//     result = result + network.first + "_" + network.last
// elif network.type=="SUBNET":
//     result = result + network.cidr
// elif network.type=="HOST":
//     result = result + network.ip
// result
// `,
// 		"mip_name_template": `
// result = "MIP_" + intent.real_ip
// result
// `,
// 		"action": "permit",
// 	}

// 	result, err := templates.MakeNatPolicyV4(from, to, intent, ctx, metaData)

// 	require.NoError(t, err)
// 	require.NotNil(t, result)

// 	t.Logf("Generated NAT CLI:\n%s", result.CLIString)

// 	// 验证CLI中包含Twice NAT的关键字
// 	cliStr := result.CLIString
// 	assert.Contains(t, cliStr, "source static", "Twice NAT应该包含source static")
// 	assert.Contains(t, cliStr, "destination static", "Twice NAT应该包含destination static")

// 	// 使用FlyConfig解析生成的CLI并添加到节点
// 	allCLI := strings.Builder{}
// 	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
// 		allCLI.WriteString(networkCLI)
// 		allCLI.WriteString("\n")
// 	}
// 	if natCLI, exists := result.FlyObject["NAT"]; exists && natCLI != "" {
// 		allCLI.WriteString(natCLI)
// 		allCLI.WriteString("\n")
// 	}
// 	// 应用所有CLI
// 	if allCLI.Len() > 0 {
// 		node.FlyConfig(allCLI.String())
// 	}

// 	// 使用InputNat验证NAT匹配
// 	matchResult := node.InputNat(intent, from)
// 	verifyInputNatResult(t, matchResult, intent, to, firewall.NAT_MATCHED)
// }

// TestAsaV4ObjectNatSNAT 测试对象NAT（SNAT）
// func TestAsaV4ObjectNatSNAT(t *testing.T) {
// 	node := NewTestASANode()

// 	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
// 	require.NoError(t, err)

// 	from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("inside")
// 	to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("outside")

// 	// 创建Object NAT SNAT意图
// 	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
// 	intent.Snat = "203.0.113.1"
// 	intent.TicketNumber = "TEST001"

// 	ctx := &firewall.PolicyContext{
// 		Node:      node,
// 		Intent:    intent,
// 		Variables: make(map[string]interface{}),
// 	}

// 	metaData := map[string]interface{}{
// 		"output.nat":                        "natpolicy.snat",
// 		"snat_object_type":                  "NETWORK_OBJECT",
// 		"natpolicy.name_template":           "OBJECT_NAT_SNAT_{SEQ:id:4:1:1:MAIN}",
// 		"natpolicy.snat.object_style":       "true",
// 		"natpolicy.snat.source_object":      "true",
// 		"natpolicy.snat.destination_object": "true",
// 		"natpolicy.snat.service_object":     "true",
// 		"service_object_name_template": `
// result = ""
// if service.protocol.Equal("IP"):
// 	pass
// elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
//     result = str(service.protocol)
// 	if service.hasDstPort:
// 		if service.dst_port.count == 1:
// 			result = result + "_" + service.dst_port.compact
// 		else:
// 			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
// elif service.protocol.Equal("ICMP"):
// 	result = str(service.protocol)
// 	if service.hasType:
// 		result = result + "_" + str(service.type)
// 		if service.hasCode:
// 			result = result + "_" + str(service.code)
// else:
// 	result = str(service.protocol) + "_" + str(service.protocol.number)
// result
// `,
// 		"network_object_name_template": `
// result = "DMZ_"
// if network.type=="RANGE":
//     result = result + network.first + "_" + network.last
// elif network.type=="SUBNET":
//     result = result + network.cidr
// elif network.type=="HOST":
//     result = result + network.ip
// result
// `,
// 		"action": "permit",
// 	}

// 	result, err := templates.MakeNatPolicyV4(from, to, intent, ctx, metaData)

// 	require.NoError(t, err)
// 	require.NotNil(t, result)

// 	t.Logf("Generated NAT CLI:\n%s", result.CLIString)

// 	// 验证CLI中包含Object NAT的关键字
// 	cliStr := result.CLIString
// 	assert.Contains(t, cliStr, "object network", "Object NAT应该包含'object network'关键字")

// 	// 使用FlyConfig解析生成的CLI并添加到节点
// 	allCLI := strings.Builder{}
// 	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
// 		allCLI.WriteString(networkCLI)
// 		allCLI.WriteString("\n")
// 	}
// 	if natCLI, exists := result.FlyObject["NAT"]; exists && natCLI != "" {
// 		allCLI.WriteString(natCLI)
// 		allCLI.WriteString("\n")
// 	}
// 	// 应用所有CLI
// 	if allCLI.Len() > 0 {
// 		node.FlyConfig(allCLI.String())
// 	}

// 	// 使用OutputNat验证NAT匹配
// 	matchResult := node.OutputNat(intent, from, to)
// 	verifyInputNatResult(t, matchResult, intent, to, firewall.NAT_MATCHED)
// }

// // TestAsaV4ObjectNatDNAT 测试对象NAT（DNAT）
// func TestAsaV4ObjectNatDNAT(t *testing.T) {
// 	node := NewTestASANode()

// 	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
// 	require.NoError(t, err)

// 	from := NewASAPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("outside")
// 	to := NewASAPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("inside")

// 	// 创建Object NAT DNAT意图
// 	intent := newTestPolicyIntent("0.0.0.0/0", "10.0.0.1/32", "tcp", "8080")
// 	intent.RealIp = "192.168.1.10"
// 	intent.RealPort = "80"
// 	intent.TicketNumber = "TEST001"

// 	ctx := &firewall.PolicyContext{
// 		Node:      node,
// 		Intent:    intent,
// 		Variables: make(map[string]interface{}),
// 	}

// 	metaData := map[string]interface{}{
// 		"input.nat":                         "natpolicy.dnat",
// 		"dnat_object_type":                  "NETWORK_OBJECT",
// 		"natpolicy.name_template":           "OBJECT_NAT_DNAT_{SEQ:id:4:1:1:MAIN}",
// 		"natpolicy.dnat.object_style":       "true",
// 		"natpolicy.dnat.source_object":      "true",
// 		"natpolicy.dnat.destination_object": "true",
// 		"natpolicy.dnat.service_object":     "true",
// 		"service_object_name_template": `
// result = ""
// if service.protocol.Equal("IP"):
// 	pass
// elif service.protocol.Equal("TCP") or service.protocol.Equal("UDP"):
//     result = str(service.protocol)
// 	if service.hasDstPort:
// 		if service.dst_port.count == 1:
// 			result = result + "_" + service.dst_port.compact
// 		else:
// 			result = result + "_" + service.dst_port.first + "_" + service.dst_port.last
// elif service.protocol.Equal("ICMP"):
// 	result = str(service.protocol)
// 	if service.hasType:
// 		result = result + "_" + str(service.type)
// 		if service.hasCode:
// 			result = result + "_" + str(service.code)
// else:
// 	result = str(service.protocol) + "_" + str(service.protocol.number)
// result
// `,
// 		"network_object_name_template": `
// result = "DMZ_"
// if network.type=="RANGE":
//     result = result + network.first + "_" + network.last
// elif network.type=="SUBNET":
//     result = result + network.cidr
// elif network.type=="HOST":
//     result = result + network.ip
// result
// `,
// 		"mip_name_template": `
// result = "MIP_" + intent.real_ip
// result
// `,
// 		"action": "permit",
// 	}

// 	result, err := templates.MakeNatPolicyV4(from, to, intent, ctx, metaData)

// 	require.NoError(t, err)
// 	require.NotNil(t, result)

// 	t.Logf("Generated NAT CLI:\n%s", result.CLIString)

// 	// 验证CLI中包含Object NAT的关键字
// 	cliStr := result.CLIString
// 	assert.Contains(t, cliStr, "object network", "Object NAT应该包含'object network'关键字")

// 	// 使用FlyConfig解析生成的CLI并添加到节点
// 	allCLI := strings.Builder{}
// 	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
// 		allCLI.WriteString(networkCLI)
// 		allCLI.WriteString("\n")
// 	}
// 	if natCLI, exists := result.FlyObject["NAT"]; exists && natCLI != "" {
// 		allCLI.WriteString(natCLI)
// 		allCLI.WriteString("\n")
// 	}
// 	// 应用所有CLI
// 	if allCLI.Len() > 0 {
// 		node.FlyConfig(allCLI.String())
// 	}

// 	// 使用InputNat验证NAT匹配
// 	matchResult := node.InputNat(intent, from)
// 	verifyInputNatResult(t, matchResult, intent, to, firewall.NAT_MATCHED)
// }
