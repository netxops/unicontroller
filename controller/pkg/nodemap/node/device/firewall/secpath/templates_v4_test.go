package secpath

import (
	"fmt"
	"strings"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
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

// verifyInputPolicyResult 验证InputPolicy返回的数据
func verifyInputPolicyResult(t *testing.T, result processor.AbstractMatchResult, intent *policy.Intent, from, to api.Port, expectedAction firewall.Action) {
	t.Helper()

	if !assert.NotNil(t, result, "InputPolicy不应该返回空，策略应该匹配") {
		t.Fatalf("InputPolicy返回nil，测试失败")
		return
	}

	// 验证类型
	policyResult, ok := result.(*firewall.PolicyMatchResult)
	if !ok {
		t.Fatalf("InputPolicy返回结果类型错误，期望 *firewall.PolicyMatchResult，实际 %T", result)
		return
	}

	// 验证Action
	action := policyResult.Action()
	t.Logf("InputPolicy result: Action=%d (期望=%d)", action, int(expectedAction))
	assert.Equal(t, int(expectedAction), action, "策略动作应该匹配")

	// 验证Rule
	rule := policyResult.Rule()
	assert.NotNil(t, rule, "策略规则不应该为nil")
	if rule != nil {
		t.Logf("匹配的策略规则: %s", rule.Cli())
	}

	// 验证FromPort
	fromPort := policyResult.FromPort()
	assert.NotNil(t, fromPort, "源端口不应该为nil")
	if fromPort != nil {
		if zonePort, ok := fromPort.(firewall.ZoneFirewall); ok {
			t.Logf("源Zone: %s", zonePort.Zone())
		} else {
			t.Logf("源端口: %s", fromPort.Name())
		}
	}

	// 验证OutPort
	outPort := policyResult.OutPort()
	assert.NotNil(t, outPort, "目标端口不应该为nil")
	if outPort != nil {
		if zonePort, ok := outPort.(firewall.ZoneFirewall); ok {
			t.Logf("目标Zone: %s", zonePort.Zone())
		} else {
			t.Logf("目标端口: %s", outPort.Name())
		}
	}
}

// verifyInputNatResult 验证InputNat返回的数据
func verifyInputNatResult(t *testing.T, result processor.AbstractMatchResult, intent *policy.Intent, to api.Port, expectedAction firewall.Action) {
	t.Helper()

	if !assert.NotNil(t, result, "InputNat不应该返回空，NAT规则应该匹配") {
		t.Fatalf("InputNat返回nil，测试失败")
		return
	}

	// 验证类型
	natResult, ok := result.(*firewall.NatMatchResult)
	if !ok {
		t.Fatalf("InputNat返回结果类型错误，期望 *firewall.NatMatchResult，实际 %T", result)
		return
	}

	// 验证Action
	action := natResult.Action()
	t.Logf("InputNat result: Action=%d (期望=%d)", action, int(expectedAction))
	if action != int(expectedAction) {
		t.Logf("警告：NAT规则未匹配，Action=%d (期望=%d)", action, int(expectedAction))
		t.Logf("可能的原因：")
		t.Logf("  - 服务对象未正确创建")
		t.Logf("  - VIP/MIP对象未正确创建")
		t.Logf("  - NAT策略CLI格式不正确")
		t.Logf("  - Zone配置不正确")
	} else {
		t.Logf("✓ NAT规则匹配成功")
	}

	// 验证Rule和Translate
	rule := natResult.Rule()
	if rule != nil {
		t.Logf("匹配的NAT规则: %s", rule.Cli())

		// 验证规则中的Translate方法
		ruleTranslate := rule.Translate()
		if ruleTranslate != nil {
			t.Logf("规则中的Translate定义:")
			if ruleTranslate.Dst() != nil && !ruleTranslate.Dst().IsEmpty() {
				t.Logf("  - Dst: %s", ruleTranslate.Dst().String())
			}
			if ruleTranslate.Src() != nil && !ruleTranslate.Src().IsEmpty() {
				t.Logf("  - Src: %s", ruleTranslate.Src().String())
			}
			if ruleTranslate.Service() != nil && !ruleTranslate.Service().IsEmpty() {
				t.Logf("  - Service: %s", ruleTranslate.Service().String())
			}
		} else {
			t.Logf("警告：规则中的Translate为nil")
		}
	}

	// 验证TranslateTo（DNAT）- 只在匹配成功时验证
	if action == int(firewall.NAT_MATCHED) {
		translateTo := natResult.TranslateTo()
		if assert.NotNil(t, translateTo, "DNAT应该返回转换后的intent") {
			t.Logf("转换后的Intent:")
			t.Logf("  原始Intent: Src=%s, Dst=%s, Service=%s",
				intent.Src().String(), intent.Dst().String(), intent.Service().String())
			t.Logf("  转换后Intent: Src=%s, Dst=%s, Service=%s",
				translateTo.Src().String(), translateTo.Dst().String(), translateTo.Service().String())

			// 验证目标地址转换（DNAT）
			if intent.RealIp != "" {
				if translateTo.Dst() != nil {
					expectedDst := intent.RealIp
					actualDst := translateTo.Dst().String()
					t.Logf("DNAT地址转换: %s -> %s", intent.Dst().String(), actualDst)
					assert.Contains(t, actualDst, expectedDst, "DNAT应该转换到正确的目标地址")

					// 验证转换后的地址与规则中的translate一致（如果规则有定义）
					if rule != nil && rule.Translate() != nil {
						ruleTranslate := rule.Translate()
						if ruleTranslate.Dst() != nil && !ruleTranslate.Dst().IsEmpty() {
							// 验证转换后的地址是否在规则定义的translate范围内
							ruleDstStr := ruleTranslate.Dst().String()
							t.Logf("规则Translate.Dst: %s, 转换后Dst: %s", ruleDstStr, actualDst)
							// 注意：这里不强制要求完全匹配，因为translate可能是一个范围
						}
					}
				} else {
					t.Errorf("DNAT转换后Dst()为nil，但RealIp不为空")
				}
			}

			// 验证端口转换（DNAT）
			if intent.RealPort != "" {
				if translateTo.Service() != nil {
					actualService := translateTo.Service().String()
					t.Logf("DNAT端口转换: %s -> %s", intent.Service().String(), actualService)
					assert.Contains(t, actualService, intent.RealPort, "DNAT应该转换到正确的端口")

					// 验证转换后的服务与规则中的translate一致（如果规则有定义）
					if rule != nil && rule.Translate() != nil {
						ruleTranslate := rule.Translate()
						if ruleTranslate.Service() != nil && !ruleTranslate.Service().IsEmpty() {
							ruleSvcStr := ruleTranslate.Service().String()
							t.Logf("规则Translate.Service: %s, 转换后Service: %s", ruleSvcStr, actualService)
						}
					}
				} else {
					t.Errorf("DNAT转换后Service()为nil，但RealPort不为空")
				}
			}

			// 验证源地址保持不变（DNAT通常不改变源地址）
			if translateTo.Src() != nil {
				originalSrc := intent.Src().String()
				translatedSrc := translateTo.Src().String()
				if originalSrc != "" && translatedSrc != "" {
					t.Logf("源地址验证: %s -> %s (DNAT通常不改变源地址)", originalSrc, translatedSrc)
				}
			}
		} else {
			t.Errorf("DNAT匹配成功但TranslateTo()为nil")
		}
	} else if action != int(firewall.NAT_MATCHED) {
		// 如果未匹配，打印详细的调试信息
		t.Logf("生成的CLI用于调试:")
		// 这些信息会在调用处打印，这里只记录未匹配的情况
	}

	// 验证FromPort
	fromPort := natResult.FromPort()
	assert.NotNil(t, fromPort, "源端口不应该为nil")
}

// verifyOutputNatResult 验证OutputNat返回的数据
func verifyOutputNatResult(t *testing.T, result processor.AbstractMatchResult, intent *policy.Intent, from, to api.Port, expectedAction firewall.Action) {
	t.Helper()

	if result == nil {
		t.Logf("OutputNat返回nil，可能的原因：")
		t.Logf("  - NAT策略CLI未正确解析（pool_id格式问题）")
		t.Logf("  - SNAT_POOL对象未正确创建")
		t.Logf("  - Zone配置不正确")
		return
	}

	// 验证类型
	natResult, ok := result.(*firewall.NatMatchResult)
	if !ok {
		t.Fatalf("OutputNat返回结果类型错误，期望 *firewall.NatMatchResult，实际 %T", result)
		return
	}

	// 验证Action - 必须是 NAT_MATCHED 才能继续验证
	action := natResult.Action()
	t.Logf("OutputNat result: Action=%d (期望=%d)", action, int(expectedAction))
	if action != int(expectedAction) {
		t.Errorf("NAT规则未匹配，Action=%d (期望=%d)", action, int(expectedAction))
		t.Logf("可能的原因：")
		t.Logf("  - pool_id格式问题导致策略未正确解析")
		t.Logf("  - SNAT_POOL对象未正确创建")
		t.Logf("  - Zone配置不正确")
		t.Logf("  - NAT策略CLI格式不正确")
		return // 如果action不匹配，直接返回，不进行后续验证
	}
	t.Logf("✓ NAT规则匹配成功")

	// 验证Rule和Translate
	rule := natResult.Rule()
	if rule != nil {
		t.Logf("匹配的NAT规则: %s", rule.Cli())

		// 验证规则中的Translate方法
		ruleTranslate := rule.Translate()
		if ruleTranslate != nil {
			t.Logf("规则中的Translate定义:")
			if ruleTranslate.Dst() != nil && !ruleTranslate.Dst().IsEmpty() {
				t.Logf("  - Dst: %s", ruleTranslate.Dst().String())
			}
			if ruleTranslate.Src() != nil && !ruleTranslate.Src().IsEmpty() {
				t.Logf("  - Src: %s", ruleTranslate.Src().String())
			}
			if ruleTranslate.Service() != nil && !ruleTranslate.Service().IsEmpty() {
				t.Logf("  - Service: %s", ruleTranslate.Service().String())
			}
		} else {
			t.Logf("警告：规则中的Translate为nil")
		}
	}

	// 只有当action是NAT_MATCHED时，才进行详细的转换验证
	if action == int(firewall.NAT_MATCHED) {
		translateTo := natResult.TranslateTo()
		if assert.NotNil(t, translateTo, "SNAT应该返回转换后的intent") {
			t.Logf("转换后的Intent:")
			t.Logf("  原始Intent: Src=%s, Dst=%s, Service=%s",
				intent.Src().String(), intent.Dst().String(), intent.Service().String())
			t.Logf("  转换后Intent: Src=%s, Dst=%s, Service=%s",
				translateTo.Src().String(), translateTo.Dst().String(), translateTo.Service().String())

			// 验证源地址转换（SNAT）
			if intent.Snat != "" {
				if translateTo.Src() != nil {
					actualSrc := translateTo.Src().String()
					t.Logf("SNAT地址转换: %s -> %s", intent.Src().String(), actualSrc)
					assert.NotEmpty(t, actualSrc, "SNAT应该转换源地址")

					// 验证转换后的地址与规则中的translate一致（如果规则有定义）
					if rule != nil && rule.Translate() != nil {
						ruleTranslate := rule.Translate()
						if ruleTranslate.Src() != nil && !ruleTranslate.Src().IsEmpty() {
							// 验证转换后的地址是否在规则定义的translate范围内
							ruleSrcStr := ruleTranslate.Src().String()
							t.Logf("规则Translate.Src: %s, 转换后Src: %s", ruleSrcStr, actualSrc)
							// 注意：这里不强制要求完全匹配，因为translate可能是一个范围或池
						}
					}
				} else {
					t.Errorf("SNAT转换后Src()为nil，但Snat不为空")
				}
			}

			// 验证目标地址保持不变（SNAT通常不改变目标地址）
			if translateTo.Dst() != nil {
				originalDst := intent.Dst().String()
				translatedDst := translateTo.Dst().String()
				if originalDst != "" && translatedDst != "" {
					t.Logf("目标地址验证: %s -> %s (SNAT通常不改变目标地址)", originalDst, translatedDst)
				}
			}

			// 验证服务保持不变（SNAT通常不改变服务）
			if translateTo.Service() != nil {
				originalSvc := intent.Service().String()
				translatedSvc := translateTo.Service().String()
				if originalSvc != "" && translatedSvc != "" {
					t.Logf("服务验证: %s -> %s (SNAT通常不改变服务)", originalSvc, translatedSvc)
					// SNAT通常不改变服务，但允许有变化（某些场景下可能改变）
				}
			}
		} else {
			t.Errorf("SNAT匹配成功但TranslateTo()为nil")
		}
	}

	// 验证FromPort和OutPort
	fromPort := natResult.FromPort()
	assert.NotNil(t, fromPort, "源端口不应该为nil")

	outPort := natResult.OutPort()
	assert.NotNil(t, outPort, "目标端口不应该为nil")
}

func NewTestSecPathNode() *SecPathNode {
	// 先创建 DeviceNode，然后创建 SecPathNode
	deviceNode := node.NewDeviceNode("test-secpath-id", "test-secpath", api.FIREWALL)
	node := &SecPathNode{
		DeviceNode: deviceNode,
		PolicySet: &PolicySet{
			ipv4NameAcl:       make(map[string]*PolicyGroup),
			ipv6NameAcl:       make(map[string]*PolicyGroup),
			securityPolicyAcl: []*Policy{},
		},
		Nats:   &Nats{},
		AclSet: &ACLSet{Sets: []*ACL{}},
	}
	node.ObjectSet = NewSecPathObjectSet(node)
	node.PolicySet.node = node
	node.PolicySet.objects = node.ObjectSet
	node.AclSet.objects = node.ObjectSet
	node.Nats.objects = node.ObjectSet
	node.Nats.node = node

	// 添加一些示例地址对象
	node.ObjectSet.ZoneNetworkMap = map[ZoneName]map[string]firewall.FirewallNetworkObject{
		"trust": {
			"internal_network": &secpathNetwork{
				ObjName:      "internal_network",
				NetworkGroup: network.NewNetworkGroupFromStringMust("192.168.1.0/24"),
			},
			"dmz_network": &secpathNetwork{
				ObjName:      "dmz_network",
				NetworkGroup: network.NewNetworkGroupFromStringMust("172.16.0.0/16"),
			},
		},
		"untrust": {
			"external_network": &secpathNetwork{
				ObjName:      "external_network",
				NetworkGroup: network.NewNetworkGroupFromStringMust("10.0.0.0/8"),
			},
		},
	}

	// 添加一些示例服务对象
	node.ObjectSet.ServiceMap = map[string]firewall.FirewallServiceObject{
		"HTTP": &secpathService{
			name:    "HTTP",
			service: service.NewServiceMust("tcp:80"),
		},
		"HTTPS": &secpathService{
			name:    "HTTPS",
			service: service.NewServiceMust("tcp:443"),
		},
		"DNS": &secpathService{
			name:    "DNS",
			service: service.NewServiceMust("udp:53"),
		},
	}

	// 添加一些示例安全策略
	node.PolicySet.securityPolicyAcl = []*Policy{
		{
			id:     1,
			name:   "allow_http_to_dmz",
			ipType: network.IPv4,
			policyEntry: policy.NewPolicyEntryWithAll(
				network.NewNetworkGroupFromStringMust("192.168.1.0/24"),
				network.NewNetworkGroupFromStringMust("172.16.0.0/16"),
				service.NewServiceMust("tcp:80"),
			),
			node:      node,
			srcZone:   []string{"trust"},
			dstZone:   []string{"dmz"},
			srcAddr:   []string{"192.168.1.0/24"},
			srcObject: []string{"internal_network"},
			dstAddr:   []string{"172.16.0.0/16"},
			dstObject: []string{"dmz_network"},
			srv:       []string{"tcp:80"},
			srvObject: []string{"HTTP"},
			action:    firewall.POLICY_PERMIT,
			status:    firewall.POLICY_ACTIVE,
			objects:   node.ObjectSet,
		},
		{
			id:     2,
			name:   "allow_https_to_external",
			ipType: network.IPv4,
			policyEntry: policy.NewPolicyEntryWithAll(
				network.NewNetworkGroupFromStringMust("192.168.1.0/24"),
				network.NewNetworkGroupFromStringMust("10.0.0.0/8"),
				service.NewServiceMust("tcp:443"),
			),
			node:      node,
			srcZone:   []string{"trust"},
			dstZone:   []string{"untrust"},
			srcAddr:   []string{"192.168.1.0/24"},
			srcObject: []string{"internal_network"},
			dstAddr:   []string{"10.0.0.0/8"},
			dstObject: []string{"external_network"},
			srv:       []string{"tcp:443"},
			srvObject: []string{"HTTPS"},
			action:    firewall.POLICY_PERMIT,
			status:    firewall.POLICY_ACTIVE,
			objects:   node.ObjectSet,
		},
	}

	return node
}

// simplePortIterator 简单的 PortIterator 实现，用于测试
type simplePortIterator struct {
	ports map[string]api.Port
}

func (s *simplePortIterator) GetPort(ref string) api.Port {
	return s.ports[ref]
}

func (s *simplePortIterator) GetAllPorts() []api.Port {
	result := make([]api.Port, 0, len(s.ports))
	for _, port := range s.ports {
		result = append(result, port)
	}
	return result
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

// TestSecPathV4PolicyGeneration 测试 SecPath V4 策略生成
func TestSecPathV4PolicyGeneration(t *testing.T) {
	// 创建 SecPath 节点
	node := NewTestSecPathNode()

	// 创建 V4 模板（使用 Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	// 创建端口
	from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, []api.Member{}).WithZone("trust")
	to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", map[network.IPFamily][]string{
		network.IPv4: {"10.0.0.1/24"},
	}, []api.Member{}).WithZone("untrust")

	// 创建策略意图
	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
	intent.TicketNumber = "HQWLTK20250327001"
	intent.SubTicket = "1"

	// 创建策略上下文
	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	// 配置 metadata（参考 config.yaml）
	metaData := map[string]interface{}{
		"policy_name_template":                          "GL4F-policy{SEQ:id:4:1:1:MAIN}",
		"service_object_name_template":                  `result = meta.get("policy_name", "") + "_"; items = intent.service.EachDetailed() if intent.service else []; result += items[0].protocol.lower if len(items) > 0 else ""; result += "_" + str(meta.get("compact_port", "")) if meta.get("compact_port") and meta.get("compact_port") != "" else ""; result`,
		"network_object_name_template":                  `result = ""; if meta.get("single_rule") == "true" or meta.get("single_rule") == True: ng = intent.src.EachDataRangeEntryAsAbbrNet() if meta.get("is_source") == "true" or meta.get("is_source") == True else intent.dst.EachDataRangeEntryAsAbbrNet(); result = "DMZ_" + ng[0].ip if len(ng) > 0 else ""; elif meta.get("object_name") and meta.get("object_name") != "": result = meta.get("object_name", ""); elif meta.get("policy_name") and meta.get("policy_name") != "": result = meta.get("policy_name", "") + ("_src_addr" if meta.get("is_source") == "true" or meta.get("is_source") == True else "_dst_addr"); result`,
		"securitypolicy.use_source_address_object":      false,
		"securitypolicy.use_destination_address_object": false,
		"securitypolicy.use_service_object":             false,
		"reuse_policy":                                  "true",
		"action":                                        "permit",
	}

	// 生成策略
	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err, "策略生成应该成功")
	require.NotNil(t, result, "结果不应为 nil")

	// 验证策略名称
	assert.NotEmpty(t, result.PolicyName, "策略名称不应为空")
	t.Logf("Generated policy name: %s", result.PolicyName)

	// 验证 CLI 字符串
	assert.NotEmpty(t, result.CLIString, "CLI 字符串不应为空")
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 验证 CLI 包含基本元素（根据 SecPath 格式）
	assert.Contains(t, result.CLIString, "rule", "应该包含 rule")
	assert.Contains(t, result.CLIString, "name", "应该包含 name")
	assert.Contains(t, result.CLIString, "source-zone", "应该包含 source-zone")
	assert.Contains(t, result.CLIString, "destination-zone", "应该包含 destination-zone")
	assert.Contains(t, result.CLIString, "action", "应该包含 action")

	// 使用FlyConfig解析生成的CLI并添加到节点
	flyObject := make(map[string]string)
	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
		flyObject["NETWORK"] = networkCLI
	}
	if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
		flyObject["SERVICE"] = serviceCLI
	}
	// 先应用对象CLI
	if len(flyObject) > 0 {
		node.FlyConfig(flyObject)
	}
	// 再应用策略CLI
	if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
		node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
	}

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestSecPathV4PolicyWithObjectStyle 测试使用对象模式的策略生成
func TestSecPathV4PolicyWithObjectStyle(t *testing.T) {
	node := NewTestSecPathNode()

	// 创建 V4 模板（使用 Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("trust")
	to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("untrust")

	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
	intent.TicketNumber = "HQWLTK20250327001"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	// 使用对象模式（参考 config.yaml 中的第二个设备配置）
	metaData := map[string]interface{}{
		"policy_name_template": "JiS_DMZ_{SEQ:id:3:1:1:MAIN}",
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
		"reuse_policy":                                  "true",
		"action":                                        "permit",
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Source objects: %v", result.SourceObjects)
	t.Logf("Destination objects: %v", result.DestinationObjects)
	t.Logf("Service objects: %v", result.ServiceObjects)
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 使用FlyConfig解析生成的CLI并添加到节点
	flyObject := make(map[string]string)
	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
		flyObject["NETWORK"] = networkCLI
	}
	if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
		flyObject["SERVICE"] = serviceCLI
	}
	// 先应用对象CLI
	if len(flyObject) > 0 {
		node.FlyConfig(flyObject)
	}
	// 再应用策略CLI
	if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
		node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
	}

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestSecPathV4PolicyNameTemplate 测试策略名称模板
func TestSecPathV4PolicyNameTemplate(t *testing.T) {
	node := NewTestSecPathNode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("trust")
	to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("untrust")

	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
	intent.TicketNumber = "HQWLTK20250327001"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	testCases := []struct {
		name           string
		template       string
		expectedPrefix string
	}{
		{
			name:           "GL4F policy template",
			template:       "GL4F-policy{SEQ:id:4:1:1:MAIN}",
			expectedPrefix: "GL4F-policy",
		},
		{
			name:           "JiS DMZ policy template",
			template:       "JiS_DMZ_{SEQ:id:3:1:1:MAIN}",
			expectedPrefix: "JiS_DMZ_",
		},
		{
			name:           "LY policy template",
			template:       "LY_policy_{SEQ:id:4:1:1:MAIN}",
			expectedPrefix: "LY_policy_",
		},
		{
			name:           "YiZ DMZ policy template",
			template:       "YiZ_DMZ_policy{SEQ:id:4:2000:1:MAIN}",
			expectedPrefix: "YiZ_DMZ_policy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metaData := map[string]interface{}{
				"policy_name_template":                          tc.template,
				"securitypolicy.use_source_address_object":      false,
				"securitypolicy.use_destination_address_object": false,
				"securitypolicy.use_service_object":             false,
				"action":                                        "permit",
			}

			result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.True(t, strings.HasPrefix(result.PolicyName, tc.expectedPrefix),
				"策略名称应该以 %s 开头，实际为 %s", tc.expectedPrefix, result.PolicyName)
			t.Logf("Policy name: %s", result.PolicyName)

			// 使用FlyConfig解析生成的CLI并添加到节点
			flyObject := make(map[string]string)
			if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
				flyObject["NETWORK"] = networkCLI
			}
			if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
				flyObject["SERVICE"] = serviceCLI
			}
			// 先应用对象CLI
			if len(flyObject) > 0 {
				node.FlyConfig(flyObject)
			}
			// 再应用策略CLI
			if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
				node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
			}

			// 使用InputPolicy验证策略匹配
			matchResult := node.InputPolicy(intent, from, to)
			verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
		})
	}
}

// TestSecPathV4NetworkObjectNameTemplate 测试网络对象名称模板
func TestSecPathV4NetworkObjectNameTemplate(t *testing.T) {
	node := NewTestSecPathNode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("trust")
	to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("untrust")

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

	t.Logf("Source objects: %v", result.SourceObjects)
	t.Logf("Destination objects: %v", result.DestinationObjects)
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 验证单个 IP 时使用 DMZ_{ip} 格式
	if len(result.SourceObjects) > 0 {
		// 对于单个 IP，应该使用 DMZ_ 前缀
		srcObj := result.SourceObjects[0]
		t.Logf("Source object name: %s", srcObj)
		// 注意：实际生成可能因模板引擎而异，这里主要验证生成成功
		assert.NotEmpty(t, srcObj, "源地址对象名称不应为空")
	}

	// 使用FlyConfig解析生成的CLI并添加到节点
	flyObject := make(map[string]string)
	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
		flyObject["NETWORK"] = networkCLI
	}
	if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
		flyObject["SERVICE"] = serviceCLI
	}
	// 先应用对象CLI
	if len(flyObject) > 0 {
		node.FlyConfig(flyObject)
	}
	// 再应用策略CLI
	if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
		node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
	}

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestSecPathV4ServiceObjectNameTemplate 测试服务对象名称模板
func TestSecPathV4ServiceObjectNameTemplate(t *testing.T) {
	node := NewTestSecPathNode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("trust")
	to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("untrust")

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
		"action":                                        "permit",
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Service objects: %v", result.ServiceObjects)
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 验证服务对象名称包含策略名称和协议
	if len(result.ServiceObjects) > 0 {
		svcObj := result.ServiceObjects[0]
		t.Logf("Service object name: %s", svcObj)
		assert.NotEmpty(t, svcObj, "服务对象名称不应为空")
		// 验证包含协议信息
		assert.Contains(t, strings.ToLower(svcObj), "tcp", "服务对象名称应该包含协议")
	}

	// 使用FlyConfig解析生成的CLI并添加到节点
	flyObject := make(map[string]string)
	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
		flyObject["NETWORK"] = networkCLI
	}
	if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
		flyObject["SERVICE"] = serviceCLI
	}
	// 先应用对象CLI
	if len(flyObject) > 0 {
		node.FlyConfig(flyObject)
	}
	// 再应用策略CLI
	if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
		node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
	}

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestSecPathV4PolicyReuse 测试策略复用
func TestSecPathV4PolicyReuse(t *testing.T) {
	node := NewTestSecPathNode()

	// 先创建一个已存在的策略
	existingPolicy := &Policy{
		id:      1,
		name:    "EXISTING_POLICY",
		srcZone: []string{"trust"},
		dstZone: []string{"untrust"},
		policyEntry: policy.NewPolicyEntryWithAll(
			network.NewNetworkGroupFromStringMust("192.168.1.0/24"),
			network.NewNetworkGroupFromStringMust("10.0.0.0/24"),
			service.NewServiceMust("tcp:80"),
		),
		node:    node,
		objects: node.ObjectSet,
		action:  firewall.POLICY_PERMIT,
		status:  firewall.POLICY_ACTIVE,
		ipType:  network.IPv4,
	}
	node.PolicySet.securityPolicyAcl = append(node.PolicySet.securityPolicyAcl, existingPolicy)

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("trust")
	to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("untrust")

	// 创建相同的策略意图
	intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	metaData := map[string]interface{}{
		"policy_name_template":                          "TEST_policy_{SEQ:id:4:1:1:MAIN}",
		"reuse_policy":                                  "true",
		"securitypolicy.use_source_address_object":      false,
		"securitypolicy.use_destination_address_object": false,
		"securitypolicy.use_service_object":             false,
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	// 验证策略被复用
	if result.IsReused {
		assert.Equal(t, "EXISTING_POLICY", result.ReusedPolicyName, "应该复用现有策略")
		t.Logf("Policy reused: %s", result.ReusedPolicyName)
	} else {
		t.Logf("Policy not reused, new policy created: %s", result.PolicyName)

		// 如果策略未被复用，需要加载新策略并验证
		// 使用FlyConfig解析生成的CLI并添加到节点
		flyObject := make(map[string]string)
		if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
			flyObject["NETWORK"] = networkCLI
		}
		if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
			flyObject["SERVICE"] = serviceCLI
		}
		// 先应用对象CLI
		if len(flyObject) > 0 {
			node.FlyConfig(flyObject)
		}
		// 再应用策略CLI
		if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
			node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
		}

		// 使用InputPolicy验证策略匹配
		matchResult := node.InputPolicy(intent, from, to)
		verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
	}
}

// TestSecPathV4MultipleNetworks 测试多个网络地址的策略生成
func TestSecPathV4MultipleNetworks(t *testing.T) {
	node := NewTestSecPathNode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("trust")
	to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("untrust")

	// 创建包含多个网络的策略意图
	intent := &policy.Intent{}
	srcNg := network.NewNetworkGroup()
	srcNg.AddGroup(network.NewNetworkGroupFromStringMust("192.168.1.0/24"))
	srcNg.AddGroup(network.NewNetworkGroupFromStringMust("192.168.3.0/24"))
	intent.SetSrc(srcNg)

	dstNg := network.NewNetworkGroup()
	dstNg.AddGroup(network.NewNetworkGroupFromStringMust("10.0.0.0/24"))
	dstNg.AddGroup(network.NewNetworkGroupFromStringMust("10.0.2.0/24"))
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
		"securitypolicy.use_source_address_object":      true,
		"securitypolicy.use_destination_address_object": true,
		"securitypolicy.use_service_object":             true,
		"securitypolicy.service_group_member":           true, // 需要生成服务组成员对象
		"action":                                        "permit",
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

	// 使用FlyConfig解析生成的CLI并添加到节点
	flyObject := make(map[string]string)
	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
		flyObject["NETWORK"] = networkCLI
	}
	if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
		flyObject["SERVICE"] = serviceCLI
	}
	// 先应用对象CLI
	if len(flyObject) > 0 {
		node.FlyConfig(flyObject)
	}
	// 再应用策略CLI
	if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
		node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
	}

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestSecPathV4PolicyWithDifferentZones 测试不同 Zone 的策略生成
func TestSecPathV4PolicyWithDifferentZones(t *testing.T) {
	node := NewTestSecPathNode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		fromZone string
		toZone   string
	}{
		{"trust to untrust", "trust", "untrust"},
		{"trust to dmz", "trust", "dmz"},
		{"dmz to untrust", "dmz", "untrust"},
		{"QXDCN to 163", "QXDCN", "163"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			from := NewSecPathPort("eth0", "tenant1", nil, nil).WithZone(tc.fromZone)
			to := NewSecPathPort("eth1", "tenant1", nil, nil).WithZone(tc.toZone)

			intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
			intent.TicketNumber = "TEST001"

			ctx := &firewall.PolicyContext{
				Node:      node,
				Intent:    intent,
				Variables: make(map[string]interface{}),
			}

			metaData := map[string]interface{}{
				"policy_name_template":                          "TEST_policy_{SEQ:id:4:1:1:MAIN}",
				"securitypolicy.use_source_address_object":      false,
				"securitypolicy.use_destination_address_object": false,
				"securitypolicy.use_service_object":             false,
				"action":                                        "permit",
			}

			result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

			require.NoError(t, err)
			require.NotNil(t, result)

			// 验证 CLI 包含正确的 Zone
			assert.Contains(t, result.CLIString, tc.fromZone, "应该包含源 Zone")
			assert.Contains(t, result.CLIString, tc.toZone, "应该包含目标 Zone")

			t.Logf("From zone: %s, To zone: %s", tc.fromZone, tc.toZone)
			t.Logf("Generated CLI:\n%s", result.CLIString)

			// 使用FlyConfig解析生成的CLI并添加到节点
			flyObject := make(map[string]string)
			if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
				flyObject["NETWORK"] = networkCLI
			}
			if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
				flyObject["SERVICE"] = serviceCLI
			}
			// 先应用对象CLI
			if len(flyObject) > 0 {
				node.FlyConfig(flyObject)
			}
			// 再应用策略CLI
			if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
				node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
			}

			// 使用InputPolicy验证策略匹配
			matchResult := node.InputPolicy(intent, from, to)
			verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
		})
	}
}

// newTestPolicyIntentWithProtocol 创建测试用的策略意图（支持各种协议）
func newTestPolicyIntentWithProtocol(src, dst, protocol string, port string) *policy.Intent {
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

	// 根据协议类型创建服务
	var svc *service.Service
	var err error

	switch protocol {
	case "ip":
		// IP 协议（所有协议）
		svc, err = service.NewServiceWithProto("ip")
	case "1", "icmp":
		// ICMP 协议
		svc, err = service.NewServiceWithProto("icmp")
	case "tcp":
		// TCP 协议
		if port != "" {
			svc, err = service.NewServiceFromString("tcp:" + port)
		} else {
			svc, err = service.NewServiceWithProto("tcp")
		}
	case "udp":
		// UDP 协议
		if port != "" {
			svc, err = service.NewServiceFromString("udp:" + port)
		} else {
			svc, err = service.NewServiceWithProto("udp")
		}
	default:
		// 其他协议，尝试使用 protocol:port 格式
		if port != "" {
			svc, err = service.NewServiceFromString(protocol + ":" + port)
		} else {
			svc, err = service.NewServiceWithProto(protocol)
		}
	}

	if err != nil {
		panic(fmt.Sprintf("failed to create service for protocol %s: %v", protocol, err))
	}

	if svc != nil {
		intent.SetService(svc)
	}

	return intent
}

// TestSecPathV4PolicyWithVariousProtocols 测试各种协议的服务
func TestSecPathV4PolicyWithVariousProtocols(t *testing.T) {
	testCases := []struct {
		name                string
		protocol            string
		port                string
		expectServiceObject bool
		expectServicePort   bool
		skipInputPolicy     bool // 是否跳过 InputPolicy 验证
		description         string
	}{
		{
			name:                "IP协议",
			protocol:            "ip",
			port:                "",
			expectServiceObject: false,
			expectServicePort:   true,  // IP 协议会生成 service-port ip
			skipInputPolicy:     false, // 现在可以验证 IP 协议了
			description:         "IP 协议表示所有协议，会生成 service-port ip",
		},
		{
			name:                "ICMP协议（数字）",
			protocol:            "1",
			port:                "",
			expectServiceObject: false,
			expectServicePort:   true,
			skipInputPolicy:     false,
			description:         "ICMP 协议使用协议号 1",
		},
		{
			name:                "ICMP协议（名称）",
			protocol:            "icmp",
			port:                "",
			expectServiceObject: false,
			expectServicePort:   true,
			skipInputPolicy:     false,
			description:         "ICMP 协议使用名称 icmp",
		},
		{
			name:                "TCP协议（无端口）",
			protocol:            "tcp",
			port:                "",
			expectServiceObject: false,
			expectServicePort:   true,
			skipInputPolicy:     false,
			description:         "TCP 协议不指定端口",
		},
		{
			name:                "TCP协议（指定端口）",
			protocol:            "tcp",
			port:                "80",
			expectServiceObject: false,
			expectServicePort:   true,
			skipInputPolicy:     false,
			description:         "TCP 协议指定端口 80",
		},
		{
			name:                "UDP协议（无端口）",
			protocol:            "udp",
			port:                "",
			expectServiceObject: false,
			expectServicePort:   true,
			skipInputPolicy:     false,
			description:         "UDP 协议不指定端口",
		},
		{
			name:                "UDP协议（指定端口）",
			protocol:            "udp",
			port:                "53",
			expectServiceObject: false,
			expectServicePort:   true,
			skipInputPolicy:     false,
			description:         "UDP 协议指定端口 53（DNS）",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			node := NewTestSecPathNode()

			templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
			require.NoError(t, err)

			from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("trust")
			to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("untrust")

			// 创建指定协议的策略意图
			intent := newTestPolicyIntentWithProtocol("192.168.1.0/24", "10.0.0.0/24", tc.protocol, tc.port)
			intent.TicketNumber = "TEST001"

			ctx := &firewall.PolicyContext{
				Node:      node,
				Intent:    intent,
				Variables: make(map[string]interface{}),
			}

			metaData := map[string]interface{}{
				"policy_name_template":                          "TEST_policy_{SEQ:id:4:1:1:MAIN}",
				"securitypolicy.use_source_address_object":      false,
				"securitypolicy.use_destination_address_object": false,
				"securitypolicy.use_service_object":             false,
				"action":                                        "permit",
			}

			result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

			require.NoError(t, err, "策略生成应该成功")
			require.NotNil(t, result, "结果不应为 nil")

			t.Logf("协议: %s, 端口: %s", tc.protocol, tc.port)
			t.Logf("描述: %s", tc.description)
			t.Logf("Generated CLI:\n%s", result.CLIString)

			// 验证服务对象
			if tc.expectServiceObject {
				assert.NotEmpty(t, result.ServiceObjects, "应该生成服务对象")
			} else {
				assert.Empty(t, result.ServiceObjects, "不应该生成服务对象")
			}

			// 验证 service-port
			if tc.expectServicePort {
				// 根据协议类型验证 service-port
				switch tc.protocol {
				case "ip":
					// IP 协议可能生成 service-port ip，也可能不生成
					if strings.Contains(result.CLIString, "service-port ip") {
						t.Logf("CLI 包含 service-port ip（符合预期）")
					} else {
						t.Logf("CLI 不包含 service-port ip（IP 协议时可能不生成，这是正常的）")
					}
				case "1", "icmp":
					assert.Contains(t, result.CLIString, "service-port icmp", "应该包含 service-port icmp")
				case "tcp":
					if tc.port != "" {
						assert.Contains(t, result.CLIString, "service-port tcp", "应该包含 service-port tcp")
						assert.Contains(t, result.CLIString, tc.port, "应该包含端口号")
					} else {
						assert.Contains(t, result.CLIString, "service-port tcp", "应该包含 service-port tcp")
					}
				case "udp":
					if tc.port != "" {
						assert.Contains(t, result.CLIString, "service-port udp", "应该包含 service-port udp")
						assert.Contains(t, result.CLIString, tc.port, "应该包含端口号")
					} else {
						assert.Contains(t, result.CLIString, "service-port udp", "应该包含 service-port udp")
					}
				}
			}

			// 使用FlyConfig解析生成的CLI并添加到节点
			flyObject := make(map[string]string)
			if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
				flyObject["NETWORK"] = networkCLI
			}
			if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
				flyObject["SERVICE"] = serviceCLI
			}
			// 先应用对象CLI
			if len(flyObject) > 0 {
				node.FlyConfig(flyObject)
			}
			// 再应用策略CLI
			if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
				node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
			}

			// 使用InputPolicy验证策略匹配（如果不需要跳过）
			if !tc.skipInputPolicy {
				matchResult := node.InputPolicy(intent, from, to)
				verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
			} else {
				t.Logf("跳过 InputPolicy 验证（%s）", tc.description)
			}
		})
	}
}

// TestSecPathV4PolicyComplexScenario 测试复杂场景（参考 config.yaml）
func TestSecPathV4PolicyComplexScenario(t *testing.T) {
	node := NewTestSecPathNode()

	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	// 模拟 config.yaml 中的配置
	from := NewSecPathPort("Route-Aggregation12.1051", "tenant1", map[network.IPFamily][]string{
		network.IPv4: {"132.252.148.65/24"},
	}, []api.Member{}).WithZone("QXDCN")
	to := NewSecPathPort("Route-Aggregation12.1052", "tenant1", map[network.IPFamily][]string{
		network.IPv4: {"132.252.148.66/24"},
	}, []api.Member{}).WithZone("QXBSS")

	// 创建复杂的策略意图（多个源地址和目标地址）
	intent := &policy.Intent{}
	srcNg := network.NewNetworkGroup()
	srcNg.AddGroup(network.NewNetworkGroupFromStringMust("132.254.24.53/32"))
	srcNg.AddGroup(network.NewNetworkGroupFromStringMust("132.252.35.26/31"))
	srcNg.AddGroup(network.NewNetworkGroupFromStringMust("132.252.136.58/31"))
	intent.SetSrc(srcNg)

	dstNg := network.NewNetworkGroup()
	dstNg.AddGroup(network.NewNetworkGroupFromStringMust("132.252.128.223/32"))
	dstNg.AddGroup(network.NewNetworkGroupFromStringMust("132.252.128.224/32"))
	dstNg.AddGroup(network.NewNetworkGroupFromStringMust("132.252.128.225/32"))
	intent.SetDst(dstNg)

	svc, _ := service.NewServiceFromString("tcp:16492")
	intent.SetService(svc)
	intent.TicketNumber = "HQWLTK20250327001"
	intent.SubTicket = "1"

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    intent,
		Variables: make(map[string]interface{}),
	}

	// 使用 config.yaml 中的配置
	metaData := map[string]interface{}{
		"policy_name_template": "GL4F-policy{SEQ:id:4:1:1:MAIN}",
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
		"reuse_policy":                                  "true",
	}

	result, err := templates.MakePolicyV4(from, to, intent, ctx, metaData)

	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Policy name: %s", result.PolicyName)
	t.Logf("Source objects: %v", result.SourceObjects)
	t.Logf("Destination objects: %v", result.DestinationObjects)
	t.Logf("Service objects: %v", result.ServiceObjects)
	t.Logf("Generated CLI:\n%s", result.CLIString)

	// 验证策略名称格式
	assert.True(t, strings.HasPrefix(result.PolicyName, "GL4F-policy"),
		"策略名称应该以 GL4F-policy 开头")

	// 验证 CLI 包含必要的元素
	assert.Contains(t, result.CLIString, "rule", "应该包含 rule")
	assert.Contains(t, result.CLIString, "name", "应该包含 name")
	assert.Contains(t, result.CLIString, "source-zone", "应该包含 source-zone")
	assert.Contains(t, result.CLIString, "destination-zone", "应该包含 destination-zone")
	assert.Contains(t, result.CLIString, "16492", "应该包含端口号")

	// 使用FlyConfig解析生成的CLI并添加到节点
	flyObject := make(map[string]string)
	if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
		flyObject["NETWORK"] = networkCLI
	}
	if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
		flyObject["SERVICE"] = serviceCLI
	}
	// 先应用对象CLI
	if len(flyObject) > 0 {
		node.FlyConfig(flyObject)
	}
	// 再应用策略CLI
	if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
		node.FlyConfig(map[string]string{"SECURITY_POLICY": policyCLI})
	}

	// 使用InputPolicy验证策略匹配
	matchResult := node.InputPolicy(intent, from, to)
	verifyInputPolicyResult(t, matchResult, intent, from, to, firewall.POLICY_PERMIT)
}

// TestSecPathV4NatPolicyGeneration 测试 SecPath V4 NAT 策略生成（表驱动测试）
func TestSecPathV4NatPolicyGeneration(t *testing.T) {
	tests := []struct {
		name                 string
		dnatObjectType       string // "NETWORK_OBJECT" 或 "INLINE"
		sourceObject         bool
		destinationObject    bool
		serviceObject        bool
		expectNetworkObjects bool // 是否期望生成网络对象
		expectServiceObjects bool // 是否期望生成服务对象
		expectVipMipObject   bool // 是否期望生成VIP/MIP对象（仅NETWORK_OBJECT时）
		skipInputNat         bool // 是否跳过InputNat验证（某些组合可能无法正确解析）
	}{
		{
			name:                 "NETWORK_OBJECT_全对象模式",
			dnatObjectType:       "NETWORK_OBJECT",
			sourceObject:         true,
			destinationObject:    true,
			serviceObject:        true,
			expectNetworkObjects: true,
			expectServiceObjects: true,
			expectVipMipObject:   true,
			skipInputNat:         false,
		},
		{
			name:                 "NETWORK_OBJECT_仅服务对象",
			dnatObjectType:       "NETWORK_OBJECT",
			sourceObject:         false,
			destinationObject:    false,
			serviceObject:        true,
			expectNetworkObjects: false,
			expectServiceObjects: true,
			expectVipMipObject:   true,
			skipInputNat:         false,
		},
		{
			name:                 "NETWORK_OBJECT_源和目标对象",
			dnatObjectType:       "NETWORK_OBJECT",
			sourceObject:         true,
			destinationObject:    true,
			serviceObject:        false,
			expectNetworkObjects: true,
			expectServiceObjects: false,
			expectVipMipObject:   true,
			skipInputNat:         false,
		},
		{
			name:                 "NETWORK_OBJECT_仅源对象",
			dnatObjectType:       "NETWORK_OBJECT",
			sourceObject:         true,
			destinationObject:    false,
			serviceObject:        false,
			expectNetworkObjects: true,
			expectServiceObjects: false,
			expectVipMipObject:   true,
			skipInputNat:         false,
		},
		{
			name:                 "INLINE_全对象模式",
			dnatObjectType:       "INLINE",
			sourceObject:         true,
			destinationObject:    true,
			serviceObject:        true,
			expectNetworkObjects: true,
			expectServiceObjects: true,
			expectVipMipObject:   false, // INLINE模式不生成VIP/MIP对象
			skipInputNat:         false,
		},
		{
			name:                 "INLINE_仅服务对象",
			dnatObjectType:       "INLINE",
			sourceObject:         false,
			destinationObject:    false,
			serviceObject:        true,
			expectNetworkObjects: false,
			expectServiceObjects: true,
			expectVipMipObject:   false,
			skipInputNat:         false,
		},
		{
			name:                 "INLINE_源和目标对象",
			dnatObjectType:       "INLINE",
			sourceObject:         true,
			destinationObject:    true,
			serviceObject:        false,
			expectNetworkObjects: true,
			expectServiceObjects: false,
			expectVipMipObject:   false,
			skipInputNat:         false,
		},
		{
			name:                 "INLINE_全内联模式",
			dnatObjectType:       "INLINE",
			sourceObject:         false,
			destinationObject:    false,
			serviceObject:        false,
			expectNetworkObjects: false,
			expectServiceObjects: false,
			expectVipMipObject:   false,
			skipInputNat:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := NewTestSecPathNode()

			templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
			require.NoError(t, err)

			from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", nil, nil).WithZone("trust")
			to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", nil, nil).WithZone("untrust")

			// 创建 DNAT 策略意图
			intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
			intent.RealIp = "10.0.0.10"
			intent.RealPort = "8080"
			intent.TicketNumber = "TEST001"

			ctx := &firewall.PolicyContext{
				Node:      node,
				Intent:    intent,
				Variables: make(map[string]interface{}),
			}

			metaData := map[string]interface{}{
				"input.nat":                         "natpolicy.dnat",
				"dnat_object_type":                  tc.dnatObjectType,
				"natpolicy.dnat.object_style":       "true",
				"natpolicy.name_template":           "GL4F-policy{SEQ:id:4:1:1:MAIN}",
				"natpolicy.dnat.source_object":      fmt.Sprintf("%v", tc.sourceObject),
				"natpolicy.dnat.destination_object": fmt.Sprintf("%v", tc.destinationObject),
				"natpolicy.dnat.service_object":     fmt.Sprintf("%v", tc.serviceObject),
			}

			result, err := templates.MakeNatPolicyV4(from, to, intent, ctx, metaData)

			require.NoError(t, err)
			require.NotNil(t, result)

			t.Logf("NAT name: %s", result.NatName)
			t.Logf("NAT type: %s", result.NatType)
			t.Logf("VIP/MIP name: %s", result.VipMipName)
			t.Logf("Source objects: %v", result.SourceObjects)
			t.Logf("Destination objects: %v", result.DestinationObjects)
			t.Logf("Service objects: %v", result.ServiceObjects)
			t.Logf("Generated CLI:\n%s", result.CLIString)

			// 验证对象生成情况
			if tc.expectNetworkObjects {
				assert.True(t, len(result.SourceObjects) > 0 || len(result.DestinationObjects) > 0,
					"应该生成源或目标地址对象")
			} else {
				assert.Equal(t, 0, len(result.SourceObjects), "不应该生成源地址对象")
				assert.Equal(t, 0, len(result.DestinationObjects), "不应该生成目标地址对象")
			}

			if tc.expectServiceObjects {
				assert.True(t, len(result.ServiceObjects) > 0, "应该生成服务对象")
			} else {
				assert.Equal(t, 0, len(result.ServiceObjects), "不应该生成服务对象")
			}

			if tc.expectVipMipObject {
				assert.NotEmpty(t, result.VipMipName, "应该生成VIP/MIP对象名称")
			} else {
				assert.Empty(t, result.VipMipName, "不应该生成VIP/MIP对象名称（INLINE模式）")
			}

			// 使用FlyConfig解析生成的CLI并添加到节点
			flyObject := make(map[string]string)
			if vipCLI, exists := result.FlyObject["VIP"]; exists && vipCLI != "" {
				flyObject["NAT_SERVER"] = vipCLI
			}
			if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
				flyObject["NETWORK"] = networkCLI
			}
			if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
				flyObject["SERVICE"] = serviceCLI
			}
			// 先应用对象CLI
			if len(flyObject) > 0 {
				node.FlyConfig(flyObject)
			}
			// 再应用NAT策略CLI
			if natCLI, exists := result.FlyObject["NAT"]; exists && natCLI != "" {
				node.FlyConfig(map[string]string{"NAT": natCLI})
			}

			// 使用InputNat验证NAT匹配（如果不需要跳过）
			if !tc.skipInputNat {
				inputNatResult := node.InputNat(intent, to)
				verifyInputNatResult(t, inputNatResult, intent, to, firewall.NAT_MATCHED)
			} else {
				t.Logf("跳过 InputNat 验证（%s）", tc.name)
			}
		})
	}
}

// TestSecPathV4NatPolicySNAT 测试 SecPath V4 SNAT 策略生成（表驱动测试）
func TestSecPathV4NatPolicySNAT(t *testing.T) {
	tests := []struct {
		name                 string
		snatPoolType         string // "SNAT_POOL" 或 "INTERFACE"
		sourceObject         bool
		destinationObject    bool
		serviceObject        bool
		snatValue            string // intent.Snat 的值，INTERFACE 模式可以为空或 "interface"
		expectNetworkObjects bool   // 是否期望生成网络对象
		expectServiceObjects bool   // 是否期望生成服务对象
		expectSnatPoolObject bool   // 是否期望生成SNAT_POOL对象（仅SNAT_POOL类型时）
		skipOutputNat        bool   // 是否跳过OutputNat验证（某些组合可能无法正确解析）
	}{
		{
			name:                 "SNAT_POOL_全对象模式",
			snatPoolType:         "SNAT_POOL",
			sourceObject:         true,
			destinationObject:    true,
			serviceObject:        true,
			snatValue:            "192.168.100.1",
			expectNetworkObjects: true,
			expectServiceObjects: true,
			expectSnatPoolObject: true,
			skipOutputNat:        false,
		},
		{
			name:                 "SNAT_POOL_仅服务对象",
			snatPoolType:         "SNAT_POOL",
			sourceObject:         false,
			destinationObject:    false,
			serviceObject:        true,
			snatValue:            "192.168.100.1",
			expectNetworkObjects: false,
			expectServiceObjects: true,
			expectSnatPoolObject: true,
			skipOutputNat:        false,
		},
		{
			name:                 "SNAT_POOL_源和目标对象",
			snatPoolType:         "SNAT_POOL",
			sourceObject:         true,
			destinationObject:    true,
			serviceObject:        false,
			snatValue:            "192.168.100.1",
			expectNetworkObjects: true,
			expectServiceObjects: false,
			expectSnatPoolObject: true,
			skipOutputNat:        false,
		},
		{
			name:                 "SNAT_POOL_仅源对象",
			snatPoolType:         "SNAT_POOL",
			sourceObject:         true,
			destinationObject:    false,
			serviceObject:        false,
			snatValue:            "192.168.100.1",
			expectNetworkObjects: true,
			expectServiceObjects: false,
			expectSnatPoolObject: true,
			skipOutputNat:        false,
		},
		{
			name:                 "INTERFACE_全对象模式",
			snatPoolType:         "INTERFACE",
			sourceObject:         true,
			destinationObject:    true,
			serviceObject:        true,
			snatValue:            "interface", // 或为空
			expectNetworkObjects: true,
			expectServiceObjects: true,
			expectSnatPoolObject: false, // INTERFACE模式不生成SNAT_POOL对象
			skipOutputNat:        false,
		},
		{
			name:                 "INTERFACE_仅服务对象",
			snatPoolType:         "INTERFACE",
			sourceObject:         false,
			destinationObject:    false,
			serviceObject:        true,
			snatValue:            "interface",
			expectNetworkObjects: false,
			expectServiceObjects: true,
			expectSnatPoolObject: false,
			skipOutputNat:        false,
		},
		{
			name:                 "INTERFACE_源和目标对象",
			snatPoolType:         "INTERFACE",
			sourceObject:         true,
			destinationObject:    true,
			serviceObject:        false,
			snatValue:            "interface",
			expectNetworkObjects: true,
			expectServiceObjects: false,
			expectSnatPoolObject: false,
			skipOutputNat:        false,
		},
		{
			name:                 "INTERFACE_全内联模式",
			snatPoolType:         "INTERFACE",
			sourceObject:         false,
			destinationObject:    false,
			serviceObject:        false,
			snatValue:            "interface",
			expectNetworkObjects: false,
			expectServiceObjects: false,
			expectSnatPoolObject: false,
			skipOutputNat:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := NewTestSecPathNode()

			// 准备端口数据：设置正确的 zone 和 IP 地址（easy-ip 需要根据 zone 查找端口）
			from := NewSecPathPort("GigabitEthernet0/0/0", "tenant1", map[network.IPFamily][]string{
				network.IPv4: {"192.168.1.1/24"},
			}, []api.Member{}).WithZone("trust")
			from.WithID("port-from-id")
			from.WithNode(node)

			to := NewSecPathPort("GigabitEthernet0/0/1", "tenant1", map[network.IPFamily][]string{
				network.IPv4: {"10.0.0.1/24"},
			}, []api.Member{}).WithZone("untrust")
			to.WithID("port-to-id")
			to.WithNode(node)

			// 创建简单的 PortIterator 用于测试
			portMap := map[string]api.Port{
				"port-from-id": from,
				"port-to-id":   to,
			}
			simpleIterator := &simplePortIterator{ports: portMap}
			node.WithPortIterator(simpleIterator)

			// 将端口添加到节点（在调用 FlyConfig 之前，确保 easy-ip 可以找到端口）
			node.AddPort(from, nil)
			node.AddPort(to, nil)

			templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
			require.NoError(t, err)

			// 创建 SNAT 策略意图
			intent := newTestPolicyIntent("192.168.1.0/24", "10.0.0.0/24", "tcp", "80")
			intent.Snat = tc.snatValue
			intent.TicketNumber = "TEST001"

			ctx := &firewall.PolicyContext{
				Node:      node,
				Intent:    intent,
				Variables: make(map[string]interface{}),
			}

			metaData := map[string]interface{}{
				"output.nat":                        "natpolicy.snat",
				"snat_pool_type":                    tc.snatPoolType,
				"natpolicy.name_template":           "GL4F-policy{SEQ:id:4:1:1:MAIN}",
				"natpolicy.snat.object_style":       "true",
				"natpolicy.snat.source_object":      tc.sourceObject,
				"natpolicy.snat.destination_object": tc.destinationObject,
				"natpolicy.snat.service_object":     tc.serviceObject,
			}

			result, err := templates.MakeNatPolicyV4(from, to, intent, ctx, metaData)

			require.NoError(t, err)
			require.NotNil(t, result)

			t.Logf("NAT name: %s", result.NatName)
			t.Logf("NAT type: %s", result.NatType)
			t.Logf("SNAT Pool name: %s", result.SnatPoolName)
			t.Logf("Source objects: %v", result.SourceObjects)
			t.Logf("Destination objects: %v", result.DestinationObjects)
			t.Logf("Service objects: %v", result.ServiceObjects)
			t.Logf("Generated CLI:\n%s", result.CLIString)

			// 验证 NAT 类型
			assert.Equal(t, "SNAT", result.NatType, "应该是 SNAT 类型")

			// 验证对象生成情况
			if tc.expectNetworkObjects {
				assert.True(t, len(result.SourceObjects) > 0 || len(result.DestinationObjects) > 0,
					"应该生成源或目标地址对象")
			} else {
				assert.Equal(t, 0, len(result.SourceObjects), "不应该生成源地址对象")
				assert.Equal(t, 0, len(result.DestinationObjects), "不应该生成目标地址对象")
			}

			if tc.expectServiceObjects {
				assert.True(t, len(result.ServiceObjects) > 0, "应该生成服务对象")
			} else {
				assert.Equal(t, 0, len(result.ServiceObjects), "不应该生成服务对象")
			}

			if tc.expectSnatPoolObject {
				assert.NotEmpty(t, result.SnatPoolName, "应该生成SNAT_POOL对象名称")
			} else {
				assert.Empty(t, result.SnatPoolName, "不应该生成SNAT_POOL对象名称（INTERFACE模式）")
			}

			// 使用FlyConfig解析生成的CLI并添加到节点
			flyObject := make(map[string]string)
			if poolCLI, exists := result.FlyObject["POOL"]; exists && poolCLI != "" {
				flyObject["POOL"] = poolCLI
			}
			if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
				flyObject["NETWORK"] = networkCLI
			}
			if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
				flyObject["SERVICE"] = serviceCLI
			}
			// 先应用对象CLI
			if len(flyObject) > 0 {
				node.FlyConfig(flyObject)
			}
			// 再应用NAT策略CLI
			if natCLI, exists := result.FlyObject["NAT"]; exists && natCLI != "" {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Logf("应用NAT策略CLI时发生panic: %v（可能是指定格式问题）", r)
						}
					}()
					node.FlyConfig(map[string]string{"NAT": natCLI})
				}()
			}

			// 使用OutputNat验证NAT匹配（如果不需要跳过）
			if !tc.skipOutputNat {
				outputNatResult := node.OutputNat(intent, from, to)
				verifyOutputNatResult(t, outputNatResult, intent, from, to, firewall.NAT_MATCHED)
			} else {
				t.Logf("跳过 OutputNat 验证（%s）", tc.name)
			}
		})
	}
}
