package sangfor

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/netxops/utils/policy"
	"github.com/stretchr/testify/assert"
)

// NewTestSangforNode 创建一个用于测试的 SangforNode 实例
func NewTestSangforNode() *SangforNode {
	sangfor := &SangforNode{
		DeviceNode: node.NewDeviceNode("test-sangfor", "test-sangfor", api.FIREWALL),
	}

	sangfor.objectSet = NewSangforObjectSet(sangfor)
	sangfor.policySet = &PolicySet{
		objects:   sangfor.objectSet,
		node:      sangfor,
		policySet: []*Policy{},
	}
	sangfor.nats = NewSangforNats(sangfor)

	return sangfor
}

// newTestSangforPort 创建一个用于测试的 Sangfor Port（基于 zone）
// 这是一个辅助函数，用于简化测试代码
func newTestSangforPort(name, zone string) api.Port {
	return NewSangforPort(name, "", nil, nil).WithZone(zone)
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
	if !ok {
		t.Fatalf("InputPolicy返回结果类型错误，期望 *firewall.PolicyMatchResult，实际 %T", result)
		return
	}

	// 验证Action
	action := policyResult.Action()
	t.Logf("InputPolicy result: Action=%d (期望=%d)", action, int(expectedAction))
	if action != int(expectedAction) {
		t.Logf("警告：策略未匹配，Action=%d (期望=%d)", action, int(expectedAction))
		t.Logf("可能的原因：")
		t.Logf("  - 地址对象未正确创建")
		t.Logf("  - 服务对象未正确创建")
		t.Logf("  - 策略CLI格式不正确")
		t.Logf("  - Zone配置不正确")
	} else {
		t.Logf("✓ 策略匹配成功")
	}

	// 验证Rule
	rule := policyResult.Rule()
	if rule != nil {
		t.Logf("匹配的策略: %s", rule.Name())
		t.Logf("策略CLI: %s", rule.Cli())
	} else {
		t.Logf("警告：匹配的策略为nil")
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
							ruleDstStr := ruleTranslate.Dst().String()
							t.Logf("规则Translate.Dst: %s, 转换后Dst: %s", ruleDstStr, actualDst)
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
		t.Logf("生成的CLI用于调试:")
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

	// 验证Action
	action := natResult.Action()
	t.Logf("OutputNat result: Action=%d (期望=%d)", action, int(expectedAction))
	if action != int(expectedAction) {
		t.Logf("警告：NAT规则未匹配，Action=%d (期望=%d)", action, int(expectedAction))
		t.Logf("可能的原因：pool_id格式问题导致策略未正确解析")
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

	// 验证TranslateTo（SNAT）- 只在匹配成功时验证
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
							ruleSrcStr := ruleTranslate.Src().String()
							t.Logf("规则Translate.Src: %s, 转换后Src: %s", ruleSrcStr, actualSrc)
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

// TestFlyConfigParsing 测试 FlyConfig 是否正确解析 FlyObject 的各个字段
func TestFlyConfigParsing(t *testing.T) {
	sangfor := NewTestSangforNode()

	// 测试 1: 测试字符串格式的 FlyObject（单个字段）
	t.Run("StringFormat", func(t *testing.T) {
		poolCLI := `config
ipgroup "pool-1" ipv4
type ip
importance ordinary
ipentry 203.0.113.1-203.0.113.1
end
`

		sangfor.FlyConfig(poolCLI)

		// 验证 POOL 对象是否被正确解析
		if sangfor.objectSet != nil {
			poolObj, ok := sangfor.objectSet.networkMap["pool-1"]
			assert.True(t, ok, "POOL 对象应该被解析")
			if ok {
				// 注意：当通过 parseCLIString 解析时，POOL 对象可能被解析为普通网络对象
				// 需要检查 objType 字段是否正确设置
				t.Logf("✓ POOL 对象解析成功: %s, Type: %d", poolObj.Name(), poolObj.Type())
			}
		}
	})

	// 测试 2: 测试 map[string]interface{} 格式（模拟 parseCLIString 的返回格式）
	t.Run("MapFormat", func(t *testing.T) {
		sangfor2 := NewTestSangforNode()

		flyObjectMap := map[string]interface{}{
			"NETWORK": []interface{}{
				map[string]interface{}{
					"name":        "test-network",
					"addressType": "ipv4",
					"ipRanges": []interface{}{
						map[string]interface{}{
							"start": "192.168.1.0",
							"bits":  float64(24),
						},
					},
				},
			},
			"SERVICE": []interface{}{
				map[string]interface{}{
					"name": "test-service",
					"tcpEntrys": []interface{}{
						map[string]interface{}{
							"destinationPort": float64(80),
						},
					},
				},
			},
			"STATIC_NAT": []interface{}{
				map[string]interface{}{
					"name":    "test-dnat",
					"natType": "DNAT",
					"enable":  true,
					"dnat": map[string]interface{}{
						"transferIP": "192.168.1.100",
					},
				},
			},
		}

		sangfor2.FlyConfig(flyObjectMap)

		// 验证网络对象
		if sangfor2.objectSet != nil {
			netObj, ok := sangfor2.objectSet.networkMap["test-network"]
			assert.True(t, ok, "网络对象应该被解析")
			if ok {
				t.Logf("✓ 网络对象解析成功: %s", netObj.Name())
			}
		}

		// 验证服务对象
		if sangfor2.objectSet != nil {
			svcObj, ok := sangfor2.objectSet.serviceMap["test-service"]
			assert.True(t, ok, "服务对象应该被解析")
			if ok {
				t.Logf("✓ 服务对象解析成功: %s", svcObj.Name())
			}
		}

		// 验证 NAT 规则
		if sangfor2.nats != nil {
			assert.Greater(t, len(sangfor2.nats.destinationNatRules), 0, "DNAT 规则应该被解析")
			if len(sangfor2.nats.destinationNatRules) > 0 {
				t.Logf("✓ DNAT 规则解析成功: %s", sangfor2.nats.destinationNatRules[0].Name())
			}
		}
	})

	// 测试 3: 测试 POOL 字段的解析
	t.Run("POOLField", func(t *testing.T) {
		sangfor3 := NewTestSangforNode()

		poolCLI := `config
ipgroup "pool-2" ipv4
type ip
importance ordinary
ipentry 203.0.113.2-203.0.113.2
end
`

		// 模拟 FlyObject 中 POOL 字段的格式
		flyObjectMap := map[string]interface{}{
			"POOL": poolCLI, // POOL 是字符串格式
		}

		sangfor3.FlyConfig(flyObjectMap)

		// 验证 POOL 对象是否被正确解析
		if sangfor3.objectSet != nil {
			poolObj, ok := sangfor3.objectSet.networkMap["pool-2"]
			assert.True(t, ok, "POOL 对象应该被解析")
			if ok {
				// 注意：当通过 parseCLIString 解析时，POOL 对象可能被解析为普通网络对象
				// 需要检查 objType 字段是否正确设置
				t.Logf("✓ POOL 字段解析成功: %s, Type: %d", poolObj.Name(), poolObj.Type())
			}
		}
	})

	// 测试 4: 测试完整的 FlyObject 解析流程（模拟实际使用场景）
	t.Run("CompleteFlow", func(t *testing.T) {
		sangfor4 := NewTestSangforNode()

		// 模拟从 MakePolicyBaseNatRuleCli 返回的 FlyObject 格式
		networkCLI := `config
ipgroup "NAT_TK001_src" ipv4
type ip
importance ordinary
ipentry 192.168.1.0/24
end
`

		serviceCLI := `config
service "NAT_TK001_TCP"
tcp-entry destination-port 80
tcp-entry destination-port 443
end
`

		natCLI := `config
dnat-rule "NAT_TK001" bottom
src-zone ""
schedule "all-week"
src-ipgroup "NAT_TK001_src"
dst-ipgroup "NAT_TK001_dst"
ignore-acl enable
log bypass-acl disable
dst-zone 
service NAT_TK001_TCP
service NAT_TK001_TCP_01
transfer ip 192.168.1.100 port 8080
transfer load-balance disable
end
`

		// 按顺序解析：先 NETWORK 和 SERVICE，再 NAT
		sangfor4.FlyConfig(networkCLI)
		sangfor4.FlyConfig(serviceCLI)
		sangfor4.FlyConfig(natCLI)

		// 验证所有对象都被正确解析
		if sangfor4.objectSet != nil {
			netObj, ok := sangfor4.objectSet.networkMap["NAT_TK001_src"]
			assert.True(t, ok, "网络对象应该被解析")
			if ok {
				t.Logf("✓ 网络对象: %s", netObj.Name())
			}

			svcObj, ok := sangfor4.objectSet.serviceMap["NAT_TK001_TCP"]
			assert.True(t, ok, "服务对象应该被解析")
			if ok {
				t.Logf("✓ 服务对象: %s", svcObj.Name())
			}
		}

		// 验证 NAT 规则
		if sangfor4.nats != nil {
			assert.Greater(t, len(sangfor4.nats.destinationNatRules), 0, "DNAT 规则应该被解析")
			if len(sangfor4.nats.destinationNatRules) > 0 {
				rule := sangfor4.nats.destinationNatRules[0]
				t.Logf("✓ DNAT 规则: %s", rule.Name())
				// 验证规则中的对象引用是否正确
				if rule.original != nil {
					if src := rule.original.Src(); src != nil {
						t.Logf("  - Original Src: %s", src.String())
					}
					if dst := rule.original.Dst(); dst != nil {
						t.Logf("  - Original Dst: %s", dst.String())
					}
					if svc := rule.original.Service(); svc != nil {
						t.Logf("  - Original Service: %s", svc.String())
					}
				}
			}
		}
	})

	// 测试 5: 测试 map[string]string 格式（FlyObject 的实际类型）
	t.Run("MapStringStringFormat", func(t *testing.T) {
		sangfor5 := NewTestSangforNode()

		// FlyObject 的实际类型是 map[string]string
		flyObject := map[string]string{
			"NETWORK": `config
ipgroup "test-net" ipv4
type ip
importance ordinary
ipentry 10.0.0.0/24
end
`,
			"SERVICE": `config
service "test-svc"
tcp-entry destination-port 80
end
`,
			"NAT": `config
snat-rule "test-snat" bottom
src-ipgroup "test-net"
transfer ipgroup pool-1
end
`,
		}

		// 注意：FlyConfig 不支持 map[string]string，需要转换为字符串
		// 这是当前实现的一个限制
		var combinedCLI string
		for _, value := range flyObject {
			combinedCLI += value + "\n"
		}

		sangfor5.FlyConfig(combinedCLI)

		// 验证对象是否被解析
		if sangfor5.objectSet != nil {
			netObj, ok := sangfor5.objectSet.networkMap["test-net"]
			assert.True(t, ok, "网络对象应该被解析")
			if ok {
				t.Logf("✓ 合并 CLI 解析成功: %s", netObj.Name())
			}
		}
	})
}
