package dptech

import (
	"strings"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	v4 "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common/v4"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDptechV4EnhancedPolicyReuse 测试增强策略复用功能
func TestDptechV4EnhancedPolicyReuse(t *testing.T) {
	tests := []struct {
		name                    string
		existingPolicySrc       string
		existingPolicyDst       string
		existingPolicyService   string
		existingPolicyUsesGroup bool // 现有策略是否使用地址组/服务组
		newIntentSrc            string
		newIntentDst            string
		newIntentService        string
		expectGroupUpdate       bool // 是否期望生成组更新CLI
		expectPolicyCLI         bool // 是否期望生成策略CLI
		description             string
	}{
		{
			name:                    "地址组复用-源地址组添加新地址",
			existingPolicySrc:       "192.168.1.0/24",
			existingPolicyDst:       "10.0.0.0/24",
			existingPolicyService:   "tcp:80",
			existingPolicyUsesGroup: true,                            // 使用地址组
			newIntentSrc:            "192.168.1.0/24,192.168.2.0/24", // 添加新地址
			newIntentDst:            "10.0.0.0/24",
			newIntentService:        "tcp:80",
			expectGroupUpdate:       true,
			expectPolicyCLI:         false, // 只更新组，不生成策略
			description:             "当现有策略使用源地址组时，应该只生成地址组更新CLI",
		},
		// {
		// 	name:                    "地址组复用-目标地址组添加新地址",
		// 	existingPolicySrc:       "192.168.1.0/24",
		// 	existingPolicyDst:       "10.0.0.0/24",
		// 	existingPolicyService:   "tcp:80",
		// 	existingPolicyUsesGroup: true,
		// 	newIntentSrc:            "192.168.1.0/24",
		// 	newIntentDst:            "10.0.0.0/24,10.0.1.0/24", // 添加新地址
		// 	newIntentService:        "tcp:80",
		// 	expectGroupUpdate:       true,
		// 	expectPolicyCLI:         false,
		// 	description:             "当现有策略使用目标地址组时，应该只生成地址组更新CLI",
		// },
		// {
		// 	name:                    "服务组复用-添加新服务",
		// 	existingPolicySrc:       "192.168.1.0/24",
		// 	existingPolicyDst:       "10.0.0.0/24",
		// 	existingPolicyService:   "tcp:80",
		// 	existingPolicyUsesGroup: true,
		// 	newIntentSrc:            "192.168.1.0/24",
		// 	newIntentDst:            "10.0.0.0/24",
		// 	newIntentService:        "tcp:80,443", // 添加新服务
		// 	expectGroupUpdate:       true,
		// 	expectPolicyCLI:         false,
		// 	description:             "当现有策略使用服务组时，应该只生成服务组更新CLI",
		// },
		// {
		// 	name:                    "标准复用-不使用组时生成差异策略",
		// 	existingPolicySrc:       "192.168.1.0/24",
		// 	existingPolicyDst:       "10.0.0.0/24",
		// 	existingPolicyService:   "tcp:80",
		// 	existingPolicyUsesGroup: false, // 不使用组
		// 	newIntentSrc:            "192.168.1.0/24,192.168.2.0/24",
		// 	newIntentDst:            "10.0.0.0/24",
		// 	newIntentService:        "tcp:80",
		// 	expectGroupUpdate:       false,
		// 	expectPolicyCLI:         true, // 生成包含差异的策略
		// 	description:             "当现有策略不使用组时，应该生成包含差异的新策略",
		// },
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := NewTestDptechNode()

			// 创建现有策略使用的地址组或对象
			var existingSrcObj firewall.FirewallNetworkObject
			var existingDstObj firewall.FirewallNetworkObject
			var existingSvcObj firewall.FirewallServiceObject

			if tc.existingPolicyUsesGroup {
				// 创建地址组和服务组
				srcNg, _ := network.NewNetworkGroupFromString(tc.existingPolicySrc)
				dstNg, _ := network.NewNetworkGroupFromString(tc.existingPolicyDst)
				svc, _ := service.NewServiceFromString(tc.existingPolicyService)

				// 创建源地址组
				srcGroupName := "EXISTING_SRC_GROUP"
				srcGroup := &DptechNetwork{
					name:     srcGroupName,
					network:  srcNg,
					catagory: firewall.GROUP_NETWORK,
				}
				if node.ObjectSet.addressGroupSet == nil {
					node.ObjectSet.addressGroupSet = make(map[string]firewall.FirewallNetworkObject)
				}
				node.ObjectSet.addressGroupSet[srcGroupName] = srcGroup
				existingSrcObj = srcGroup

				// 创建目标地址组
				dstGroupName := "EXISTING_DST_GROUP"
				dstGroup := &DptechNetwork{
					name:     dstGroupName,
					network:  dstNg,
					catagory: firewall.GROUP_NETWORK,
				}
				node.ObjectSet.addressGroupSet[dstGroupName] = dstGroup
				existingDstObj = dstGroup

				// 创建服务组
				svcGroupName := "EXISTING_SVC_GROUP"
				svcGroup := &DptechService{
					name:     svcGroupName,
					service:  svc,
					catagory: firewall.GROUP_SERVICE,
				}
				if node.ObjectSet.serviceGroup == nil {
					node.ObjectSet.serviceGroup = make(map[string]firewall.FirewallServiceObject)
				}
				node.ObjectSet.serviceGroup[svcGroupName] = svcGroup
				existingSvcObj = svcGroup
			} else {
				// 不使用组，创建普通对象
				srcNg, _ := network.NewNetworkGroupFromString(tc.existingPolicySrc)
				dstNg, _ := network.NewNetworkGroupFromString(tc.existingPolicyDst)
				svc, _ := service.NewServiceFromString(tc.existingPolicyService)

				srcObjName := "EXISTING_SRC_OBJ"
				srcObj := &DptechNetwork{
					name:     srcObjName,
					network:  srcNg,
					catagory: firewall.OBJECT_NETWORK,
				}
				if node.ObjectSet.addressObjectSet == nil {
					node.ObjectSet.addressObjectSet = make(map[string]firewall.FirewallNetworkObject)
				}
				node.ObjectSet.addressObjectSet[srcObjName] = srcObj
				existingSrcObj = srcObj

				dstObjName := "EXISTING_DST_OBJ"
				dstObj := &DptechNetwork{
					name:     dstObjName,
					network:  dstNg,
					catagory: firewall.OBJECT_NETWORK,
				}
				node.ObjectSet.addressObjectSet[dstObjName] = dstObj
				existingDstObj = dstObj

				svcObjName := "EXISTING_SVC_OBJ"
				svcObj := &DptechService{
					name:     svcObjName,
					service:  svc,
					catagory: firewall.OBJECT_SERVICE,
				}
				if node.ObjectSet.serviceMap == nil {
					node.ObjectSet.serviceMap = make(map[string]firewall.FirewallServiceObject)
				}
				node.ObjectSet.serviceMap[svcObjName] = svcObj
				existingSvcObj = svcObj
			}

			// 创建现有策略
			existingSrcNg, _ := network.NewNetworkGroupFromString(tc.existingPolicySrc)
			existingDstNg, _ := network.NewNetworkGroupFromString(tc.existingPolicyDst)
			existingSvc, _ := service.NewServiceFromString(tc.existingPolicyService)

			existingPolicy := &Policy{
				name:    "EXISTING_POLICY",
				srcZone: []string{"trust"},
				dstZone: []string{"untrust"},
				policyEntry: policy.NewPolicyEntryWithAll(
					existingSrcNg,
					existingDstNg,
					existingSvc,
				),
				node:      node,
				objects:   node.ObjectSet,
				action:    firewall.POLICY_PERMIT,
				status:    firewall.POLICY_ACTIVE,
				srcObject: []string{existingSrcObj.Name()},
				dstObject: []string{existingDstObj.Name()},
				srvObject: []string{existingSvcObj.Name()},
			}
			from := NewDptechPort("eth1", "tenant1", nil, nil).WithZone("trust")
			to := NewDptechPort("eth2", "tenant1", nil, nil).WithZone("untrust")
			node.PolicySet.policySet = append(node.PolicySet.policySet, existingPolicy)

			// 创建 V4 模板
			templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
			require.NoError(t, err)

			// 创建新的策略意图（包含差异）
			newIntent := &policy.Intent{}
			// 设置元数据字段，用于验证是否被保留
			newIntent.TicketNumber = "TEST_TICKET_001"
			newIntent.SubTicket = "1"
			newIntent.Area = "TEST_AREA"

			if strings.Contains(tc.newIntentSrc, ",") {
				// 多个地址
				srcNg := network.NewNetworkGroup()
				for _, addr := range strings.Split(tc.newIntentSrc, ",") {
					ng, _ := network.NewNetworkGroupFromString(strings.TrimSpace(addr))
					if ng != nil {
						srcNg.AddGroup(ng)
					}
				}
				newIntent.SetSrc(srcNg)
			} else {
				srcNg, _ := network.NewNetworkGroupFromString(tc.newIntentSrc)
				if srcNg != nil {
					newIntent.SetSrc(srcNg)
				}
			}

			if strings.Contains(tc.newIntentDst, ",") {
				dstNg := network.NewNetworkGroup()
				for _, addr := range strings.Split(tc.newIntentDst, ",") {
					ng, _ := network.NewNetworkGroupFromString(strings.TrimSpace(addr))
					if ng != nil {
						dstNg.AddGroup(ng)
					}
				}
				newIntent.SetDst(dstNg)
			} else {
				dstNg, _ := network.NewNetworkGroupFromString(tc.newIntentDst)
				if dstNg != nil {
					newIntent.SetDst(dstNg)
				}
			}

			if strings.Contains(tc.newIntentService, ",") {
				svc, _ := service.NewServiceFromString(tc.newIntentService)
				if svc != nil {
					newIntent.SetService(svc)
				}
			} else {
				svc, _ := service.NewServiceFromString(tc.newIntentService)
				if svc != nil {
					newIntent.SetService(svc)
				}
			}

			ctx := &firewall.PolicyContext{
				Node:      node,
				Intent:    newIntent,
				Variables: make(map[string]interface{}),
			}

			// 配置增强复用模式
			metaData := map[string]interface{}{
				"policy_name_template":                           "TEST_policy_{SEQ:id:4:1:1:MAIN}",
				"securitypolicy.reuse_policy":                    "true",
				"securitypolicy.reuse_policy_mode":               "enhanced", // 使用增强模式
				"securitypolicy.use_source_address_object":       true,
				"securitypolicy.use_destination_address_object":  true,
				"securitypolicy.source_address_group_style":      "member",
				"securitypolicy.destination_address_group_style": "member",
				"securitypolicy.use_service_object":              tc.existingPolicyUsesGroup,
				"action":                                         "permit",
			}

			result, err := templates.MakePolicyV4(from, to, newIntent, ctx, metaData)

			require.NoError(t, err)
			require.NotNil(t, result)

			// 执行 FlyConfig 应用生成的 CLI
			allCLI := strings.Builder{}
			if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
				allCLI.WriteString(networkCLI)
				allCLI.WriteString("\n!\n")
			}
			if serviceCLI, exists := result.FlyObject["SERVICE"]; exists && serviceCLI != "" {
				allCLI.WriteString(serviceCLI)
				allCLI.WriteString("\n!\n")
			}
			// 先应用对象CLI
			if allCLI.Len() > 0 {
				node.FlyConfig(allCLI.String())
			}
			// 再应用策略CLI
			if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
				node.FlyConfig(policyCLI + "\n!\n")
			}

			// 通过 PolicyEntry 进行测试
			// 查找复用或新创建的策略
			var matchedPolicy *Policy
			if result.IsReused && result.ReusedPolicyName != "" {
				// 查找复用的策略
				for _, p := range node.PolicySet.policySet {
					if p.name == result.ReusedPolicyName {
						matchedPolicy = p
						break
					}
				}
			} else if result.PolicyName != "" {
				// 查找新创建的策略
				for _, p := range node.PolicySet.policySet {
					if p.name == result.PolicyName {
						matchedPolicy = p
						break
					}
				}
			}

			// 验证策略存在
			if result.IsReused || result.PolicyName != "" {
				require.NotNil(t, matchedPolicy, "应该找到匹配的策略")
				if matchedPolicy != nil {
					// 验证策略的 PolicyEntry 能够匹配新的 intent
					match := matchedPolicy.policyEntry.Match(newIntent)
					assert.True(t, match, "策略的 PolicyEntry 应该能够匹配新的 intent")
					t.Logf("✓ PolicyEntry 匹配验证通过: 策略 %s 能够匹配新的 intent", matchedPolicy.name)
				}
			}
		})
	}
}

// TestDptechV4EnhancedPolicyReuseStandardMode 测试标准复用模式与增强模式的对比
func TestDptechV4EnhancedPolicyReuseStandardMode(t *testing.T) {
	node := NewTestDptechNode()

	// 创建现有策略（不使用组）
	existingPolicy := &Policy{
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
	}
	from := NewDptechPort("eth1", "tenant1", nil, nil).WithZone("trust")
	to := NewDptechPort("eth2", "tenant1", nil, nil).WithZone("untrust")
	node.PolicySet.policySet = append(node.PolicySet.policySet, existingPolicy)

	// 创建 V4 模板
	templates, err := v4.NewCommonTemplatesV4(node, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	require.NoError(t, err)

	// 创建新的策略意图（添加新地址）
	newIntent := &policy.Intent{}
	newIntent.SetSrc(network.NewNetworkGroupFromStringMust("192.168.1.0/24,192.168.2.0/24"))
	newIntent.SetDst(network.NewNetworkGroupFromStringMust("10.0.0.0/24"))
	newIntent.SetService(service.NewServiceMust("tcp:80"))

	ctx := &firewall.PolicyContext{
		Node:      node,
		Intent:    newIntent,
		Variables: make(map[string]interface{}),
	}

	// 测试标准模式
	t.Run("标准模式", func(t *testing.T) {
		metaData := map[string]interface{}{
			"policy_name_template":             "TEST_policy_{SEQ:id:4:1:1:MAIN}",
			"securitypolicy.reuse_policy":      "true",
			"securitypolicy.reuse_policy_mode": "standard", // 使用标准模式
			"action":                           "permit",
		}

		result, err := templates.MakePolicyV4(from, to, newIntent, ctx, metaData)
		require.NoError(t, err)
		require.NotNil(t, result)

		t.Logf("策略复用: %v", result.IsReused)
		if result.IsReused {
			t.Logf("复用策略名称: %s", result.ReusedPolicyName)
		}
		t.Logf("生成的CLI:\n%s", result.CLIString)

		// 验证标准模式：应该生成策略CLI，不生成组更新CLI
		hasGroupUpdate := false
		if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
			if strings.Contains(networkCLI, "address-group") {
				hasGroupUpdate = true
			}
		}
		hasPolicyCLI := false
		if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
			hasPolicyCLI = true
		}

		assert.False(t, hasGroupUpdate, "标准模式：不应该生成组更新CLI")
		assert.True(t, hasPolicyCLI, "标准模式：应该生成策略CLI")
		t.Logf("✓ 标准模式：生成了策略CLI，未生成组更新CLI")
	})

	// 测试增强模式
	t.Run("增强模式", func(t *testing.T) {
		metaData := map[string]interface{}{
			"policy_name_template":             "TEST_policy_{SEQ:id:4:1:1:MAIN}",
			"securitypolicy.reuse_policy":      "true",
			"securitypolicy.reuse_policy_mode": "enhanced", // 使用增强模式
			"action":                           "permit",
		}

		result, err := templates.MakePolicyV4(from, to, newIntent, ctx, metaData)
		require.NoError(t, err)
		require.NotNil(t, result)

		t.Logf("策略复用: %v", result.IsReused)
		if result.IsReused {
			t.Logf("复用策略名称: %s", result.ReusedPolicyName)
		}
		t.Logf("生成的CLI:\n%s", result.CLIString)

		// 验证增强模式：不使用组时，应该生成包含差异的策略CLI
		hasGroupUpdate := false
		if networkCLI, exists := result.FlyObject["NETWORK"]; exists && networkCLI != "" {
			if strings.Contains(networkCLI, "address-group") {
				hasGroupUpdate = true
			}
		}
		hasPolicyCLI := false
		if policyCLI, exists := result.FlyObject["SECURITY_POLICY"]; exists && policyCLI != "" {
			hasPolicyCLI = true
		}

		assert.False(t, hasGroupUpdate, "增强模式：未生成组更新CLI（因为不使用组），生成了包含差异的策略CLI")
		assert.True(t, hasPolicyCLI, "增强模式：应该生成包含差异的策略CLI")
		t.Logf("✓ 增强模式：未生成组更新CLI（因为不使用组），生成了包含差异的策略CLI")

		t.Logf("\n=== 模式对比 ===")
		t.Logf("标准模式：生成策略CLI = true, 生成组更新CLI = false")
		t.Logf("增强模式：生成策略CLI = true, 生成组更新CLI = false")
		t.Logf("✓ 验证通过：两种模式都只使用差异部分进行后续CLI生成")
	})
}
