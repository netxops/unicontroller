package sangfor

import (
	"strings"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSangforFlyConfigAddressGroupUpdate 测试地址组更新功能
func TestSangforFlyConfigAddressGroupUpdate(t *testing.T) {
	node := NewTestSangforNode()

	// 创建初始地址组（通过parseNetworkItem）
	initialItemMap := map[string]interface{}{
		"name":         "EXISTING_GROUP",
		"businessType": "ADDRGROUP",
		"ipRanges": []interface{}{
			map[string]interface{}{
				"start": "192.168.1.1",
				"end":   "192.168.1.1",
			},
			map[string]interface{}{
				"start": "192.168.1.2",
				"end":   "192.168.1.2",
			},
		},
	}

	// 解析初始对象
	node.objectSet.parseNetworkItem(initialItemMap)

	// 验证初始组存在
	existingGroup, ok := node.objectSet.networkMap["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该存在")
	require.NotNil(t, existingGroup, "EXISTING_GROUP不应该为nil")
	assert.Equal(t, firewall.GROUP_NETWORK, existingGroup.objType, "应该是组类型")

	// 获取初始网络组
	initialNetwork := existingGroup.network
	initialCount := 0
	initialNetworkStr := ""
	if initialNetwork != nil {
		initialNetwork.EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			initialCount++
			netStr := n.String()
			initialNetworkStr += netStr + ", "
			t.Logf("初始成员: %s", netStr)
			return true
		})
	}
	t.Logf("初始成员数量: %d", initialCount)

	// 添加新成员的CLI（只包含一个成员，这是添加成员格式）
	updateItemMap := map[string]interface{}{
		"name":         "EXISTING_GROUP",
		"businessType": "ADDRGROUP",
		"ipRanges": []interface{}{
			map[string]interface{}{
				"start": "192.168.1.3",
				"end":   "192.168.1.3",
			},
		},
	}

	// 解析更新对象
	t.Logf("更新对象: %+v", updateItemMap)
	node.objectSet.parseNetworkItem(updateItemMap)

	// 验证组已更新（不是覆盖）
	updatedGroup, ok := node.objectSet.networkMap["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该仍然存在")
	require.NotNil(t, updatedGroup, "EXISTING_GROUP不应该为nil")

	// 验证网络组已合并（包含新成员）
	updatedNetwork := updatedGroup.network
	updatedCount := 0
	updatedNetworkStr := ""
	if updatedNetwork != nil {
		updatedNetwork.EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			updatedCount++
			netStr := n.String()
			updatedNetworkStr += netStr + ", "
			t.Logf("更新后成员: %s", netStr)
			return true
		})
	}
	t.Logf("更新后成员数量: %d", updatedCount)

	// 验证更新后的网络组包含了新添加的网络
	assert.GreaterOrEqual(t, updatedCount, initialCount, "更新后的组应该包含更多或相等的成员")
	assert.True(t, strings.Contains(updatedNetworkStr, "192.168.1.3"),
		"更新后的网络组应该包含新添加的地址")
}

// TestSangforFlyConfigServiceGroupUpdate 测试服务组更新功能
func TestSangforFlyConfigServiceGroupUpdate(t *testing.T) {
	node := NewTestSangforNode()

	// 创建初始服务组
	initialItemMap := map[string]interface{}{
		"name":     "EXISTING_SVC_GROUP",
		"servType": "SERV_GRP",
		"servsInfo": []interface{}{
			"SVC_1",
			"SVC_2",
		},
	}

	// 创建成员服务对象
	node.objectSet.parseServiceItem(map[string]interface{}{
		"name": "SVC_1",
		"tcpEntrys": []interface{}{
			map[string]interface{}{
				"dstPorts": []interface{}{
					map[string]interface{}{
						"start": float64(80),
						"end":   float64(80),
					},
				},
			},
		},
	})
	node.objectSet.parseServiceItem(map[string]interface{}{
		"name": "SVC_2",
		"tcpEntrys": []interface{}{
			map[string]interface{}{
				"dstPorts": []interface{}{
					map[string]interface{}{
						"start": float64(443),
						"end":   float64(443),
					},
				},
			},
		},
	})

	// 解析初始服务组
	node.objectSet.parseServiceItem(initialItemMap)

	// 验证初始组存在
	existingGroup, ok := node.objectSet.serviceMap["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该存在")
	require.NotNil(t, existingGroup, "EXISTING_SVC_GROUP不应该为nil")
	assert.Equal(t, firewall.GROUP_SERVICE, existingGroup.objType, "应该是组类型")

	// 获取初始成员数量
	initialMemberCount := len(existingGroup.refNames)
	t.Logf("初始成员数量: %d", initialMemberCount)

	// 添加新成员的CLI（只包含一个成员，这是添加成员格式）
	updateItemMap := map[string]interface{}{
		"name":     "EXISTING_SVC_GROUP",
		"servType": "SERV_GRP",
		"servsInfo": []interface{}{
			"SVC_3",
		},
	}

	// 创建新成员服务对象
	node.objectSet.parseServiceItem(map[string]interface{}{
		"name": "SVC_3",
		"tcpEntrys": []interface{}{
			map[string]interface{}{
				"dstPorts": []interface{}{
					map[string]interface{}{
						"start": float64(8080),
						"end":   float64(8080),
					},
				},
			},
		},
	})

	// 解析更新服务组
	node.objectSet.parseServiceItem(updateItemMap)

	// 验证组已更新（不是覆盖）
	updatedGroup, ok := node.objectSet.serviceMap["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该仍然存在")
	require.NotNil(t, updatedGroup, "EXISTING_SVC_GROUP不应该为nil")

	// 验证成员已合并
	updatedMemberCount := len(updatedGroup.refNames)
	t.Logf("更新后成员数量: %d", updatedMemberCount)

	// 应该包含初始成员和新成员
	assert.Greater(t, updatedMemberCount, initialMemberCount, "更新后的组应该包含更多成员")
	assert.Contains(t, updatedGroup.refNames, "SVC_3", "应该包含新添加的成员")
}

// TestSangforFlyConfigPolicyUpdate 测试策略更新功能
func TestSangforFlyConfigPolicyUpdate(t *testing.T) {
	node := NewTestSangforNode()

	// 创建初始策略
	initialItemMap := map[string]interface{}{
		"name":     "EXISTING_POLICY",
		"srcZones": []interface{}{"trust"},
		"dstZones": []interface{}{"untrust"},
		"srcAddrs": []interface{}{
			map[string]interface{}{
				"ipRanges": []interface{}{
					map[string]interface{}{
						"start": "192.168.1.0",
						"end":   "192.168.1.255",
						"bits":  float64(24),
					},
				},
			},
		},
		"dstAddrs": []interface{}{
			map[string]interface{}{
				"ipRanges": []interface{}{
					map[string]interface{}{
						"start": "10.0.0.0",
						"end":   "10.0.255.255",
						"bits":  float64(24),
					},
				},
			},
		},
		"services": []interface{}{
			map[string]interface{}{
				"tcpEntrys": []interface{}{
					map[string]interface{}{
						"dstPorts": []interface{}{
							map[string]interface{}{
								"start": float64(80),
								"end":   float64(80),
							},
						},
					},
				},
			},
		},
		"action": "permit",
		"enable": true,
	}

	// 解析初始策略
	initialPolicy := node.policySet.parsePolicyItem(initialItemMap)
	require.NotNil(t, initialPolicy, "应该成功解析初始策略")
	node.policySet.addPolicy(initialPolicy)

	// 验证初始策略存在
	var existingPolicy *Policy
	for _, pol := range node.policySet.policySet {
		if pol.name == "EXISTING_POLICY" {
			existingPolicy = pol
			break
		}
	}
	require.NotNil(t, existingPolicy, "EXISTING_POLICY应该存在")

	// 获取初始策略条目
	initialEntry := existingPolicy.policyEntry
	initialSrcCount := 0
	if initialEntry.Src() != nil {
		initialEntry.Src().EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			initialSrcCount++
			return true
		})
	}

	// 部分策略CLI（只包含新增的源地址）
	updateItemMap := map[string]interface{}{
		"name": "EXISTING_POLICY",
		"srcAddrs": []interface{}{
			map[string]interface{}{
				"ipRanges": []interface{}{
					map[string]interface{}{
						"start": "192.168.2.0",
						"end":   "192.168.2.255",
						"bits":  float64(24),
					},
				},
			},
		},
	}

	// 解析更新策略
	updatePolicy := node.policySet.parsePolicyItem(updateItemMap)
	require.NotNil(t, updatePolicy, "应该成功解析更新策略")
	node.policySet.addPolicy(updatePolicy)

	// 验证策略已更新（合并了新的源地址）
	var updatedPolicy *Policy
	for _, pol := range node.policySet.policySet {
		if pol.name == "EXISTING_POLICY" {
			updatedPolicy = pol
			break
		}
	}
	require.NotNil(t, updatedPolicy, "EXISTING_POLICY应该仍然存在")
	assert.Equal(t, existingPolicy, updatedPolicy, "应该是同一个策略对象")

	// 验证策略条目已合并（包含新源地址）
	updatedEntry := updatedPolicy.policyEntry
	updatedSrcCount := 0
	if updatedEntry.Src() != nil {
		updatedEntry.Src().EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			updatedSrcCount++
			return true
		})
	}

	// 验证更新后的源地址包含了新添加的网络
	assert.GreaterOrEqual(t, updatedSrcCount, initialSrcCount, "更新后的源地址应该包含更多或相等的成员")

	// 验证目标地址和服务没有被覆盖（仍然存在）
	assert.NotNil(t, updatedEntry.Dst(), "目标地址应该仍然存在")
	assert.NotNil(t, updatedEntry.Service(), "服务应该仍然存在")
}

// TestSangforFlyConfigCreateNewObject 测试创建新对象（向后兼容）
func TestSangforFlyConfigCreateNewObject(t *testing.T) {
	node := NewTestSangforNode()

	// 创建新地址对象（完整定义）
	newItemMap := map[string]interface{}{
		"name": "NEW_OBJECT",
		"ipRanges": []interface{}{
			map[string]interface{}{
				"start": "192.168.10.1",
				"end":   "192.168.10.1",
			},
		},
	}

	// 解析CLI
	node.objectSet.parseNetworkItem(newItemMap)

	// 验证新对象已创建
	newNetworkObj, ok := node.objectSet.networkMap["NEW_OBJECT"]
	require.True(t, ok, "NEW_OBJECT应该被创建")
	require.NotNil(t, newNetworkObj, "NEW_OBJECT不应该为nil")
	assert.Equal(t, firewall.OBJECT_NETWORK, newNetworkObj.objType, "应该是OBJECT_NETWORK类型")

	// 验证对象包含正确的网络
	assert.NotNil(t, newNetworkObj.network, "网络组不应该为nil")
	assert.False(t, newNetworkObj.network.IsEmpty(), "网络组不应该为空")
}
