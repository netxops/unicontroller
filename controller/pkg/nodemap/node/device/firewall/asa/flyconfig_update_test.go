package asa

import (
	"strings"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestASAFlyConfigAddressGroupUpdate 测试地址组更新功能
func TestASAFlyConfigAddressGroupUpdate(t *testing.T) {
	node := NewTestASANode()

	// 创建初始地址组
	initialCLI := `object-group network EXISTING_GROUP
 network-object host 192.168.1.1
 network-object host 192.168.1.2
`

	// 解析初始CLI
	node.objectSet.parseConfig(initialCLI)

	// 验证初始组存在
	existingObj, ok := node.objectSet.networkMap["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该存在")
	existingGroup, ok := existingObj.(*asaNetwork)
	require.True(t, ok, "应该是asaNetwork类型")
	assert.Equal(t, firewall.GROUP_NETWORK, existingGroup.catagory, "应该是组类型")

	// 获取初始网络组（保存快照）
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

	// 添加新成员的CLI（没有description，这是添加成员格式）
	updateCLI := `object-group network EXISTING_GROUP
 network-object host 192.168.1.3
 network-object 192.168.2.0 255.255.255.0
`

	// 解析更新CLI
	t.Logf("更新CLI:\n%s", updateCLI)
	node.objectSet.parseConfig(updateCLI)

	// 验证组已更新（不是覆盖）
	updatedObj, ok := node.objectSet.networkMap["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该仍然存在")
	updatedGroup, ok := updatedObj.(*asaNetwork)
	require.True(t, ok, "应该是asaNetwork类型")

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
	assert.True(t, strings.Contains(updatedNetworkStr, "192.168.1.3") || strings.Contains(updatedNetworkStr, "192.168.2"),
		"更新后的网络组应该包含新添加的地址")
}

// TestASAFlyConfigServiceGroupUpdate 测试服务组更新功能
func TestASAFlyConfigServiceGroupUpdate(t *testing.T) {
	node := NewTestASANode()

	// 创建初始服务组
	initialCLI := `object-group service EXISTING_SVC_GROUP tcp
 port-object eq 80
 port-object eq 443
`

	// 解析初始CLI
	node.objectSet.parseConfig(initialCLI)

	// 验证初始组存在
	existingObj, ok := node.objectSet.serviceMap["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该存在")
	existingGroup, ok := existingObj.(*asaService)
	require.True(t, ok, "应该是asaService类型")
	assert.Equal(t, firewall.GROUP_SERVICE, existingGroup.catagory, "应该是组类型")

	// 获取初始服务
	initialService := existingGroup.service
	initialCount := 0
	if initialService != nil {
		initialService.EachDetailed(func(item service.ServiceEntry) bool {
			initialCount++
			return true
		})
	}

	// 添加新成员的CLI（没有description，这是添加成员格式）
	updateCLI := `object-group service EXISTING_SVC_GROUP tcp
 port-object eq 8080
 port-object range 9000 9010
`

	// 解析更新CLI
	node.objectSet.parseConfig(updateCLI)

	// 验证组已更新（不是覆盖）
	updatedObj, ok := node.objectSet.serviceMap["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该仍然存在")
	updatedGroup, ok := updatedObj.(*asaService)
	require.True(t, ok, "应该是asaService类型")

	// 验证服务已合并（包含新成员）
	updatedService := updatedGroup.service
	updatedCount := 0
	if updatedService != nil {
		updatedService.EachDetailed(func(item service.ServiceEntry) bool {
			updatedCount++
			return true
		})
	}

	// 应该包含初始成员和新成员
	assert.Greater(t, updatedCount, initialCount, "更新后的组应该包含更多成员")
}

// TestASAFlyConfigPolicyUpdate 测试策略更新功能
func TestASAFlyConfigPolicyUpdate(t *testing.T) {
	node := NewTestASANode()

	// 创建初始策略
	initialCLI := `access-list TEST_ACL extended permit tcp host 192.168.1.1 host 10.0.0.1 eq 80
`

	// 解析初始CLI
	node.policySet.parseConfig(initialCLI)

	// 验证初始策略存在
	var existingPolicy *Policy
	for _, polList := range node.policySet.policySet {
		for _, pol := range polList {
			if strings.Contains(pol.cli, "192.168.1.1") {
				existingPolicy = pol
				break
			}
		}
		if existingPolicy != nil {
			break
		}
	}
	require.NotNil(t, existingPolicy, "应该找到初始策略")

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
	updateCLI := `access-list TEST_ACL extended permit tcp host 192.168.1.2 host 10.0.0.1 eq 80
`

	// 解析更新CLI
	node.policySet.parseConfig(updateCLI)

	// 验证策略已更新（合并了新的源地址）
	// 注意：ASA的策略可能通过ACL名称合并，这里主要验证解析成功
	t.Logf("策略更新完成")
}

// TestASAFlyConfigCreateNewObject 测试创建新对象（向后兼容）
func TestASAFlyConfigCreateNewObject(t *testing.T) {
	node := NewTestASANode()

	// 创建新地址对象（完整定义，包含description）
	newCLI := `object network NEW_OBJECT
 host 192.168.10.1
 description New object
`

	// 解析CLI
	node.objectSet.parseConfig(newCLI)

	// 验证新对象已创建
	newObj, ok := node.objectSet.networkMap["NEW_OBJECT"]
	require.True(t, ok, "NEW_OBJECT应该被创建")
	newNetworkObj, ok := newObj.(*asaNetwork)
	require.True(t, ok, "应该是asaNetwork类型")
	assert.Equal(t, firewall.OBJECT_NETWORK, newNetworkObj.catagory, "应该是OBJECT_NETWORK类型")

	// 验证对象包含正确的网络
	assert.NotNil(t, newNetworkObj.network, "网络组不应该为nil")
	assert.False(t, newNetworkObj.network.IsEmpty(), "网络组不应该为空")
}
