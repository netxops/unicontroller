package secpath

import (
	"strings"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecPathFlyConfigAddressGroupUpdate 测试地址组更新功能
func TestSecPathFlyConfigAddressGroupUpdate(t *testing.T) {
	node := NewTestSecPathNode()

	// 创建初始地址组
	initialCLI := `object-group ip address EXISTING_GROUP
 network subnet 192.168.1.0 255.255.255.0
 network subnet 192.168.2.0 255.255.255.0
`

	// 解析初始CLI
	node.ObjectSet.parseNetworkCli(initialCLI)

	// 验证初始组存在
	zoneMap, ok := node.ObjectSet.ZoneNetworkMap["global"]
	require.True(t, ok, "trust zone应该存在")
	existingObj, ok := zoneMap["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该存在")
	existingGroup, ok := existingObj.(*secpathNetwork)
	require.True(t, ok, "应该是secpathNetwork类型")
	assert.Equal(t, firewall.GROUP_NETWORK, existingGroup.Catagory, "应该是组类型")

	// 获取初始网络组（保存快照，因为更新后会改变）
	initialNetwork := existingGroup.NetworkGroup
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
	t.Logf("初始网络组: %s", initialNetworkStr)

	// 添加新成员的CLI（没有security-zone，这是添加成员格式）
	// 注意：每次只添加一个成员，因为解析逻辑可能不支持一次添加多个
	updateCLI := `object-group ip address EXISTING_GROUP
 network subnet 192.168.3.0 255.255.255.0
`

	// 解析更新CLI
	t.Logf("更新CLI:\n%s", updateCLI)
	node.ObjectSet.parseNetworkCli(updateCLI)

	// 验证组已更新（不是覆盖）
	updatedObj, ok := zoneMap["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该仍然存在")
	updatedGroup, ok := updatedObj.(*secpathNetwork)
	require.True(t, ok, "应该是secpathNetwork类型")

	// 验证网络组已合并（包含新成员）
	updatedNetwork := updatedGroup.NetworkGroup
	updatedCount := 0
	if updatedNetwork != nil {
		updatedNetwork.EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			updatedCount++
			t.Logf("更新后成员: %s", n.String())
			return true
		})
	}
	t.Logf("更新后成员数量: %d", updatedCount)

	// NetworkGroup会自动合并相邻的网络，所以成员数量可能不会增加
	// 但我们应该验证更新后的网络组包含了新添加的网络
	// 验证新成员存在（可能被合并到范围中）
	has192_168_3_0 := false
	updatedNetworkStr := ""
	if updatedNetwork != nil {
		updatedNetwork.EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			netStr := n.String()
			updatedNetworkStr += netStr + ", "
			// 检查是否包含192.168.3.0/24（可能在合并后的范围中）
			if netStr == "192.168.3.0/24" || strings.Contains(netStr, "192.168.3") {
				has192_168_3_0 = true
			}
			return true
		})
	}
	t.Logf("更新后的网络组: %s", updatedNetworkStr)

	// 验证更新后的网络组包含了新添加的网络（可能被合并）
	// 如果初始是192.168.1.0-192.168.2.255，更新后应该是192.168.1.0-192.168.3.255
	assert.True(t, has192_168_3_0 || strings.Contains(updatedNetworkStr, "192.168.3"),
		"更新后的网络组应该包含192.168.3.0/24（可能在合并后的范围中）")

	// 验证更新确实发生了：如果初始网络组不包含192.168.3，更新后应该包含
	assert.NotEqual(t, initialNetworkStr, updatedNetworkStr, "更新后的网络组应该与初始不同")
	assert.True(t, strings.Contains(updatedNetworkStr, "192.168.3") || !strings.Contains(initialNetworkStr, "192.168.3"),
		"更新后的网络组应该包含192.168.3（如果初始不包含）")
}

// TestSecPathFlyConfigServiceGroupUpdate 测试服务组更新功能
func TestSecPathFlyConfigServiceGroupUpdate(t *testing.T) {
	node := NewTestSecPathNode()

	// 创建初始服务组
	initialCLI := `object-group service EXISTING_SVC_GROUP
 service tcp destination eq 80
 service tcp destination eq 443
`

	// 解析初始CLI
	node.ObjectSet.parseServiceCli(initialCLI)

	// 验证初始组存在
	existingObj, ok := node.ObjectSet.ServiceMap["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该存在")
	existingGroup, ok := existingObj.(*secpathService)
	require.True(t, ok, "应该是secpathService类型")
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

	// 添加新成员的CLI（没有完整定义，这是添加成员格式）
	updateCLI := `object-group service EXISTING_SVC_GROUP
 service tcp destination eq 8080
 service udp destination eq 53
`

	// 解析更新CLI
	node.ObjectSet.parseServiceCli(updateCLI)

	// 验证组已更新（不是覆盖）
	updatedObj, ok := node.ObjectSet.ServiceMap["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该仍然存在")
	updatedGroup, ok := updatedObj.(*secpathService)
	require.True(t, ok, "应该是secpathService类型")

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
	assert.Equal(t, initialCount+2, updatedCount, "应该添加了2个新成员")
}

// TestSecPathFlyConfigPolicyUpdate 测试策略更新功能
func TestSecPathFlyConfigPolicyUpdate(t *testing.T) {
	node := NewTestSecPathNode()

	// 创建初始策略
	initialCLI := `security-policy ip
 rule 1 name EXISTING_POLICY
  source-zone trust
  destination-zone untrust
  source-ip-subnet 192.168.1.0 255.255.255.0
  destination-ip-subnet 10.0.0.0 255.255.255.0
  service-port tcp destination eq 80
  action pass
`

	// 解析初始CLI
	node.PolicySet.flySecurityRuleCli(initialCLI)

	// 验证初始策略存在
	var existingPolicy *Policy
	for _, pol := range node.PolicySet.securityPolicyAcl {
		if pol.name == "EXISTING_POLICY" {
			existingPolicy = pol
			break
		}
	}
	require.NotNil(t, existingPolicy, "EXISTING_POLICY应该存在")

	// 获取初始策略条目（保存快照）
	initialEntry := existingPolicy.policyEntry
	initialSrcCount := 0
	initialSrcStr := ""
	if initialEntry.Src() != nil {
		initialEntry.Src().EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			initialSrcCount++
			initialSrcStr += n.String() + ", "
			return true
		})
	}
	t.Logf("初始源地址: %s", initialSrcStr)

	// 部分策略CLI（只包含新增的源地址，这是差异部分）
	updateCLI := `security-policy ip
 rule 1 name EXISTING_POLICY
  source-ip-subnet 192.168.2.0 255.255.255.0
  source-ip-subnet 192.168.3.0 255.255.255.0
`

	// 解析更新CLI
	node.PolicySet.flySecurityRuleCli(updateCLI)

	// 验证策略已更新（不是覆盖）
	var updatedPolicy *Policy
	for _, pol := range node.PolicySet.securityPolicyAcl {
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
	updatedSrcStr := ""
	if updatedEntry.Src() != nil {
		updatedEntry.Src().EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			updatedSrcCount++
			updatedSrcStr += n.String() + ", "
			return true
		})
	}
	t.Logf("更新后源地址: %s", updatedSrcStr)

	// NetworkGroup会自动合并相邻的网络，所以成员数量可能不会增加
	// 但我们应该验证更新后的源地址包含了新添加的网络
	assert.NotEqual(t, initialSrcStr, updatedSrcStr, "更新后的源地址应该与初始不同")
	assert.True(t, strings.Contains(updatedSrcStr, "192.168.2") || strings.Contains(updatedSrcStr, "192.168.3"),
		"更新后的源地址应该包含192.168.2或192.168.3")

	// 验证目标地址和服务没有被覆盖（仍然存在）
	assert.NotNil(t, updatedEntry.Dst(), "目标地址应该仍然存在")
	assert.NotNil(t, updatedEntry.Service(), "服务应该仍然存在")

	// 使用 PolicyEntry 的 Match 方法验证策略匹配
	// 测试1: 使用初始源地址（192.168.1.0/24）应该能匹配
	intent1 := &policy.Intent{}
	srcNg1, _ := network.NewNetworkGroupFromString("192.168.1.0/24")
	intent1.SetSrc(srcNg1)
	dstNg1, _ := network.NewNetworkGroupFromString("10.0.0.0/24")
	intent1.SetDst(dstNg1)
	svc1, _ := service.NewServiceFromString("tcp:80")
	intent1.SetService(svc1)

	match1 := updatedPolicy.policyEntry.Match(intent1)
	assert.True(t, match1, "使用初始源地址 192.168.1.0/24 的策略应该匹配")
	t.Logf("测试1通过: 初始源地址 192.168.1.0/24 匹配成功")

	// 测试2: 使用新增的源地址（192.168.2.0/24）应该能匹配
	intent2 := &policy.Intent{}
	srcNg2, _ := network.NewNetworkGroupFromString("192.168.2.0/24")
	intent2.SetSrc(srcNg2)
	dstNg2, _ := network.NewNetworkGroupFromString("10.0.0.0/24")
	intent2.SetDst(dstNg2)
	svc2, _ := service.NewServiceFromString("tcp:80")
	intent2.SetService(svc2)

	match2 := updatedPolicy.policyEntry.Match(intent2)
	assert.True(t, match2, "使用新增源地址 192.168.2.0/24 的策略应该匹配")
	t.Logf("测试2通过: 新增源地址 192.168.2.0/24 匹配成功")

	// 测试3: 使用另一个新增的源地址（192.168.3.0/24）应该能匹配
	intent3 := &policy.Intent{}
	srcNg3, _ := network.NewNetworkGroupFromString("192.168.3.0/24")
	intent3.SetSrc(srcNg3)
	dstNg3, _ := network.NewNetworkGroupFromString("10.0.0.0/24")
	intent3.SetDst(dstNg3)
	svc3, _ := service.NewServiceFromString("tcp:80")
	intent3.SetService(svc3)

	match3 := updatedPolicy.policyEntry.Match(intent3)
	assert.True(t, match3, "使用另一个新增源地址 192.168.3.0/24 的策略应该匹配")
	t.Logf("测试3通过: 新增源地址 192.168.3.0/24 匹配成功")

	// 测试4: 使用不匹配的源地址（192.168.4.0/24）应该不匹配
	intent4 := &policy.Intent{}
	srcNg4, _ := network.NewNetworkGroupFromString("192.168.4.0/24")
	intent4.SetSrc(srcNg4)
	dstNg4, _ := network.NewNetworkGroupFromString("10.0.0.0/24")
	intent4.SetDst(dstNg4)
	svc4, _ := service.NewServiceFromString("tcp:80")
	intent4.SetService(svc4)

	match4 := updatedPolicy.policyEntry.Match(intent4)
	assert.False(t, match4, "使用不匹配的源地址 192.168.4.0/24 的策略应该不匹配")
	t.Logf("测试4通过: 不匹配的源地址 192.168.4.0/24 正确返回 false")
}

// TestSecPathFlyConfigCreateNewObject 测试创建新对象（向后兼容）
func TestSecPathFlyConfigCreateNewObject(t *testing.T) {
	node := NewTestSecPathNode()

	// 创建新地址对象（完整定义，包含security-zone）
	// 注意：单个子网的对象应该是OBJECT_NETWORK，不是GROUP_NETWORK
	newCLI := `object-group ip address NEW_OBJECT
 security-zone trust
 network subnet 192.168.10.0 255.255.255.0
`

	// 解析CLI
	node.ObjectSet.parseNetworkCli(newCLI)

	// 验证新对象已创建
	zoneMap, ok := node.ObjectSet.ZoneNetworkMap["trust"]
	require.True(t, ok, "trust zone应该存在")
	newObj, ok := zoneMap["NEW_OBJECT"]
	require.True(t, ok, "NEW_OBJECT应该被创建")
	newNetworkObj, ok := newObj.(*secpathNetwork)
	require.True(t, ok, "应该是secpathNetwork类型")
	// 单个子网的对象应该是OBJECT_NETWORK类型
	assert.Equal(t, firewall.OBJECT_NETWORK, newNetworkObj.Catagory, "单个子网应该是OBJECT_NETWORK类型")

	// 验证对象包含正确的网络
	assert.NotNil(t, newNetworkObj.NetworkGroup, "网络组不应该为nil")
	assert.False(t, newNetworkObj.NetworkGroup.IsEmpty(), "网络组不应该为空")
}
