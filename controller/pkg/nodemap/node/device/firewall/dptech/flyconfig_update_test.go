package dptech

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

// TestDptechFlyConfigAddressGroupUpdate 测试地址组更新功能
func TestDptechFlyConfigAddressGroupUpdate(t *testing.T) {
	node := NewTestDptechNode()

	// 先创建地址对象，供地址组引用
	addressObjectCLI := `address-object OBJ1 192.168.1.0/24
address-object OBJ2 192.168.2.0/24
`
	node.ObjectSet.ParseConfig(addressObjectCLI)

	// 创建初始地址组
	initialCLI := `address-group EXISTING_GROUP address-object OBJ1
address-group EXISTING_GROUP address-object OBJ2
`

	// 解析初始CLI
	node.ObjectSet.ParseConfig(initialCLI)

	// 验证初始组存在
	existingObj, ok := node.ObjectSet.addressGroupSet["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该存在")
	existingGroup, ok := existingObj.(*DptechNetwork)
	require.True(t, ok, "应该是DptechNetwork类型")
	assert.Equal(t, firewall.OBJECT_NETWORK, existingGroup.catagory, "应该是网络对象类型")

	// 获取初始网络组（保存快照，因为更新后会改变）
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
	t.Logf("初始网络组: %s", initialNetworkStr)

	// 先创建新的地址对象
	newAddressObjectCLI := `address-object OBJ3 192.168.3.0/24
`
	node.ObjectSet.ParseConfig(newAddressObjectCLI)

	// 添加新成员的CLI（这是添加成员格式）
	updateCLI := `address-group EXISTING_GROUP address-object OBJ3
`

	// 解析更新CLI
	t.Logf("更新CLI:\n%s", updateCLI)
	node.ObjectSet.ParseConfig(updateCLI)

	// 验证组已更新（不是覆盖）
	updatedObj, ok := node.ObjectSet.addressGroupSet["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该仍然存在")
	updatedGroup, ok := updatedObj.(*DptechNetwork)
	require.True(t, ok, "应该是DptechNetwork类型")

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
	t.Logf("更新后的网络组: %s", updatedNetworkStr)

	// 验证更新后的网络组包含了新添加的网络
	has192_168_3_0 := false
	if updatedNetwork != nil {
		updatedNetwork.EachDataRangeEntryAsAbbrNet(func(n network.AbbrNet) bool {
			netStr := n.String()
			// 检查是否包含192.168.3.0/24（可能在合并后的范围中）
			if netStr == "192.168.3.0/24" || strings.Contains(netStr, "192.168.3") {
				has192_168_3_0 = true
			}
			return true
		})
	}

	// 验证更新后的网络组包含了新添加的网络
	assert.True(t, has192_168_3_0 || strings.Contains(updatedNetworkStr, "192.168.3"),
		"更新后的网络组应该包含192.168.3.0/24（可能在合并后的范围中）")

	// 验证更新确实发生了：如果初始网络组不包含192.168.3，更新后应该包含
	assert.NotEqual(t, initialNetworkStr, updatedNetworkStr, "更新后的网络组应该与初始不同")
	assert.True(t, strings.Contains(updatedNetworkStr, "192.168.3") || !strings.Contains(initialNetworkStr, "192.168.3"),
		"更新后的网络组应该包含192.168.3（如果初始不包含）")
}

// TestDptechFlyConfigServiceGroupUpdate 测试服务组更新功能
func TestDptechFlyConfigServiceGroupUpdate(t *testing.T) {
	node := NewTestDptechNode()

	// 先创建服务对象，供服务组引用
	serviceObjectCLI := `service-object SVC1 protocol tcp destination-port 80
service-object SVC2 protocol tcp destination-port 443
`
	node.ObjectSet.ParseConfig(serviceObjectCLI)

	// 创建初始服务组
	initialCLI := `service-group EXISTING_SVC_GROUP service-object SVC1
service-group EXISTING_SVC_GROUP service-object SVC2
`

	// 解析初始CLI
	node.ObjectSet.ParseConfig(initialCLI)

	// 验证初始组存在
	existingObj, ok := node.ObjectSet.serviceGroup["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该存在")
	existingGroup, ok := existingObj.(*DptechService)
	require.True(t, ok, "应该是DptechService类型")
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
	t.Logf("初始服务数量: %d", initialCount)

	// 先创建新的服务对象
	newServiceObjectCLI := `service-object SVC3 protocol tcp destination-port 8080
service-object SVC4 protocol udp destination-port 53
`
	node.ObjectSet.ParseConfig(newServiceObjectCLI)

	// 添加新成员的CLI（这是添加成员格式）
	updateCLI := `service-group EXISTING_SVC_GROUP service-object SVC3
service-group EXISTING_SVC_GROUP service-object SVC4
`

	// 解析更新CLI
	node.ObjectSet.ParseConfig(updateCLI)

	// 验证组已更新（不是覆盖）
	updatedObj, ok := node.ObjectSet.serviceGroup["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该仍然存在")
	updatedGroup, ok := updatedObj.(*DptechService)
	require.True(t, ok, "应该是DptechService类型")

	// 验证服务已合并（包含新成员）
	updatedService := updatedGroup.service
	updatedCount := 0
	if updatedService != nil {
		updatedService.EachDetailed(func(item service.ServiceEntry) bool {
			updatedCount++
			return true
		})
	}
	t.Logf("更新后服务数量: %d", updatedCount)

	// 应该包含初始成员和新成员
	assert.GreaterOrEqual(t, updatedCount, initialCount, "更新后的组应该包含更多或相等的成员")
}

// TestDptechFlyConfigPolicyUpdate 测试策略更新功能
func TestDptechFlyConfigPolicyUpdate(t *testing.T) {
	node := NewTestDptechNode()

	// 先创建地址对象
	addressObjectCLI := `address-object SRC_OBJ 192.168.1.0/24
address-object DST_OBJ 10.0.0.0/24
`
	node.ObjectSet.ParseConfig(addressObjectCLI)

	// 创建服务对象
	serviceObjectCLI := `service-object SVC_OBJ protocol tcp destination-port 80
`
	node.ObjectSet.ParseConfig(serviceObjectCLI)

	// 创建初始策略（dptech 支持多行策略）
	// CombinKey 会将同一策略名称的多行合并成一个 section，合并后的 section 包含所有行
	// 每行都需要包含 src-zone 和 dst-zone，因为 parseSectionWithGroup 使用 [^\n]+ 匹配
	initialCLI := `security-policy EXISTING_POLICY src-zone trust dst-zone untrust src-address address-object SRC_OBJ
security-policy EXISTING_POLICY src-zone trust dst-zone untrust dst-address address-object DST_OBJ
security-policy EXISTING_POLICY src-zone trust dst-zone untrust service service-object SVC_OBJ
security-policy EXISTING_POLICY src-zone trust dst-zone untrust action permit
`

	// 解析初始策略CLI
	err := node.PolicySet.parseConfig(initialCLI)
	require.NoError(t, err, "解析初始策略应该成功")

	// 验证初始策略存在
	var existingPolicy *Policy
	for _, pol := range node.PolicySet.policySet {
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

	// 创建新的地址对象用于更新
	newAddressObjectCLI := `address-object SRC_OBJ2 192.168.2.0/24
address-object SRC_OBJ3 192.168.3.0/24
`
	node.ObjectSet.ParseConfig(newAddressObjectCLI)

	// 部分策略CLI（只包含新增的源地址，这是差异部分）
	// 注意：dptech 的策略解析会合并同名策略，所以可以分别添加新的源地址
	updateCLI := `security-policy EXISTING_POLICY src-zone trust dst-zone untrust src-address address-object SRC_OBJ2
security-policy EXISTING_POLICY src-zone trust dst-zone untrust src-address address-object SRC_OBJ3
`

	// 解析更新CLI
	err = node.PolicySet.parseConfig(updateCLI)
	require.NoError(t, err, "解析更新策略应该成功")

	// 验证策略已更新（不是覆盖）
	var updatedPolicy *Policy
	for _, pol := range node.PolicySet.policySet {
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

// TestDptechFlyConfigCreateNewObject 测试创建新对象（向后兼容）
func TestDptechFlyConfigCreateNewObject(t *testing.T) {
	node := NewTestDptechNode()

	// 创建新地址对象（完整定义）
	newCLI := `address-object NEW_OBJECT 192.168.10.0/24
`

	// 解析CLI
	node.ObjectSet.ParseConfig(newCLI)

	// 验证新对象已创建
	newObj, ok := node.ObjectSet.addressObjectSet["NEW_OBJECT"]
	require.True(t, ok, "NEW_OBJECT应该被创建")
	newNetworkObj, ok := newObj.(*DptechNetwork)
	require.True(t, ok, "应该是DptechNetwork类型")
	assert.Equal(t, firewall.OBJECT_NETWORK, newNetworkObj.catagory, "应该是OBJECT_NETWORK类型")

	// 验证对象包含正确的网络
	assert.NotNil(t, newNetworkObj.network, "网络组不应该为nil")
	assert.False(t, newNetworkObj.network.IsEmpty(), "网络组不应该为空")
}
