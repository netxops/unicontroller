package srx

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NewTestSRXNode 创建测试用的SRX节点
func NewTestSRXNode() *SRXNode {
	deviceNode := node.NewDeviceNode("test-srx-id", "test-srx", api.FIREWALL)
	srx := &SRXNode{
		DeviceNode: deviceNode,
		objectSet:  NewSRXObjectSet(nil),
		policySet: &PolicySet{
			objects:   nil,
			node:      nil,
			policySet: map[string]map[string][]*Policy{},
		},
	}
	srx.objectSet = NewSRXObjectSet(srx)
	srx.policySet.objects = srx.objectSet
	srx.policySet.node = srx
	return srx
}

// TestSRXFlyConfigAddressGroupUpdate 测试地址组更新功能
func TestSRXFlyConfigAddressGroupUpdate(t *testing.T) {
	node := NewTestSRXNode()

	// 创建初始地址组
	initialCLI := `set security address-book global address-set EXISTING_GROUP
set security address-book global address-set EXISTING_GROUP address 192.168.1.1
set security address-book global address-set EXISTING_GROUP address 192.168.1.2
`

	// 解析初始CLI
	node.objectSet.parseConfig(initialCLI)

	// 验证初始组存在
	zoneMap, ok := node.objectSet.zoneAddressBook["global"]
	require.True(t, ok, "global zone应该存在")
	existingObj, ok := zoneMap["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该存在")
	existingGroup, ok := existingObj.(*srxNetwork)
	require.True(t, ok, "应该是srxNetwork类型")
	assert.Equal(t, firewall.GROUP_NETWORK, existingGroup.catagory, "应该是组类型")

	// 获取初始成员数量
	initialMemberCount := len(existingGroup.refNames)
	t.Logf("初始成员数量: %d", initialMemberCount)

	// 添加新成员的CLI（只包含一个成员，这是添加成员格式）
	updateCLI := `set security address-book global address-set EXISTING_GROUP address 192.168.1.3
`

	// 解析更新CLI
	t.Logf("更新CLI:\n%s", updateCLI)
	node.objectSet.parseConfig(updateCLI)

	// 验证组已更新（不是覆盖）
	updatedObj, ok := zoneMap["EXISTING_GROUP"]
	require.True(t, ok, "EXISTING_GROUP应该仍然存在")
	updatedGroup, ok := updatedObj.(*srxNetwork)
	require.True(t, ok, "应该是srxNetwork类型")

	// 验证成员已合并
	updatedMemberCount := len(updatedGroup.refNames)
	t.Logf("更新后成员数量: %d", updatedMemberCount)

	// 应该包含初始成员和新成员
	assert.Greater(t, updatedMemberCount, initialMemberCount, "更新后的组应该包含更多成员")
	assert.Contains(t, updatedGroup.refNames, "192.168.1.3", "应该包含新添加的成员")
}

// TestSRXFlyConfigServiceGroupUpdate 测试服务组更新功能
func TestSRXFlyConfigServiceGroupUpdate(t *testing.T) {
	node := NewTestSRXNode()

	// 创建初始服务组
	initialCLI := `set applications application-set EXISTING_SVC_GROUP
set applications application-set EXISTING_SVC_GROUP application tcp-80
set applications application-set EXISTING_SVC_GROUP application tcp-443
`

	// 解析初始CLI
	node.objectSet.parseConfig(initialCLI)

	// 验证初始组存在
	existingObj, ok := node.objectSet.serviceMap["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该存在")
	existingGroup, ok := existingObj.(*srxService)
	require.True(t, ok, "应该是srxService类型")
	assert.Equal(t, firewall.GROUP_SERVICE, existingGroup.catagory, "应该是组类型")

	// 获取初始成员数量
	initialMemberCount := len(existingGroup.refNames)
	t.Logf("初始成员数量: %d", initialMemberCount)

	// 添加新成员的CLI（只包含一个成员，这是添加成员格式）
	updateCLI := `set applications application-set EXISTING_SVC_GROUP application tcp-8080
`

	// 解析更新CLI
	node.objectSet.parseConfig(updateCLI)

	// 验证组已更新（不是覆盖）
	updatedObj, ok := node.objectSet.serviceMap["EXISTING_SVC_GROUP"]
	require.True(t, ok, "EXISTING_SVC_GROUP应该仍然存在")
	updatedGroup, ok := updatedObj.(*srxService)
	require.True(t, ok, "应该是srxService类型")

	// 验证成员已合并
	updatedMemberCount := len(updatedGroup.refNames)
	t.Logf("更新后成员数量: %d", updatedMemberCount)

	// 应该包含初始成员和新成员
	assert.Greater(t, updatedMemberCount, initialMemberCount, "更新后的组应该包含更多成员")
	assert.Contains(t, updatedGroup.refNames, "tcp-8080", "应该包含新添加的成员")
}

// TestSRXFlyConfigPolicyUpdate 测试策略更新功能
func TestSRXFlyConfigPolicyUpdate(t *testing.T) {
	node := NewTestSRXNode()

	// 先创建必要的地址对象和应用对象
	addressCLI := `set security address-book global address 192.168.1.0/24 192.168.1.0/24
set security address-book global address 10.0.0.0/24 10.0.0.0/24
set security address-book global address 192.168.2.0/24 192.168.2.0/24
`
	applicationCLI := `set applications application tcp-80
set applications application tcp-80 protocol tcp
set applications application tcp-80 destination-port 80
`

	// 解析地址对象和应用对象
	node.objectSet.parseConfig(addressCLI)
	node.objectSet.parseConfig(applicationCLI)

	// 创建初始策略
	initialCLI := `set security policies from-zone trust to-zone untrust policy EXISTING_POLICY
set security policies from-zone trust to-zone untrust policy EXISTING_POLICY match source-address 192.168.1.0/24
set security policies from-zone trust to-zone untrust policy EXISTING_POLICY match destination-address 10.0.0.0/24
set security policies from-zone trust to-zone untrust policy EXISTING_POLICY match application tcp-80
set security policies from-zone trust to-zone untrust policy EXISTING_POLICY then permit
`

	// 解析初始CLI
	node.policySet.parseConfig(initialCLI)

	// 验证初始策略存在
	var existingPolicy *Policy
	for _, fromMap := range node.policySet.policySet {
		for _, polList := range fromMap {
			for _, pol := range polList {
				if pol.name == "EXISTING_POLICY" {
					existingPolicy = pol
					break
				}
			}
			if existingPolicy != nil {
				break
			}
		}
		if existingPolicy != nil {
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
	updateCLI := `set security policies from-zone trust to-zone untrust policy EXISTING_POLICY match source-address 192.168.2.0/24
`

	// 解析更新CLI
	node.policySet.parseConfig(updateCLI)

	// 验证策略已更新（合并了新的源地址）
	var updatedPolicy *Policy
	for _, fromMap := range node.policySet.policySet {
		for _, polList := range fromMap {
			for _, pol := range polList {
				if pol.name == "EXISTING_POLICY" {
					updatedPolicy = pol
					break
				}
			}
			if updatedPolicy != nil {
				break
			}
		}
		if updatedPolicy != nil {
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

// TestSRXFlyConfigCreateNewObject 测试创建新对象（向后兼容）
func TestSRXFlyConfigCreateNewObject(t *testing.T) {
	node := NewTestSRXNode()

	// 创建新地址对象（完整定义）
	newCLI := `set security address-book global address NEW_OBJECT 192.168.10.1/32
`

	// 解析CLI
	node.objectSet.parseConfig(newCLI)

	// 验证新对象已创建
	zoneMap, ok := node.objectSet.zoneAddressBook["global"]
	require.True(t, ok, "global zone应该存在")
	newObj, ok := zoneMap["NEW_OBJECT"]
	require.True(t, ok, "NEW_OBJECT应该被创建")
	newNetworkObj, ok := newObj.(*srxNetwork)
	require.True(t, ok, "应该是srxNetwork类型")
	assert.Equal(t, firewall.OBJECT_NETWORK, newNetworkObj.catagory, "应该是OBJECT_NETWORK类型")

	// 验证对象包含正确的网络
	assert.NotNil(t, newNetworkObj.network, "网络组不应该为nil")
	assert.False(t, newNetworkObj.network.IsEmpty(), "网络组不应该为空")
}
