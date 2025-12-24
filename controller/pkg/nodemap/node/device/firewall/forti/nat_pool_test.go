package forti

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
)

func TestParseRespResultForIpPool(t *testing.T) {
	tests := []struct {
		name          string
		result        []dto.ForiRespResult
		expectedPools map[string]struct {
			name    string
			startIP string
			endIP   string
		}
		expectedCount int
	}{
		{
			name: "Single pool with IP range",
			result: []dto.ForiRespResult{
				{
					Name:        "pool1",
					StartIpPool: "192.168.1.1",
					EndIpPool:   "192.168.1.10",
				},
			},
			expectedPools: map[string]struct {
				name    string
				startIP string
				endIP   string
			}{
				"pool1": {
					name:    "pool1",
					startIP: "192.168.1.1",
					endIP:   "192.168.1.10",
				},
			},
			expectedCount: 1,
		},
		{
			name: "Multiple pools with different IP ranges",
			result: []dto.ForiRespResult{
				{
					Name:        "pool1",
					StartIpPool: "192.168.1.1",
					EndIpPool:   "192.168.1.10",
				},
				{
					Name:        "pool2",
					StartIpPool: "10.0.0.1",
					EndIpPool:   "10.0.0.20",
				},
				{
					Name:        "pool3",
					StartIpPool: "172.16.0.1",
					EndIpPool:   "172.16.0.5",
				},
			},
			expectedPools: map[string]struct {
				name    string
				startIP string
				endIP   string
			}{
				"pool1": {
					name:    "pool1",
					startIP: "192.168.1.1",
					endIP:   "192.168.1.10",
				},
				"pool2": {
					name:    "pool2",
					startIP: "10.0.0.1",
					endIP:   "10.0.0.20",
				},
				"pool3": {
					name:    "pool3",
					startIP: "172.16.0.1",
					endIP:   "172.16.0.5",
				},
			},
			expectedCount: 3,
		},
		{
			name: "Pool with single IP (same start and end)",
			result: []dto.ForiRespResult{
				{
					Name:        "singleippool",
					StartIpPool: "192.168.1.100",
					EndIpPool:   "192.168.1.100",
				},
			},
			expectedPools: map[string]struct {
				name    string
				startIP string
				endIP   string
			}{
				"singleippool": {
					name:    "singleippool",
					startIP: "192.168.1.100",
					endIP:   "192.168.1.100",
				},
			},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &FortigateNode{}
			nats := NewFortiNats(node)
			node.nats = nats
			node.objectSet = NewFortiObjectSet(node)

			// 测试解析
			nats.parseRespResultForIpPool(tt.result)

			// 验证池的数量
			assert.Equal(t, tt.expectedCount, len(nats.DynamicRules), "Pool count mismatch")

			// 验证每个池
			for poolName, expected := range tt.expectedPools {
				rule := nats.getPoolByName(poolName)
				assert.NotNil(t, rule, "Pool %s should be found", poolName)
				if rule != nil {
					assert.Equal(t, expected.name, rule.Name(), "Pool name mismatch")
					assert.Equal(t, firewall.DYNAMIC_NAT, rule.natType, "NAT type should be DYNAMIC_NAT")
					assert.Equal(t, firewall.NAT_ACTIVE, rule.status, "Status should be ACTIVE")
					assert.Equal(t, "any", rule.from, "From should be 'any'")
					assert.Equal(t, "any", rule.to, "To should be 'any'")

					// 验证网络组
					translateSrc := rule.translate.Src()
					assert.NotNil(t, translateSrc, "Translate source should not be nil")

					expectedNetwork, err := network.NewNetworkGroupFromString(expected.startIP + "-" + expected.endIP)
					assert.NoError(t, err, "Should create expected network group")
					assert.True(t, expectedNetwork.Same(translateSrc), "Network range mismatch for pool %s", poolName)

					// 验证 CLI
					assert.NotEmpty(t, rule.Cli(), "CLI should not be empty")
					assert.Contains(t, rule.Cli(), expected.name, "CLI should contain pool name")
					assert.Contains(t, rule.Cli(), expected.startIP, "CLI should contain start IP")
					assert.Contains(t, rule.Cli(), expected.endIP, "CLI should contain end IP")
				}
			}
		})
	}
}

func TestParseRespResultForIpPool_InvalidInput(t *testing.T) {
	t.Run("Pool with empty start IP", func(t *testing.T) {
		node := &FortigateNode{}
		nats := NewFortiNats(node)
		node.nats = nats
		node.objectSet = NewFortiObjectSet(node)

		result := []dto.ForiRespResult{
			{
				Name:        "pool1",
				StartIpPool: "",
				EndIpPool:   "192.168.1.10",
			},
		}

		assert.Panics(t, func() {
			nats.parseRespResultForIpPool(result)
		}, "Should panic when start IP is empty")
	})

	t.Run("Pool with empty end IP", func(t *testing.T) {
		node := &FortigateNode{}
		nats := NewFortiNats(node)
		node.nats = nats
		node.objectSet = NewFortiObjectSet(node)

		result := []dto.ForiRespResult{
			{
				Name:        "pool1",
				StartIpPool: "192.168.1.1",
				EndIpPool:   "",
			},
		}

		assert.Panics(t, func() {
			nats.parseRespResultForIpPool(result)
		}, "Should panic when end IP is empty")
	})
}

func TestGetPoolByName(t *testing.T) {
	// 创建测试数据
	result := []dto.ForiRespResult{
		{
			Name:        "pool1",
			StartIpPool: "192.168.1.1",
			EndIpPool:   "192.168.1.10",
		},
		{
			Name:        "pool2",
			StartIpPool: "10.0.0.1",
			EndIpPool:   "10.0.0.20",
		},
	}

	node := &FortigateNode{}
	nats := NewFortiNats(node)
	node.nats = nats
	node.objectSet = NewFortiObjectSet(node)

	nats.parseRespResultForIpPool(result)

	// 测试获取存在的池
	t.Run("Get existing pool", func(t *testing.T) {
		rule := nats.getPoolByName("pool1")
		assert.NotNil(t, rule, "Pool should be found")
		if rule != nil {
			assert.Equal(t, "pool1", rule.Name(), "Pool name should match")
			assert.Equal(t, firewall.DYNAMIC_NAT, rule.natType, "NAT type should match")
		}
	})

	// 测试获取不存在的池
	t.Run("Get non-existing pool", func(t *testing.T) {
		rule := nats.getPoolByName("nonexistent")
		assert.Nil(t, rule, "Pool should not be found")
	})
}

func TestPoolIterator(t *testing.T) {
	// 创建测试数据
	result := []dto.ForiRespResult{
		{
			Name:        "pool1",
			StartIpPool: "192.168.1.1",
			EndIpPool:   "192.168.1.10",
		},
		{
			Name:        "pool2",
			StartIpPool: "10.0.0.1",
			EndIpPool:   "10.0.0.20",
		},
		{
			Name:        "pool3",
			StartIpPool: "172.16.0.1",
			EndIpPool:   "172.16.0.5",
		},
	}

	node := &FortigateNode{}
	nats := NewFortiNats(node)
	node.nats = nats
	node.objectSet = NewFortiObjectSet(node)

	nats.parseRespResultForIpPool(result)

	// 测试迭代所有池
	t.Run("Iterate all pools", func(t *testing.T) {
		count := 0
		for _, rule := range nats.DynamicRules {
			assert.NotNil(t, rule, "Pool should not be nil")
			assert.NotEmpty(t, rule.Name(), "Pool name should not be empty")
			assert.Equal(t, firewall.DYNAMIC_NAT, rule.natType, "NAT type should be DYNAMIC_NAT")
			assert.NotNil(t, rule.translate, "Translate should not be nil")
			assert.NotNil(t, rule.translate.Src(), "Translate source should not be nil")
			count++
		}
		assert.Equal(t, 3, count, "Should iterate all 3 pools")
	})

	// 测试按网络组过滤
	t.Run("Filter by network group", func(t *testing.T) {
		// 创建一个网络组用于过滤
		filterNet, err := network.NewNetworkGroupFromString("192.168.1.1-192.168.1.10")
		assert.NoError(t, err, "Should create filter network group")

		matchCount := 0
		for _, rule := range nats.DynamicRules {
			poolNet := rule.translate.Src()
			if poolNet != nil && poolNet.Same(filterNet) {
				matchCount++
				assert.Equal(t, "pool1", rule.Name(), "Matched pool should be pool1")
			}
		}
		assert.Equal(t, 1, matchCount, "Should match one pool")
	})

	// 测试按网络组过滤（无匹配）
	t.Run("Filter by network group - no match", func(t *testing.T) {
		// 创建一个不匹配的网络组
		filterNet, err := network.NewNetworkGroupFromString("10.10.10.1-10.10.10.10")
		assert.NoError(t, err, "Should create filter network group")

		matchCount := 0
		for _, rule := range nats.DynamicRules {
			poolNet := rule.translate.Src()
			if poolNet != nil && poolNet.Same(filterNet) {
				matchCount++
			}
		}
		assert.Equal(t, 0, matchCount, "Should match no pools")
	})

	// 测试部分匹配
	t.Run("Filter by network group - partial match", func(t *testing.T) {
		// 创建一个部分匹配的网络组（包含在 pool1 的范围内）
		filterNet, err := network.NewNetworkGroupFromString("192.168.1.5-192.168.1.7")
		assert.NoError(t, err, "Should create filter network group")

		matchCount := 0
		for _, rule := range nats.DynamicRules {
			poolNet := rule.translate.Src()
			if poolNet != nil {
				// 检查是否有重叠
				_, mid, _ := network.NetworkGroupCmp(*poolNet, *filterNet)
				if mid != nil && !mid.IsEmpty() {
					matchCount++
				}
			}
		}
		assert.GreaterOrEqual(t, matchCount, 1, "Should match at least one pool")
	})
}

func TestGetPoolByNetworkGroup(t *testing.T) {
	// 创建测试数据
	result := []dto.ForiRespResult{
		{
			Name:        "pool1",
			StartIpPool: "192.168.1.1",
			EndIpPool:   "192.168.1.10",
		},
		{
			Name:        "pool2",
			StartIpPool: "10.0.0.1",
			EndIpPool:   "10.0.0.20",
		},
	}

	node := &FortigateNode{}
	nats := NewFortiNats(node)
	node.nats = nats
	node.objectSet = NewFortiObjectSet(node)

	nats.parseRespResultForIpPool(result)

	// 测试按网络组获取池
	t.Run("Get pool by matching network group", func(t *testing.T) {
		ng, err := network.NewNetworkGroupFromString("192.168.1.1-192.168.1.10")
		assert.NoError(t, err, "Should create network group")

		poolObj, ok := node.GetPoolByNetworkGroup(ng, firewall.DYNAMIC_NAT)
		assert.True(t, ok, "Pool should be found")
		if ok {
			assert.NotNil(t, poolObj, "Pool object should not be nil")
			assert.Equal(t, "pool1", poolObj.Name(), "Pool name should match")
			assert.Equal(t, firewall.OBJECT_POOL, poolObj.Type(), "Object type should be POOL")
		}
	})

	// 测试按网络组获取池（无匹配）
	t.Run("Get pool by non-matching network group", func(t *testing.T) {
		ng, err := network.NewNetworkGroupFromString("10.10.10.1-10.10.10.10")
		assert.NoError(t, err, "Should create network group")

		poolObj, ok := node.GetPoolByNetworkGroup(ng, firewall.DYNAMIC_NAT)
		assert.False(t, ok, "Pool should not be found")
		assert.Nil(t, poolObj, "Pool object should be nil")
	})
}

func TestPoolNetwork(t *testing.T) {
	// 测试单个 IP 地址的池
	result := []dto.ForiRespResult{
		{
			Name:        "singleippool",
			StartIpPool: "192.168.1.100",
			EndIpPool:   "192.168.1.100",
		},
	}

	node := &FortigateNode{}
	nats := NewFortiNats(node)
	node.nats = nats
	node.objectSet = NewFortiObjectSet(node)

	nats.parseRespResultForIpPool(result)

	rule := nats.getPoolByName("singleippool")
	assert.NotNil(t, rule, "Pool should be found")

	// 验证网络组
	poolNetwork := rule.translate.Src()
	assert.NotNil(t, poolNetwork, "Pool network should not be nil")

	expectedNetwork, err := network.NewNetworkGroupFromString("192.168.1.100-192.168.1.100")
	assert.NoError(t, err, "Should create expected network group")
	assert.True(t, expectedNetwork.Same(poolNetwork), "Network should match")

	// 测试 IP 范围的池
	result2 := []dto.ForiRespResult{
		{
			Name:        "rangepool",
			StartIpPool: "10.0.0.1",
			EndIpPool:   "10.0.0.10",
		},
	}

	node2 := &FortigateNode{}
	nats2 := NewFortiNats(node2)
	node2.nats = nats2
	node2.objectSet = NewFortiObjectSet(node2)

	nats2.parseRespResultForIpPool(result2)

	rule2 := nats2.getPoolByName("rangepool")
	assert.NotNil(t, rule2, "Pool should be found")

	// 验证网络组
	poolNetwork2 := rule2.translate.Src()
	assert.NotNil(t, poolNetwork2, "Pool network should not be nil")

	expectedNetwork2, err := network.NewNetworkGroupFromString("10.0.0.1-10.0.0.10")
	assert.NoError(t, err, "Should create expected network group")
	assert.True(t, expectedNetwork2.Same(poolNetwork2), "Network should match")
}

func TestPoolIteratorWithParseRespResultForIpPool(t *testing.T) {
	// 测试解析和迭代器的集成
	result := []dto.ForiRespResult{
		{
			Name:        "testpool1",
			StartIpPool: "192.168.1.1",
			EndIpPool:   "192.168.1.10",
		},
		{
			Name:        "testpool2",
			StartIpPool: "10.0.0.1",
			EndIpPool:   "10.0.0.5",
		},
	}

	node := &FortigateNode{}
	nats := NewFortiNats(node)
	node.nats = nats
	node.objectSet = NewFortiObjectSet(node)

	nats.parseRespResultForIpPool(result)

	// 验证池已正确解析
	assert.Equal(t, 2, len(nats.DynamicRules), "Should have 2 pools")

	// 使用迭代器验证池
	poolNames := make(map[string]bool)
	for _, rule := range nats.DynamicRules {
		poolNames[rule.Name()] = true
		assert.NotNil(t, rule.translate, "Translate should not be nil")
		assert.NotNil(t, rule.translate.Src(), "Translate source should not be nil")
	}

	assert.True(t, poolNames["testpool1"], "testpool1 should be found")
	assert.True(t, poolNames["testpool2"], "testpool2 should be found")
}
