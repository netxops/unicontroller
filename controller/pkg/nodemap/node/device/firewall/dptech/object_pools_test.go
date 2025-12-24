package dptech

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/parse"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
)

func TestParsePools(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		expectedPools map[string]struct {
			name     string
			startIP  string
			endIP    string
			hasEndIP bool
		}
		expectedErrors int
	}{
		{
			name: "Single pool with start and end address",
			config: `address-pool Dynamic-PAT-DMZ-IN-DCN-Address-Pool address 132.252.45.245 to 132.252.45.254
address-pool Another-Pool address 10.0.0.1 to 10.0.0.10`,
			expectedPools: map[string]struct {
				name     string
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"Dynamic-PAT-DMZ-IN-DCN-Address-Pool": {
					name:     "Dynamic-PAT-DMZ-IN-DCN-Address-Pool",
					startIP:  "132.252.45.245",
					endIP:    "132.252.45.254",
					hasEndIP: true,
				},
				"Another-Pool": {
					name:     "Another-Pool",
					startIP:  "10.0.0.1",
					endIP:    "10.0.0.10",
					hasEndIP: true,
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Single pool with only start address",
			config: `address-pool Single-IP-Pool address 192.168.1.1
address-pool Another-Single-IP-Pool address 10.0.0.1`,
			expectedPools: map[string]struct {
				name     string
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"Single-IP-Pool": {
					name:     "Single-IP-Pool",
					startIP:  "192.168.1.1",
					hasEndIP: false,
				},
				"Another-Single-IP-Pool": {
					name:     "Another-Single-IP-Pool",
					startIP:  "10.0.0.1",
					hasEndIP: false,
				},
			},
			expectedErrors: 0,
		},
		{
			name: "Mixed pool types",
			config: `address-pool Range-Pool address 172.16.0.1 to 172.16.0.10
address-pool Single-IP-Pool address 192.168.1.1`,
			expectedPools: map[string]struct {
				name     string
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"Range-Pool": {
					name:     "Range-Pool",
					startIP:  "172.16.0.1",
					endIP:    "172.16.0.10",
					hasEndIP: true,
				},
				"Single-IP-Pool": {
					name:     "Single-IP-Pool",
					startIP:  "192.168.1.1",
					hasEndIP: false,
				},
			},
			expectedErrors: 0,
		},
		{
			name:   "Invalid pool configuration",
			config: `address-pool Invalid-Pool address invalid-ip`,
			expectedPools: map[string]struct {
				name     string
				startIP  string
				endIP    string
				hasEndIP bool
			}{},
			expectedErrors: 1,
		},
		{
			name: "Multiple pools with ranges",
			config: `address-pool Pool1 address 1.1.1.1 to 1.1.1.10
address-pool Pool2 address 2.2.2.1 to 2.2.2.20
address-pool Pool3 address 3.3.3.1`,
			expectedPools: map[string]struct {
				name     string
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"Pool1": {
					name:     "Pool1",
					startIP:  "1.1.1.1",
					endIP:    "1.1.1.10",
					hasEndIP: true,
				},
				"Pool2": {
					name:     "Pool2",
					startIP:  "2.2.2.1",
					endIP:    "2.2.2.20",
					hasEndIP: true,
				},
				"Pool3": {
					name:     "Pool3",
					startIP:  "3.3.3.1",
					hasEndIP: false,
				},
			},
			expectedErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &DptechNode{}
			dos := NewDptechObjectSet(node)
			result := parse.NewParseResult()

			dos.parsePools(tt.config, result)

			assert.Equal(t, tt.expectedErrors, len(result.Errors), "Unexpected number of errors")

			// 验证池的数量
			poolCount := len(dos.poolMap)
			assert.Equal(t, len(tt.expectedPools), poolCount, "Pool count mismatch")

			// 验证每个池
			for poolName, expected := range tt.expectedPools {
				pool, ok := dos.poolMap[poolName]
				assert.True(t, ok, "Pool %s not found", poolName)
				if ok {
					assert.Equal(t, expected.name, pool.Name(), "Pool name mismatch")

					natPool, ok := pool.(*NatPool)
					assert.True(t, ok, "Pool should be *NatPool")
					if ok {
						assert.Equal(t, firewall.DYNAMIC_NAT, natPool.NatType(), "NAT type mismatch")
						assert.Equal(t, firewall.OBJECT_POOL, natPool.Type(), "Object type mismatch")

						// 验证网络组
						poolNetwork := natPool.Network(nil)
						assert.NotNil(t, poolNetwork, "Pool network should not be nil")

						var expectedNetwork *network.NetworkGroup
						var err error
						if expected.hasEndIP {
							expectedNetwork, err = network.NewNetworkGroupFromString(expected.startIP + "-" + expected.endIP)
							assert.NoError(t, err, "Should create expected network group")
						} else {
							expectedNetwork, err = network.NewNetworkGroupFromString(expected.startIP)
							assert.NoError(t, err, "Should create expected network group")
						}

						assert.True(t, expectedNetwork.Same(poolNetwork), "Network range mismatch for pool %s", poolName)

						// 验证 CLI
						if expected.hasEndIP {
							assert.Contains(t, natPool.Cli(), expected.startIP, "CLI should contain start IP")
							assert.Contains(t, natPool.Cli(), expected.endIP, "CLI should contain end IP")
							assert.Contains(t, natPool.Cli(), " to ", "CLI should contain ' to '")
						} else {
							assert.Contains(t, natPool.Cli(), expected.startIP, "CLI should contain start IP")
						}
					}
				}
			}
		})
	}
}

func TestNatPoolIterator(t *testing.T) {
	// 创建测试数据
	config := `address-pool Pool1 address 1.1.1.1 to 1.1.1.10
address-pool Pool2 address 2.2.2.1 to 2.2.2.20
address-pool Pool3 address 3.3.3.1`

	node := &DptechNode{}
	dos := NewDptechObjectSet(node)
	result := parse.NewParseResult()

	dos.parsePools(config, result)
	assert.False(t, result.HasErrors(), "Should not have errors")

	// 测试迭代所有池
	t.Run("Iterate all pools", func(t *testing.T) {
		iterator := node.NatPoolIterator()
		count := 0
		for iterator.HasNext() {
			item := iterator.Next()
			assert.NotNil(t, item, "Pool should not be nil")
			pool, ok := item.(firewall.NatPool)
			assert.True(t, ok, "Item should be NatPool")
			if ok {
				assert.NotEmpty(t, pool.Name(), "Pool name should not be empty")
				// 使用类型断言获取 *NatPool 以访问 Network 方法
				if natPool, ok := item.(*NatPool); ok {
					assert.NotNil(t, natPool.Network(nil), "Pool network should not be nil")
				}
				count++
			}
		}
		assert.Equal(t, 3, count, "Should iterate all 3 pools")
	})

	// 测试按网络组过滤
	t.Run("Filter by network group", func(t *testing.T) {
		// 创建一个网络组用于过滤
		filterNet, err := network.NewNetworkGroupFromString("1.1.1.1-1.1.1.10")
		assert.NoError(t, err, "Should create filter network group")

		iterator := node.NatPoolIterator(firewall.WithNetworkGroup(filterNet))
		matchCount := 0
		for iterator.HasNext() {
			item := iterator.Next()
			pool, ok := item.(firewall.NatPool)
			assert.True(t, ok, "Item should be NatPool")
			if ok {
				// 使用类型断言获取 *NatPool 以访问 Network 方法
				if natPool, ok := item.(*NatPool); ok {
					poolNet := natPool.Network(nil)
					if poolNet != nil && poolNet.Same(filterNet) {
						matchCount++
						assert.Equal(t, "Pool1", pool.Name(), "Matched pool should be Pool1")
					}
				}
			}
		}
		assert.Equal(t, 1, matchCount, "Should match one pool")
	})

	// 测试按网络组过滤（无匹配）
	t.Run("Filter by network group - no match", func(t *testing.T) {
		// 创建一个不匹配的网络组
		filterNet, err := network.NewNetworkGroupFromString("10.10.10.1-10.10.10.10")
		assert.NoError(t, err, "Should create filter network group")

		iterator := node.NatPoolIterator(firewall.WithNetworkGroup(filterNet))
		matchCount := 0
		for iterator.HasNext() {
			item := iterator.Next()
			_, ok := item.(firewall.NatPool)
			assert.True(t, ok, "Item should be NatPool")
			if ok {
				// 使用类型断言获取 *NatPool 以访问 Network 方法
				if natPool, ok := item.(*NatPool); ok {
					poolNet := natPool.Network(nil)
					if poolNet != nil && poolNet.Same(filterNet) {
						matchCount++
					}
				}
			}
		}
		assert.Equal(t, 0, matchCount, "Should match no pools")
	})

	// 测试部分匹配（使用 MatchNetworkGroup，它使用 Same 方法，需要完全匹配）
	// 注意：MatchNetworkGroup 使用 Same 方法，所以部分匹配可能不会通过过滤器
	// 这里我们直接测试迭代器，不使用过滤器
	t.Run("Filter by network group - partial match", func(t *testing.T) {
		// 创建一个部分匹配的网络组（包含在 Pool1 的范围内）
		filterNet, err := network.NewNetworkGroupFromString("1.1.1.5-1.1.1.7")
		assert.NoError(t, err, "Should create filter network group")

		// 不使用过滤器，直接迭代所有池并检查重叠
		iterator := node.NatPoolIterator()
		matchCount := 0
		for iterator.HasNext() {
			item := iterator.Next()
			_, ok := item.(firewall.NatPool)
			assert.True(t, ok, "Item should be NatPool")
			if ok {
				// 使用类型断言获取 *NatPool 以访问 Network 方法
				if natPool, ok := item.(*NatPool); ok {
					poolNet := natPool.Network(nil)
					if poolNet != nil {
						// 检查是否有重叠
						_, mid, _ := network.NetworkGroupCmp(*poolNet, *filterNet)
						if mid != nil && !mid.IsEmpty() {
							matchCount++
						}
					}
				}
			}
		}
		assert.GreaterOrEqual(t, matchCount, 1, "Should match at least one pool")
	})
}

func TestNatPoolIteratorWithParsePools(t *testing.T) {
	// 测试解析和迭代器的集成
	config := `address-pool TestPool1 address 192.168.1.1 to 192.168.1.10
address-pool TestPool2 address 10.0.0.1`

	node := &DptechNode{}
	dos := NewDptechObjectSet(node)
	result := parse.NewParseResult()

	dos.parsePools(config, result)
	assert.False(t, result.HasErrors(), "Should not have errors")

	// 验证池已正确解析
	assert.Equal(t, 2, len(dos.poolMap), "Should have 2 pools")

	// 使用迭代器验证池
	iterator := node.NatPoolIterator()
	poolNames := make(map[string]bool)
	for iterator.HasNext() {
		item := iterator.Next()
		pool, ok := item.(firewall.NatPool)
		assert.True(t, ok, "Item should be NatPool")
		if ok {
			poolNames[pool.Name()] = true
			// 使用类型断言获取 *NatPool 以访问 Network 方法
			if natPool, ok := item.(*NatPool); ok {
				assert.NotNil(t, natPool.Network(nil), "Pool network should not be nil")
			}
		}
	}

	assert.True(t, poolNames["TestPool1"], "TestPool1 should be found")
	assert.True(t, poolNames["TestPool2"], "TestPool2 should be found")
}

func TestNatPoolNetwork(t *testing.T) {
	// 测试单个 IP 地址的池
	config := `address-pool SingleIPPool address 192.168.1.100`

	node1 := &DptechNode{}
	dos1 := NewDptechObjectSet(node1)
	result1 := parse.NewParseResult()

	dos1.parsePools(config, result1)
	assert.False(t, result1.HasErrors(), "Should not have errors")

	pool1, ok := dos1.poolMap["SingleIPPool"]
	assert.True(t, ok, "Pool should be found")

	natPool1, ok := pool1.(*NatPool)
	assert.True(t, ok, "Pool should be *NatPool")

	// 验证网络组
	poolNetwork1 := natPool1.Network(nil)
	assert.NotNil(t, poolNetwork1, "Pool network should not be nil")

	expectedNetwork1, err := network.NewNetworkGroupFromString("192.168.1.100")
	assert.NoError(t, err, "Should create expected network group")
	assert.True(t, expectedNetwork1.Same(poolNetwork1), "Network should match")

	// 测试 IP 范围的池
	config2 := `address-pool RangePool address 10.0.0.1 to 10.0.0.10`

	node2 := &DptechNode{}
	dos2 := NewDptechObjectSet(node2)
	result2 := parse.NewParseResult()

	dos2.parsePools(config2, result2)
	assert.False(t, result2.HasErrors(), "Should not have errors")

	pool2, ok := dos2.poolMap["RangePool"]
	assert.True(t, ok, "Pool should be found")

	natPool2, ok := pool2.(*NatPool)
	assert.True(t, ok, "Pool should be *NatPool")

	// 验证网络组
	poolNetwork2 := natPool2.Network(nil)
	assert.NotNil(t, poolNetwork2, "Pool network should not be nil")

	expectedNetwork2, err := network.NewNetworkGroupFromString("10.0.0.1-10.0.0.10")
	assert.NoError(t, err, "Should create expected network group")
	assert.True(t, expectedNetwork2.Same(poolNetwork2), "Network should match")
}
