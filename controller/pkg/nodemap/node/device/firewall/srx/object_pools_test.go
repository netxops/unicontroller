package srx

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
)

func TestParsePools(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		expectedPools map[string]struct {
			name     string
			natType  firewall.NatType
			startIP  string
			endIP    string
			hasEndIP bool
		}
	}{
		{
			name:   "Single source pool with address",
			config: `set security nat source pool pool1 address 192.168.1.1`,
			expectedPools: map[string]struct {
				name     string
				natType  firewall.NatType
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"pool1": {
					name:     "pool1",
					natType:  firewall.DYNAMIC_NAT,
					startIP:  "192.168.1.1",
					hasEndIP: false,
				},
			},
		},
		{
			name:   "Single destination pool with address range",
			config: `set security nat destination pool pool2 address 10.0.0.1 to 10.0.0.10`,
			expectedPools: map[string]struct {
				name     string
				natType  firewall.NatType
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"pool2": {
					name:     "pool2",
					natType:  firewall.DESTINATION_NAT,
					startIP:  "10.0.0.1",
					endIP:    "10.0.0.10",
					hasEndIP: true,
				},
			},
		},
		{
			name: "Multiple pools with different types",
			config: `set security nat source pool pool1 address 192.168.1.1
set security nat destination pool pool2 address 10.0.0.1 to 10.0.0.10
set security nat source pool pool3 address 172.16.0.1`,
			expectedPools: map[string]struct {
				name     string
				natType  firewall.NatType
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"pool1": {
					name:     "pool1",
					natType:  firewall.DYNAMIC_NAT,
					startIP:  "192.168.1.1",
					hasEndIP: false,
				},
				"pool2": {
					name:     "pool2",
					natType:  firewall.DESTINATION_NAT,
					startIP:  "10.0.0.1",
					endIP:    "10.0.0.10",
					hasEndIP: true,
				},
				"pool3": {
					name:     "pool3",
					natType:  firewall.DYNAMIC_NAT,
					startIP:  "172.16.0.1",
					hasEndIP: false,
				},
			},
		},
		{
			name: "Pool with port range",
			config: `set security nat source pool pool1 address 192.168.1.1
set security nat source pool pool1 port range 1000
set security nat source pool pool1 port range to 2000`,
			expectedPools: map[string]struct {
				name     string
				natType  firewall.NatType
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"pool1": {
					name:     "pool1",
					natType:  firewall.DYNAMIC_NAT,
					startIP:  "192.168.1.1",
					hasEndIP: false,
				},
			},
		},
		{
			name:   "Pool with address and CIDR",
			config: `set security nat source pool pool1 address 192.168.1.1/24`,
			expectedPools: map[string]struct {
				name     string
				natType  firewall.NatType
				startIP  string
				endIP    string
				hasEndIP bool
			}{
				"pool1": {
					name:     "pool1",
					natType:  firewall.DYNAMIC_NAT,
					startIP:  "192.168.1.1/24", // parsePool 会保留CIDR前缀
					hasEndIP: false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &SRXNode{}
			srx := NewSRXObjectSet(node)

			srx.parsePools(tt.config)

			// 验证池的数量
			totalPools := 0
			for _, poolMap := range srx.poolMap {
				totalPools += len(poolMap)
			}
			assert.Equal(t, len(tt.expectedPools), totalPools, "Pool count mismatch")

			// 验证每个池
			for poolName, expected := range tt.expectedPools {
				poolMap, ok := srx.poolMap[expected.natType]
				assert.True(t, ok, "Pool map for NAT type %v should exist", expected.natType)

				pool, ok := poolMap[poolName]
				assert.True(t, ok, "Pool %s not found", poolName)
				if ok {
					assert.Equal(t, expected.name, pool.Name(), "Pool name mismatch")

					natPool, ok := pool.(*NatPool)
					assert.True(t, ok, "Pool should be *NatPool")
					if ok {
						assert.Equal(t, expected.natType, natPool.NatType(), "NAT type mismatch")
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
					}
				}
			}
		})
	}
}

func TestNatPoolIterator(t *testing.T) {
	// 创建测试数据
	config := `set security nat source pool pool1 address 1.1.1.1 to 1.1.1.10
set security nat destination pool pool2 address 2.2.2.1 to 2.2.2.20
set security nat source pool pool3 address 3.3.3.1`

	node := &SRXNode{}
	srx := NewSRXObjectSet(node)

	srx.parsePools(config)

	// 测试迭代所有池
	t.Run("Iterate all pools", func(t *testing.T) {
		// 手动迭代所有池
		totalPools := 0
		for _, poolMap := range srx.poolMap {
			for _, pool := range poolMap {
				assert.NotNil(t, pool, "Pool should not be nil")
				natPool, ok := pool.(*NatPool)
				assert.True(t, ok, "Pool should be *NatPool")
				if ok {
					assert.NotEmpty(t, natPool.Name(), "Pool name should not be empty")
					assert.NotNil(t, natPool.Network(nil), "Pool network should not be nil")
					totalPools++
				}
			}
		}
		assert.Equal(t, 3, totalPools, "Should iterate all 3 pools")
	})

	// 测试按 NAT 类型过滤
	t.Run("Filter by NAT type", func(t *testing.T) {
		// 测试 DYNAMIC_NAT 类型的池
		poolMap, ok := srx.poolMap[firewall.DYNAMIC_NAT]
		assert.True(t, ok, "Pool map for DYNAMIC_NAT should exist")
		assert.Equal(t, 2, len(poolMap), "Should have 2 DYNAMIC_NAT pools")

		// 测试 DESTINATION_NAT 类型的池
		poolMap2, ok := srx.poolMap[firewall.DESTINATION_NAT]
		assert.True(t, ok, "Pool map for DESTINATION_NAT should exist")
		assert.Equal(t, 1, len(poolMap2), "Should have 1 DESTINATION_NAT pool")
	})

	// 测试按网络组匹配
	t.Run("Filter by network group", func(t *testing.T) {
		// 创建一个网络组用于匹配
		filterNet, err := network.NewNetworkGroupFromString("1.1.1.1-1.1.1.10")
		assert.NoError(t, err, "Should create filter network group")

		matchCount := 0
		for _, poolMap := range srx.poolMap {
			for _, pool := range poolMap {
				natPool, ok := pool.(*NatPool)
				if ok {
					poolNet := natPool.Network(nil)
					if poolNet != nil && poolNet.Same(filterNet) {
						matchCount++
						assert.Equal(t, "pool1", natPool.Name(), "Matched pool should be pool1")
					}
				}
			}
		}
		assert.Equal(t, 1, matchCount, "Should match one pool")
	})

	// 测试按网络组匹配（无匹配）
	t.Run("Filter by network group - no match", func(t *testing.T) {
		// 创建一个不匹配的网络组
		filterNet, err := network.NewNetworkGroupFromString("10.10.10.1-10.10.10.10")
		assert.NoError(t, err, "Should create filter network group")

		matchCount := 0
		for _, poolMap := range srx.poolMap {
			for _, pool := range poolMap {
				natPool, ok := pool.(*NatPool)
				if ok {
					poolNet := natPool.Network(nil)
					if poolNet != nil && poolNet.Same(filterNet) {
						matchCount++
					}
				}
			}
		}
		assert.Equal(t, 0, matchCount, "Should match no pools")
	})
}

func TestNatPoolIteratorWithParsePools(t *testing.T) {
	// 测试解析和迭代器的集成
	config := `set security nat source pool testpool1 address 192.168.1.1 to 192.168.1.10
set security nat destination pool testpool2 address 10.0.0.1`

	node := &SRXNode{}
	srx := NewSRXObjectSet(node)

	srx.parsePools(config)

	// 验证池已正确解析
	totalPools := 0
	for _, poolMap := range srx.poolMap {
		totalPools += len(poolMap)
	}
	assert.Equal(t, 2, totalPools, "Should have 2 pools")

	// 使用迭代器验证池
	poolNames := make(map[string]bool)
	for _, poolMap := range srx.poolMap {
		for _, pool := range poolMap {
			natPool, ok := pool.(*NatPool)
			assert.True(t, ok, "Pool should be *NatPool")
			if ok {
				poolNames[natPool.Name()] = true
				assert.NotNil(t, natPool.Network(nil), "Pool network should not be nil")
			}
		}
	}

	assert.True(t, poolNames["testpool1"], "testpool1 should be found")
	assert.True(t, poolNames["testpool2"], "testpool2 should be found")
}

func TestNatPoolNetwork(t *testing.T) {
	// 测试单个 IP 地址的池
	config := `set security nat source pool singleippool address 192.168.1.100`

	node := &SRXNode{}
	srx := NewSRXObjectSet(node)

	srx.parsePools(config)

	poolMap, ok := srx.poolMap[firewall.DYNAMIC_NAT]
	assert.True(t, ok, "Pool map should exist")

	pool, ok := poolMap["singleippool"]
	assert.True(t, ok, "Pool should be found")

	natPool, ok := pool.(*NatPool)
	assert.True(t, ok, "Pool should be *NatPool")

	// 验证网络组
	poolNetwork := natPool.Network(nil)
	assert.NotNil(t, poolNetwork, "Pool network should not be nil")

	expectedNetwork, err := network.NewNetworkGroupFromString("192.168.1.100")
	assert.NoError(t, err, "Should create expected network group")
	assert.True(t, expectedNetwork.Same(poolNetwork), "Network should match")

	// 测试 IP 范围的池
	config2 := `set security nat destination pool rangepool address 10.0.0.1 to 10.0.0.10`

	node2 := &SRXNode{}
	srx2 := NewSRXObjectSet(node2)

	srx2.parsePools(config2)

	poolMap2, ok := srx2.poolMap[firewall.DESTINATION_NAT]
	assert.True(t, ok, "Pool map should exist")

	pool2, ok := poolMap2["rangepool"]
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
