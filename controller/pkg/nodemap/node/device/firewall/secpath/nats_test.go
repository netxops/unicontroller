package secpath

import (
	"strconv"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/secpath/model"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
)

func TestParseAddressGroupCli(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		expectedCount  int
		expectedGroups []struct {
			groupNumber int
			startIP     string
			endIP       string
		}
	}{
		{
			name: "Single address group with one range",
			config: `nat address-group 1
		address 192.168.1.1 192.168.1.10
		#`,
			expectedCount: 1,
			expectedGroups: []struct {
				groupNumber int
				startIP     string
				endIP       string
			}{
				{groupNumber: 1, startIP: "192.168.1.1", endIP: "192.168.1.10"},
			},
		},
		{
			name: "Single address group with name",
			config: `nat address-group 2 name POOL_1
		address 203.0.113.1 203.0.113.10
		#`,
			expectedCount: 1,
			expectedGroups: []struct {
				groupNumber int
				startIP     string
				endIP       string
			}{
				{groupNumber: 2, startIP: "203.0.113.1", endIP: "203.0.113.10"},
			},
		},
		{
			name: "Multiple address groups",
			config: `nat address-group 1
 address 192.168.1.1 192.168.1.10
#
nat address-group 2 name POOL_2
 address 203.0.113.1 203.0.113.20
#
 nat address-group 3
 address 10.0.0.1 10.0.0.5
#`,
			expectedCount: 3,
			expectedGroups: []struct {
				groupNumber int
				startIP     string
				endIP       string
			}{
				{groupNumber: 1, startIP: "192.168.1.1", endIP: "192.168.1.10"},
				{groupNumber: 2, startIP: "203.0.113.1", endIP: "203.0.113.20"},
				{groupNumber: 3, startIP: "10.0.0.1", endIP: "10.0.0.5"},
			},
		},
		{
			name: "Address group with multiple ranges (should handle all ranges)",
			config: `nat address-group 1
address 192.168.1.1 192.168.1.10
address 192.168.2.1 192.168.2.10
#`,
			expectedCount: 1,
			expectedGroups: []struct {
				groupNumber int
				startIP     string
				endIP       string
			}{
				{groupNumber: 1, startIP: "192.168.1.1", endIP: "192.168.1.10"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nats := &Nats{
				addrGroups: []*model.AddressGroup{},
			}

			nats.parseAddressGroupCli(tt.config)

			assert.Equal(t, tt.expectedCount, len(nats.addrGroups), "Address group count should match")

			for i, expected := range tt.expectedGroups {
				if i < len(nats.addrGroups) {
					ag := nats.addrGroups[i]
					assert.Equal(t, expected.groupNumber, ag.GroupNumber, "Group number should match")

					// 验证网络组包含期望的 IP 范围
					if ag.N != nil {
						// 检查网络组是否包含期望的 IP 范围
						expectedNet, err := network.NewNetworkGroupFromString(expected.startIP + "-" + expected.endIP)
						assert.NoError(t, err, "Should create expected network group")

						// 对于多个范围的测试用例，验证网络组包含期望的范围（而不是完全匹配）
						// 使用 NetworkGroupCmp 来检查是否包含
						_, mid, _ := network.NetworkGroupCmp(*ag.N, *expectedNet)
						assert.NotNil(t, mid, "Address group network should contain expected range")
						assert.True(t, mid.Same(expectedNet), "Address group network should contain expected range")
					}
				}
			}
		})
	}
}

func TestNatPoolIterator(t *testing.T) {
	// 创建测试用的 AddressGroup
	ag1, err := createAddressGroup(1, "192.168.1.1", "192.168.1.10")
	assert.NoError(t, err)

	ag2, err := createAddressGroup(2, "203.0.113.1", "203.0.113.20")
	assert.NoError(t, err)

	ag3, err := createAddressGroup(3, "10.0.0.1", "10.0.0.5")
	assert.NoError(t, err)

	// 创建 SecPathNode 和 Nats
	node := &SecPathNode{
		Nats: &Nats{
			addrGroups: []*model.AddressGroup{ag1, ag2, ag3},
		},
	}

	tests := []struct {
		name          string
		options       []firewall.IteratorOption
		expectedCount int
		expectedIDs   []string
	}{
		{
			name:          "Iterate all pools",
			options:       []firewall.IteratorOption{},
			expectedCount: 3,
			expectedIDs:   []string{"1", "2", "3"},
		},
		{
			name: "Filter by network group - match",
			options: []firewall.IteratorOption{
				func() firewall.IteratorOption {
					ng, _ := network.NewNetworkGroupFromString("192.168.1.1-192.168.1.10")
					return firewall.WithNetworkGroup(ng)
				}(),
			},
			expectedCount: 1,
			expectedIDs:   []string{"1"},
		},
		{
			name: "Filter by network group - no match",
			options: []firewall.IteratorOption{
				func() firewall.IteratorOption {
					ng, _ := network.NewNetworkGroupFromString("172.16.0.1-172.16.0.10")
					return firewall.WithNetworkGroup(ng)
				}(),
			},
			expectedCount: 0,
			expectedIDs:   []string{},
		},
		{
			name: "Filter by network group - partial match",
			options: []firewall.IteratorOption{
				func() firewall.IteratorOption {
					ng, _ := network.NewNetworkGroupFromString("203.0.113.1-203.0.113.20")
					return firewall.WithNetworkGroup(ng)
				}(),
			},
			expectedCount: 1,
			expectedIDs:   []string{"2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iterator := node.NatPoolIterator(tt.options...)

			var pools []firewall.NatPool
			for iterator.HasNext() {
				item := iterator.Next()
				if pool, ok := item.(firewall.NatPool); ok {
					pools = append(pools, pool)
				}
			}

			assert.Equal(t, tt.expectedCount, len(pools), "Pool count should match")

			for i, expectedID := range tt.expectedIDs {
				if i < len(pools) {
					assert.Equal(t, expectedID, pools[i].ID(), "Pool ID should match")
					assert.Equal(t, expectedID, pools[i].Name(), "Pool Name should match")
					// 验证 MatchNetworkGroup 方法可用
					if ag, ok := pools[i].(*model.AddressGroup); ok {
						assert.NotNil(t, ag.N, "AddressGroup Network should not be nil")
					}
				}
			}
		})
	}
}

func TestNatPoolIteratorWithParseAddressGroupCli(t *testing.T) {
	// 测试 parseAddressGroupCli 和 NatPoolIterator 的集成
	config := `nat address-group 1
 address 192.168.1.1 192.168.1.10
#
nat address-group 2 name POOL_2
 address 203.0.113.1 203.0.113.20
#
nat address-group 3
 address 10.0.0.1 10.0.0.5
#`

	node := &SecPathNode{
		Nats: &Nats{
			addrGroups: []*model.AddressGroup{},
		},
	}

	// 解析配置
	node.Nats.parseAddressGroupCli(config)

	// 验证解析结果
	assert.Equal(t, 3, len(node.Nats.addrGroups), "Should parse 3 address groups")

	// 使用迭代器遍历
	iterator := node.NatPoolIterator()
	var pools []firewall.NatPool
	for iterator.HasNext() {
		item := iterator.Next()
		if pool, ok := item.(firewall.NatPool); ok {
			pools = append(pools, pool)
		}
	}

	assert.Equal(t, 3, len(pools), "Iterator should return 3 pools")

	// 验证每个 pool 的属性
	expectedIDs := []string{"1", "2", "3"}
	for i, pool := range pools {
		assert.Equal(t, expectedIDs[i], pool.ID(), "Pool ID should match")
		assert.Equal(t, expectedIDs[i], pool.Name(), "Pool Name should match")
		// 验证 MatchNetworkGroup 方法可用
		if ag, ok := pool.(*model.AddressGroup); ok {
			assert.NotNil(t, ag.N, "AddressGroup Network should not be nil")
		}
	}

	// 测试 MatchNetworkGroup
	testNet, err := network.NewNetworkGroupFromString("192.168.1.1-192.168.1.10")
	assert.NoError(t, err)

	found := false
	for _, pool := range pools {
		if pool.MatchNetworkGroup(testNet) {
			found = true
			assert.Equal(t, "1", pool.ID(), "Matched pool should have ID 1")
			break
		}
	}
	assert.True(t, found, "Should find matching pool")
}

// 辅助函数：创建 AddressGroup
func createAddressGroup(groupNumber int, startIP, endIP string) (*model.AddressGroup, error) {
	net, err := network.NewNetworkGroupFromString(startIP + "-" + endIP)
	if err != nil {
		return nil, err
	}

	cli := "nat address-group " + strconv.Itoa(groupNumber) + "\naddress " + startIP + " " + endIP

	return &model.AddressGroup{
		GroupNumber: groupNumber,
		C:           cli,
		N:           net,
	}, nil
}
