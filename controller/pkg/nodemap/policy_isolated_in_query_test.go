package nodemap

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/stretchr/testify/assert"
)

// mockPolicy 用于测试的 mock 策略
type mockPolicy struct {
	name        string
	policyEntry *policy.PolicyEntry
}

func (m *mockPolicy) Name() string {
	return m.name
}

func (m *mockPolicy) Description() string {
	return ""
}

func (m *mockPolicy) ID() string {
	return ""
}

func (m *mockPolicy) Cli() string {
	return ""
}

func (m *mockPolicy) Action() firewall.Action {
	return firewall.POLICY_PERMIT
}

func (m *mockPolicy) Status() firewall.PolicyStatus {
	return firewall.POLICY_ACTIVE
}

func (m *mockPolicy) PolicyEntry() policy.PolicyEntryInf {
	return m.policyEntry
}

func (m *mockPolicy) FromZones() []string {
	return []string{}
}

func (m *mockPolicy) ToZones() []string {
	return []string{}
}

func (m *mockPolicy) Extended() map[string]interface{} {
	return make(map[string]interface{})
}

func (m *mockPolicy) FromPorts() []api.Port {
	return []api.Port{}
}

func (m *mockPolicy) ToPorts() []api.Port {
	return []api.Port{}
}

func (m *mockPolicy) GetSourceAddressObject() (firewall.FirewallNetworkObject, bool) {
	return nil, false
}

func (m *mockPolicy) GetDestinationAddressObject() (firewall.FirewallNetworkObject, bool) {
	return nil, false
}

func (m *mockPolicy) GetServiceObject() (firewall.FirewallServiceObject, bool) {
	return nil, false
}

// createMockPolicy 创建包含多个孤立地址的 mock 策略
func createMockPolicy(name string, isolatedAddresses ...string) *mockPolicy {
	policyAddr := network.NewNetworkGroup()
	for _, addr := range isolatedAddresses {
		if addr != "" {
			ng, err := network.NewNetworkGroupFromString(addr)
			if err == nil {
				policyAddr.AddGroup(ng)
			}
		}
	}

	entry := policy.NewPolicyEntry()
	entry.SetSrc(policyAddr)
	entry.SetDst(network.NewNetworkGroup())

	return &mockPolicy{
		name:        name,
		policyEntry: entry,
	}
}

// TestAddressMatcher_StrategyIsolatedInQuery 测试孤立地址在查询范围内匹配策略
func TestAddressMatcher_StrategyIsolatedInQuery(t *testing.T) {
	tests := []struct {
		name            string
		queryAddress    string   // 查询地址
		policyAddresses []string // 策略中的孤立地址列表
		isSource        bool     // 是否匹配源地址
		expectedMatch   bool     // 期望是否匹配
		expectedCount   int64    // 期望匹配的孤立地址数量
		description     string   // 测试描述
	}{
		{
			name:            "部分孤立地址在查询范围内_IPv4",
			queryAddress:    "10.0.0.0/8",
			policyAddresses: []string{"10.1.0.0/24", "10.2.0.0/24", "192.168.1.0/24"},
			isSource:        true,
			expectedMatch:   true,
			expectedCount:   512, // 10.1.0.0/24 和 10.2.0.0/24 都在查询范围内，每个 /24 有 256 个地址
			description:     "策略包含 3 个孤立地址，其中 2 个在查询范围内，应该匹配",
		},
		{
			name:            "部分孤立地址在查询范围内_IPv4",
			queryAddress:    "10.1.0.0/25",
			policyAddresses: []string{"10.1.0.0/24", "10.2.0.0/24", "192.168.1.0/24"},
			isSource:        true,
			expectedMatch:   false,
			expectedCount:   0,
			description:     "策略包含 2 个孤立地址，其中 0 个在查询范围内",
		},
		{
			name:            "部分孤立地址在查询范围内_IPv4",
			queryAddress:    "10.3.0.0/25",
			policyAddresses: []string{"10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/25", "192.168.1.0/24"},
			isSource:        true,
			expectedMatch:   true,
			expectedCount:   128,
			description:     "策略包含 3 个孤立地址，其中 1 个在查询范围内",
		},
		{
			name:            "全部孤立地址在查询范围内_IPv4",
			queryAddress:    "10.0.0.0/8",
			policyAddresses: []string{"10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"},
			isSource:        true,
			expectedMatch:   true,
			expectedCount:   768, // 所有 3 个孤立地址都在查询范围内
			description:     "策略包含 3 个孤立地址，全部在查询范围内，应该匹配",
		},
		{
			name:            "无孤立地址在查询范围内_IPv4",
			queryAddress:    "172.16.0.0/16",
			policyAddresses: []string{"10.1.0.0/24", "10.2.0.0/24", "192.168.1.0/24"},
			isSource:        true,
			expectedMatch:   false,
			expectedCount:   0,
			description:     "策略包含 3 个孤立地址，都不在查询范围内，不应该匹配",
		},
		{
			name:            "单个孤立地址在查询范围内_IPv4",
			queryAddress:    "192.168.0.0/16",
			policyAddresses: []string{"10.1.0.0/24", "192.168.1.0/24", "172.16.0.0/24"},
			isSource:        true,
			expectedMatch:   true,
			expectedCount:   256, // 只有 192.168.1.0/24 在查询范围内
			description:     "策略包含 3 个孤立地址，只有 1 个在查询范围内，应该匹配",
		},
		{
			name:            "匹配目标地址_IPv4",
			queryAddress:    "10.0.0.0/8",
			policyAddresses: []string{"10.1.0.0/24", "10.2.0.0/24"},
			isSource:        false, // 匹配目标地址
			expectedMatch:   true,
			expectedCount:   512,
			description:     "匹配策略的目标地址，孤立地址在查询范围内，应该匹配",
		},
		{
			name:            "查询地址包含单个IP_IPv4",
			queryAddress:    "10.1.0.0/24",
			policyAddresses: []string{"10.1.0.1/32", "10.1.0.2/32", "10.2.0.1/32"},
			isSource:        true,
			expectedMatch:   true,
			expectedCount:   2, // 10.1.0.1/32 和 10.1.0.2/32 在查询范围内
			description:     "查询地址是 /24，策略包含单个 IP 地址，部分在查询范围内，应该匹配",
		},
		{
			name:            "策略地址为空_IPv4",
			queryAddress:    "10.0.0.0/8",
			policyAddresses: []string{},
			isSource:        true,
			expectedMatch:   false,
			expectedCount:   0,
			description:     "策略地址为空，不应该匹配",
		},
		{
			name:            "查询地址为Any_IPv4",
			queryAddress:    "0.0.0.0/0",
			policyAddresses: []string{"10.1.0.0/24", "192.168.1.0/24"},
			isSource:        true,
			expectedMatch:   true,
			expectedCount:   512, // 所有地址都在 Any 范围内
			description:     "查询地址为 Any，所有孤立地址都应该匹配",
		},
		{
			name:            "策略地址为Any_IPv4",
			queryAddress:    "10.1.0.0/24",
			policyAddresses: []string{"0.0.0.0/0"},
			isSource:        true,
			expectedMatch:   false, // Any 地址不应该被当作孤立地址匹配
			expectedCount:   0,
			description:     "策略地址为 Any，不应该匹配（Any 不是孤立地址）",
		},
		{
			name:            "部分重叠但不完全包含_IPv4",
			queryAddress:    "10.1.0.0/25",             // 10.1.0.0-10.1.0.127
			policyAddresses: []string{"10.1.0.128/25"}, // 10.1.0.128-10.1.0.255
			isSource:        true,
			expectedMatch:   false, // 不完全包含，不应该匹配
			expectedCount:   0,
			description:     "查询地址和策略地址部分重叠但不完全包含，不应该匹配",
		},
		{
			name:            "完全包含单个孤立地址_IPv4",
			queryAddress:    "10.0.0.0/8",
			policyAddresses: []string{"10.1.0.0/24"},
			isSource:        true,
			expectedMatch:   true,
			expectedCount:   256,
			description:     "查询地址完全包含单个孤立地址，应该匹配",
		},
		{
			name:            "多个孤立地址部分匹配_IPv4",
			queryAddress:    "10.1.0.0/24",
			policyAddresses: []string{"10.1.0.0/25", "10.1.0.128/25", "10.2.0.0/24"},
			isSource:        true,
			expectedMatch:   true,
			// 注意：10.1.0.0/25 和 10.1.0.128/25 会被 DataRange() 合并成 10.1.0.0/24
			// 所以实际匹配的是合并后的 10.1.0.0/24（256个地址），而不是两个独立的 /25（256个地址）
			expectedCount: 256,
			description:   "查询地址包含策略中的多个孤立地址（合并后），应该匹配",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建查询地址的 NetworkGroup
			queryNG, err := network.NewNetworkGroupFromString(tt.queryAddress)
			if err != nil {
				t.Fatalf("Failed to create query address: %v", err)
			}

			// 创建 AddressMatcher
			matcher := &AddressMatcher{
				Address:   queryNG,
				Strategy:  StrategyIsolatedInQuery,
				IsSource:  tt.isSource,
				Threshold: 0.0,
			}

			// 创建包含多个孤立地址的策略
			policy := createMockPolicy("test-policy", tt.policyAddresses...)
			if !tt.isSource {
				// 如果匹配目标地址，需要设置目标地址
				policyAddr := network.NewNetworkGroup()
				for _, addr := range tt.policyAddresses {
					if addr != "" {
						ng, err := network.NewNetworkGroupFromString(addr)
						if err == nil {
							policyAddr.AddGroup(ng)
						}
					}
				}
				policy.policyEntry.SetDst(policyAddr)
				policy.policyEntry.SetSrc(network.NewNetworkGroup())
			}

			// 执行匹配
			result := matcher.Match(policy)

			// 验证结果
			assert.Equal(t, tt.expectedMatch, result.Matched, "Match result mismatch: %s", tt.description)
			if tt.expectedMatch {
				assert.NotNil(t, result.MatchedAddress, "MatchedAddress should not be nil when matched")
				actualCount := result.MatchedAddress.IPv4().Count().Int64() + result.MatchedAddress.IPv6().Count().Int64()
				assert.Equal(t, tt.expectedCount, actualCount, "Matched address count mismatch: %s", tt.description)
				if tt.isSource {
					assert.Equal(t, MatchSource, result.MatchType, "MatchType should be MatchSource")
				} else {
					assert.Equal(t, MatchDestination, result.MatchType, "MatchType should be MatchDestination")
				}
			} else {
				if result.MatchedAddress != nil {
					actualCount := result.MatchedAddress.IPv4().Count().Int64() + result.MatchedAddress.IPv6().Count().Int64()
					assert.Equal(t, int64(0), actualCount, "MatchedAddress should be empty when not matched")
				}
			}
		})
	}
}

// TestAddressMatcher_StrategyIsolatedInQuery_EdgeCases 测试边界情况
func TestAddressMatcher_StrategyIsolatedInQuery_EdgeCases(t *testing.T) {
	t.Run("策略地址为nil", func(t *testing.T) {
		queryNG, _ := network.NewNetworkGroupFromString("10.0.0.0/8")
		matcher := &AddressMatcher{
			Address:  queryNG,
			Strategy: StrategyIsolatedInQuery,
			IsSource: true,
		}

		// 创建策略地址为 nil 的策略
		policy := &mockPolicy{
			name:        "nil-policy",
			policyEntry: policy.NewPolicyEntry(), // Src 和 Dst 都是 nil
		}

		result := matcher.Match(policy)
		// 当策略地址为 nil 时，会被设置为 Any，但 Any 不应该匹配
		// 根据代码逻辑，DataRange() 可能返回 nil，所以不应该匹配
		assert.False(t, result.Matched, "Should not match when policy address is nil")
	})

	t.Run("查询地址为nil", func(t *testing.T) {
		// 注意：实际使用中应该确保 Address 不为 nil
		// 这里只是文档说明，不进行实际测试以避免 panic
		t.Skip("Skipping nil address test to avoid panic - Address should always be non-nil in production")
	})

	t.Run("策略包含大量孤立地址", func(t *testing.T) {
		queryNG, _ := network.NewNetworkGroupFromString("10.0.0.0/8")
		matcher := &AddressMatcher{
			Address:  queryNG,
			Strategy: StrategyIsolatedInQuery,
			IsSource: true,
		}

		// 创建包含大量孤立地址的策略
		addresses := make([]string, 100)
		for i := 0; i < 50; i++ {
			addresses[i] = "10.1.0.0/24" // 在查询范围内
		}
		for i := 50; i < 100; i++ {
			addresses[i] = "192.168.1.0/24" // 不在查询范围内
		}

		policy := createMockPolicy("large-policy", addresses...)
		result := matcher.Match(policy)

		assert.True(t, result.Matched, "Should match when some isolated addresses are in query range")
		assert.Greater(t, result.MatchedAddress.IPv4().Count().Int64(), int64(0), "Should have matched addresses")
	})
}

// TestAddressMatcher_StrategyIsolatedInQuery_IPv6 测试 IPv6 场景
func TestAddressMatcher_StrategyIsolatedInQuery_IPv6(t *testing.T) {
	tests := []struct {
		name            string
		queryAddress    string
		policyAddresses []string
		expectedMatch   bool
		description     string
	}{
		{
			name:            "IPv6部分孤立地址在查询范围内",
			queryAddress:    "2001:db8::/32",
			policyAddresses: []string{"2001:db8:1::/48", "2001:db8:2::/48", "2001:db9::/48"},
			expectedMatch:   true,
			description:     "IPv6 策略包含 3 个孤立地址，其中 2 个在查询范围内，应该匹配",
		},
		{
			name:            "IPv6无孤立地址在查询范围内",
			queryAddress:    "2001:db8::/32",
			policyAddresses: []string{"2001:db9::/48", "2001:dba::/48"},
			expectedMatch:   false,
			description:     "IPv6 策略包含 2 个孤立地址，都不在查询范围内，不应该匹配",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queryNG, err := network.NewNetworkGroupFromString(tt.queryAddress)
			if err != nil {
				t.Fatalf("Failed to create query address: %v", err)
			}

			matcher := &AddressMatcher{
				Address:  queryNG,
				Strategy: StrategyIsolatedInQuery,
				IsSource: true,
			}

			policy := createMockPolicy("ipv6-policy", tt.policyAddresses...)
			result := matcher.Match(policy)

			assert.Equal(t, tt.expectedMatch, result.Matched, "Match result mismatch: %s", tt.description)
		})
	}
}

// TestAddressMatcher_StrategyIsolatedInQuery_MixedIPv4IPv6 测试混合 IPv4 和 IPv6 场景
func TestAddressMatcher_StrategyIsolatedInQuery_MixedIPv4IPv6(t *testing.T) {
	t.Run("策略包含IPv4和IPv6孤立地址", func(t *testing.T) {
		// 查询 IPv4 地址
		queryNG, _ := network.NewNetworkGroupFromString("10.0.0.0/8")
		matcher := &AddressMatcher{
			Address:  queryNG,
			Strategy: StrategyIsolatedInQuery,
			IsSource: true,
		}

		// 策略包含 IPv4 和 IPv6 地址
		policy := createMockPolicy("mixed-policy", "10.1.0.0/24", "2001:db8::/48")
		result := matcher.Match(policy)

		// IPv4 地址应该匹配，IPv6 地址不应该匹配（因为查询的是 IPv4）
		assert.True(t, result.Matched, "Should match IPv4 isolated address")
		assert.Greater(t, result.MatchedAddress.IPv4().Count().Int64(), int64(0), "Should have matched IPv4 addresses")
		assert.Equal(t, int64(0), result.MatchedAddress.IPv6().Count().Int64(), "Should not have matched IPv6 addresses")
	})
}
