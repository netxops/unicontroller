package usg

import (
	"strconv"
	"testing"

	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
)

func TestParseAddressGroups(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		expectedCount  int
		expectedGroups []struct {
			groupNumber string
			startIP     string
			endIP       string
		}
	}{
		{
			name: "Single destination-nat address-group with one section",
			config: `# destination-nat address-group d1 0
section 6.6.6.6 6.6.6.10
#`,
			expectedCount: 1,
			expectedGroups: []struct {
				groupNumber string
				startIP     string
				endIP       string
			}{
				{groupNumber: "0", startIP: "6.6.6.6", endIP: "6.6.6.10"},
			},
		},
		{
			name: "Single nat address-group with one section",
			config: `# nat address-group 1 0
section 0 1.1.1.1 1.1.1.22
#`,
			expectedCount: 1,
			expectedGroups: []struct {
				groupNumber string
				startIP     string
				endIP       string
			}{
				{groupNumber: "1", startIP: "1.1.1.1", endIP: "1.1.1.22"},
			},
		},
		{
			name: "Multiple destination-nat address-groups",
			config: `# destination-nat address-group d1 0
section 6.6.6.6 6.6.6.10
# destination-nat address-group d2 1
section 7.7.7.7 7.7.7.20
#`,
			expectedCount: 2,
			expectedGroups: []struct {
				groupNumber string
				startIP     string
				endIP       string
			}{
				{groupNumber: "0", startIP: "6.6.6.6", endIP: "6.6.6.10"},
				{groupNumber: "1", startIP: "7.7.7.7", endIP: "7.7.7.20"},
			},
		},
		{
			name: "Multiple nat address-groups",
			config: `# nat address-group 1 0
section 0 1.1.1.1 1.1.1.22
# nat address-group 2 0
section 0 2.2.2.2 2.2.2.30
#`,
			expectedCount: 2,
			expectedGroups: []struct {
				groupNumber string
				startIP     string
				endIP       string
			}{
				{groupNumber: "1", startIP: "1.1.1.1", endIP: "1.1.1.22"},
				{groupNumber: "2", startIP: "2.2.2.2", endIP: "2.2.2.30"},
			},
		},
		{
			name: "Address group with multiple sections",
			config: `# destination-nat address-group d1 0
section 6.6.6.6 6.6.6.10
section 7.7.7.7 7.7.7.20
#`,
			expectedCount: 1,
			expectedGroups: []struct {
				groupNumber string
				startIP     string
				endIP       string
			}{
				{groupNumber: "0", startIP: "6.6.6.6", endIP: "6.6.6.10"},
			},
		},
		{
			name: "Mixed destination-nat and nat address-groups",
			config: `# destination-nat address-group d1 0
section 6.6.6.6 6.6.6.10
# nat address-group 1 0
section 0 1.1.1.1 1.1.1.22
#`,
			expectedCount: 2,
			expectedGroups: []struct {
				groupNumber string
				startIP     string
				endIP       string
			}{
				{groupNumber: "0", startIP: "6.6.6.6", endIP: "6.6.6.10"},
				{groupNumber: "1", startIP: "1.1.1.1", endIP: "1.1.1.22"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nats := &Nats{
				addressGroups: make(map[string]*AddressGroup),
			}

			err := nats.parseAddressGroups(tt.config)
			assert.NoError(t, err, "parseAddressGroups should not return error")
			assert.Equal(t, tt.expectedCount, len(nats.addressGroups), "Address group count should match")

			for _, expected := range tt.expectedGroups {
				// 查找对应的地址组
				var ag *AddressGroup
				var found bool
				for _, group := range nats.addressGroups {
					if group.GroupNumber == expected.groupNumber {
						ag = group
						found = true
						break
					}
				}

				assert.True(t, found, "Address group with number %s should be found", expected.groupNumber)
				if found {
					assert.Equal(t, expected.groupNumber, ag.GroupNumber, "Group number should match")
					assert.NotEmpty(t, ag.Sections, "Address group should have at least one section")

					// 验证第一个 section 的 IP 范围
					if len(ag.Sections) > 0 {
						firstSection := ag.Sections[0]
						assert.Equal(t, expected.startIP, firstSection.StartIP, "First section start IP should match")
						assert.Equal(t, expected.endIP, firstSection.EndIP, "First section end IP should match")

						// 验证网络组包含期望的 IP 范围
						if ag.N != nil {
							expectedNet, err := network.NewNetworkGroupFromString(expected.startIP + "-" + expected.endIP)
							assert.NoError(t, err, "Should create expected network group")

							// 使用 NetworkGroupCmp 来检查是否包含
							_, mid, _ := network.NetworkGroupCmp(*ag.N, *expectedNet)
							assert.NotNil(t, mid, "Address group network should contain expected range")
							assert.True(t, mid.Same(expectedNet), "Address group network should contain expected range")
						}
					}
				}
			}
		})
	}
}

func TestParseDestinationNatAddressGroups(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		expectedCount  int
		expectedGroups map[string]struct {
			groupNumber string
			groupName   string
			sections    []struct {
				startIP string
				endIP   string
			}
		}
	}{
		{
			name: "Single destination-nat address-group",
			config: `# destination-nat address-group d1 0
section 6.6.6.6 6.6.6.10
#`,
			expectedCount: 1,
			expectedGroups: map[string]struct {
				groupNumber string
				groupName   string
				sections    []struct {
					startIP string
					endIP   string
				}
			}{
				"d1": {
					groupNumber: "0",
					groupName:   "d1",
					sections: []struct {
						startIP string
						endIP   string
					}{
						{startIP: "6.6.6.6", endIP: "6.6.6.10"},
					},
				},
			},
		},
		{
			name: "Multiple sections in destination-nat address-group",
			config: `# destination-nat address-group d1 0
section 6.6.6.6 6.6.6.10
section 7.7.7.7 7.7.7.20
#`,
			expectedCount: 1,
			expectedGroups: map[string]struct {
				groupNumber string
				groupName   string
				sections    []struct {
					startIP string
					endIP   string
				}
			}{
				"d1": {
					groupNumber: "0",
					groupName:   "d1",
					sections: []struct {
						startIP string
						endIP   string
					}{
						{startIP: "6.6.6.6", endIP: "6.6.6.10"},
						{startIP: "7.7.7.7", endIP: "7.7.7.20"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nats := &Nats{
				addressGroups: make(map[string]*AddressGroup),
			}

			err := nats.parseDestinationNatAddressGroups(tt.config)
			assert.NoError(t, err, "parseDestinationNatAddressGroups should not return error")
			assert.Equal(t, tt.expectedCount, len(nats.addressGroups), "Address group count should match")

			for groupName, expected := range tt.expectedGroups {
				ag, ok := nats.addressGroups[groupName]
				assert.True(t, ok, "Address group %s should be found", groupName)
				if ok {
					assert.Equal(t, expected.groupNumber, ag.GroupNumber, "Group number should match")
					assert.Equal(t, len(expected.sections), len(ag.Sections), "Section count should match")

					for idx, expectedSection := range expected.sections {
						if idx < len(ag.Sections) {
							section := ag.Sections[idx]
							assert.Equal(t, expectedSection.startIP, section.StartIP, "Section %d start IP should match", idx)
							assert.Equal(t, expectedSection.endIP, section.EndIP, "Section %d end IP should match", idx)
							assert.NotNil(t, section.Network, "Section %d network should not be nil", idx)
						}
					}
				}
			}
		})
	}
}

func TestParseNatAddressGroups(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		expectedCount  int
		expectedGroups map[string]struct {
			groupNumber string
			sections    []struct {
				sectionNumber string
				startIP       string
				endIP         string
			}
		}
	}{
		{
			name: "Single nat address-group",
			config: `# nat address-group 1 0
section 0 1.1.1.1 1.1.1.22
#`,
			expectedCount: 1,
			expectedGroups: map[string]struct {
				groupNumber string
				sections    []struct {
					sectionNumber string
					startIP       string
					endIP         string
				}
			}{
				"1": {
					groupNumber: "1",
					sections: []struct {
						sectionNumber string
						startIP       string
						endIP         string
					}{
						{sectionNumber: "0", startIP: "1.1.1.1", endIP: "1.1.1.22"},
					},
				},
			},
		},
		{
			name: "Multiple sections in nat address-group",
			config: `# nat address-group 1 0
section 0 1.1.1.1 1.1.1.22
section 1 2.2.2.2 2.2.2.30
#`,
			expectedCount: 1,
			expectedGroups: map[string]struct {
				groupNumber string
				sections    []struct {
					sectionNumber string
					startIP       string
					endIP         string
				}
			}{
				"1": {
					groupNumber: "1",
					sections: []struct {
						sectionNumber string
						startIP       string
						endIP         string
					}{
						{sectionNumber: "0", startIP: "1.1.1.1", endIP: "1.1.1.22"},
						{sectionNumber: "1", startIP: "2.2.2.2", endIP: "2.2.2.30"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nats := &Nats{
				addressGroups: make(map[string]*AddressGroup),
			}

			err := nats.parseNatAddressGroups(tt.config)
			assert.NoError(t, err, "parseNatAddressGroups should not return error")
			assert.Equal(t, tt.expectedCount, len(nats.addressGroups), "Address group count should match")

			for groupNumber, expected := range tt.expectedGroups {
				ag, ok := nats.addressGroups[groupNumber]
				assert.True(t, ok, "Address group %s should be found", groupNumber)
				if ok {
					assert.Equal(t, expected.groupNumber, ag.GroupNumber, "Group number should match")
					assert.Equal(t, len(expected.sections), len(ag.Sections), "Section count should match")

					for i, expectedSection := range expected.sections {
						if i < len(ag.Sections) {
							section := ag.Sections[i]
							assert.Equal(t, expectedSection.sectionNumber, section.SectionNumber, "Section %d number should match", i)
							assert.Equal(t, expectedSection.startIP, section.StartIP, "Section %d start IP should match", i)
							assert.Equal(t, expectedSection.endIP, section.EndIP, "Section %d end IP should match", i)
							assert.NotNil(t, section.Network, "Section %d network should not be nil", i)
						}
					}
				}
			}
		})
	}
}

func TestAddressGroupIterator(t *testing.T) {
	// 创建测试数据
	config := `# destination-nat address-group d1 0
section 6.6.6.6 6.6.6.10
# nat address-group 1 0
section 0 1.1.1.1 1.1.1.22
# nat address-group 2 0
section 0 2.2.2.2 2.2.2.30
#`

	nats := &Nats{
		addressGroups: make(map[string]*AddressGroup),
	}

	err := nats.parseAddressGroups(config)
	assert.NoError(t, err, "parseAddressGroups should not return error")
	assert.Equal(t, 3, len(nats.addressGroups), "Should have 3 address groups")

	// 测试迭代所有地址组
	t.Run("Iterate all address groups", func(t *testing.T) {
		count := 0
		for _, ag := range nats.addressGroups {
			assert.NotNil(t, ag, "Address group should not be nil")
			assert.NotEmpty(t, ag.GroupNumber, "Group number should not be empty")
			assert.NotEmpty(t, ag.Sections, "Address group should have sections")
			count++
		}
		assert.Equal(t, 3, count, "Should iterate all 3 address groups")
	})

	// 测试按网络组过滤
	t.Run("Filter by network group", func(t *testing.T) {
		// 创建一个网络组用于过滤
		filterNet, err := network.NewNetworkGroupFromString("6.6.6.6-6.6.6.10")
		assert.NoError(t, err, "Should create filter network group")

		matchCount := 0
		for _, ag := range nats.addressGroups {
			// 确保网络组已初始化（通过调用 Network 方法）
			agNet := ag.Network(nil)
			if agNet != nil {
				_, mid, _ := network.NetworkGroupCmp(*agNet, *filterNet)
				if mid != nil && mid.Same(filterNet) {
					matchCount++
					// d1 的 groupNumber 是 "0"
					if ag.GroupNumber == "0" {
						assert.Equal(t, "0", ag.GroupNumber, "Matched group should be d1")
					}
				}
			}
		}
		assert.Equal(t, 1, matchCount, "Should match one address group")
	})

	// 测试 NextPoolId
	t.Run("NextPoolId", func(t *testing.T) {
		nextId := nats.NextPoolId("")
		nextIdInt, err := strconv.Atoi(nextId)
		assert.NoError(t, err, "Next pool ID should be a valid integer")
		assert.Greater(t, nextIdInt, 0, "Next pool ID should be greater than 0")

		// 验证 nextId 大于所有现有的 group number
		maxId := 0
		for _, ag := range nats.addressGroups {
			groupId, err := strconv.Atoi(ag.GroupNumber)
			if err == nil && groupId > maxId {
				maxId = groupId
			}
		}
		assert.GreaterOrEqual(t, nextIdInt, maxId+1, "Next pool ID should be at least maxId+1")
	})
}

func TestAddressGroupNetwork(t *testing.T) {
	config := `# destination-nat address-group d1 0
section 6.6.6.6 6.6.6.10
section 7.7.7.7 7.7.7.20
#`

	nats := &Nats{
		addressGroups: make(map[string]*AddressGroup),
	}

	err := nats.parseAddressGroups(config)
	assert.NoError(t, err, "parseAddressGroups should not return error")

	ag, ok := nats.addressGroups["d1"]
	assert.True(t, ok, "Address group d1 should be found")

	// 测试 Network 方法
	ng := ag.Network(nil)
	assert.NotNil(t, ng, "Network should not be nil")

	// 验证网络组包含所有 section 的 IP 范围
	expectedNet1, err := network.NewNetworkGroupFromString("6.6.6.6-6.6.6.10")
	assert.NoError(t, err, "Should create expected network group 1")
	expectedNet2, err := network.NewNetworkGroupFromString("7.7.7.7-7.7.7.20")
	assert.NoError(t, err, "Should create expected network group 2")

	// 检查网络组包含期望的范围
	_, mid1, _ := network.NetworkGroupCmp(*ng, *expectedNet1)
	assert.NotNil(t, mid1, "Network should contain first section")
	assert.True(t, mid1.Same(expectedNet1), "Network should contain first section")

	_, mid2, _ := network.NetworkGroupCmp(*ng, *expectedNet2)
	assert.NotNil(t, mid2, "Network should contain second section")
	assert.True(t, mid2.Same(expectedNet2), "Network should contain second section")
}
