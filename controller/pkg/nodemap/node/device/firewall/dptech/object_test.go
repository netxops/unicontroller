package dptech

// import (
// 	"testing"
// 	"time"

// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/errors"
// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"

// 	"github.com/influxdata/telegraf/controller/pkg/nodemap/parse"
// 	"github.com/netxops/utils/network"
// 	"github.com/netxops/utils/policy"
// 	"github.com/netxops/utils/service"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// )

// type MockDptechAdapter struct {
// 	mock.Mock
// }

// func (m *MockDptechAdapter) Ports(force bool) ([]api.Port, error) {
// 	args := m.Called(force)
// 	return args.Get(0).([]api.Port), args.Error(1)
// }

// func (m *MockDptechAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
// 	args := m.Called(force)
// 	return args.Get(0).(map[string]*network.AddressTable), args.Get(1).(map[string]*network.AddressTable)
// }

// func (m *MockDptechAdapter) Zones(force bool) ([]interface{}, error) {
// 	args := m.Called(force)
// 	return args.Get(0).([]interface{}), args.Error(1)
// }

// func (m *MockDptechAdapter) ParseName(force bool) string {
// 	args := m.Called(force)
// 	return args.String(0)
// }

// // NewMockDptechAdapter creates a new mock DptechAdapter with pre-configured data
// func NewMockDptechAdapter() *MockDptechAdapter {
// 	mockAdapter := &MockDptechAdapter{}

// 	// Mock Ports
// 	ports := []api.Port{
// 		NewDptechPort("eth1", "default", map[network.IPFamily][]string{
// 			network.IPv4: {"192.168.1.1/24"},
// 			network.IPv6: {"2001:db8::1/64"},
// 		}, []api.Member{}),
// 		NewDptechPort("eth2", "default", map[network.IPFamily][]string{
// 			network.IPv4: {"10.0.0.1/24"},
// 			network.IPv6: {"2001:db8:1::1/64"},
// 		}, []api.Member{}),
// 	}
// 	mockAdapter.On("Ports", mock.Anything).Return(ports, nil)

// 	// Mock RouteTable
// 	ipv4Table := network.NewAddressTable(network.IPv4)
// 	ipv4Table.PushRoute(mustParseIPNet("0.0.0.0/0"), mustNexthop("eth1", "192.168.1.254", false, false, nil))
// 	ipv4Table.PushRoute(mustParseIPNet("10.0.0.0/8"), mustNexthop("eth2", "", true, false, nil))

// 	ipv6Table := network.NewAddressTable(network.IPv6)
// 	ipv6Table.PushRoute(mustParseIPNet("::/0"), mustNexthop("eth1", "2001:db8::ffff", false, false, nil))
// 	ipv6Table.PushRoute(mustParseIPNet("2001:db8::/32"), mustNexthop("eth2", "", true, false, nil))

// 	mockAdapter.On("RouteTable", mock.Anything).Return(
// 		map[string]*network.AddressTable{"default": ipv4Table},
// 		map[string]*network.AddressTable{"default": ipv6Table},
// 	)

// 	// Mock Zones
// 	zones := []interface{}{
// 		map[string]interface{}{
// 			"ZoneName":    "trust",
// 			"IfName":      "eth1",
// 			"Priority":    "1",
// 			"Description": "Internal network",
// 		},
// 		map[string]interface{}{
// 			"ZoneName":    "untrust",
// 			"IfName":      "eth2",
// 			"Priority":    "2",
// 			"Description": "External network",
// 		},
// 	}
// 	mockAdapter.On("Zones", mock.Anything).Return(zones, nil)

// 	// Mock ParseName
// 	mockAdapter.On("ParseName", mock.Anything).Return("DptechFirewall")

// 	return mockAdapter
// }

// // 设置预期行为和返回值
// func (m *MockDptechAdapter) SetupMockBehavior() {
// 	// Mock Ports
// 	ports := []api.Port{
// 		NewDptechPort("eth1", "trust", map[network.IPFamily][]string{
// 			network.IPv4: {"192.168.1.1/24"},
// 			network.IPv6: {"2001:db8::1/64"},
// 		}, []api.Member{}),
// 		NewDptechPort("eth2", "untrust", map[network.IPFamily][]string{
// 			network.IPv4: {"10.0.0.1/24"},
// 			network.IPv6: {"2001:db8:1::1/64"},
// 		}, []api.Member{}),
// 	}
// 	m.On("Ports", mock.Anything).Return(ports, nil)

// 	// Mock RouteTable
// 	ipv4Table := network.NewAddressTable(network.IPv4)
// 	ipv4Table.PushRoute(mustParseIPNet("0.0.0.0/0"), mustNexthop("eth2", "10.0.0.254", false, false, nil))
// 	ipv4Table.PushRoute(mustParseIPNet("192.168.0.0/16"), mustNexthop("eth1", "", true, false, nil))

// 	ipv6Table := network.NewAddressTable(network.IPv6)
// 	ipv6Table.PushRoute(mustParseIPNet("::/0"), mustNexthop("eth2", "2001:db8:1::ffff", false, false, nil))
// 	ipv6Table.PushRoute(mustParseIPNet("2001:db8::/32"), mustNexthop("eth1", "", true, false, nil))

// 	m.On("RouteTable", mock.Anything).Return(
// 		map[string]*network.AddressTable{"default": ipv4Table},
// 		map[string]*network.AddressTable{"default": ipv6Table},
// 		nil,
// 	)

// 	// Mock Zones
// 	zones := []interface{}{
// 		map[string]interface{}{
// 			"ZoneName":    "trust",
// 			"IfName":      "eth1",
// 			"Priority":    "1",
// 			"Description": "Internal network",
// 		},
// 		map[string]interface{}{
// 			"ZoneName":    "untrust",
// 			"IfName":      "eth2",
// 			"Priority":    "2",
// 			"Description": "External network",
// 		},
// 	}
// 	m.On("Zones", mock.Anything).Return(zones, nil)
// }

// func mustParseIPNet(ip string) *network.IPNet {
// 	ipn, err := network.ParseIPNet(ip)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return ipn
// }

// func mustNexthop(ifName, gateway string, isDefault, isStatic bool, options map[string]string) *network.NextHop {
// 	nh := network.NewNextHop()
// 	nh.AddHop(ifName, gateway, isDefault, isStatic, options)
// 	return nh
// }

// func TestDptechObjectSet_parseService(t *testing.T) {
// 	tests := []struct {
// 		name        string
// 		config      string
// 		expectedLen int
// 		expectedErr bool
// 	}{
// 		{
// 			name: "Multiple valid services",
// 			config: `service-object tcp_80 protocol tcp dst-port 80
// 				service-object udp_53 protocol udp dst-port 53
// 				service-object tcp_range protocol tcp dst-port 1000 to 2000
// 				service-object udp_multi protocol udp dst-port 67,68`,
// 			expectedLen: 4,
// 			expectedErr: false,
// 		},
// 		{
// 			name: "ICMP services",
// 			config: `service-object icmp_echo protocol icmp type 8 code 0
// 				service-object icmp_all protocol icmp`,
// 			expectedLen: 2,
// 			expectedErr: false,
// 		},
// 		{
// 			name: "Protocol services",
// 			config: `service-object gre protocol 47
// 				service-object esp protocol 50`,
// 			expectedLen: 2,
// 			expectedErr: false,
// 		},

// 		{
// 			name: "Services with source ports",
// 			config: `service-object tcp_src_dst protocol tcp src-port 1024 to 65535 dst-port 80
// 				service-object udp_src_dst protocol udp src-port 53 dst-port 1024 to 65535`,
// 			expectedLen: 2,
// 			expectedErr: false,
// 		},
// 		{
// 			name: "Complex mixed configuration",
// 			config: `service-object tcp_multi protocol tcp dst-port 80,443,8080
// 				service-object udp_range protocol udp dst-port 1000 to 2000
// 				service-object icmp_echo protocol icmp type 8
// 				service-object gre protocol 47
// 				service-object tcp_src_dst protocol tcp src-port 1024 to 65535 dst-port 22`,
// 			expectedLen: 5,
// 			expectedErr: false,
// 		},

// 		{
// 			name: "Boundary port values",
// 			config: `service-object tcp_min protocol tcp dst-port 1
// 				service-object tcp_max protocol tcp dst-port 65535
// 				service-object udp_min protocol udp dst-port 1
// 				service-object udp_max protocol udp dst-port 65535`,
// 			expectedLen: 4,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Large number of ports",
// 			config:      `service-object tcp_many protocol tcp dst-port 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Maximum allowed port range",
// 			config:      `service-object tcp_full_range protocol tcp dst-port 1 to 65535`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "ICMP with maximum type and code",
// 			config:      `service-object icmp_max protocol icmp type 255 code 255`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Long service name",
// 			config:      `service-object this_is_a_very_long_service_name_that_might_be_close_to_or_at_the_maximum_allowed_length protocol tcp dst-port 8080`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Complex ICMP service",
// 			config:      `service-object icmp_complex protocol icmp code 5 code 7 code 8 to 15`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Custom protocol service",
// 			config:      `service-object custom_proto protocol 33`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "ICMP with type range and single code",
// 			config:      `service-object icmp_type_range protocol icmp type 0 to 45 code 7`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Complex ICMP with multiple types and ranges",
// 			config:      `service-object icmp_complex_types protocol icmp type 55 type 57 type 12 to 25 code 77`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "TCP with multiple source and destination port ranges",
// 			config:      `service-object tcp_complex protocol tcp src-port 0 to 555 src-port 558 to 777 src-port 888 dst-port 555 dst-port 77 to 554`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name: "Multiple complex services",
// 			config: `service-object icmp_service protocol icmp code 5 code 7 code 8 to 15
// 		service-object custom_proto protocol 33
// 		service-object icmp_range protocol icmp type 0 to 45 code 7
// 		service-object tcp_complex protocol tcp src-port 0 to 555 src-port 558 to 777 src-port 888 dst-port 555 dst-port 77 to 554`,
// 			expectedLen: 4,
// 			expectedErr: false,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			dos := &DptechObjectSet{
// 				serviceMap: make(map[string]firewall.FirewallServiceObject),
// 			}
// 			result := parse.NewParseResult()

// 			dos.parseService(tt.config, result)

// 			assert.Equal(t, tt.expectedLen, len(dos.serviceMap), "Unexpected number of services parsed")
// 			assert.Equal(t, tt.expectedErr, result.HasErrors(), "Unexpected error state")

// 			// Additional checks for specific test cases
// 			if tt.name == "Multiple valid services" {
// 				assert.Contains(t, dos.serviceMap, "tcp_80", "TCP 80 service not found")
// 				assert.Contains(t, dos.serviceMap, "udp_53", "UDP 53 service not found")
// 				assert.Contains(t, dos.serviceMap, "tcp_range", "TCP range service not found")
// 				assert.Contains(t, dos.serviceMap, "udp_multi", "UDP multi-port service not found")
// 			}

// 			// if tt.name == "Duplicate service names" {
// 			// 	assert.Contains(t, dos.serviceMap, "duplicate", "Duplicate service not found")
// 			// 	svc, ok := dos.serviceMap["duplicate"]
// 			// 	assert.True(t, ok, "Duplicate service should exist")
// 			// 	assert.Equal(t, "tcp", svc.Service(nil).Protocol().String(), "Duplicate service should be TCP")
// 			// }
// 		})
// 	}
// }

// func TestDptechObjectSet_parseAddress(t *testing.T) {
// 	tests := []struct {
// 		name        string
// 		config      string
// 		expectedLen int
// 		expectedErr bool
// 	}{
// 		{
// 			name: "Valid address objects",
// 			config: `address-object server1 192.168.1.100/32
// 		address-object network1 192.168.0.0/24`,
// 			expectedLen: 2,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Invalid address object",
// 			config:      `address-object invalid_address 300.400.500.600`,
// 			expectedLen: 0,
// 			expectedErr: true,
// 		},
// 		{
// 			name:        "IPv4 address with /32 subnet",
// 			config:      `address-object single_ip 10.0.0.1/32`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "IPv4 address with /0 subnet",
// 			config:      `address-object any_ip 0.0.0.0/0`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "IPv6 address",
// 			config:      `address-object ipv6_addr 2001:db8::1/64`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "IPv6 network",
// 			config:      `address-object ipv6_net 2001:db8::/64`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name: "Multiple valid and invalid addresses",
// 			config: `address-object valid1 192.168.1.1/32
// 		address-object invalid1 256.0.0.1
// 		address-object valid2 10.0.0.0/8
// 		address-object invalid2 192.168.1.1/33`,
// 			expectedLen: 2,
// 			expectedErr: true,
// 		},
// 		{
// 			name:        "Address with leading/trailing spaces",
// 			config:      `address-object spaced_addr 192.168.1.100/32  `,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Address object with empty name",
// 			config:      `address-object "" 192.168.1.1`,
// 			expectedLen: 0,
// 			expectedErr: true,
// 		},
// 		{
// 			name:        "Address object with very long name",
// 			config:      `address-object this_is_a_very_long_address_object_name_that_might_be_close_to_or_at_the_maximum_allowed_length 192.168.1.1/32`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Address object with special characters in name",
// 			config:      `address-object special!@#$%^&*()_+[] 192.168.1.1/32`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name: "Duplicate address object names",
// 			config: `address-object duplicate 192.168.1.1/32
// 		address-object duplicate 192.168.1.2/32`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Address object with no IP",
// 			config:      `address-object no_ip`,
// 			expectedLen: 0,
// 			expectedErr: true,
// 		},
// 		{
// 			name:        "Address object with multiple IPs (invalid)",
// 			config:      `address-object multi_ip 192.168.1.1 192.168.1.2`,
// 			expectedLen: 0,
// 			expectedErr: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			dos := &DptechObjectSet{
// 				addressObjectSet: make(map[string]firewall.FirewallNetworkObject),
// 			}
// 			result := parse.NewParseResult()

// 			dos.parseAddress(tt.config, result)

// 			assert.Equal(t, tt.expectedLen, len(dos.addressObjectSet), "Unexpected number of address objects parsed")
// 			assert.Equal(t, tt.expectedErr, result.HasErrors(), "Unexpected error state")

// 			// Additional checks for specific test cases
// 			switch tt.name {
// 			case "Valid address objects":
// 				assert.Contains(t, dos.addressObjectSet, "server1", "server1 address object not found")
// 				assert.Contains(t, dos.addressObjectSet, "network1", "network1 address object not found")
// 			case "IPv4 address with /32 subnet":
// 				assert.Contains(t, dos.addressObjectSet, "single_ip", "single_ip address object not found")
// 			case "IPv4 address with /0 subnet":
// 				assert.Contains(t, dos.addressObjectSet, "any_ip", "any_ip address object not found")
// 			case "IPv6 address":
// 				assert.Contains(t, dos.addressObjectSet, "ipv6_addr", "ipv6_addr address object not found")
// 			case "IPv6 network":
// 				assert.Contains(t, dos.addressObjectSet, "ipv6_net", "ipv6_net address object not found")
// 			case "Duplicate address object names":
// 				assert.Contains(t, dos.addressObjectSet, "duplicate", "duplicate address object not found")
// 				assert.Len(t, dos.addressObjectSet, 1, "Should only contain one address object")
// 			}
// 		})
// 	}
// }

// func TestDptechObjectSet_parseAddressSet(t *testing.T) {
// 	tests := []struct {
// 		name        string
// 		config      string
// 		expectedLen int
// 		expectedErr bool
// 	}{
// 		{
// 			name: "Valid address group",
// 			config: `
// 		address-group servers address-object server1
// 		address-group servers address-object server2`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Invalid address group",
// 			config:      `address-group invalid_group address-object non_existent_object`,
// 			expectedLen: 1,
// 			expectedErr: true,
// 		},

// 		{
// 			name: "Valid address group",
// 			config: `
// 		address-group servers address-object server1
// 		address-group servers address-object server2`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Invalid address group",
// 			config:      `address-group invalid_group address-object non_existent_object`,
// 			expectedLen: 1,
// 			expectedErr: true,
// 		},
// 		// 添加新的边界测试用例
// 		{
// 			name:        "Empty address group",
// 			config:      `address-group empty_group`,
// 			expectedLen: 0,
// 			expectedErr: true,
// 		},
// 		{
// 			name: "Address group with duplicate objects",
// 			config: `
// 		address-group duplicate_group address-object server1
// 		address-group duplicate_group address-object server1`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name: "Multiple address groups",
// 			config: `
// 				address-group group1 address-object server1
// 				address-group group2 address-object server2`,
// 			expectedLen: 2,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Address group with very long name",
// 			config:      `address-group this_is_a_very_long_address_group_name_that_might_be_close_to_or_at_the_maximum_allowed_length address-object server1`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name:        "Address group with special characters in name",
// 			config:      `address-group special!@#$%^&*()_+[] address-object server1`,
// 			expectedLen: 1,
// 			expectedErr: false,
// 		},
// 		{
// 			name: "Address group with mixed valid and invalid objects",
// 			config: `
// 		address-group mixed_group address-object server1
// 		address-group mixed_group address-object non_existent_object`,
// 			expectedLen: 1,
// 			expectedErr: true,
// 		},
// 		{
// 			name:        "Address group with no objects",
// 			config:      `address-group no_objects_group`,
// 			expectedLen: 0,
// 			expectedErr: true,
// 		},
// 		{
// 			name: "Nested address groups (if supported)",
// 			config: `
// 		address-group parent_group address-object server1
// 		address-group child_group address-object server2
// 		address-group parent_group address-group child_group`,
// 			expectedLen: 2,
// 			expectedErr: false, // Change to true if nested groups are not supported
// 		},
// 		{
// 			name:        "Address group with invalid syntax",
// 			config:      `address-group invalid syntax address-object server1`,
// 			expectedLen: 0,
// 			expectedErr: true,
// 		},
// 		{
// 			name: "Address group with maximum number of objects",
// 			config: `
// 		address-group max_objects address-object server1
// 		address-group max_objects address-object server2
// 		address-group max_objects address-object server3
// 		address-group max_objects address-object server4
// 		address-group max_objects address-object server5`,
// 			expectedLen: 1,
// 			expectedErr: true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			dos := &DptechObjectSet{
// 				addressGroupSet:  make(map[string]firewall.FirewallNetworkObject),
// 				addressObjectSet: make(map[string]firewall.FirewallNetworkObject),
// 			}
// 			// Add some mock address objects
// 			dos.addressObjectSet["server1"] = &DptechNetwork{
// 				network: network.NewNetworkGroup(),
// 			}
// 			dos.addressObjectSet["server2"] = &DptechNetwork{
// 				network: network.NewNetworkGroup(),
// 			}

// 			result := parse.NewParseResult()

// 			dos.parseAddressGroup(tt.config, result)

// 			assert.Equal(t, tt.expectedLen, len(dos.addressGroupSet), "Unexpected number of address groups parsed")
// 			assert.Equal(t, tt.expectedErr, result.HasErrors(), "Unexpected error state")
// 		})
// 	}
// }

// func TestParseServiceGroup(t *testing.T) {
// 	tests := []struct {
// 		name           string
// 		config         string
// 		expectedResult map[string]*DptechService
// 		expectedErrors []*errors.StructuredError
// 	}{
// 		{
// 			name: "Valid single service group",
// 			config: `
// service-group DMZ_SEC_SDP_Server_policy03_dstport service-object TCP_30001
// service-group DMZ_SEC_SDP_Server_policy03_dstport service-object TCP_30002
// 		`,
// 			expectedResult: map[string]*DptechService{
// 				"DMZ_SEC_SDP_Server_policy03_dstport": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "DMZ_SEC_SDP_Server_policy03_dstport",
// 					cli: `service-group DMZ_SEC_SDP_Server_policy03_dstport service-object TCP_30001
// service-group DMZ_SEC_SDP_Server_policy03_dstport service-object TCP_30002`,
// 					refNames: []string{"TCP_30001", "TCP_30002"},
// 				},
// 			},
// 			expectedErrors: nil,
// 		},
// 		{
// 			name: "Multiple service groups",
// 			config: `
// service-group Group1 service-object TCP_80
// service-group Group1 service-object TCP_443
// service-group Group2 service-object UDP_53
// 				`,
// 			expectedResult: map[string]*DptechService{
// 				"Group1": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "Group1",
// 					cli: `service-group Group1 service-object TCP_80
// service-group Group1 service-object TCP_443`,
// 					refNames: []string{"TCP_80", "TCP_443"},
// 				},
// 				"Group2": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "Group2",
// 					cli:      "service-group Group2 service-object UDP_53",
// 					refNames: []string{"UDP_53"},
// 				},
// 			},
// 			expectedErrors: nil,
// 		},
// 		{
// 			name:           "Empty config",
// 			config:         "",
// 			expectedResult: map[string]*DptechService{},
// 			expectedErrors: []*errors.StructuredError{
// 				{
// 					Type:      errors.ParseError,
// 					Message:   "Failed to parse service group sections",
// 					Severity:  errors.SeverityError,
// 					Section:   "Service Groups",
// 					Line:      0,
// 					RawData:   "service-group InvalidGroup",
// 					Timestamp: time.Now(),
// 					Context:   map[string]interface{}{"error": "failed to process section: no matched"},
// 				},
// 			},
// 		},
// 		{
// 			name: "Invalid service group syntax",
// 			config: `
// service-group InvalidGroup aa
// service-group ValidGroup service-object TCP_80
// 		`,
// 			expectedResult: map[string]*DptechService{
// 				"ValidGroup": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "ValidGroup",
// 					cli:      "service-group ValidGroup service-object TCP_80",
// 					refNames: []string{"TCP_80"},
// 				},
// 			},
// 			expectedErrors: []*errors.StructuredError{
// 				{
// 					Type:      errors.ParseError,
// 					Message:   "Failed to parse service group",
// 					Severity:  errors.SeverityWarning,
// 					Section:   "Service Groups",
// 					Line:      0,
// 					RawData:   "service-group InvalidGroup",
// 					Timestamp: time.Now(),
// 					Context:   map[string]interface{}{"error": "failed to process section: no matched"},
// 				},
// 			},
// 		},

// 		{
// 			name: "Service group with built-in services",
// 			config: `
// service-group BuiltInGroup predefined-service HTTP
// service-group BuiltInGroup predefined-service HTTPS
// service-group BuiltInGroup predefined-service FTP
//             `,
// 			expectedResult: map[string]*DptechService{
// 				"BuiltInGroup": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "BuiltInGroup",
// 					cli: `service-group BuiltInGroup predefined-service HTTP
// service-group BuiltInGroup predefined-service HTTPS
// service-group BuiltInGroup predefined-service FTP`,
// 					refNames: []string{"HTTP", "HTTPS", "FTP"},
// 				},
// 			},
// 			expectedErrors: nil,
// 		},
// 		{
// 			name: "Mixed service group with custom and built-in services",
// 			config: `
// service-group MixedGroup service-object TCP_80
// service-group MixedGroup predefined-service HTTPS
// service-group MixedGroup service-object UDP_53
//             `,
// 			expectedResult: map[string]*DptechService{
// 				"MixedGroup": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "MixedGroup",
// 					cli: `service-group MixedGroup service-object TCP_80
// service-group MixedGroup predefined-service HTTPS
// service-group MixedGroup service-object UDP_53`,
// 					refNames: []string{"TCP_80", "HTTPS", "UDP_53"},
// 				},
// 			},
// 			expectedErrors: nil,
// 		},
// 		{
// 			name: "Service group with invalid built-in service",
// 			config: `
// service-group InvalidBuiltInGroup predefined-service INVALID_SERVICE
// service-group InvalidBuiltInGroup predefined-service HTTP
//             `,
// 			expectedResult: map[string]*DptechService{
// 				"InvalidBuiltInGroup": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "InvalidBuiltInGroup",
// 					cli: `service-group InvalidBuiltInGroup predefined-service HTTP`,
// 					refNames: []string{"HTTP"},
// 				},
// 			},
// 			expectedErrors: []*errors.StructuredError{
// 				{
// 					Type:      errors.ParseError,
// 					Message:   "Built-in service 'INVALID_SERVICE' not found",
// 					Severity:  errors.SeverityWarning,
// 					Section:   "Service Groups",
// 					Line:      0,
// 					RawData:   "service-group InvalidBuiltInGroup predefined-service INVALID_SERVICE",
// 					Timestamp: time.Now(),
// 					Context:   map[string]interface{}{"builtin_service": "INVALID_SERVICE"},
// 				},
// 			},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			dos := NewDptechObjectSet()
// 			result := parse.NewParseResult()

// 			s1, _ := service.NewServiceFromString("tcp:--|30001")
// 			s2, _ := service.NewServiceFromString("tcp:--|30002")
// 			tcpService80, _ := service.NewServiceFromString("tcp:--|80")
// 			tcpService443, _ := service.NewServiceFromString("tcp:--|443")
// 			udpService53, _ := service.NewServiceFromString("udp:--|53")

// 			// 模拟一些 service-object
// 			dos.serviceMap["TCP_30001"] = &DptechService{
// 				name:     "TCP_30001",
// 				catagory: firewall.OBJECT_SERVICE,
// 				service:  s1,
// 				// 添加其他必要的字段
// 			}
// 			dos.serviceMap["TCP_30002"] = &DptechService{
// 				name:     "TCP_30002",
// 				catagory: firewall.OBJECT_SERVICE,
// 				service:  s2,

// 				// 添加其他必要的字段
// 			}
// 			dos.serviceMap["TCP_80"] = &DptechService{
// 				name:     "TCP_80",
// 				catagory: firewall.OBJECT_SERVICE,
// 				service:  tcpService80,
// 			}
// 			dos.serviceMap["TCP_443"] = &DptechService{
// 				name:     "TCP_443",
// 				catagory: firewall.OBJECT_SERVICE,
// 				service:  tcpService443,
// 			}
// 			dos.serviceMap["UDP_53"] = &DptechService{
// 				name:     "UDP_53",
// 				catagory: firewall.OBJECT_SERVICE,
// 				service:  udpService53,
// 			}

// 			// 解析 service-group
// 			dos.parseServiceGroup(tt.config, result)

// 			// 检查解析结果
// 			for groupName, expectedGroup := range tt.expectedResult {
// 				actualGroup, exists := dos.serviceGroup[groupName]
// 				if !exists {
// 					t.Errorf("Expected service group %s not found", groupName)
// 					continue
// 				}

// 				if actualGroup.Type() != expectedGroup.Type() {
// 					t.Errorf("Service group %s: expected category %v, got %v", groupName, expectedGroup.Type(), actualGroup.Type())
// 				}

// 				if actualGroup.Name() != expectedGroup.Name() {
// 					t.Errorf("Service group %s: expected name %s, got %s", groupName, expectedGroup.Name(), actualGroup.Name())
// 				}

// 				if actualGroup.Cli() != expectedGroup.Cli() {
// 					t.Errorf("Service group %s: expected CLI %s, got %s", groupName, expectedGroup.Cli(), actualGroup.Cli())
// 				}

// 				// actualRefNames := actualGroup.RefNames()
// 				// expectedRefNames := expectedGroup.RefNames()
// 				// if !reflect.DeepEqual(actualRefNames, expectedRefNames) {
// 				// 	t.Errorf("Service group %s: expected refNames %v, got %v", groupName, expectedRefNames, actualRefNames)
// 				// }
// 			}

// 			// 检查错误
// 			if len(result.Errors) != len(tt.expectedErrors) {
// 				t.Errorf("Expected %d errors, got %d", len(tt.expectedErrors), len(result.Errors))
// 			} else {
// 				for i, expectedErr := range tt.expectedErrors {
// 					actualErr := result.Errors[i]
// 					if actualErr.Type != expectedErr.Type ||
// 						actualErr.Message != expectedErr.Message ||
// 						actualErr.Severity != expectedErr.Severity ||
// 						actualErr.Section != expectedErr.Section {
// 						t.Errorf("Error %d: expected %v, got %v", i, expectedErr, actualErr)
// 					}
// 				}
// 			}
// 		})
// 	}
// }

// func TestParseServiceGroup_EdgeCases(t *testing.T) {
// 	tests := []struct {
// 		name           string
// 		config         string
// 		expectedResult map[string]*DptechService
// 		expectedErrors []*errors.StructuredError
// 	}{
// 		{
// 			name: "Service group with no objects",
// 			config: `
// service-group EmptyGroup
// 		`,
// 			expectedResult: map[string]*DptechService{},
// 			expectedErrors: []*errors.StructuredError{
// 				{
// 					Type:      errors.ParseError,
// 					Message:   "Failed to parse service group sections",
// 					Severity:  errors.SeverityError,
// 					Section:   "Service Groups",
// 					Line:      0,
// 					RawData:   "service-group EmptyGroup",
// 					Timestamp: time.Now(),
// 					Context:   map[string]interface{}{"error": "failed to process section: no matched"},
// 				},
// 			},
// 		},
// 		{
// 			name: "Service group with duplicate objects",
// 			config: `
// service-group DuplicateGroup service-object TCP_80
// service-group DuplicateGroup service-object TCP_80
// 				`,
// 			expectedResult: map[string]*DptechService{
// 				"DuplicateGroup": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "DuplicateGroup",
// 					cli: `service-group DuplicateGroup service-object TCP_80
// service-group DuplicateGroup service-object TCP_80`,
// 					refNames: []string{"TCP_80", "TCP_80"},
// 				},
// 			},
// 			expectedErrors: nil,
// 		},
// 		{
// 			name: "Service group with very long name",
// 			config: `
// service-group ThisIsAVeryLongServiceGroupNameThatMightExceedSomeLimits service-object TCP_80
// 		`,
// 			expectedResult: map[string]*DptechService{
// 				"ThisIsAVeryLongServiceGroupNameThatMightExceedSomeLimits": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "ThisIsAVeryLongServiceGroupNameThatMightExceedSomeLimits",
// 					cli:      "service-group ThisIsAVeryLongServiceGroupNameThatMightExceedSomeLimits service-object TCP_80",
// 					refNames: []string{"TCP_80"},
// 				},
// 			},
// 			expectedErrors: nil,
// 		},
// 		{
// 			name: "Service group with special characters in name",
// 			config: `
// service-group Special!@#$%^&*()_+{}|:"<>?-=[];',./Group service-object TCP_80
// 		`,
// 			expectedResult: map[string]*DptechService{
// 				"Special!@#$%^&*()_+{}|:\"<>?-=[];',./Group": {
// 					catagory: firewall.GROUP_SERVICE,
// 					name:     "Special!@#$%^&*()_+{}|:\"<>?-=[];',./Group",
// 					cli:      "service-group Special!@#$%^&*()_+{}|:\"<>?-=[];',./Group service-object TCP_80",
// 					refNames: []string{"TCP_80"},
// 				},
// 			},
// 			expectedErrors: nil,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			dos := NewDptechObjectSet()
// 			tcpService80, _ := service.NewServiceFromString("tcp:--|80")
// 			dos.serviceMap["TCP_80"] = &DptechService{
// 				name:     "TCP_80",
// 				catagory: firewall.OBJECT_SERVICE,
// 				service:  tcpService80,
// 			}
// 			result := parse.NewParseResult()

// 			dos.parseServiceGroup(tt.config, result)

// 			// Check the parsed service groups
// 			if len(dos.serviceGroup) != len(tt.expectedResult) {
// 				t.Errorf("parseServiceGroup() got = %v, want %v", dos.serviceGroup, tt.expectedResult)
// 			}

// 			// Check the errors
// 			if len(result.Errors) != len(tt.expectedErrors) {
// 				t.Errorf("parseServiceGroup() got %d errors, want %d", len(result.Errors), len(tt.expectedErrors))
// 			} else {
// 				for i, structErr := range result.Errors {
// 					// structErr, ok := err.(*errors.StructuredError)
// 					// if !ok {
// 					// 	t.Errorf("Error is not a StructuredError: %v", err)
// 					// 	continue
// 					// }
// 					expectedErr := tt.expectedErrors[i]
// 					if structErr.Type != expectedErr.Type ||
// 						structErr.Message != expectedErr.Message ||
// 						structErr.Severity != expectedErr.Severity ||
// 						structErr.Section != expectedErr.Section {
// 						t.Errorf("parseServiceGroup() error %d: got %v, want %v", i, structErr, expectedErr)
// 					}
// 				}
// 			}
// 		})
// 	}
// }

// func TestDptechObjectSet_parsePools(t *testing.T) {
// 	tests := []struct {
// 		name           string
// 		config         string
// 		expectedPools  map[string]string
// 		expectedErrors int
// 	}{
// 		{
// 			name: "Single pool with start and end address",
// 			config: `address-pool Dynamic-PAT-DMZ-IN-DCN-Address-Pool address 132.252.45.245 to 132.252.45.254
// address-pool Another-Pool address 10.0.0.1 to 10.0.0.10`,
// 			expectedPools: map[string]string{
// 				"Dynamic-PAT-DMZ-IN-DCN-Address-Pool": "132.252.45.245-132.252.45.254",
// 				"Another-Pool":                        "10.0.0.1-10.0.0.10",
// 			},
// 			expectedErrors: 0,
// 		},
// 		{
// 			name: "Single pool with only start address",
// 			config: `address-pool Single-IP-Pool address 192.168.1.1
// address-pool Another-Single-IP-Pool address 10.0.0.1`,
// 			expectedPools: map[string]string{
// 				"Single-IP-Pool":         "192.168.1.1",
// 				"Another-Single-IP-Pool": "10.0.0.1",
// 			},
// 			expectedErrors: 0,
// 		},
// 		{
// 			name: "Mixed pool types",
// 			config: `address-pool Range-Pool address 172.16.0.1 to 172.16.0.10
// address-pool Single-IP-Pool address 192.168.1.1`,
// 			expectedPools: map[string]string{
// 				"Range-Pool":     "172.16.0.1-172.16.0.10",
// 				"Single-IP-Pool": "192.168.1.1",
// 			},
// 			expectedErrors: 0,
// 		},
// 		{
// 			name:           "Invalid pool configuration",
// 			config:         `address-pool Invalid-Pool address invalid-ip`,
// 			expectedPools:  map[string]string{},
// 			expectedErrors: 1,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			dos := NewDptechObjectSet()
// 			result := parse.NewParseResult()

// 			dos.parsePools(tt.config, result)

// 			assert.Equal(t, tt.expectedErrors, len(result.Errors), "Unexpected number of errors")

// 			for poolName, expectedRange := range tt.expectedPools {
// 				pool, ok := dos.poolMap[firewall.DYNAMIC_NAT][poolName]
// 				assert.True(t, ok, "Pool %s not found", poolName)
// 				if ok {
// 					assert.Equal(t, poolName, pool.Name(), "Pool name mismatch")
// 					assert.Equal(t, firewall.DYNAMIC_NAT, pool.(*NatPool).NatType(), "NAT type mismatch")

// 					expectedNetwork, _ := network.NewNetworkGroupFromString(expectedRange)
// 					assert.True(t, expectedNetwork.Same(pool.Network(nil)), "Network range mismatch for pool %s", poolName)
// 				}
// 			}
// 		})
// 	}
// }

// func TestNatsParseConfig(t *testing.T) {
// 	config := `
// nat source-nat NAT_DCN-to-DMZ_dynamic interface bond11
// nat source-nat NAT_DCN-to-DMZ_dynamic src-address 192.168.1.0/24
// nat source-nat NAT_DCN-to-DMZ_dynamic dst-address 10.0.0.0/8
// nat source-nat NAT_DCN-to-DMZ_dynamic action address-pool SNAT_pool1
// nat static-nat STATIC_NAT_1 interface eth0
// nat static-nat STATIC_NAT_1 global-address 203.0.113.1
// nat static-nat STATIC_NAT_1 local-address 192.168.1.10
// nat destination-nat DNAT_WEB interface eth1
// nat destination-nat DNAT_WEB dst-address 203.0.113.2
// nat destination-nat DNAT_WEB action dnat ip-address 192.168.1.20 local-port 80
// `

// 	nats := &Nats{
// 		objects:             NewDptechObjectSet(),
// 		node:                &DptechNode{},
// 		staticNatRules:      map[string]*NatRuleSet{},
// 		sourceNatRules:      map[string]*NatRuleSet{},
// 		destinationNatRules: map[string]*NatRuleSet{},
// 	}

// 	err := nats.parseConfig(config)
// 	assert.NoError(t, err)

// 	// Test source NAT
// 	assert.Contains(t, nats.sourceNatRules, "NAT_DCN-to-DMZ_dynamic")
// 	sourceNat := nats.sourceNatRules["NAT_DCN-to-DMZ_dynamic"]
// 	assert.Equal(t, firewall.DYNAMIC_NAT, sourceNat.natType)
// 	assert.Len(t, sourceNat.rules, 1)
// 	assert.Contains(t, sourceNat.rules[0].from, "bond11")

// 	// Test static NAT
// 	assert.Contains(t, nats.staticNatRules, "STATIC_NAT_1")
// 	staticNat := nats.staticNatRules["STATIC_NAT_1"]
// 	assert.Equal(t, firewall.STATIC_NAT, staticNat.natType)
// 	assert.Len(t, staticNat.rules, 1)
// 	assert.Equal(t, staticNat.rules[0].from, "eth0")

// 	// Test destination NAT
// 	assert.Contains(t, nats.destinationNatRules, "DNAT_WEB")
// 	destNat := nats.destinationNatRules["DNAT_WEB"]
// 	assert.Equal(t, firewall.DESTINATION_NAT, destNat.natType)
// 	assert.Len(t, destNat.rules, 1)
// 	assert.Equal(t, destNat.rules[0].from, "eth1")
// }

// // nat source-nat 1 interface tengige0_2
// // nat source-nat 1 src-address any
// // nat source-nat 1 dst-address any
// // nat source-nat 1 service any
// // nat source-nat 1 action use-interface
// // nat source-nat 1 port 1500 to 65535
// // nat source-nat NAT_DCN-to-DMZ_dynamic interface bond11
// // nat source-nat NAT_DCN-to-DMZ_dynamic src-address address-object 192.168.0.0/16
// // nat source-nat NAT_DCN-to-DMZ_dynamic dst-address address-object DCN_132.224.0.0/11
// // nat source-nat NAT_DCN-to-DMZ_dynamic dst-address address-object DCN_10.0.0.0/8
// // nat source-nat NAT_DCN-to-DMZ_dynamic service any
// // nat source-nat NAT_DCN-to-DMZ_dynamic action address-pool Dynamic-PAT-DMZ-IN-DCN-Address-Pool
// // nat source-nat NAT_DCN-to-DMZ_dynamic port 1500 to 65535
// // nat destination-nat DCN_SSLVPN_TEST05 interface bond12 global-address 192.168.6.8 service icmp tcp 9441 to 9441 local-address                            132.252.138.226 to 132.252.138.226 local-port 441
// // nat destination-nat DCN_SSLVPN_TEST01 interface bond12 global-address 192.168.6.8 service icmp tcp 443 to 443 local-address 13                           2.252.197.183 to 132.252.197.183 local-port 443
// // nat destination-nat DCN_SSLVPN_TEST02 interface bond12 global-address 192.168.6.8 service icmp tcp 8443 to 8443 local-address                            132.252.197.184 to 132.252.197.184 local-port 443
// // nat destination-nat DCN_SSLVPN_TEST03 interface bond12 global-address 192.168.6.8 service icmp tcp 8441 to 8441 local-address                            132.252.197.184 to 132.252.197.184 local-port 441
// // nat destination-nat DCN_SSLVPN_TEST04 interface bond12 global-address 192.168.6.8 service icmp tcp 9443 to 9443 local-address 132.252.138.226 to 132.252.138.226 local-port 443
// // nat static DMZ_YZ_Telecom_report_robot_system interface bond11 global-address 132.252.45.11 local-address 192.168.21.10
// // nat static DMZ_YDOA01 interface bond11 global-address 132.252.45.10 local-address 192.168.22.10
// // nat static DMZ_MSS_U_Server01 interface bond11 global-address 132.252.45.12 local-address 192.168.22.100
// // nat static DMZ_MSS_U_Server02 interface bond11 global-address 132.252.45.13 local-address 192.168.22.101
// // nat static DMZ_MSS_VAT_Manage01 interface bond11 global-address 132.252.45.14 local-address 192.168.22.104
// // nat static DMZ_MSS_Code interface bond11 global-address 132.252.45.15 local-address 192.168.22.82

// func TestNatsParseRuleSet(t *testing.T) {
// 	config := `
// nat source-nat NAT_1 interface eth0
// nat source-nat NAT_1 src-address 192.168.1.0/24
// nat static STATIC_1 interface eth1
// nat static STATIC_1 global-address 203.0.113.1
// `

// 	nats := &Nats{}
// 	ruleSets, err := nats.parseRuleSet(config)
// 	assert.NoError(t, err)

// 	assert.Len(t, ruleSets, 2)
// 	assert.Equal(t, firewall.DYNAMIC_NAT, ruleSets[0].natType)
// 	assert.Equal(t, "NAT_1", ruleSets[0].name)
// 	assert.Equal(t, firewall.STATIC_NAT, ruleSets[1].natType)
// 	assert.Equal(t, "STATIC_1", ruleSets[1].name)
// }

// func TestNatsParseStaticNat(t *testing.T) {
// 	ruleSet := &NatRuleSet{
// 		natType: firewall.STATIC_NAT,
// 		name:    "STATIC_1",
// 		configs: []string{
// 			"nat static STATIC_1 interface eth0 eth1 eth2 global-address 203.0.113.1 local-address 192.168.1.10",
// 		},
// 	}

// 	nats := &Nats{
// 		objects:        NewDptechObjectSet(),
// 		node:           &DptechNode{},
// 		staticNatRules: map[string]*NatRuleSet{},
// 	}

// 	err := nats.parseStaticNat(ruleSet)
// 	assert.NoError(t, err)

// 	assert.Contains(t, nats.staticNatRules, "STATIC_1")
// 	staticNat := nats.staticNatRules["STATIC_1"]
// 	assert.Len(t, staticNat.rules, 1)
// 	assert.Contains(t, staticNat.rules[0].from, "eth0")
// 	assert.Equal(t, "203.0.113.1/32", staticNat.rules[0].translate.(*policy.PolicyEntry).Src().String())
// 	assert.Equal(t, "192.168.1.10/32", staticNat.rules[0].orignal.(*policy.PolicyEntry).Dst().String())
// }

// func TestNatsParseSourceNat(t *testing.T) {
// 	ruleSet := &NatRuleSet{
// 		natType: firewall.DYNAMIC_NAT,
// 		name:    "NAT_1",
// 		configs: []string{
// 			"nat source-nat NAT_1 interface eth0",
// 			"nat source-nat NAT_1 src-address address-object 192.168.1.0/24",
// 			"nat source-nat NAT_1 dst-address address-object 10.0.0.0/8",
// 			"nat source-nat NAT_1 action address-pool SNAT_pool1",
// 		},
// 	}

// 	objects := NewDptechObjectSet()

// 	// 创建一个地址池
// 	poolNetwork, _ := network.NewNetworkGroupFromString("172.16.0.1-172.16.0.10")
// 	pool := &NatPool{
// 		name:    "SNAT_pool1",
// 		network: poolNetwork,
// 		natType: firewall.DYNAMIC_NAT,
// 	}
// 	objects.poolMap[firewall.DYNAMIC_NAT] = map[string]firewall.FirewallNetworkObject{
// 		"SNAT_pool1": pool,
// 	}

// 	nats := &Nats{
// 		objects:        objects,
// 		node:           &DptechNode{},
// 		sourceNatRules: map[string]*NatRuleSet{},
// 	}

// 	// 添加必要的网络和服务对象
// 	internalNet, _ := network.NewNetworkGroupFromString("192.168.1.0/24")
// 	externalNet, _ := network.NewNetworkGroupFromString("10.0.0.0/8")
// 	// httpService, _ := service.NewServiceWithL4("tcp", "", "80")

// 	objects.addressObjectSet["192.168.1.0/24"] = &DptechNetwork{
// 		catagory: firewall.OBJECT_NETWORK,
// 		name:     "192.168.1.0/24",
// 		network:  internalNet,
// 	}

// 	objects.addressObjectSet["10.0.0.0/8"] = &DptechNetwork{
// 		catagory: firewall.OBJECT_NETWORK,
// 		name:     "10.0.0.0/8",
// 		network:  externalNet,
// 	}

// 	// objects.serviceMap["HTTP"] = &DptechService{
// 	// 	catagory: firewall.OBJECT_SERVICE,
// 	// 	name:     "HTTP",
// 	// 	service:  httpService,
// 	// }

// 	err := nats.parseSourceNat(ruleSet)
// 	assert.NoError(t, err)

// 	assert.Contains(t, nats.sourceNatRules, "NAT_1")
// 	sourceNat := nats.sourceNatRules["NAT_1"]
// 	assert.Len(t, sourceNat.rules, 1)
// 	assert.Contains(t, sourceNat.rules[0].from, "eth0")
// 	assert.Equal(t, "192.168.1.0/24", sourceNat.rules[0].orignal.(*policy.PolicyEntry).Src().String())
// 	assert.Equal(t, "10.0.0.0/8", sourceNat.rules[0].orignal.(*policy.PolicyEntry).Dst().String())

// 	// 测试地址池是否被正确应用
// 	assert.Equal(t, "172.16.0.1-172.16.0.10", sourceNat.rules[0].translate.(*policy.PolicyEntry).Src().String())
// }

// func TestNatsParseDestinationNat(t *testing.T) {
// 	ruleSet := &NatRuleSet{
// 		natType: firewall.DESTINATION_NAT,
// 		name:    "DNAT_1",
// 		configs: []string{
// 			"nat destination-nat DNAT_1 interface bond12 global-address 1.1.1.1 service ftp http tcp 8888 tcp 1000 to 1003 local-address 132.252.138.226 to 132.252.138.226 local-port 5555",
// 		},
// 	}

// 	nats := &Nats{
// 		objects:             NewDptechObjectSet(),
// 		node:                &DptechNode{},
// 		destinationNatRules: map[string]*NatRuleSet{},
// 	}

// 	err := nats.parseDestinationNat(ruleSet)
// 	assert.NoError(t, err)

// 	assert.Contains(t, nats.destinationNatRules, "DNAT_1")
// 	destNat := nats.destinationNatRules["DNAT_1"]
// 	assert.Len(t, destNat.rules, 1)
// 	assert.Contains(t, destNat.rules[0].from, "bond12")
// 	assert.Equal(t, "1.1.1.1/32", destNat.rules[0].orignal.(*policy.PolicyEntry).Dst().String())
// 	assert.Equal(t, "132.252.138.226-132.252.138.226", destNat.rules[0].translate.(*policy.PolicyEntry).Dst().String())
// 	// You might need to add a test for the local port, depending on how it's implemented
// }

// func TestPolicyParse(t *testing.T) {
// 	config := `security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST src-address address-object INTERNAL_NET
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST dst-address address-object EXTERNAL_NET
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST service service-object HTTP
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST action permit`

// 	node := &DptechNode{}
// 	objects := NewDptechObjectSet()

// 	plc := &Policy{
// 		objects: objects,
// 		node:    node,
// 	}

// 	// 添加必要的网络和服务对象
// 	internalNet, _ := network.NewNetworkGroupFromString("192.168.1.0/24")
// 	externalNet, _ := network.NewNetworkGroupFromString("10.0.0.0/8")
// 	httpService, _ := service.NewServiceWithL4("tcp", "", "80")

// 	objects.addressObjectSet["INTERNAL_NET"] = &DptechNetwork{
// 		catagory: firewall.OBJECT_NETWORK,
// 		name:     "INTERNAL_NET",
// 		network:  internalNet,
// 	}

// 	objects.addressObjectSet["EXTERNAL_NET"] = &DptechNetwork{
// 		catagory: firewall.OBJECT_NETWORK,
// 		name:     "EXTERNAL_NET",
// 		network:  externalNet,
// 	}

// 	objects.serviceMap["HTTP"] = &DptechService{
// 		catagory: firewall.OBJECT_SERVICE,
// 		name:     "HTTP",
// 		service:  httpService,
// 	}

// 	err := plc.parsePolicy(config)
// 	assert.NoError(t, err)

// 	assert.Equal(t, "POLICY_1", plc.Name())
// 	assert.Equal(t, firewall.POLICY_PERMIT, plc.Action())

// 	pe := plc.PolicyEntry().(*policy.PolicyEntry)
// 	assert.Equal(t, "192.168.1.0/24", pe.Src().String())
// 	assert.Equal(t, "10.0.0.0/8", pe.Dst().String())
// 	assert.Equal(t, "TCP:--|80", pe.Service().String())

// 	// // 检查是否正确添加了端口
// 	// _, exists := node.Ports()["TRUST"]
// 	// assert.True(t, exists)
// 	// _, exists = node.Ports()["UNTRUST"]
// 	// assert.True(t, exists)
// }

// func TestPolicySetParseConfig(t *testing.T) {
// 	config := `
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST src-address address-object INTERNAL_NET
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST src-address 1.1.1.1 mask 255.255.255.255
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST src-address 192.168.1.0 mask 255.255.255.0
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST dst-address address-object EXTERNAL_NET
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST service service-object HTTP
// security-policy POLICY_1 src-zone TRUST dst-zone UNTRUST action permit
// security-policy POLICY_2 src-zone TRUST dst-zone DMZ src-address address-object INTERNAL_NET
// security-policy POLICY_2 src-zone TRUST dst-zone DMZ dst-address address-object DMZ_SERVERS
// security-policy POLICY_2 src-zone TRUST dst-zone DMZ service service-object HTTPS
// security-policy POLICY_2 src-zone TRUST dst-zone DMZ action permit
// `

// 	node := &DptechNode{}
// 	objects := NewDptechObjectSet()

// 	ps := &PolicySet{
// 		objects:   objects,
// 		node:      node,
// 		policySet: make(map[string]map[string][]*Policy),
// 	}

// 	// 添加必要的网络和服务对象
// 	internalNet, _ := network.NewNetworkGroupFromString("192.168.1.0/24")
// 	externalNet, _ := network.NewNetworkGroupFromString("10.0.0.0/8")
// 	dmzServers, _ := network.NewNetworkGroupFromString("172.16.0.0/24")
// 	httpService, _ := service.NewServiceWithL4("tcp", "", "80")
// 	httpsService, _ := service.NewServiceWithL4("tcp", "", "443")

// 	// 使用 DptechNetwork 和 DptechService 对象
// 	objects.addressObjectSet["INTERNAL_NET"] = &DptechNetwork{
// 		catagory: firewall.OBJECT_NETWORK,
// 		name:     "INTERNAL_NET",
// 		network:  internalNet,
// 	}
// 	objects.addressObjectSet["EXTERNAL_NET"] = &DptechNetwork{
// 		catagory: firewall.OBJECT_NETWORK,
// 		name:     "EXTERNAL_NET",
// 		network:  externalNet,
// 	}
// 	objects.addressObjectSet["DMZ_SERVERS"] = &DptechNetwork{
// 		catagory: firewall.OBJECT_NETWORK,
// 		name:     "DMZ_SERVERS",
// 		network:  dmzServers,
// 	}
// 	objects.serviceMap["HTTP"] = &DptechService{
// 		catagory: firewall.OBJECT_SERVICE,
// 		name:     "HTTP",
// 		service:  httpService,
// 	}
// 	objects.serviceMap["HTTPS"] = &DptechService{
// 		catagory: firewall.OBJECT_SERVICE,
// 		name:     "HTTPS",
// 		service:  httpsService,
// 	}

// 	ps.parseConfig(config)

// 	assert.Len(t, ps.policySet, 1)
// 	assert.Len(t, ps.policySet["TRUST"], 2)
// 	assert.Len(t, ps.policySet["TRUST"]["UNTRUST"], 1)
// 	assert.Len(t, ps.policySet["TRUST"]["DMZ"], 1)

// 	assert.Equal(t, "POLICY_1", ps.policySet["TRUST"]["UNTRUST"][0].Name())
// 	assert.Equal(t, firewall.POLICY_ACTIVE, ps.policySet["TRUST"]["UNTRUST"][0].status)

// 	assert.Equal(t, "POLICY_2", ps.policySet["TRUST"]["DMZ"][0].Name())
// 	assert.Equal(t, firewall.POLICY_ACTIVE, ps.policySet["TRUST"]["DMZ"][0].status)

// 	// // 检查是否正确添加了端口
// 	// _, exists := node.Ports()["TRUST"]
// 	// assert.True(t, exists)
// 	// _, exists = node.Ports()["UNTRUST"]
// 	// assert.True(t, exists)
// 	// _, exists = node.Ports()["DMZ"]
// 	// assert.True(t, exists)
// }

// func TestPolicySetMatch(t *testing.T) {
// 	ps := &PolicySet{
// 		policySet: make(map[string]map[string][]*Policy),
// 	}

// 	policy1 := &Policy{
// 		name:   "POLICY_1",
// 		action: firewall.POLICY_PERMIT,
// 		status: firewall.POLICY_ACTIVE,
// 		from:   []string{"TRUST"},
// 		out:       []string{"UNTRUST"},
// 	}
// 	pe1 := policy.NewPolicyEntry()
// 	pe1.AddSrc(mustNetworkGroup("192.168.1.0/24"))
// 	pe1.AddDst(mustNetworkGroup("10.0.0.0/8"))
// 	pe1.AddService(mustService("80", "tcp"))
// 	policy1.policyEntry = pe1

// 	ps.addPolicy(policy1)

// 	// Test matching policy
// 	matchPE := policy.NewPolicyEntry()
// 	matchPE.AddSrc(mustNetworkGroup("192.168.1.100/32"))
// 	matchPE.AddDst(mustNetworkGroup("10.0.0.1/32"))
// 	matchPE.AddService(mustService("80", "tcp"))

// 	matched, matchedPolicy := ps.Match("TRUST", "UNTRUST", matchPE)
// 	assert.True(t, matched)
// 	assert.Equal(t, "POLICY_1", matchedPolicy.Name())

// 	// Test non-matching policy
// 	nonMatchPE := policy.NewPolicyEntry()
// 	nonMatchPE.AddSrc(mustNetworkGroup("172.16.0.0/16"))
// 	nonMatchPE.AddDst(mustNetworkGroup("10.0.0.1/32"))
// 	nonMatchPE.AddService(mustService("80", "tcp"))

// 	matched, matchedPolicy = ps.Match("TRUST", "UNTRUST", nonMatchPE)
// 	assert.False(t, matched)
// 	assert.Nil(t, matchedPolicy)
// }

// // func mustNetworkGroup(s string) *network.NetworkGroup {
// // 	ng, err := network.NewNetworkGroupFromString(s)
// // 	if err != nil {
// // 		panic(err)
// // 	}
// // 	return ng
// // }

// // func mustService(port, protocol string) *service.Service {
// // 	s, err := service.NewServiceWithL4(protocol, port, "")
// // 	if err != nil {
// // 		panic(err)
// // 	}
// // 	return s
// // }
