package secpath

import (
	"testing"

	"github.com/netxops/utils/service"
	"github.com/netxops/utils/tools"
	"github.com/stretchr/testify/assert"
)

func TestSECPATHNameToService(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		expected    *service.Service
		expectError bool
	}{
		// Protocol tests
		{"TCP Protocol", "tcp", tools.MaybeError(service.NewServiceFromString("tcp")), false},
		{"UDP Protocol", "udp", tools.MaybeError(service.NewServiceFromString("udp")), false},
		{"ICMP Protocol", "icmp", tools.MaybeError(service.NewServiceFromString("icmp")), false},
		{"ICMPv6 Protocol", "icmp6", tools.MaybeError(service.NewServiceFromString("icmp6")), false},
		{"Custom IP Protocol", "ah", tools.MaybeError(service.NewServiceWithProto("51")), false},

		// TCP service tests
		{"HTTP Service", "http", tools.MaybeError(service.NewServiceWithL4("tcp", "0-65535", "80")), false},
		{"HTTPS Service", "https", tools.MaybeError(service.NewServiceWithL4("tcp", "0-65535", "443")), false},

		// UDP service tests
		{"DNS UDP Service", "dns-udp", tools.MaybeError(service.NewServiceWithL4("udp", "0-65535", "53")), false},
		{"SNMP Request", "snmp-request", tools.MaybeError(service.NewServiceWithL4("udp", "0-65535", "161")), false},

		// ICMP type tests
		{"ICMP Echo (Ping)", "ping", tools.MaybeError(service.NewServiceWithIcmp("icmp", 8, service.ICMP_DEFAULT_CODE)), false},
		{"ICMP Timestamp", "icmp-timestamp", tools.MaybeError(service.NewServiceWithIcmp("icmp", 13, service.ICMP_DEFAULT_CODE)), false},

		// ICMPv6 type tests
		// {"ICMPv6 Echo (Ping)", "pingv6", tools.MaybeError(service.NewServiceWithIcmp("icmp6", 128, service.ICMP_DEFAULT_CODE)), false},

		// TCP-UDP combined service tests
		// {"DNS TCP-UDP Service", "dns-tcp", tools.MaybeError(service.NewServiceWithL4("tcp", "0-65535", "53")).Add(service.ServiceEntry(tools.MaybeError(service.NewServiceWithL4("tcp", "0-65535", "53")))), false},

		// Error case
		{"Unknown Service", "unknown-service", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SECPATHNameToService(tt.serviceName)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// assert.(t, tt.expected, result)
				if !tt.expected.Same(result) {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}
