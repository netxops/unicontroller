package node

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/netxops/utils/network"
	"github.com/tj/assert"
)

func TestNodePortJSONSerialization(t *testing.T) {
	// 创建一个测试用的 NodePort 实例
	testPort := &NodePort{
		id:       "test-id",
		PortName: "eth0",
		Alias:    api.StringList{"alias1", "alias2"},
		IpList: map[network.IPFamily][]string{
			network.IPv4: {"192.168.1.1/24", "10.0.0.1/8"},
			network.IPv6: {"2001:db8::1/64"},
		},
		Tenant:      "test-tenant",
		FhrpMembers: []api.Member{},
		PortVrf:     "default",
		RemoteVrf:   api.StringList{"remote-vrf1", "remote-vrf2"},
		SnmpIfIndex: 1,
		NodeID:      100,
		Connector:   "connector-id",
		PrimaryIpv4: "192.168.1.1",
		PrimaryIpv6: "2001:db8::1",
		Status:      api.DOWN,
	}

	// 测试 MarshalJSON
	t.Run("MarshalJSON", func(t *testing.T) {
		jsonData, err := json.Marshal(testPort)
		assert.NoError(t, err)

		var unmarshaled map[string]interface{}
		fmt.Println(string(jsonData))
		err = json.Unmarshal(jsonData, &unmarshaled)
		assert.NoError(t, err)

		assert.Equal(t, "test-id", unmarshaled["id"])
		assert.Equal(t, "eth0", unmarshaled["port_name"])
		assert.Equal(t, []interface{}{"alias1", "alias2"}, unmarshaled["alias"])
		assert.Contains(t, fmt.Sprintf("%v", unmarshaled["ip_list"]), "192.168.1.1/24")
		assert.Contains(t, fmt.Sprintf("%v", unmarshaled["ip_list"]), "2001:db8::1/64")
		// assert.Contains(t, unmarshaled["fhrp_members"], "192.168.1.2")
	})

	// 测试 UnmarshalJSON
	t.Run("UnmarshalJSON", func(t *testing.T) {
		jsonStr := `
		{
			"port_name": "eth0",
			"alias": [
				"alias1",
				"alias2"
			],
			"ip_list": {
				"0": [
					"192.168.1.1/24",
					"10.0.0.1/8"
				],
				"1": [
					"2001:db8::1/64"
				]
			},
			"ip_list_raw": "",
			"tenant": "test-tenant",
			"fhrp_members": [

			],
			"fhrp_members_raw": "",
			"port_vrf": "default",
			"remote_vrf": [
				"remote-vrf1",
				"remote-vrf2"
			],
			"snmp_if_index": 1,
			"node_id": 100,
			"connector": "connector-id",
			"connector_raw": "",
			"primary_ipv4": "192.168.1.1",
			"primary_ipv6": "2001:db8::1",
			"input_acl": "",
			"output_acl": "",
			"security_level": "",
			"zone_name": "",
			"description": "",
			"status": 1,
			"id": "test-id"
		}
		`
		var newPort NodePort
		err := json.Unmarshal([]byte(jsonStr), &newPort)
		assert.NoError(t, err)

		assert.Equal(t, "test-id", newPort.id)
		assert.Equal(t, "eth0", newPort.PortName)
		assert.Equal(t, api.StringList{"alias1", "alias2"}, newPort.Alias)
		assert.Equal(t, []string{"192.168.1.1/24", "10.0.0.1/8"}, newPort.IpList[network.IPv4])
		assert.Equal(t, []string{"2001:db8::1/64"}, newPort.IpList[network.IPv6])
		assert.Equal(t, "test-tenant", newPort.Tenant)
		assert.Equal(t, 0, len(newPort.FhrpMembers))
		// assert.Equal(t, "172.16.0.2", newPort.FhrpMembers[0].IP)
		assert.Equal(t, "default", newPort.PortVrf)
		assert.Equal(t, api.StringList{"remote-vrf1", "remote-vrf2"}, newPort.RemoteVrf)
		assert.Equal(t, 1, newPort.SnmpIfIndex)
		assert.Equal(t, 100, newPort.NodeID)
		assert.Equal(t, "connector-id", newPort.Connector)
		assert.Equal(t, "192.168.1.1", newPort.PrimaryIpv4)
		assert.Equal(t, "2001:db8::1", newPort.PrimaryIpv6)
		assert.Equal(t, api.DOWN, newPort.Status)
	})
}
