package nodemap_test

import (
	"encoding/json"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/tests/fixtures"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeMapMarshalJSON(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	node1 := fixtures.NewTestNode("node1", api.ROUTER)
	port1 := fixtures.NewTestPort("port1", "vrf1", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	})
	node1.AddPort(port1, nil)
	nm.AddNode(node1, nil)
	nm.Ports = append(nm.Ports, port1)

	data, err := json.Marshal(nm)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestNodeMapUnmarshalJSON(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	node1 := fixtures.NewTestNode("node1", api.ROUTER)
	port1 := fixtures.NewTestPort("port1", "vrf1", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	})
	node1.AddPort(port1, nil)
	nm.AddNode(node1, nil)
	nm.Ports = append(nm.Ports, port1)

	// 序列化
	data, err := json.Marshal(nm)
	require.NoError(t, err)

	// 反序列化
	var deserializedNM nodemap.NodeMap
	err = json.Unmarshal(data, &deserializedNM)
	require.NoError(t, err)

	assert.Equal(t, nm.Name, deserializedNM.Name)
	assert.Equal(t, len(nm.Nodes), len(deserializedNM.Nodes))
	assert.Equal(t, len(nm.Ports), len(deserializedNM.Ports))
}
