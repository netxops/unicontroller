package nodemap_test

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/tests/fixtures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeMapCreation(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	assert.NotNil(t, nm)
	assert.Equal(t, "TestNodeMap", nm.Name)
	assert.NotNil(t, nm.CxMananger)
}

func TestNodeMapAddNode(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	node1 := fixtures.NewTestNode("node1", api.ROUTER)
	node2 := fixtures.NewTestNode("node2", api.FIREWALL)

	nm.AddNode(node1, nil)
	nm.AddNode(node2, nil)

	assert.Equal(t, 2, len(nm.Nodes))
	assert.Equal(t, "node1", nm.Nodes[0].Name())
	assert.Equal(t, "node2", nm.Nodes[1].Name())
}

func TestNodeMapGetNode(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	node1 := fixtures.NewTestNode("node1", api.ROUTER)
	nm.AddNode(node1, nil)

	retrievedNode := nm.GetNode("node1")
	require.NotNil(t, retrievedNode)
	assert.Equal(t, "node1", retrievedNode.Name())

	nonExistentNode := nm.GetNode("non-existent")
	assert.Nil(t, nonExistentNode)
}

func TestNodeMapGetPort(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	port1 := fixtures.NewTestPort("port1", "vrf1", nil)
	nm.Ports = append(nm.Ports, port1)

	retrievedPort := nm.GetPort(port1.ID())
	require.NotNil(t, retrievedPort)
	assert.Equal(t, "port1", retrievedPort.Name())
}
