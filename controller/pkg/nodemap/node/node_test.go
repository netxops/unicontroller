package node

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
)

func TestDeviceNodeJSONSerialization(t *testing.T) {
	// 创建一个测试用的 DeviceNode 实例
	originalNode := &DeviceNode{
		id:   "test-id",
		name: "test-node",
		vrfs: []api.Vrf{
			&NodeVrf{
				name:      "default",
				ipv4Table: network.NewAddressTable(network.IPv4),
				ipv6Table: network.NewAddressTable(network.IPv6),
			},
		},
		portRefs:    []string{"eth0"}, // 使用 portRefs 替代 portList
		NodeMapName: "test-nodemap",
		cmdIp:       "10.0.0.1",
		nodeType:    api.ROUTER,
		DeviceConfig: &config.DeviceConfig{
			Host: "10.0.0.1",
			Port: 22,
		},
	}

	// 创建一个模拟的 PortIterator
	mockPortIterator := &MockPortIterator{
		ports: []api.Port{
			&NodePort{
				id:       "port-id",
				PortName: "eth0",
				IpList: map[network.IPFamily][]string{
					network.IPv4: {"192.168.1.1/24"},
				},
				PortVrf: "default",
			},
		},
	}
	originalNode.WithPortIterator(mockPortIterator)

	// 序列化
	jsonData, err := json.Marshal(originalNode)
	assert.NoError(t, err)
	fmt.Println("Serialized JSON:", string(jsonData))

	// 反序列化
	var newNode DeviceNode
	err = json.Unmarshal(jsonData, &newNode)
	assert.NoError(t, err)

	// 验证字段
	assert.Equal(t, originalNode.id, newNode.id)
	assert.Equal(t, originalNode.name, newNode.name)
	assert.Equal(t, originalNode.NodeMapName, newNode.NodeMapName)
	assert.Equal(t, originalNode.cmdIp, newNode.cmdIp)
	assert.Equal(t, originalNode.nodeType, newNode.nodeType)

	// 验证VRF
	assert.Equal(t, len(originalNode.vrfs), len(newNode.vrfs))
	if len(newNode.vrfs) > 0 {
		assert.Equal(t, originalNode.vrfs[0].Name(), newNode.vrfs[0].Name())
		assert.NotNil(t, newNode.vrfs[0].(*NodeVrf).ipv4Table)
		assert.NotNil(t, newNode.vrfs[0].(*NodeVrf).ipv6Table)
	}

	// 验证端口引用
	assert.Equal(t, originalNode.portRefs, newNode.portRefs)

	// 验证设备配置
	assert.Equal(t, originalNode.DeviceConfig.Host, newNode.DeviceConfig.Host)
	assert.Equal(t, originalNode.DeviceConfig.Port, newNode.DeviceConfig.Port)

	// 注意：我们不能直接验证 PortIterator，因为它不会被序列化
	// 但是我们可以确保 portRefs 被正确序列化和反序列化
}

// MockPortIterator 是一个用于测试的 PortIterator 实现
type MockPortIterator struct {
	ports []api.Port
}

func (m *MockPortIterator) GetPort(ref string) api.Port {
	for _, port := range m.ports {
		if port.ID() == ref {
			return port
		}
	}
	return nil
}

func (m *MockPortIterator) GetAllPorts() []api.Port {
	return m.ports
}

func TestNodeVrfJSONSerialization(t *testing.T) {
	// 创建一个测试用的 NodeVrf 实例
	originalVrf := &NodeVrf{
		name:      "test-vrf",
		ipv4Table: network.NewAddressTable(network.IPv4),
		ipv6Table: network.NewAddressTable(network.IPv6),
	}

	// 测试 MarshalJSON
	jsonData, err := json.Marshal(originalVrf)
	assert.NoError(t, err)

	// 验证序列化后的 JSON 数据
	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonData, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, "test-vrf", unmarshaled["name"])
	assert.NotNil(t, unmarshaled["ipv4Table"])
	assert.NotNil(t, unmarshaled["ipv6Table"])

	// 测试 UnmarshalJSON
	var newVrf NodeVrf
	err = json.Unmarshal(jsonData, &newVrf)
	assert.NoError(t, err)

	// 验证反序列化后的结构体
	assert.Equal(t, originalVrf.name, newVrf.name)
	assert.NotNil(t, newVrf.ipv4Table)
	assert.NotNil(t, newVrf.ipv6Table)
	assert.Equal(t, network.IPv4, newVrf.ipv4Table.Type())
	assert.Equal(t, network.IPv6, newVrf.ipv6Table.Type())

	// 测试空 VRF 的序列化和反序列化
	emptyVrf := &NodeVrf{}
	jsonData, err = json.Marshal(emptyVrf)
	assert.NoError(t, err)

	var emptyUnmarshaled NodeVrf
	err = json.Unmarshal(jsonData, &emptyUnmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, "", emptyUnmarshaled.name)
	assert.Nil(t, emptyUnmarshaled.ipv4Table)
	assert.Nil(t, emptyUnmarshaled.ipv6Table)
}
