package node

// import (
// 	"encoding/json"
// 	"reflect"
// 	"testing"

// 	"github.com/stretchr/testify/assert"
// )

// // 为测试创建一些模拟类型
// type MockVrf struct {
// 	Name string
// }

// func (m MockVrf) VrfName() string  { return m.Name }
// func (m MockVrf) TypeName() string { return "MockVrf" }

// type MockPort struct {
// 	Name string
// 	Type string
// }

// func (m MockPort) PortName() string { return m.Name }
// func (m MockPort) PortType() string { return m.Type }
// func (m MockPort) TypeName() string { return "MockPort" }

// // 测试 InterfaceRegistry
// func TestInterfaceRegistry(t *testing.T) {
// 	registry := NewInterfaceRegistry()

// 	// 注册类型
// 	vrfType := reflect.TypeOf((*MockVrf)(nil)).Elem()
// 	portType := reflect.TypeOf((*MockPort)(nil)).Elem()

// 	registry.RegisterType(vrfType, "MockVrf", reflect.TypeOf(MockVrf{}))
// 	registry.RegisterType(portType, "MockPort", reflect.TypeOf(MockPort{}))

// 	// 测试 GetType
// 	t.Run("GetType", func(t *testing.T) {
// 		gotType, ok := registry.GetType(vrfType, "MockVrf")
// 		assert.True(t, ok)
// 		assert.Equal(t, reflect.TypeOf(MockVrf{}), gotType)

// 		gotType, ok = registry.GetType(portType, "MockPort")
// 		assert.True(t, ok)
// 		assert.Equal(t, reflect.TypeOf(MockPort{}), gotType)

// 		_, ok = registry.GetType(vrfType, "UnknownType")
// 		assert.False(t, ok)
// 	})
// }

// // 测试 interfacesToRawMessages
// func TestInterfacesToRawMessages(t *testing.T) {
// 	vrfs := []MockVrf{
// 		{Name: "VRF1"},
// 		{Name: "VRF2"},
// 	}

// 	rawMessages, err := InterfacesToRawMessages(vrfs)
// 	assert.NoError(t, err)
// 	assert.Len(t, rawMessages, 2)

// 	for i, raw := range rawMessages {
// 		var wrapper struct {
// 			Type string
// 			Data json.RawMessage
// 		}
// 		err := json.Unmarshal(raw, &wrapper)
// 		assert.NoError(t, err)
// 		assert.Equal(t, "MockVrf", wrapper.Type)

// 		var vrf MockVrf
// 		err = json.Unmarshal(wrapper.Data, &vrf)
// 		assert.NoError(t, err)
// 		assert.Equal(t, vrfs[i].Name, vrf.Name)
// 	}
// }

// // 测试 rawMessagesToInterfaces
// func TestRawMessagesToInterfaces(t *testing.T) {
// 	// 首先注册类型
// 	registry := NewInterfaceRegistry()
// 	registry.RegisterType(reflect.TypeOf((*MockVrf)(nil)).Elem(), "MockVrf", reflect.TypeOf(MockVrf{}))
// 	registry.RegisterType(reflect.TypeOf((*MockPort)(nil)).Elem(), "MockPort", reflect.TypeOf(MockPort{}))

// 	rawVrfs := []json.RawMessage{
// 		json.RawMessage(`{"Type":"MockVrf","Data":{"Name":"VRF1"}}`),
// 		json.RawMessage(`{"Type":"MockVrf","Data":{"Name":"VRF2"}}`),
// 	}

// 	vrfs, err := RawMessagesToInterfaces[MockVrf](rawVrfs)
// 	assert.NoError(t, err)
// 	assert.Len(t, vrfs, 2)
// 	assert.Equal(t, "VRF1", vrfs[0].Name)
// 	assert.Equal(t, "VRF2", vrfs[1].Name)

// 	rawPorts := []json.RawMessage{
// 		json.RawMessage(`{"Type":"MockPort","Data":{"Name":"Port1","Type":"Ethernet"}}`),
// 		json.RawMessage(`{"Type":"MockPort","Data":{"Name":"Port2","Type":"Fiber"}}`),
// 	}

// 	ports, err := RawMessagesToInterfaces[MockPort](rawPorts)
// 	assert.NoError(t, err)
// 	assert.Len(t, ports, 2)
// 	assert.Equal(t, "Port1", ports[0].Name)
// 	assert.Equal(t, "Ethernet", ports[0].Type)
// 	assert.Equal(t, "Port2", ports[1].Name)
// 	assert.Equal(t, "Fiber", ports[1].Type)
// }

// // 测试序列化和反序列化的完整流程
// func TestSerializationDeserialization(t *testing.T) {
// 	// 注册类型
// 	registry := NewInterfaceRegistry()
// 	registry.RegisterType(reflect.TypeOf((*MockVrf)(nil)).Elem(), "MockVrf", reflect.TypeOf(MockVrf{}))
// 	registry.RegisterType(reflect.TypeOf((*MockPort)(nil)).Elem(), "MockPort", reflect.TypeOf(MockPort{}))

// 	originalVrfs := []MockVrf{
// 		{Name: "VRF1"},
// 		{Name: "VRF2"},
// 	}

// 	// 序列化
// 	rawMessages, err := InterfacesToRawMessages(originalVrfs)
// 	assert.NoError(t, err)

// 	// 反序列化
// 	deserializedVrfs, err := RawMessagesToInterfaces[MockVrf](rawMessages)
// 	assert.NoError(t, err)

// 	// 比较原始数据和反序列化后的数据
// 	assert.Equal(t, originalVrfs, deserializedVrfs)
// }

// // 测试错误处理
// func TestErrorHandling(t *testing.T) {
// 	t.Run("UnknownType", func(t *testing.T) {
// 		rawMessages := []json.RawMessage{
// 			json.RawMessage(`{"Type":"UnknownType","Data":{}}`),
// 		}

// 		_, err := RawMessagesToInterfaces[MockVrf](rawMessages)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "unknown type")
// 	})

// 	t.Run("InvalidJSON", func(t *testing.T) {
// 		rawMessages := []json.RawMessage{
// 			json.RawMessage(`{"Type":"MockVrf","Data":invalid_json}`),
// 		}

// 		_, err := RawMessagesToInterfaces[MockVrf](rawMessages)
// 		assert.Error(t, err)
// 	})
// }
