package nodemap

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
)

type StubInfo struct {
	Node api.Node
	Port api.Port
}

// // MarshalJSON implements the json.Marshaler interface
// type stubInfoJSON struct {
//     NodeID string `json:"node_id"`
//     PortID string `json:"port_id"`
// }

// // MarshalJSON implements the json.Marshaler interface
// func (si StubInfo) MarshalJSON() ([]byte, error) {
//     return json.Marshal(stubInfoJSON{
//         NodeID: si.Node.ID(),
//         PortID: si.Port.ID(),
//     })
// }

// // UnmarshalJSON implements the json.Unmarshaler interface
// func (si *StubInfo) UnmarshalJSON(data []byte) error {
//     var aux stubInfoJSON
//     if err := json.Unmarshal(data, &aux); err != nil {
//         return err
//     }

//     // 这里需要一个方法来根据 ID 获取 Node 和 Port 对象
//     // 假设我们有一个全局的 NodeMap 对象可以访问
//     node := globalNodeMap.GetNode(aux.NodeID)
//     if node == nil {
//         return fmt.Errorf("failed to find Node with ID: %s", aux.NodeID)
//     }

//     port := node.GetPortByID(aux.PortID)
//     if port == nil {
//         return fmt.Errorf("failed to find Port with ID: %s in Node %s", aux.PortID, aux.NodeID)
//     }

//     si.Node = node
//     si.Port = port

//     return nil
// }
