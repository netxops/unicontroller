package nodemap

import (
	"fmt"

	"github.com/netxops/utils/graph"
)

// 实现graph.Vertex接口
func (tn *TraverseNode) Key() interface{} {
	// return tn.Node.FlattenName()
	return fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
}

func (tn *TraverseNode) Vertices(key interface{}) graph.Vertex {
	return tn.Neighbor[key]
}

func (tn *TraverseNode) AddVertex(other graph.Vertex) {
	tn.Neighbor[other.Key()] = other
}

func (tn *TraverseNode) Iterator() *graph.VertexIterator {
	keyList := []interface{}{}
	for k := range tn.Neighbor {
		keyList = append(keyList, k)
	}

	it := graph.VertexIterator{
		V:       tn,
		KeyList: keyList,
	}
	return &it
}
