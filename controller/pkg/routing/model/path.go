package model

import (
	"fmt"
	"strings"
	"time"
)

// PathResult 路径查询结果
type PathResult struct {
	PathID    string
	Success   bool
	Hops      []*PathHop
	TotalHops int
	IsECMP    bool
	Error     error
	Metadata  map[string]interface{}
	StartTime time.Time
	EndTime   time.Time
}

// PathHop 路径跳
type PathHop struct {
	Node        string
	InPort      string
	OutPort     string
	VRF         string
	NextHopIP   string
	IsConnected bool
	IsECMP      bool
	HopIndex    int // 跳索引（从0开始）
}

// NewPathResult 创建路径结果
func NewPathResult(pathID string) *PathResult {
	return &PathResult{
		PathID:    pathID,
		Hops:      []*PathHop{},
		Metadata:  make(map[string]interface{}),
		StartTime: time.Now(),
	}
}

// AddHop 添加路径跳
func (pr *PathResult) AddHop(hop *PathHop) {
	hop.HopIndex = len(pr.Hops)
	pr.Hops = append(pr.Hops, hop)
	pr.TotalHops = len(pr.Hops)
}

// Complete 完成路径
func (pr *PathResult) Complete(success bool, err error) {
	pr.Success = success
	pr.Error = err
	pr.EndTime = time.Now()
}

// PathString 返回路径字符串表示
func (pr *PathResult) PathString() string {
	if len(pr.Hops) == 0 {
		return ""
	}
	
	var path []string
	for _, hop := range pr.Hops {
		if hop.OutPort != "" {
			path = append(path, fmt.Sprintf("%s:%s->%s", hop.Node, hop.InPort, hop.OutPort))
		} else {
			path = append(path, fmt.Sprintf("%s:%s", hop.Node, hop.InPort))
		}
	}
	return strings.Join(path, " -> ")
}

