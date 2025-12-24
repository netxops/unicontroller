package firewall

import (
	"sync"

	"github.com/netxops/utils/network"
)

type Namer interface {
	Name() string
}

type NamerIterator interface {
	HasNext() bool
	Next() Namer
	Reset()
}

// BaseIterator 是一个通用的基础迭代器结构
type BaseIterator struct {
	items      []Namer
	options    *IteratorOptions
	index      int
	filterFunc func(Namer, *IteratorOptions) bool
	mu         sync.Mutex
}

// NewBaseIterator 创建一个新的基础迭代器

func NewBaseIterator(items []Namer, options *IteratorOptions, filterFunc func(Namer, *IteratorOptions) bool) *BaseIterator {
	return &BaseIterator{
		items:      items,
		options:    options,
		filterFunc: filterFunc,
	}
}

// HasNext 检查是否还有下一个元素
func (bi *BaseIterator) HasNext() bool {
	// bi.mu.Lock()
	// defer bi.mu.Unlock()

	for bi.index < len(bi.items) {
		if bi.filterFunc == nil || bi.filterFunc(bi.items[bi.index], bi.options) {
			return true
		}
		bi.index++
	}
	return false
}

// Next 返回下一个元素
func (bi *BaseIterator) Next() Namer {
	// bi.mu.Lock()
	// defer bi.mu.Unlock()

	if !bi.HasNext() {
		return nil
	}
	item := bi.items[bi.index]
	bi.index++
	return item
}

func (bi *BaseIterator) Reset() {
	bi.mu.Lock()
	bi.index = 0
	bi.mu.Unlock()
}

// IteratorOptions 结构体定义
type IteratorOptions struct {
	Zone         string
	IPFamily     network.IPFamily
	Protocol     int
	FromZone     string
	ToZone       string
	NatType      NatType
	NetworkGroup *network.NetworkGroup
	AclType      string
}

// 通用的 IteratorOption 函数
func WithZone(zone string) IteratorOption {
	return func(o interface{}) {
		o.(*IteratorOptions).Zone = zone
	}
}

func WithIPFamily(family network.IPFamily) IteratorOption {
	return func(o interface{}) {
		o.(*IteratorOptions).IPFamily = family
	}
}

func WithProtocol(protocol int) IteratorOption {
	return func(o interface{}) {
		o.(*IteratorOptions).Protocol = protocol
	}
}

func WithFromZone(zone string) IteratorOption {
	return func(o interface{}) {
		o.(*IteratorOptions).FromZone = zone
	}
}

func WithToZone(zone string) IteratorOption {
	return func(o interface{}) {
		o.(*IteratorOptions).ToZone = zone
	}
}

func WithNatType(natType NatType) IteratorOption {
	return func(o interface{}) {
		o.(*IteratorOptions).NatType = natType
	}
}

func WithNetworkGroup(ng *network.NetworkGroup) IteratorOption {
	return func(o interface{}) {
		o.(*IteratorOptions).NetworkGroup = ng
	}
}

func WithAclType(aclType string) IteratorOption {
	return func(o interface{}) {
		o.(*IteratorOptions).AclType = aclType
	}
}

func ApplyOptions(opts ...IteratorOption) *IteratorOptions {
	options := &IteratorOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return options
}

// // SetFilterFunc 设置过滤函数
// func (bi *BaseIterator) SetFilterFunc(filterFunc func(Namer, map[string]interface{}) bool) {
// 	bi.filterFunc = filterFunc
// }

// // AddOption 添加一个选项
// func (bi *BaseIterator) AddOption(key string, value interface{}) {
// 	bi.options[key] = value
// }

// // PolicyIterator 策略迭代器
// type PolicyIterator struct {
// 	*BaseIterator
// }

// func NewPolicyIterator(policies []FirewallPolicy, opts ...IteratorOption) *PolicyIterator {
// 	items := make([]Namer, len(policies))
// 	for i, p := range policies {
// 		items[i] = p
// 	}

// 	options := make(map[string]interface{})
// 	for _, opt := range opts {
// 		opt(options)
// 	}

// 	return &PolicyIterator{
// 		BaseIterator: NewBaseIterator(items, options, policyFilter),
// 	}
// }

// func policyFilter(item Namer, options map[string]interface{}) bool {
// 	// policy, ok := item.(FirewallPolicy)
// 	// if !ok {
// 	// 	return false
// 	// }
// 	// 实现策略过滤逻辑
// 	// 例如：检查 Zone、IPFamily 等
// 	return true // 根据实际情况返回
// }
