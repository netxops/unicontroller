package fixtures

import (
	"context"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
)

// NewTestPolicyContext 创建测试用的策略上下文
func NewTestPolicyContext() *firewall.PolicyContext {
	return &firewall.PolicyContext{
		Context:            context.Background(),
		Variables:          make(map[string]interface{}),
		DeviceSpecificData: make(map[string]interface{}),
		GeneratedObjects:   make(map[string]interface{}),
	}
}

// NewTestIntent 创建测试用的策略意图
func NewTestIntent(src, dst string) *policy.Intent {
	intent := &policy.Intent{}
	if src != "" {
		srcNg, _ := network.NewNetworkGroupFromString(src)
		if srcNg != nil {
			intent.SetSrc(srcNg)
		}
	}
	if dst != "" {
		dstNg, _ := network.NewNetworkGroupFromString(dst)
		if dstNg != nil {
			intent.SetDst(dstNg)
		}
	}
	return intent
}

// NewTestIntentWithService 创建带服务的测试策略意图
func NewTestIntentWithService(src, dst, protocol, port string) *policy.Intent {
	intent := NewTestIntent(src, dst)
	if protocol != "" {
		// 这里可以扩展添加服务信息
		// 具体实现取决于 policy.Intent 的 API
	}
	return intent
}
