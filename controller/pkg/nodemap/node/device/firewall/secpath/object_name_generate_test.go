package secpath

import (
	"reflect"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
	"github.com/netxops/keys"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"github.com/stretchr/testify/assert"
)

func TestGenerateObjectName(t *testing.T) {
	// 创建 SecPathNode
	secpath := &SecPathNode{
		ObjectSet: NewSecPathObjectSet(nil),
	}

	// 在 objectSet 中直接添加一些预定义的对象
	ng1, _ := network.NewNetworkGroupFromString("192.168.1.0/24")
	ng2, _ := network.NewNetworkGroupFromString("10.0.0.0/8")
	svc1, _ := service.NewServiceFromString("tcp:80")
	svc2, _ := service.NewServiceFromString("udp:53")

	// 直接将网络对象添加到 zoneNetworkMap
	secpath.ObjectSet.ZoneNetworkMap[""] = map[string]firewall.FirewallNetworkObject{
		"existing_network_1": &secpathNetwork{ObjName: "existing_network_1", NetworkGroup: ng1},
		"existing_network_2": &secpathNetwork{ObjName: "existing_network_2", NetworkGroup: ng2},
	}

	// 直接将服务对象添加到 serviceMap
	secpath.ObjectSet.ServiceMap = map[string]firewall.FirewallServiceObject{
		"existing_service_1": &secpathService{name: "existing_service_1", service: svc1},
		"existing_service_2": &secpathService{name: "existing_service_2", service: svc2},
	}

	// 测试用例
	testCases := []struct {
		name          string
		key           keys.Keys
		obj           interface{}
		retryMethod   string
		expectedKey   string
		expectedIsNew bool
		expectedErr   bool
	}{
		{
			name:          "New network object",
			key:           keys.NewKeyBuilder("new_network"),
			obj:           network.NewNetworkGroupFromStringMust("172.16.0.0/16"),
			retryMethod:   RetryMethodNext,
			expectedKey:   "new_network",
			expectedIsNew: true,
			expectedErr:   false,
		},
		{
			name:          "Existing network object",
			key:           keys.NewKeyBuilder("existing_network_1").Separator("_"),
			obj:           ng1,
			retryMethod:   RetryMethodNext,
			expectedKey:   "existing_network_1",
			expectedIsNew: false,
			expectedErr:   false,
		},
		{
			name:          "Conflicting network object with next retry",
			key:           keys.NewKeyBuilder("existing_network_1").Separator("_"),
			obj:           network.NewNetworkGroupFromStringMust("192.168.2.0/24"),
			retryMethod:   RetryMethodNext,
			expectedKey:   "existing_network_1_1",
			expectedIsNew: true,
			expectedErr:   false,
		},
		{
			name:          "Conflicting network object with suffix retry",
			key:           keys.NewKeyBuilder("existing_network_1").Separator("_"),
			obj:           network.NewNetworkGroupFromStringMust("192.168.3.0/24"),
			retryMethod:   RetryMethodSuffix,
			expectedKey:   "existing_network_1_1",
			expectedIsNew: true,
			expectedErr:   false,
		},
		{
			name:          "New service object",
			key:           keys.NewKeyBuilder("new_service").Separator("_"),
			obj:           service.NewServiceMust("tcp:443"),
			retryMethod:   RetryMethodNext,
			expectedKey:   "new_service",
			expectedIsNew: true,
			expectedErr:   false,
		},
		{
			name:          "Existing service object",
			key:           keys.NewKeyBuilder("existing_service_1").Separator("_"),
			obj:           svc1,
			retryMethod:   RetryMethodNext,
			expectedKey:   "existing_service_1",
			expectedIsNew: false,
			expectedErr:   false,
		},
		{
			name:          "Conflicting service object with next retry",
			key:           keys.NewKeyBuilder("existing_service_1").Separator("_"),
			obj:           service.NewServiceMust("tcp:8080"),
			retryMethod:   RetryMethodNext,
			expectedKey:   "existing_service_1_1",
			expectedIsNew: true,
			expectedErr:   false,
		},
		{
			name:          "Unsupported object type",
			key:           keys.NewKeyBuilder("unsupported"),
			obj:           "unsupported",
			retryMethod:   RetryMethodNext,
			expectedKey:   "unsupported",
			expectedIsNew: false,
			expectedErr:   true,
		},
	}

	for _, tc := range testCases {
		om := common.NewObjectNameManager()
		t.Run(tc.name, func(t *testing.T) {
			var resultKey keys.Keys
			var isNew bool
			var err error
			if reflect.TypeOf(tc.obj) == reflect.TypeOf(&service.Service{}) {
				resultKey, isNew, err = common.GenerateObjectName(keys.NewAutoIncrementKeys(tc.key, 1), tc.obj, func() firewall.NamerIterator {
					return secpath.ServiceIterator()
				}, secpath, nil, tc.retryMethod, om, true)
			} else {
				resultKey, isNew, err = common.GenerateObjectName(keys.NewAutoIncrementKeys(tc.key, 1), tc.obj, func() firewall.NamerIterator {
					return secpath.NetworkIterator()
				}, secpath, nil, tc.retryMethod, om, true)
			}

			assert.Equal(t, tc.expectedKey, resultKey.String(), "Unexpected key")
			assert.Equal(t, tc.expectedIsNew, isNew, "Unexpected isNew value")
			if tc.expectedErr {
				assert.Error(t, err, "Expected an error")
			} else {
				assert.NoError(t, err, "Unexpected error")
			}
		})
	}
}
