package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNacosManager(t *testing.T) {
	config := &Config{
		Nacos: NacosConfig{
			Server:    "192.168.100.122",
			Port:      8848,
			Namespace: "dev",
			Group:     "OneOPS_GROUP",
			DataID:    "cipher-aes-agent-config",
			LogDir:    "/tmp/nacos/log",
			CacheDir:  "/tmp/nacos/cache",
			LogLevel:  "info",
		},
	}

	nm, err := ProvideNacosManager(config)
	require.NoError(t, err)
	require.NotNil(t, nm)

	// 	// t.Run("SetConfig", func(t *testing.T) {
	// 	// 	err := nm.SetConfig("test-value")
	// 	// 	assert.NoError(t, err)
	// 	// })

	// 测试 GetConfig
	t.Run("GetConfig", func(t *testing.T) {
		value, err := nm.GetConfig("cipher-aes-agent-config", "OneOPS_GROUP")
		assert.NoError(t, err)
		assert.Contains(t, value, "global_variables")
	})

	// 	// // // 测试 ListenConfig
	// 	// t.Run("ListenConfig", func(t *testing.T) {
	// 	// 	configChanged := make(chan string)
	// 	// 	err := nm.ListenConfig(func(data string) {
	// 	// 		configChanged <- data
	// 	// 	})
	// 	// 	assert.NoError(t, err)

	// 	// 	// 在另一个 goroutine 中更新配置
	// 	// 	go func() {
	// 	// 		time.Sleep(2 * time.Second)
	// 	// 		err := nm.SetConfig("updated-value")
	// 	// 		assert.NoError(t, err)
	// 	// 	}()

	// 	// 	// 等待配置更新
	// 	// 	select {
	// 	// 	case newValue := <-configChanged:
	// 	// 		assert.Equal(t, "updated-value", newValue)
	// 	// 	case <-time.After(5 * time.Second):
	// 	// 		t.Fatal("Timeout waiting for config change")
	// 	// 	}
	// 	// })

	// 	// t.Run("DeleteConfig", func(t *testing.T) {
	// 	// 	err := nm.DeleteConfig()
	// 	// 	assert.NoError(t, err)

	// // 	// 验证配置已被删除
	// // 	_, err = nm.GetConfig()
	// // 	assert.Error(t, err)
	// // })
}
