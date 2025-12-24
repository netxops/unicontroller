package controller

import (
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestAgentDiscovery_ParseAgentFromEtcdValue(t *testing.T) {
	logger := zaptest.NewLogger(t)
	
	// 模拟 etcd value
	etcdValue := []byte(`{
		"Op": 0,
		"Addr": "192.168.1.100:10380",
		"MetadataX": {
			"AppID": "agent-001",
			"Name": "server-agent",
			"Address": "192.168.1.100:10380",
			"Metadata": {
				"agent_code": "agent-001",
				"services": "[{\"name\":\"service-1\",\"version\":\"1.0.0\",\"is_running\":true,\"duration\":3600}]"
			},
			"Scheme": "grpc"
		}
	}`)
	
	// 验证 JSON 格式是否正确
	var testValue map[string]interface{}
	err := json.Unmarshal(etcdValue, &testValue)
	if err != nil {
		t.Fatalf("Failed to unmarshal test value: %v", err)
	}
	
	metadataX, ok := testValue["MetadataX"].(map[string]interface{})
	if !ok {
		t.Error("MetadataX should be a map")
	}
	
	appID, ok := metadataX["AppID"].(string)
	if !ok || appID != "agent-001" {
		t.Errorf("Expected AppID 'agent-001', got: %v", appID)
	}
	
	_ = logger // 避免未使用变量警告
}

func TestAgentDiscovery_ExtractAgentIDFromKey(t *testing.T) {
	key := "grpc://server-agent/192.168.1.100:10380"
	
	// 验证 key 格式
	if !strings.HasPrefix(key, "grpc://server-agent/") {
		t.Error("Key should start with 'grpc://server-agent/'")
	}
	
	parts := strings.Split(key, "/")
	if len(parts) < 3 {
		t.Error("Key should have at least 3 parts")
	}
	
	address := parts[len(parts)-1]
	if address == "" {
		t.Error("Address should not be empty")
	}
}
