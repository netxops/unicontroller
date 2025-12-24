package nodemap

import (
	"testing"

	"go.uber.org/zap"
)

func TestConvertToString(t *testing.T) {
	testCases := []struct {
		input    interface{}
		expected string
	}{
		{nil, ""},
		{"hello", "hello"},
		{123, "123"},
		{123.45, "123.45"},
		{true, "true"},
		{false, "false"},
		{[]string{"a", "b"}, `["a","b"]`},
		{map[string]int{"key": 1}, `{"key":1}`},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			result := convertToString(tc.input)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

func TestConvertMapToStringMap(t *testing.T) {
	input := map[string]interface{}{
		"string": "hello",
		"int":    123,
		"float":  123.45,
		"bool":   true,
		"nil":    nil,
	}

	expected := map[string]string{
		"string": "hello",
		"int":    "123",
		"float":  "123.45",
		"bool":   "true",
		"nil":    "",
	}

	result := convertMapToStringMap(input)

	for k, v := range expected {
		if result[k] != v {
			t.Errorf("Key '%s': Expected '%s', got '%s'", k, v, result[k])
		}
	}
}

func TestRouteDecisionWithStringTypes(t *testing.T) {
	logger := zap.NewNop()
	tracer := NewRouteTracer(logger, nil)

	// 测试记录决策，使用interface{}类型的参数
	criteria := map[string]interface{}{
		"src_network": "192.168.1.0/24",
		"vrf":         "default",
		"area":        "test_area",
		"gateway":     192168001001, // 数字类型
		"input_node":  "test_node",
		"enabled":     true, // 布尔类型
	}

	tracer.LogSourceNodeLocationFailure("Area not found.", criteria)

	// 验证决策是否被正确记录
	decisions := tracer.GetRouteDecisions()
	if len(decisions) == 0 {
		t.Fatal("Expected at least one decision to be recorded")
	}

	decision := decisions[0]

	// 验证Criteria字段都是string类型
	if decision.Criteria["src_network"] != "192.168.1.0/24" {
		t.Errorf("Expected '192.168.1.0/24', got '%s'", decision.Criteria["src_network"])
	}

	if decision.Criteria["gateway"] != "192168001001" {
		t.Errorf("Expected '192168001001', got '%s'", decision.Criteria["gateway"])
	}

	if decision.Criteria["enabled"] != "true" {
		t.Errorf("Expected 'true', got '%s'", decision.Criteria["enabled"])
	}

	// 验证Details字段都是string类型
	if decision.Details["error_message"] != "Area not found." {
		t.Errorf("Expected 'Area not found.', got '%s'", decision.Details["error_message"])
	}

	if decision.Details["failure_type"] != "AREA_NOT_FOUND" {
		t.Errorf("Expected 'AREA_NOT_FOUND', got '%s'", decision.Details["failure_type"])
	}
}

func TestExitInfoWithStringTypes(t *testing.T) {
	logger := zap.NewNop()
	tracer := NewRouteTracer(logger, nil)

	// 测试记录退出信息，使用interface{}类型的参数
	details := map[string]interface{}{
		"exit_reason": "ConnectedRoute",
		"hop_count":   5,
		"success":     true,
		"error_code":  nil,
	}

	tracer.LogExit(ExitReasonConnectedRoute, "test-node", "eth0", "default", true, "", details)

	// 验证退出信息是否被正确记录
	exitInfo := tracer.GetExitInfo()
	if exitInfo == nil {
		t.Fatal("Expected exit info to be recorded")
	}

	// 验证Details字段都是string类型
	if exitInfo.Details["exit_reason"] != "ConnectedRoute" {
		t.Errorf("Expected 'ConnectedRoute', got '%s'", exitInfo.Details["exit_reason"])
	}

	if exitInfo.Details["hop_count"] != "5" {
		t.Errorf("Expected '5', got '%s'", exitInfo.Details["hop_count"])
	}

	if exitInfo.Details["success"] != "true" {
		t.Errorf("Expected 'true', got '%s'", exitInfo.Details["success"])
	}

	if exitInfo.Details["error_code"] != "" {
		t.Errorf("Expected empty string, got '%s'", exitInfo.Details["error_code"])
	}
}
