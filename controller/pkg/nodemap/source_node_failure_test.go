package nodemap

import (
	"testing"
	"go.uber.org/zap"
)

func TestSourceNodeLocationFailure(t *testing.T) {
	// 创建测试用的logger
	logger := zap.NewNop()
	
	// 创建RouteTracer
	tracer := NewRouteTracer(logger, nil)
	
	// 测试各种源节点定位失败的情况
	testCases := []struct {
		errorMsg    string
		expectedReason string
		expectedType   string
	}{
		{
			errorMsg: "Area not found.",
			expectedReason: "指定的区域未找到",
			expectedType: "AREA_NOT_FOUND",
		},
		{
			errorMsg: "No matching ports found.",
			expectedReason: "未找到匹配的端口",
			expectedType: "NO_MATCHING_PORTS",
		},
		{
			errorMsg: "Multiple matching ports found.",
			expectedReason: "找到多个匹配的端口，需要更精确的定位条件",
			expectedType: "MULTIPLE_MATCHING_PORTS",
		},
		{
			errorMsg: "No outside node.",
			expectedReason: "未找到外部连接节点",
			expectedType: "NO_OUTSIDE_NODE",
		},
		{
			errorMsg: "nodemap have multiple outside connections, must give area info",
			expectedReason: "网络拓扑有多个外部连接，必须提供区域信息",
			expectedType: "MULTIPLE_OUTSIDE_CONNECTIONS",
		},
		{
			errorMsg: "Unknown error message",
			expectedReason: "源节点定位失败: Unknown error message",
			expectedType: "UNKNOWN_ERROR",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.errorMsg, func(t *testing.T) {
			// 测试失败原因分析
			reason := tracer.analyzeSourceNodeLocationFailure(tc.errorMsg)
			if reason != tc.expectedReason {
				t.Errorf("Expected reason '%s', got '%s'", tc.expectedReason, reason)
			}
			
			// 测试失败类型分析
			failureType := tracer.getFailureType(tc.errorMsg)
			if failureType != tc.expectedType {
				t.Errorf("Expected failure type '%s', got '%s'", tc.expectedType, failureType)
			}
			
			// 测试记录失败决策
			criteria := map[string]interface{}{
				"src_network": "192.168.1.0/24",
				"vrf":         "default",
				"area":        "test_area",
				"gateway":     "192.168.1.1",
				"input_node":  "test_node",
			}
			
			tracer.LogSourceNodeLocationFailure(tc.errorMsg, criteria)
			
			// 验证决策是否被记录
			decisions := tracer.GetRouteDecisions()
			if len(decisions) == 0 {
				t.Error("Expected at least one decision to be recorded")
			}
			
			lastDecision := decisions[len(decisions)-1]
			if lastDecision.DecisionType != string(DecisionSourceNodeLocation) {
				t.Errorf("Expected decision type %s, got %s", DecisionSourceNodeLocation, lastDecision.DecisionType)
			}
			
			if lastDecision.Result != "failed" {
				t.Errorf("Expected result 'failed', got '%s'", lastDecision.Result)
			}
			
			if lastDecision.Reason != tc.expectedReason {
				t.Errorf("Expected reason '%s', got '%s'", tc.expectedReason, lastDecision.Reason)
			}
			
			// 验证详细信息
			if lastDecision.Details == nil {
				t.Error("Expected details to be recorded")
			} else {
				if lastDecision.Details["error_message"] != tc.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tc.errorMsg, lastDecision.Details["error_message"])
				}
				
				if lastDecision.Details["failure_type"] != tc.expectedType {
					t.Errorf("Expected failure type '%s', got '%s'", tc.expectedType, lastDecision.Details["failure_type"])
				}
			}
		})
	}
}


