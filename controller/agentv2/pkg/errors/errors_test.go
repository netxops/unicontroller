package errors

import (
	"errors"
	"testing"
)

func TestAgentError(t *testing.T) {
	// 测试创建新错误
	err := NewError(ErrCodeServiceNotFound, "service not found")
	if err.Code != ErrCodeServiceNotFound {
		t.Errorf("Expected error code %s, got %s", ErrCodeServiceNotFound, err.Code)
	}
	if err.Message != "service not found" {
		t.Errorf("Expected error message 'service not found', got '%s'", err.Message)
	}

	// 测试包装错误
	originalErr := errors.New("original error")
	wrappedErr := WrapError(ErrCodeInternal, "wrapped error", originalErr)
	if wrappedErr.Code != ErrCodeInternal {
		t.Errorf("Expected error code %s, got %s", ErrCodeInternal, wrappedErr.Code)
	}
	if wrappedErr.Err != originalErr {
		t.Error("Wrapped error should contain original error")
	}

	// 测试错误检查
	if !IsErrorCode(wrappedErr, ErrCodeInternal) {
		t.Error("Should identify error code correctly")
	}
	if IsErrorCode(wrappedErr, ErrCodeServiceNotFound) {
		t.Error("Should not match wrong error code")
	}
}
