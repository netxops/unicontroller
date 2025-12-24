package errors

import (
	"fmt"
)

// ErrorCode 错误代码类型
type ErrorCode string

const (
	// 通用错误
	ErrCodeUnknown        ErrorCode = "UNKNOWN"
	ErrCodeInvalidRequest ErrorCode = "INVALID_REQUEST"
	ErrCodeNotFound       ErrorCode = "NOT_FOUND"
	ErrCodeInternal       ErrorCode = "INTERNAL_ERROR"

	// 服务相关错误
	ErrCodeServiceNotFound    ErrorCode = "SERVICE_NOT_FOUND"
	ErrCodeServiceNotRunning  ErrorCode = "SERVICE_NOT_RUNNING"
	ErrCodeServiceAlreadyRunning ErrorCode = "SERVICE_ALREADY_RUNNING"
	ErrCodeServiceStartFailed  ErrorCode = "SERVICE_START_FAILED"
	ErrCodeServiceStopFailed   ErrorCode = "SERVICE_STOP_FAILED"

	// 健康检查相关错误
	ErrCodeHealthCheckFailed ErrorCode = "HEALTH_CHECK_FAILED"
	ErrCodeHealthCheckTimeout ErrorCode = "HEALTH_CHECK_TIMEOUT"

	// 配置相关错误
	ErrCodeConfigInvalid ErrorCode = "CONFIG_INVALID"
	ErrCodeConfigNotFound ErrorCode = "CONFIG_NOT_FOUND"
)

// AgentError Agent 自定义错误
type AgentError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *AgentError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *AgentError) Unwrap() error {
	return e.Err
}

// NewError 创建新的错误
func NewError(code ErrorCode, message string) *AgentError {
	return &AgentError{
		Code:    code,
		Message: message,
	}
}

// WrapError 包装现有错误
func WrapError(code ErrorCode, message string, err error) *AgentError {
	return &AgentError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// IsErrorCode 检查错误是否是指定的错误代码
func IsErrorCode(err error, code ErrorCode) bool {
	if agentErr, ok := err.(*AgentError); ok {
		return agentErr.Code == code
	}
	return false
}

