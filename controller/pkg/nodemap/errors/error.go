package errors

import (
    "fmt"
    "time"
)

type ErrorType int

const (
    ParseError ErrorType = iota
    ExecutionError
    ValidationError
    // 可以根据需要添加更多错误类型
)

type ErrorSeverity int

const (
    SeverityInfo ErrorSeverity = iota
    SeverityWarning
    SeverityError
    SeverityCritical
)

type StructuredError struct {
    Type      ErrorType
    Severity  ErrorSeverity
    Message   string
    Section   string
    Line      int
    RawData   string
    Timestamp time.Time
    Context   map[string]interface{}
}

func (e *StructuredError) Error() string {
    return fmt.Sprintf("[%s][%s] %s: %s (Section: %s, Line: %d)", 
        e.Type, e.Severity, e.Timestamp.Format(time.RFC3339), e.Message, e.Section, e.Line)
}

func NewError(errorType ErrorType, message string, severity ErrorSeverity, section string, line int, rawData string, context map[string]interface{}) *StructuredError {
    return &StructuredError{
        Type:      errorType,
        Message:   message,
        Severity:  severity,
        Section:   section,
        Line:      line,
        RawData:   rawData,
        Timestamp: time.Now(),
        Context:   context,
    }
}
