package utils

import (
	"errors"
	"fmt"
	"time"
)

// 封装error类型
func NewError(message string, err string) error {
	return errors.New(fmt.Sprintf("%s: %s", err, message))
}

// 返回当前时间
func Now() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

const (
	OBJECT_OPTION_ONE_MATCH_TWO = 0x1
	OBJECT_OPTION_TWO_MATCH_ONE = 0x2
	OBJECT_OPTION_SAME          = 0x4
)
