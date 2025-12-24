package helpers

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// SetupTestLogger 设置测试日志
// 默认级别为 Info，可以通过环境变量或参数调整
func SetupTestLogger(level ...zapcore.Level) *zap.Logger {
	logLevel := zapcore.InfoLevel
	if len(level) > 0 {
		logLevel = level[0]
	}

	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(logLevel)
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, _ := config.Build()
	return logger
}

// SetupTestLoggerDebug 设置调试级别的测试日志
func SetupTestLoggerDebug() *zap.Logger {
	return SetupTestLogger(zapcore.DebugLevel)
}

// SetupTestLoggerInfo 设置信息级别的测试日志
func SetupTestLoggerInfo() *zap.Logger {
	return SetupTestLogger(zapcore.InfoLevel)
}

// SetupTestLoggerWarn 设置警告级别的测试日志
func SetupTestLoggerWarn() *zap.Logger {
	return SetupTestLogger(zapcore.WarnLevel)
}

// SetupTestLoggerError 设置错误级别的测试日志
func SetupTestLoggerError() *zap.Logger {
	return SetupTestLogger(zapcore.ErrorLevel)
}
