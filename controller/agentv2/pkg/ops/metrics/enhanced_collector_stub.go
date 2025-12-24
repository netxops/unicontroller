//go:build !linux
// +build !linux

// Package metrics provides metrics collection functionality.
// This file provides stub implementations for EnhancedMetricsCollector
// on non-Linux systems (macOS, Windows, etc.).
// On these systems, use TelegrafInputCollector instead.

package metrics

import (
	"context"
	"fmt"
	"sync"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// EnhancedMetricsCollector 增强型指标收集器（非 Linux 系统上的 stub 实现）
// 在非 Linux 系统上，此类型不可用，应使用 TelegrafInputCollector
type EnhancedMetricsCollector struct {
	logger        *zap.Logger
	currentConfig EnhancedCollectorConfig
	mu            sync.RWMutex // 为了编译通过而保留，实际不会被使用
	// 注意：这些字段在 stub 实现中不需要，但为了编译通过而保留
	// 实际使用时，这些字段不会被访问，因为 NewEnhancedMetricsCollector 会返回错误
}

// EnhancedCollectorConfig 增强型收集器配置
type EnhancedCollectorConfig struct {
	EnabledCollectors []string // 启用的collectors列表（空表示启用所有）
	ExcludeCollectors []string // 排除的collectors列表
	OnlyCore          bool     // 是否只启用核心collectors
}

// StrategyManagerInterface 策略管理器接口（避免循环依赖）
type StrategyManagerInterface interface {
	GetMetricInterval(metricName string) int // 获取指标的采集间隔（秒）
}

// NewEnhancedMetricsCollector 创建增强型指标收集器（非 Linux 系统上的 stub）
// 在非 Linux 系统上，此函数返回错误，提示使用 TelegrafInputCollector
func NewEnhancedMetricsCollector(logger *zap.Logger, config ...EnhancedCollectorConfig) (*EnhancedMetricsCollector, error) {
	logger.Warn("EnhancedMetricsCollector is not available on this platform. Please use TelegrafInputCollector instead.")
	return nil, fmt.Errorf("EnhancedMetricsCollector is only available on Linux. Use TelegrafInputCollector on %s", "non-Linux systems")
}

// SetStrategyManager 设置策略管理器（stub 实现）
func (ec *EnhancedMetricsCollector) SetStrategyManager(sm StrategyManagerInterface) {
	if ec != nil && ec.logger != nil {
		ec.logger.Warn("SetStrategyManager called on stub EnhancedMetricsCollector")
	}
}

// UpdateMetrics 更新指标（stub 实现）
func (ec *EnhancedMetricsCollector) UpdateMetrics(ctx context.Context) error {
	if ec == nil {
		return fmt.Errorf("EnhancedMetricsCollector is not available on this platform")
	}
	return fmt.Errorf("EnhancedMetricsCollector is not available on this platform. Use TelegrafInputCollector instead")
}

// CollectSystemMetrics 收集系统指标（stub 实现）
func (ec *EnhancedMetricsCollector) CollectSystemMetrics(ctx context.Context) (*domain.SystemMetrics, error) {
	if ec == nil {
		return nil, fmt.Errorf("EnhancedMetricsCollector is not available on this platform")
	}
	return nil, fmt.Errorf("EnhancedMetricsCollector is not available on this platform. Use TelegrafInputCollector instead")
}

// GetSystemMetrics 获取系统指标（stub 实现）
func (ec *EnhancedMetricsCollector) GetSystemMetrics() *domain.SystemMetrics {
	if ec == nil {
		return &domain.SystemMetrics{}
	}
	return &domain.SystemMetrics{}
}

// GetPrometheusRegistry 获取 Prometheus Registry（stub 实现）
func (ec *EnhancedMetricsCollector) GetPrometheusRegistry() *prometheus.Registry {
	if ec == nil {
		return prometheus.NewRegistry()
	}
	return prometheus.NewRegistry()
}

// GetConfig 获取当前配置（stub 实现）
func (ec *EnhancedMetricsCollector) GetConfig() EnhancedCollectorConfig {
	return EnhancedCollectorConfig{}
}

// GetEnabledCollectors 获取当前启用的 collectors 列表（stub 实现）
func (ec *EnhancedMetricsCollector) GetEnabledCollectors() []string {
	return []string{}
}
