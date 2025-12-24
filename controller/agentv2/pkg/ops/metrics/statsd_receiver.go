package metrics

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// StatsDReceiver StatsD 协议接收器
// 支持接收 StatsD 格式的指标数据
type StatsDReceiver struct {
	logger   *zap.Logger
	listener *net.UDPConn
	port     int
	enabled  bool
	mu       sync.RWMutex
	metrics  map[string]float64
}

// NewStatsDReceiver 创建 StatsD 接收器
func NewStatsDReceiver(logger *zap.Logger, port int) (*StatsDReceiver, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP port %d: %w", port, err)
	}

	receiver := &StatsDReceiver{
		logger:  logger,
		listener: listener,
		port:    port,
		enabled: true,
		metrics: make(map[string]float64),
	}

	// 启动接收循环
	go receiver.receiveLoop()

	logger.Info("StatsD receiver started", zap.Int("port", port))

	return receiver, nil
}

// receiveLoop 接收循环
func (r *StatsDReceiver) receiveLoop() {
	buffer := make([]byte, 65507) // UDP 最大数据包大小

	for r.enabled {
		n, _, err := r.listener.ReadFromUDP(buffer)
		if err != nil {
			if r.enabled {
				r.logger.Error("Failed to read from UDP", zap.Error(err))
			}
			continue
		}

		// 解析 StatsD 消息
		message := string(buffer[:n])
		r.parseStatsDMessage(message)
	}
}

// parseStatsDMessage 解析 StatsD 消息
// 格式: metric.name:value|type|@sample_rate
// 例如: my.metric:123|c|@0.1
func (r *StatsDReceiver) parseStatsDMessage(message string) {
	lines := strings.Split(message, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析格式: metric:value|type
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			r.logger.Warn("Invalid StatsD message format", zap.String("message", line))
			continue
		}

		metricPart := parts[0]
		metricType := parts[1]

		// 解析 metric:value
		metricValueParts := strings.Split(metricPart, ":")
		if len(metricValueParts) != 2 {
			r.logger.Warn("Invalid StatsD metric format", zap.String("metric", metricPart))
			continue
		}

		metricName := metricValueParts[0]
		valueStr := metricValueParts[1]

		var value float64
		if _, err := fmt.Sscanf(valueStr, "%f", &value); err != nil {
			r.logger.Warn("Failed to parse StatsD value",
				zap.String("value", valueStr),
				zap.Error(err))
			continue
		}

		// 根据类型处理
		r.mu.Lock()
		switch metricType {
		case "c": // counter
			r.metrics[metricName] += value
		case "g": // gauge
			r.metrics[metricName] = value
		case "ms": // timer (milliseconds)
			r.metrics[metricName] = value
		case "h": // histogram
			r.metrics[metricName] = value
		case "s": // set
			r.metrics[metricName] = value
		default:
			r.logger.Warn("Unknown StatsD metric type", zap.String("type", metricType))
		}
		r.mu.Unlock()
	}
}

// GetMetrics 获取指标
func (r *StatsDReceiver) GetMetrics() map[string]float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]float64, len(r.metrics))
	for k, v := range r.metrics {
		result[k] = v
	}
	return result
}

// Shutdown 关闭接收器
func (r *StatsDReceiver) Shutdown() error {
	r.mu.Lock()
	r.enabled = false
	r.mu.Unlock()

	if r.listener != nil {
		return r.listener.Close()
	}
	return nil
}

