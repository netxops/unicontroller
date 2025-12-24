package metrics

import "time"

// CollectorConfig 指标收集器配置
type CollectorConfig struct {
	Interval       time.Duration
	CollectSystem  bool
	CollectService bool
	// 增强型收集器配置（已废弃，使用 TelegrafInputs）
	EnhancedEnabled bool
	// 历史缓存配置
	HistoryEnabled   bool
	HistoryMaxPoints int // 历史数据点最大数量，默认 360（1小时，10秒间隔）
	// Telegraf Input 插件配置
	TelegrafInputsEnabled  bool
	TelegrafInputsList     []string
	TelegrafInputsConfigs  map[string]interface{}
	TelegrafInputsInterval time.Duration
}
