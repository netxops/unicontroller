package models

// BatchOperationRequest 批量操作请求
type BatchOperationRequest struct {
	Agents   []string `json:"agents"`   // Agent ID 列表
	Packages []string `json:"packages"` // 服务包名列表（可选，为空则操作所有服务）
}

// BatchConfigRequest 批量配置更新请求
type BatchConfigRequest struct {
	Agents    []string    `json:"agents"`     // Agent ID 列表
	Package   string      `json:"package"`    // 服务包名
	Configs   []ConfigItem `json:"configs"`   // 配置项列表
	ConfigFile string     `json:"config_file"` // 配置文件名称（可选）
}

// ConfigItem 配置项
type ConfigItem struct {
	FileName string `json:"file_name"`
	Content  string `json:"content"`
}

// BatchOperationResult 批量操作结果
type BatchOperationResult struct {
	Total      int              `json:"total"`       // 总操作数
	Success    int              `json:"success"`    // 成功数
	Failed     int              `json:"failed"`     // 失败数
	Results    []OperationResult `json:"results"`   // 详细结果
	DurationMs int64            `json:"duration_ms"` // 执行时长（毫秒）
}

// OperationResult 单个操作结果
type OperationResult struct {
	AgentCode string `json:"agent_code"`
	Package   string `json:"package"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
}

