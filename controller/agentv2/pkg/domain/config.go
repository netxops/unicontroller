package domain

// PackageSpecV2 扩展的 PackageSpec，包含运维配置
// 这个结构体与原有的 types.PackageSpec 兼容，但添加了运维相关字段
type PackageSpecV2 struct {
	Package     string
	Version     string
	Description string
	Binary      *BinarySpec
	Startup     *StartupSpec
	Config      *ConfigSpec
	Operations  *OperationsConfig `json:"operations,omitempty"`
}

// 注意：OperationsConfig 已经在 service.go 中定义
// 这里只是为了文档说明

