package model

type Schema struct {
	Package       string              `gorm:"not null" json:"package"`
	Format        string              `gorm:"not null" json:"format"`
	Binary        string              `gorm:"not null" json:"binary"`
	ConfigFile    string              `gorm:"" json:"config_file"`
	Configs       []*SchemaConfigItem `gorm:"type:json;serializer:json;not null" json:"configs"`
	Args          []string            `gorm:"type:json;serializer:json;not null" json:"args"`
	ListenPort    []uint32            `gorm:"type:json;serializer:json;not null" json:"listen_port"`
	StartupMethod string              `gorm:"not null" json:"startup_method"`
	Version       string              `gorm:"not null" json:"version"`
	Desc          string              `gorm:"not null" json:"desc"`
}

type SchemaConfigItem struct {
	Arg  string `json:"arg"`
	File string `json:"file"`
}

type RestartPolicy string

const (
	RestartAlways RestartPolicy = "always"
	RestartNever  RestartPolicy = "never"
)

type ObserverInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
