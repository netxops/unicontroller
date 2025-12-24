package config

type Config struct {
	AppID                 string
	Code                  string
	Workspace             string
	PackDiscoveryInterval int64
	UseDebugDb            bool
	Capabilities          []*Capability
	// Controller   string
	// Syslog       string
	// Prometheus   string
	// ConfigCenter string
}

type Capability struct {
	Name string
	Dep  string
}
