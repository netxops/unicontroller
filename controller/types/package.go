package types

import "time"

type PackageStatus struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	IsRunning bool          `json:"is_running"`
	Duration  time.Duration `json:"duration"`
}
