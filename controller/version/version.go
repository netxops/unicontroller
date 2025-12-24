package version

import (
	"fmt"
	"runtime"
)

//go:generate go run gen_version.go

var (
	// Version 是应用程序的语义版本号，将由 gen_version.go 生成
	// Version string

	// GitCommit 是构建时的 Git 提交哈希
	GitCommit string

	// BuildTime 是应用程序构建的时间
	BuildTime string
)

// FullVersion 返回完整的版本信息字符串
func FullVersion() string {
	return fmt.Sprintf("Version: %s\nGit Commit: %s\nBuild Time: %s\nGo Version: %s\nOS/Arch: %s/%s",
		Version, GitCommit, BuildTime, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
