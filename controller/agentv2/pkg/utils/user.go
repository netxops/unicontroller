package utils

import (
	"os"
	"os/user"
	"path/filepath"
)

// IsPrivilegedUser 检查当前是否为特权用户（root）
func IsPrivilegedUser() bool {
	return os.Geteuid() == 0
}

// GetHomeDir 获取用户主目录
func GetHomeDir() string {
	if IsPrivilegedUser() {
		return "/root"
	}

	// 尝试从环境变量获取
	if home := os.Getenv("HOME"); home != "" {
		return home
	}

	// 从系统获取
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}

	// 回退到 /tmp
	return "/tmp"
}

// GetDefaultWorkspace 获取默认工作目录
func GetDefaultWorkspace() string {
	if IsPrivilegedUser() {
		return "/opt/uniops-agent"
	}
	return filepath.Join(GetHomeDir(), "app", "uniops-agent")
}

// GetDefaultLogDirectory 获取默认日志目录
func GetDefaultLogDirectory() string {
	if IsPrivilegedUser() {
		return "/var/log/agentv2"
	}
	return filepath.Join(GetHomeDir(), ".local", "log", "agentv2")
}

// GetDefaultConfigDirectory 获取默认配置目录（用于服务配置）
func GetDefaultConfigDirectory(serviceName string) string {
	if IsPrivilegedUser() {
		return filepath.Join("/etc", serviceName)
	}
	return filepath.Join(GetHomeDir(), ".config", serviceName)
}
