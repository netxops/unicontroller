package models

import (
	"time"
)

// Device 表示服务器设备信息
type Device struct {
	ID           string            `json:"id"`            // 设备唯一标识
	Name         string            `json:"name"`          // 设备名称
	IP           string            `json:"ip"`            // 设备 IP 地址
	FunctionArea string            `json:"function_area"` // 功能区域，用于确定 Controller
	Status       string            `json:"status"`        // 设备状态
	AgentCode    string            `json:"agent_code"`    // Agent 标识码（由运维平台生成和管理，唯一）
	AgentVersion string            `json:"agent_version"` // Agent 版本
	OS           string            `json:"os"`            // linux, windows
	Architecture string            `json:"architecture"`  // amd64, arm64
	LoginMethod  string            `json:"login_method"`  // ssh, winrm
	LoginDetails LoginDetails      `json:"login_details"` // 登录凭证
	CreatedAt    time.Time         `json:"created_at"`    // 入库时间
	UpdatedAt    time.Time         `json:"updated_at"`    // 更新时间
	Metadata     map[string]string `json:"metadata"`      // 扩展元数据
}

// LoginDetails 登录凭证信息
type LoginDetails struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"` // 可选，使用 SSH Key 时为空
	SSHKey   string `json:"ssh_key,omitempty"`  // SSH 私钥
	Port     int    `json:"port,omitempty"`     // SSH/WinRM 端口
}

// DeviceStatus 设备状态常量
const (
	DeviceStatusInventory    = "inventory"          // 已入库，未部署 Agent
	DeviceStatusDeploying    = "agent_deploying"    // Agent 部署中
	DeviceStatusInstalled    = "agent_installed"    // Agent 已安装
	DeviceStatusOnline       = "agent_online"       // Agent 在线
	DeviceStatusOffline      = "agent_offline"      // Agent 离线
	DeviceStatusUpgrading    = "agent_upgrading"    // Agent 升级中
	DeviceStatusUninstalling = "agent_uninstalling" // Agent 卸载中
)
