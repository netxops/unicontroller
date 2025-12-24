package models

import "time"

type DeploymentStatus string

const (
	DeploymentStatusPending    DeploymentStatus = "pending"
	DeploymentStatusInProgress DeploymentStatus = "in_progress"
	DeploymentStatusCompleted  DeploymentStatus = "completed"
	DeploymentStatusFailed     DeploymentStatus = "failed"
)

type OperationType string

const (
	OperationTypeDeploy   OperationType = "deploy"   // 部署
	OperationTypeUninstall OperationType = "uninstall" // 卸载
	OperationTypeRestart  OperationType = "restart"  // 重启
)

type Deployment struct {
	ID            string                 `json:"id" bson:"id"`
	AppID         string                 `json:"app_id" bson:"app_id"`
	Type          string                 `json:"type" bson:"type"`
	Version       string                 `json:"version" bson:"version"`
	OperationType OperationType          `json:"operation_type" bson:"operation_type"` // 操作类型：部署或卸载
	Variables     map[string]interface{} `json:"variables" bson:"variables"`
	TargetDevices []TargetDevice         `json:"target_devices" bson:"target_devices"`
	OverallStatus DeploymentStatus       `json:"overall_status" bson:"overall_status"`
	StartTime     time.Time              `json:"start_time" bson:"start_time"`
	EndTime       time.Time              `json:"end_time,omitempty" bson:"end_time,omitempty"`
	Logs          []string               `json:"logs" bson:"logs"`
}

type DeploymentRequest struct {
	ID            string                 `json:"id" bson:"id"`
	AppID         string                 `json:"app_id" bson:"app_id"`
	Type          string                 `json:"type" bson:"type"`
	Version       string                 `json:"version" bson:"version"`
	OperationType OperationType          `json:"operation_type" bson:"operation_type"` // 操作类型：部署或卸载
	Variables     map[string]interface{} `json:"variables" bson:"variables"`
	TargetDevices []TargetDevice         `json:"target_devices" bson:"target_devices"`
	OverallStatus DeploymentStatus       `json:"overall_status" bson:"overall_status"`
	StartTime     time.Time              `json:"start_time" bson:"start_time"`
}

type LoginMethod string

const (
	LoginMethodSSH      LoginMethod = "ssh"
	LoginMethodWinRM    LoginMethod = "winrm"
	LoginMethodAPIToken LoginMethod = "api_token"
)

type TargetDevice struct {
	Name         string           `json:"name" bson:"name"`
	IP           string           `json:"ip" bson:"ip"`
	LoginMethod  LoginMethod      `json:"login_method" bson:"login_method"`
	LoginDetails LoginDetails     `json:"login_details" bson:"login_details"`
	AgentCode    string           `json:"agent_code" bson:"agent_code"`
	Status       DeploymentStatus `json:"status" bson:"status"`
	Message      string           `json:"message" bson:"message"`
}

type LoginDetails struct {
	Username string `json:"username,omitempty" bson:"username,omitempty"`
	Password string `json:"password,omitempty" bson:"password,omitempty"`
	SSHKey   string `json:"ssh_key,omitempty" bson:"ssh_key,omitempty"`
	APIToken string `json:"api_token,omitempty" bson:"api_token,omitempty"`
}

type DeploymentStatusUpdate struct {
	Status  DeploymentStatus `json:"status" bson:"status"`
	Message string           `json:"message" bson:"message"`
}

type PackageInstall struct {
	ID            string            `bson:"_id"`
	AppID         string            `bson:"app_id"`
	Version       string            `bson:"version"`
	Type          string            `bson:"type"`
	PackageURL    string            `bson:"package_url"`
	InstallStatus map[string]string `bson:"install_status"`
	InstallTime   time.Time         `bson:"install_time"`
}

// type DeviceStatus struct {
// 	AgentCode string                 `json:"agent_code"`
// 	Status    string                 `json:"status"`
// 	Message   string                 `json:"message"`
// 	Results   map[string]interface{} `json:"results"`
// }

type StatusUpdate struct {
	DeploymentID string           `json:"deployment_id"`
	AgentCode    string           `json:"agent_code"`
	Status       DeploymentStatus `json:"status"`
	Message      string           `json:"message"`
	Timestamp    time.Time        `json:"timestamp"`
}
