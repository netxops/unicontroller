// File: deployment-agent.go

package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/influxdata/telegraf/controller/types"

	"github.com/minio/minio-go"
)

var (
	deploymentID string
	agentCode    string
	appID        string
	// version        string
	controllerURL  string
	packageURL     string
	configFilePath string
	templateVars   string
	operation      string // 操作类型：deploy 或 uninstall

	minioEndpoint        string
	minioAccessKeyID     string
	minioSecretAccessKey string
	minioBucketName      string
	minioObjectName      string
	minioUseSSL          bool
)

type Data struct {
	AppID          string
	Version        string
	ControllerURL  string
	PackageURL     string
	ConfigFilePath string
	Variables      map[string]interface{} // 使用 interface{} 以支持数组类型（如 etcd_endpoints）
	Spec           *types.PackageSpec
}

var deploymentData Data
var (
	globalAppDir    string
	globalConfigDir string
	globalUnitFile  string
)

func init() {
	flag.StringVar(&deploymentID, "deployment-id", "", "Deployment ID")
	flag.StringVar(&agentCode, "agent-code", "", "Agent code")
	flag.StringVar(&appID, "app-id", "", "Application ID")
	// flag.StringVar(&version, "version", "", "Application version")
	flag.StringVar(&controllerURL, "controller-url", "", "Controller API URL")
	flag.StringVar(&packageURL, "package-url", "", "Package URL")
	flag.StringVar(&operation, "operation", "deploy", "Operation type: deploy or uninstall")

	flag.StringVar(&minioEndpoint, "minio-endpoint", os.Getenv("MINIO_ENDPOINT"), "Minio server endpoint")
	flag.StringVar(&minioAccessKeyID, "minio-access-key", os.Getenv("MINIO_ACCESS_KEY"), "Minio access key ID")
	flag.StringVar(&minioSecretAccessKey, "minio-secret-key", os.Getenv("MINIO_SECRET_KEY"), "Minio secret access key")
	flag.StringVar(&minioBucketName, "minio-bucket", os.Getenv("MINIO_BUCKET"), "Minio bucket name")
	flag.StringVar(&minioObjectName, "minio-object", os.Getenv("MINIO_OBJECT"), "Minio object name")
	flag.BoolVar(&minioUseSSL, "minio-use-ssl", os.Getenv("MINIO_USE_SSL") == "true", "Use SSL for Minio connection")

	flag.Parse()

	// if deploymentID == "" || appID == "" || version == "" || controllerURL == "" {
	if deploymentID == "" || appID == "" || controllerURL == "" {

		fmt.Println("All flags are required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 只有在 packageURL 为空时才检查 Minio 相关参数
	if packageURL == "" {
		if minioEndpoint == "" || minioAccessKeyID == "" || minioSecretAccessKey == "" || minioBucketName == "" || minioObjectName == "" {
			fmt.Println("When package-url is not provided, all Minio-related flags are required")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}
}
func main() {
	// 根据操作类型决定是部署、卸载还是重启
	if operation == "uninstall" {
		performUninstall()
	} else if operation == "restart" {
		performRestart()
	} else {
		performDeploy()
	}
}

func performDeploy() {
	fmt.Println("Starting deployment process...")
	reportStatus(models.DeploymentStatusInProgress, "Deployment started")

	fmt.Println("Downloading package...")
	if err := downloadPackage(); err != nil {
		fmt.Printf("Error: Failed to download package: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to download package: %v", err))
		os.Exit(1)
	}
	fmt.Println("Package downloaded successfully.")

	//
	if err := checkAndStopExistingService(appID); err != nil {
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to check or stop existing service: %v", err))
		os.Exit(1)
	}

	fmt.Println("Extracting package...")
	if err := extractPackage(); err != nil {
		fmt.Printf("Error: Failed to extract package: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to extract package: %v", err))
		os.Exit(1)
	}
	fmt.Println("Package extracted successfully.")

	fmt.Println("Loading package specification...")
	spec, err := loadPackageSpec()
	if err != nil {
		fmt.Printf("Error: Failed to load package spec: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to load package spec: %v", err))
		os.Exit(1)
	}
	fmt.Println("Package specification loaded successfully.")

	fmt.Println("Getting template variables from controller...")
	templateVars, err := getTemplateVarsFromController()
	if err != nil {
		fmt.Printf("Error: Failed to get template variables: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to get template variables: %v", err))
		os.Exit(1)
	}
	fmt.Println("Template variables retrieved successfully.")

	if err := calculateDeploymentPaths(spec); err != nil {
		fmt.Printf("Error: Failed to calculate deployment paths: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to calculate deployment paths: %v", err))
		os.Exit(1)
	}
	if err := prepareVariables(templateVars, spec); err != nil {
		fmt.Printf("Error: Failed to prepare variables: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to prepare variables: %v", err))
		os.Exit(1)
	}

	deploymentData = Data{
		AppID:          appID,
		Version:        spec.Version,
		ControllerURL:  controllerURL,
		PackageURL:     packageURL,
		ConfigFilePath: configFilePath,
		Variables:      templateVars,
		Spec:           spec,
	}

	fmt.Println("Checking and configuring firewall...")
	if err := checkAndConfigureFirewall(spec); err != nil {
		fmt.Printf("Error: Failed to configure firewall: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to configure firewall: %v", err))
		os.Exit(1)
	}
	fmt.Println("Firewall configured successfully.")

	fmt.Println("Setting up configuration...")
	if err := setupConfiguration(spec, templateVars); err != nil {
		fmt.Printf("Error: Failed to setup configuration: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to setup configuration: %v", err))
		os.Exit(1)
	}
	fmt.Println("Configuration set up successfully.")

	fmt.Println("Setting up systemd service...")
	if err := setupSystemdService(spec, templateVars); err != nil {
		fmt.Printf("Error: Failed to setup systemd service: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to setup systemd service: %v", err))
		os.Exit(1)
	}
	fmt.Println("Systemd service set up successfully.")

	fmt.Println("Running post-install script...")
	if err := runPostInstallScript(spec); err != nil {
		fmt.Printf("Error: Failed to run post-install script: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to run post-install script: %v", err))
		os.Exit(1)
	}
	fmt.Println("Post-install script executed successfully.")

	fmt.Println("Starting application...")
	if err := startApplication(spec); err != nil {
		fmt.Printf("Error: Failed to start application: %v\n", err)
		reportStatus(models.DeploymentStatusFailed, fmt.Sprintf("Failed to start application: %v", err))
		os.Exit(1)
	}
	fmt.Println("Application started successfully.")

	fmt.Println("Deployment completed successfully.")
	reportStatus(models.DeploymentStatusCompleted, "Deployment completed successfully")
}

func performUninstall() {
	fmt.Println("Starting uninstall process...")
	reportStatus(models.DeploymentStatusInProgress, "Uninstall started")

	// 加载 package spec 以获取卸载信息
	spec, err := loadPackageSpec()
	if err != nil {
		// 如果无法加载 spec，仍然可以继续卸载（使用默认路径）
		fmt.Printf("Warning: Failed to load package spec: %v, proceeding with default uninstall\n", err)
		spec = nil
	}

	// 停止服务
	fmt.Println("Stopping service...")
	if err := checkAndStopExistingService(appID); err != nil {
		fmt.Printf("Warning: Failed to stop service: %v, continuing with uninstall\n", err)
	}

	// 禁用并删除 systemd 服务
	if spec != nil {
		fmt.Println("Removing systemd service...")
		if err := removeSystemdService(spec); err != nil {
			fmt.Printf("Warning: Failed to remove systemd service: %v\n", err)
		}
	} else {
		// 尝试使用 appID 作为服务名
		fmt.Println("Removing systemd service...")
		if err := removeSystemdServiceByName(appID); err != nil {
			fmt.Printf("Warning: Failed to remove systemd service: %v\n", err)
		}
	}

	// 删除应用目录
	fmt.Println("Removing application directory...")
	appDir := types.GetAppDir(appID)
	if err := os.RemoveAll(appDir); err != nil {
		fmt.Printf("Warning: Failed to remove application directory %s: %v\n", appDir, err)
	} else {
		fmt.Printf("Application directory %s removed successfully.\n", appDir)
	}

	// 删除配置目录（可选，根据需求决定）
	// fmt.Println("Removing configuration directory...")
	// if spec != nil && spec.Config.Directory != "" {
	// 	if err := os.RemoveAll(spec.Config.Directory); err != nil {
	// 		fmt.Printf("Warning: Failed to remove configuration directory %s: %v\n", spec.Config.Directory, err)
	// 	}
	// }

	fmt.Println("Uninstall completed successfully.")
	reportStatus(models.DeploymentStatusCompleted, "Uninstall completed successfully")
}

func performRestart() {
	fmt.Println("Starting agent restart process...")
	reportStatus(models.DeploymentStatusInProgress, "Agent restart started")

	// Agent服务名称，默认为 "agent"
	serviceName := "agent"

	// 尝试从package.json获取服务名称（如果存在）
	spec, err := loadPackageSpec()
	if err == nil && spec != nil && spec.Startup.ServiceName != "" {
		serviceName = spec.Startup.ServiceName
		fmt.Printf("Using service name from package.json: %s\n", serviceName)
	} else {
		fmt.Printf("Using default service name: %s\n", serviceName)
	}

	// 检查服务是否存在
	fmt.Printf("Checking if service %s exists...\n", serviceName)
	exists, err := isServiceExists(serviceName)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to check service existence: %v", err)
		fmt.Printf("Error: %s\n", errMsg)
		reportStatus(models.DeploymentStatusFailed, errMsg)
		os.Exit(1)
	}

	if !exists {
		errMsg := fmt.Sprintf("Service %s does not exist", serviceName)
		fmt.Printf("Error: %s\n", errMsg)
		reportStatus(models.DeploymentStatusFailed, errMsg)
		os.Exit(1)
	}

	// 检查服务当前状态
	fmt.Printf("Checking current status of service %s...\n", serviceName)
	isRunning, err := isServiceRunning(serviceName)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to check service status: %v", err)
		fmt.Printf("Error: %s\n", errMsg)
		reportStatus(models.DeploymentStatusFailed, errMsg)
		os.Exit(1)
	}

	if isRunning {
		fmt.Printf("Service %s is currently running, proceeding with restart...\n", serviceName)
	} else {
		fmt.Printf("Service %s is not running, will start it...\n", serviceName)
	}

	// 执行重启命令
	fmt.Printf("Restarting service %s...\n", serviceName)
	reportStatus(models.DeploymentStatusInProgress, fmt.Sprintf("Restarting service %s", serviceName))

	var cmd *exec.Cmd
	if types.IsPrivilegedUser() {
		fmt.Println("Restarting systemd service as privileged user")
		cmd = exec.Command("systemctl", "restart", serviceName)
	} else {
		fmt.Println("Restarting systemd service as non-privileged user")
		cmd = exec.Command("systemctl", "--user", "restart", serviceName)
		uid := os.Getuid()
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", uid),
			fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", uid),
			fmt.Sprintf("SYSTEMD_EXEC_PID=%d", os.Getpid()))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to restart service %s: %v, output: %s", serviceName, err, string(output))
		fmt.Printf("Error: %s\n", errMsg)
		reportStatus(models.DeploymentStatusFailed, errMsg)
		os.Exit(1)
	}

	fmt.Printf("Service restart command executed successfully\n")
	if len(output) > 0 {
		fmt.Printf("Command output: %s\n", string(output))
	}

	// 等待服务启动（最多等待30秒）
	fmt.Println("Waiting for service to start...")
	reportStatus(models.DeploymentStatusInProgress, "Waiting for service to start")

	maxWaitTime := 30 // 最多等待30秒
	waitCount := 0
	for waitCount < maxWaitTime {
		time.Sleep(1 * time.Second)
		waitCount++

		isRunning, err := isServiceRunning(serviceName)
		if err != nil {
			fmt.Printf("Warning: Failed to check service status: %v\n", err)
			continue
		}

		if isRunning {
			fmt.Printf("Service %s is now running (waited %d seconds)\n", serviceName, waitCount)
			reportStatus(models.DeploymentStatusInProgress, fmt.Sprintf("Service %s is running", serviceName))
			break
		}

		if waitCount%5 == 0 {
			fmt.Printf("Still waiting for service to start... (%d/%d seconds)\n", waitCount, maxWaitTime)
		}
	}

	// 最终验证服务状态
	fmt.Printf("Verifying service %s status...\n", serviceName)
	isRunning, err = isServiceRunning(serviceName)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to verify service status: %v", err)
		fmt.Printf("Error: %s\n", errMsg)
		reportStatus(models.DeploymentStatusFailed, errMsg)
		os.Exit(1)
	}

	if !isRunning {
		// 尝试获取服务日志
		var journalCmd *exec.Cmd
		if types.IsPrivilegedUser() {
			journalCmd = exec.Command("journalctl", "-u", serviceName, "--no-pager", "-n", "20")
		} else {
			journalCmd = exec.Command("journalctl", "--user", "-u", serviceName, "--no-pager", "-n", "20")
			uid := os.Getuid()
			journalCmd.Env = append(os.Environ(),
				fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", uid),
				fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", uid))
		}
		journalOutput, _ := journalCmd.CombinedOutput()

		errMsg := fmt.Sprintf("Service %s failed to start after restart. Service logs:\n%s", serviceName, string(journalOutput))
		fmt.Printf("Error: %s\n", errMsg)
		reportStatus(models.DeploymentStatusFailed, errMsg)
		os.Exit(1)
	}

	fmt.Printf("Service %s restarted successfully\n", serviceName)
	reportStatus(models.DeploymentStatusCompleted, fmt.Sprintf("Service %s restarted successfully", serviceName))
}

func isServiceExists(serviceName string) (bool, error) {
	// 确保服务名称有 .service 后缀（如果没有的话）
	serviceNameWithSuffix := serviceName
	if !strings.HasSuffix(serviceName, ".service") {
		serviceNameWithSuffix = serviceName + ".service"
	}

	var cmd *exec.Cmd
	if types.IsPrivilegedUser() {
		// 使用 list-unit-files 命令，但需要正确处理退出码
		cmd = exec.Command("systemctl", "list-unit-files", "--type=service", "--no-legend", serviceNameWithSuffix)
	} else {
		cmd = exec.Command("systemctl", "--user", "list-unit-files", "--type=service", "--no-legend", serviceNameWithSuffix)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()),
			fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))
	}

	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	// list-unit-files 命令的行为：
	// - 如果服务存在：返回0，输出包含服务名称和状态
	// - 如果服务不存在：返回1，输出为空或错误信息

	// 检查输出是否包含服务名称（说明服务存在）
	if len(outputStr) > 0 {
		// 输出不为空，检查是否包含服务名称
		if strings.Contains(outputStr, serviceNameWithSuffix) || strings.Contains(outputStr, serviceName) {
			return true, nil
		}
	}

	// 如果命令返回错误，检查是否是"服务不存在"的情况
	if err != nil {
		// 如果输出为空或包含"not found"等，说明服务不存在（这是正常情况）
		if len(outputStr) == 0 ||
			strings.Contains(outputStr, "not found") ||
			strings.Contains(outputStr, "No such file") {
			return false, nil
		}
		// 其他错误情况
		return false, fmt.Errorf("failed to check service existence: %v, output: %s", err, outputStr)
	}

	// 命令成功执行且输出不为空，说明服务存在
	return len(outputStr) > 0, nil
}

func removeSystemdService(spec *types.PackageSpec) error {
	// 使用 Startup.ServiceName，如果不存在则使用 Package 名称
	serviceName := spec.Startup.ServiceName
	if serviceName == "" {
		serviceName = spec.Package + ".service"
	} else if !strings.HasSuffix(serviceName, ".service") {
		serviceName = serviceName + ".service"
	}
	return removeSystemdServiceByName(serviceName)
}

func removeSystemdServiceByName(serviceName string) error {
	isUserUnit := !types.IsPrivilegedUser()

	// 禁用服务
	var disableCmd *exec.Cmd
	if isUserUnit {
		disableCmd = exec.Command("systemctl", "--user", "disable", serviceName)
		disableCmd.Env = append(os.Environ(),
			fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()),
			fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))
	} else {
		disableCmd = exec.Command("systemctl", "disable", serviceName)
	}

	if output, err := disableCmd.CombinedOutput(); err != nil {
		fmt.Printf("Warning: Failed to disable service: %v, output: %s\n", err, string(output))
	}

	// 删除服务文件
	var serviceFile string
	if isUserUnit {
		serviceFile = filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", serviceName)
	} else {
		serviceFile = filepath.Join("/etc", "systemd", "system", serviceName)
	}

	if err := os.Remove(serviceFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file %s: %v", serviceFile, err)
	}

	// 重新加载 systemd
	if err := reloadSystemd(isUserUnit); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	return nil
}

func prepareVariables(vars map[string]interface{}, spec *types.PackageSpec) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user info: %v", err)
	}

	if types.IsPrivilegedUser() {
		vars["user"] = currentUser.Username // 默认使用当前用户
	}
	// 获取组名
	group, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		return fmt.Errorf("failed to lookup group: %v", err)
	}
	if types.IsPrivilegedUser() {
		vars["group"] = group.Name
	}

	vars["app_id"] = appID
	vars["device_code"] = agentCode
	// 确保 agent_code 也被设置（优先使用从 Controller 获取的值，如果没有则使用 agentCode）
	if _, exists := vars["agent_code"]; !exists {
		vars["agent_code"] = agentCode
	}
	vars["install_dir"] = globalAppDir
	vars["config_dir"] = globalConfigDir
	vars["version"] = spec.Version

	// unitVars := make(map[string]interface{})

	vars["wanted_by"] = "multi-user.target" // 默认值，可以根据需要修改

	// 如果 spec 中指定了 User，则使用指定的 User
	if spec.Startup.User != "" && types.IsPrivilegedUser() {
		vars["user"] = spec.Startup.User
	}

	vars["workspace"] = types.GetWorkspaceDir()

	// 如果 spec 中指定了 Group，则使用指定的 Group
	if spec.Startup.Group != "" && types.IsPrivilegedUser() {
		vars["group"] = spec.Startup.Group
	}

	// 如果是非特权用户，修改 WantedBy
	if !types.IsPrivilegedUser() {
		vars["wanted_by"] = "default.target"
	}

	// Controller URL 处理：
	// controller_url 是必需的，必须来自 Controller 配置的 BaseConfig.DefaultPort
	// 不能有歧义，也不能进行其他降级处理
	controllerURLValue, exists := vars["controller_url"]
	if !exists {
		return fmt.Errorf("controller_url is required but not provided by Controller API. Please check Controller BaseConfig.DefaultPort configuration")
	}
	// 验证 controller_url 是字符串类型且不为空
	controllerURL, ok := controllerURLValue.(string)
	if !ok || controllerURL == "" {
		return fmt.Errorf("controller_url is required but invalid (type: %T, value: %v). Please check Controller BaseConfig.DefaultPort configuration", controllerURLValue, controllerURLValue)
	}
	// controller_url 已经由 Controller API 基于 BaseConfig.DefaultPort 构建，直接使用即可

	// 处理 metrics 增强型收集器配置（数组类型）
	// 确保数组类型变量正确格式化，以便模板可以正确渲染
	normalizeArrayVariable(vars, "metrics_enhanced_collectors")
	normalizeArrayVariable(vars, "metrics_enhanced_exclude")
	// etcd_endpoints 已经在模板中处理，这里不需要额外处理

	return nil
}

// normalizeArrayVariable 规范化数组类型变量，确保模板可以正确渲染
// 如果变量是字符串类型（逗号分隔），则转换为数组
// 如果变量已经是数组类型，则保持不变
// 如果变量不存在或为空，则不处理（模板会使用默认值）
func normalizeArrayVariable(vars map[string]interface{}, key string) {
	value, exists := vars[key]
	if !exists {
		return // 变量不存在，模板会使用默认值
	}

	// 如果已经是数组类型，直接返回
	switch v := value.(type) {
	case []string:
		return // 已经是正确的类型
	case []interface{}:
		// 转换为 []string
		strSlice := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				strSlice = append(strSlice, str)
			}
		}
		if len(strSlice) > 0 {
			vars[key] = strSlice
		} else {
			delete(vars, key) // 空数组，删除变量让模板使用默认值
		}
		return
	case string:
		// 如果是字符串（可能是逗号分隔），转换为数组
		if v == "" {
			delete(vars, key) // 空字符串，删除变量让模板使用默认值
			return
		}
		// 尝试按逗号分割
		parts := strings.Split(v, ",")
		trimmedParts := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				trimmedParts = append(trimmedParts, trimmed)
			}
		}
		if len(trimmedParts) > 0 {
			vars[key] = trimmedParts
		} else {
			delete(vars, key) // 分割后为空，删除变量让模板使用默认值
		}
		return
	default:
		// 其他类型，删除变量让模板使用默认值
		fmt.Printf("Warning: Variable %s has unsupported type %T, will use template default\n", key, v)
		delete(vars, key)
		return
	}
}

func extractPackage() error {
	reportStatus(models.DeploymentStatusInProgress, "Extracting package")

	// 使用新的公共方法获取目标目录
	targetDir := types.GetAppDir(appID)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %v", err)
	}

	// 打开 zip 文件
	reader, err := zip.OpenReader("package.zip")
	if err != nil {
		return fmt.Errorf("failed to open zip file: %v", err)
	}
	defer reader.Close()

	// 遍历 zip 文件中的所有文件和目录
	for _, file := range reader.File {
		path := filepath.Join(targetDir, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode())
			continue
		}

		if err := extractFile(file, path); err != nil {
			return err
		}
	}

	reportStatus(models.DeploymentStatusInProgress, fmt.Sprintf("Package extracted to %s", targetDir))
	return nil
}

func extractFile(file *zip.File, path string) error {
	fileReader, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open file in zip: %v", err)
	}
	defer fileReader.Close()

	targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return fmt.Errorf("failed to create target file: %v", err)
	}
	defer targetFile.Close()

	if _, err := io.Copy(targetFile, fileReader); err != nil {
		return fmt.Errorf("failed to write file content: %v", err)
	}

	return nil
}

func loadPackageSpec() (*types.PackageSpec, error) {
	packageJsonPath := filepath.Join(types.GetAppDir(appID), "package.json")

	data, err := ioutil.ReadFile(packageJsonPath)
	if err != nil {
		// 如果是卸载操作且文件不存在，返回 nil（允许继续卸载）
		if operation == "uninstall" && os.IsNotExist(err) {
			return nil, nil
		}
		// 列出目录中的所有文件，用于调试
		appDir := types.GetAppDir(appID)
		fmt.Printf("Failed to find package.json in %s. Directory contents:\n", appDir)
		if entries, listErr := ioutil.ReadDir(appDir); listErr == nil {
			for _, entry := range entries {
				fmt.Printf("  - %s (isDir: %v)\n", entry.Name(), entry.IsDir())
			}
		}
		return nil, fmt.Errorf("failed to read %s: %v", packageJsonPath, err)
	}

	var spec types.PackageSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %v", packageJsonPath, err)
	}

	return &spec, nil
}

func calculateDeploymentPaths(spec *types.PackageSpec) error {
	baseDir := types.GetBaseDir()
	globalAppDir = types.GetAppDir(appID)

	if types.IsPrivilegedUser() {
		globalConfigDir = spec.Config.Directory
		if globalConfigDir == "" {
			globalConfigDir = filepath.Join("/etc", spec.Package)
		}
	} else {
		// 首先尝试使用 spec.Config.Directory
		if spec.Config.Directory != "" {
			// 检查是否有读写权限
			if err := types.CheckWritePermission(spec.Config.Directory); err == nil {
				globalConfigDir = spec.Config.Directory
			} else {
				fmt.Printf("Warning: No write permission for %s, falling back to user's .config directory\n", spec.Config.Directory)
				globalConfigDir = filepath.Join(baseDir, ".config", spec.Package)
			}
		} else {
			globalConfigDir = filepath.Join(baseDir, ".config", spec.Package)
		}
	}

	// 确保目录存在
	dirs := []string{globalAppDir, globalConfigDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	return nil
}

func reportStatus(status models.DeploymentStatus, message string) {
	update := struct {
		AgentCode string                  `json:"agent_code"`
		Status    models.DeploymentStatus `json:"status"`
		Message   string                  `json:"message"`
		// Results   map[string]interface{}  `json:"results"`
	}{
		AgentCode: agentCode,
		Status:    status,
		Message:   message,
		// Results:   make(map[string]interface{}), // 如果有具体结果，可以在这里填充
	}

	jsonData, err := json.Marshal(update)
	if err != nil {
		fmt.Printf("Failed to marshal status update: %v\n", err)
		return
	}

	resp, err := http.Post(fmt.Sprintf("%s/api/v1/deployments/%s/status", controllerURL, deploymentID), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Failed to send status update: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("Status update not accepted by controller. Status code: %d, Body: %s\n", resp.StatusCode, string(body))
	} else {
		fmt.Println("Status update successfully sent to controller")
	}
}

func checkAndConfigureFirewall(spec *types.PackageSpec) error {
	reportStatus(models.DeploymentStatusInProgress, "Checking firewall status")

	// 检查是否安装并启用了 firewalld
	cmd := exec.Command("systemctl", "is-active", "firewalld")
	if err := cmd.Run(); err != nil {
		reportStatus(models.DeploymentStatusInProgress, "Firewalld is not active, skipping firewall configuration")
		return nil // 防火墙未激活，但这不是错误，我们直接返回
	}

	reportStatus(models.DeploymentStatusInProgress, "Firewalld is active, configuring ports")

	// 获取当前开放的端口
	cmd = exec.Command("firewall-cmd", "--list-ports")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list firewall ports: %v", err)
	}

	currentPorts := string(output)

	// 检查并开放应用所需的端口
	for _, port := range spec.Ports {
		portString := fmt.Sprintf("%d/%s", port.Number, port.Protocol)
		if !strings.Contains(currentPorts, portString) {
			reportStatus(models.DeploymentStatusInProgress, fmt.Sprintf("Opening port %s", portString))
			cmd = exec.Command("firewall-cmd", "--add-port="+portString, "--permanent")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to open port %s: %v", portString, err)
			}
		}
	}

	// 重新加载防火墙配置
	cmd = exec.Command("firewall-cmd", "--reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload firewall: %v", err)
	}

	reportStatus(models.DeploymentStatusInProgress, "Firewall configured successfully")
	return nil
}

func renderConfigTemplate(spec *types.PackageSpec, source, destination string, templateVars map[string]interface{}) error {
	// 定义一个helper函数来处理路径
	// resolvePath := func(path string) string {
	// 	if filepath.IsAbs(path) {
	// 		return path
	// 	}
	// 	return filepath.Join(types.GetAppDir(appID), path)
	// }

	// 解析源文件和目标文件的路径
	// sourcePath := resolvePath(source)
	sourcePath := types.ConfigFile(spec, appID, source)
	destinationPath := types.ConfigFile(spec, appID, destination)

	// 验证源文件存在
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source template file does not exist: %s", sourcePath)
	}

	// 读取源模板文件
	tmplContent, err := ioutil.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read template file %s: %v", sourcePath, err)
	}

	// 解析并渲染模板
	tmpl, err := template.New(filepath.Base(sourcePath)).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %v", sourcePath, err)
	}

	var renderedContent bytes.Buffer
	if err := tmpl.Execute(&renderedContent, templateVars); err != nil {
		return fmt.Errorf("failed to render template %s: %v", sourcePath, err)
	}

	// 确保目标目录存在
	destDir := filepath.Dir(destinationPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %v", destDir, err)
	}

	// 写入渲染后的内容到目标文件
	if err := ioutil.WriteFile(destinationPath, renderedContent.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write rendered file %s: %v", destinationPath, err)
	}

	return nil
}

func renderUnitFileTemplate(spec *types.PackageSpec, variables map[string]interface{}) error {
	if globalUnitFile != "" {
		return fmt.Errorf("global unit file is already set: %s", globalUnitFile)
	}

	var destinationPath string
	sourcePath := filepath.Join(globalAppDir, spec.UnitFile.Source)
	if types.IsPrivilegedUser() {
		destinationPath = fmt.Sprintf("/etc/systemd/system/%s.service", spec.Startup.ServiceName)
	} else {
		destinationPath = filepath.Join(os.Getenv("HOME"), ".config/systemd/user", spec.UnitFile.Destination)
	}

	// 验证源文件存在
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source template file does not exist: %s", sourcePath)
	}

	// 读取源模板文件
	tmplContent, err := ioutil.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read template file %s: %v", sourcePath, err)
	}

	// 解析模板
	tmpl, err := template.New(filepath.Base(sourcePath)).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %v", sourcePath, err)
	}

	// 准备 unit 文件特定的变量
	// unitVars, err := prepareUnitVars(spec, variables)
	// if err != nil {
	// 	return fmt.Errorf("failed to prepare unit file variables: %v", err)
	// }

	var renderedContent bytes.Buffer
	if err := tmpl.Execute(&renderedContent, variables); err != nil {
		return fmt.Errorf("failed to render template %s: %v", sourcePath, err)
	}

	// 确保目标目录存在
	destDir := filepath.Dir(destinationPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %v", destDir, err)
	}

	// 写入渲染后的内容到目标文件
	if err := ioutil.WriteFile(destinationPath, renderedContent.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write rendered file %s: %v", destinationPath, err)
	}

	globalUnitFile = destinationPath // 记录全局 unit 文件路径
	// 校验文件是否生成
	if _, err := os.Stat(destinationPath); os.IsNotExist(err) {
		return fmt.Errorf("unit file %s does not exist after rendering", destinationPath)
	}

	return nil
}

func prepareUnitVars(spec *types.PackageSpec, variables map[string]interface{}) (map[string]interface{}, error) {

	unitVars := make(map[string]interface{})

	unitVars["wanted_by"] = "multi-user.target" // 默认值，可以根据需要修改

	// 如果 spec 中指定了 User，则使用指定的 User
	if spec.Startup.User != "" {
		unitVars["user"] = spec.Startup.User
	}

	// 如果 spec 中指定了 Group，则使用指定的 Group
	if spec.Startup.Group != "" {
		unitVars["group"] = spec.Startup.Group
	}

	// 如果是非特权用户，修改 WantedBy
	if !types.IsPrivilegedUser() {
		unitVars["wanted_by"] = "default.target"
	}

	// 遍历 variables 并添加到 unitVars
	for key, value := range variables {
		unitVars[key] = value
	}

	return unitVars, nil
}

func setupSystemdService(spec *types.PackageSpec, variables map[string]interface{}) error {
	fmt.Println("Setting up systemd service...")

	if err := renderUnitFileTemplate(spec, variables); err != nil {
		return fmt.Errorf("failed to render unit file template: %v", err)
	}

	if globalUnitFile == "" {
		return fmt.Errorf("global unit file is not set")
	}

	if spec.Startup.Method != "systemd" {
		fmt.Println("Startup method is not systemd, skipping systemd service setup")
		return nil
	}

	isUserUnit := !types.IsPrivilegedUser()

	fmt.Println("Reloading systemd...")
	if err := reloadSystemd(isUserUnit); err != nil {
		fmt.Printf("Error reloading systemd: %v\n", err)
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	fmt.Println("Enabling systemd service...")
	if err := enableSystemdService(spec.Startup.ServiceName, isUserUnit); err != nil {
		fmt.Printf("Error enabling systemd service: %v\n", err)
		return fmt.Errorf("failed to enable systemd service: %v", err)
	}

	fmt.Println("Systemd service setup completed successfully")
	return nil
}

func reloadSystemd(isUserUnit bool) error {
	var cmd *exec.Cmd
	if isUserUnit {
		cmd = exec.Command("systemctl", "--user", "daemon-reload")
		cmd.Env = append(os.Environ(), fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()))
	} else {
		cmd = exec.Command("systemctl", "daemon-reload")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reload systemd: %v, output: %s", err, string(output))
	}
	return nil
}
func enableSystemdService(serviceName string, isUserUnit bool) error {
	var cmd *exec.Cmd
	if isUserUnit {
		cmd = exec.Command("systemctl", "--user", "enable", serviceName)
		cmd.Env = append(os.Environ(), fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()))
	} else {
		cmd = exec.Command("systemctl", "enable", serviceName)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable systemd service: %v, output: %s", err, string(output))
	}
	return nil
}

func runPostInstallScript(spec *types.PackageSpec) error {
	if spec.PostInstallScript == "" {
		return nil
	}

	cmd := exec.Command("/bin/sh", spec.PostInstallScript)
	cmd.Dir = filepath.Join("/opt", spec.Package)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run post-install script: %v", err)
	}

	return nil
}

func startApplication(spec *types.PackageSpec) error {
	reportStatus(models.DeploymentStatusInProgress, "Starting application")

	if spec.Startup.Method == "systemd" {
		fmt.Println("Using systemd to start the application")

		if !types.IsPrivilegedUser() {
			fmt.Println("Ensuring user systemd is running...")
			if err := ensureUserSystemdRunning(); err != nil {
				errMsg := fmt.Sprintf("failed to ensure user systemd is running: %v", err)
				fmt.Println(errMsg)
				reportStatus(models.DeploymentStatusInProgress, errMsg)
				return fmt.Errorf(errMsg)
			}

			fmt.Println("Ensuring user lingering is enabled...")
			if err := ensureUserLingering(); err != nil {
				errMsg := fmt.Sprintf("failed to ensure user is lingering: %v", err)
				fmt.Println(errMsg)
				reportStatus(models.DeploymentStatusInProgress, errMsg)
				return fmt.Errorf(errMsg)
			}

			// 重新加载用户的 systemd 配置
			if err := reloadUserSystemd(); err != nil {
				errMsg := fmt.Sprintf("failed to reload user systemd: %v", err)
				fmt.Println(errMsg)
				reportStatus(models.DeploymentStatusInProgress, errMsg)
				return fmt.Errorf(errMsg)
			}
		}

		var cmd *exec.Cmd
		if types.IsPrivilegedUser() {
			fmt.Println("Starting systemd service as privileged user")
			cmd = exec.Command("systemctl", "start", spec.Startup.ServiceName)
		} else {
			// if err := ensureUserInSystemdJournalGroup(); err != nil {
			// 	fmt.Printf("Warning: %v\n", err)
			// }

			fmt.Println("Starting systemd service as non-privileged user")
			cmd = exec.Command("systemctl", "--user", "start", spec.Startup.ServiceName)
			uid := os.Getuid()
			cmd.Env = append(os.Environ(),
				fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", uid),
				fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", uid),
				fmt.Sprintf("SYSTEMD_EXEC_PID=%d", os.Getpid()))

			// output, err := cmd.CombinedOutput()
			// if err != nil {
			// 	fmt.Printf("Error starting service: %v\n", err)
			// 	fmt.Printf("Command output: %s\n", string(output))

			// 	// Get systemd user service status
			// 	statusCmd := exec.Command("systemctl", "--user", "status", spec.Startup.ServiceName)
			// 	statusCmd.Env = cmd.Env
			// 	statusOutput, _ := statusCmd.CombinedOutput()
			// 	fmt.Printf("Service status:\n%s\n", string(statusOutput))

			// 	return fmt.Errorf("failed to start systemd service: %v", err)
			// }
		}

		output, err := cmd.CombinedOutput()
		if err != nil {
			errMsg := fmt.Sprintf("failed to start systemd service: %v, output: %s", err, string(output))
			fmt.Println(errMsg)
			reportStatus(models.DeploymentStatusFailed, errMsg)
			return fmt.Errorf(errMsg)
		}

		fmt.Println("Systemd service start command executed, checking service status...")

		// 检查服务状态
		time.Sleep(5 * time.Second) // 给服务更多的启动时间

		checkCmd := exec.Command("systemctl", "is-active", spec.Startup.ServiceName)
		if !types.IsPrivilegedUser() {
			checkCmd = exec.Command("systemctl", "--user", "is-active", spec.Startup.ServiceName)
			checkCmd.Env = cmd.Env
		}

		status, err := checkCmd.Output()
		if err != nil {
			// 如果服务未激活，尝试获取更多信息
			journalCmd := exec.Command("journalctl", "-u", spec.Startup.ServiceName, "--no-pager", "-n", "20")
			if !types.IsPrivilegedUser() {
				journalCmd = exec.Command("journalctl", "--user", "-u", spec.Startup.ServiceName, "--no-pager", "-n", "20")
				journalCmd.Env = cmd.Env
			}
			journalOutput, _ := journalCmd.CombinedOutput()

			errMsg := fmt.Sprintf("error checking service status: %v\nService logs:\n%s", err, string(journalOutput))
			fmt.Println(errMsg)
			reportStatus(models.DeploymentStatusFailed, errMsg)
			return fmt.Errorf(errMsg)
		}

		if strings.TrimSpace(string(status)) != "active" {
			// 如果服务未激活，尝试获取更多信息
			journalCmd := exec.Command("journalctl", "-u", spec.Startup.ServiceName, "--no-pager", "-n", "20")
			if !types.IsPrivilegedUser() {
				journalCmd = exec.Command("journalctl", "--user", "-u", spec.Startup.ServiceName, "--no-pager", "-n", "20")
				journalCmd.Env = cmd.Env
			}
			journalOutput, _ := journalCmd.CombinedOutput()

			errMsg := fmt.Sprintf("service is not active after start attempt. Status: %s\nService logs:\n%s", strings.TrimSpace(string(status)), string(journalOutput))
			fmt.Println(errMsg)
			reportStatus(models.DeploymentStatusFailed, errMsg)
			return fmt.Errorf(errMsg)
		}

		fmt.Println("Systemd service started successfully")
		reportStatus(models.DeploymentStatusInProgress, "Application started successfully via systemd")

	} else {
		fmt.Println("Starting application directly (non-systemd)")
		// 如果不是 systemd，则直接运行二进制文件
		binaryPath := filepath.Join(types.GetAppDir(appID), spec.Binary.Path)
		cmd := exec.Command(binaryPath, spec.Startup.Args...)

		for k, v := range spec.Startup.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}

		// 使用 Start() 而不是 Run()，这样应用程序可以在后台运行
		if err := cmd.Start(); err != nil {
			errMsg := fmt.Sprintf("Failed to start application: %v", err)
			fmt.Println(errMsg)
			reportStatus(models.DeploymentStatusFailed, errMsg)
			return fmt.Errorf(errMsg)
		}

		fmt.Printf("Application started with PID %d\n", cmd.Process.Pid)
		reportStatus(models.DeploymentStatusInProgress, fmt.Sprintf("Application started successfully with PID %d", cmd.Process.Pid))

		// 可以在这里添加一些简单的健康检查逻辑
		time.Sleep(2 * time.Second) // 给应用一些启动时间
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			errMsg := "Application exited immediately after starting"
			fmt.Println(errMsg)
			reportStatus(models.DeploymentStatusFailed, errMsg)
			return fmt.Errorf(errMsg)
		}
	}

	fmt.Println("Application start process completed")
	return nil
}

func ensureUserSystemdRunning() error {
	cmd := exec.Command("systemctl", "--user", "is-active", "dbus.socket")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()),
		fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))

	output, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "active" {
		startCmd := exec.Command("systemctl", "--user", "start", "dbus.socket")
		startCmd.Env = cmd.Env
		if err := startCmd.Run(); err != nil {
			return fmt.Errorf("failed to start user dbus.socket: %v", err)
		}
	}
	return nil
}

func ensureUserLingering() error {
	user := os.Getenv("USER")
	cmd := exec.Command("loginctl", "show-user", user, "--property=Linger")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check lingering status: %v, output: %s", err, string(output))
	}

	if strings.TrimSpace(string(output)) != "Linger=yes" {
		fmt.Printf("Warning: Lingering is not enabled for user %s. Some services may not start automatically.\n", user)
		fmt.Println("To enable lingering, run 'sudo loginctl enable-linger $USER' and restart the deployment.")
	}

	return nil
}

func reloadUserSystemd() error {
	cmd := exec.Command("systemctl", "--user", "daemon-reload")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()),
		fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reload user systemd: %v, output: %s", err, string(output))
	}
	return nil
}

func getTemplateVarsFromController() (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/variables?agent_code=%s&app_id=%s", controllerURL, agentCode, appID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get template vars: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get template vars: HTTP status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read template vars: %v", err)
	}

	// 使用 interface{} 类型以支持数组（如 etcd_endpoints）
	var variables map[string]interface{}
	err = json.Unmarshal(body, &variables)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal template vars: %v", err)
	}

	return variables, nil
}
func downloadPackage() error {
	reportStatus(models.DeploymentStatusInProgress, "Downloading package")

	if packageURL != "" {
		// 如果存在 packageUrl，直接从该 URL 下载
		return downloadFromURL(packageURL)
	}

	// 否则，从 Minio 下载最新版本
	return downloadFromMinio()
}

func downloadFromURL(url string) error {
	reportStatus(models.DeploymentStatusInProgress, fmt.Sprintf("Downloading package from URL: %s", url))

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download package from URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download package, HTTP status: %d", resp.StatusCode)
	}

	out, err := os.Create("package.zip")
	if err != nil {
		return fmt.Errorf("failed to create package file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save package file: %v", err)
	}

	reportStatus(models.DeploymentStatusInProgress, "Successfully downloaded package from URL")
	return nil
}

func downloadFromMinio() error {
	reportStatus(models.DeploymentStatusInProgress, "Downloading package from Minio")

	// 创建 Minio 客户端
	minioClient, err := minio.New(minioEndpoint, minioAccessKeyID, minioSecretAccessKey, false)
	if err != nil {
		return fmt.Errorf("failed to create Minio client: %v", err)
	}

	// 构建对象前缀
	prefix := fmt.Sprintf("application/%s/", appID)

	// 列出所有匹配的对象
	objectCh := minioClient.ListObjects(minioBucketName, prefix, true, nil)

	var latestVersion string
	var latestObject minio.ObjectInfo

	// 遍历所有对象，找到最新的版本
	for object := range objectCh {
		if object.Err != nil {
			return fmt.Errorf("error listing objects: %v", object.Err)
		}

		// 从对象名称中提取版本
		parts := strings.Split(object.Key, "-")
		if len(parts) < 2 {
			continue
		}
		version := strings.TrimSuffix(parts[len(parts)-1], ".zip")

		// 如果这是第一个版本或者比当前最新版本更新，则更新
		if latestVersion == "" || version > latestVersion {
			latestVersion = version
			latestObject = object
		}
	}

	if latestVersion == "" {
		return fmt.Errorf("no package found for application %s", appID)
	}

	// 从 Minio 下载最新版本的文件
	err = minioClient.FGetObject(minioBucketName, latestObject.Key, "package.zip", minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to download package from Minio: %v", err)
	}

	reportStatus(models.DeploymentStatusInProgress, fmt.Sprintf("Successfully downloaded package: %s (version %s)", latestObject.Key, latestVersion))
	return nil
}
func setupConfiguration(spec *types.PackageSpec, templateVars map[string]interface{}) error {

	fmt.Printf("Application directory: %s\n", globalAppDir)
	fmt.Printf("Configuration directory: %s\n", globalConfigDir)

	for _, template := range spec.Config.Templates {
		sourcePath := filepath.Join(globalAppDir, template.Source)
		destinationPath := filepath.Join(globalConfigDir, template.Destination)
		// if template.Type == "config_file" {
		if err := renderConfigTemplate(spec, sourcePath, destinationPath, templateVars); err != nil {
			return fmt.Errorf("failed to render config template %s: %v", template.Source, err)
		}
	}

	// 如果有主配置文件，确保它在正确的位置
	if spec.Config.MainFile != "" {
		mainFilePath := filepath.Join(globalConfigDir, spec.Config.MainFile)
		if _, err := os.Stat(mainFilePath); os.IsNotExist(err) {
			return fmt.Errorf("main configuration file %s does not exist after template rendering", mainFilePath)
		}
	}

	return nil
}

// func ensureUserInSystemdJournalGroup() error {
// 	currentUser, err := user.Current()
// 	if err != nil {
// 		return fmt.Errorf("failed to get current user: %v", err)
// 	}

// 	cmd := exec.Command("groups", currentUser.Username)
// 	output, err := cmd.Output()
// 	if err != nil {
// 		return fmt.Errorf("failed to get user groups: %v", err)
// 	}

// 	if !strings.Contains(string(output), "systemd-journal") {
// 		fmt.Println("User is not part of systemd-journal group. Adding...")
// 		addCmd := exec.Command("sudo", "usermod", "-a", "-G", "systemd-journal", currentUser.Username)
// 		if err := addCmd.Run(); err != nil {
// 			return fmt.Errorf("failed to add user to systemd-journal group: %v", err)
// 		}
// 		fmt.Println("User added to systemd-journal group. A logout/login may be required for changes to take effect.")
// 	}

// 	return nil
// }

func checkAndStopExistingService(appID string) error {
	reportStatus(models.DeploymentStatusInProgress, "Checking for existing service")

	isRunning, err := isServiceRunning(appID)
	if err != nil {
		return fmt.Errorf("failed to check service status: %v", err)
	}

	if isRunning {
		reportStatus(models.DeploymentStatusInProgress, "Stopping existing service")
		if err := stopService(appID); err != nil {
			return fmt.Errorf("failed to stop existing service: %v", err)
		}

		// 等待服务完全停止
		for i := 0; i < 30; i++ { // 最多等待30秒
			time.Sleep(time.Second)
			isRunning, err = isServiceRunning(appID)
			if err != nil {
				return fmt.Errorf("failed to check service status: %v", err)
			}
			if !isRunning {
				break
			}
		}

		if isRunning {
			return fmt.Errorf("service did not stop within the timeout period")
		}
	}

	reportStatus(models.DeploymentStatusInProgress, "Service is not running, proceeding with deployment")
	return nil
}

func isServiceRunning(serviceName string) (bool, error) {
	var cmd *exec.Cmd
	if types.IsPrivilegedUser() {
		cmd = exec.Command("systemctl", "is-active", serviceName)
	} else {
		cmd = exec.Command("systemctl", "--user", "is-active", serviceName)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()),
			fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果服务不存在或未运行，systemctl 会返回非零退出码
		return false, nil
	}

	return strings.TrimSpace(string(output)) == "active", nil
}

func stopService(serviceName string) error {
	var cmd *exec.Cmd
	if types.IsPrivilegedUser() {
		cmd = exec.Command("systemctl", "stop", serviceName)
	} else {
		cmd = exec.Command("systemctl", "--user", "stop", serviceName)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()),
			fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop service: %v, output: %s", err, string(output))
	}

	return nil
}
