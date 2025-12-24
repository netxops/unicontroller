package controller

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/minio/minio-go/v7"
	"github.com/pkg/sftp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/ssh"
)

type DeploymentManager struct {
	ConfigManager   *ConfigManager
	RegistryManager *RegistryManager
	MinioManager    *MinioManager
	MongoClient     *mongo.Client
	deployments     map[string]*models.Deployment
	// deploymentSemaphore chan struct{}
	deviceSemaphore chan struct{}

	// deploymentService *deploymentservice.DeploymentService
	mutex sync.RWMutex
}

func ProvideDeployManager(configManager *ConfigManager, registryManager *RegistryManager, minio *MinioManager, mongoClient *mongo.Client) *DeploymentManager {
	return &DeploymentManager{
		ConfigManager:   configManager,
		RegistryManager: registryManager,
		MongoClient:     mongoClient,
		MinioManager:    minio,
		deployments:     make(map[string]*models.Deployment),
		deviceSemaphore: make(chan struct{}, configManager.Config.BaseConfig.Deployment.ConcurrentDeployments),
	}
}
func (dm *DeploymentManager) CreateDeployment(req models.DeploymentRequest) (*models.Deployment, error) {
	// 获取包的URL
	// packageUrl, err := dm.MinioManager.GetProxyPackageURL(dm.ConfigManager.Config.Minio.BucketName, fmt.Sprintf("%s/%s", req.Type, req.AppID))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get package URL from minio: %v", err)
	// }

	// 准备部署变量
	// variables := req.Variables
	// if variables == nil {
	// 	variables = make(map[string]interface{})
	// }
	// variables["package_url"] = packageUrl
	// ctx := context.Background()

	// vars, err := dm.RegistryManager.GetVariables(ctx, "xxxxx", "xxxxx")
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get variables: %v", err)
	// }

	// for k, v := range vars {
	// 	variables[k] = v
	// }
	// variables["uniops_agent_etcd_endpoint"] = variables["etcd_endpoints"]

	// 创建部署请求
	deployment := &models.Deployment{
		ID:            req.ID,
		AppID:         req.AppID,
		Type:          req.Type,
		Version:       req.Version,
		OperationType: req.OperationType, // 设置操作类型（部署或卸载）
		Variables:     req.Variables,     // 传递 Variables，包含 deployment_tool_object_name
		TargetDevices: make([]models.TargetDevice, len(req.TargetDevices)),
		OverallStatus: models.DeploymentStatusPending,
		StartTime:     time.Now(),
	}

	// 如果 OperationType 未设置，默认为部署
	if deployment.OperationType == "" {
		deployment.OperationType = models.OperationTypeDeploy
	}

	// 记录 Variables 内容（用于调试）
	if deployment.Variables != nil {
		log.Printf("[CreateDeployment] Variables已设置，数量: %d", len(deployment.Variables))
		if objName, ok := deployment.Variables["deployment_tool_object_name"].(string); ok {
			log.Printf("[CreateDeployment] Variables中包含部署工具ObjectName: %s", objName)
		} else {
			log.Printf("[CreateDeployment] Variables中未找到deployment_tool_object_name")
		}
	} else {
		log.Printf("[CreateDeployment] Variables为nil")
	}

	for i, device := range req.TargetDevices {
		deployment.TargetDevices[i] = models.TargetDevice{
			AgentCode:    device.AgentCode,
			IP:           device.IP,
			LoginMethod:  device.LoginMethod,
			LoginDetails: device.LoginDetails,
			Name:         device.Name,
			Status:       models.DeploymentStatusPending,
		}
	}

	// 保存部署到数据库
	err := dm.saveDeployment(deployment)
	if err != nil {
		return nil, fmt.Errorf("failed to save deployment: %v", err)
	}

	// 启动异步处理部署的 goroutine
	go dm.processDeployment(deployment)

	// 尝试获取信号量
	// select {
	// case dm.deploymentSemaphore <- struct{}{}:
	// 	// 成功获取信号量，可以开始新的部署
	// 	go func() {
	// 		defer func() { <-dm.deploymentSemaphore }() // 部署完成后释放信号量
	// 		dm.processDeployment(deployment)
	// 	}()
	// default:
	// 	// 无法获取信号量，达到最大并发数
	// 	return nil, fmt.Errorf("max concurrent deployments (%d) reached, please try again later", dm.ConfigManager.Config.Deployment.ConcurrentDeployments)
	// }

	return deployment, nil
}

// 在 DeploymentManager 中更新此方法
func (dm *DeploymentManager) GetDeployment(deploymentID string) (*models.Deployment, error) {
	// 创建一个上下文，设置超时时间为5秒
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 获取 deployments 集合
	collection := dm.MongoClient.Database(dm.ConfigManager.Config.Database.Database).Collection("deployments")

	// 创建一个 Deployment 对象来存储结果
	var deployment models.Deployment

	// 使用 FindOne 方法查找指定 ID 的部署
	err := collection.FindOne(ctx, bson.M{"id": deploymentID}).Decode(&deployment)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// 如果没有找到文档，返回自定义错误
			return nil, fmt.Errorf("deployment not found: %s", deploymentID)
		}
		// 如果是其他错误，返回该错误
		return nil, fmt.Errorf("error fetching deployment: %v", err)
	}

	// 返回找到的部署
	return &deployment, nil
}

// func (dm *DeploymentManager) GetDeploymentStatus(deploymentID string) (*models.Deployment, error) {
// 	deployment, err := dm.GetDeployment(deploymentID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	status := &models.Deployment{
// 		ID:            deployment.ID,
// 		OverallStatus: deployment.OverallStatus,
// 		StartTime:     deployment.StartTime,
// 		EndTime:       deployment.EndTime,
// 		TargetDevices: make([]models.TargetDevice, len(deployment.TargetDevices)),
// 	}

// 	for i, device := range deployment.TargetDevices {
// 		status.TargetDevices[i] = models.TargetDevice{
// 			AgentCode: device.AgentCode,
// 			Name:      device.Name,
// 			Status:    device.Status,
// 			Message:   device.Message,
// 		}
// 	}

// 	return status, nil
// }

func (dm *DeploymentManager) ListDeployments() ([]models.Deployment, error) {
	// 创建一个上下文，设置超时时间为10秒
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 获取 deployments 集合
	collection := dm.MongoClient.Database(dm.ConfigManager.Config.Database.Database).Collection("deployments")

	// 创建一个切片来存储结果
	var deployments []models.Deployment

	// 使用 Find 方法查找所有部署
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("error fetching deployments: %v", err)
	}
	defer cursor.Close(ctx)

	// 遍历结果并解码到 deployments 切片中
	if err = cursor.All(ctx, &deployments); err != nil {
		return nil, fmt.Errorf("error decoding deployments: %v", err)
	}

	return deployments, nil
}

// func (dm *DeploymentManager) processDeployment(deployment *models.Deployment) {
// 	dm.mutex.Lock()
// 	deployment.OverallStatus = models.DeploymentStatusInProgress
// 	for i := range deployment.TargetDevices {
// 		deployment.TargetDevices[i].Status = models.DeploymentStatusInProgress
// 	}
// 	dm.saveDeployment(deployment)
// 	dm.mutex.Unlock()

// 	tempFile, err := os.CreateTemp("", "deployment-agent-*")
// 	if err != nil {
// 		fmt.Printf("failed to create temp file: %v", err)
// 		return
// 	}
// 	// defer tempFile.Close()

// 	// 1. 从 MinIO 下载 deployment-agent
// 	agentFileName := "deployment-tools/deployment-agent"
// 	agentFilePath, err := dm.downloadAgentFromMinio(agentFileName, tempFile)
// 	if err != nil {
// 		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to download deployment-agent: %v", err))
// 		return
// 	}
// 	defer os.Remove(agentFilePath) // 清理临时文件

// 	// 2. 遍历目标设备，执行部署
// 	var wg sync.WaitGroup
// 	for i := range deployment.TargetDevices {
// 		wg.Add(1)
// 		go func(i int) {
// 			defer wg.Done()
// 			err := dm.deployToDevice(deployment, deployment.TargetDevices[i], agentFilePath)
// 			if err != nil {
// 				dm.logDeploymentError(deployment, fmt.Sprintf("Failed to deploy to device %s: %v", deployment.TargetDevices[i].Name, err))
// 				deployment.TargetDevices[i].Status = models.DeploymentStatusFailed
// 				deployment.TargetDevices[i].Message = err.Error()
// 			} else {
// 				deployment.TargetDevices[i].Status = models.DeploymentStatusCompleted
// 			}
// 			dm.saveDeployment(deployment)
// 		}(i)
// 	}

// 	wg.Wait()

// 	dm.mutex.Lock()
// 	defer dm.mutex.Unlock()
// 	deployment.EndTime = time.Now()
// 	deployment.OverallStatus = dm.calculateOverallStatus(deployment.TargetDevices)
// 	dm.saveDeployment(deployment)
// 	dm.logDeploymentCompletion(deployment)
// }

func (dm *DeploymentManager) processDeployment(deployment *models.Deployment) {
	dm.logDeploymentStep(deployment, "Starting deployment process")
	dm.mutex.Lock()
	deployment.OverallStatus = models.DeploymentStatusInProgress
	for i := range deployment.TargetDevices {
		deployment.TargetDevices[i].Status = models.DeploymentStatusInProgress
	}
	dm.saveDeployment(deployment)
	dm.mutex.Unlock()

	tempFile, err := os.CreateTemp("", "deployment-agent-*")
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to create temp file: %v", err))
		return
	}
	defer os.Remove(tempFile.Name())
	dm.logDeploymentStep(deployment, "Created temporary file for deployment agent")

	// 从 Variables 获取部署工具 ObjectName（如果提供）
	deploymentToolObjectName := ""
	if deployment.Variables != nil {
		log.Printf("[processDeployment] Variables不为空，Variables数量: %d", len(deployment.Variables))
		log.Printf("[processDeployment] Variables内容: %+v", deployment.Variables)
		if objName, ok := deployment.Variables["deployment_tool_object_name"].(string); ok && objName != "" {
			deploymentToolObjectName = objName
			dm.logDeploymentStep(deployment, fmt.Sprintf("从Variables获取部署工具ObjectName: %s", deploymentToolObjectName))
			log.Printf("[processDeployment] 成功从Variables获取部署工具ObjectName: %s", deploymentToolObjectName)
		} else {
			log.Printf("[processDeployment] Variables中未找到deployment_tool_object_name或为空")
			log.Printf("[processDeployment] deployment_tool_object_name类型断言结果: ok=%v", ok)
			if objName != "" {
				log.Printf("[processDeployment] deployment_tool_object_name值: %s", objName)
			}
		}
	} else {
		log.Printf("[processDeployment] Variables为nil")
	}

	// 如果未提供部署工具信息，使用默认路径（向后兼容）
	if deploymentToolObjectName == "" {
		deploymentToolObjectName = "deployment-tools/deployment-agent"
		dm.logDeploymentStep(deployment, fmt.Sprintf("未提供部署工具信息，使用默认路径: %s", deploymentToolObjectName))
	}

	// 记录MinIO配置信息（不包含敏感信息）
	bucketName := dm.ConfigManager.Config.Minio.BucketName
	dm.logDeploymentStep(deployment, fmt.Sprintf("准备下载部署工具: bucket=%s, objectName=%s", bucketName, deploymentToolObjectName))

	// 检查MinIO客户端是否已初始化
	if dm.MinioManager.client == nil {
		dm.logDeploymentError(deployment, "MinIO客户端未初始化，尝试初始化...")
		err := dm.MinioManager.initMinioClient()
		if err != nil {
			dm.logDeploymentError(deployment, fmt.Sprintf("初始化MinIO客户端失败: %v", err))
			return
		}
		dm.logDeploymentStep(deployment, "MinIO客户端初始化成功")
	}

	// 记录MinIO配置摘要（不包含敏感信息）
	minioConfig := dm.ConfigManager.Config.Minio
	dm.logDeploymentStep(deployment, fmt.Sprintf("MinIO配置: endpoint=%s, bucketName=%s, useSSL=%v, hasAccessKey=%v, hasSecretKey=%v",
		minioConfig.Endpoint, minioConfig.BucketName, minioConfig.UseSSL,
		minioConfig.AccessKeyID != "", minioConfig.SecretAccessKey != ""))

	agentFilePath, err := dm.downloadAgentFromMinio(deploymentToolObjectName, tempFile)
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to download deployment tool: %v", err))
		dm.logDeploymentError(deployment, fmt.Sprintf("下载参数: bucket=%s, objectName=%s, tempFile=%s", bucketName, deploymentToolObjectName, tempFile.Name()))
		return
	}
	dm.logDeploymentStep(deployment, fmt.Sprintf("Downloaded deployment tool from MinIO: %s", agentFilePath))

	var wg sync.WaitGroup
	for i := range deployment.TargetDevices {
		wg.Add(1)
		go func(i int) {
			deviceName := deployment.TargetDevices[i].Name
			dm.logDeploymentStep(deployment, fmt.Sprintf("Starting deployment for device: %s", deviceName))

			// 获取信号量
			dm.deviceSemaphore <- struct{}{}
			defer func() { <-dm.deviceSemaphore }() // 释放信号量
			defer wg.Done()

			err := dm.deployToDevice(deployment, deployment.TargetDevices[i], agentFilePath)
			if err != nil {
				errMsg := fmt.Sprintf("Failed to deploy to device %s: %v", deviceName, err)
				dm.logDeploymentError(deployment, errMsg)
				deployment.TargetDevices[i].Status = models.DeploymentStatusFailed
				deployment.TargetDevices[i].Message = err.Error()
			} else {
				dm.logDeploymentStep(deployment, fmt.Sprintf("Successfully deployed to device: %s", deviceName))
				deployment.TargetDevices[i].Status = models.DeploymentStatusCompleted
			}
			dm.saveDeployment(deployment)
		}(i)
	}

	wg.Wait()
	dm.logDeploymentStep(deployment, "All device deployments completed")

	dm.mutex.Lock()
	defer dm.mutex.Unlock()
	deployment.EndTime = time.Now()
	deployment.OverallStatus = dm.calculateOverallStatus(deployment.TargetDevices)
	err = dm.saveDeployment(deployment)
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to save final deployment status: %v", err))
	}
	dm.logDeploymentCompletion(deployment)
}

func (dm *DeploymentManager) logDeploymentStep(deployment *models.Deployment, message string) {
	logEntry := fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), message)
	fmt.Println(logEntry) // 打印到控制台

	// 将日志添加到部署记录中
	deployment.Logs = append(deployment.Logs, logEntry)

	// 每10条日志保存一次，确保外部可以及时获取到日志
	// 使用mutex保护，避免并发写入问题
	if len(deployment.Logs)%10 == 0 {
		dm.mutex.Lock()
		_ = dm.saveDeployment(deployment) // 忽略错误，避免影响部署流程
		dm.mutex.Unlock()
	}

	// 可以考虑在这里添加将日志写入文件或发送到日志系统的代码
}
func (dm *DeploymentManager) downloadAgentFromMinio(objectName string, tempFile *os.File) (string, error) {
	bucketName := dm.ConfigManager.Config.Minio.BucketName
	log.Printf("[downloadAgentFromMinio] 开始下载: bucket=%s, objectName=%s, tempFile=%s", bucketName, objectName, tempFile.Name())

	// 优先尝试使用 MinIO Proxy URL 通过 HTTP 下载
	proxyURL, err := dm.MinioManager.GetProxyPackageURL(bucketName, objectName)
	if err != nil {
		log.Printf("[downloadAgentFromMinio] 获取MinIO Proxy URL失败，回退到直接MinIO下载: %v", err)
		// 回退到直接 MinIO 下载（向后兼容）
		return dm.downloadFromMinioDirect(bucketName, objectName, tempFile)
	}

	log.Printf("[downloadAgentFromMinio] 获取MinIO Proxy URL成功: %s", proxyURL)

	// 通过 HTTP 从 MinIO Proxy 下载文件
	err = dm.downloadFromURL(proxyURL, tempFile)
	if err != nil {
		log.Printf("[downloadAgentFromMinio] 通过HTTP下载失败，回退到直接MinIO下载: %v", err)
		// 回退到直接 MinIO 下载（向后兼容）
		return dm.downloadFromMinioDirect(bucketName, objectName, tempFile)
	}

	log.Printf("[downloadAgentFromMinio] 通过HTTP下载成功: bucket=%s, objectName=%s, tempFile=%s", bucketName, objectName, tempFile.Name())
	return tempFile.Name(), nil
}

// downloadFromMinioDirect 直接从 MinIO 下载文件（向后兼容方法）
func (dm *DeploymentManager) downloadFromMinioDirect(bucketName, objectName string, tempFile *os.File) (string, error) {
	log.Printf("[downloadFromMinioDirect] 开始直接MinIO下载: bucket=%s, objectName=%s, tempFile=%s", bucketName, objectName, tempFile.Name())

	// 检查 MinIO 客户端是否已初始化
	if dm.MinioManager.client == nil {
		log.Printf("[downloadFromMinioDirect] MinIO客户端未初始化，尝试初始化...")
		err := dm.MinioManager.initMinioClient()
		if err != nil {
			log.Printf("[downloadFromMinioDirect] 初始化MinIO客户端失败: %v (error type: %T)", err, err)
			return "", fmt.Errorf("MinIO客户端未初始化且初始化失败: %v", err)
		}
		log.Printf("[downloadFromMinioDirect] MinIO客户端初始化成功")
	}

	// 检查bucket是否存在
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exists, err := dm.MinioManager.client.BucketExists(ctx, bucketName)
	if err != nil {
		log.Printf("[downloadFromMinioDirect] 检查bucket存在性失败: %v (error type: %T)", err, err)
		// 即使检查失败，也尝试下载（可能只是权限问题）
		log.Printf("[downloadFromMinioDirect] 继续尝试下载，忽略bucket存在性检查错误")
	} else {
		log.Printf("[downloadFromMinioDirect] Bucket存在性检查: bucket=%s, exists=%v", bucketName, exists)
		if !exists {
			return "", fmt.Errorf("bucket %s does not exist", bucketName)
		}
	}

	// 尝试列出对象，用于调试
	log.Printf("[downloadFromMinioDirect] 尝试列出对象以验证路径: bucket=%s, objectName=%s", bucketName, objectName)
	objectCh := dm.MinioManager.client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
		Prefix:    objectName,
		Recursive: false,
	})
	found := false
	for object := range objectCh {
		if object.Err != nil {
			log.Printf("[downloadFromMinioDirect] 列出对象时出错: %v", object.Err)
			break
		}
		log.Printf("[downloadFromMinioDirect] 找到对象: %s (size: %d)", object.Key, object.Size)
		if object.Key == objectName {
			found = true
			break
		}
	}
	if !found {
		log.Printf("[downloadFromMinioDirect] 警告: 未找到精确匹配的对象 %s，但将继续尝试下载", objectName)
	}

	err = dm.MinioManager.DownloadFile(bucketName, objectName, tempFile.Name())
	if err != nil {
		log.Printf("[downloadFromMinioDirect] 下载失败: bucket=%s, objectName=%s, error=%v (error type: %T)", bucketName, objectName, err, err)
		return "", fmt.Errorf("failed to download file from MinIO: %v", err)
	}

	log.Printf("[downloadFromMinioDirect] 下载成功: bucket=%s, objectName=%s, tempFile=%s", bucketName, objectName, tempFile.Name())
	return tempFile.Name(), nil
}

// downloadFromURL 通过 HTTP 从 URL 下载文件
func (dm *DeploymentManager) downloadFromURL(url string, tempFile *os.File) error {
	log.Printf("[downloadFromURL] 开始通过HTTP下载: url=%s, tempFile=%s", url, tempFile.Name())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Minute,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	// 获取文件大小（如果可用）
	contentLength := resp.ContentLength
	if contentLength > 0 {
		log.Printf("[downloadFromURL] 文件大小: %d bytes", contentLength)
	}

	// 下载文件
	written, err := io.Copy(tempFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	log.Printf("[downloadFromURL] 下载完成: url=%s, written=%d bytes", url, written)
	return nil
}
func (dm *DeploymentManager) deployToDevice(deployment *models.Deployment, device models.TargetDevice, agentFilePath string) error {
	dm.logDeploymentStep(deployment, fmt.Sprintf("Starting deployment to device: %s", device.Name))

	var client *ssh.Client
	var err error

	switch device.LoginMethod {
	case models.LoginMethodSSH:
		dm.logDeploymentStep(deployment, fmt.Sprintf("Connecting to device %s via SSH", device.Name))
		client, err = dm.connectSSH(device)
	case models.LoginMethodWinRM:
		dm.logDeploymentStep(deployment, fmt.Sprintf("WinRM not implemented for device %s", device.Name))
		return fmt.Errorf("WinRM not implemented yet")
	case models.LoginMethodAPIToken:
		dm.logDeploymentStep(deployment, fmt.Sprintf("API Token method not implemented for device %s", device.Name))
		return fmt.Errorf("API Token method not implemented yet")
	default:
		dm.logDeploymentStep(deployment, fmt.Sprintf("Unsupported login method for device %s: %s", device.Name, device.LoginMethod))
		return fmt.Errorf("unsupported login method: %s", device.LoginMethod)
	}

	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to connect to device %s: %v", device.Name, err))
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.Close()
	dm.logDeploymentStep(deployment, fmt.Sprintf("Successfully connected to device %s", device.Name))

	// 创建 SFTP 客户端
	dm.logDeploymentStep(deployment, fmt.Sprintf("Creating SFTP client for device %s", device.Name))
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to create SFTP client for device %s: %v", device.Name, err))
		return fmt.Errorf("failed to create SFTP client: %v", err)
	}
	defer sftpClient.Close()
	dm.logDeploymentStep(deployment, fmt.Sprintf("SFTP client created for device %s", device.Name))

	// 上传 deployment-agent 到目标服务器
	dm.logDeploymentStep(deployment, fmt.Sprintf("Uploading deployment-agent to device %s", device.Name))
	remoteFile, err := sftpClient.Create("/tmp/deployment-agent")
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to create remote file on device %s: %v", device.Name, err))
		return fmt.Errorf("failed to create remote file: %v", err)
	}

	localFile, err := os.Open(agentFilePath)
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to open local file for device %s: %v", device.Name, err))
		return fmt.Errorf("failed to open local file: %v", err)
	}
	defer localFile.Close()

	_, err = io.Copy(remoteFile, localFile)
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to copy file to device %s: %v", device.Name, err))
		return fmt.Errorf("failed to copy file: %v", err)
	}
	remoteFile.Close()
	dm.logDeploymentStep(deployment, fmt.Sprintf("Successfully uploaded deployment-agent to device %s", device.Name))

	// 执行部署命令
	dm.logDeploymentStep(deployment, fmt.Sprintf("Creating SSH session for device %s", device.Name))
	session, err := client.NewSession()
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to create session for device %s: %v", device.Name, err))
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	ctr, err := dm.RegistryManager.GetControllerAddress()
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to get controller address for device %s: %v", device.Name, err))
		return fmt.Errorf("failed to get controller address: %v", err)
	}

	// 获取最新的包 URL
	dm.logDeploymentStep(deployment, fmt.Sprintf("Getting latest package URL for device %s", device.Name))
	packageURL, err := dm.MinioManager.GetProxyLatestPackageURL(dm.ConfigManager.Config.Minio.BucketName, fmt.Sprintf("application/%s", deployment.AppID))
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to get latest package URL for device %s: %v", device.Name, err))
		return fmt.Errorf("failed to get latest package URL: %v", err)
	}

	// 构建 deployment-agent 命令
	operationType := "deploy"
	if deployment.OperationType == models.OperationTypeUninstall {
		operationType = "uninstall"
	} else if deployment.OperationType == models.OperationTypeRestart {
		operationType = "restart"
	}

	cmd := fmt.Sprintf(`chmod +x /tmp/deployment-agent && /tmp/deployment-agent \
        --deployment-id %s \
        --agent-code %s \
        --app-id %s \
        --controller-url %s \
        --package-url %s \
        --operation %s`,
		deployment.ID,
		device.AgentCode,
		deployment.AppID,
		"http://"+ctr,
		packageURL,
		operationType)

	dm.logDeploymentStep(deployment, fmt.Sprintf("Executing %s command on device %s", operationType, device.Name))
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		dm.logDeploymentError(deployment, fmt.Sprintf("Failed to run command on device %s: %v, output: %s", device.Name, err, string(output)))
		return fmt.Errorf("failed to run command: %v, output: %s", err, string(output))
	}

	// 将输出按行分割，并为每行添加主机名
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		logLine := fmt.Sprintf("[%s] %s", device.Name, line)
		dm.logDeploymentStep(deployment, logLine)
		fmt.Println(logLine)
	}

	operationType = "deployment"
	if deployment.OperationType == models.OperationTypeUninstall {
		operationType = "uninstall"
	} else if deployment.OperationType == models.OperationTypeRestart {
		operationType = "restart"
	}
	dm.logDeploymentStep(deployment, fmt.Sprintf("%s completed successfully for device %s", strings.Title(operationType), device.Name))

	// 在部署过程中定期保存日志，确保外部可以获取到最新日志
	// 使用mutex保护，避免并发写入问题
	dm.mutex.Lock()
	err = dm.saveDeployment(deployment)
	dm.mutex.Unlock()
	if err != nil {
		log.Printf("Failed to save deployment logs during deployment: %v", err)
	}

	return nil
}

func (dm *DeploymentManager) connectSSH(device models.TargetDevice) (*ssh.Client, error) {
	var auth []ssh.AuthMethod

	if device.LoginDetails.SSHKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(device.LoginDetails.SSHKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH key: %v", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	} else if device.LoginDetails.Password != "" {
		auth = append(auth, ssh.Password(device.LoginDetails.Password))
	} else {
		return nil, fmt.Errorf("no SSH key or password provided")
	}

	config := &ssh.ClientConfig{
		User:            device.LoginDetails.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 注意：在生产环境中应验证主机密钥
	}

	return ssh.Dial("tcp", device.IP+":22", config)
}

func (dm *DeploymentManager) logDeploymentError(deployment *models.Deployment, errorMsg string) {
	fmt.Printf("Error in deployment %s: %s\n", deployment.ID, errorMsg)
	// 这里可以添加更多的错误处理逻辑，比如发送警报等
}

func (dm *DeploymentManager) logDeploymentCompletion(deployment *models.Deployment) {
	duration := deployment.EndTime.Sub(deployment.StartTime)
	fmt.Printf("Deployment %s completed with status: %s. Duration: %v\n",
		deployment.ID, deployment.OverallStatus, duration)
	// 添加日志到 deployment.Logs
	logEntry := fmt.Sprintf("[%s] Deployment completed with status: %s. Duration: %v",
		time.Now().Format(time.RFC3339), deployment.OverallStatus, duration)
	deployment.Logs = append(deployment.Logs, logEntry)
	// 保存更新后的日志
	err := dm.saveDeployment(deployment)
	if err != nil {
		fmt.Printf("Failed to save deployment completion log: %v\n", err)
	}
}

func (dm *DeploymentManager) UpdateDeploymentDeviceStatus(deploymentID string, deviceStatus models.TargetDevice) error {
	// 获取当前部署
	deployment, err := dm.GetDeployment(deploymentID)
	if err != nil {
		return err
	}

	// 更新特定设备的状态
	updated := false
	for i, device := range deployment.TargetDevices {
		if device.AgentCode == deviceStatus.AgentCode {
			deployment.TargetDevices[i].Status = deviceStatus.Status
			deployment.TargetDevices[i].Message = deviceStatus.Message
			// deployment.TargetDevices[i].Results = deviceStatus.Results
			updated = true
			break
		}
	}

	if !updated {
		return fmt.Errorf("device with agent code %s not found in deployment", deviceStatus.AgentCode)
	}

	// 重新计算整体部署状态
	deployment.OverallStatus = dm.calculateOverallStatus(deployment.TargetDevices)

	// 保存更新后的部署信息
	return dm.saveDeployment(deployment)
}

func (dm *DeploymentManager) calculateOverallStatus(devices []models.TargetDevice) models.DeploymentStatus {
	allCompleted := true
	anyFailed := false

	for _, device := range devices {
		switch device.Status {
		case models.DeploymentStatusCompleted:
			// Do nothing
		case models.DeploymentStatusFailed:
			anyFailed = true
			allCompleted = false
		case models.DeploymentStatusInProgress:
			allCompleted = false
		}
	}

	if anyFailed {
		return models.DeploymentStatusFailed
	} else if allCompleted {
		return models.DeploymentStatusCompleted
	} else {
		return models.DeploymentStatusInProgress
	}
}
func (dm *DeploymentManager) saveDeployment(deployment *models.Deployment) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	collection := dm.MongoClient.Database(dm.ConfigManager.Config.Database.Database).Collection("deployments")

	filter := bson.M{"id": deployment.ID}

	// 创建一个只包含非空字段的更新文档
	updateFields := bson.M{}

	if deployment.AppID != "" {
		updateFields["app_id"] = deployment.AppID
	}
	if deployment.Type != "" {
		updateFields["type"] = deployment.Type
	}
	if deployment.Version != "" {
		updateFields["version"] = deployment.Version
	}
	// if deployment.Env != "" {
	//     updateFields["env"] = deployment.Env
	// }
	if deployment.Variables != nil {
		updateFields["variables"] = deployment.Variables
	}
	if deployment.OverallStatus != "" {
		updateFields["overall_status"] = deployment.OverallStatus
	}

	if deployment.TargetDevices != nil {
		updateFields["target_devices"] = deployment.TargetDevices
	}
	if !deployment.StartTime.IsZero() {
		updateFields["start_time"] = deployment.StartTime
	}
	if !deployment.EndTime.IsZero() {
		updateFields["end_time"] = deployment.EndTime
	}
	if deployment.Logs != nil {
		updateFields["logs"] = deployment.Logs
		log.Printf("[saveDeployment] 保存日志到MongoDB: deploymentID=%s, logCount=%d", deployment.ID, len(deployment.Logs))
	} else {
		log.Printf("[saveDeployment] 警告: deployment.Logs为nil, deploymentID=%s", deployment.ID)
	}

	update := bson.M{
		"$set": updateFields,
	}

	opts := options.Update().SetUpsert(true)
	_, err := collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to upsert deployment: %v", err)
	}

	log.Printf("[saveDeployment] 成功保存部署到MongoDB: deploymentID=%s", deployment.ID)
	return nil
}
