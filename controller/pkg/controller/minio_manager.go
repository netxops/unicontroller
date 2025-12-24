package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/tidwall/gjson"
)

var MinioResouceName = ""

// const (
// 	MinioServiceName = "minio_proxy"
// )

type MinioManager struct {
	client          *minio.Client
	KeyManager      *KeyManager
	ConfigManager   *ConfigManager
	RegistryManager *RegistryManager
	serviceInfo     *models.ServiceInfo
	proxyServer     *http.Server
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
}

func ProvideMinioManager(km *KeyManager, configManager *ConfigManager, registryManager *RegistryManager) (*MinioManager, error) {
	mm := &MinioManager{
		// Config:          config,
		KeyManager:      km,
		ConfigManager:   configManager,
		RegistryManager: registryManager,
	}
	// err := mm.initMinioClient()
	// if err != nil {
	// 	return nil, err
	// }
	return mm, nil
}

func (mm *MinioManager) checkMinioHealth() (models.ResourceStatus, error) {
	if mm.client == nil {
		return models.ResourceStatusStopped, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := mm.client.ListBuckets(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return models.ResourceStatusStopped, nil
		}
		return models.ResourceStatusDegraded, fmt.Errorf("minio service is degraded: %v", err)
	}

	return models.ResourceStatusRunning, nil
}

func (mm *MinioManager) initMinioClient() error {
	log.Printf("[MinioManager.initMinioClient] 开始初始化MinIO客户端")

	resourceName, err := mm.ConfigManager.GetContainerNameByResourceType(models.ResourceTypeMinio)
	if err != nil {
		log.Printf("[MinioManager.initMinioClient] 获取MinIO资源名称失败: %v", err)
		return fmt.Errorf("failed to get minio resource name: %v", err)
	}
	MinioResouceName = resourceName
	log.Printf("[MinioManager.initMinioClient] MinIO资源名称: %s", resourceName)

	minioJson, err := mm.ConfigManager.GetJson(models.ResourceTypeMinio)
	if err != nil {
		log.Printf("[MinioManager.initMinioClient] 获取MinIO配置失败: %v", err)
		return fmt.Errorf("failed to get minio config: %v", err)
	}

	log.Printf("[MinioManager.initMinioClient] 从Etcd获取的MinIO配置JSON: %s", minioJson)

	endpoint := gjson.Get(minioJson, "endpoint").String()
	if endpoint == "" {
		log.Printf("[MinioManager.initMinioClient] MinIO endpoint为空")
		return errors.New("minio endpoint is not provided")
	}
	accessKey := gjson.Get(minioJson, "accessKeyID").String()
	if accessKey == "" {
		log.Printf("[MinioManager.initMinioClient] MinIO accessKeyID为空，尝试从Config结构体获取")
		// 如果从JSON中获取不到，尝试从Config结构体中获取
		if mm.ConfigManager.Config.Minio.AccessKeyID != "" {
			accessKey = mm.ConfigManager.Config.Minio.AccessKeyID
			log.Printf("[MinioManager.initMinioClient] 从Config结构体获取accessKeyID成功")
		} else {
			log.Printf("[MinioManager.initMinioClient] MinIO accessKeyID为空")
			return errors.New("minio accessKeyID is not provided")
		}
	}
	secretKey := gjson.Get(minioJson, "secretAccessKey").String()
	if secretKey == "" {
		log.Printf("[MinioManager.initMinioClient] MinIO secretAccessKey为空，尝试从Config结构体获取")
		// 如果从JSON中获取不到，尝试从Config结构体中获取
		if mm.ConfigManager.Config.Minio.SecretAccessKey != "" {
			secretKey = mm.ConfigManager.Config.Minio.SecretAccessKey
			log.Printf("[MinioManager.initMinioClient] 从Config结构体获取secretAccessKey成功")
		} else {
			log.Printf("[MinioManager.initMinioClient] MinIO secretAccessKey为空")
			return errors.New("minio secretAccessKey is not provided")
		}
	}
	useSSL := gjson.Get(minioJson, "useSSL").Bool()

	log.Printf("[MinioManager.initMinioClient] MinIO配置: endpoint=%s, useSSL=%v, hasAccessKey=%v (length=%d), hasSecretKey=%v (length=%d)",
		endpoint, useSSL, accessKey != "", len(accessKey), secretKey != "", len(secretKey))

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})

	if err != nil {
		log.Printf("[MinioManager.initMinioClient] 初始化MinIO客户端失败: %v", err)
		return fmt.Errorf("failed to initialize minio client: %v", err)
	}
	mm.client = minioClient
	log.Printf("[MinioManager.initMinioClient] MinIO客户端初始化成功: endpoint=%s", endpoint)

	// 测试连接：尝试列出 buckets
	log.Printf("[MinioManager.initMinioClient] 测试MinIO连接...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buckets, err := minioClient.ListBuckets(ctx)
	if err != nil {
		log.Printf("[MinioManager.initMinioClient] MinIO连接测试失败: %v (error type: %T)", err, err)
		// 不返回错误，允许后续重试
		log.Printf("[MinioManager.initMinioClient] 警告: MinIO连接测试失败，但将继续初始化（可能在后续操作中重试）")
	} else {
		log.Printf("[MinioManager.initMinioClient] MinIO连接测试成功: 找到 %d 个bucket", len(buckets))
		for _, bucket := range buckets {
			log.Printf("[MinioManager.initMinioClient]   - bucket: %s (创建时间: %s)", bucket.Name, bucket.CreationDate.Format(time.RFC3339))
		}
	}

	return nil
}

func (mm *MinioManager) RegisterService() error {
	log.Printf("[MinioManager.RegisterService] 开始注册MinIO Proxy服务")

	mm.ctx, mm.cancel = context.WithCancel(context.Background())

	// 生成 MinioProxy 服务信息
	configJson, err := mm.ConfigManager.GetJson(models.ResourceTypeMinio)
	if err != nil {
		log.Printf("[MinioManager.RegisterService] 获取MinIO配置失败: %v", err)
		return fmt.Errorf("failed to get minio proxy address: %v", err)
	}

	// 尝试从配置JSON中获取proxyAddr
	minioProxyAddr := gjson.Get(configJson, "proxyAddr").String()
	if minioProxyAddr == "" {
		// 如果JSON中没有，尝试从Config结构体中获取
		if mm.ConfigManager.Config.Minio.ProxyAddr != "" {
			minioProxyAddr = mm.ConfigManager.Config.Minio.ProxyAddr
			log.Printf("[MinioManager.RegisterService] 从Config结构体获取proxyAddr: %s", minioProxyAddr)
		} else {
			log.Printf("[MinioManager.RegisterService] proxyAddr为空，无法注册服务")
			return errors.New("minio proxy address is not provided")
		}
	} else {
		log.Printf("[MinioManager.RegisterService] 从配置JSON获取proxyAddr: %s", minioProxyAddr)
	}

	parts := strings.Split(minioProxyAddr, ":")
	if len(parts) != 2 {
		log.Printf("[MinioManager.RegisterService] proxyAddr格式无效: %s (期望格式: host:port)", minioProxyAddr)
		return fmt.Errorf("invalid minio proxy address format: %s (expected format: host:port)", minioProxyAddr)
	}

	log.Printf("[MinioManager.RegisterService] 生成服务Key: serviceName=%s, hostIdentifier=%s, port=%s",
		string(models.ServiceNameMinioProxy), mm.RegistryManager.HostIdentifier, parts[1])
	key, err := mm.KeyManager.GenerateServiceKey(string(models.ServiceNameMinioProxy), mm.RegistryManager.HostIdentifier, parts[1])
	if err != nil {
		log.Printf("[MinioManager.RegisterService] 生成服务Key失败: %v", err)
		return fmt.Errorf("failed to generate resource key: %v", err)
	}

	serviceInfo := &models.ServiceInfo{
		Key:     key,
		Name:    string(models.ServiceNameMinioProxy),
		Address: minioProxyAddr,
	}
	mm.serviceInfo = serviceInfo
	log.Printf("[MinioManager.RegisterService] 服务信息已创建: Key=%s, Name=%s, Address=%s",
		serviceInfo.Key, serviceInfo.Name, serviceInfo.Address)

	// 立即注册一次（不等待周期性注册）
	log.Printf("[MinioManager.RegisterService] 立即注册服务到Registry")
	err = mm.RegistryManager.RegisterService(serviceInfo, 1*time.Minute)
	if err != nil {
		log.Printf("[MinioManager.RegisterService] 立即注册失败: %v", err)
		// 不返回错误，继续启动周期性注册
	} else {
		log.Printf("[MinioManager.RegisterService] 立即注册成功")
	}

	// 启动周期性注册
	log.Printf("[MinioManager.RegisterService] 启动周期性注册（每30秒）")
	go mm.periodicRegister(serviceInfo)

	log.Printf("[MinioManager.RegisterService] 服务注册流程完成")
	return nil
}

func (mm *MinioManager) periodicRegister(serviceInfo *models.ServiceInfo) {
	log.Printf("[MinioManager.periodicRegister] 开始周期性注册: serviceName=%s, address=%s",
		serviceInfo.Name, serviceInfo.Address)

	ticker := time.NewTicker(30 * time.Second) // 每30秒注册一次
	defer ticker.Stop()

	// 立即注册一次
	err := mm.RegistryManager.RegisterService(serviceInfo, 1*time.Minute) // TTL设置为1分钟
	if err != nil {
		log.Printf("[MinioManager.periodicRegister] 初始注册失败: %v", err)
	} else {
		log.Printf("[MinioManager.periodicRegister] 初始注册成功")
	}

	for {
		select {
		case <-ticker.C:
			err := mm.RegistryManager.RegisterService(serviceInfo, 1*time.Minute) // TTL设置为1分钟
			if err != nil {
				log.Printf("[MinioManager.periodicRegister] 周期性注册失败: %v", err)
			} else {
				log.Printf("[MinioManager.periodicRegister] 周期性注册成功: serviceName=%s, address=%s",
					serviceInfo.Name, serviceInfo.Address)
			}
		case <-mm.ctx.Done():
			log.Printf("[MinioManager.periodicRegister] 停止周期性注册")
			return
		}
	}
}

// func (mm *MinioManager) UnregisterService() error {
// 	if mm.cancel != nil {
// 		mm.cancel() // 取消 context，停止周期性注册
// 	}

// 	serviceID, err := mm.KeyManager.GenerateServiceKey(MinioServiceName, MinioResouceName)
// 	if err != nil {
// 		return fmt.Errorf("failed to generate service key: %v", err)
// 	}
// 	return mm.RegistryManager.UnregisterService(serviceID)
// }

func (mm *MinioManager) CreateBucket(bucketName string) error {
	ctx := context.Background()
	err := mm.client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
	if err != nil {
		// 检查错误是否为"桶已经存在"
		exists, errBucketExists := mm.client.BucketExists(ctx, bucketName)
		if errBucketExists == nil && exists {
			return nil
		}
		return fmt.Errorf("failed to create bucket: %v", err)
	}
	return nil
}

func (mm *MinioManager) UploadFile(bucketName, objectName string, filePath string) error {
	ctx := context.Background()
	_, err := mm.client.FPutObject(ctx, bucketName, objectName, filePath, minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to upload file: %v", err)
	}
	return nil
}

func (mm *MinioManager) DownloadFile(bucketName, objectName string, filePath string) error {
	log.Printf("[MinioManager.DownloadFile] 开始下载: bucket=%s, objectName=%s, filePath=%s", bucketName, objectName, filePath)

	if mm.client == nil {
		log.Printf("[MinioManager.DownloadFile] MinIO客户端为nil，尝试初始化")
		err := mm.initMinioClient()
		if err != nil {
			log.Printf("[MinioManager.DownloadFile] 初始化MinIO客户端失败: %v", err)
			return fmt.Errorf("minio client is not initialized and initialization failed: %v", err)
		}
		log.Printf("[MinioManager.DownloadFile] MinIO客户端初始化成功")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 检查bucket是否存在
	exists, err := mm.client.BucketExists(ctx, bucketName)
	if err != nil {
		log.Printf("[MinioManager.DownloadFile] 检查bucket存在性失败: bucket=%s, error=%v", bucketName, err)
		return fmt.Errorf("failed to check bucket existence: %v", err)
	}
	if !exists {
		log.Printf("[MinioManager.DownloadFile] Bucket不存在: bucket=%s", bucketName)
		return fmt.Errorf("bucket %s does not exist", bucketName)
	}
	log.Printf("[MinioManager.DownloadFile] Bucket存在: bucket=%s", bucketName)

	// 尝试列出对象以验证对象是否存在
	objectCh := mm.client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
		Prefix:    objectName,
		Recursive: false,
	})
	objectFound := false
	for object := range objectCh {
		if object.Err != nil {
			log.Printf("[MinioManager.DownloadFile] 列出对象时出错: %v", object.Err)
			break
		}
		if object.Key == objectName {
			objectFound = true
			log.Printf("[MinioManager.DownloadFile] 找到对象: key=%s, size=%d, lastModified=%v", object.Key, object.Size, object.LastModified)
			break
		}
	}
	if !objectFound {
		log.Printf("[MinioManager.DownloadFile] 对象不存在: bucket=%s, objectName=%s", bucketName, objectName)
		return fmt.Errorf("object %s does not exist in bucket %s", objectName, bucketName)
	}

	err = mm.client.FGetObject(ctx, bucketName, objectName, filePath, minio.GetObjectOptions{})
	if err != nil {
		log.Printf("[MinioManager.DownloadFile] 下载文件失败: bucket=%s, objectName=%s, filePath=%s, error=%v", bucketName, objectName, filePath, err)
		return fmt.Errorf("failed to download file: %v", err)
	}

	log.Printf("[MinioManager.DownloadFile] 下载成功: bucket=%s, objectName=%s, filePath=%s", bucketName, objectName, filePath)
	return nil
}

func (mm *MinioManager) ListBuckets() ([]minio.BucketInfo, error) {
	ctx := context.Background()
	buckets, err := mm.client.ListBuckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %v", err)
	}
	return buckets, nil
}

func (mm *MinioManager) ListObjects(bucketName string) ([]minio.ObjectInfo, error) {
	ctx := context.Background()
	var objects []minio.ObjectInfo
	for object := range mm.client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{}) {
		if object.Err != nil {
			return nil, fmt.Errorf("failed to list objects: %v", object.Err)
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func (mm *MinioManager) DeleteObject(bucketName, objectName string) error {
	ctx := context.Background()
	err := mm.client.RemoveObject(ctx, bucketName, objectName, minio.RemoveObjectOptions{})
	if err != nil {
		// 检查是否是因为对象不存在而导致的错误
		if strings.Contains(err.Error(), "The specified key does not exist") {
			// 如果对象不存在，我们可以认为删除成功
			return nil
		}
		return fmt.Errorf("failed to delete object: %v", err)
	}
	return nil
}

// GetObjectInfo 获取对象信息
func (mm *MinioManager) GetObjectInfo(bucketName, objectName string) (minio.ObjectInfo, error) {
	ctx := context.Background()
	info, err := mm.client.StatObject(ctx, bucketName, objectName, minio.StatObjectOptions{})
	if err != nil {
		return minio.ObjectInfo{}, fmt.Errorf("failed to get object info: %v", err)
	}
	return info, nil
}

// GetPresignedURL 获取预签名URL
// GetPresignedURL 获取预签名URL
func (mm *MinioManager) GetPresignedURL(bucketName, objectName string, expiry time.Duration, method string) (string, error) {
	ctx := context.Background()
	var presignedURL *url.URL
	var err error

	switch strings.ToUpper(method) {
	case "GET":
		presignedURL, err = mm.client.PresignedGetObject(ctx, bucketName, objectName, expiry, nil)
	case "PUT":
		presignedURL, err = mm.client.PresignedPutObject(ctx, bucketName, objectName, expiry)
	default:
		return "", fmt.Errorf("unsupported HTTP method: %s", method)
	}

	if err != nil {
		return "", fmt.Errorf("failed to get presigned URL: %v", err)
	}

	return presignedURL.String(), nil
}

func (mm *MinioManager) GetProxyPackageURL(bucketName, objectName string) (string, error) {
	// 从 Registry Manager 获取 Minio 代理服务信息
	serviceInfo, err := mm.RegistryManager.FirstByName(string(models.ServiceNameMinioProxy))
	if err != nil {
		log.Printf("[GetProxyPackageURL] 查询MinIO Proxy服务失败: %v, 服务名称: %s", err, string(models.ServiceNameMinioProxy))
		// 尝试列出所有服务，用于调试
		services := mm.RegistryManager.ListServices()
		if len(services) > 0 {
			log.Printf("[GetProxyPackageURL] 当前注册的服务列表 (共%d个):", len(services))
			for _, svc := range services {
				log.Printf("[GetProxyPackageURL]   - 名称: %s, 地址: %s", svc.Name, svc.Address)
			}
		} else {
			log.Printf("[GetProxyPackageURL] 当前没有注册的服务")
		}
		return "", fmt.Errorf("failed to get Minio proxy service info: %v", err)
	}

	if serviceInfo == nil || serviceInfo.Address == "" {
		log.Printf("[GetProxyPackageURL] MinIO Proxy服务信息为空或地址为空")
		return "", fmt.Errorf("minio proxy service not found or address is empty")
	}

	log.Printf("[GetProxyPackageURL] 找到MinIO Proxy服务: 名称=%s, 地址=%s", serviceInfo.Name, serviceInfo.Address)

	// 构建 URL
	// URL格式: http://{address}/{bucketName}/{objectName}
	// 注意：objectName 可能已经包含路径，如 "application/deployment-tools/..."
	url := fmt.Sprintf("http://%s/%s/%s", serviceInfo.Address, bucketName, objectName)
	log.Printf("[GetProxyPackageURL] 构建的URL: %s (bucket=%s, objectName=%s)", url, bucketName, objectName)

	return url, nil
}

func (mm *MinioManager) GetProxyLatestPackageURL(bucketName, objectName string) (string, error) {
	// 获取 Minio 代理服务信息
	serviceInfo, err := mm.RegistryManager.FirstByName(string(models.ServiceNameMinioProxy))
	if err != nil {
		return "", fmt.Errorf("failed to get Minio proxy service info: %v", err)
	}

	if serviceInfo == nil || serviceInfo.Address == "" {
		return "", fmt.Errorf("minio proxy service not found or address is empty")
	}

	// 列出指定 bucket 和对象名称前缀的所有对象
	ctx := context.Background()
	objectCh := mm.client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
		Prefix:    objectName,
		Recursive: true,
	})

	var latestObject minio.ObjectInfo
	var latestVersion string

	// 遍历所有对象，找出最新版本
	for object := range objectCh {
		if object.Err != nil {
			return "", fmt.Errorf("error listing objects: %v", object.Err)
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
		return "", fmt.Errorf("no package found for %s in bucket %s", objectName, bucketName)
	}

	// 构建最新版本对象的代理 URL
	url := fmt.Sprintf("http://%s/%s/%s", serviceInfo.Address, bucketName, latestObject.Key)

	return url, nil
}

func (mm *MinioManager) ListPackages(bucketName string) ([]string, error) {
	ctx := context.Background()
	var packages []string

	// 检查 bucket 是否存在
	exists, err := mm.client.BucketExists(ctx, bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to check bucket existence: %v", err)
	}
	if !exists {
		return nil, fmt.Errorf("bucket %s does not exist", bucketName)
	}

	// 列出 bucket 中的所有对象
	objectCh := mm.client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
		Recursive: true,
	})

	for object := range objectCh {
		if object.Err != nil {
			return nil, fmt.Errorf("error listing objects: %v", object.Err)
		}
		// 只添加文件名（不包括路径）到列表中
		packages = append(packages, object.Key)
	}

	return packages, nil
}

// Start 启动Minio管理器和代理服务器
func (mm *MinioManager) Start() error {
	log.Printf("[MinioManager.Start] 开始启动MinIO管理器")

	// 初始化 MinIO 客户端
	log.Printf("[MinioManager.Start] 步骤1: 初始化MinIO客户端")
	err := mm.initMinioClient()
	if err != nil {
		log.Printf("[MinioManager.Start] 初始化MinIO客户端失败: %v", err)
		return fmt.Errorf("failed to initialize MinIO client: %v", err)
	}
	log.Printf("[MinioManager.Start] MinIO客户端初始化成功")

	// 启动代理服务器
	log.Printf("[MinioManager.Start] 步骤2: 启动MinIO代理服务器")
	if err := mm.startProxyServer(); err != nil {
		log.Printf("[MinioManager.Start] 启动MinIO代理服务器失败: %v", err)
		return fmt.Errorf("failed to start MinIO proxy server: %v", err)
	}
	log.Printf("[MinioManager.Start] MinIO代理服务器启动成功")

	// 注册服务
	log.Printf("[MinioManager.Start] 步骤3: 注册MinIO Proxy服务到Registry")
	if err := mm.RegisterService(); err != nil {
		log.Printf("[MinioManager.Start] 注册MinIO Proxy服务失败: %v", err)
		return fmt.Errorf("failed to register MinIO proxy service: %v", err)
	}
	log.Printf("[MinioManager.Start] MinIO Proxy服务注册成功")

	log.Printf("[MinioManager.Start] MinIO管理器启动完成")
	return nil
}

func (mm *MinioManager) startProxyServer() error {
	jsonConfig, err := mm.ConfigManager.GetJson(models.ResourceTypeMinio)
	if err != nil {
		return fmt.Errorf("failed to get Minio config: %v", err)
	}
	addr := gjson.Get(string(jsonConfig), "proxyAddr").String()
	if addr == "" {
		return errors.New("minio proxy address is not provided")
	}
	mm.proxyServer = &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mm.handleProxyRequest(w, r)
		}),
	}

	go func() {
		if err := mm.proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Minio proxy server error: %v\n", err)
		}
	}()

	fmt.Printf("Minio proxy server started on %s\n", addr)
	return nil
}
func (mm *MinioManager) handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Received %s request for %s\n", r.Method, r.URL.Path)

	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// 检查 MinIO 客户端是否已初始化
	if mm.client == nil {
		fmt.Printf("[handleProxyRequest] MinIO client is nil, attempting to initialize...\n")
		err := mm.initMinioClient()
		if err != nil {
			fmt.Printf("[handleProxyRequest] Failed to initialize MinIO client: %v\n", err)
			http.Error(w, fmt.Sprintf("MinIO client not initialized: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Printf("[handleProxyRequest] MinIO client initialized successfully\n")
	}

	// 解析请求路径
	// URL格式: /{bucketName}/{objectName}
	// objectName 可能包含多个路径段，如 "application/deployment-tools/..."
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		fmt.Printf("Invalid request path: %s (expected format: /bucket/object)\n", r.URL.Path)
		http.Error(w, fmt.Sprintf("Invalid request path: %s (expected format: /bucket/object)", r.URL.Path), http.StatusBadRequest)
		return
	}
	bucketName := parts[0]
	objectName := parts[1]
	fmt.Printf("Bucket: %s, Object: %s\n", bucketName, objectName)

	switch r.Method {
	case http.MethodGet:
		fmt.Printf("Processing GET request for %s/%s\n", bucketName, objectName)

		// 先获取对象信息，确保对象存在且可以访问
		objectInfo, err := mm.client.StatObject(context.Background(), bucketName, objectName, minio.StatObjectOptions{})
		if err != nil {
			// 记录详细的错误信息
			fmt.Printf("Failed to stat object %s/%s: %v (error type: %T)\n", bucketName, objectName, err, err)
			if strings.Contains(err.Error(), "The specified key does not exist") ||
				strings.Contains(err.Error(), "does not exist") ||
				strings.Contains(err.Error(), "NoSuchKey") {
				fmt.Printf("Object not found: %s/%s\n", bucketName, objectName)
				// 尝试列出 bucket 中的对象，用于调试
				fmt.Printf("Attempting to list objects in bucket %s with prefix matching...\n", bucketName)
				ctx := context.Background()
				objectCh := mm.client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{
					Prefix:    strings.Split(objectName, "/")[0], // 使用第一个路径段作为前缀
					Recursive: false,
				})
				count := 0
				for object := range objectCh {
					if object.Err != nil {
						fmt.Printf("Error listing objects: %v\n", object.Err)
						break
					}
					fmt.Printf("  Found object: %s (size: %d)\n", object.Key, object.Size)
					count++
					if count >= 10 { // 只列出前10个
						fmt.Printf("  ... (showing first 10 objects)\n")
						break
					}
				}
				http.Error(w, fmt.Sprintf("Object not found: %s/%s", bucketName, objectName), http.StatusNotFound)
			} else {
				fmt.Printf("Failed to stat object: %v\n", err)
				http.Error(w, fmt.Sprintf("Failed to get object info: %v", err), http.StatusInternalServerError)
			}
			return
		}

		// 检查对象大小
		if objectInfo.Size == 0 {
			fmt.Printf("Warning: Object %s/%s has zero size\n", bucketName, objectName)
			http.Error(w, "Object is empty", http.StatusBadRequest)
			return
		}

		// 设置响应头（必须在写入数据之前设置）
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", objectName))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", objectInfo.Size))

		fmt.Printf("Streaming file to client, size: %d bytes\n", objectInfo.Size)

		// 获取对象内容
		object, err := mm.client.GetObject(context.Background(), bucketName, objectName, minio.GetObjectOptions{})
		if err != nil {
			fmt.Printf("Failed to get object: %v\n", err)
			http.Error(w, fmt.Sprintf("Failed to get object: %v", err), http.StatusInternalServerError)
			return
		}
		defer object.Close()

		// 复制数据到响应，并检查实际复制的字节数
		bytesWritten, err := io.Copy(w, object)
		if err != nil {
			fmt.Printf("Error streaming file: %v (wrote %d/%d bytes)\n", err, bytesWritten, objectInfo.Size)
			// 注意：如果已经写入部分数据，http.Error 可能无法正常工作
			// 但至少记录错误，客户端可能会收到不完整的数据
			return
		}

		// 检查实际写入的字节数是否与预期一致
		if bytesWritten != objectInfo.Size {
			fmt.Printf("Warning: Expected %d bytes but wrote %d bytes\n", objectInfo.Size, bytesWritten)
		} else {
			fmt.Printf("File streamed successfully, %d bytes written\n", bytesWritten)
		}

	case http.MethodPut:
		fmt.Printf("Processing PUT request for %s/%s\n", bucketName, objectName)
		// 直接从请求体读取内容
		content, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("Failed to read request body: %v\n", err)
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusInternalServerError)
			return
		}

		// 打印上传的内容（用于调试）
		fmt.Printf("Uploading content: %s\n", string(content))

		// 使用 PutObject 而不是 UploadFile
		_, err = mm.client.PutObject(context.Background(), bucketName, objectName, bytes.NewReader(content), int64(len(content)), minio.PutObjectOptions{ContentType: "application/octet-stream"})
		if err != nil {
			fmt.Printf("Failed to upload file: %v\n", err)
			http.Error(w, fmt.Sprintf("Failed to upload file: %v", err), http.StatusInternalServerError)
			return
		}

		fmt.Printf("File uploaded successfully\n")
		w.WriteHeader(http.StatusOK)

	case http.MethodDelete:
		fmt.Printf("Processing DELETE request for %s/%s\n", bucketName, objectName)
		err := mm.DeleteObject(bucketName, objectName)
		if err != nil {
			fmt.Printf("Failed to delete object: %v\n", err)
			http.Error(w, fmt.Sprintf("Failed to delete object: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Printf("Object deleted successfully\n")
		w.WriteHeader(http.StatusNoContent) // 使用 204 No Content 状态码

	case http.MethodHead:
		fmt.Printf("Processing HEAD request for %s/%s\n", bucketName, objectName)
		_, err := mm.GetObjectInfo(bucketName, objectName)
		if err != nil {
			if strings.Contains(err.Error(), "The specified key does not exist") {
				http.Error(w, "Object not found", http.StatusNotFound)
			} else {
				http.Error(w, fmt.Sprintf("Failed to get object info: %v", err), http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		fmt.Printf("Unsupported method: %s\n", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	fmt.Printf("Request processing completed for %s %s/%s\n", r.Method, bucketName, objectName)
}

// Stop 停止Minio管理器和代理服务器
func (mm *MinioManager) Stop() error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if mm.cancel != nil {
		mm.cancel() // 取消 context，停止周期性注册
	}

	if mm.proxyServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mm.proxyServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to stop Minio proxy server: %v", err)
		}
	}

	if mm.client != nil {
		mm.client = nil
	}

	// // 注销服务
	// if err := mm.UnregisterService(); err != nil {
	// 	return fmt.Errorf("failed to unregister Minio service: %v", err)
	// }

	return nil
}

func (mm *MinioManager) GetMiniManagerStatus() (models.ResourceStatus, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	if mm.client == nil {
		return models.ResourceStatusStopped, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := mm.client.ListBuckets(ctx)
	if err != nil {
		// 检查错误类型，可能需要根据具体的错误来判断状态
		if strings.Contains(err.Error(), "connection refused") {
			return models.ResourceStatusStopped, nil
		}
		return models.ResourceStatusDegraded, fmt.Errorf("minio service is degraded: %v", err)
	}

	return models.ResourceStatusRunning, nil
}
