package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "path/filepath"

    "github.com/minio/minio-go/v7"
    "github.com/minio/minio-go/v7/pkg/credentials"
)

func main() {
    // 定义命令行参数
    endpoint := flag.String("endpoint", "localhost:9000", "Minio server endpoint")
    useSSL := flag.Bool("use-ssl", false, "Use SSL for Minio connection")
    bucketName := flag.String("bucket", "", "Minio bucket name")
    objectPrefix := flag.String("prefix", "", "Object name prefix in Minio")
    localFile := flag.String("file", "", "Local file to upload")

    flag.Parse()

    // 从环境变量获取访问密钥
    accessKeyID := os.Getenv("MINIO_ACCESS_KEY")
    secretAccessKey := os.Getenv("MINIO_SECRET_KEY")

    // 验证必要参数
    if accessKeyID == "" || secretAccessKey == "" {
        log.Fatal("MINIO_ACCESS_KEY and MINIO_SECRET_KEY must be set in environment variables")
    }

    if *bucketName == "" || *localFile == "" {
        log.Fatal("Missing required parameters: bucket and file")
    }

    // 初始化 Minio 客户端
    minioClient, err := minio.New(*endpoint, &minio.Options{
        Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
        Secure: *useSSL,
    })
    if err != nil {
        log.Fatalf("Error creating Minio client: %v", err)
    }

    // 打开本地文件
    file, err := os.Open(*localFile)
    if err != nil {
        log.Fatalf("Error opening file: %v", err)
    }
    defer file.Close()

    // 获取文件信息
    fileInfo, err := file.Stat()
    if err != nil {
        log.Fatalf("Error getting file info: %v", err)
    }

    // 构建对象名称
    objectName := filepath.Join(*objectPrefix, filepath.Base(*localFile))

    // 上传文件
    _, err = minioClient.PutObject(context.Background(), *bucketName, objectName, file, fileInfo.Size(), minio.PutObjectOptions{ContentType: "application/octet-stream"})
    if err != nil {
        log.Fatalf("Error uploading file: %v", err)
    }

    fmt.Printf("Successfully uploaded %s to %s/%s\n", *localFile, *bucketName, objectName)
}