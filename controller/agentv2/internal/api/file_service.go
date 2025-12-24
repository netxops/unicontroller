package api

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// FileService 文件操作服务
type FileService struct {
	logger    *zap.Logger
	uploadDir string
	chunkSize int64
	uploads   map[string]*UploadSession
	mu        sync.RWMutex
}

// GetChunkSize 获取块大小
func (fs *FileService) GetChunkSize() int64 {
	return fs.chunkSize
}

// UploadSession 上传会话
type UploadSession struct {
	ID           string
	FilePath     string
	TotalSize    int64
	ReceivedSize int64
	Chunks       map[int64]bool
	MD5          string
	SHA256       string
	Status       string // "uploading", "completed", "failed"
	CreatedAt    time.Time
	mu           sync.RWMutex
}

// FileInfo 文件信息
type FileInfo struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	IsDir   bool      `json:"is_dir"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
	MD5     string    `json:"md5,omitempty"`
	SHA256  string    `json:"sha256,omitempty"`
}

// NewFileService 创建文件操作服务
func NewFileService(logger *zap.Logger, uploadDir string) *FileService {
	if uploadDir == "" {
		uploadDir = "/tmp/agentv2/uploads"
	}

	// 确保上传目录存在
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		logger.Warn("Failed to create upload directory", zap.Error(err))
	}

	return &FileService{
		logger:    logger,
		uploadDir: uploadDir,
		chunkSize: 1024 * 1024, // 1MB
		uploads:   make(map[string]*UploadSession),
	}
}

// StartUpload 开始上传（创建上传会话）
func (fs *FileService) StartUpload(ctx context.Context, filePath string, totalSize int64, md5, sha256 string) (string, error) {
	sessionID := generateSessionID()

	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	session := &UploadSession{
		ID:           sessionID,
		FilePath:     filePath,
		TotalSize:    totalSize,
		ReceivedSize: 0,
		Chunks:       make(map[int64]bool),
		MD5:          md5,
		SHA256:       sha256,
		Status:       "uploading",
		CreatedAt:    time.Now(),
	}

	fs.mu.Lock()
	fs.uploads[sessionID] = session
	fs.mu.Unlock()

	fs.logger.Info("Upload session started",
		zap.String("session_id", sessionID),
		zap.String("file_path", filePath),
		zap.Int64("total_size", totalSize))

	return sessionID, nil
}

// UploadChunk 上传文件块
func (fs *FileService) UploadChunk(ctx context.Context, sessionID string, chunkIndex int64, data []byte) error {
	fs.mu.RLock()
	session, exists := fs.uploads[sessionID]
	fs.mu.RUnlock()

	if !exists {
		return fmt.Errorf("upload session not found: %s", sessionID)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.Status != "uploading" {
		return fmt.Errorf("upload session is not in uploading status: %s", session.Status)
	}

	// 检查块是否已上传
	if session.Chunks[chunkIndex] {
		return nil // 块已存在，忽略
	}

	// 打开或创建临时文件（使用读写模式，支持随机写入）
	tempFilePath := session.FilePath + ".tmp"
	file, err := os.OpenFile(tempFilePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open temp file: %w", err)
	}
	defer file.Close()

	// 计算写入位置
	offset := chunkIndex * fs.chunkSize
	chunkEnd := offset + int64(len(data))

	// 确保文件大小足够（如果文件小于需要的长度，扩展文件）
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat temp file: %w", err)
	}

	if fileInfo.Size() < chunkEnd {
		// 扩展文件到所需大小
		if err := file.Truncate(chunkEnd); err != nil {
			return fmt.Errorf("failed to truncate file: %w", err)
		}
	}

	// 写入块数据（使用 WriteAt 进行随机写入）
	if _, err := file.WriteAt(data, offset); err != nil {
		return fmt.Errorf("failed to write chunk: %w", err)
	}

	// 标记块已上传
	session.Chunks[chunkIndex] = true
	session.ReceivedSize += int64(len(data))

	// 检查是否完成
	if session.ReceivedSize >= session.TotalSize {
		// 验证文件
		if err := fs.verifyFile(tempFilePath, session.MD5, session.SHA256); err != nil {
			session.Status = "failed"
			return fmt.Errorf("file verification failed: %w", err)
		}

		// 移动到最终位置
		if err := os.Rename(tempFilePath, session.FilePath); err != nil {
			session.Status = "failed"
			return fmt.Errorf("failed to move file: %w", err)
		}

		session.Status = "completed"
		fs.logger.Info("Upload completed",
			zap.String("session_id", sessionID),
			zap.String("file_path", session.FilePath))
	}

	return nil
}

// GetUploadStatus 获取上传状态
func (fs *FileService) GetUploadStatus(ctx context.Context, sessionID string) (*UploadSession, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	session, exists := fs.uploads[sessionID]
	if !exists {
		return nil, fmt.Errorf("upload session not found: %s", sessionID)
	}

	return session, nil
}

// DownloadFile 下载文件
func (fs *FileService) DownloadFile(ctx context.Context, filePath string, offset, length int64) (io.ReadCloser, int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open file: %w", err)
	}

	// 获取文件信息
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, fmt.Errorf("failed to stat file: %w", err)
	}

	// 如果指定了偏移量，移动到指定位置
	if offset > 0 {
		if _, err := file.Seek(offset, 0); err != nil {
			file.Close()
			return nil, 0, fmt.Errorf("failed to seek file: %w", err)
		}
	}

	// 如果指定了长度，创建限制读取器
	var reader io.ReadCloser = file
	if length > 0 && offset+length < info.Size() {
		reader = &limitedReadCloser{
			Reader: io.LimitReader(file, length),
			Closer: file,
		}
	}

	return reader, info.Size(), nil
}

// ListFiles 列出文件
func (fs *FileService) ListFiles(ctx context.Context, dirPath string) ([]FileInfo, error) {
	// 验证路径安全性
	if dirPath == "" {
		return nil, fmt.Errorf("directory path cannot be empty")
	}

	// 检查路径是否存在
	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat directory: %w", err)
	}

	// 确保是目录
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dirPath)
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())
		fileInfo := FileInfo{
			Path:    filePath,
			Size:    info.Size(),
			IsDir:   info.IsDir(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime(),
		}

		// 如果是文件，计算校验和
		if !info.IsDir() && info.Size() < 100*1024*1024 { // 只计算小于 100MB 的文件
			if md5, err := fs.calculateMD5(filePath); err == nil {
				fileInfo.MD5 = md5
			}
		}

		files = append(files, fileInfo)
	}

	return files, nil
}

// GetFileInfo 获取文件信息
func (fs *FileService) GetFileInfo(ctx context.Context, filePath string) (*FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	fileInfo := &FileInfo{
		Path:    filePath,
		Size:    info.Size(),
		IsDir:   info.IsDir(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime(),
	}

	// 如果是文件，计算校验和
	if !info.IsDir() {
		if md5, err := fs.calculateMD5(filePath); err == nil {
			fileInfo.MD5 = md5
		}
		if sha256, err := fs.calculateSHA256(filePath); err == nil {
			fileInfo.SHA256 = sha256
		}
	}

	return fileInfo, nil
}

// DeleteFile 删除文件
func (fs *FileService) DeleteFile(ctx context.Context, filePath string) error {
	return os.Remove(filePath)
}

// DeleteDirectory 删除目录
func (fs *FileService) DeleteDirectory(ctx context.Context, dirPath string) error {
	return os.RemoveAll(dirPath)
}

// CreateDirectory 创建目录
func (fs *FileService) CreateDirectory(ctx context.Context, dirPath string, perm os.FileMode) error {
	return os.MkdirAll(dirPath, perm)
}

// MoveFile 移动文件
func (fs *FileService) MoveFile(ctx context.Context, srcPath, dstPath string) error {
	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return os.Rename(srcPath, dstPath)
}

// CopyFile 复制文件
func (fs *FileService) CopyFile(ctx context.Context, srcPath, dstPath string) error {
	source, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer source.Close()

	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	destination, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// 辅助函数

func generateSessionID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
}

func (fs *FileService) verifyFile(filePath, expectedMD5, expectedSHA256 string) error {
	if expectedMD5 != "" {
		actualMD5, err := fs.calculateMD5(filePath)
		if err != nil {
			return fmt.Errorf("failed to calculate MD5: %w", err)
		}
		if actualMD5 != expectedMD5 {
			return fmt.Errorf("MD5 mismatch: expected %s, got %s", expectedMD5, actualMD5)
		}
	}

	if expectedSHA256 != "" {
		actualSHA256, err := fs.calculateSHA256(filePath)
		if err != nil {
			return fmt.Errorf("failed to calculate SHA256: %w", err)
		}
		if actualSHA256 != expectedSHA256 {
			return fmt.Errorf("SHA256 mismatch: expected %s, got %s", expectedSHA256, actualSHA256)
		}
	}

	return nil
}

func (fs *FileService) calculateMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (fs *FileService) calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// limitedReadCloser 限制读取器
type limitedReadCloser struct {
	io.Reader
	io.Closer
}
