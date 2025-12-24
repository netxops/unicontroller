package filemonitor

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/netxops/log"
	"go.uber.org/zap"
)

// FileMonitor 文件监控器
type FileMonitor struct {
	SourceDir     string        // 源目录
	TargetDir     string        // 目标目录
	CheckInterval time.Duration // 检查间隔
	Logger        *zap.Logger   // 日志记录器
	stopChan      chan bool     // 停止信号
}

// NewFileMonitor 创建新的文件监控器
func NewFileMonitor(sourceDir, targetDir string, checkInterval time.Duration) *FileMonitor {
	return &FileMonitor{
		SourceDir:     sourceDir,
		TargetDir:     targetDir,
		CheckInterval: checkInterval,
		Logger:        log.NewLogger(nil, true).Logger,
		stopChan:      make(chan bool),
	}
}

// Start 启动文件监控
func (fm *FileMonitor) Start() {
	fm.Logger.Info("启动文件监控器",
		zap.String("source_dir", fm.SourceDir),
		zap.String("target_dir", fm.TargetDir),
		zap.Duration("check_interval", fm.CheckInterval))

	// 确保目标目录存在
	if err := os.MkdirAll(fm.TargetDir, 0755); err != nil {
		fm.Logger.Error("创建目标目录失败", zap.Error(err))
		return
	}

	ticker := time.NewTicker(fm.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fm.checkAndProcessFiles()
		case <-fm.stopChan:
			fm.Logger.Info("文件监控器已停止")
			return
		}
	}
}

// Stop 停止文件监控
func (fm *FileMonitor) Stop() {
	close(fm.stopChan)
}

// checkAndProcessFiles 检查并处理文件
func (fm *FileMonitor) checkAndProcessFiles() {
	// 检查源目录是否存在
	if _, err := os.Stat(fm.SourceDir); os.IsNotExist(err) {
		fm.Logger.Debug("源目录不存在", zap.String("source_dir", fm.SourceDir))
		return
	}

	// 读取源目录中的文件
	files, err := os.ReadDir(fm.SourceDir)
	if err != nil {
		fm.Logger.Error("读取源目录失败", zap.Error(err))
		return
	}

	// 处理每个文件
	for _, file := range files {
		if !file.IsDir() {
			fm.processFile(file.Name())
		}
	}
}

// processFile 处理单个文件
func (fm *FileMonitor) processFile(filename string) {
	sourcePath := filepath.Join(fm.SourceDir, filename)

	// 检查文件是否已经被处理过（通过文件名后缀判断）
	if fm.isProcessedFile(filename) {
		fm.Logger.Debug("文件已被处理过，跳过", zap.String("filename", filename))
		return
	}

	// 生成新的文件名（去掉日期前缀）
	newFilename := fm.removeDatePrefix(filename)
	if newFilename == "" {
		fm.Logger.Debug("文件名不符合格式，跳过处理", zap.String("filename", filename))
		return
	}

	targetPath := filepath.Join(fm.TargetDir, newFilename)

	// 检查目标文件是否已存在
	if _, err := os.Stat(targetPath); err == nil {
		fm.Logger.Debug("目标文件已存在，比较MD5值", zap.String("target_file", targetPath))

		// 比较源文件和目标文件的MD5值
		sourceMD5, err := fm.calculateMD5(sourcePath)
		if err != nil {
			fm.Logger.Error("计算源文件MD5失败", zap.String("source", sourcePath), zap.Error(err))
			return
		}

		targetMD5, err := fm.calculateMD5(targetPath)
		if err != nil {
			fm.Logger.Error("计算目标文件MD5失败", zap.String("target", targetPath), zap.Error(err))
			return
		}

		if sourceMD5 == targetMD5 {
			fm.Logger.Info("文件MD5一致，标记源文件为已处理",
				zap.String("source", sourcePath),
				zap.String("target", targetPath),
				zap.String("md5", sourceMD5))
			// 重命名源文件，标记为已处理
			if err := fm.markFileAsProcessed(sourcePath); err != nil {
				fm.Logger.Error("标记文件为已处理失败", zap.String("source", sourcePath), zap.Error(err))
			} else {
				fm.Logger.Info("源文件已标记为已处理", zap.String("source", sourcePath))
			}
			return
		} else {
			fm.Logger.Info("文件MD5不一致，将重新复制",
				zap.String("source", sourcePath),
				zap.String("target", targetPath),
				zap.String("source_md5", sourceMD5),
				zap.String("target_md5", targetMD5))
		}
	}

	// 复制文件
	if err := fm.copyFile(sourcePath, targetPath); err != nil {
		fm.Logger.Error("复制文件失败",
			zap.String("source", sourcePath),
			zap.String("target", targetPath),
			zap.Error(err))
		return
	}

	// 复制成功后标记源文件为已处理
	if err := fm.markFileAsProcessed(sourcePath); err != nil {
		fm.Logger.Error("标记文件为已处理失败", zap.String("source", sourcePath), zap.Error(err))
		return
	}

	fm.Logger.Info("文件处理成功",
		zap.String("source", sourcePath),
		zap.String("target", targetPath),
		zap.String("original_name", filename),
		zap.String("new_name", newFilename))
}

// removeDatePrefix 去掉文件名中的日期前缀
func (fm *FileMonitor) removeDatePrefix(filename string) string {
	// 匹配日期格式：YYYY-MM-DD-HH.MM.SS-
	// 例如：2025-05-30-08.48.03-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E
	datePattern := `^\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}-`

	re := regexp.MustCompile(datePattern)

	// 检查是否匹配日期格式
	if !re.MatchString(filename) {
		return ""
	}

	// 如果匹配，则去掉日期前缀
	result := re.ReplaceAllString(filename, "")

	// 如果去掉前缀后为空，说明文件名格式不符合预期
	if result == "" {
		return ""
	}

	return result
}

// isProcessedFile 检查文件是否已经被处理过
func (fm *FileMonitor) isProcessedFile(filename string) bool {
	// 检查文件名是否以 .processed 结尾
	return strings.HasSuffix(filename, ".processed")
}

// markFileAsProcessed 标记文件为已处理（通过重命名）
func (fm *FileMonitor) markFileAsProcessed(filePath string) error {
	// 在文件名后添加 .processed 后缀
	newPath := filePath + ".processed"
	return os.Rename(filePath, newPath)
}

// calculateMD5 计算文件的MD5值
func (fm *FileMonitor) calculateMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// copyFile 复制文件
func (fm *FileMonitor) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	// 同步文件到磁盘
	return destFile.Sync()
}

// GetProcessedFiles 获取已处理的文件列表
func (fm *FileMonitor) GetProcessedFiles() ([]string, error) {
	files, err := os.ReadDir(fm.TargetDir)
	if err != nil {
		return nil, err
	}

	var processedFiles []string
	for _, file := range files {
		if !file.IsDir() {
			processedFiles = append(processedFiles, file.Name())
		}
	}

	return processedFiles, nil
}

// GetFileMapping 获取文件名映射关系
func (fm *FileMonitor) GetFileMapping() (map[string]string, error) {
	mapping := make(map[string]string)

	// 读取源目录
	sourceFiles, err := os.ReadDir(fm.SourceDir)
	if err != nil {
		return nil, err
	}

	// 读取目标目录
	targetFiles, err := os.ReadDir(fm.TargetDir)
	if err != nil {
		return nil, err
	}

	// 创建目标文件名的映射
	targetMap := make(map[string]string)
	for _, file := range targetFiles {
		if !file.IsDir() {
			targetMap[file.Name()] = file.Name()
		}
	}

	// 匹配源文件和目标文件
	for _, file := range sourceFiles {
		if !file.IsDir() {
			originalName := file.Name()
			newName := fm.removeDatePrefix(originalName)
			if newName != "" && targetMap[newName] != "" {
				mapping[originalName] = newName
			}
		}
	}

	return mapping, nil
}
