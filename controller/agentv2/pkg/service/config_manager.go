package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/errors"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/utils"
	"go.uber.org/zap"
)

// ConfigManager 配置管理器
type ConfigManager interface {
	GetConfigFiles(serviceID string) ([]ConfigFile, error)
	UpdateConfigFiles(serviceID string, files []ConfigFile) (map[string]int, error)
}

// ConfigFile 配置文件
type ConfigFile struct {
	Path    string
	Content string
}

// configManager 配置管理器实现
type configManager struct {
	registry *ServiceRegistry
	logger   *zap.Logger
}

// NewConfigManager 创建配置管理器
func NewConfigManager(registry *ServiceRegistry, logger *zap.Logger) ConfigManager {
	return &configManager{
		registry: registry,
		logger:   logger,
	}
}

// GetConfigFiles 获取服务的配置文件
func (cm *configManager) GetConfigFiles(serviceID string) ([]ConfigFile, error) {
	service, exists := cm.registry.Get(serviceID)
	if !exists {
		return nil, errors.NewError(errors.ErrCodeServiceNotFound, fmt.Sprintf("service %s not found", serviceID))
	}

	if service.Spec == nil || service.Spec.Config == nil {
		return []ConfigFile{}, nil
	}

	// 获取配置文件列表
	configFiles := cm.getConfigFilePaths(service)

	files := make([]ConfigFile, 0, len(configFiles))
	for _, filePath := range configFiles {
		content, err := os.ReadFile(filePath)
		if err != nil {
			cm.logger.Warn("Failed to read config file",
				zap.String("service", serviceID),
				zap.String("file", filePath),
				zap.Error(err))
			// 继续处理其他文件，不因为一个文件失败而全部失败
			continue
		}

		files = append(files, ConfigFile{
			Path:    filePath,
			Content: string(content),
		})
	}

	return files, nil
}

// UpdateConfigFiles 更新服务的配置文件
func (cm *configManager) UpdateConfigFiles(serviceID string, files []ConfigFile) (map[string]int, error) {
	service, exists := cm.registry.Get(serviceID)
	if !exists {
		return nil, errors.NewError(errors.ErrCodeServiceNotFound, fmt.Sprintf("service %s not found", serviceID))
	}

	if service.Spec == nil || service.Spec.Config == nil {
		return nil, errors.NewError(errors.ErrCodeInvalidRequest, fmt.Sprintf("service %s has no config specification", serviceID))
	}

	// 获取有效的配置路径
	validPaths := cm.getValidConfigPaths(service)

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "config_update_")
	if err != nil {
		return nil, errors.WrapError(errors.ErrCodeInternal, "failed to create temp directory", err)
	}
	defer os.RemoveAll(tempDir)

	updatedFiles := make(map[string]int)

	// 验证并写入临时文件
	for _, file := range files {
		// 验证路径是否在有效范围内
		if !cm.isValidPath(file.Path, validPaths) {
			cm.logger.Warn("Config file path is not valid",
				zap.String("service", serviceID),
				zap.String("file", file.Path))
			continue
		}

		// 写入临时文件
		tempFilePath := filepath.Join(tempDir, filepath.Base(file.Path))
		if err := os.MkdirAll(filepath.Dir(tempFilePath), 0755); err != nil {
			return nil, errors.WrapError(errors.ErrCodeInternal, fmt.Sprintf("failed to create temp dir for %s", file.Path), err)
		}

		if err := os.WriteFile(tempFilePath, []byte(file.Content), 0644); err != nil {
			return nil, errors.WrapError(errors.ErrCodeInternal, fmt.Sprintf("failed to write temp file %s", tempFilePath), err)
		}

		// 验证配置文件
		if err := cm.validateConfigFile(tempFilePath); err != nil {
			return nil, errors.WrapError(errors.ErrCodeConfigInvalid, fmt.Sprintf("config file validation failed for %s", file.Path), err)
		}

		// 移动到目标位置
		if err := cm.moveFile(tempFilePath, file.Path); err != nil {
			return nil, errors.WrapError(errors.ErrCodeInternal, fmt.Sprintf("failed to move config file to %s", file.Path), err)
		}

		// 记录更新的文件
		fileInfo, err := os.Stat(file.Path)
		if err == nil {
			updatedFiles[file.Path] = int(fileInfo.Size())
		} else {
			updatedFiles[file.Path] = len(file.Content)
		}
	}

	return updatedFiles, nil
}

// getConfigFilePaths 获取配置文件路径列表
func (cm *configManager) getConfigFilePaths(service *domain.Service) []string {
	if service.Spec.Config == nil {
		return []string{}
	}

	var files []string

	// 主配置文件
	if service.Spec.Config.MainFile != "" {
		configDir := service.Spec.Config.Directory
		if configDir == "" {
			configDir = utils.GetDefaultConfigDirectory(service.Name)
		}
		files = append(files, filepath.Join(configDir, service.Spec.Config.MainFile))
	}

	// 模板文件的目标路径
	for _, template := range service.Spec.Config.Templates {
		if template.Destination != "" {
			files = append(files, template.Destination)
		}
	}

	return files
}

// getValidConfigPaths 获取有效的配置路径
func (cm *configManager) getValidConfigPaths(service *domain.Service) []string {
	var paths []string

	// 配置目录
	if service.Spec.Config.Directory != "" {
		paths = append(paths, service.Spec.Config.Directory)
	} else {
		paths = append(paths, utils.GetDefaultConfigDirectory(service.Name))
	}

	// 所有配置文件所在的目录
	configFiles := cm.getConfigFilePaths(service)
	for _, filePath := range configFiles {
		dir := filepath.Dir(filePath)
		paths = append(paths, dir)
	}

	return paths
}

// isValidPath 检查路径是否在有效范围内
func (cm *configManager) isValidPath(filePath string, validPaths []string) bool {
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}

	for _, validPath := range validPaths {
		absValidPath, err := filepath.Abs(validPath)
		if err != nil {
			continue
		}
		// 检查文件路径是否在有效路径下
		if strings.HasPrefix(absFilePath, absValidPath) {
			return true
		}
	}
	return false
}

// validateConfigFile 验证配置文件
func (cm *configManager) validateConfigFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if len(content) == 0 {
		return fmt.Errorf("config file is empty")
	}

	// 可以添加更多验证逻辑，如格式检查等
	return nil
}

// moveFile 移动文件（支持跨设备）
func (cm *configManager) moveFile(src, dst string) error {
	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 尝试直接移动
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// 如果移动失败（可能是跨设备），使用复制+删除
	return cm.copyFile(src, dst)
}

// copyFile 复制文件
func (cm *configManager) copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}
