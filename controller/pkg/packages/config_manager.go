package packages

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/types"
	"github.com/netxops/utils/tools"
)

type ConfigManager struct {
	packages *tools.SafeMap[string, *types.PackageSpec]
}

func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		packages: tools.NewSafeMap[string, *types.PackageSpec](),
	}
}

func (cm *ConfigManager) GetConfigFiles(name string) ([]map[string]string, error) {
	spec, ok := cm.packages.Get(name)
	if !ok {
		return nil, fmt.Errorf("package %s not found", name)
	}

	files := types.ConfigFiles(spec)
	configFiles := make([]map[string]string, 0, len(files))
	for _, file := range files {
		bs, err := os.ReadFile(file)
		if err != nil {
			xlog.Error("failed to read config file", xlog.String("file", file), xlog.FieldErr(err))
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		configFiles = append(configFiles, map[string]string{
			"source":  file,
			"content": string(bs),
		})
	}

	return configFiles, nil
}

func (cm *ConfigManager) UpdateConfigs(spec *types.PackageSpec, configFiles []map[string]string) (map[string]int, error) {
	// 获取有效的配置路径列表
	validConfigPaths := make(map[string]bool)
	updatedFiles := make(map[string]int)

	// 将配置目录添加到有效路径列表
	configDir := spec.Config.Directory
	if configDir == "" {
		if types.IsPrivilegedUser() {
			configDir = filepath.Join("/etc", spec.Package)
		} else {
			configDir = filepath.Join(types.GetBaseDir(), ".config", spec.Package)
		}
	}
	validConfigPaths[configDir] = true

	// 添加所有配置文件的路径到有效路径列表
	configFilePaths := types.ConfigFiles(spec)
	for _, filePath := range configFilePaths {
		// 添加文件所在的目录作为有效路径
		dirPath := filepath.Dir(filePath)
		validConfigPaths[dirPath] = true
	}

	// 添加应用目录作为有效路径
	appDir := types.GetAppDir(spec.Package)
	validConfigPaths[appDir] = true

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "config_update_")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // 确保清理临时目录

	// 处理每个配置文件
	for _, file := range configFiles {
		sourcePath := file["source"]

		// 检查文件路径是否在有效的配置路径中
		isValidPath := false
		xlog.Debug("validating config file path",
			xlog.String("file", sourcePath),
			xlog.String("package", spec.Package))

		for path := range validConfigPaths {
			xlog.Debug("checking against valid path",
				xlog.String("file_path", sourcePath),
				xlog.String("valid_path", path))

			if filepath.HasPrefix(sourcePath, path) {
				isValidPath = true
				xlog.Debug("file path is valid",
					xlog.String("file", sourcePath),
					xlog.String("matched_path", path))
				break
			}
		}

		if !isValidPath {
			xlog.Warn("config file path is not in valid configuration directories",
				xlog.String("file", sourcePath),
				xlog.Any("valid_paths", validConfigPaths))
			continue
		}

		// 在临时目录中创建目标文件的路径
		tempFilePath := filepath.Join(tempDir, sourcePath)

		// 创建临时文件的目录
		if err := os.MkdirAll(filepath.Dir(tempFilePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for temp config file %s: %v", tempFilePath, err)
		}

		// 写入内容到临时文件
		xlog.Debug("writing config file to temp location",
			xlog.String("temp_file", tempFilePath),
			xlog.Int("content_length", len(file["content"])))

		if err := os.WriteFile(tempFilePath, []byte(file["content"]), 0644); err != nil {
			return nil, fmt.Errorf("failed to write temp config file %s: %v", tempFilePath, err)
		}

		// 验证临时文件
		if err := validateConfigFile(tempFilePath); err != nil {
			return nil, fmt.Errorf("config file validation failed for %s: %v", sourcePath, err)
		}
	}

	// 所有文件都已成功写入临时目录并通过验证，现在我们可以安全地移动它们到目标位置
	for _, file := range configFiles {
		sourcePath := file["source"]
		tempFilePath := filepath.Join(tempDir, sourcePath)

		// 确保目标目录存在
		if err := os.MkdirAll(filepath.Dir(sourcePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for config file %s: %v", sourcePath, err)
		}

		// 使用 os.Rename 来原子性地移动文件
		if err := os.Rename(tempFilePath, sourcePath); err != nil {
			// 如果跨设备移动失败，尝试复制然后删除
			if err := copyFile(tempFilePath, sourcePath); err != nil {
				return nil, fmt.Errorf("failed to copy config file from %s to %s: %v", tempFilePath, sourcePath, err)
			}
			os.Remove(tempFilePath) // 清理临时文件
		}

		// 记录文件更新成功
		fileInfo, err := os.Stat(sourcePath)
		if err == nil {
			xlog.Info("successfully applied config file",
				xlog.String("file", sourcePath),
				xlog.Int64("size", fileInfo.Size()),
				xlog.String("mode", fileInfo.Mode().String()),
				xlog.Any("modified", fileInfo.ModTime()))
			updatedFiles[sourcePath] = int(fileInfo.Size())
		} else {
			xlog.Info("successfully applied config file", xlog.String("file", sourcePath))
			updatedFiles[sourcePath] = len(file["content"])
		}
	}

	return updatedFiles, nil
}

// validateConfigFile 验证配置文件的内容
func validateConfigFile(filePath string) error {
	// 这里应该包含实际的配置文件验证逻辑
	// 例如，检查文件格式、必要的字段等
	// 这里只是一个简单的示例，实际实现应该根据具体需求来编写
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file for validation: %v", err)
	}
	if len(content) == 0 {
		return fmt.Errorf("config file is empty")
	}
	// 可以添加更多的验证逻辑...
	return nil
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

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
