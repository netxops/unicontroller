package types

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type PackageSpec struct {
	Package     string `json:"package"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Binary      struct {
		Name string `json:"name"`
		Path string `json:"path"`
	} `json:"binary"`
	Startup struct {
		Method      string            `json:"method"`
		ServiceName string            `json:"service_name"`
		User        string            `json:"user"`
		Group       string            `json:"group"`
		Args        []string          `json:"args"`
		Environment map[string]string `json:"environment"`
	} `json:"startup"`
	RestartOnConfigChange bool `json:"restart_on_config_change"`
	Config                struct {
		Format    string `json:"format"`
		MainFile  string `json:"main_file"`
		Directory string `json:"directory"`
		Templates []struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
			Type        string `json:"type"`
		} `json:"templates"`
	} `json:"config"`
	UnitFile struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	} `json:"unit_file"`
	Ports []struct {
		Number      int    `json:"number"`
		Protocol    string `json:"protocol"`
		Description string `json:"description"`
	} `json:"ports"`
	Dependencies       []map[string]string `json:"dependencies"`
	PostInstallScript  string              `json:"post_install_script"`
	PreUninstallScript string              `json:"pre_uninstall_script"`
	Logging            map[string]string   `json:"logging"`
	Healthcheck        map[string]string   `json:"healthcheck"`
}

var globalAppDir, globalConfigDir string

func IsPrivilegedUser() bool {
	return os.Geteuid() == 0
}

func CalculateDeploymentPaths(spec *PackageSpec, isPrivilegedUser bool) error {
	baseDir := GetBaseDir()
	globalAppDir = GetAppDir(spec.Package)

	if isPrivilegedUser {
		globalConfigDir = spec.Config.Directory
		if globalConfigDir == "" {
			globalConfigDir = filepath.Join("/etc", spec.Package)
		}
	} else {
		// 首先尝试使用 spec.Config.Directory
		if spec.Config.Directory != "" {
			// 检查是否有读写权限
			if err := CheckWritePermission(spec.Config.Directory); err == nil {
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

func CheckWritePermission(dir string) error {
	// 创建一个临时文件来测试写入权限
	tempFile := filepath.Join(dir, ".write_test")
	err := ioutil.WriteFile(tempFile, []byte("test"), 0644)
	if err != nil {
		return err
	}
	// 清理临时文件
	os.Remove(tempFile)
	return nil
}

func GetBaseDir() string {
	if IsPrivilegedUser() {
		return "/"
	}
	return os.Getenv("HOME")
}

func GetAppDir(appName string) string {
	baseDir := GetBaseDir()
	if IsPrivilegedUser() {
		return filepath.Join(baseDir, "opt", appName)
	}
	return filepath.Join(baseDir, "app", appName)
}

func GetConfigBase(spec *PackageSpec) string {
	if IsPrivilegedUser() {
		return "/etc"
	}

	baseDir := GetBaseDir()
	return filepath.Join(baseDir, ".config")
}

func ConfigFile(spec *PackageSpec, appID, targetFile string) string {
	resolvePath := func(path string) string {
		if filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(GetConfigBase(spec), appID, path)
	}

	// 解析源文件和目标文件的路径
	filePath := resolvePath(targetFile)
	return filePath
}

func ConfigFiles(spec *PackageSpec) []string {
	configFiles := []string{}
	for _, template := range spec.Config.Templates {
		destinationPath := ConfigFile(spec, spec.Package, template.Destination)
		configFiles = append(configFiles, destinationPath)
	}

	return configFiles
}

func GetWorkspaceDir() string {
	baseDir := GetBaseDir()
	if IsPrivilegedUser() {
		return filepath.Join(baseDir, "opt")
	}
	return filepath.Join(baseDir, "app")
}
