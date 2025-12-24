package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/errors"
	"go.uber.org/zap/zaptest"
)

func TestConfigManager_GetConfigFiles_ServiceNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	_, err := manager.GetConfigFiles("non-existent")
	if err == nil {
		t.Error("Expected error when service not found")
	}
	if !errors.IsErrorCode(err, errors.ErrCodeServiceNotFound) {
		t.Errorf("Expected ErrCodeServiceNotFound, got: %v", err)
	}
}

func TestConfigManager_GetConfigFiles_NoConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			// 没有 Config 配置
		},
	}
	registry.Register(service)

	files, err := manager.GetConfigFiles("test-service")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("Expected empty files list, got: %d files", len(files))
	}
}

func TestConfigManager_GetConfigFiles_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	// 创建临时目录和配置文件
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")
	configContent := "key: value\n"
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Config: &domain.ConfigSpec{
				Directory: tempDir,
				MainFile:  "config.yaml",
			},
		},
	}
	registry.Register(service)

	files, err := manager.GetConfigFiles("test-service")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("Expected 1 file, got: %d", len(files))
	}
	if files[0].Path != configFile {
		t.Errorf("Expected path %s, got: %s", configFile, files[0].Path)
	}
	if files[0].Content != configContent {
		t.Errorf("Expected content %q, got: %q", configContent, files[0].Content)
	}
}

func TestConfigManager_GetConfigFiles_MissingFile(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	tempDir := t.TempDir()

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Config: &domain.ConfigSpec{
				Directory: tempDir,
				MainFile:  "missing.yaml",
			},
		},
	}
	registry.Register(service)

	// 文件不存在时，应该返回空列表（不报错，因为实现中会跳过缺失的文件）
	files, err := manager.GetConfigFiles("test-service")
	if err != nil {
		t.Errorf("Expected no error (missing files are skipped), got: %v", err)
	}
	// 实现中会跳过缺失的文件，所以应该返回空列表
	if len(files) != 0 {
		t.Errorf("Expected empty files list (missing file skipped), got: %d files", len(files))
	}
}

func TestConfigManager_UpdateConfigFiles_ServiceNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	files := []ConfigFile{
		{Path: "/tmp/config.yaml", Content: "key: value"},
	}

	_, err := manager.UpdateConfigFiles("non-existent", files)
	if err == nil {
		t.Error("Expected error when service not found")
	}
	if !errors.IsErrorCode(err, errors.ErrCodeServiceNotFound) {
		t.Errorf("Expected ErrCodeServiceNotFound, got: %v", err)
	}
}

func TestConfigManager_UpdateConfigFiles_NoConfigSpec(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			// 没有 Config 配置
		},
	}
	registry.Register(service)

	files := []ConfigFile{
		{Path: "/tmp/config.yaml", Content: "key: value"},
	}

	_, err := manager.UpdateConfigFiles("test-service", files)
	if err == nil {
		t.Error("Expected error when no config spec")
	}
	if !errors.IsErrorCode(err, errors.ErrCodeInvalidRequest) {
		t.Errorf("Expected ErrCodeInvalidRequest, got: %v", err)
	}
}

func TestConfigManager_UpdateConfigFiles_InvalidPath(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	tempDir := t.TempDir()

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Config: &domain.ConfigSpec{
				Directory: tempDir,
				MainFile:  "config.yaml",
			},
		},
	}
	registry.Register(service)

	// 使用无效路径（不在配置目录下）
	files := []ConfigFile{
		{Path: "/etc/passwd", Content: "invalid"},
	}

	updatedFiles, err := manager.UpdateConfigFiles("test-service", files)
	if err != nil {
		t.Errorf("Expected no error (invalid paths are skipped), got: %v", err)
	}
	if len(updatedFiles) != 0 {
		t.Errorf("Expected no updated files (invalid path skipped), got: %d", len(updatedFiles))
	}
}

func TestConfigManager_UpdateConfigFiles_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Config: &domain.ConfigSpec{
				Directory: tempDir,
				MainFile:  "config.yaml",
			},
		},
	}
	registry.Register(service)

	newContent := "key: new_value\n"
	files := []ConfigFile{
		{Path: configFile, Content: newContent},
	}

	updatedFiles, err := manager.UpdateConfigFiles("test-service", files)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(updatedFiles) != 1 {
		t.Fatalf("Expected 1 updated file, got: %d", len(updatedFiles))
	}

	// 验证文件内容已更新
	actualContent, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to read updated file: %v", err)
	}
	if string(actualContent) != newContent {
		t.Errorf("Expected content %q, got: %q", newContent, string(actualContent))
	}
}

func TestConfigManager_UpdateConfigFiles_EmptyContent(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	// 先创建一个非空文件
	initialContent := "key: initial\n"
	if err := os.WriteFile(configFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("Failed to create initial file: %v", err)
	}

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Config: &domain.ConfigSpec{
				Directory: tempDir,
				MainFile:  "config.yaml",
			},
		},
	}
	registry.Register(service)

	// 尝试更新为空内容（应该失败验证）
	files := []ConfigFile{
		{Path: configFile, Content: ""},
	}

	_, err := manager.UpdateConfigFiles("test-service", files)
	if err == nil {
		t.Error("Expected error when content is empty")
	}
	if !errors.IsErrorCode(err, errors.ErrCodeConfigInvalid) {
		t.Errorf("Expected ErrCodeConfigInvalid, got: %v", err)
	}
}

func TestConfigManager_UpdateConfigFiles_WithTemplates(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := NewServiceRegistry()
	manager := NewConfigManager(registry, logger)

	tempDir := t.TempDir()
	templateDest := filepath.Join(tempDir, "template.conf")

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Config: &domain.ConfigSpec{
				Directory: tempDir,
				Templates: []domain.ConfigTemplate{
					{Destination: templateDest},
				},
			},
		},
	}
	registry.Register(service)

	templateContent := "template: value\n"
	files := []ConfigFile{
		{Path: templateDest, Content: templateContent},
	}

	updatedFiles, err := manager.UpdateConfigFiles("test-service", files)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(updatedFiles) != 1 {
		t.Fatalf("Expected 1 updated file, got: %d", len(updatedFiles))
	}

	// 验证文件内容
	actualContent, err := os.ReadFile(templateDest)
	if err != nil {
		t.Fatalf("Failed to read updated file: %v", err)
	}
	if string(actualContent) != templateContent {
		t.Errorf("Expected content %q, got: %q", templateContent, string(actualContent))
	}
}
