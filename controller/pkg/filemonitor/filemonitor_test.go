package filemonitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoveDatePrefix(t *testing.T) {
	fm := &FileMonitor{}

	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "2025-05-30-08.48.03-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt",
			expected: "132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt",
		},
		{
			input:    "2025-01-01-12.30.45-192.168.1.1-FW-Device.config",
			expected: "192.168.1.1-FW-Device.config",
		},
		{
			input:    "normal-filename.txt",
			expected: "",
		},
		{
			input:    "2025-05-30-08.48.03-",
			expected: "",
		},
	}

	for _, test := range tests {
		result := fm.removeDatePrefix(test.input)
		if result != test.expected {
			t.Errorf("removeDatePrefix(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestFileMonitor(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	targetDir := filepath.Join(tempDir, "target")

	// 创建源目录
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("Failed to create source directory: %v", err)
	}

	// 创建文件监控器
	fm := NewFileMonitor(sourceDir, targetDir, 100*time.Millisecond)

	// 创建测试文件
	testFile := "2025-05-30-08.48.03-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt"
	testContent := "This is a test file content"
	testFilePath := filepath.Join(sourceDir, testFile)

	if err := os.WriteFile(testFilePath, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// 启动监控器（在协程中）
	go fm.Start()

	// 等待文件被处理
	time.Sleep(200 * time.Millisecond)

	// 检查目标文件是否存在
	expectedTargetFile := "132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt"
	targetFilePath := filepath.Join(targetDir, expectedTargetFile)

	if _, err := os.Stat(targetFilePath); os.IsNotExist(err) {
		t.Errorf("Target file was not created: %s", targetFilePath)
	} else {
		// 验证文件内容
		content, err := os.ReadFile(targetFilePath)
		if err != nil {
			t.Errorf("Failed to read target file: %v", err)
		} else if string(content) != testContent {
			t.Errorf("File content mismatch. Expected: %s, Got: %s", testContent, string(content))
		}
	}

	// 检查源文件是否已被标记为已处理
	processedFilePath := testFilePath + ".processed"
	if _, err := os.Stat(processedFilePath); os.IsNotExist(err) {
		t.Errorf("Source file should have been marked as processed: %s", processedFilePath)
	}

	// 检查原始源文件是否已不存在
	if _, err := os.Stat(testFilePath); err == nil {
		t.Errorf("Original source file should not exist: %s", testFilePath)
	}

	// 停止监控器
	fm.Stop()
}

func TestFileMonitorSkipInvalidFiles(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	targetDir := filepath.Join(tempDir, "target")

	// 创建源目录
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("Failed to create source directory: %v", err)
	}

	// 创建文件监控器
	fm := NewFileMonitor(sourceDir, targetDir, 100*time.Millisecond)

	// 创建不符合格式的测试文件
	invalidFile := "normal-filename.txt"
	invalidContent := "This is an invalid file"
	invalidFilePath := filepath.Join(sourceDir, invalidFile)

	if err := os.WriteFile(invalidFilePath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to create invalid test file: %v", err)
	}

	// 启动监控器（在协程中）
	go fm.Start()

	// 等待文件被处理
	time.Sleep(200 * time.Millisecond)

	// 检查源文件是否仍然存在（应该没有被处理）
	if _, err := os.Stat(invalidFilePath); os.IsNotExist(err) {
		t.Errorf("Invalid file should not have been processed: %s", invalidFilePath)
	}

	// 检查目标目录是否为空
	files, err := os.ReadDir(targetDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("Failed to read target directory: %v", err)
	}
	if len(files) > 0 {
		t.Errorf("Target directory should be empty, but contains %d files", len(files))
	}

	// 停止监控器
	fm.Stop()
}

func TestFileMonitorSkipProcessedFiles(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	targetDir := filepath.Join(tempDir, "target")

	// 创建源目录
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("Failed to create source directory: %v", err)
	}

	// 创建文件监控器
	fm := NewFileMonitor(sourceDir, targetDir, 100*time.Millisecond)

	// 创建已处理的测试文件（带.processed后缀）
	processedFile := "2025-05-30-08.48.03-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt.processed"
	processedContent := "This is a processed file"
	processedFilePath := filepath.Join(sourceDir, processedFile)

	if err := os.WriteFile(processedFilePath, []byte(processedContent), 0644); err != nil {
		t.Fatalf("Failed to create processed test file: %v", err)
	}

	// 启动监控器（在协程中）
	go fm.Start()

	// 等待文件被处理
	time.Sleep(200 * time.Millisecond)

	// 检查源文件是否仍然存在（应该没有被处理）
	if _, err := os.Stat(processedFilePath); os.IsNotExist(err) {
		t.Errorf("Processed file should not have been processed: %s", processedFilePath)
	}

	// 检查目标目录是否为空
	files, err := os.ReadDir(targetDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("Failed to read target directory: %v", err)
	}
	if len(files) > 0 {
		t.Errorf("Target directory should be empty, but contains %d files", len(files))
	}

	// 停止监控器
	fm.Stop()
}

func TestFileMonitorMD5Comparison(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	targetDir := filepath.Join(tempDir, "target")

	// 创建源目录和目标目录
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("Failed to create source directory: %v", err)
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("Failed to create target directory: %v", err)
	}

	// 创建文件监控器
	fm := NewFileMonitor(sourceDir, targetDir, 100*time.Millisecond)

	// 创建测试文件
	testFile := "2025-05-30-08.48.03-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt"
	testContent := "This is a test file content"
	testFilePath := filepath.Join(sourceDir, testFile)
	expectedTargetFile := "132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt"
	targetFilePath := filepath.Join(targetDir, expectedTargetFile)

	// 第一次：创建源文件，目标文件不存在
	if err := os.WriteFile(testFilePath, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// 启动监控器（在协程中）
	go fm.Start()

	// 等待文件被处理
	time.Sleep(200 * time.Millisecond)

	// 检查目标文件是否存在
	if _, err := os.Stat(targetFilePath); os.IsNotExist(err) {
		t.Errorf("Target file was not created: %s", targetFilePath)
	}

	// 检查源文件是否已被标记为已处理
	processedFilePath := testFilePath + ".processed"
	if _, err := os.Stat(processedFilePath); os.IsNotExist(err) {
		t.Errorf("Source file should have been marked as processed: %s", processedFilePath)
	}

	// 停止监控器
	fm.Stop()

	// 第二次：创建相同内容的文件，测试MD5一致的情况
	fm2 := NewFileMonitor(sourceDir, targetDir, 100*time.Millisecond)

	// 创建相同内容的源文件
	testFile2 := "2025-05-30-09.00.00-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt"
	testFilePath2 := filepath.Join(sourceDir, testFile2)
	if err := os.WriteFile(testFilePath2, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create second test file: %v", err)
	}

	// 启动监控器（在协程中）
	go fm2.Start()

	// 等待文件被处理
	time.Sleep(200 * time.Millisecond)

	// 检查源文件是否已被标记为已处理（因为MD5一致）
	processedFilePath2 := testFilePath2 + ".processed"
	if _, err := os.Stat(processedFilePath2); os.IsNotExist(err) {
		t.Errorf("Source file should have been marked as processed due to MD5 match: %s", processedFilePath2)
	}

	// 停止监控器
	fm2.Stop()

	// 第三次：创建不同内容的文件，测试MD5不一致的情况
	fm3 := NewFileMonitor(sourceDir, targetDir, 100*time.Millisecond)

	// 创建不同内容的源文件
	testFile3 := "2025-05-30-10.00.00-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt"
	testContent3 := "This is a different test file content"
	testFilePath3 := filepath.Join(sourceDir, testFile3)
	if err := os.WriteFile(testFilePath3, []byte(testContent3), 0644); err != nil {
		t.Fatalf("Failed to create third test file: %v", err)
	}

	// 启动监控器（在协程中）
	go fm3.Start()

	// 等待文件被处理
	time.Sleep(200 * time.Millisecond)

	// 检查目标文件内容是否被更新
	content, err := os.ReadFile(targetFilePath)
	if err != nil {
		t.Errorf("Failed to read target file: %v", err)
	} else if string(content) != testContent3 {
		t.Errorf("Target file content should have been updated. Expected: %s, Got: %s", testContent3, string(content))
	}

	// 检查源文件是否已被标记为已处理
	processedFilePath3 := testFilePath3 + ".processed"
	if _, err := os.Stat(processedFilePath3); os.IsNotExist(err) {
		t.Errorf("Source file should have been marked as processed: %s", processedFilePath3)
	}

	// 停止监控器
	fm3.Stop()
}

func TestGetProcessedFiles(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	targetDir := filepath.Join(tempDir, "target")

	// 创建目标目录和文件
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("Failed to create target directory: %v", err)
	}

	// 创建一些测试文件
	testFiles := []string{"file1.txt", "file2.txt", "file3.txt"}
	for _, filename := range testFiles {
		filePath := filepath.Join(targetDir, filename)
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// 创建文件监控器
	fm := NewFileMonitor("", targetDir, time.Second)

	// 获取已处理的文件列表
	processedFiles, err := fm.GetProcessedFiles()
	if err != nil {
		t.Fatalf("Failed to get processed files: %v", err)
	}

	// 验证文件列表
	if len(processedFiles) != len(testFiles) {
		t.Errorf("Expected %d files, got %d", len(testFiles), len(processedFiles))
	}

	for _, expectedFile := range testFiles {
		found := false
		for _, processedFile := range processedFiles {
			if processedFile == expectedFile {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected file %s not found in processed files", expectedFile)
		}
	}
}
