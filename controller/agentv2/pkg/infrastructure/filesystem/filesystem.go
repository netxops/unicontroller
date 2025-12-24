package filesystem

import (
	"os"
	"path/filepath"
)

// FileSystem 文件系统接口
type FileSystem interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Stat(path string) (os.FileInfo, error)
	Exists(path string) bool
}

// RealFileSystem 真实文件系统实现
type RealFileSystem struct{}

// NewRealFileSystem 创建真实文件系统实例
func NewRealFileSystem() *RealFileSystem {
	return &RealFileSystem{}
}

// ReadFile 读取文件
func (fs *RealFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile 写入文件
func (fs *RealFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

// MkdirAll 创建目录
func (fs *RealFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// Stat 获取文件信息
func (fs *RealFileSystem) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// Exists 检查文件是否存在
func (fs *RealFileSystem) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
