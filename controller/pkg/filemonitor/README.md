# 文件监控器 (FileMonitor)

## 功能描述

文件监控器是一个后台协程服务，用于监控指定目录中的文件，当检测到新文件时，自动将文件复制到目标目录并进行重命名。

## 主要特性

- **周期性监控**: 每隔指定时间间隔检查源目录
- **格式过滤**: 只处理符合日期前缀格式的文件
- **自动重命名**: 自动去掉文件名中的日期前缀
- **文件复制**: 将文件从源目录复制到目标目录
- **MD5比较**: 当目标文件存在时，通过MD5比较决定是否重新复制
- **处理标记**: 通过重命名标记已处理的文件（添加.processed后缀）
- **重复检测**: 避免重复处理已存在的文件和已标记的文件
- **日志记录**: 详细的操作日志记录

## 文件名重命名规则

### 输入格式
```
YYYY-MM-DD-HH.MM.SS-<实际文件名>
```

### 输出格式
```
<实际文件名>
```

### 示例
- 输入: `2025-05-30-08.48.03-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt`
- 输出: `132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt`
- 源文件标记: `2025-05-30-08.48.03-132.252.20.11-NJ-JiS-E24-FW-1.RP.Edu8000E.txt.processed`

## 使用方法

### 1. 在main.go中启动

```go
import (
    "time"
    "github.com/netxops/l2service/pkg/filemonitor"
)

func main() {
    // ... 其他初始化代码 ...
    
    // 启动文件监控协程
    startFileMonitor(logger.Logger)
    
    // ... 其他代码 ...
}

func startFileMonitor(logger *zap.Logger) {
    sourceDir := "./config"           // 源目录
    targetDir := "./pkg/example"      // 目标目录
    checkInterval := 30 * time.Second // 检查间隔

    monitor := filemonitor.NewFileMonitor(sourceDir, targetDir, checkInterval)
    
    go func() {
        logger.Info("启动文件监控协程")
        monitor.Start()
    }()
}
```

### 2. 直接使用

```go
import "github.com/netxops/l2service/pkg/filemonitor"

// 创建监控器
monitor := filemonitor.NewFileMonitor(
    "./source",      // 源目录
    "./target",      // 目标目录
    30*time.Second,  // 检查间隔
)

// 启动监控
go monitor.Start()

// 停止监控
monitor.Stop()
```

## 配置参数

| 参数 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| SourceDir | string | 源目录路径 | "./config" |
| TargetDir | string | 目标目录路径 | "./pkg/example" |
| CheckInterval | time.Duration | 检查间隔 | 30秒 |

## API接口

### NewFileMonitor
```go
func NewFileMonitor(sourceDir, targetDir string, checkInterval time.Duration) *FileMonitor
```
创建新的文件监控器实例。

### Start
```go
func (fm *FileMonitor) Start()
```
启动文件监控器。这是一个阻塞方法，通常在协程中调用。

### Stop
```go
func (fm *FileMonitor) Stop()
```
停止文件监控器。

### GetProcessedFiles
```go
func (fm *FileMonitor) GetProcessedFiles() ([]string, error)
```
获取已处理的文件列表。

### GetFileMapping
```go
func (fm *FileMonitor) GetFileMapping() (map[string]string, error)
```
获取文件名映射关系（原始文件名 -> 新文件名）。

## 日志记录

监控器会记录以下操作：

- 启动/停止信息
- 文件复制成功/失败
- 目录不存在警告
- 文件名处理失败警告

## 测试

运行测试：
```bash
go test -v ./pkg/filemonitor/...
```

## 注意事项

1. **目录权限**: 确保程序对源目录有读写权限，对目标目录有写权限
2. **文件格式**: 只有符合日期前缀格式的文件才会被处理
3. **MD5比较**: 当目标文件已存在时，会比较源文件和目标文件的MD5值
   - 如果MD5一致：标记源文件为已处理，跳过复制
   - 如果MD5不一致：重新复制文件，更新目标文件
4. **处理标记**: 处理成功的文件会在源目录中重命名为 `.processed` 后缀
5. **已处理文件**: 带 `.processed` 后缀的文件会被跳过，不会重复处理
6. **协程安全**: 监控器是协程安全的，可以在多个协程中使用

## 错误处理

- 源目录不存在：记录警告日志，继续监控
- 目标目录创建失败：记录错误日志，停止监控
- 文件复制失败：记录错误日志，继续处理其他文件
- 文件标记失败：记录错误日志，继续处理其他文件
- 文件名格式不符合：记录调试日志，跳过该文件
- 已处理文件：记录调试日志，跳过该文件
