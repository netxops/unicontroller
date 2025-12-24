# Agent V2 下一步行动计划

## 🎯 本周重点任务

### 1. 配置管理系统（优先级：最高）🔥

**问题**：当前很多参数都是硬编码的，需要从配置文件读取

**任务清单**：
- [ ] 引入配置管理库（推荐使用 `spf13/viper`）
- [ ] 定义配置结构体
- [ ] 实现配置加载和验证
- [ ] 替换所有硬编码的参数

**文件需要修改**：
- `internal/wire.go` - 从配置读取参数
- `pkg/config/config.go` - 定义配置结构（需要创建）
- `cmd/agentv2/main.go` - 加载配置文件

**预计时间**：1-2 天

---

### 2. Package 服务功能完善（优先级：高）📦

**问题**：`GetConfigs`、`ApplyConfigs`、`GetRecentLogs` 都是占位符

**任务清单**：
- [ ] 实现 `GetConfigs` - 读取服务配置文件
- [ ] 实现 `ApplyConfigs` - 应用配置变更并重启服务
- [ ] 实现 `GetRecentLogs` - 从 systemd journal 或日志文件读取
- [ ] 完善 `PackageList` - 计算服务运行时长

**文件需要修改**：
- `internal/api/package_service.go`
- `pkg/ops/logs/log_manager.go` - 完善日志读取功能
- `pkg/infrastructure/filesystem/filesystem.go` - 可能需要扩展

**预计时间**：2-3 天

---

### 3. 服务发现和自动注册（优先级：高）🔍

**问题**：需要自动发现工作目录中的服务并注册

**任务清单**：
- [ ] 实现服务发现（扫描 package.json 文件）
- [ ] 解析 package.json 并创建 Service 对象
- [ ] 自动注册到 ServiceRegistry
- [ ] 实现定期扫描和更新

**文件需要创建/修改**：
- `pkg/service/discovery.go` - 服务发现逻辑（需要创建）
- `cmd/agentv2/main.go` - 启动服务发现

**预计时间**：2-3 天

---

## 📋 详细任务分解

### 任务 1：配置管理系统

#### 步骤 1.1：创建配置结构

```go
// pkg/config/config.go
type Config struct {
    Agent      AgentConfig      `yaml:"agent"`
    Server     ServerConfig     `yaml:"server"`
    Registry   RegistryConfig   `yaml:"registry"`
    Discovery  DiscoveryConfig  `yaml:"discovery"`
    HealthCheck HealthCheckConfig `yaml:"health_check"`
    // ...
}
```

#### 步骤 1.2：实现配置加载

```go
// pkg/config/loader.go
func LoadConfig(path string) (*Config, error) {
    // 使用 viper 加载配置
}
```

#### 步骤 1.3：更新 wire.go

```go
// 从配置读取参数，而不是硬编码
func provideRegistry(config *config.Config, logger *zap.Logger) (registry.Registry, error) {
    return registry.NewEtcdRegistry(
        config.Registry.EtcdEndpoints,
        config.Registry.EtcdPrefix,
        logger,
    )
}
```

---

### 任务 2：Package 服务功能完善

#### 步骤 2.1：实现 GetConfigs

```go
func (s *PackageService) GetConfigs(ctx context.Context, req *pb.GetConfigsReq) (*pb.GetConfigsResp, error) {
    // 1. 获取服务
    // 2. 读取配置文件
    // 3. 返回配置内容
}
```

#### 步骤 2.2：实现 ApplyConfigs

```go
func (s *PackageService) ApplyConfigs(ctx context.Context, req *pb.ApplyConfigsReq) (*pb.ApplyConfigsResp, error) {
    // 1. 验证配置
    // 2. 写入配置文件
    // 3. 重启服务（如果需要）
}
```

#### 步骤 2.3：实现 GetRecentLogs

```go
func (s *PackageService) GetRecentLogs(ctx context.Context, req *pb.GetRecentLogsReq) (*pb.GetRecentLogsResp, error) {
    // 1. 使用 LogManager 获取日志
    // 2. 返回日志内容
}
```

---

### 任务 3：服务发现和自动注册

#### 步骤 3.1：创建服务发现器

```go
// pkg/service/discovery.go
type ServiceDiscovery interface {
    Discover(ctx context.Context) ([]*domain.Service, error)
    Watch(ctx context.Context) (<-chan *domain.Service, error)
}
```

#### 步骤 3.2：实现 package.json 解析

```go
func parsePackageJSON(path string) (*domain.ServiceSpec, error) {
    // 解析 package.json
    // 转换为 ServiceSpec
}
```

#### 步骤 3.3：集成到主程序

```go
// cmd/agentv2/main.go
discovery := service.NewServiceDiscovery(config)
go discovery.Watch(ctx)
```

---

## 🛠️ 技术选型建议

### 配置管理
- **推荐**：`spf13/viper` - 功能强大，支持多种格式
- **备选**：标准库 `encoding/json` + `gopkg.in/yaml.v3`

### 日志文件读取
- **推荐**：`github.com/hpcloud/tail` - 支持 tail -f 功能
- **备选**：标准库 `os` + `bufio`

### 服务发现
- **推荐**：使用 `filepath.Walk` 扫描目录
- **备选**：使用 `fsnotify` 监听文件变化

---

## 📝 代码示例

### 配置加载示例

```go
// pkg/config/loader.go
package config

import (
    "github.com/spf13/viper"
)

func Load(path string) (*Config, error) {
    viper.SetConfigFile(path)
    viper.SetConfigType("yaml")
    
    if err := viper.ReadInConfig(); err != nil {
        return nil, err
    }
    
    var cfg Config
    if err := viper.Unmarshal(&cfg); err != nil {
        return nil, err
    }
    
    return &cfg, nil
}
```

### 服务发现示例

```go
// pkg/service/discovery.go
func (d *discovery) Discover(ctx context.Context) ([]*domain.Service, error) {
    var services []*domain.Service
    
    err := filepath.Walk(d.workspace, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        
        if info.Name() == "package.json" {
            spec, err := parsePackageJSON(path)
            if err != nil {
                return err
            }
            
            service := &domain.Service{
                ID:   spec.Package,
                Name: spec.Package,
                Spec: spec,
            }
            services = append(services, service)
        }
        
        return nil
    })
    
    return services, err
}
```

---

## ✅ 完成标准

每个任务完成后，应该满足：

1. **功能完整**：所有方法都有实现，不是占位符
2. **错误处理**：有完善的错误处理和日志
3. **单元测试**：至少有一个基本的单元测试
4. **文档更新**：更新相关文档

---

## 🚀 快速开始

### 今天就可以开始：

1. **创建配置管理模块**
   ```bash
   mkdir -p agentv2/pkg/config
   # 创建 config.go 和 loader.go
   ```

2. **实现第一个 Package 方法**
   ```bash
   # 从最简单的 GetConfigs 开始
   ```

3. **编写测试**
   ```bash
   # 为每个新功能编写测试
   ```

---

## 📊 进度跟踪

使用 GitHub Issues 或项目管理工具跟踪：
- [ ] 配置管理系统
- [ ] GetConfigs 实现
- [ ] ApplyConfigs 实现
- [ ] GetRecentLogs 实现
- [ ] 服务发现实现
- [ ] 自动注册实现

---

## 💡 提示

1. **小步迭代**：每次完成一个小功能，提交代码
2. **测试驱动**：先写测试，再写实现
3. **文档同步**：代码变更时同步更新文档
4. **代码审查**：重要功能提交前进行代码审查



