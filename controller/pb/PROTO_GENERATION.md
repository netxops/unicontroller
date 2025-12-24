# Proto 代码生成说明

## 新增的 Proto 文件

本次更新添加了以下 proto 文件：

1. **metrics.proto** - 扩展了 Metrics 服务，添加了：
   - `GetApplicationMetrics` - 获取应用指标
   - `GetMetricsHistory` - 获取指标历史数据

2. **file.proto** - 新增文件操作服务，包含：
   - `ListFiles` - 列出文件
   - `GetFileInfo` - 获取文件信息
   - `StartFileUpload` - 开始文件上传
   - `UploadFileChunk` - 上传文件块
   - `GetUploadStatus` - 获取上传状态
   - `DownloadFile` - 下载文件（流式）

## 生成 Proto 代码

在 `agent/pb` 目录下运行：

```bash
cd agent/pb
./gen.sh
```

或者手动运行：

```bash
protoc -I . \
  --go_out=. \
  --go-grpc_out=. \
  ./metrics.proto \
  ./file.proto
```

## 生成后的文件

生成后会创建以下文件：

- `metrics.pb.go` - Metrics 消息类型
- `metrics_grpc.pb.go` - Metrics gRPC 客户端和服务端代码
- `file.pb.go` - File 消息类型
- `file_grpc.pb.go` - File gRPC 客户端和服务端代码

## 注意事项

1. 确保已安装 `protoc` 和 `protoc-gen-go`、`protoc-gen-go-grpc` 插件
2. 生成代码后，Controller 中的 gRPC 调用代码才能正常工作
3. AgentV2 需要实现对应的 gRPC 服务方法

