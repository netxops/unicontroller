# TextFSM & 正则表达式测试工具

这是一个用于测试和调试TextFSM模板与正则表达式的Web工具。

## 功能特性

- 🔧 **TextFSM模板测试**: 支持测试TextFSM模板的解析功能
- 🔍 **正则表达式测试**: 支持测试正则表达式的匹配功能
- 🎨 **现代化UI**: 美观的响应式Web界面
- 📱 **移动端支持**: 支持手机和平板设备访问
- 🚀 **实时测试**: 即时显示解析结果和错误信息

## 使用方法

### 启动工具

```bash
cd /home/jacky/project/agent/cmd/textfsm_tool
go build -o textfsm_tool main.go

# 默认启动 (localhost:8080)
./textfsm_tool

# 指定监听地址和端口
./textfsm_tool --host 0.0.0.0 --port 9090

# 查看帮助
./textfsm_tool --help
```

### 命令行参数

- `--host`: 监听地址 (默认: localhost)
- `--port`: 监听端口 (默认: 8080)

### 访问界面

根据启动参数访问对应地址，例如:
- 默认: http://localhost:8080
- 自定义: http://0.0.0.0:9090

## TextFSM模板示例

```textfsm
Value LOCAL_PORT (\S+)
Value NEIGHBOR_INDEX (\d+)
Value PEER_INTERFACE (\S+)
Value SYSTEM_NAME (.+)
Value MANAGEMENT_IP ([\d\.]+)
Value CHASSIS_ID (\S+)
Value SYSTEM_DESC (.+)

Start
  ^LLDP neighbor-information of port ${NEIGHBOR_INDEX}\[${LOCAL_PORT}\]:
  ^  Neighbor index\s+: ${NEIGHBOR_INDEX}
  ^  Chassis ID\s+: ${CHASSIS_ID}
  ^  Port ID\s+: ${PEER_INTERFACE}
  ^  System name\s+: ${SYSTEM_NAME}
  ^  System description\s+: ${SYSTEM_DESC}
  ^  Management address\s+: ${MANAGEMENT_IP} -> Record
```

## 正则表达式示例

- IP地址匹配: `(\d+\.\d+\.\d+\.\d+)`
- MAC地址匹配: `([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`
- 邮箱匹配: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`

## API接口

### TextFSM测试接口

**POST** `/api/textfsm`

请求体:
```json
{
  "template": "TextFSM模板内容",
  "input": "要解析的文本"
}
```

响应:
```json
{
  "success": true,
  "data": [
    {
      "FIELD1": "value1",
      "FIELD2": "value2"
    }
  ],
  "fields": ["FIELD1", "FIELD2"]
}
```

### 正则表达式测试接口

**POST** `/api/regex`

请求体:
```json
{
  "pattern": "正则表达式",
  "input": "要匹配的文本"
}
```

响应:
```json
{
  "success": true,
  "matches": ["匹配1", "匹配2"],
  "groups": [
    ["完整匹配", "捕获组1", "捕获组2"]
  ]
}
```

## 技术栈

- **后端**: Go 1.23+
- **前端**: HTML5, CSS3, JavaScript (ES6+)
- **TextFSM库**: github.com/sirikothe/gotextfsm
- **静态文件**: Go embed

## 文件结构

```
textfsm_tool/
├── main.go          # 主程序文件
├── static/          # 静态文件目录
│   ├── index.html   # 主页面
│   ├── style.css    # 样式文件
│   └── script.js    # JavaScript文件
└── README.md        # 说明文档
```

## 功能特性

- ✅ **表单提交**: TextFSM和正则表达式都通过HTML表单提交
- ✅ **参数验证**: 前端和后端双重验证，确保数据完整性
- ✅ **灵活配置**: 支持自定义监听地址和端口
- ✅ **单文件部署**: 所有静态文件嵌入在可执行文件中
- ✅ **实时反馈**: 即时显示解析结果和错误信息

## 注意事项

1. 工具默认运行在localhost:8080，可通过参数自定义
2. 支持跨域请求
3. 所有静态文件都嵌入在可执行文件中，无需额外部署
4. 支持实时错误提示和结果展示
5. 表单提交方式更加标准化，支持浏览器验证
