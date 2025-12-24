# Sangfor 真实设备 JSON 数据分析

本文档分析了 `pkg/nodemap/example/sangfor/cmd/` 目录中真实设备返回的 JSON 数据结构，用于指导测试用例的编写和改进。

## 1. 网络对象 (network_api.json)

### 数据结构特点

```json
{
  "code": 0,
  "message": "成功",
  "data": {
    "items": [
      {
        "uuid": "...",
        "name": "All",
        "businessType": "IP",
        "ipRanges": [
          {
            "start": "0.0.0.0",
            "end": "255.255.255.255",
            "bits": 0
          }
        ],
        "refIpGroup": null
      }
    ]
  }
}
```

### 关键发现

1. **IP 范围格式**:
   - `bits: 0` 且 `start` 和 `end` 都存在 → IP 范围 (如 `192.168.1.0-192.168.1.255`)
   - `bits > 0` → CIDR 格式 (如 `192.168.1.0/24`)
   - 只有 `start`，`end` 为空 → 单个 IP (如 `1.1.1.1`)

2. **真实对象示例**:
   - `"All"`: 所有 IP (0.0.0.0-255.255.255.255)
   - `"192.168.100.0-24"`: 包含多个 IP 范围的对象
   - `"dst-text1"`: 单个子网 (192.168.100.0/24)
   - `"dest-text-2"`: 单个 IP (1.1.1.1)

3. **地址组**:
   - `businessType: "ADDRGROUP"` 表示地址组
   - `refIpGroup` 包含引用的地址组名称数组

## 2. 服务对象 (service_api.json)

### 数据结构特点

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "uuid": "...",
        "name": "ssh",
        "servType": "PREDEF_SERV",
        "tcpEntrys": [
          {
            "srcPorts": [{"start": 0, "end": 65535}],
            "dstPorts": [{"start": 22, "end": 22}]
          }
        ]
      }
    ]
  }
}
```

### 关键发现

1. **端口格式**:
   - 单个端口: `{"start": 22, "end": 22}`
   - 端口范围: `{"start": 8000, "end": 8010}`
   - 全端口: `{"start": 0, "end": 65535}`

2. **真实服务示例**:
   - `"any"`: 所有协议和端口
   - `"ping"`: ICMP (type: 8, code: 0)
   - `"ssh"`: TCP 22
   - `"ftp"`: TCP 21

3. **服务组**:
   - `servType: "SERV_GRP"` 表示服务组
   - `servsInfo` 包含引用的服务名称数组

## 3. NAT 规则 (nat_api.json)

### DNAT 规则结构

```json
{
  "name": "dest-nat-1",
  "natType": "DNAT",
  "enable": true,
  "dnat": {
    "srcZones": ["L3_trust_B"],
    "srcIpGroups": ["dest-3"],
    "dstIpobj": {
      "dstIpobjType": "IP",
      "specifyIp": ["172.32.2.108"]
    },
    "natService": ["ssh"],
    "transfer": {
      "transferType": "IP",
      "specifyIp": "192.168.100.111",
      "transferPort": [{"start": 22, "end": 0}]
    }
  }
}
```

### SNAT 规则结构

```json
{
  "name": "nat-text-2",
  "natType": "SNAT",
  "enable": true,
  "snat": {
    "srcZones": ["L3_trust_B"],
    "srcIpGroups": ["dest-3"],
    "dstNetobj": {
      "dstNetobjType": "ZONE",
      "zone": ["L3_untrust_A"]
    },
    "dstIpGroups": ["dest-text-2"],
    "natService": ["any"],
    "transfer": {
      "transferType": "IP_RANGE",
      "ipRange": {
        "start": "192.168.100.101",
        "end": "192.168.100.102"
      }
    }
  }
}
```

### 关键发现

1. **DNAT transfer 类型**:
   - `"IP"`: 单个 IP (`specifyIp`)
   - `"IP_RANGE"`: IP 范围 (`ipRange.start` - `ipRange.end`)
   - `"IPGROUP"`: IP 组 (`ipGroups`)
   - `"IP_PREFIX"`: IP 前缀 (`ipPrefix`)

2. **SNAT transfer 类型**:
   - `"IPGROUP"`: IP 组 (`ipGroups`)
   - `"IP_RANGE"`: IP 范围 (`ipRange`)
   - `"IP"`: 单个 IP (`specifyIp`)

3. **端口转换**:
   - `transferPort`: `[{"start": 22, "end": 0}]` 表示端口 22
   - `end: 0` 表示单个端口

4. **真实 NAT 规则示例**:
   - `"dest-nat-1"`: DNAT，将 172.32.2.108:22 转换为 192.168.100.111:22
   - `"dest-nat-2"`: DNAT，将 172.32.2.108 转换为 192.168.100.1-255 范围
   - `"nat-text-2"`: SNAT，将源地址转换为 192.168.100.101-102 范围
   - `"nat-text-3"`: SNAT，使用 IP 组进行转换

## 4. 测试改进建议

### 4.1 使用真实数据测试

1. **网络对象测试**:
   - 使用真实对象名称和结构
   - 测试各种 IP 范围格式
   - 测试地址组引用

2. **服务对象测试**:
   - 使用预定义服务 (any, ssh, ping)
   - 测试端口范围解析
   - 测试服务组引用

3. **NAT 规则测试**:
   - 使用真实的 DNAT/SNAT 规则
   - 测试各种 transfer 类型
   - 测试端口转换
   - 测试 FlyConfig 加载和 InputNat/OutputNat 验证

4. **端到端测试**:
   - 加载完整的 JSON 数据
   - 生成 CLI
   - 通过 FlyConfig 重新加载
   - 验证 InputPolicy/InputNat/OutputNat 匹配

### 4.2 测试用例改进

1. **基于真实数据的测试**:
   ```go
   // 加载真实 JSON 数据
   networkData := loadJSONFromFile("network_api.json")
   sangfor.objectSet.parseRespResultForNetwork(networkData)
   
   // 使用真实对象进行测试
   obj, found := sangfor.GetObjectByNetworkGroup(ng, ...)
   ```

2. **CLI 生成和验证**:
   ```go
   // 生成 CLI
   cli := obj.Cli()
   
   // 通过 FlyConfig 加载
   sangfor.FlyConfig(cli)
   
   // 验证对象被正确加载
   loadedObj, found := sangfor.GetObjectByNetworkGroup(...)
   ```

3. **NAT 规则验证**:
   ```go
   // 加载 NAT 规则
   sangfor.nats.parseRespResultForNat(natData)
   
   // 生成 CLI
   cli := rule.Cli()
   
   // 通过 FlyConfig 加载
   sangfor.FlyConfig(cli)
   
   // 验证 InputNat/OutputNat
   result := sangfor.InputNat(intent, from)
   ```

## 5. 数据文件位置

- 网络对象: `pkg/nodemap/example/sangfor/cmd/network/network_api.json`
- 服务对象: `pkg/nodemap/example/sangfor/cmd/service/service_api.json`
- NAT 规则: `pkg/nodemap/example/sangfor/cmd/nat/nat_api.json`
- 安全策略: `pkg/nodemap/example/sangfor/cmd/policy/policy_api.json`
- 静态路由: `pkg/nodemap/example/sangfor/cmd/staticroute/staticroute_api.json`
- 区域: `pkg/nodemap/example/sangfor/cmd/zone/zone_api.json`
- 接口: `pkg/nodemap/example/sangfor/cmd/interface/interface_api.json`

## 6. 注意事项

1. **数据格式一致性**: 确保解析逻辑与真实 API 返回格式一致
2. **字段类型**: 注意数字字段可能是 `float64` 类型
3. **空值处理**: `null` 值需要正确处理
4. **数组格式**: 某些字段可能是数组或单个值
5. **端口格式**: `end: 0` 表示单个端口，需要特殊处理

