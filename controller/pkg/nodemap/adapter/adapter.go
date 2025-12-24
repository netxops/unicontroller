package adapter

import (
	"encoding/json"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
)

// Adapter 基础适配器接口，提供基本的写入功能
type Adapter interface {
	Write(p []byte) (n int, err error)
}

// FwAdapter 防火墙适配器通用接口
// 基于对 ASA、SecPath、Fortigate、SRX、USG、Dptech 等实现的总结
//
// 所有防火墙适配器都需要实现 api.Adapter 接口，该接口包含以下核心方法：
//
//  1. Info(force bool) (*device.DeviceBaseInfo, error)
//     获取设备基本信息（主机名、版本、型号、序列号等）
//
//  2. ParseName(force bool) string
//     解析设备名称/主机名
//
//  3. PortList(force bool) []api.Port
//     获取端口列表，包含端口名称、IP地址、VRF等信息
//
//  4. RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable)
//     获取路由表，返回 IPv4 和 IPv6 路由表，按 VRF 组织
//
//  5. GetConfig(force bool) interface{}
//     获取设备配置（完整配置或部分配置）
//
//  6. GetRawConfig(apiPath string, force bool) (any, error)
//     获取原始配置（支持指定 API 路径，某些适配器如 Fortigate 支持）
//
//  7. BatchRun(p interface{}) (interface{}, error)
//     批量执行命令（多次登录设备）
//     参数: []*command.CliCmdList 或 []*command.HttpCmdList
//
//  8. BatchConfig(p ...interface{}) (interface{}, error)
//     批量配置（单次登录，合并执行）
//     参数: []*command.CliCmdList、[]string 等类型
//
//  9. TaskId() uint
//     获取任务 ID（用于关联任务）
//
//  10. AttachChannel(out chan string) bool
//     附加输出通道（用于实时输出）
//
// 注意：所有防火墙适配器都实现了 api.Adapter 接口
type FwAdapter interface {
	api.Adapter
}

//type LbAdapter interface {
//}
//
//type L2Adapter interface {
//}
//
//type L3Adapter interface {
//}

// func IndentSection(txt string) *text.SplitterResult {
// indentRegexMap := map[string]string{
// "regex": `(?P<section>^\w[^\n]+(\n[ \t]+[^\n]+)+)`,
// "name":  "intent",
// "flags": "m",
// "pcre":  "true",
// }
//
// indentRegexSplitter, err := text.NewSplitterFromMap(indentRegexMap)
// if err != nil {
// panic(err)
// }
//
// indentResult, err := indentRegexSplitter.Input(txt)
// if err != nil {
// panic(err)
// }
//
// return indentResult
// }
type CommandRunner struct {
	Adapter Adapter
}

func (c *CommandRunner) RunConfig(config interface{}) (output interface{}, err error) {
	var byteS []byte
	byteS, err = json.Marshal(config)
	if err != nil {
		return
	}

	return c.Adapter.Write(byteS)
}
