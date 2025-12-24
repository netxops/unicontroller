package sangfor

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	sangforEnum "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/sangfor/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	sangforPort "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/sangfor"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/netxops/utils/network"
)

var _ api.Adapter = &SangforAdapter{}

type SangforAdapter struct {
	Type       api.AdapterType
	DeviceType string
	info       *session.DeviceBaseInfo
	token      string
	sessid     string
	namespace  string
	httpClient *http.Client
	current    string
	// zoneMap 缓存接口名称到 zone 名称的映射
	zoneMap map[string]string
}

func NewSangforAdapter(info *session.DeviceBaseInfo, config string) *SangforAdapter {
	if info == nil || info.Host == "" {
		return &SangforAdapter{
			Type:       api.StringAdapter,
			DeviceType: "Sangfor",
			current:    config,
		}
	}

	// 创建HTTP客户端
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{Transport: tr}

	adapter := &SangforAdapter{
		Type:       api.LiveAdapter,
		DeviceType: "Sangfor",
		info:       info,
		httpClient: httpClient,
	}

	// 如果提供了token，直接使用
	if info.Token != "" {
		adapter.token = info.Token
	}

	return adapter
}

// CreateClient 创建HTTP客户端并执行登录
func (sa *SangforAdapter) CreateClient() error {
	if sa.httpClient == nil {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		sa.httpClient = &http.Client{Transport: tr}
	}

	// 如果已经有token，不需要重新登录
	if sa.token != "" {
		return nil
	}

	// 执行登录
	loginURL := fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/login", sa.info.Host)
	loginData := map[string]string{
		"name":     sa.info.Username,
		"password": sa.info.Password,
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return fmt.Errorf("marshal login data: %w", err)
	}

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := sa.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var loginResp map[string]interface{}
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	// 提取token和namespace
	if code, ok := loginResp["code"].(float64); ok && code == 0 {
		if data, ok := loginResp["data"].(map[string]interface{}); ok {
			if loginResult, ok := data["loginResult"].(map[string]interface{}); ok {
				if token, ok := loginResult["token"].(string); ok {
					sa.token = token
				}
			}
			if namespace, ok := data["namespace"].(string); ok {
				sa.namespace = namespace
			}
		}

		// 从Cookie中提取SESSID
		if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
			for _, cookie := range cookies {
				if strings.HasPrefix(cookie, "SESSID=") {
					sessid := strings.TrimPrefix(cookie, "SESSID=")
					if idx := strings.Index(sessid, ";"); idx > 0 {
						sa.sessid = sessid[:idx]
					} else {
						sa.sessid = sessid
					}
					break
				}
			}
		}
	}

	if sa.token == "" {
		return errors.New("login failed: token is empty")
	}

	return nil
}

// GetResponseByApi 通过API获取响应
func (sa *SangforAdapter) GetResponseByApi(apiPath sangforEnum.ApiPath) (map[string]interface{}, error) {
	if err := sa.CreateClient(); err != nil {
		return nil, err
	}

	namespace := sa.namespace
	if namespace == "" {
		namespace = "@namespace"
	}

	// 替换URL中的@namespace
	urlPath := string(apiPath)
	urlPath = strings.ReplaceAll(urlPath, "@namespace", namespace)

	apiURL := fmt.Sprintf("https://%s%s", sa.info.Host, urlPath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// 设置Cookie认证
	cookieValue := ""
	if sa.token != "" {
		cookieValue = fmt.Sprintf("token=%s", sa.token)
	}
	if sa.sessid != "" {
		if cookieValue != "" {
			cookieValue += "; SESSID=" + sa.sessid
		} else {
			cookieValue = fmt.Sprintf("SESSID=%s", sa.sessid)
		}
	}
	if cookieValue != "" {
		req.Header.Set("Cookie", cookieValue)
	}

	resp, err := sa.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return result, nil
}

func (sa *SangforAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	// 通过 SystemVersion API 获取系统版本信息
	versionMap, err := sa.GetResponseByApi(sangforEnum.SystemVersion)
	if err != nil {
		// 如果获取版本信息失败，返回基本信息
		return &device.DeviceBaseInfo{
			Hostname: sa.info.Host,
			Version:  "Unknown",
			Model:    "Sangfor Firewall",
			SN:       "",
		}, nil
	}

	// 解析版本信息
	info := &device.DeviceBaseInfo{
		Hostname: sa.info.Host,
		Model:    "Sangfor Firewall",
		SN:       "",
	}

	// 检查响应码
	if code, ok := versionMap["code"].(float64); ok && code == 0 {
		if data, ok := versionMap["data"].(map[string]interface{}); ok {
			// 获取完整版本号
			if full, ok := data["full"].(string); ok && full != "" {
				info.Version = full
			} else {
				// 如果没有完整版本号，尝试组合版本号
				var versionParts []string
				if major, ok := data["major"].(float64); ok {
					versionParts = append(versionParts, fmt.Sprintf("%.0f", major))
				}
				if minor, ok := data["minor"].(float64); ok {
					versionParts = append(versionParts, fmt.Sprintf("%.0f", minor))
				}
				if increase, ok := data["increase"].(float64); ok {
					versionParts = append(versionParts, fmt.Sprintf("%.0f", increase))
				}
				if len(versionParts) > 0 {
					info.Version = strings.Join(versionParts, ".")
				} else {
					info.Version = "Unknown"
				}
			}

			// 获取构建日期
			if build, ok := data["build"].(string); ok && build != "" {
				// 可以将构建日期添加到版本信息中
				if info.Version != "Unknown" {
					info.Version = fmt.Sprintf("%s (%s)", info.Version, build)
				}
			}
		}
	} else {
		// 如果响应码不为0，返回默认值
		info.Version = "Unknown"
	}

	return info, nil
}

func (sa *SangforAdapter) TaskId() uint {
	return 1
}

func (sa *SangforAdapter) GetConfig(force bool) interface{} {
	// Sangfor 使用 HTTP API，没有类似 FortiGate 的完整配置文本
	// 这里返回一个 JSON 格式的配置摘要，包含主要配置信息
	config := make(map[string]interface{})

	// 获取接口配置
	if interfaceMap, err := sa.GetResponseByApi(sangforEnum.Interfaces); err == nil {
		if code, ok := interfaceMap["code"].(float64); ok && code == 0 {
			config["interfaces"] = interfaceMap["data"]
		}
	}

	// 获取网络对象配置
	if ipGroupMap, err := sa.GetResponseByApi(sangforEnum.IPGroups); err == nil {
		if code, ok := ipGroupMap["code"].(float64); ok && code == 0 {
			config["ipgroups"] = ipGroupMap["data"]
		}
	}

	// 获取服务配置
	if serviceMap, err := sa.GetResponseByApi(sangforEnum.Services); err == nil {
		if code, ok := serviceMap["code"].(float64); ok && code == 0 {
			config["services"] = serviceMap["data"]
		}
	}

	// 获取策略配置
	if policyMap, err := sa.GetResponseByApi(sangforEnum.Securitys); err == nil {
		if code, ok := policyMap["code"].(float64); ok && code == 0 {
			config["securitys"] = policyMap["data"]
		}
	}

	// 获取区域配置
	if zoneMap, err := sa.GetResponseByApi(sangforEnum.Zones); err == nil {
		if code, ok := zoneMap["code"].(float64); ok && code == 0 {
			config["zones"] = zoneMap["data"]
		}
	}

	// 获取静态路由配置
	if staticRouteMap, err := sa.GetResponseByApi(sangforEnum.StaticRoutes); err == nil {
		if code, ok := staticRouteMap["code"].(float64); ok && code == 0 {
			config["staticroutes"] = staticRouteMap["data"]
		}
	}

	// 获取NAT配置
	if natMap, err := sa.GetResponseByApi(sangforEnum.NATs); err == nil {
		if code, ok := natMap["code"].(float64); ok && code == 0 {
			config["nats"] = natMap["data"]
		}
	}

	// 将配置转换为 JSON 字符串
	configJSON, err := json.Marshal(config)
	if err != nil {
		return ""
	}

	return string(configJSON)
}

func (sa *SangforAdapter) PortList(force bool) []api.Port {
	// 如果 zoneMap 为空或强制刷新，先获取 zone 信息
	if sa.zoneMap == nil || force {
		sa.loadZoneMap()
	}

	// 获取接口列表
	interfaceMap, err := sa.GetResponseByApi(sangforEnum.Interfaces)
	if err != nil {
		return nil
	}

	// 解析接口数据
	var portList []api.Port
	if data, ok := interfaceMap["data"].(map[string]interface{}); ok {
		if items, ok := data["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					port := sa.parseInterface(itemMap)
					if port != nil {
						portList = append(portList, port)
					}
				}
			}
		}
	}

	return portList
}

// loadZoneMap 从 Zones API 加载接口名称到 zone 名称的映射
func (sa *SangforAdapter) loadZoneMap() {
	sa.zoneMap = make(map[string]string)

	// 获取 zone 列表
	zoneMap, err := sa.GetResponseByApi(sangforEnum.Zones)
	if err != nil {
		return
	}

	// 检查响应码
	if code, ok := zoneMap["code"].(float64); !ok || code != 0 {
		return
	}

	// 解析 zone 数据
	if data, ok := zoneMap["data"].(map[string]interface{}); ok {
		if items, ok := data["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					// 获取 zone 名称
					zoneName, ok := itemMap["name"].(string)
					if !ok || zoneName == "" {
						continue
					}

					// 获取该 zone 下的接口列表
					// 注意：Sangfor API 中 interfaces 字段可能是字符串数组或对象数组
					interfacesValue, ok := itemMap["interfaces"]
					if !ok {
						continue
					}

					// 尝试不同的解析方式
					var interfaceNames []string

					// 方式1: 字符串数组
					if strList, ok := interfacesValue.([]string); ok {
						interfaceNames = strList
					} else if ifList, ok := interfacesValue.([]interface{}); ok {
						// 方式2: interface{} 数组，元素为字符串或对象
						for _, item := range ifList {
							if str, ok := item.(string); ok && str != "" {
								interfaceNames = append(interfaceNames, str)
							} else if obj, ok := item.(map[string]interface{}); ok {
								// 如果是对象，尝试提取 name 字段
								if name, ok := obj["name"].(string); ok && name != "" {
									interfaceNames = append(interfaceNames, name)
								} else if ifName, ok := obj["ifName"].(string); ok && ifName != "" {
									interfaceNames = append(interfaceNames, ifName)
								}
							}
						}
					} else if str, ok := interfacesValue.(string); ok && str != "" {
						// 方式3: 单个字符串
						interfaceNames = []string{str}
					}

					if len(interfaceNames) > 0 {
						for _, ifName := range interfaceNames {
							sa.zoneMap[ifName] = zoneName
						}
					}
				}
			}
		}
	}
}

// getMapKeys 辅助函数：获取 map 的所有键（用于调试）
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (sa *SangforAdapter) parseInterface(itemMap map[string]interface{}) api.Port {
	// 获取接口名称
	name, ok := itemMap["name"].(string)
	if !ok || name == "" {
		return nil
	}

	// 获取接口类型和模式
	ifType, _ := itemMap["ifType"].(string)
	ifMode, _ := itemMap["ifMode"].(string)

	// 只处理路由模式的接口（三层接口）
	if ifMode != "ROUTE" && ifType != "LOOPBACK" {
		// 跳过非路由模式的接口（二层接口）
		return nil
	}

	// 创建IP地址映射
	ipMap := map[network.IPFamily][]string{
		network.IPv4: []string{},
		network.IPv6: []string{},
	}

	// 解析IPv4地址
	if ipv4Data, ok := itemMap["ipv4"].(map[string]interface{}); ok {
		if ipv4Mode, ok := ipv4Data["ipv4Mode"].(string); ok && ipv4Mode == "STATIC" {
			if staticIpList, ok := ipv4Data["staticIp"].([]interface{}); ok {
				for _, staticIpItem := range staticIpList {
					if staticIpMap, ok := staticIpItem.(map[string]interface{}); ok {
						if ipaddress, ok := staticIpMap["ipaddress"].(map[string]interface{}); ok {
							start, _ := ipaddress["start"].(string)
							if start != "" {
								// 获取掩码位数
								var bits int = 32 // 默认32位掩码
								if bitsVal, ok := ipaddress["bits"]; ok {
									switch v := bitsVal.(type) {
									case float64:
										bits = int(v)
									case int:
										bits = v
									case int64:
										bits = int(v)
									}
								}
								// 构建IP地址字符串：start/bits
								ipStr := fmt.Sprintf("%s/%d", start, bits)
								ipMap[network.IPv4] = append(ipMap[network.IPv4], ipStr)
							}
						}
					}
				}
			}
		}
	}

	// 解析IPv6地址
	if ipv6Data, ok := itemMap["ipv6"].(map[string]interface{}); ok {
		if ipv6Mode, ok := ipv6Data["ipv6Mode"].(string); ok && (ipv6Mode == "STATIC" || ipv6Mode == "DHCP6") {
			if staticIpList, ok := ipv6Data["staticIp"].([]interface{}); ok {
				for _, staticIpItem := range staticIpList {
					if staticIpMap, ok := staticIpItem.(map[string]interface{}); ok {
						start, _ := staticIpMap["start"].(string)
						if start != "" {
							// 获取掩码位数
							var bits int = 64 // 默认64位掩码（IPv6）
							if bitsVal, ok := staticIpMap["bits"]; ok {
								switch v := bitsVal.(type) {
								case float64:
									bits = int(v)
								case int:
									bits = v
								case int64:
									bits = int(v)
								}
							}
							// 构建IPv6地址字符串：start/bits
							ipStr := fmt.Sprintf("%s/%d", start, bits)
							ipMap[network.IPv6] = append(ipMap[network.IPv6], ipStr)
						}
					}
				}
			}
		}
	}

	// 如果没有IP地址，跳过该接口
	if len(ipMap[network.IPv4]) == 0 && len(ipMap[network.IPv6]) == 0 {
		return nil
	}

	// 创建Port对象 - 使用 SangforPort 而不是 NodePort
	port := sangforPort.NewSangforPort(name, "", ipMap, []api.Member{})

	// 设置别名（如果有描述）
	if description, ok := itemMap["description"].(string); ok && description != "" {
		port.WithAliasName(description)
	}

	// 设置VRF（默认使用DefaultVrf）
	port.WithVrf(enum.DefaultVrf)

	// 设置主IPv4地址（第一个IPv4地址）
	if len(ipMap[network.IPv4]) > 0 {
		port.PrimaryIpv4 = ipMap[network.IPv4][0]
	}

	// 设置主IPv6地址（第一个IPv6地址）
	if len(ipMap[network.IPv6]) > 0 {
		port.PrimaryIpv6 = ipMap[network.IPv6][0]
	}

	// 设置UUID（如果有）
	if uuid, ok := itemMap["uuid"].(string); ok && uuid != "" {
		port.WithID(uuid)
	}

	// 设置状态（根据shutdown字段）
	if shutdown, ok := itemMap["shutdown"].(bool); ok {
		if shutdown {
			port.WithStatus("DOWN")
		} else {
			port.WithStatus("UP")
		}
	}

	// 设置 zone（如果有 zone 信息）
	// 优先级：
	// 1. 接口数据中的 zone 或 zoneName 字段（如果存在）
	// 2. 从 zoneMap 中查找（通过接口名称匹配）
	if zone, ok := itemMap["zone"].(string); ok && zone != "" {
		port.WithZone(zone)
	} else if zoneName, ok := itemMap["zoneName"].(string); ok && zoneName != "" {
		port.WithZone(zoneName)
	} else if sa.zoneMap != nil {
		// 从 zoneMap 中查找该接口对应的 zone
		if zoneName, found := sa.zoneMap[name]; found && zoneName != "" {
			port.WithZone(zoneName)
		}
	}

	return port
}

func (sa *SangforAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	ipv4TableMap = make(map[string]*network.AddressTable)
	ipv6TableMap = make(map[string]*network.AddressTable)

	// 解析IPv4路由
	ipv4Table := sa.parseIpv4Routes()
	if ipv4Table != nil {
		ipv4TableMap[enum.DefaultVrf] = ipv4Table
	}

	// 解析IPv6路由
	ipv6Table := sa.parseIpv6Routes()
	if ipv6Table != nil {
		ipv6TableMap[enum.DefaultVrf] = ipv6Table
	}

	return ipv4TableMap, ipv6TableMap
}

// parseIpv4Routes 解析IPv4路由表
func (sa *SangforAdapter) parseIpv4Routes() *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv4)

	// 构建API路径
	namespace := sa.namespace
	if namespace == "" {
		namespace = "@namespace"
	}
	apiPath := fmt.Sprintf("/api/v1/namespaces/%s/routes/ipv4", namespace)

	// 获取路由数据
	routeMap, err := sa.GetResponseByApi(sangforEnum.ApiPath(apiPath))
	if err != nil {
		return routeTable
	}

	// 检查响应码
	if code, ok := routeMap["code"].(float64); !ok || code != 0 {
		return routeTable
	}

	// 解析数据
	if data, ok := routeMap["data"].(map[string]interface{}); ok {
		if items, ok := data["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					sa.parseRouteItem(routeTable, itemMap, network.IPv4)
				}
			}
		}
	}

	return routeTable
}

// parseIpv6Routes 解析IPv6路由表
func (sa *SangforAdapter) parseIpv6Routes() *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv6)

	// 构建API路径
	namespace := sa.namespace
	if namespace == "" {
		namespace = "@namespace"
	}
	apiPath := fmt.Sprintf("/api/v1/namespaces/%s/routes/ipv6", namespace)

	// 获取路由数据
	routeMap, err := sa.GetResponseByApi(sangforEnum.ApiPath(apiPath))
	if err != nil {
		return routeTable
	}

	// 检查响应码
	if code, ok := routeMap["code"].(float64); !ok || code != 0 {
		return routeTable
	}

	// 解析数据
	if data, ok := routeMap["data"].(map[string]interface{}); ok {
		if items, ok := data["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					sa.parseRouteItem(routeTable, itemMap, network.IPv6)
				}
			}
		}
	}

	return routeTable
}

// parseRouteItem 解析单个路由项
func (sa *SangforAdapter) parseRouteItem(routeTable *network.AddressTable, itemMap map[string]interface{}, ipFamily network.IPFamily) {
	// 获取前缀
	prefix, ok := itemMap["prefix"].(string)
	if !ok || prefix == "" {
		return
	}

	// 解析网络地址
	net, err := network.ParseIPNet(prefix)
	if err != nil {
		return
	}

	// 创建下一跳
	nextHop := &network.NextHop{}

	// 获取网关列表
	if gatewayList, ok := itemMap["gateway"].([]interface{}); ok {
		// 获取接口列表
		var ifNameList []string
		if ifNameListInterface, ok := itemMap["ifname"].([]interface{}); ok {
			for _, ifName := range ifNameListInterface {
				if ifNameStr, ok := ifName.(string); ok {
					ifNameList = append(ifNameList, ifNameStr)
				}
			}
		}

		// 处理每个网关
		for i, gateway := range gatewayList {
			gatewayStr, ok := gateway.(string)
			if !ok || gatewayStr == "" {
				continue
			}

			// 获取对应的接口名称
			var ifName string
			if i < len(ifNameList) {
				ifName = ifNameList[i]
			}

			// 判断是否为直连路由（网关为空或为0.0.0.0/::）
			isDirect := gatewayStr == "" || gatewayStr == "0.0.0.0" || gatewayStr == "::"

			// 添加下一跳
			_, _ = nextHop.AddHop(ifName, gatewayStr, isDirect, false, nil)
		}
	} else {
		// 如果没有网关，可能是直连路由
		// 获取接口列表
		if ifNameListInterface, ok := itemMap["ifname"].([]interface{}); ok {
			for _, ifName := range ifNameListInterface {
				if ifNameStr, ok := ifName.(string); ok && ifNameStr != "" {
					_, _ = nextHop.AddHop(ifNameStr, "", true, false, nil)
				}
			}
		}
	}

	// 添加路由到路由表
	if err = routeTable.PushRoute(net, nextHop); err != nil {
		// 忽略错误，继续处理下一条路由
	}
}

func (sa *SangforAdapter) ParseName(force bool) string {
	info, _ := sa.Info(force)
	return info.Hostname
}

func (sa *SangforAdapter) BatchRun(p interface{}) (interface{}, error) {
	// 批量执行命令
	// Sangfor 使用 HTTP API，这里需要根据实际情况实现
	return p, nil
}

func (sa *SangforAdapter) BatchConfig(p ...interface{}) (interface{}, error) {
	// 批量配置
	// Sangfor 使用 HTTP API，这里需要根据实际情况实现
	return nil, nil
}

func (sa *SangforAdapter) AttachChannel(out chan string) bool {
	return false
}

func (sa *SangforAdapter) GetRawConfig(apiPath string, force bool) (any, error) {
	// 获取原始配置
	responseData, err := sa.GetResponseByApi(sangforEnum.ApiPath(apiPath))
	if err != nil {
		return nil, err
	}
	return responseData, nil
}
