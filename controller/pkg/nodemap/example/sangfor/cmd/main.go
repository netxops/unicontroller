package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/auth"
	interface_ "github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/interface"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/nat"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/network"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/pbr"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/policy"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/route"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/service"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/staticroute"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/example/sangfor/zone"
)

// saveJSON 将 API 响应保存为 JSON 文件
func saveJSON(data interface{}, filePath string) error {
	// 确保目录存在
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 序列化为 JSON
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Errorf("JSON 序列化失败: %v", err)
	}

	// 写入文件
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	fmt.Printf("  ✓ JSON 已保存到: %s\n", filePath)
	return nil
}

func main() {
	// 目标地址
	host := "192.168.100.107"
	username := "admin"
	password := "yaan@123"

	// 创建认证客户端
	authClient := auth.NewClient(host)

	// 执行登录
	fmt.Println("=== 深信服防火墙登录 ===")
	fmt.Printf("目标地址: %s\n", host)
	fmt.Printf("用户名: %s\n", username)
	fmt.Println("---")

	loginResp, err := authClient.Login(username, password)
	if err != nil {
		log.Fatalf("登录失败: %v", err)
	}

	// 打印响应信息
	fmt.Printf("响应码: %d\n", loginResp.Code)
	fmt.Printf("响应消息: %s\n", loginResp.Message)

	if !loginResp.IsSuccess() {
		fmt.Printf("⚠⚠⚠ 登录失败\n")
		fmt.Printf("错误码: %d, 错误消息: %s\n", loginResp.Code, loginResp.Message)
		return
	}

	fmt.Println("---")
	fmt.Printf("✓✓✓ 登录成功！\n")
	fmt.Printf("Token: %s\n", loginResp.GetToken())
	if loginResp.GetSESSID() != "" {
		fmt.Printf("SESSID: %s\n", loginResp.GetSESSID())
	}
	if loginResp.Data.Name != "" {
		fmt.Printf("用户名: %s\n", loginResp.Data.Name)
	}
	if loginResp.Data.Role != "" {
		fmt.Printf("角色: %s\n", loginResp.Data.Role)
	}
	if loginResp.Data.Namespace != "" {
		fmt.Printf("命名空间: %s\n", loginResp.Data.Namespace)
	}
	fmt.Println("---")

	// 创建HTTP客户端用于后续API调用
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	httpClient := &http.Client{Transport: tr}

	// 创建网络对象客户端
	ipGroupClient := network.NewClient(host, loginResp.GetToken(), loginResp.GetSESSID(), httpClient)

	// 示例1: 获取所有网络对象（默认查询）
	fmt.Println("\n=== 示例1: 获取所有网络对象（默认查询） ===")
	req1 := &network.GetNetObjsRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp1, err := ipGroupClient.GetNetObjs(req1)
	if err != nil {
		log.Printf("获取网络对象失败: %v", err)
	} else {
		if resp1.IsSuccess() {
			fmt.Printf("✓ 成功获取网络对象\n")
			fmt.Printf("  总数: %d\n", resp1.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp1.Data.PageNumber, resp1.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp1.Data.ItemLength)
			fmt.Printf("  网络对象列表:\n")
			for i, item := range resp1.Data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(resp1.Data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s (UUID: %s, 类型: %s)\n", i+1, item.Name, item.UUID, item.BusinessType)
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
			}
			// 保存 JSON
			if err := saveJSON(resp1, "network/network_api.json"); err != nil {
				log.Printf("保存网络对象 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp1.Code, resp1.Message)
		}
	}

	// 示例2: 按条件查询网络对象
	fmt.Println("\n=== 示例2: 按条件查询网络对象 ===")
	req2 := &network.GetNetObjsRequest{
		AddressType:  network.AddressTypeIPv4, // 只查询IPv4
		BusinessType: network.BusinessTypeIP,  // 只查询IP类型
		Important:    network.ImportantAll,    // 不过滤重要级别
		Length:       50,                      // 最多返回50条
		Start:        0,                       // 从第0条开始
		Order:        network.OrderDesc,       // 降序排列
	}
	resp2, err := ipGroupClient.GetNetObjs(req2)
	if err != nil {
		log.Printf("按条件查询网络对象失败: %v", err)
	} else {
		if resp2.IsSuccess() {
			fmt.Printf("✓ 成功查询网络对象\n")
			fmt.Printf("  总数: %d\n", resp2.Data.TotalItems)
			fmt.Printf("  返回数量: %d\n", resp2.Data.ItemLength)
		} else {
			fmt.Printf("⚠ 查询失败: code=%d, message=%s\n", resp2.Code, resp2.Message)
		}
	}

	// 示例3: 搜索网络对象
	fmt.Println("\n=== 示例3: 搜索网络对象 ===")
	req3 := &network.GetNetObjsRequest{
		Search: "私有", // 搜索包含"私有"的网络对象
		Length: 20,
		Start:  0,
	}
	resp3, err := ipGroupClient.GetNetObjs(req3)
	if err != nil {
		log.Printf("搜索网络对象失败: %v", err)
	} else {
		if resp3.IsSuccess() {
			fmt.Printf("✓ 搜索成功\n")
			fmt.Printf("  找到: %d 个匹配的网络对象\n", resp3.Data.TotalItems)
			for i, item := range resp3.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s\n", i+1, item.Name)
			}
		} else {
			fmt.Printf("⚠ 搜索失败: code=%d, message=%s\n", resp3.Code, resp3.Message)
		}
	}

	// 创建服务客户端
	serviceClient := service.NewClient(host, loginResp.GetToken(), loginResp.GetSESSID(), httpClient)

	// 示例4: 获取所有服务（默认查询）
	fmt.Println("\n=== 示例4: 获取所有服务（默认查询） ===")
	req4 := &service.GetServicesRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp4, err := serviceClient.GetServices(req4)
	if err != nil {
		log.Printf("获取服务失败: %v", err)
	} else {
		if resp4.IsSuccess() {
			fmt.Printf("✓ 成功获取服务\n")
			fmt.Printf("  总数: %d\n", resp4.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp4.Data.PageNumber, resp4.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp4.Data.ItemLength)
			fmt.Printf("  服务列表:\n")
			for i, item := range resp4.Data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(resp4.Data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s (UUID: %s, 类型: %s)\n", i+1, item.Name, item.UUID, item.ServType)
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
			}
			// 保存 JSON
			if err := saveJSON(resp4, "service/service_api.json"); err != nil {
				log.Printf("保存服务 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp4.Code, resp4.Message)
		}
	}

	// 示例5: 获取自定义服务
	fmt.Println("\n=== 示例5: 获取自定义服务 ===")
	req5 := &service.GetServicesRequest{
		ServType: service.ServTypeUsrdefServ, // 只查询自定义服务
		Length:   50,                         // 最多返回50条
		Start:    0,                          // 从第0条开始
		Order:    service.OrderDesc,          // 降序排列
	}
	resp5, err := serviceClient.GetServices(req5)
	if err != nil {
		log.Printf("获取自定义服务失败: %v", err)
	} else {
		if resp5.IsSuccess() {
			fmt.Printf("✓ 成功获取自定义服务\n")
			fmt.Printf("  总数: %d\n", resp5.Data.TotalItems)
			fmt.Printf("  返回数量: %d\n", resp5.Data.ItemLength)
			for i, item := range resp5.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s\n", i+1, item.Name)
				// 显示TCP条目信息
				if len(item.TCPEntrys) > 0 {
					fmt.Printf("        TCP条目数: %d\n", len(item.TCPEntrys))
					for j, tcpEntry := range item.TCPEntrys {
						if j >= 1 { // 只显示第一个TCP条目
							break
						}
						if len(tcpEntry.DstPorts) > 0 {
							port := tcpEntry.DstPorts[0]
							if port.End > 0 {
								fmt.Printf("        目的端口: %d-%d\n", port.Start, port.End)
							} else {
								fmt.Printf("        目的端口: %d\n", port.Start)
							}
						}
					}
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp5.Code, resp5.Message)
		}
	}

	// 示例6: 搜索服务
	fmt.Println("\n=== 示例6: 搜索服务 ===")
	req6 := &service.GetServicesRequest{
		Search: "test", // 搜索包含"test"的服务
		Length: 20,
		Start:  0,
	}
	resp6, err := serviceClient.GetServices(req6)
	if err != nil {
		log.Printf("搜索服务失败: %v", err)
	} else {
		if resp6.IsSuccess() {
			fmt.Printf("✓ 搜索成功\n")
			fmt.Printf("  找到: %d 个匹配的服务\n", resp6.Data.TotalItems)
			for i, item := range resp6.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (类型: %s)\n", i+1, item.Name, item.ServType)
			}
		} else {
			fmt.Printf("⚠ 搜索失败: code=%d, message=%s\n", resp6.Code, resp6.Message)
		}
	}

	// 创建NAT策略客户端
	natClient := nat.NewClient(host, loginResp.GetToken(), loginResp.GetSESSID(), httpClient)

	// 示例7: 获取所有NAT策略（默认查询）
	fmt.Println("\n=== 示例7: 获取所有NAT策略（默认查询） ===")
	req7 := &nat.GetNatsRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp7, err := natClient.GetNats(req7)
	if err != nil {
		log.Printf("获取NAT策略失败: %v", err)
	} else {
		if resp7.IsSuccess() {
			fmt.Printf("✓ 成功获取NAT策略\n")
			fmt.Printf("  总数: %d\n", resp7.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp7.Data.PageNumber, resp7.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp7.Data.ItemLength)
			fmt.Printf("  NAT策略列表:\n")
			for i, item := range resp7.Data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(resp7.Data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s (UUID: %s, 类型: %s, 启用: %v)\n", i+1, item.Name, item.UUID, item.NATType, item.Enable)
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
				if item.NATHit > 0 {
					fmt.Printf("        匹配次数: %d\n", item.NATHit)
				}
			}
			// 保存 JSON
			if err := saveJSON(resp7, "nat/nat_api.json"); err != nil {
				log.Printf("保存NAT策略 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp7.Code, resp7.Message)
		}
	}

	// 示例8: 获取SNAT策略
	fmt.Println("\n=== 示例8: 获取SNAT策略 ===")
	req8 := &nat.GetNatsRequest{
		TransType: nat.TransTypeSNAT, // 只查询SNAT类型
		Length:    50,                // 最多返回50条
		Start:     0,                 // 从第0条开始
	}
	resp8, err := natClient.GetNats(req8)
	if err != nil {
		log.Printf("获取SNAT策略失败: %v", err)
	} else {
		if resp8.IsSuccess() {
			fmt.Printf("✓ 成功获取SNAT策略\n")
			fmt.Printf("  总数: %d\n", resp8.Data.TotalItems)
			fmt.Printf("  返回数量: %d\n", resp8.Data.ItemLength)
			for i, item := range resp8.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s\n", i+1, item.Name)
				if item.SNAT != nil {
					fmt.Printf("        源区域: %v\n", item.SNAT.SrcZones)
					fmt.Printf("        源IP组: %v\n", item.SNAT.SrcIPGroups)
					if item.SNAT.Transfer.TransferType != "" {
						fmt.Printf("        转换类型: %s\n", item.SNAT.Transfer.TransferType)
					}
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp8.Code, resp8.Message)
		}
	}

	// 示例9: 搜索NAT策略
	fmt.Println("\n=== 示例9: 搜索NAT策略 ===")
	req9 := &nat.GetNatsRequest{
		Search: "test", // 搜索包含"test"的NAT策略
		Length: 20,
		Start:  0,
	}
	resp9, err := natClient.GetNats(req9)
	if err != nil {
		log.Printf("搜索NAT策略失败: %v", err)
	} else {
		if resp9.IsSuccess() {
			fmt.Printf("✓ 搜索成功\n")
			fmt.Printf("  搜索关键词: \"test\"\n")
			fmt.Printf("  找到: %d 个匹配的NAT策略\n", resp9.Data.TotalItems)
			if resp9.Data.TotalItems == 0 {
				// 如果搜索结果为0，先检查总共有多少NAT策略
				checkReq := &nat.GetNatsRequest{
					Length: 1, // 只获取1条，用于检查总数
					Start:  0,
				}
				checkResp, checkErr := natClient.GetNats(checkReq)
				if checkErr == nil && checkResp.IsSuccess() {
					fmt.Printf("  提示: 设备上共有 %d 个NAT策略，但搜索\"test\"未找到匹配项\n", checkResp.Data.TotalItems)
					if checkResp.Data.TotalItems > 0 && len(checkResp.Data.Items) > 0 {
						fmt.Printf("  示例策略名称: %s (可尝试搜索策略名称中的关键词)\n", checkResp.Data.Items[0].Name)
					}
				}
			}
			for i, item := range resp9.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (类型: %s, 启用: %v)\n", i+1, item.Name, item.NATType, item.Enable)
			}
		} else {
			fmt.Printf("⚠ 搜索失败: code=%d, message=%s\n", resp9.Code, resp9.Message)
		}
	}

	// 创建安全防护策略客户端
	// 根据API文档，安全防护策略API应使用 @namespace 而不是实际命名空间
	fmt.Printf("\n[调试] 准备查询安全防护策略\n")
	fmt.Printf("[调试] 登录响应中的命名空间: %s\n", loginResp.Data.Namespace)
	fmt.Printf("[调试] 使用API路径: /api/v1/namespaces/@namespace/securitys\n")

	// 使用 @namespace（默认）
	policyClient := policy.NewClient(host, loginResp.GetToken(), loginResp.GetSESSID(), httpClient)

	// 示例10: 获取所有安全防护策略（默认查询）
	fmt.Println("\n=== 示例10: 获取所有安全防护策略（默认查询） ===")
	fmt.Printf("  请求参数: Length=%d, Start=%d\n", 100, 0)
	req10 := &policy.GetSecuritysRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp10, err := policyClient.GetSecuritys(req10)
	if err != nil {
		fmt.Printf("✗ 获取安全防护策略失败: %v\n", err)
		log.Printf("详细错误: %v", err)
		// 尝试打印更多调试信息
		fmt.Printf("  调试: 请检查:\n")
		fmt.Printf("    1. API路径是否正确 (当前使用: /api/v1/namespaces/@namespace/securitys)\n")
		fmt.Printf("    2. Token和SESSID是否有效\n")
		fmt.Printf("    3. 是否为虚拟系统（虚拟系统不支持该API）\n")
	} else {
		if resp10.IsSuccess() {
			fmt.Printf("✓ 成功获取安全防护策略\n")
			fmt.Printf("  响应码: %d\n", resp10.Code)
			fmt.Printf("  响应消息: %s\n", resp10.Message)
			fmt.Printf("  总数: %d\n", resp10.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp10.Data.PageNumber, resp10.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp10.Data.ItemLength)
			if resp10.Data.TotalItems == 0 {
				fmt.Printf("  提示: 设备上当前没有配置安全防护策略\n")
				fmt.Printf("  调试信息: API调用成功(code=0)，但返回的策略数量为0\n")
				fmt.Printf("  可能原因:\n")
				fmt.Printf("    1. 设备上确实没有配置安全防护策略\n")
				fmt.Printf("    2. 权限不足，无法查看策略\n")
				fmt.Printf("    3. 虚拟系统不支持该API（根据API文档说明）\n")

				// 如果使用@namespace没有结果，尝试使用实际命名空间
				if loginResp.Data.Namespace != "" {
					fmt.Printf("\n  尝试使用实际命名空间(%s)查询...\n", loginResp.Data.Namespace)
					policyClient2 := policy.NewClientWithNamespace(host, loginResp.GetToken(), loginResp.GetSESSID(), loginResp.Data.Namespace, httpClient)
					req10_2 := &policy.GetSecuritysRequest{
						Length: 100,
						Start:  0,
					}
					resp10_2, err2 := policyClient2.GetSecuritys(req10_2)
					if err2 == nil && resp10_2.IsSuccess() {
						fmt.Printf("  使用命名空间(%s)查询结果: 总数=%d\n", loginResp.Data.Namespace, resp10_2.Data.TotalItems)
						if resp10_2.Data.TotalItems > 0 {
							fmt.Printf("  ✓ 使用命名空间(%s)找到了策略！\n", loginResp.Data.Namespace)
						}
					}
				}
			} else {
				fmt.Printf("  安全防护策略列表:\n")
				for i, item := range resp10.Data.Items {
					if i >= 5 { // 只显示前5个
						fmt.Printf("    ... 还有 %d 个\n", len(resp10.Data.Items)-5)
						break
					}
					fmt.Printf("    [%d] %s (UUID: %s, 类型: %s, 启用: %v)\n", i+1, item.Name, item.UUID, item.PolicyType, item.Enable)
					if item.Description != "" {
						fmt.Printf("        描述: %s\n", item.Description)
					}
					if len(item.SrcZones) > 0 {
						fmt.Printf("        源区域: %v\n", item.SrcZones)
					}
					if len(item.DstZones) > 0 {
						fmt.Printf("        目的区域: %v\n", item.DstZones)
					}
				}
			}
			// 保存 JSON
			if err := saveJSON(resp10, "policy/policy_api.json"); err != nil {
				log.Printf("保存安全防护策略 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp10.Code, resp10.Message)
			fmt.Printf("  调试信息: API返回了错误码，请检查权限或API路径是否正确\n")
		}
	}

	// 示例11: 获取业务防护策略
	fmt.Println("\n=== 示例11: 获取业务防护策略 ===")
	req11 := &policy.GetSecuritysRequest{
		PolicyType: policy.PolicyTypeServer, // 只查询业务防护策略
		Length:     50,                      // 最多返回50条
		Start:      0,                       // 从第0条开始
	}
	resp11, err := policyClient.GetSecuritys(req11)
	if err != nil {
		log.Printf("获取业务防护策略失败: %v", err)
	} else {
		if resp11.IsSuccess() {
			fmt.Printf("✓ 成功获取业务防护策略\n")
			fmt.Printf("  总数: %d\n", resp11.Data.TotalItems)
			fmt.Printf("  返回数量: %d\n", resp11.Data.ItemLength)
			if resp11.Data.TotalItems == 0 {
				fmt.Printf("  提示: 设备上当前没有配置业务防护策略（PolicyType=SERVER）\n")
			}
			for i, item := range resp11.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s\n", i+1, item.Name)
				if item.Defence.WAF.Enable {
					fmt.Printf("        WAF: 启用 (模板: %s, 动作: %s)\n", item.Defence.WAF.Template, item.Defence.WAF.Action)
				}
				if item.Defence.IPS.Enable {
					fmt.Printf("        IPS: 启用 (模板: %s, 动作: %s)\n", item.Defence.IPS.Template, item.Defence.IPS.Action)
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp11.Code, resp11.Message)
		}
	}

	// 示例12: 按源IP筛选安全防护策略
	fmt.Println("\n=== 示例12: 按源IP筛选安全防护策略 ===")
	req12 := &policy.GetSecuritysRequest{
		SrcIP:  "192.168.1.1", // 筛选源IP
		Length: 20,
		Start:  0,
	}
	resp12, err := policyClient.GetSecuritys(req12)
	if err != nil {
		log.Printf("按源IP筛选安全防护策略失败: %v", err)
	} else {
		if resp12.IsSuccess() {
			fmt.Printf("✓ 筛选成功\n")
			fmt.Printf("  筛选条件: 源IP = %s\n", req12.SrcIP)
			fmt.Printf("  找到: %d 个匹配的安全防护策略\n", resp12.Data.TotalItems)
			if resp12.Data.TotalItems == 0 {
				fmt.Printf("  提示: 没有策略的源地址包含该IP，请检查IP地址是否正确或尝试其他IP\n")
			}
			for i, item := range resp12.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (类型: %s, 启用: %v)\n", i+1, item.Name, item.PolicyType, item.Enable)
			}
		} else {
			fmt.Printf("⚠ 筛选失败: code=%d, message=%s\n", resp12.Code, resp12.Message)
		}
	}

	// 示例13: 搜索安全防护策略
	fmt.Println("\n=== 示例13: 搜索安全防护策略 ===")
	req13 := &policy.GetSecuritysRequest{
		Search: "admin", // 搜索包含"admin"的安全防护策略
		Length: 20,
		Start:  0,
	}
	resp13, err := policyClient.GetSecuritys(req13)
	if err != nil {
		log.Printf("搜索安全防护策略失败: %v", err)
	} else {
		if resp13.IsSuccess() {
			fmt.Printf("✓ 搜索成功\n")
			fmt.Printf("  搜索关键词: \"%s\"\n", req13.Search)
			fmt.Printf("  找到: %d 个匹配的安全防护策略\n", resp13.Data.TotalItems)
			if resp13.Data.TotalItems == 0 {
				// 如果搜索结果为0，先检查总共有多少安全防护策略
				checkReq := &policy.GetSecuritysRequest{
					Length: 1, // 只获取1条，用于检查总数
					Start:  0,
				}
				checkResp, checkErr := policyClient.GetSecuritys(checkReq)
				if checkErr == nil && checkResp.IsSuccess() {
					fmt.Printf("  提示: 设备上共有 %d 个安全防护策略，但搜索\"%s\"未找到匹配项\n", checkResp.Data.TotalItems, req13.Search)
					if checkResp.Data.TotalItems > 0 && len(checkResp.Data.Items) > 0 {
						fmt.Printf("  示例策略名称: %s (可尝试搜索策略名称中的关键词)\n", checkResp.Data.Items[0].Name)
					}
				}
			}
			for i, item := range resp13.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (类型: %s, 启用: %v)\n", i+1, item.Name, item.PolicyType, item.Enable)
				if item.Highlight.Search.Fuzzy != "" {
					fmt.Printf("        高亮位置: %s\n", item.Highlight.Search.Position)
				}
			}
		} else {
			fmt.Printf("⚠ 搜索失败: code=%d, message=%s\n", resp13.Code, resp13.Message)
		}
	}

	// 示例14: 获取所有应用控制策略（默认查询）
	fmt.Println("\n=== 示例14: 获取所有应用控制策略（默认查询） ===")
	req14_app := &policy.GetAppcontrolsRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp14_app, err := policyClient.GetAppcontrols(req14_app)
	if err != nil {
		log.Printf("获取应用控制策略失败: %v", err)
	} else {
		if resp14_app.IsSuccess() {
			fmt.Printf("✓ 成功获取应用控制策略\n")
			fmt.Printf("  总数: %d\n", resp14_app.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp14_app.Data.PageNumber, resp14_app.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp14_app.Data.ItemLength)
			if resp14_app.Data.TotalItems == 0 {
				fmt.Printf("  提示: 设备上当前没有配置应用控制策略\n")
			} else {
				fmt.Printf("  应用控制策略列表:\n")
				for i, item := range resp14_app.Data.Items {
					if i >= 5 { // 只显示前5个
						fmt.Printf("    ... 还有 %d 个\n", len(resp14_app.Data.Items)-5)
						break
					}
					actionText := "拒绝"
					if item.Action == 1 {
						actionText = "允许"
					}
					fmt.Printf("    [%d] %s (UUID: %s, 动作: %s, 启用: %v, 位置: %d)\n", i+1, item.Name, item.UUID, actionText, item.Enable, item.Position)
					if item.ShowName != "" {
						fmt.Printf("        显示名称: %s\n", item.ShowName)
					}
					if item.Description != "" {
						fmt.Printf("        描述: %s\n", item.Description)
					}
					if item.Group != "" {
						fmt.Printf("        策略组: %s\n", item.Group)
					}
					if item.Hits > 0 {
						fmt.Printf("        命中次数: %d\n", item.Hits)
					}
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp14_app.Code, resp14_app.Message)
		}
	}

	// 示例15: 搜索应用控制策略
	fmt.Println("\n=== 示例15: 搜索应用控制策略 ===")
	req15_app := &policy.GetAppcontrolsRequest{
		Search: "test", // 搜索包含"test"的应用控制策略
		Length: 20,
		Start:  0,
	}
	resp15_app, err := policyClient.GetAppcontrols(req15_app)
	if err != nil {
		log.Printf("搜索应用控制策略失败: %v", err)
	} else {
		if resp15_app.IsSuccess() {
			fmt.Printf("✓ 搜索成功\n")
			fmt.Printf("  搜索关键词: \"test\"\n")
			fmt.Printf("  找到: %d 个匹配的应用控制策略\n", resp15_app.Data.TotalItems)
			for i, item := range resp15_app.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				actionText := "拒绝"
				if item.Action == 1 {
					actionText = "允许"
				}
				fmt.Printf("    [%d] %s (动作: %s, 启用: %v)\n", i+1, item.Name, actionText, item.Enable)
			}
		} else {
			fmt.Printf("⚠ 搜索失败: code=%d, message=%s\n", resp15_app.Code, resp15_app.Message)
		}
	}

	// 示例16: 按动作过滤应用控制策略
	fmt.Println("\n=== 示例16: 按动作过滤应用控制策略 ===")
	req16_app := &policy.GetAppcontrolsRequest{
		Action: 1, // 只查询允许的策略
		Length: 50,
		Start:  0,
	}
	resp16_app, err := policyClient.GetAppcontrols(req16_app)
	if err != nil {
		log.Printf("按动作过滤应用控制策略失败: %v", err)
	} else {
		if resp16_app.IsSuccess() {
			fmt.Printf("✓ 过滤成功\n")
			fmt.Printf("  过滤条件: 动作 = 允许\n")
			fmt.Printf("  找到: %d 个匹配的应用控制策略\n", resp16_app.Data.TotalItems)
			for i, item := range resp16_app.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (启用: %v, 位置: %d)\n", i+1, item.Name, item.Enable, item.Position)
			}
		} else {
			fmt.Printf("⚠ 过滤失败: code=%d, message=%s\n", resp16_app.Code, resp16_app.Message)
		}
	}

	// 示例17: 按源IP筛选应用控制策略
	fmt.Println("\n=== 示例17: 按源IP筛选应用控制策略 ===")
	req17_app := &policy.GetAppcontrolsRequest{
		SrcIP:  "192.168.1.1", // 筛选源IP
		Length: 20,
		Start:  0,
	}
	resp17_app, err := policyClient.GetAppcontrols(req17_app)
	if err != nil {
		log.Printf("按源IP筛选应用控制策略失败: %v", err)
	} else {
		if resp17_app.IsSuccess() {
			fmt.Printf("✓ 筛选成功\n")
			fmt.Printf("  筛选条件: 源IP = %s\n", req17_app.SrcIP)
			fmt.Printf("  找到: %d 个匹配的应用控制策略\n", resp17_app.Data.TotalItems)
			if resp17_app.Data.TotalItems == 0 {
				fmt.Printf("  提示: 没有策略的源地址包含该IP，请检查IP地址是否正确或尝试其他IP\n")
			}
			for i, item := range resp17_app.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				actionText := "拒绝"
				if item.Action == 1 {
					actionText = "允许"
				}
				fmt.Printf("    [%d] %s (动作: %s, 启用: %v)\n", i+1, item.Name, actionText, item.Enable)
			}
		} else {
			fmt.Printf("⚠ 筛选失败: code=%d, message=%s\n", resp17_app.Code, resp17_app.Message)
		}
	}

	// 创建区域客户端
	zoneClient := zone.NewClient(host, loginResp.GetToken(), loginResp.GetSESSID(), httpClient)

	// 示例18: 获取所有区域（默认查询）
	fmt.Println("\n=== 示例18: 获取所有区域（默认查询） ===")
	req14 := &zone.GetZonesRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp14, err := zoneClient.GetZones(req14)
	if err != nil {
		log.Printf("获取区域失败: %v", err)
	} else {
		if resp14.IsSuccess() {
			fmt.Printf("✓ 成功获取区域\n")
			fmt.Printf("  总数: %d\n", resp14.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp14.Data.PageNumber, resp14.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp14.Data.ItemLength)
			fmt.Printf("  区域列表:\n")
			for i, item := range resp14.Data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(resp14.Data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s (UUID: %s)\n", i+1, item.Name, item.UUID)
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
				if len(item.Interfaces) > 0 {
					fmt.Printf("        关联接口: %v\n", item.Interfaces)
				}
			}
			// 保存 JSON
			if err := saveJSON(resp14, "zone/zone_api.json"); err != nil {
				log.Printf("保存区域 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp14.Code, resp14.Message)
		}
	}

	// 示例19: 搜索区域
	fmt.Println("\n=== 示例19: 搜索区域 ===")
	req15 := &zone.GetZonesRequest{
		Search: "test", // 搜索包含"test"的区域
		Length: 20,
		Start:  0,
	}
	resp15, err := zoneClient.GetZones(req15)
	if err != nil {
		log.Printf("搜索区域失败: %v", err)
	} else {
		if resp15.IsSuccess() {
			fmt.Printf("✓ 搜索成功\n")
			fmt.Printf("  找到: %d 个匹配的区域\n", resp15.Data.TotalItems)
			for i, item := range resp15.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (启用: %v)\n", i+1, item.Name, item.Enable)
			}
		} else {
			fmt.Printf("⚠ 搜索失败: code=%d, message=%s\n", resp15.Code, resp15.Message)
		}
	}

	// 创建接口客户端（使用实际命名空间）
	interfaceNamespace := "public" // 从登录响应中获取的命名空间
	if loginResp.Data.Namespace != "" {
		interfaceNamespace = loginResp.Data.Namespace
	}
	interfaceClient := interface_.NewClientWithNamespace(host, loginResp.GetToken(), loginResp.GetSESSID(), interfaceNamespace, httpClient)

	// 示例20: 获取所有接口（默认查询）
	fmt.Println("\n=== 示例20: 获取所有接口（默认查询） ===")
	req16 := &interface_.GetInterfacesRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp16, err := interfaceClient.GetInterfaces(req16)
	if err != nil {
		log.Printf("获取接口失败: %v", err)
	} else {
		if resp16.IsSuccess() {
			fmt.Printf("✓ 成功获取接口\n")
			fmt.Printf("  总数: %d\n", resp16.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp16.Data.PageNumber, resp16.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp16.Data.ItemLength)
			fmt.Printf("  接口列表:\n")
			for i, item := range resp16.Data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(resp16.Data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s (UUID: %s, 类型: %s, 模式: %s)\n", i+1, item.Name, item.UUID, item.IfType, item.IfMode)
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
				if item.MAC != "" {
					fmt.Printf("        MAC: %s\n", item.MAC)
				}
				if item.IPv4 != nil && item.IPv4.IPv4Mode != "" {
					fmt.Printf("        IPv4模式: %s\n", item.IPv4.IPv4Mode)
				}
			}
			// 保存 JSON
			if err := saveJSON(resp16, "interface/interface_api.json"); err != nil {
				log.Printf("保存接口 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp16.Code, resp16.Message)
		}
	}

	// 示例21: 获取物理接口
	fmt.Println("\n=== 示例21: 获取物理接口 ===")
	req17 := &interface_.GetInterfacesRequest{
		IfType: interface_.InterfaceTypePhysicalIf, // 过滤物理口
		Length: 50,
		Start:  0,
	}
	resp17, err := interfaceClient.GetInterfaces(req17)
	if err != nil {
		log.Printf("获取物理接口失败: %v", err)
	} else {
		if resp17.IsSuccess() {
			fmt.Printf("✓ 成功获取物理接口\n")
			fmt.Printf("  找到: %d 个物理接口\n", resp17.Data.TotalItems)
			for i, item := range resp17.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (MAC: %s, 启用: %v)\n", i+1, item.Name, item.MAC, !item.Shutdown)
				if item.PhysicalIf != nil && item.PhysicalIf.SpeedDuplex.Speed > 0 {
					fmt.Printf("        速率: %d Mbps, 双工: %s\n", item.PhysicalIf.SpeedDuplex.Speed, item.PhysicalIf.SpeedDuplex.Duplex)
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp17.Code, resp17.Message)
		}
	}

	// 示例22: 获取路由模式的接口
	fmt.Println("\n=== 示例22: 获取路由模式的接口 ===")
	req18 := &interface_.GetInterfacesRequest{
		IfMode: interface_.InterfaceModeRoute, // 过滤路由模式
		Length: 50,
		Start:  0,
	}
	resp18, err := interfaceClient.GetInterfaces(req18)
	if err != nil {
		log.Printf("获取路由模式接口失败: %v", err)
	} else {
		if resp18.IsSuccess() {
			fmt.Printf("✓ 成功获取路由模式接口\n")
			fmt.Printf("  找到: %d 个路由模式接口\n", resp18.Data.TotalItems)
			for i, item := range resp18.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (类型: %s)\n", i+1, item.Name, item.IfType)
				if item.IPv4 != nil && len(item.IPv4.StaticIP) > 0 {
					ip := item.IPv4.StaticIP[0]
					if ip.IPAddress.Start != "" {
						fmt.Printf("        IPv4: %s", ip.IPAddress.Start)
						if ip.IPAddress.End != "" {
							fmt.Printf(" - %s", ip.IPAddress.End)
						}
						if ip.IPAddress.Bits > 0 {
							fmt.Printf(" /%d", ip.IPAddress.Bits)
						}
						fmt.Println()
					}
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp18.Code, resp18.Message)
		}
	}

	// 创建静态路由客户端
	staticRouteClient := staticroute.NewClient(host, loginResp.GetToken(), loginResp.GetSESSID(), httpClient)

	// 示例23: 获取所有IPv4静态路由（默认查询）
	fmt.Println("\n=== 示例23: 获取所有IPv4静态路由（默认查询） ===")
	req19 := &staticroute.GetIPv4StaticRoutesRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp19, err := staticRouteClient.GetIPv4StaticRoutes(req19)
	if err != nil {
		log.Printf("获取IPv4静态路由失败: %v", err)
	} else {
		if resp19.IsSuccess() {
			fmt.Printf("✓ 成功获取IPv4静态路由\n")
			fmt.Printf("  总数: %d\n", resp19.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp19.Data.PageNumber, resp19.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp19.Data.ItemLength)
			fmt.Printf("  静态路由列表:\n")
			for i, item := range resp19.Data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(resp19.Data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s -> %s (UUID: %s, 启用: %v)\n", i+1, item.Prefix, item.Gateway, item.UUID, item.Enable)
				if item.IfName != "" {
					fmt.Printf("        出接口: %s\n", item.IfName)
				}
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
				fmt.Printf("        距离: %d, 权重: %d, 度量值: %d\n", item.Distance, item.Weight, item.Metric)
			}
			// 保存 JSON
			if err := saveJSON(resp19, "staticroute/staticroute_api.json"); err != nil {
				log.Printf("保存静态路由 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp19.Code, resp19.Message)
		}
	}

	// 示例24: 根据前缀搜索静态路由
	fmt.Println("\n=== 示例24: 根据前缀搜索静态路由 ===")
	req20 := &staticroute.GetIPv4StaticRoutesRequest{
		Prefix: "0.0.0.0/0", // 搜索默认路由
		Length: 50,
		Start:  0,
	}
	resp20, err := staticRouteClient.GetIPv4StaticRoutes(req20)
	if err != nil {
		log.Printf("搜索静态路由失败: %v", err)
	} else {
		if resp20.IsSuccess() {
			fmt.Printf("✓ 搜索成功\n")
			fmt.Printf("  找到: %d 个匹配的静态路由\n", resp20.Data.TotalItems)
			for i, item := range resp20.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s -> %s (启用: %v)\n", i+1, item.Prefix, item.Gateway, item.Enable)
				if item.IfName != "" {
					fmt.Printf("        出接口: %s\n", item.IfName)
				}
			}
		} else {
			fmt.Printf("⚠ 搜索失败: code=%d, message=%s\n", resp20.Code, resp20.Message)
		}
	}

	// 示例25: 根据出接口过滤静态路由
	fmt.Println("\n=== 示例25: 根据出接口过滤静态路由 ===")
	req21 := &staticroute.GetIPv4StaticRoutesRequest{
		IfName: "eth0", // 过滤出接口为eth0的路由
		Length: 50,
		Start:  0,
	}
	resp21, err := staticRouteClient.GetIPv4StaticRoutes(req21)
	if err != nil {
		log.Printf("获取接口静态路由失败: %v", err)
	} else {
		if resp21.IsSuccess() {
			fmt.Printf("✓ 成功获取接口静态路由\n")
			fmt.Printf("  找到: %d 个匹配的静态路由\n", resp21.Data.TotalItems)
			for i, item := range resp21.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s -> %s (接口: %s, 启用: %v)\n", i+1, item.Prefix, item.Gateway, item.IfName, item.Enable)
				if item.LinkDTEnable {
					fmt.Printf("        链路探测: %s\n", item.LinkDT)
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp21.Code, resp21.Message)
		}
	}

	// 创建策略路由客户端
	pbrClient := pbr.NewClient(host, loginResp.GetToken(), loginResp.GetSESSID(), httpClient)

	// 示例26: 获取所有IPv4策略路由（默认查询）
	fmt.Println("\n=== 示例26: 获取所有IPv4策略路由（默认查询） ===")
	req22 := &pbr.GetIPv4PBRsRequest{
		Length: 100, // 最多返回100条
		Start:  0,   // 从第0条开始
	}
	resp22, err := pbrClient.GetIPv4PBRs(req22)
	if err != nil {
		log.Printf("获取IPv4策略路由失败: %v", err)
	} else {
		if resp22.IsSuccess() {
			fmt.Printf("✓ 成功获取IPv4策略路由\n")
			fmt.Printf("  总数: %d\n", resp22.Data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", resp22.Data.PageNumber, resp22.Data.TotalPages)
			fmt.Printf("  返回数量: %d\n", resp22.Data.ItemLength)
			fmt.Printf("  策略路由列表:\n")
			for i, item := range resp22.Data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(resp22.Data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s (UUID: %s, 启用: %v, 位置: %d)\n", i+1, item.Name, item.UUID, item.Enable, item.Position)
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
				fmt.Printf("        源区域: %v\n", item.SrcZones)
				fmt.Printf("        源IP组: %v\n", item.SrcIPGroups)
				fmt.Printf("        目的IP组: %v\n", item.DstIPGroups)
				fmt.Printf("        服务: %v\n", item.Services)
				if len(item.OutIf) > 0 {
					fmt.Printf("        出接口:\n")
					for j, outif := range item.OutIf {
						fmt.Printf("          [%d] %s", j+1, outif.OutIfName)
						if outif.Gateway != "" {
							fmt.Printf(" -> %s", outif.Gateway)
						}
						if outif.LinkDT != "" {
							fmt.Printf(" (链路探测: %s)", outif.LinkDT)
						}
						fmt.Println()
					}
				}
			}
			// 保存 JSON
			if err := saveJSON(resp22, "pbr/pbr_api.json"); err != nil {
				log.Printf("保存策略路由 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp22.Code, resp22.Message)
		}
	}

	// 示例27: 搜索策略路由
	fmt.Println("\n=== 示例27: 搜索策略路由 ===")
	req23 := &pbr.GetIPv4PBRsRequest{
		Search: "test", // 搜索包含"test"的策略路由
		Length: 50,
		Start:  0,
	}
	resp23, err := pbrClient.GetIPv4PBRs(req23)
	if err != nil {
		log.Printf("搜索策略路由失败: %v", err)
	} else {
		if resp23.IsSuccess() {
			fmt.Printf("✓ 搜索成功\n")
			fmt.Printf("  找到: %d 个匹配的策略路由\n", resp23.Data.TotalItems)
			for i, item := range resp23.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (启用: %v, 类型: %s)\n", i+1, item.Name, item.Enable, item.PBRType)
				if item.Schedule != "" {
					fmt.Printf("        时间计划: %s\n", item.Schedule)
				}
				if item.LBMethod != "" {
					fmt.Printf("        负载均衡方法: %s\n", item.LBMethod)
				}
			}
		} else {
			fmt.Printf("⚠ 搜索失败: code=%d, message=%s\n", resp23.Code, resp23.Message)
		}
	}

	// 示例28: 移动搜索策略路由
	fmt.Println("\n=== 示例28: 移动搜索策略路由 ===")
	req24 := &pbr.GetIPv4PBRsRequest{
		MoveSearch: "10", // 搜索名称带10以及位置处于10的策略路由
		Length:     50,
		Start:      0,
	}
	resp24, err := pbrClient.GetIPv4PBRs(req24)
	if err != nil {
		log.Printf("移动搜索策略路由失败: %v", err)
	} else {
		if resp24.IsSuccess() {
			fmt.Printf("✓ 移动搜索成功\n")
			fmt.Printf("  找到: %d 个匹配的策略路由\n", resp24.Data.TotalItems)
			for i, item := range resp24.Data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s (位置: %d, 启用: %v)\n", i+1, item.Name, item.Position, item.Enable)
			}
		} else {
			fmt.Printf("⚠ 移动搜索失败: code=%d, message=%s\n", resp24.Code, resp24.Message)
		}
	}

	// 创建路由状态客户端（使用实际命名空间）
	routeNamespace := "public" // 从登录响应中获取的命名空间
	if loginResp.Data.Namespace != "" {
		routeNamespace = loginResp.Data.Namespace
	}
	routeClient := route.NewClientWithNamespace(host, loginResp.GetToken(), loginResp.GetSESSID(), routeNamespace, httpClient)

	// 示例29: 获取所有IPv4路由信息（默认查询）
	fmt.Println("\n=== 示例29: 获取所有IPv4路由信息（默认查询） ===")
	req25 := &route.GetIPv4RoutesRequest{
		RouteType: route.RouteTypeAll, // 获取所有类型的路由
		Length:    100,                // 最多返回100条
		Start:     0,                  // 从第0条开始
	}
	resp25, err := routeClient.GetIPv4Routes(req25)
	if err != nil {
		log.Printf("获取IPv4路由信息失败: %v", err)
	} else {
		if resp25.IsSuccess() {
			data := resp25.GetData()
			fmt.Printf("✓ 成功获取IPv4路由信息\n")
			fmt.Printf("  总数: %d\n", data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", data.PageNumber, data.TotalPages)
			fmt.Printf("  返回数量: %d\n", data.ItemLength)
			fmt.Printf("  路由列表:\n")
			for i, item := range data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s: %s", i+1, item.RouteType, item.Prefix)
				if len(item.Gateway) > 0 && item.Gateway[0] != "0.0.0.0" {
					fmt.Printf(" -> %v", item.Gateway)
				}
				if len(item.IfName) > 0 {
					fmt.Printf(" via %v", item.IfName)
				}
				fmt.Printf(" (状态: %s)\n", item.Status)
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
				fmt.Printf("        度量值: %d, 管理距离: %d\n", item.Metric, item.Distance)
			}
			// 保存 JSON
			if err := saveJSON(resp25, "route/route_api.json"); err != nil {
				log.Printf("保存路由 JSON 失败: %v", err)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp25.Code, resp25.Message)
		}
	}

	// 示例30: 获取静态路由信息
	fmt.Println("\n=== 示例30: 获取静态路由信息 ===")
	req26 := &route.GetIPv4RoutesRequest{
		RouteType: route.RouteTypeStatic, // 只获取静态路由
		Length:    50,
		Start:     0,
	}
	resp26, err := routeClient.GetIPv4Routes(req26)
	if err != nil {
		log.Printf("获取静态路由信息失败: %v", err)
	} else {
		if resp26.IsSuccess() {
			data := resp26.GetData()
			fmt.Printf("✓ 成功获取静态路由信息\n")
			fmt.Printf("  找到: %d 个静态路由\n", data.TotalItems)
			for i, item := range data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s", i+1, item.Prefix)
				if len(item.Gateway) > 0 {
					fmt.Printf(" -> %v", item.Gateway)
				}
				if len(item.IfName) > 0 {
					fmt.Printf(" via %v", item.IfName)
				}
				fmt.Printf(" (状态: %s)\n", item.Status)
				if item.LinkDT != "" {
					fmt.Printf("        链路探测: %s\n", item.LinkDT)
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp26.Code, resp26.Message)
		}
	}

	// 示例31: 获取直连路由信息
	fmt.Println("\n=== 示例31: 获取直连路由信息 ===")
	req27 := &route.GetIPv4RoutesRequest{
		RouteType: route.RouteTypeDirect, // 只获取直连路由
		Length:    50,
		Start:     0,
	}
	resp27, err := routeClient.GetIPv4Routes(req27)
	if err != nil {
		log.Printf("获取直连路由信息失败: %v", err)
	} else {
		if resp27.IsSuccess() {
			data := resp27.GetData()
			fmt.Printf("✓ 成功获取直连路由信息\n")
			fmt.Printf("  找到: %d 个直连路由\n", data.TotalItems)
			for i, item := range data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s", i+1, item.Prefix)
				if len(item.IfName) > 0 {
					fmt.Printf(" via %v", item.IfName)
				}
				fmt.Printf(" (状态: %s)\n", item.Status)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp27.Code, resp27.Message)
		}
	}

	// 示例32: 获取所有IPv6路由信息（默认查询）
	fmt.Println("\n=== 示例32: 获取所有IPv6路由信息（默认查询） ===")
	req28 := &route.GetIPv6RoutesRequest{
		RouteType: route.RouteTypeAll, // 获取所有类型的路由
		Length:    100,                // 最多返回100条
		Start:     0,                  // 从第0条开始
	}
	resp28, err := routeClient.GetIPv6Routes(req28)
	if err != nil {
		log.Printf("获取IPv6路由信息失败: %v", err)
	} else {
		if resp28.IsSuccess() {
			data := resp28.GetData()
			fmt.Printf("✓ 成功获取IPv6路由信息\n")
			fmt.Printf("  总数: %d\n", data.TotalItems)
			fmt.Printf("  当前页: %d/%d\n", data.PageNumber, data.TotalPages)
			fmt.Printf("  返回数量: %d\n", data.ItemLength)
			fmt.Printf("  路由列表:\n")
			for i, item := range data.Items {
				if i >= 5 { // 只显示前5个
					fmt.Printf("    ... 还有 %d 个\n", len(data.Items)-5)
					break
				}
				fmt.Printf("    [%d] %s: %s", i+1, item.RouteType, item.Prefix)
				if len(item.Gateway) > 0 {
					fmt.Printf(" -> %v", item.Gateway)
				}
				if len(item.IfName) > 0 {
					fmt.Printf(" via %v", item.IfName)
				}
				fmt.Printf(" (状态: %s)\n", item.Status)
				if item.Description != "" {
					fmt.Printf("        描述: %s\n", item.Description)
				}
				fmt.Printf("        度量值: %d, 管理距离: %d\n", item.Metric, item.Distance)
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp28.Code, resp28.Message)
		}
	}

	// 示例33: 获取IPv6静态路由信息
	fmt.Println("\n=== 示例33: 获取IPv6静态路由信息 ===")
	req29 := &route.GetIPv6RoutesRequest{
		RouteType: route.RouteTypeStatic, // 只获取静态路由
		Length:    50,
		Start:     0,
	}
	resp29, err := routeClient.GetIPv6Routes(req29)
	if err != nil {
		log.Printf("获取IPv6静态路由信息失败: %v", err)
	} else {
		if resp29.IsSuccess() {
			data := resp29.GetData()
			fmt.Printf("✓ 成功获取IPv6静态路由信息\n")
			fmt.Printf("  找到: %d 个IPv6静态路由\n", data.TotalItems)
			for i, item := range data.Items {
				if i >= 3 { // 只显示前3个
					break
				}
				fmt.Printf("    [%d] %s", i+1, item.Prefix)
				if len(item.Gateway) > 0 {
					fmt.Printf(" -> %v", item.Gateway)
				}
				if len(item.IfName) > 0 {
					fmt.Printf(" via %v", item.IfName)
				}
				fmt.Printf(" (状态: %s)\n", item.Status)
				if item.LinkDTEnable {
					fmt.Printf("        链路探测: %s (启用: %v)\n", item.LinkDT, item.LinkDTEnable)
				}
			}
		} else {
			fmt.Printf("⚠ 获取失败: code=%d, message=%s\n", resp29.Code, resp29.Message)
		}
	}
}
