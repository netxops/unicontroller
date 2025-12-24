package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/sangfor"
	sangforEnum "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/sangfor/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func initRedisAndLogger() {
	// Initialize Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:         "192.168.100.122:6379",
		Password:     "", // Set password if required
		DB:           0,  // Use default DB
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		PoolTimeout:  30 * time.Second,
	})

	// Test Redis connection
	_, err := redisClient.Ping(context.Background()).Result()
	if err != nil {
		fmt.Printf("Failed to connect to Redis: %v\n", err)
		return
	}

	global.Redis = redisClient

	// Initialize Logger
	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.InfoLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding:         "json",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := config.Build()
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		return
	}

	zap.ReplaceGlobals(logger)

	logger.Info("Redis and Logger initialized successfully")
}

func testSangforAdapter() {
	// 创建设备信息
	// 注意：请根据实际情况修改以下参数
	info := session.NewDeviceBaseInfo(
		"192.168.100.107", // 设备IP
		"admin",           // 用户名
		"yaan@123",        // 密码
		"Sangfor",         // 设备类型
		"",                // community
		443,               // 端口（HTTPS）
	)

	// 如果已有token，可以直接设置
	// info.WithToken("your-token-here")

	// 创建 Sangfor adapter
	adapter := sangfor.NewSangforAdapter(info, "")

	fmt.Println("=== 测试 Sangfor Adapter ===")
	fmt.Println()

	// 1. 测试设备信息
	fmt.Println("1. 获取设备信息:")
	deviceInfo, err := adapter.Info(false)
	if err != nil {
		fmt.Printf("   ❌ 获取设备信息失败: %v\n", err)
	} else {
		fmt.Printf("   ✓ 主机名: %s\n", deviceInfo.Hostname)
		fmt.Printf("   ✓ 型号: %s\n", deviceInfo.Model)
		fmt.Printf("   ✓ 版本: %s\n", deviceInfo.Version)
		fmt.Printf("   ✓ 序列号: %s\n", deviceInfo.SN)
	}
	fmt.Println()

	// 2. 测试解析设备名称
	fmt.Println("2. 解析设备名称:")
	name := adapter.ParseName(false)
	fmt.Printf("   ✓ 设备名称: %s\n", name)
	fmt.Println()

	// 3. 测试获取接口列表
	fmt.Println("3. 获取接口列表:")
	ports := adapter.PortList(false)
	if len(ports) == 0 {
		fmt.Println("   ⚠ 未找到接口（可能需要完善 parseInterface 方法）")
	} else {
		fmt.Printf("   ✓ 找到 %d 个接口:\n", len(ports))
		lo.ForEach(ports, func(port api.Port, index int) {
			fmt.Printf("   [%d] 名称: %s, VRF: %s\n", index+1, port.Name(), port.Vrf())
			if len(port.Ipv4List()) > 0 {
				fmt.Printf("        IPv4: %v\n", port.Ipv4List())
			}
			if len(port.Ipv6List()) > 0 {
				fmt.Printf("        IPv6: %v\n", port.Ipv6List())
			}
		})
	}
	fmt.Println()

	// 4. 测试获取路由表
	fmt.Println("4. 获取路由表:")
	ipv4TableMap, ipv6TableMap := adapter.RouteTable(false)
	if len(ipv4TableMap) > 0 {
		fmt.Println("   IPv4 路由表:")
		for vrf, routeTable := range ipv4TableMap {
			fmt.Printf("     VRF: %s\n", vrf)
			it := routeTable.Iterator()
			count := 0
			for it.HasNext() && count < 10 { // 只显示前10条
				net, hop := it.Next()
				fmt.Printf("       %s via %s\n", net, hop)
				count++
			}
			if count >= 10 {
				fmt.Printf("       ... (还有更多路由)\n")
			}
		}
	} else {
		fmt.Println("   ⚠ 未找到 IPv4 路由表（可能需要完善路由解析方法）")
	}

	if len(ipv6TableMap) > 0 {
		fmt.Println("   IPv6 路由表:")
		for vrf, routeTable := range ipv6TableMap {
			fmt.Printf("     VRF: %s\n", vrf)
			it := routeTable.Iterator()
			count := 0
			for it.HasNext() && count < 10 { // 只显示前10条
				net, hop := it.Next()
				fmt.Printf("       %s via %s\n", net, hop)
				count++
			}
			if count >= 10 {
				fmt.Printf("       ... (还有更多路由)\n")
			}
		}
	} else {
		fmt.Println("   ⚠ 未找到 IPv6 路由表（可能需要完善路由解析方法）")
	}
	fmt.Println()

	// 5. 测试获取配置
	fmt.Println("5. 获取配置:")
	config := adapter.GetConfig(false)
	if config != nil {
		fmt.Printf("   ✓ 配置长度: %d 字符\n", len(fmt.Sprintf("%v", config)))
	} else {
		fmt.Println("   ⚠ 配置为空")
	}
	fmt.Println()

	// 6. 测试通过 API 获取数据
	fmt.Println("6. 通过 API 获取数据:")

	// 测试获取系统版本
	fmt.Println("   6.1 获取系统版本 (SystemVersion):")
	systemVersion, err := adapter.GetResponseByApi(sangforEnum.SystemVersion)
	if err != nil {
		fmt.Printf("      ❌ 获取系统版本失败: %v\n", err)
	} else {
		systemVersionJSON, _ := json.MarshalIndent(systemVersion, "      ", "  ")
		fmt.Printf("      ✓ 系统版本数据:\n%s\n", string(systemVersionJSON))
		// 解析并显示版本信息
		if code, ok := systemVersion["code"].(float64); ok && code == 0 {
			if data, ok := systemVersion["data"].(map[string]interface{}); ok {
				if full, ok := data["full"].(string); ok {
					fmt.Printf("      ✓ 完整版本号: %s\n", full)
				}
				if build, ok := data["build"].(string); ok {
					fmt.Printf("      ✓ 构建日期: %s\n", build)
				}
			}
		}
	}

	// 测试获取网络对象
	fmt.Println("   6.2 获取网络对象 (IPGroups):")
	ipGroups, err := adapter.GetResponseByApi(sangforEnum.IPGroups)
	if err != nil {
		fmt.Printf("      ❌ 获取网络对象失败: %v\n", err)
	} else {
		ipGroupsJSON, _ := json.MarshalIndent(ipGroups, "      ", "  ")
		fmt.Printf("      ✓ 网络对象数据:\n%s\n", string(ipGroupsJSON))
	}

	// 测试获取服务
	fmt.Println("   6.3 获取服务 (Services):")
	services, err := adapter.GetResponseByApi(sangforEnum.Services)
	if err != nil {
		fmt.Printf("      ❌ 获取服务失败: %v\n", err)
	} else {
		servicesJSON, _ := json.MarshalIndent(services, "      ", "  ")
		fmt.Printf("      ✓ 服务数据:\n%s\n", string(servicesJSON))
	}

	// 测试获取安全策略
	fmt.Println("   6.4 获取安全策略 (Securitys):")
	securitys, err := adapter.GetResponseByApi(sangforEnum.Securitys)
	if err != nil {
		fmt.Printf("      ❌ 获取安全策略失败: %v\n", err)
	} else {
		securitysJSON, _ := json.MarshalIndent(securitys, "      ", "  ")
		fmt.Printf("      ✓ 安全策略数据:\n%s\n", string(securitysJSON))
	}

	// 测试获取区域
	fmt.Println("   6.5 获取区域 (Zones):")
	zones, err := adapter.GetResponseByApi(sangforEnum.Zones)
	if err != nil {
		fmt.Printf("      ❌ 获取区域失败: %v\n", err)
	} else {
		zonesJSON, _ := json.MarshalIndent(zones, "      ", "  ")
		fmt.Printf("      ✓ 区域数据:\n%s\n", string(zonesJSON))
	}

	// 测试获取接口
	fmt.Println("   6.6 获取接口 (Interfaces):")
	interfaces, err := adapter.GetResponseByApi(sangforEnum.Interfaces)
	if err != nil {
		fmt.Printf("      ❌ 获取接口失败: %v\n", err)
	} else {
		interfacesJSON, _ := json.MarshalIndent(interfaces, "      ", "  ")
		fmt.Printf("      ✓ 接口数据:\n%s\n", string(interfacesJSON))
	}

	// 测试获取静态路由
	fmt.Println("   6.7 获取静态路由 (StaticRoutes):")
	staticRoutes, err := adapter.GetResponseByApi(sangforEnum.StaticRoutes)
	if err != nil {
		fmt.Printf("      ❌ 获取静态路由失败: %v\n", err)
	} else {
		staticRoutesJSON, _ := json.MarshalIndent(staticRoutes, "      ", "  ")
		fmt.Printf("      ✓ 静态路由数据:\n%s\n", string(staticRoutesJSON))
	}

	// 测试获取策略路由
	fmt.Println("   6.8 获取策略路由 (PBRs):")
	pbrs, err := adapter.GetResponseByApi(sangforEnum.PBRs)
	if err != nil {
		fmt.Printf("      ❌ 获取策略路由失败: %v\n", err)
	} else {
		pbrsJSON, _ := json.MarshalIndent(pbrs, "      ", "  ")
		fmt.Printf("      ✓ 策略路由数据:\n%s\n", string(pbrsJSON))
	}

	// 测试获取路由状态
	fmt.Println("   6.9 获取路由状态 (Routes):")
	routes, err := adapter.GetResponseByApi(sangforEnum.Routes)
	if err != nil {
		fmt.Printf("      ❌ 获取路由状态失败: %v\n", err)
	} else {
		routesJSON, _ := json.MarshalIndent(routes, "      ", "  ")
		fmt.Printf("      ✓ 路由状态数据:\n%s\n", string(routesJSON))
	}

	// 测试获取NAT
	fmt.Println("   6.10 获取NAT (NATs):")
	nats, err := adapter.GetResponseByApi(sangforEnum.NATs)
	if err != nil {
		fmt.Printf("      ❌ 获取NAT失败: %v\n", err)
	} else {
		natsJSON, _ := json.MarshalIndent(nats, "      ", "  ")
		fmt.Printf("      ✓ NAT数据:\n%s\n", string(natsJSON))
	}

	fmt.Println("\n=== 测试完成 ===")
}

func main() {
	initRedisAndLogger()
	testSangforAdapter()
}
