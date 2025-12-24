package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	"github.com/influxdata/telegraf/controller/pkg/sdk"
)

// maskPassword 掩码密码用于显示
func maskPassword(password string) string {
	if password == "" {
		return "(empty)"
	}
	if len(password) <= 4 {
		return "****"
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}

var (
	configPath = flag.String("config", "", "Path to agent configuration file")
)

func main() {
	flag.Parse()

	var endpoints []string
	var username, password string

	// 如果提供了配置文件，从配置文件读取etcd配置
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		if cfg.Registry.Enabled && len(cfg.Registry.EtcdEndpoints) > 0 {
			endpoints = cfg.Registry.EtcdEndpoints
			username = cfg.Registry.EtcdUsername
			password = cfg.Registry.EtcdPassword
			fmt.Printf("Loaded config from %s:\n", *configPath)
			fmt.Printf("  Etcd Endpoints: %v\n", endpoints)
			fmt.Printf("  Etcd Username: %s\n", username)
			fmt.Printf("  Etcd Password: %s\n", maskPassword(password))
		} else {
			log.Fatalf("Registry is not enabled or etcd_endpoints is not configured in config file")
		}
	} else {
		// 默认值（向后兼容）
		endpoints = []string{"192.168.100.122:2379"}
		fmt.Println("Warning: No config file provided, using default endpoints without authentication")
	}

	// 创建 ConfigDriver 实例
	base := "agent_config"
	area := "DefaultArea"

	var cd *sdk.ConfigDriver
	if username != "" && password != "" {
		fmt.Println("Using etcd authentication")
		cd = sdk.NewConfigDriverWithAuth(base, area, endpoints, username, password)
	} else {
		fmt.Println("Warning: No etcd authentication configured")
		cd = sdk.NewConfigDriver(base, area, endpoints)
	}

	// 创建一个带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 写入配置
	config := map[string]interface{}{
		"enabled": "true",
	}

	err := cd.PutConfig(ctx, config, "ExampleCode", "uniops-telegraf")
	if err != nil {
		log.Fatalf("Failed to put config: %v", err)
	}
	fmt.Println("Config written successfully")

	// 读取刚刚写入的配置
	// retrievedConfig, err := cd.GetConfig(ctx, "DEV20250303000001", "uniops-telegraf")

	retrievedConfig, err := cd.GetConfig(ctx, "ExampleCode", "uniops-telegraf")
	if err != nil {
		log.Fatalf("Failed to get config: %v", err)
	}
	fmt.Printf("Retrieved config: %+v\n", retrievedConfig)

	// // 更新配置
	// updatedConfig := map[string]interface{}{
	// 	"interval": "10s",
	// 	"outputs": map[string]interface{}{
	// 		"prometheus_client": map[string]interface{}{
	// 			"listen": ":9273",
	// 		},
	// 	},
	// }

	// err = cd.PutConfig(ctx, updatedConfig, "DEV20250303000001", "telegraf")
	// if err != nil {
	// 	log.Fatalf("Failed to update config: %v", err)
	// }
	// fmt.Println("Config updated successfully")

	// // 再次读取更新后的配置
	// retrievedUpdatedConfig, err := cd.GetConfig(ctx, "DEV20250303000001", "telegraf")
	// if err != nil {
	// 	log.Fatalf("Failed to get updated config: %v", err)
	// }
	// fmt.Printf("Retrieved updated config: %+v\n", retrievedUpdatedConfig)

	// 列出所有配置键
	// configKeys, err := cd.ListConfigKeys(ctx, "DEV20250303000001")
	// if err != nil {
	//     log.Fatalf("Failed to list config keys: %v", err)
	// }
	// fmt.Printf("Config keys: %v\n", configKeys)

	// // 删除配置
	// err = cd.DeleteConfig(ctx, "DEV20250303000001", "telegraf")
	// if err != nil {
	//     log.Fatalf("Failed to delete config: %v", err)
	// }
	// fmt.Println("Config deleted successfully")

	// 尝试读取已删除的配置
	// deletedConfig, err := cd.GetConfig(ctx, "DEV20250303000001", "telegraf")
	// if err != nil {
	// 	fmt.Printf("As expected, failed to get deleted config: %v\n", err)
	// } else {
	// 	fmt.Printf("Unexpectedly retrieved deleted config: %+v\n", deletedConfig)
	// }
}
