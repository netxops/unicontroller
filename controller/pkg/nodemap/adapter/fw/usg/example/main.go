package main

import (
	"context"
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/usg"
	USG "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/usg"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/redis/go-redis/v9"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func initRedisAndLogger() {
	// Initialize Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:6379",
		Password:     "Redis@Passw0rd", // Set password if required
		DB:           0,                // Use default DB
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
		OutputPaths:      []string{"stdout", "./logs/app.log"},
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

func initxx() {
	info := &session.DeviceBaseInfo{
		BaseInfo: terminal.BaseInfo{
			Host:     "172.32.1.224",
			Username: "sshadmin",
			Password: "admin@123",
			Port:     22,
			Telnet:   false,
			Type:     terminalmode.HuaWei,
		},
	}

	usgAdapter := usg.NewUsgAdapter(info, "")
	//routeTable, err := fortigateAdapter.RouteTable(false)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("routeTable--", routeTable)

	deviceInfo, err := usgAdapter.Info(false)
	if err != nil {
		return
	}
	fmt.Println("info--", deviceInfo.Hostname, deviceInfo.Model, deviceInfo.Version)

	lo.ForEach(usgAdapter.PortList(false), func(aport api.Port, _ int) {
		port := aport.(*USG.UsgPort)
		fmt.Printf("  Name: %s\n", port.Name())
		fmt.Printf("  Alias: %s\n", port.AliasName())
		fmt.Printf("  VRF: %s\n", port.Vrf())

		fmt.Println("  IPv4 Addresses:")
		for _, ip := range port.Ipv4List() {
			fmt.Printf("    - %s\n", ip)
		}

		fmt.Println("  IPv6 Addresses:")
		for _, ip := range port.Ipv6List() {
			fmt.Printf("    - %s\n", ip)
		}

		fmt.Println("  Zone:", port.Zone())
	})

	v4, v6 := usgAdapter.RouteTable(true)
	fmt.Println("IPv4 Route Table:")
	for vrf, route := range v4 {
		fmt.Printf("  VRF: %s\n", vrf)
		it := route.Iterator()
		for it.HasNext() {
			net, hop := it.Next()
			fmt.Printf("  %s via %s\n", net, hop)
		}
	}
	fmt.Println("IPv6 Route Table:")
	for vrf, route := range v6 {
		fmt.Printf("  VRF: %s\n", vrf)
		fmt.Println(route.String())
	}

	//conf := fortigateAdapter.GetConfig(false)
	//fmt.Println("conf--", conf)

	//interfaceMap := fortigateAdapter.PortList(false)
	//fmt.Println("interfaceMap--", interfaceMap)

}

// func printPorts(ports interface{}) {
// 	fmt.Println("Detailed Port Information:")
// 	for i, port := range ports {
// 		fmt.Printf("Port %d:\n", i+1)
// 		fmt.Printf("  Name: %s\n", port.Name())
// 		fmt.Printf("  Alias: %s\n", port.AliasName())
// 		fmt.Printf("  VRF: %s\n", port.Vrf())

// 		if dptechPort, ok := port.(*dptech.DptechPort); ok {
// 			fmt.Printf("  Bond Group: %s\n", dptechPort.BondGroup)
// 		}

// 		fmt.Println("  IPv4 Addresses:")
// 		for _, ip := range port.Ipv4() {
// 			fmt.Printf("    - %s\n", ip)
// 		}

// 		fmt.Println("  IPv6 Addresses:")
// 		for _, ip := range port.Ipv6() {
// 			fmt.Printf("    - %s\n", ip)
// 		}

// 		if fwPort, ok := port.(api.FirewallPort); ok {
// 			fmt.Printf("  Main IPv4: %s\n", fwPort.MainIpv4())
// 			fmt.Printf("  Main IPv6: %s\n", fwPort.MainIpv6())
// 		}

// 		fmt.Println("  Members:")
// 		for _, member := range port.Members() {
// 			fmt.Printf("    - %s\n", member.Name())
// 		}

// 		fmt.Println() // Add a blank line between ports for readability
// 	}
// }

func main() {
	initRedisAndLogger()
	initxx()
}
