package main

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti"
	fortiEnum "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/netxops/cli/terminalmode"
	"github.com/redis/go-redis/v9"
)

func initRedis() {
	client := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
		//Password: redisCfg.Password, // no password set
		DB: 0, // use default DB
	})
	global.Redis = client
}

func initxx() {
	//info := &device.DeviceBaseInfo{
	//	Hostname: "Fortigate",
	//	Version:  "abc",
	//	Model:    md,
	//	SN:       serial,
	//}

	fortigateInfo := session.NewDeviceBaseInfo("172.32.1.8", "admin", "admin@123", terminalmode.FortiGate.String(), "", 22)
	fortigateInfo.WithToken("m8tQ97dtqkygGyyHfGg8wzQ3qbQs4n") //m8tQ97dtqkygGyyHfGg8wzQ3qbQs4n  r7Hnnfgym6NqNQmxGHmrxnnf0d1Qdb

	fortigateAdapter := forti.NewFortiAdapter(fortigateInfo, "")
	//routeTable, err := fortigateAdapter.RouteTable(false)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("routeTable--", routeTable)

	//info, err2 := fortigateAdapter.Info(false)
	//if err2 != nil {
	//	return
	//}
	//fmt.Println("info--", info)

	//conf := fortigateAdapter.GetConfig(false)
	//fmt.Println("conf--", conf)

	//interfaceMap := fortigateAdapter.PortList(false)
	//fmt.Println("interfaceMap--", interfaceMap)

	client, _ := fortigateAdapter.CreateClient()
	ipPool, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallObjectIPPool)
	if err != nil {
		return
	}
	fmt.Println("ipPool--->", ipPool)
	vip, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallVip)
	if err != nil {
		return
	}
	fmt.Println("vip--->", vip)
	vipgrp, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallVipGroup)
	if err != nil {
		return
	}
	fmt.Println("vipgrp--->", vipgrp)
	policy, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallPolicy)
	if err != nil {
		return
	}
	fmt.Println("policy--->", policy)

	addresses, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallAddress)
	if err != nil {
		return
	}
	fmt.Println("addresses--->", addresses)

	addresses6, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallAddress6)
	if err != nil {
		return
	}
	fmt.Println("addresses6--->", addresses6)

	addrgrp, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallAddrgrp)
	if err != nil {
		return
	}
	fmt.Println("addrgrp--->", addrgrp)

	addrgrp6, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallAddrgrp6)
	if err != nil {
		return
	}
	fmt.Println("addrgrp6--->", addrgrp6)

	firewallServiceCustoms, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallServiceCustom)
	if err != nil {
		return
	}
	fmt.Println("firewallServiceCustoms--->", firewallServiceCustoms)

	firewallServiceGroups, err := fortigateAdapter.GetResponseByApi(client, fortiEnum.FirewallServiceGroup)
	if err != nil {
		return
	}
	fmt.Println("firewallServiceGroups--->", firewallServiceGroups)
}

func main() {
	initRedis()
	initxx()
}
