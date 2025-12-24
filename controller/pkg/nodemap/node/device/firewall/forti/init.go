package forti

import (
	"context"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	fortiEnum "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/enum"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
)

func (fortigate *FortigateNode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
	fortigate.WithNodeType(api.FIREWALL)
	firewallAddress, err := adapter.GetRawConfig(string(fortiEnum.FirewallAddress), false)
	if err != nil {
		fmt.Println("forti address fetch err: ", err)
		return
	}

	firewallAddress6, err := adapter.GetRawConfig(string(fortiEnum.FirewallAddress6), false)
	if err != nil {
		fmt.Println("forti address6 fetch err: ", err)
		return
	}

	firewallAddrgrp, err := adapter.GetRawConfig(string(fortiEnum.FirewallAddrgrp), false)
	if err != nil {
		fmt.Println("forti firewallAddrgrp fetch err: ", err)
		return
	}

	firewallAddrgrp6, err := adapter.GetRawConfig(string(fortiEnum.FirewallAddrgrp6), false)
	if err != nil {
		fmt.Println("forti firewallAddrgrp6 fetch err: ", err)
		return
	}

	firewallServiceCustom, err := adapter.GetRawConfig(string(fortiEnum.FirewallServiceCustom), false)
	if err != nil {
		fmt.Println("forti firewallServiceCustom fetch err: ", err)
		return
	}

	firewallServiceGroup, err := adapter.GetRawConfig(string(fortiEnum.FirewallServiceGroup), false)
	if err != nil {
		fmt.Println("forti firewallServiceGroup fetch err: ", err)
		return
	}

	policies, err := adapter.GetRawConfig(string(fortiEnum.FirewallPolicy), false)
	if err != nil {
		fmt.Println("forti policies fetch err: ", err)
		return
	}

	objectSet := NewFortiObjectSet(fortigate)
	if _, ok := firewallAddress.(dto.FortiResponse); ok {
		resp := firewallAddress.(dto.FortiResponse)
		objectSet.parseRespResultForNetwork(resp.Results)
	}
	if _, ok := firewallAddress6.(dto.FortiResponse); ok {
		resp := firewallAddress6.(dto.FortiResponse)
		objectSet.parseRespResultForNetwork(resp.Results)
	}
	if _, ok := firewallAddrgrp.(dto.FortiResponse); ok {
		resp := firewallAddrgrp.(dto.FortiResponse)
		objectSet.parseRespResultForNetworkGroup(resp.Results)
	}
	if _, ok := firewallAddrgrp6.(dto.FortiResponse); ok {
		resp := firewallAddrgrp6.(dto.FortiResponse)
		objectSet.parseRespResultForNetworkGroup(resp.Results)
	}
	if _, ok := firewallServiceCustom.(dto.FortiResponse); ok {
		resp := firewallServiceCustom.(dto.FortiResponse)
		objectSet.parseRespResultForService(resp.Results)
	}
	if _, ok := firewallServiceGroup.(dto.FortiResponse); ok {
		resp := firewallServiceGroup.(dto.FortiResponse)
		objectSet.parseRespResultForServiceGroup(resp.Results)
	}
	fortigate.objectSet = objectSet
	fmt.Println("objectSet--->", objectSet)

	firewallVip, err := adapter.GetRawConfig(string(fortiEnum.FirewallVip), false)
	if err != nil {
		fmt.Println("forti firewallVip fetch err: ", err)
		return
	}
	if _, ok := firewallVip.(dto.FortiResponse); ok {
		resp := firewallVip.(dto.FortiResponse)
		nats := NewFortiNats(fortigate)
		nats.parseRespResultForVip(resp.Results)
		fortigate.nats = nats
	}
	fmt.Println("nats--->", fortigate.nats)

	firewallIpPool, err := adapter.GetRawConfig(string(fortiEnum.FirewallObjectIPPool), false)
	if err != nil {
		fmt.Println("forti firewallIpPool fetch err: ", err)
		return
	}
	if _, ok := firewallIpPool.(dto.FortiResponse); ok {
		resp := firewallIpPool.(dto.FortiResponse)
		if fortigate.nats == nil {
			nats := NewFortiNats(fortigate)
			nats.parseRespResultForIpPool(resp.Results)
			fortigate.nats = nats
		} else {
			fortigate.nats.parseRespResultForIpPool(resp.Results)
		}
	}
	fmt.Println("dynamic nats--->", fortigate.nats)

	if _, ok := policies.(dto.FortiResponse); ok {
		resp := policies.(dto.FortiResponse)
		policySet := &PolicySet{
			parent:    fortigate,
			objects:   objectSet,
			node:      fortigate,
			policySet: map[string]*Policy{},
		}
		policySet.parseRespResultForPolicy(resp.Results)
		fortigate.policySet = policySet
	}
	fmt.Println("policySet--->", fortigate.policySet)

	fortigate.tmpData = make(map[string]any)
	fortigate.snatDesignInfo = deviceConfig.Snat
}

func (fortigate *FortigateNode) FlyConfig(cli interface{}) {
	// 支持多种输入类型：
	// 1. map[string][]interface{} - 直接的对象映射（原有格式）
	// 2. *common.PolicyResult - PolicyResult 对象
	// 3. map[string]string - CLI 字符串映射（从 result.FlyObject）

	var flyObjectMap map[string][]interface{}

	switch v := cli.(type) {
	case map[string][]interface{}:
		// 直接使用
		flyObjectMap = v
	case map[string]string:
		// 从 CLI 字符串映射解析
		flyObjectMap = make(map[string][]interface{})
		for key, cliStr := range v {
			if cliStr == "" {
				continue
			}
			// 解析 CLI 字符串为 dto.ForiRespResult 对象
			// 返回 map[string][]*dto.ForiRespResult，其中 key 是类型（如 "NETWORK", "SERVICE", "STATIC_NAT", "POOL"）
			resultMap, err := parseCLIToForiRespResult(cliStr)
			if err != nil {
				// 如果解析失败，抛出错误而不是静默跳过
				panic(fmt.Errorf("failed to parse CLI for key %s: %v", key, err))
			}
			// 将解析结果添加到对应的键（根据解析出的类型）
			for resultType, results := range resultMap {
				for _, result := range results {
					flyObjectMap[resultType] = append(flyObjectMap[resultType], result)
				}
			}
		}
	default:
		// 尝试类型断言为 map[string][]interface{}
		var ok bool
		flyObjectMap, ok = cli.(map[string][]interface{})
		if !ok {
			panic(fmt.Errorf("FlyConfig: unsupported type %T", cli))
		}
	}

	fortigate.parseFlyConfig(flyObjectMap)

	// 只有在 nats 已初始化时才打印 VIP 规则
	if fortigate.nats != nil {
		for _, r := range fortigate.nats.VipRules {
			fmt.Println(fmt.Sprintf("forti vip rule name:%s Original:%s Translate:%s", r.name, r.Original().String(), r.Translate().String()))
		}
		for _, r := range fortigate.nats.DynamicRules {
			fmt.Println(fmt.Sprintf("forti dynamic rule name:%s Original:%s Translate:%s", r.name, r.Original().String(), r.Translate().String()))
		}
	}
}

func (fortigate *FortigateNode) FlyObjectToFlattenCli(flyObject interface{}, ctx *context.Context) string {
	flyObjectMap := flyObject.(map[string][]interface{})
	var cliStr string
	if _, ok := flyObjectMap[common.FlyObjectClis]; ok {
		cliArr := flyObjectMap[common.FlyObjectClis]
		var cliStrArr []string
		for _, cli := range cliArr {
			cliStrArr = append(cliStrArr, cli.(string))
		}
		cliStr = strings.Join(cliStrArr, "\n")
	}
	return cliStr
}

func (fortigate *FortigateNode) parseFlyConfig(flyObjectMap map[string][]interface{}) {
	if len(flyObjectMap[common.FlyObjectNetwork]) != 0 {
		theNetworks := flyObjectMap[common.FlyObjectNetwork]
		for _, nk := range theNetworks {
			theNetwork, ok := nk.(*dto.ForiRespResult)
			if !ok {
				panic(fmt.Errorf("invalid type for NETWORK: expected *dto.ForiRespResult, got %T", nk))
			}
			fortigate.objectSet.parseRespResultForNetwork([]dto.ForiRespResult{*theNetwork})
		}
	}

	// // 处理 NETWORK_OBJECT 键（与 NETWORK 相同，都是网络对象）
	// if len(flyObjectMap["NETWORK_OBJECT"]) != 0 {
	// 	theNetworks := flyObjectMap["NETWORK_OBJECT"]
	// 	for _, nk := range theNetworks {
	// 		theNetwork, ok := nk.(*dto.ForiRespResult)
	// 		if !ok {
	// 			panic(fmt.Errorf("invalid type for NETWORK_OBJECT: expected *dto.ForiRespResult, got %T", nk))
	// 		}
	// 		fortigate.objectSet.parseRespResultForNetwork([]dto.ForiRespResult{*theNetwork})
	// 	}
	// }

	if len(flyObjectMap[common.FlyObjectNetworkObjectGroup]) != 0 {
		theNetworkGroup := flyObjectMap[common.FlyObjectNetworkObjectGroup]
		for _, nk := range theNetworkGroup {
			theNetwork, ok := nk.(*dto.ForiRespResult)
			if !ok {
				panic(fmt.Errorf("invalid type for NETWORK_OBJECT_GROUP: expected *dto.ForiRespResult, got %T", nk))
			}
			fortigate.objectSet.parseRespResultForNetworkGroup([]dto.ForiRespResult{*theNetwork})
		}
	}

	if len(flyObjectMap[common.FlyObjectService]) != 0 {
		theServices := flyObjectMap[common.FlyObjectService]
		for _, nk := range theServices {
			theService, ok := nk.(*dto.ForiRespResult)
			if !ok {
				panic(fmt.Errorf("invalid type for SERVICE: expected *dto.ForiRespResult, got %T", nk))
			}
			fortigate.objectSet.parseRespResultForService([]dto.ForiRespResult{*theService})
		}
	}

	if len(flyObjectMap[common.FlyObjectServiceGroup]) != 0 {
		theServiceGroup := flyObjectMap[common.FlyObjectServiceGroup]
		for _, nk := range theServiceGroup {
			theGroup, ok := nk.(*dto.ForiRespResult)
			if !ok {
				panic(fmt.Errorf("invalid type for SERVICE_GROUP: expected *dto.ForiRespResult, got %T", nk))
			}
			fortigate.objectSet.parseRespResultForServiceGroup([]dto.ForiRespResult{*theGroup})
		}
	}

	if len(flyObjectMap[common.FlyObjectStaticNat]) != 0 {
		// 确保 nats 已初始化
		if fortigate.nats == nil {
			fortigate.nats = NewFortiNats(fortigate)
		}
		theNats := flyObjectMap[common.FlyObjectStaticNat]
		for _, nk := range theNats {
			theNat, ok := nk.(*dto.ForiRespResult)
			if !ok {
				panic(fmt.Errorf("invalid type for STATIC_NAT: expected *dto.ForiRespResult, got %T", nk))
			}
			fortigate.nats.parseRespResultForVip([]dto.ForiRespResult{*theNat})
		}
	}

	if len(flyObjectMap[common.FlyObjectPool]) != 0 {
		thePools := flyObjectMap[common.FlyObjectPool]
		for _, nk := range thePools {
			thePool, ok := nk.(*dto.ForiRespResult)
			if !ok {
				panic(fmt.Errorf("invalid type for POOL: expected *dto.ForiRespResult, got %T", nk))
			}
			fortigate.nats.parseRespResultForIpPool([]dto.ForiRespResult{*thePool})
		}
	}

	if len(flyObjectMap[common.FlyObjectSecurityPolicy]) != 0 {
		thePolicies := flyObjectMap[common.FlyObjectSecurityPolicy]
		for _, nk := range thePolicies {
			thePolicy, ok := nk.(*dto.ForiRespResult)
			if !ok {
				panic(fmt.Errorf("invalid type for SECURITY_POLICY: expected *dto.ForiRespResult, got %T", nk))
			}
			fortigate.policySet.parseRespResultForPolicy([]dto.ForiRespResult{*thePolicy})
		}
	}

}
