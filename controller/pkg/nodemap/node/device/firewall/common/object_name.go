package common

import (
	"fmt"
	"strings"
	"sync"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/keys"
	"github.com/netxops/utils/dsl"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

const (
	RetryMethodNext   = "next"
	RetryMethodSuffix = "suffix"
)

type ObjectStatus int

const (
	ObjectNotExist ObjectStatus = iota
	ObjectExistSame
	ObjectExistDifferent
)

type NamingTemplates struct {
	NetworkTemplate    string
	L3ProtocolTemplate string
	ICMPTemplate       string
	L4Template         string
}

var DefaultTemplates = NamingTemplates{
	NetworkTemplate:    `ADDR_{if:isHost=="true"}HOST_{ip}{else if:isNetwork="true"}NET_{ip}_{mask}{else}RANGE_{start}_{end}{endif}`,
	L3ProtocolTemplate: "SVC_L3_{protocol}",
	ICMPTemplate:       "SVC_ICMP_{type}_{code}",
	L4Template:         "SVC_{protocol}_{if:src_port!='0 65535'}SRC_{src_port}{endif}_DST_{dst_port}",
}

type ObjectNameManager struct {
	generatedNames map[string]bool
	mutex          sync.RWMutex
}

// NewObjectNameManager 创建一个新的 ObjectNameManager
func NewObjectNameManager() *ObjectNameManager {
	return &ObjectNameManager{
		generatedNames: make(map[string]bool),
	}
}

// IsNameGenerated 检查名称是否已经生成过
func (onm *ObjectNameManager) IsNameGenerated(name string) bool {
	// onm.mutex.RLock()
	// defer onm.mutex.RUnlock()
	return onm.generatedNames[name]
}

// AddGeneratedName 添加一个生成过的名称
func (onm *ObjectNameManager) AddGeneratedName(name string) {
	// onm.mutex.Lock()
	// defer onm.mutex.Unlock()
	onm.generatedNames[name] = true
}

// StarlarkExecutor 用于执行 Starlark 模板的函数类型
// intent: 策略意图
// template: Starlark 模板代码字符串
// metaData: 元数据
type StarlarkExecutor func(intent *policy.Intent, template string, metaData map[string]interface{}) string

func GenerateObjectName(auto *keys.AutoIncrementKeys, obj interface{}, itFunc func() firewall.NamerIterator, node firewall.FirewallNode, templates *NamingTemplates, retryMethod string, onm *ObjectNameManager, useBaseFirst bool) (keys.Keys, bool, error) {
	return GenerateObjectNameWithStarlark(auto, obj, itFunc, node, templates, retryMethod, onm, useBaseFirst, nil)
}

// GenerateObjectNameWithStarlark 生成对象名称（支持 Starlark 模板）
// starlarkExecutor: 可选的 Starlark 执行器，如果提供则使用 Starlark 模板生成名称
func GenerateObjectNameWithStarlark(auto *keys.AutoIncrementKeys, obj interface{}, itFunc func() firewall.NamerIterator, node firewall.FirewallNode, templates *NamingTemplates, retryMethod string, onm *ObjectNameManager, useBaseFirst bool, starlarkExecutor StarlarkExecutor) (keys.Keys, bool, error) {
	var status ObjectStatus
	var err error

	key := auto.GetBase()
	if !useBaseFirst {
		key = auto.Next()
	}
	currentKey := key.Clone()
	maxRetries := 10
	retryCount := 0

	// 根据对象类型选择适当的模板并生成名称（使用 Starlark 模板）
	var generatedName string

	if templates != nil {
		// 创建临时 intent 和 metaData
		var tempIntent *policy.Intent
		metaData := make(map[string]interface{})

		// 如果没有提供 starlarkExecutor，使用默认的 dsl.StarlarkIntentFormat
		if starlarkExecutor == nil {
			starlarkExecutor = func(intent *policy.Intent, template string, metaData map[string]interface{}) string {
				if template == "" {
					return ""
				}
				opts := dsl.NewDSLParserOptions()
				return dsl.StarlarkIntentFormat(intent, template, opts, metaData)
			}
		}

		switch v := obj.(type) {
		case *network.NetworkGroup:
			tempIntent = &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					v,
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					nil,
				),
			}
			if starlarkExecutor != nil {
				generatedName = starlarkExecutor(tempIntent, templates.NetworkTemplate, metaData)
			}
		case *network.IPNet:
			ng := network.NewNetworkGroup()
			ng.Add(v)
			tempIntent = &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					ng,
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					nil,
				),
			}
			if starlarkExecutor != nil {
				generatedName = starlarkExecutor(tempIntent, templates.NetworkTemplate, metaData)
			}
		case *network.IPRange:
			ng := network.NewNetworkGroup()
			ng.Add(v)
			tempIntent = &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					ng,
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					nil,
				),
			}
			if starlarkExecutor != nil {
				generatedName = starlarkExecutor(tempIntent, templates.NetworkTemplate, metaData)
			}
		case *network.IP:
			ng, _ := network.NewNetworkGroupFromString(v.String())
			tempIntent = &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					ng,
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					nil,
				),
			}
			if starlarkExecutor != nil {
				generatedName = starlarkExecutor(tempIntent, templates.NetworkTemplate, metaData)
			}
		case *network.Network:
			net, ok := v.IPNet()
			if ok {
				ng := network.NewNetworkGroup()
				ng.Add(net)
				tempIntent = &policy.Intent{
					PolicyEntry: *policy.NewPolicyEntryWithAll(
						ng,
						network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
						nil,
					),
				}
				if starlarkExecutor != nil {
					generatedName = starlarkExecutor(tempIntent, templates.NetworkTemplate, metaData)
				}
			}
		case *network.NetworkList:
			agg, _ := v.Aggregate()
			if agg != nil {
				ng := network.NewNetworkGroup()
				ng.Add(agg)
				tempIntent = &policy.Intent{
					PolicyEntry: *policy.NewPolicyEntryWithAll(
						ng,
						network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
						nil,
					),
				}
				if starlarkExecutor != nil {
					generatedName = starlarkExecutor(tempIntent, templates.NetworkTemplate, metaData)
				}
			}
		case *service.L3Protocol:
			svc := &service.Service{}
			svc.Add(v)
			tempIntent = &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					svc,
				),
			}
			if starlarkExecutor != nil {
				generatedName = starlarkExecutor(tempIntent, templates.L3ProtocolTemplate, metaData)
			}
		case *service.ICMPProto:
			svc := &service.Service{}
			svc.Add(v)
			tempIntent = &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					svc,
				),
			}
			if starlarkExecutor != nil {
				generatedName = starlarkExecutor(tempIntent, templates.ICMPTemplate, metaData)
			}
		case *service.L4Service:
			svc := &service.Service{}
			svc.Add(v)
			tempIntent = &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					svc,
				),
			}
			if starlarkExecutor != nil {
				generatedName = starlarkExecutor(tempIntent, templates.L4Template, metaData)
			}
		case *service.Service:
			tempIntent = &policy.Intent{
				PolicyEntry: *policy.NewPolicyEntryWithAll(
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					network.NewNetworkGroupFromStringMust("0.0.0.0/0"),
					v,
				),
			}
			if starlarkExecutor != nil {
				svcEntry, err := v.OneServiceEntry()
				if err == nil {
					var template string
					switch svcEntry.(type) {
					case *service.L3Protocol:
						template = templates.L3ProtocolTemplate
					case *service.ICMPProto:
						template = templates.ICMPTemplate
					case *service.L4Service:
						template = templates.L4Template
					}
					if template != "" {
						generatedName = starlarkExecutor(tempIntent, template, metaData)
					}
				}
			}
		}

		if generatedName != "" {
			generatedName = strings.TrimSpace(generatedName)
			currentKey = keys.NewKeyBuilder(generatedName)
		}
	}

	for retryCount < maxRetries {
		// 检查生成的名称是否已存在
		if onm.IsNameGenerated(currentKey.String()) {
			// 如果名称已存在，进行退让
			currentKey, err = retryObjectName(node, auto, retryMethod)
			if err != nil {
				return currentKey, false, err
			}
			continue
		}

		switch v := obj.(type) {
		case *network.NetworkGroup:
			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, v)
		case *network.IPNet, *network.IPRange, *network.Network, *network.NetworkList:
			ng := network.NewNetworkGroup()
			ng.Add(obj.(network.AbbrNet))
			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, ng)
		case *network.IP:
			ng, _ := network.NewNetworkGroupFromString(v.String())
			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, ng)
		case *service.Service:
			status, err = checkAndRetryServiceObject(itFunc(), currentKey, node, v)
		case *service.L3Protocol, *service.ICMPProto, *service.L4Service:
			s := &service.Service{}
			s.Add(v.(service.ServiceEntry))
			status, err = checkAndRetryServiceObject(itFunc(), currentKey, node, s)
		case network.AbbrNet:
			// 通用处理：对于任何实现了 network.AbbrNet 接口的类型，都将其转换为 NetworkGroup
			ng := network.NewNetworkGroup()
			ng.Add(v)
			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, ng)
		default:
			return currentKey, false, fmt.Errorf("unsupported object type: %T", obj)
		}

		if err != nil {
			return currentKey, false, err
		}

		switch status {
		case ObjectNotExist:
			// 添加生成的名称到管理器
			onm.AddGeneratedName(currentKey.String())
			return currentKey, true, nil
		case ObjectExistSame:
			return currentKey, false, nil
		case ObjectExistDifferent:
			// 如果对象存在但不匹配，进行退让
			currentKey, err = retryObjectName(node, auto, retryMethod)
			if err != nil {
				return currentKey, false, err
			}
		}

		retryCount++
	}

	// 如果达到最大重试次数仍未找到合适的名称
	return currentKey, false, fmt.Errorf("failed to generate unique object name after %d attempts", maxRetries)
}

// func GenerateObjectName(key keys.Keys, obj interface{}, itFunc func() firewall.NamerIterator, node firewall.FirewallNode, templates *NamingTemplates, retryMethod string) (keys.Keys, bool, error) {
// 	var status ObjectStatus
// 	var err error
// 	currentKey := key.Clone()
// 	maxRetries := 10
// 	retryCount := 0

// 	// 根据对象类型选择适当的模板并生成名称
// 	var generatedName string

// 	if templates != nil {
// 		switch v := obj.(type) {
// 		case *network.NetworkGroup:
// 			abbrNet, err := v.GenerateNetworkE()
// 			if err == nil {
// 				generatedName = dsl.NetworkFormat(abbrNet, templates.NetworkTemplate)
// 			}
// 		case *network.IPNet:
// 			generatedName = dsl.NetworkFormat(v, templates.NetworkTemplate)
// 		case *network.IPRange:
// 			generatedName = dsl.NetworkFormat(v, templates.NetworkTemplate)
// 		case *network.IP:
// 			net, _ := network.ParseIPNet(v.String())
// 			generatedName = dsl.NetworkFormat(net, templates.NetworkTemplate)
// 		case *network.Network:
// 			net, ok := v.IPNet()
// 			if ok {
// 				generatedName = dsl.NetworkFormat(net, templates.NetworkTemplate)
// 			}
// 		case *network.NetworkList:
// 			agg, _ := v.Aggregate()
// 			if agg != nil {
// 				generatedName = dsl.NetworkFormat(agg, templates.NetworkTemplate)
// 			}
// 		case *service.L3Protocol:
// 			generatedName = dsl.ServiceEntryFormat(v, templates.L3ProtocolTemplate)
// 		case *service.ICMPProto:
// 			generatedName = dsl.ServiceEntryFormat(v, templates.ICMPTemplate)
// 		case *service.L4Service:
// 			generatedName = dsl.ServiceEntryFormat(v, templates.L4Template)
// 		case *service.Service:
// 			svcEntry, err := v.OneServiceEntry()
// 			if err == nil {
// 				var template string
// 				switch svcEntry.(type) {
// 				case *service.L3Protocol:
// 					template = templates.L3ProtocolTemplate
// 				case *service.ICMPProto:
// 					template = templates.ICMPTemplate
// 				case *service.L4Service:
// 					template = templates.L4Template
// 				}
// 				generatedName = dsl.ServiceEntryFormat(svcEntry, template)
// 			}

// 		default:
// 			return currentKey, false, fmt.Errorf("unsupported object type")
// 		}

// 		if generatedName != "" {
// 			currentKey = keys.NewKeyBuilder(generatedName)
// 		}
// 	}

// 	for retryCount < maxRetries {
// 		switch v := obj.(type) {
// 		case *network.NetworkGroup:
// 			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, v)
// 		case *network.IPNet, *network.IPRange, *network.Network, *network.NetworkList:
// 			ng := network.NewNetworkGroup()
// 			ng.Add(obj.(network.AbbrNet))
// 			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, ng)
// 		case *network.IP:
// 			ng, _ := network.NewNetworkGroupFromString(v.String())
// 			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, ng)
// 		case *service.Service:
// 			status, err = checkAndRetryServiceObject(itFunc(), currentKey, node, v)
// 		case *service.L3Protocol, *service.ICMPProto, *service.L4Service:
// 			s := &service.Service{}
// 			s.Add(v.(service.ServiceEntry))
// 			status, err = checkAndRetryServiceObject(itFunc(), currentKey, node, s)
// 		default:
// 			return currentKey, false, fmt.Errorf("unsupported object type")
// 		}

// 		if err != nil {
// 			return currentKey, false, err
// 		}

// 		switch status {
// 		case ObjectNotExist:
// 			return currentKey, true, nil
// 		case ObjectExistSame:
// 			return currentKey, false, nil
// 		case ObjectExistDifferent:
// 			// 如果对象存在但不匹配，进行退让
// 			currentKey, err = retryObjectName(node, currentKey, retryMethod)
// 			if err != nil {
// 				return currentKey, false, err
// 			}
// 		}

// 		retryCount++
// 	}

// 	// 如果达到最大重试次数仍未找到合适的名称
// 	return currentKey, false, fmt.Errorf("failed to generate unique object name after %d attempts", maxRetries)
// }

// func GenerateObjectName(key keys.Keys, obj interface{}, itFunc func() firewall.NamerIterator, node firewall.FirewallNode, templates *NamingTemplates, retryMethod string, counter int) (keys.Keys, bool, error) {
// 	var status ObjectStatus
// 	var err error
// 	currentKey := key.Clone()
// 	maxRetries := 10
// 	retryCount := 0

// 	// 根据对象类型选择适当的模板并生成名称
// 	var generatedName string

// 	if templates != nil {
// 		switch v := obj.(type) {
// 		case *network.NetworkGroup:
// 			abbrNet, err := v.GenerateNetworkE()
// 			if err == nil {
// 				generatedName = dsl.NetworkFormat(abbrNet, templates.NetworkTemplate)
// 			}
// 		case *network.IPNet:
// 			generatedName = dsl.NetworkFormat(v, templates.NetworkTemplate)
// 		case *network.IPRange:
// 			generatedName = dsl.NetworkFormat(v, templates.NetworkTemplate)
// 		case *network.IP:
// 			net, _ := network.ParseIPNet(v.String())
// 			generatedName = dsl.NetworkFormat(net, templates.NetworkTemplate)
// 		case *network.Network:
// 			net, ok := v.IPNet()
// 			if ok {
// 				generatedName = dsl.NetworkFormat(net, templates.NetworkTemplate)
// 			}
// 		case *network.NetworkList:
// 			agg, _ := v.Aggregate()
// 			if agg != nil {
// 				generatedName = dsl.NetworkFormat(agg, templates.NetworkTemplate)
// 			}
// 		case *service.L3Protocol:
// 			generatedName = dsl.ServiceEntryFormat(v, templates.L3ProtocolTemplate)
// 		case *service.ICMPProto:
// 			generatedName = dsl.ServiceEntryFormat(v, templates.ICMPTemplate)
// 		case *service.L4Service:
// 			generatedName = dsl.ServiceEntryFormat(v, templates.L4Template)
// 		case *service.Service:
// 			svcEntry, err := v.OneServiceEntry()
// 			if err == nil {
// 				var template string
// 				switch svcEntry.(type) {
// 				case *service.L3Protocol:
// 					template = templates.L3ProtocolTemplate
// 				case *service.ICMPProto:
// 					template = templates.ICMPTemplate
// 				case *service.L4Service:
// 					template = templates.L4Template
// 				}
// 				generatedName = dsl.ServiceEntryFormat(svcEntry, template)
// 			}
// 		default:
// 			return currentKey, false, fmt.Errorf("unsupported object type")
// 		}

// 		if generatedName != "" {
// 			// 在生成的名称后添加计数器
// 			generatedName = fmt.Sprintf("%s_%d", generatedName, counter)
// 			currentKey = keys.NewKeyBuilder(generatedName)
// 		}
// 	}

// 	for retryCount < maxRetries {
// 		switch v := obj.(type) {
// 		case *network.NetworkGroup:
// 			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, v)
// 		case *network.IPNet, *network.IPRange, *network.Network, *network.NetworkList:
// 			ng := network.NewNetworkGroup()
// 			ng.Add(obj.(network.AbbrNet))
// 			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, ng)
// 		case *network.IP:
// 			ng, _ := network.NewNetworkGroupFromString(v.String())
// 			status, err = checkAndRetryNetworkObject(itFunc(), currentKey, node, ng)
// 		case *service.Service:
// 			status, err = checkAndRetryServiceObject(itFunc(), currentKey, node, v)
// 		case *service.L3Protocol, *service.ICMPProto, *service.L4Service:
// 			s := &service.Service{}
// 			s.Add(v.(service.ServiceEntry))
// 			status, err = checkAndRetryServiceObject(itFunc(), currentKey, node, s)
// 		default:
// 			return currentKey, false, fmt.Errorf("unsupported object type")
// 		}

// 		if err != nil {
// 			return currentKey, false, err
// 		}

// 		switch status {
// 		case ObjectNotExist:
// 			return currentKey, true, nil
// 		case ObjectExistSame:
// 			return currentKey, false, nil
// 		case ObjectExistDifferent:
// 			// 如果对象存在但不匹配，进行退让
// 			currentKey, err = retryObjectName(node, currentKey, retryMethod)
// 			if err != nil {
// 				return currentKey, false, err
// 			}
// 		}

// 		retryCount++
// 	}

// 	// 如果达到最大重试次数仍未找到合适的名称
// 	return currentKey, false, fmt.Errorf("failed to generate unique object name after %d attempts", maxRetries)
// }

func checkAndRetryNetworkObject(iterator firewall.NamerIterator, key keys.Keys, node firewall.FirewallNode, ng *network.NetworkGroup) (ObjectStatus, error) {
	for iterator.HasNext() {
		obj := iterator.Next()
		netObj := obj.(firewall.FirewallNetworkObject)
		if obj.Name() == key.String() {
			if netObj.Network(node).Same(ng) {
				return ObjectExistSame, nil
			}
			return ObjectExistDifferent, nil
		}
	}
	return ObjectNotExist, nil
}

func checkAndRetryServiceObject(iterator firewall.NamerIterator, key keys.Keys, node firewall.FirewallNode, svc *service.Service) (ObjectStatus, error) {
	for iterator.HasNext() {
		obj := iterator.Next()
		srvObj := obj.(firewall.FirewallServiceObject)
		if obj.Name() == key.String() {
			if srvObj.Service(node).Same(svc) {
				return ObjectExistSame, nil
			}
			return ObjectExistDifferent, nil
		}
	}
	return ObjectNotExist, nil
}

func retryObjectName(node firewall.FirewallNode, auto *keys.AutoIncrementKeys, retryMethod string) (keys.Keys, error) {
	switch retryMethod {
	case RetryMethodNext:
		return retryNextName(node, auto)
	case RetryMethodSuffix:
		return retrySuffixName(node, auto.GetBase())
	default:
		return auto.GetBase(), fmt.Errorf("unsupported retry method: %s", retryMethod)
	}
}

func retryNextName(node firewall.FirewallNode, auto *keys.AutoIncrementKeys) (keys.Keys, error) {
	// auto := keys.NewAutoIncrementKeys(key, 1)
	nextKey := auto.Next()
	for node.HasObjectName(nextKey.String()) {
		nextKey = auto.Next()
	}
	return nextKey, nil
}

func retrySuffixName(node firewall.FirewallNode, key keys.Keys) (keys.Keys, error) {
	auto := keys.NewAutoIncrementKeys(key, 1)
	for node.HasObjectName(key.String()) {
		key = auto.Next()
	}
	return key, nil
}
