package secpath

import (
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common"
)

func (secpath *SecPathNode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
	secpath.WithNodeType(api.FIREWALL)

	config := adapter.GetConfig(false).(map[string]interface{})
	cliConfig := config["Config"]

	objectSet := NewSecPathObjectSet(secpath)
	// objectSet.parseService(config["ServiceGroupObject"].([]interface{}))
	// ipv4_network_data := config["IPv4Objs"].([]interface{})
	// ipv6_network_data := config["IPv6Objs"].([]interface{})
	// ipv4_group_info := config["IPv4Groups"].([]interface{})
	// ipv6_group_info := config["IPv6Groups"].([]interface{})
	// objectSet.parseNetwork(ipv4_network_data, ipv6_network_data, ipv4_group_info, ipv6_group_info)
	objectSet.parseNetworkCli(cliConfig.(string))
	objectSet.parseServiceCli(cliConfig.(string))
	objectSet.parsePortObjectCli(cliConfig.(string))
	secpath.ObjectSet = objectSet

	aclSet := ACLSet{
		objects: objectSet,
		Sets:    []*ACL{},
	}
	aclSet.parseAclSection(cliConfig.(string))
	secpath.AclSet = &aclSet

	policySet := PolicySet{
		objects:     objectSet,
		node:        secpath,
		ipv4NameAcl: map[string]*PolicyGroup{},
		ipv6NameAcl: map[string]*PolicyGroup{},
		// securityPolicyAcl: map[string]*Policy{},
		securityPolicyAcl: []*Policy{},
	}
	// ipv4AclData := config["IPv4NamedBasicRules"].([]interface{})
	// ipv4AdvanceAclData := config["IPv4NamedAdvanceRules"].([]interface{})

	// ipv6AclData := config["IPv6NamedBasicRules"].([]interface{})
	// ipv6AdvanceAclData := config["IPv6NamedAdvanceRules"].([]interface{})
	// // securityPolicyRules := config["GetRules"].([]interface{})

	// policySet.parseIpv4Name(ipv4AclData)
	// policySet.parseIpv4NameAdvance(ipv4AdvanceAclData)

	// policySet.parseIpv6Name(ipv6AclData)
	// policySet.parseIpv6NameAdvance(ipv6AdvanceAclData)
	// policySet.parseSecurityRules(securityPolicyRules)
	policySet.parseSecurityRulesCli(cliConfig.(string))
	secpath.PolicySet = &policySet

	nats := Nats{
		objects: objectSet,
		node:    secpath,
	}

	// outboundDynamicRules := config["OutboundDynamicRules"].([]interface{})
	// staticOnInterface := config["StaticOnInterfaces"].([]interface{})
	// serverOnInterface := config["ServerOnInterfaces"].([]interface{})
	// // natAddrGroups := config["AddrGroupMembers"].([]interface{})
	// outboundStaticRules := config["OutboundStaticMappings"].([]interface{})
	// natPolicyRules := config["PolicyRuleMembers"].([]interface{})
	nats.parseAddressGroupCli(cliConfig.(string))
	// nats.parseAddressGroup(natAddrGroups)
	nats.parseNatGlobalPolicy(cliConfig.(string))
	nats.parseNatServerCli(cliConfig.(string))
	nats.parseInboundStaticCli(cliConfig.(string))
	nats.parseOutboundStaticCli(cliConfig.(string))
	nats.parseOutboundDynamicCli(cliConfig.(string))
	// nats.parseStaticOnInterface(staticOnInterface)
	// nats.parseNatPolicy(natPolicyRules)
	// nats.parseNatServer(serverOnInterface)
	// nats.parseOutboundStaticRules(outboundStaticRules)
	// nats.parseOutboundDynamicRules(outboundDynamicRules)
	secpath.Nats = &nats
	// secpath.objectSet = objectSet
	// policySet := &PolicySet{
	// objects:   objectSet,
	// node:      secpath,
	// policySet: map[string]map[string][]*Policy{},
	// }
	//
	// policySet.parseConfig(config)
	// secpath.policySet = policySet
	//
	// nats := &Nats{
	// objects:             objectSet,
	// node:                secpath,
	// staticNatRules:      map[string]*NatRuleSet{},
	// sourceNatRules:      map[string]*NatRuleSet{},
	// destinationNatRules: map[string]*NatRuleSet{},
	// }
	// nats.parseConfig(config)
	// secpath.nats = nats
	secpath.SnatDesignInfo = deviceConfig.Snat
}

func (secpath *SecPathNode) FlyConfigXml(cli interface{}) {
	flyObjectsMap := cli.(map[string][]interface{})

	secpath.ObjectSet.parseNetwork(flyObjectsMap["NETWORK_IPv4_OBJECT"], flyObjectsMap["NETWORK_IPv6_OBJECT"],
		flyObjectsMap["NETWORK_IPv4_GROUP"], flyObjectsMap["NETWORK_IPv6_GROUP"])
	secpath.ObjectSet.parseService(flyObjectsMap["SERVICE"])

	secpath.Nats.parseNatServer(flyObjectsMap["SERVER_ON_INTERFACE"])
	secpath.PolicySet.parseSecurityRules(flyObjectsMap["SECURITY_POLICY"])
	secpath.Nats.parseAddressGroup(flyObjectsMap["POOL"])
	secpath.Nats.parseNatPolicy(flyObjectsMap["NAT_POLICY"])

}

func (secpath *SecPathNode) FlyConfig(cli interface{}) {
	flyObjectsMap := cli.(map[string]string)
	// fmt.Println("NETWORK:", flyObjectsMap[common.FlyObjectNetwork])
	secpath.ObjectSet.parseNetworkCli(flyObjectsMap[common.FlyObjectNetwork])
	// fmt.Println("SERVICE:", flyObjectsMap[common.FlyObjectService])
	secpath.ObjectSet.parseServiceCli(flyObjectsMap[common.FlyObjectService])

	// fmt.Println("SECURITY_POLICY:", flyObjectsMap[common.FlyObjectSecurityPolicy])
	// secpath.policySet.parseSecurityRulesCli(flyObjectsMap[common.FlyObjectSecurityPolicy])
	secpath.AclSet.parseAclSection(flyObjectsMap[common.FlyObjectAcl])
	secpath.PolicySet.flySecurityRuleCli(flyObjectsMap[common.FlyObjectSecurityPolicy])
	// fmt.Println("POOL:", flyObjectsMap[common.FlyObjectPool])
	secpath.Nats.parseAddressGroupCli(flyObjectsMap[common.FlyObjectPool])
	// fmt.Println("NAT:", flyObjectsMap[common.FlyObjectNat])
	secpath.Nats.parseNatGlobalPolicy(flyObjectsMap[common.FlyObjectNat])

	secpath.Nats.parseNatServerCli(flyObjectsMap[common.FlyObjectNat])

	secpath.Nats.parseInboundStaticCli(flyObjectsMap[common.FlyObjectNat])
	secpath.Nats.parseOutboundStaticCli(flyObjectsMap[common.FlyObjectNat])
	secpath.Nats.parseOutboundDynamicCli(flyObjectsMap[common.FlyObjectNat])

	//
	// secpath.objectSet.parseNetwork(flyObjectsMap["NETWORK_IPv4_OBJECT"], flyObjectsMap["NETWORK_IPv6_OBJECT"],
	// flyObjectsMap["NETWORK_IPv4_GROUP"], flyObjectsMap["NETWORK_IPv6_GROUP"])
	// secpath.objectSet.parseService(flyObjectsMap["SERVICE"])
	//
	// secpath.nats.parseNatServer(flyObjectsMap["SERVER_ON_INTERFACE"])
	// secpath.policySet.parseSecurityRules(flyObjectsMap["SECURITY_POLICY"])
	// secpath.nats.parseAddressGroup(flyObjectsMap["POOL"])
	// secpath.nats.parseNatPolicy(flyObjectsMap["NAT_POLICY"])

}

func (secpath *SecPathNode) FlyObjectToFlattenCli(flyObject interface{}, ctx *firewall.PolicyContext) string {
	flyObjectsMap := flyObject.(map[string]string)
	clis := []string{}
	if flyObjectsMap[common.FlyObjectNetwork] != "" {
		clis = append(clis, strings.TrimSpace(flyObjectsMap[common.FlyObjectNetwork]))
	}

	if flyObjectsMap[common.FlyObjectService] != "" {
		clis = append(clis, strings.TrimSpace(flyObjectsMap[common.FlyObjectService]))
	}

	// fmt.Println("SECURITY_POLICY:", flyObjectsMap[common.FlyObjectSecurityPolicy])
	// secpath.policySet.parseSecurityRulesCli(flyObjectsMap[common.FlyObjectSecurityPolicy])
	if flyObjectsMap[common.FlyObjectSecurityPolicy] != "" {
		clis = append(clis, strings.TrimSpace(flyObjectsMap[common.FlyObjectSecurityPolicy]))
	}
	if flyObjectsMap[common.FlyObjectPool] != "" {
		clis = append(clis, strings.TrimSpace(flyObjectsMap[common.FlyObjectPool]))
	}
	// fmt.Println("NAT:", flyObjectsMap[common.FlyObjectNat])
	if flyObjectsMap[common.FlyObjectNat] != "" {
		clis = append(clis, strings.TrimSpace(flyObjectsMap[common.FlyObjectNat]))
	}

	return strings.Join(clis, "\n")

}
