package usg

import (
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
)

func (usg *UsgNode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
	usg.WithNodeType(api.FIREWALL)

	config := adapter.GetConfig(false).(string)
	// defaults := adapter.Get
	objectSet := NewUsgObjectSet(usg)
	objectSet.ParseConfig(config)
	//
	usg.objectSet = objectSet
	//
	policySet := &PolicySet{
		objects:   objectSet,
		node:      usg,
		policySet: []*Policy{},
	}

	policySet.parseConfig(config)
	usg.policySet = policySet

	nats := &Nats{
		objects: objectSet,
		node:    usg,
		// staticNatRules:      map[string]*NatRuleSet{},
		// sourceNatRules:      map[string]*NatRuleSet{},
		// destinationNatRules: map[string]*NatRuleSet{},
		insidePools: map[string]*NatPool{},
		globalPools: map[string]*NatPool{},
		// ruleSetMap: map[firewall.NatType]map[string]*NatRuleSet{},
	}
	nats.parseConfig(config)
	usg.nats = nats
	usg.snatDesignInfo = deviceConfig.Snat
}

func (usg *UsgNode) FlyConfig(cli interface{}) {
	usg.objectSet.ParseConfig(cli.(string) + "\n")
	// usg.nats.flyConfig(cli.(string) + "\n")
	usg.nats.parseConfig(cli.(string))
	usg.policySet.parseConfig(cli.(string) + "\n")

}

func (usg *UsgNode) FlyObjectToFlattenCli(flyObject interface{}, ctx *firewall.PolicyContext) string {
	return strings.TrimSpace(flyObject.(string))
}
