package srx

import (
	"context"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
)

func (srx *SRXNode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
	srx.WithNodeType(api.FIREWALL)

	config := adapter.GetConfig(false).(string)
	// defaults := adapter.Get
	objectSet := NewSRXObjectSet(srx)
	objectSet.parseConfig(config)
	//
	srx.objectSet = objectSet
	//
	policySet := &PolicySet{
		objects:   objectSet,
		node:      srx,
		policySet: map[string]map[string][]*Policy{},
	}

	policySet.parseConfig(config)
	srx.policySet = policySet

	nats := &Nats{
		objects:             objectSet,
		node:                srx,
		staticNatRules:      map[string]*NatRuleSet{},
		sourceNatRules:      map[string]*NatRuleSet{},
		destinationNatRules: map[string]*NatRuleSet{},
		// ruleSetMap: map[firewall.NatType]map[string]*NatRuleSet{},
	}
	nats.parseConfig(config)
	srx.nats = nats
	srx.snatDesignInfo = deviceConfig.Snat
}

func (srx *SRXNode) FlyConfig(cli interface{}) {
	srx.objectSet.parseConfig(cli.(string) + "\n")
	srx.nats.flyConfig(cli.(string) + "\n")
	srx.policySet.parseConfig(cli.(string) + "\n")

}

func (srx *SRXNode) FlyObjectToFlattenCli(flyObject interface{}, ctx *context.Context) string {
	return strings.TrimSpace(flyObject.(string))
}
