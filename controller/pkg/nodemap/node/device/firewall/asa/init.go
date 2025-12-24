package asa

import (
	"context"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
)

func (asa *ASANode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
	asa.WithNodeType(api.FIREWALL)
	// asaAdapter := adapter.(*ASA.ASAAdapter)
	conf := adapter.GetConfig(false).(string)
	objectSet := NewASAObjectSet(asa)
	objectSet.parseConfig(conf)
	// objectSet.process()

	asa.objectSet = objectSet

	policySet := &PolicySet{
		objects:   objectSet,
		node:      asa,
		policySet: map[string][]*Policy{},
	}
	policySet.parseConfig(conf)
	asa.policySet = policySet

	nats := &Nats{
		objects: objectSet,
		node:    asa,
	}
	nats.parseConfig(conf)

	asa.nats = nats

	matrix := &Matrix{
		policySet:   policySet,
		node:        asa,
		accessGroup: map[string]map[string]string{},
	}
	matrix.parseConfig(conf)
	asa.matrix = matrix

	asa.snatDesignInfo = deviceConfig.Snat
	//
}

func (asa *ASANode) FlyConfig(cli interface{}) {
	cmdCli := cli.(string)
	asa.objectSet.parseConfig(cmdCli + "\n")
	asa.nats.parseConfig(cmdCli + "\n")
	asa.policySet.parseConfig(cmdCli + "\n")
}

func (secpath *ASANode) FlyObjectToFlattenCli(flyObject interface{}, ctx *context.Context) string {
	return strings.TrimSpace(flyObject.(string))
}
