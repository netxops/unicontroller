package node

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/validator"
)

type NetworkListRuleValidator struct{}

func (nv *NetworkListRuleValidator) Validate(data map[string]interface{}) validator.Result {
	connector := data["connector"].(api.Connector)
	// count := len(connector.NetworkList()) + 1
	count := connector.PortCount()
	if connector.Mode() == api.P2P {
		if count > 2 {
			return validator.NewValidateResult(false, "P2P not allow-----")
		} else {
			return validator.NewValidateResult(true, "")
		}
	} else if connector.Mode() == api.MP {
		return validator.NewValidateResult(true, "")
	} else {
		return validator.NewValidateResult(false, "mode is not invalid")
	}
}

type NameDuplicationValidator struct{}

func (nv *NameDuplicationValidator) Validate(data map[string]interface{}) validator.Result {
	connector := data["connector"].(api.Connector)
	port := data["port"].(api.Port)
	nameList := []string{}
	for _, p := range connector.PortList() {
		nameList = append(nameList, p.FlattenName())
	}

	for _, n := range nameList {
		if port.FlattenName() == n {
			// return validator.NewValidateResult(false, "")
			return validator.NewValidateResult(false, fmt.Sprintf("name:%s duplicate.", port.FlattenName()))
		}
	}

	return validator.NewValidateResult(true, "")
	// return validator.NewValidateResult(false, fmt.Sprintf("name:%s duplicate.", port.FlattenName()))
}

type IpAddressConflictValidator struct{}

func (iv *IpAddressConflictValidator) Validate(data map[string]interface{}) validator.Result {
	connector := data["connector"].(api.Connector)
	port := data["port"].(api.Port)

	ipv4_flatten := []string{}
	ipv6_flatten := []string{}

	// for _, n := range connector.NetworkList() {
	// ipv4_flatten = append(ipv4_flatten, n[network.IPv4]...)
	// }
	//
	// for _, n := range connector.NetworkList() {
	// ipv6_flatten = append(ipv6_flatten, n[network.IPv6]...)
	// }
	ipv4_flatten = append(ipv4_flatten, connector.IPv4List()...)
	ipv6_flatten = append(ipv6_flatten, connector.IPv6List()...)

	for _, ip := range port.GetIpList()[network.IPv4] {
		for _, o := range ipv4_flatten {
			if ip == o {
				return validator.NewValidateResult(false, fmt.Sprintf("%s address conflict", ip))
			}
		}
	}

	for _, ip := range port.GetIpList()[network.IPv6] {
		for _, o := range ipv6_flatten {
			if strings.ToLower(ip) == strings.ToLower(o) {
				return validator.NewValidateResult(false, fmt.Sprintf("%s address conflict", ip))
			}
		}
	}

	return validator.NewValidateResult(true, "")

}
