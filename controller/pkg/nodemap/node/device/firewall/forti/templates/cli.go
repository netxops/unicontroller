package templates

import (
	"fmt"
	"reflect"
	"strings"
)

var CliTemplates = map[string]*CliTemplate{
	"ConfigFirewallAddressGroup": {
		Content: `config firewall addrgrp
edit "${AddressGroupName}"
	set member ${AddressNameArray}
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "AddressGroupName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "AddressNameArray", Type: reflect.Array},
		},
	},

	"ConfigFirewallAddressWithIpRange": {
		Content: `config firewall address
edit "${AddressName}"
    set type iprange
    set associated-interface "${Port}"
	set start-ip ${StartIp}
	set end-ip ${EndIp}
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "AddressName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "Port", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "StartIp", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "EndIp", Type: reflect.String},
		},
	},

	"ConfigFirewallAddress": {
		Content: `config firewall address
edit "${AddressName}"
	set associated-interface "${Port}"
	set subnet ${Subnet}
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "AddressName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "Port", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "Subnet", Type: reflect.String},
		},
	},

	"ConfigFirewallServiceTCP": {
		Content: `config firewall service custom
edit "${ServiceName}"
	set tcp-portrange ${PortRange}
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "ServiceName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "PortRange", Type: reflect.String},
		},
	},

	"ConfigFirewallServiceUDP": {
		Content: `config firewall service custom
edit "${ServiceName}"
	set udp-portrange ${PortRange}
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "ServiceName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "PortRange", Type: reflect.String},
		},
	},

	"ConfigFirewallServiceIP": {
		Content: `config firewall service custom
edit "${ServiceName}"
	set protocol IP
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "ServiceName", Type: reflect.String},
		},
	},

	"ConfigFirewallVipTcpUdp": {
		Content: `config firewall vip
edit "${VipName}"
	set extip ${ExtIp}
	set mappedip ${MappedIp}
	set extintf "${ExtIntf}"
	set portforward enable
	set extport ${ExtPort}
	set mappedport ${MappedPort}
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "VipName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "ExtIp", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "MappedIp", Type: reflect.Array},
			{Prefix: "${", Suffix: "}", Holder: "ExtIntf", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "ExtPort", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "MappedPort", Type: reflect.String},
		},
	},

	"ConfigFirewallVipIp": {
		Content: `config firewall vip
edit "${VipName}"
    set extip ${ExtIp}
    set mappedip ${MappedIp}
    set extintf "${ExtIntf}"
    set portforward disable
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "VipName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "ExtIp", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "MappedIp", Type: reflect.Array},
			{Prefix: "${", Suffix: "}", Holder: "ExtIntf", Type: reflect.String},
		},
	},

	"ConfigFirewallIpPool": {
		Content: `config firewall ippool
edit "${PoolName}"
    set type overload
    set startip ${StartIp}
    set endip ${EndIp}
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "PoolName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "StartIp", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "EndIp", Type: reflect.String},
		},
	},

	"ConfigFirewallIpPoolFixPortRange": {
		Content: `config firewall ippool
edit "${PoolName}"
	set type fixed-port-range
	set startip ${StartIp}
	set endip ${EndIp}
	set source-startip ${SourceStartIp}
	set source-endip ${SourceEndIp}
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "PoolName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "StartIp", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "EndIp", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "SourceStartIp", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "SourceEndIp", Type: reflect.String},
		},
	},

	"ConfigFirewallPolicyForVip": {
		Content: `config firewall policy
edit ${ID}
	set name "${PolicyName}"
	set srcintf "${SrcIntf}"
	set dstintf "${DstIntf}"
	set action accept
	set srcaddr ${SrcAddrArray}
	set dstaddr ${DstAddrArray}
	set schedule "always"
	set service ${ServiceArray}
    set nat enable
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "ID", Type: reflect.Int},
			{Prefix: "${", Suffix: "}", Holder: "PolicyName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "SrcIntf", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "DstIntf", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "SrcAddrArray", Type: reflect.Array},
			{Prefix: "${", Suffix: "}", Holder: "DstAddrArray", Type: reflect.Array},
			{Prefix: "${", Suffix: "}", Holder: "ServiceArray", Type: reflect.Array},
		},
	},

	"ConfigFirewallPolicyForPool": {
		Content: `config firewall policy
edit ${ID}
	set name "${PolicyName}"
	set srcintf "${SrcIntf}"
	set dstintf "${DstIntf}"
	set action accept
	set srcaddr ${SrcAddrArray}
	set dstaddr ${DstAddrArray}
	set schedule "always"
	set service ${ServiceArray}
	set nat enable
    set ippool enable
    set poolname "${PoolName}"
next
end`,
		Placeholders: []Placeholder{
			{Prefix: "${", Suffix: "}", Holder: "ID", Type: reflect.Int},
			{Prefix: "${", Suffix: "}", Holder: "PolicyName", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "SrcIntf", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "DstIntf", Type: reflect.String},
			{Prefix: "${", Suffix: "}", Holder: "SrcAddrArray", Type: reflect.Array},
			{Prefix: "${", Suffix: "}", Holder: "DstAddrArray", Type: reflect.Array},
			{Prefix: "${", Suffix: "}", Holder: "ServiceArray", Type: reflect.Array},
			{Prefix: "${", Suffix: "}", Holder: "PoolName", Type: reflect.String},
		},
	},
}

type CliTemplate struct {
	Content      string
	Placeholders []Placeholder
}

type Placeholder struct {
	Prefix string
	Suffix string
	Holder string
	Type   reflect.Kind
}

type ParamPair struct {
	S string
	V any
}

func (ct *CliTemplate) Formatter(pairs []ParamPair) string {
	if ct.Content == "" {
		return ""
	}

	if len(pairs) == 0 {
		return ct.Content
	}

	content := ct.Content
	for _, holder := range ct.Placeholders {
		for _, pair := range pairs {
			if holder.Holder == pair.S {
				switch holder.Type {
				case reflect.String:
					content = strings.ReplaceAll(content, fmt.Sprintf("%s%s%s", holder.Prefix, holder.Holder, holder.Suffix), pair.V.(string))
				case reflect.Int:
					content = strings.ReplaceAll(content, fmt.Sprintf("%s%s%s", holder.Prefix, holder.Holder, holder.Suffix), fmt.Sprintf("%d", pair.V.(int)))
				case reflect.Array:
					var value string
					vs := pair.V.([]string)
					for _, v := range vs {
						v = "\"" + v + "\""
					}
					value = strings.Join(vs, " ")
					content = strings.ReplaceAll(content, fmt.Sprintf("%s%s%s", holder.Prefix, holder.Holder, holder.Suffix), value)
				}
				break
			}
		}
	}
	return content
}
