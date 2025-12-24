package meta

import (
	"errors"

	"github.com/influxdata/telegraf/controller/pkg/l3nodemap/constant"
	"github.com/netxops/utils/network"
)

type MetaNodeMap struct {
	Name      string     `json:"name" mapstructure:"name"`
	MetaNodes []MetaNode `json:"meta_nodes" mapstructure:"meta_nodes"`
}

func (mnm MetaNodeMap) ValidateStruct() error {
	if len(mnm.MetaNodes) == 0 {
		return errors.New("node data not be empty")
	}

	//验证MetaNode
	nodes := map[string]MetaNode{}
	for _, v := range mnm.MetaNodes {
		if _, ok := nodes[v.Name]; ok {
			return errors.New("node data contains multiple values with the same name")
		}

		if !constant.ContainsDeviceCategory(v.NodeType) {
			return errors.New("unkown node type value")
		}

		if !constant.ContainsSpecificCategory(v.Model) {
			return errors.New("unkown node model value")
		}

		if len(v.DeviceInterconnections) != 0 {
			if err := v.validateDeviceInterconnection(); err != nil {
				return err
			}
		}

		if len(v.Ipv4Areas) != 0 {
			if err := v.validateIpv4Areas(); err != nil {
				return err
			}
		}

		if len(v.Ipv6Areas) != 0 {
			if err := v.validateIpv6Areas(); err != nil {
				return err
			}
		}

		if len(v.Ipv4Stubs) != 0 {
			if err := v.validateIpv4Stubs(); err != nil {
				return err
			}
		}

		if len(v.Ipv6Stubs) != 0 {
			if err := v.validateIpv6Stubs(); err != nil {
				return err
			}
		}

		if len(v.VsRanges) != 0 {
			if err := v.validateVsRanges(); err != nil {
				return err
			}
		}
		nodes[v.Name] = v
	}

	return nil
}

func (mn MetaNode) validateDeviceInterconnection() error {
	conns := map[string]DeviceInterconnection{}
	for _, v := range mn.DeviceInterconnections {
		if _, ok := conns[v.Interface]; ok {
			return errors.New("device interconnection data[interface] contains multiple values with the same value")
		}

		if v.Vrf == "" {
			return errors.New("device interconnection data[vrf] not be empty")
		}

		if len(v.PeerVrf) == 0 {
			return errors.New("device interconnection data[peer_vrf] not be empty")
		}
	}
	return nil
}

func (mn MetaNode) validateIpv4Areas() error {
	ipv4Areas := map[string]Area{}
	for _, v := range mn.Ipv4Areas {
		if _, ok := ipv4Areas[v.Interface]; ok {
			return errors.New("device ipv4 areas data[interface] contains multiple values with the same value")
		}

		if _, ok := ipv4Areas[v.Name]; ok {
			return errors.New("device ipv4 areas data[name] contains multiple values with the same value")
		}
	}
	return nil
}

func (mn MetaNode) validateIpv6Areas() error {
	ipv6Areas := map[string]Area{}
	for _, v := range mn.Ipv6Areas {
		if _, ok := ipv6Areas[v.Interface]; ok {
			return errors.New("device ipv6 areas data[interface] contains multiple values with the same value")
		}

		if _, ok := ipv6Areas[v.Name]; ok {
			return errors.New("device ipv6 areas data[name] contains multiple values with the same value")
		}
	}
	return nil
}

func (mn MetaNode) validateVsRanges() error {
	vsRanges := map[string]VsRange{}
	for _, v := range mn.VsRanges {
		if _, ok := vsRanges[v.Network]; ok {
			return errors.New("device vs_ranges data[network] contains multiple values with the same value")
		}

		if v.Vrf == "" {
			return errors.New("device vs_ranges data[vrf] not be empty")
		}

		typeFlag := false
		switch v.Type {
		case network.IPv4.String(), network.IPv6.String():
			typeFlag = true
		default:
			typeFlag = false
		}
		if !typeFlag {
			return errors.New("unkown node.vs_range.type value")
		}
	}
	return nil
}

func (mn MetaNode) validateIpv4Stubs() error {
	ipv4Stubs := map[string]Stub{}
	for _, v := range mn.Ipv4Stubs {
		if _, ok := ipv4Stubs[v.Interface]; ok {
			return errors.New("device ipv4 stubs data[interface] contains multiple values with the same value")
		}
	}
	return nil
}

func (mn MetaNode) validateIpv6Stubs() error {
	ipv6Stubs := map[string]Stub{}
	for _, v := range mn.Ipv4Stubs {
		if _, ok := ipv6Stubs[v.Interface]; ok {
			return errors.New("device ipv6 stubs data[interface] contains multiple values with the same value")
		}
	}
	return nil
}

func (mnm MetaNodeMap) GetMetaNode(deviceName string) (bool, *MetaNode) {
	for _, v := range mnm.MetaNodes {
		if v.Name == deviceName {
			return true, &v
		}
	}
	return false, nil
}
