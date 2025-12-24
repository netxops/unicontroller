package forti

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/forti/templates"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
)

func transToNetworkObj(foriRespResult dto.ForiRespResult) *templates.NetworkObj {
	networkObj := templates.NetworkObj{}
	networkObj.Name = foriRespResult.Name
	switch foriRespResult.Type {
	case "ipmask":
		networkObj.Type = network.SUBNET
		networkObj.Interface = foriRespResult.AssociatedInterface
		if foriRespResult.Subnet != "" {
			netArr := strings.Split(foriRespResult.Subnet, " ")
			networkObj.AddressType = network.IPv4
			networkObj.Address = netArr[0]
			networkObj.Mask = netArr[1]
		}

		if foriRespResult.Ip6 != "" {
			net, err := network.ParseIPNet(foriRespResult.Ip6)
			if err != nil {
				panic(err)
			}
			networkObj.AddressType = network.IPv6
			networkObj.Address = foriRespResult.Ip6
			networkObj.IPv6PrefixLen = net.Prefix()
		}
	case "iprange":
		networkObj.Type = network.RANGE
		networkObj.Interface = foriRespResult.AssociatedInterface
		networkObj.StartIPv4Address = foriRespResult.StartIp
		networkObj.EndIPv4Address = foriRespResult.EndIp
	}
	return &networkObj
}

func transToServiceObj(foriRespResult dto.ForiRespResult) *templates.ServiceObj {
	serviceObj := templates.ServiceObj{}
	serviceObj.Name = foriRespResult.Name
	if foriRespResult.SctpPortRange != "" {
		panic(fmt.Errorf("stcp no supported"))
	}
	var sport, dport string
	var srv *service.Service
	var err error
	if foriRespResult.TcpPortRange != "" {
		sport, dport = splitPortRange(foriRespResult.TcpPortRange, ":")
		serviceObj.Protocol = "tcp"

		srv, err = service.NewServiceWithL4("tcp", sport, dport)
		if err != nil {
			panic(err)
		}
	}
	if foriRespResult.UdpPortRange != "" {
		sport, dport = splitPortRange(foriRespResult.UdpPortRange, ":")
		tmpSrv, err := service.NewServiceWithL4("udp", sport, dport)
		if err != nil {
			panic(err)
		}

		if srv == nil {
			srv = tmpSrv
		} else {
			srv.Add(tmpSrv)
		}
	}

	if foriRespResult.Protocol == "IP" {
		srv, err = service.NewServiceFromString("ip")
		if err != nil {
			panic(err)
		}
	}
	return nil
}
