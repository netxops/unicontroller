package templates

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/name"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/validator"
)

func Simple(data interface{}) string {
	switch data.(type) {
	case *name.PolicyNamingInput:
		input := data.(*name.PolicyNamingInput)
		ng := input.Group
		if ng.AddressType() == network.HOST {
			net := ng.GenerateNetwork()
			return fmt.Sprintf("FROM_%s_TO_%s_DST_%s", input.From, input.To, net.First().String())
		} else if ng.AddressType() == network.SUBNET {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPNet).IP
			mask := net.(*network.IPNet).Mask
			return fmt.Sprintf("FROM_%s_TO_%s_DST_%s_%d", input.From, input.To, ip, mask.Prefix())
		} else if ng.AddressType() == network.RANGE {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPRange)
			return fmt.Sprintf("FROM_%s_TO_%s_DST_%s-%s", input.From, input.To, ip.First(), ip.Last())
		} else {
			panic("Formatter process error")
		}
	case *name.VipNamingInput:
		input := data.(*name.VipNamingInput)
		ng := input.Group
		if ng.AddressType() == network.HOST {
			net := ng.GenerateNetwork()
			simple := input.Service.MustSimpleServiceEntry()
			if simple.Protocol() == service.IP {
				return fmt.Sprintf("%s_%s", net.First().String(), input.Protocol)
			}
			l4Srv := simple.(*service.L4Service)
			l4Srv.WithStrFunc(func() string {
				return fmt.Sprintf("%d", l4Srv.DstPort().List()[0].Low())
			})
			if l4Srv.String() == "" {
				return fmt.Sprintf("%s_%s", net.First().String(), input.Protocol)
			} else {
				return fmt.Sprintf("%s_%s_%s", net.First().String(), input.Protocol, l4Srv.String())
			}

		} else if ng.AddressType() == network.SUBNET {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPNet).IP
			mask := net.(*network.IPNet).Mask
			return fmt.Sprintf("%s_%d_%s_%s", ip, mask.Prefix(), input.Protocol, input.Port)
		} else if ng.AddressType() == network.RANGE {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPRange)
			return fmt.Sprintf("%s-%s_%s_%s", ip.First(), ip.Last(), input.Protocol, input.Port)
		} else {
			panic("Formatter process error")
		}
	case *name.NetworkNamingInput:
		ng := data.(*name.NetworkNamingInput).Group
		if ng.AddressType() == network.HOST {
			net := ng.GenerateNetwork()
			return net.First().String()
		} else if ng.AddressType() == network.SUBNET {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPNet).IP
			mask := net.(*network.IPNet).Mask
			return fmt.Sprintf("%s_%d", ip, mask.Prefix())
		} else if ng.AddressType() == network.RANGE {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPRange)
			return fmt.Sprintf("%s-%s", ip.First(), ip.Last())
		} else {
			panic("Formatter process error")
		}
	case *name.PoolNamingInput:
		ng := data.(*name.PoolNamingInput).Group
		netCli := ""
		if ng.AddressType() == network.HOST {
			net := ng.GenerateNetwork()
			netCli = net.First().String()
		} else if ng.AddressType() == network.SUBNET {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPNet).IP
			mask := net.(*network.IPNet).Mask
			netCli = fmt.Sprintf("%s_%d", ip, mask.Prefix())
		} else if ng.AddressType() == network.RANGE {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPRange)
			netCli = fmt.Sprintf("%s_%s", ip.First(), ip.Last())
		} else {
			panic("Formatter process error")
		}
		return netCli
	case *name.ServiceNamingInput:
		s := data.(*name.ServiceNamingInput).Service
		one := s.MustOneServiceEntry()
		switch one.(type) {
		case *service.L3Protocol:
			one.WithStrFunc(func() string {
				p := one.Protocol().String()
				if validator.IsInt(p) {
					return strings.ToUpper("P" + one.Protocol().String())
				} else {
					return strings.ToUpper(one.Protocol().String())
				}
			})
			return one.String()
		case *service.ICMPProto:
			ts := []string{strings.ToUpper(one.Protocol().String())}
			if one.(*service.ICMPProto).IcmpType != service.ICMP_DEFAULT_TYPE {
				ts = append(ts, fmt.Sprintf("T%d", one.(*service.ICMPProto).IcmpType))
				if one.(*service.ICMPProto).IcmpCode != service.ICMP_DEFAULT_CODE {
					ts = append(ts, fmt.Sprintf("C%d", one.(*service.ICMPProto).IcmpCode))
				}
			}
			return strings.Join(ts, "")
		case *service.L4Service:
			ts := []string{strings.ToUpper(one.Protocol().String())}
			l4, _ := service.NewL4Port(service.RANGE, 0, 65535, 0)
			if !(one.(*service.L4Service).SrcPort().Same(l4) || one.(*service.L4Service).DstPort().Same(l4)) {
				panic("sport or dport is not match 0 to 65535")
			}
			if one.(*service.L4Service).SrcPort().Same(l4) {
				if len(one.(*service.L4Service).DstPort().DataRange.L) > 1 {
					panic("dport is not multiple section")
				}
				entry := one.(*service.L4Service).DstPort().DataRange.L[0]
				if entry.Low().Cmp(entry.High()) == 0 {
					ts = append(ts, fmt.Sprintf("%d", entry.Low()))
				} else {
					ts = append(ts, fmt.Sprintf("%dto%d", entry.Low(), entry.High()))
				}
			} else {
				if len(one.(*service.L4Service).SrcPort().DataRange.L) > 1 {
					panic("sport is not multiple section")
				}
				entry := one.(*service.L4Service).SrcPort().DataRange.L[0]
				if entry.Low().Cmp(entry.High()) == 0 {
					ts = append(ts, fmt.Sprintf("S%d", entry.Low()))
				} else {
					ts = append(ts, fmt.Sprintf("S%dto%d", entry.Low(), entry.High()))
				}

			}

			return strings.Join(ts, "")
		}

	}
	panic("unknown error")
}
