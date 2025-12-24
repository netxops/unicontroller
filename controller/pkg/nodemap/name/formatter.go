package name

import (
	"fmt"
	"strings"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"
	"github.com/netxops/utils/validator"

	"github.com/flosch/pongo2/v4"
	"github.com/gofrs/uuid"
	"github.com/sony/sonyflake"
)

var (
	DefaultNameFunc = []string{"TICKET", "ITEMID", "SIMPLE", "UUID", "SHORT_ID6", "SHORT_ID8", "SHORT_ID16"}
)

type Formatter struct {
	Format  string
	Sep     string
	callMap map[string]func(interface{}) string
}

func (fm *Formatter) WithFunc(key string, f func(data interface{}) string) *Formatter {
	if fm.callMap == nil {
		fm.callMap = map[string]func(interface{}) string{}
	}
	fm.callMap[strings.ToUpper(key)] = f
	return fm
}

func (fm *Formatter) Name(data interface{}) (create string, err error) {
	tpl, err := pongo2.FromString(fm.Format)
	if err != nil {
		return
	}

	sectionRegexMap := map[string]string{
		"regex": `{{(?P<token>\w+)}}`,
		"name":  "section",
		"pcre":  "true",
		"flag":  "m",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, fm.Format)
	if err != nil {
		return
		// return "", err
	}

	// section := strings.Split(fm.Format, fm.Sep)
	// tokens := map[string]string{}
	context := pongo2.Context{}
	for it := sectionResult.Iterator(); it.HasNext(); {
		_, _, sectionMap := it.Next()

		s := sectionMap["token"]
		a := strings.TrimLeft(s, "{{")
		a = strings.TrimRight(a, "}}")
		switch strings.ToUpper(s) {
		case "TICKET":
			if _, ok := fm.callMap[strings.ToUpper(a)]; ok {
				context[a] = fm.callMap[strings.ToUpper(a)](data)
			} else {
				context[a] = fm.TicketNumber(data)
			}
		case "ITEMID":
			if _, ok := fm.callMap[strings.ToUpper(a)]; ok {
				context[a] = fm.callMap[strings.ToUpper(a)](data)
			} else {
				context[a] = fm.SubTicket(data)
			}
		case "SIMPLE":
			if _, ok := fm.callMap[strings.ToUpper(a)]; ok {
				context[a] = fm.callMap[strings.ToUpper(a)](data)
			} else {
				context[a] = fm.Simple(data)
			}
		default:
			if _, ok := fm.callMap[strings.ToUpper(a)]; ok {
				context[a] = fm.callMap[strings.ToUpper(a)](data)
			} else {
				err = fmt.Errorf("unknown token: %s", a)
				return
			}
		}
	}

	create, err = tpl.Execute(context)
	if err != nil {
		return
	}

	if data.(NamingInput).Addition() != "" {
		create = strings.Join([]string{create, data.(NamingInput).Addition()}, fm.Sep)
	}

	return
}

func (fm *Formatter) TicketNumber(data interface{}) string {
	input := data.(NamingInput)
	return input.Intent().TicketNumber
}

func (fm *Formatter) SubTicket(data interface{}) string {
	input := data.(NamingInput)
	return input.Intent().SubTicket
}

func UUID(data interface{}) string {
	return uuid.Must(uuid.NewV4()).String()
}

func ShortId6(data interface{}) string {
	return strings.ToUpper(genSonyflake())[0:6]
}

func ShortId8(data interface{}) string {
	return strings.ToUpper(genSonyflake())[0:8]
}

func ShortId16(data interface{}) string {
	return ShortId8(data) + ShortId8(data)
}

func genSonyflake() string {
	flake := sonyflake.NewSonyflake(sonyflake.Settings{})
	id, err := flake.NextID()
	if err != nil {
		panic(err)
		// log.Fatalf("flake.NextID() failed with %s\n", err)
	}
	idS := fmt.Sprintf("%x", id)
	if len(idS) < 15 {
		panic("len of id has less than 16")
	}
	return idS
	// Note: this is base16, could shorten by encoding as base62 string
	// fmt.Printf("github.com/sony/sonyflake:      %x\n", id)
}

func (fm *Formatter) Simple(data interface{}) string {
	// input := data.(*NamingInput)
	switch data.(type) {
	case *PoolNamingInput:
		ng := data.(*PoolNamingInput).Group
		netCli := ""
		if ng.AddressType() == network.HOST {
			net := ng.GenerateNetwork()
			netCli = net.First().String()
		} else if ng.AddressType() == network.SUBNET {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPNet).IP
			mask := net.(*network.IPNet).Mask
			netCli = fmt.Sprintf("%s/%d", ip, mask.Prefix())
		} else if ng.AddressType() == network.RANGE {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPRange)
			netCli = fmt.Sprintf("%s_%s", ip.First(), ip.Last())
		} else {
			panic("Formatter process error")
		}
		return netCli

	case *NetworkNamingInput:
		ng := data.(*NetworkNamingInput).Group
		if ng.AddressType() == network.HOST {
			net := ng.GenerateNetwork()
			return net.First().String()
		} else if ng.AddressType() == network.SUBNET {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPNet).IP
			mask := net.(*network.IPNet).Mask
			return fmt.Sprintf("%s_P%d", ip, mask.Prefix())
		} else if ng.AddressType() == network.RANGE {
			net := ng.GenerateNetwork()
			ip := net.(*network.IPRange)
			return fmt.Sprintf("%s_%s", ip.First(), ip.Last())
		} else {
			panic("Formatter process error")
		}
	case *ServiceNamingInput:
		s := data.(*ServiceNamingInput).Service
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

func NewFormatter(format, sep string, callMap map[string]func(interface{}) string) *Formatter {
	tokens := []string{}
	if callMap != nil {
		for key, _ := range callMap {
			tokens = append(tokens, strings.ToUpper(key))
		}
	}

	for _, key := range DefaultNameFunc {
		if !tools.ContainsWithoutCase(tokens, key) {
			tokens = append(tokens, strings.ToUpper(key))
		}
	}

	sectionRegexMap := map[string]string{
		"regex": `{{(?P<token>\w+)}}`,
		"name":  "section",
		"pcre":  "true",
		"flag":  "m",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, format)
	if err != nil {
		panic(err)
	}

	formatter := &Formatter{
		Format: format,
		Sep:    sep,
	}

	for it := sectionResult.Iterator(); it.HasNext(); {
		_, _, sectionMap := it.Next()
		token := sectionMap["token"]

		if !tools.ContainsWithoutCase(tokens, token) {
			panic(fmt.Errorf("can not find token: %s's naming function ", token))
		}
	}

	if callMap != nil {
		for key, f := range callMap {
			formatter.WithFunc(key, f)
		}
	}

	return formatter
}
