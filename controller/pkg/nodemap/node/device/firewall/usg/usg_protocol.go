package usg

import (
	"fmt"
	"strings"

	"github.com/netxops/utils/service"
)

var Usg_Services = map[string]string{
	"ad":                "udp:--|1773",
	"ah":                "51", // Authentication Header
	"esp":               "50", // Encapsulating Security Payload
	"gre":               "47", // Generic Routing Encapsulation
	"igmp":              "2",  // Internet Group Management Protocol
	"ipinip":            "4",  // IP in IP (encapsulation)
	"ospf":              "89", // Open Shortest Path First
	"icmp":              "1",  // Internet Control Message Protocol
	"icmpv6":            "58", // Internet Control Message Protocol version 6
	"tcp":               "6",  // Transmission Control Protocol
	"udp":               "17", // User Datagram Protocol
	"stcp":              "132",
	"bgp":               "tcp:--|179",
	"biff":              "udp:--|512",
	"bootpc":            "udp:--|68",
	"bootps":            "udp:--|67",
	"chargen":           "tcp:--|19",
	"daytime":           "tcp:--|13",
	"diameter":          "tcp:--|3868,sctp:--|3868",
	"discard-tcp":       "tcp:--|9",
	"discard-udp":       "udp:--|9",
	"dns":               "udp:--|53",
	"dns-tcp":           "tcp:--|53",
	"dnsix":             "udp:--|90",
	"echo-tcp":          "tcp:--|7",
	"echo-udp":          "udp:--|7",
	"exec":              "tcp:--|512",
	"finger":            "tcp:--|79",
	"ftp":               "tcp:--|21",
	"gopher":            "tcp:--|70",
	"gtpc":              "udp:--|2123",
	"gtpu":              "udp:--|2152",
	"gtpv0":             "udp:--|3386",
	"h225":              "tcp:--|1720",
	"h323":              "tcp:--|1719",
	"hostname":          "tcp:--|101",
	"http":              "tcp:--|80",
	"https":             "tcp:--|443",
	"hwcc":              "udp:--|10000",
	"ils":               "tcp:--|1002",
	"imap":              "tcp:--|143",
	"imaps":             "tcp:--|993",
	"irc":               "tcp:--|194",
	"kerberos-tcp":      "tcp:--|88",
	"kerberos-udp":      "udp:--|88",
	"klogin":            "tcp:--|543",
	"kshell":            "tcp:--|544",
	"l2tp":              "udp:--|1701",
	"login":             "tcp:--|513",
	"lpd":               "tcp:--|515",
	"mgcp":              "udp:--|2727",
	"mms":               "tcp:--|1755",
	"mobileip-ag":       "udp:--|434",
	"mobileip-mn":       "udp:--|435",
	"msn":               "tcp:--|1863",
	"msn-audio":         "udp:--|7001",
	"msn-discard":       "udp:--|9",
	"msn-stun":          "udp:--|3478",
	"mysql":             "tcp:--|3306",
	"nameserver":        "udp:--|42",
	"netbios-datagram":  "udp:--|138",
	"netbios-name":      "udp:--|137",
	"netbios-session":   "tcp:--|139",
	"netbios-ssn":       "udp:--|139",
	"nntp":              "tcp:--|119",
	"ntp":               "udp:--|123",
	"pop2":              "tcp:--|109",
	"pop3":              "tcp:--|110",
	"pop3s":             "tcp:--|995",
	"portalserver":      "udp:--|62314",
	"pptp":              "tcp:--|1723",
	"qq":                "udp:--|8000",
	"radius":            "udp:--|1812",
	"radius-accounting": "udp:--|1813",
	"ras":               "udp:--|1719",
	"rdp-tcp":           "tcp:--|3389",
	"rdp-udp":           "udp:--|3389",
	"rip":               "udp:--|520",
	"rpc":               "tcp:--|135,udp:--|135",
	"rsh":               "tcp:--|514",
	"rtsp":              "udp:--|554,tcp:--|554",
	"sccp":              "tcp:--|2000",
	"sip":               "udp:--|5060,tcp:--|5060",
	"smb":               "tcp:--|445",
	"smtp":              "tcp:--|25",
	"smtps":             "tcp:--|465",
	"snmp":              "udp:--|161",
	"snmptrap":          "udp:--|162",
	"sqlnet":            "tcp:--|1521",
	"sqlserver":         "tcp:--|1433",
	"ssh":               "tcp:--|22",
	"sunrpc-tcp":        "tcp:--|111",
	"sunrpc-udp":        "udp:--|111",
	"syslog":            "udp:--|514",
	"tacacs":            "tcp:--|49",
	"tacacs-ds":         "udp:--|65",
	"talk-tcp":          "tcp:--|517",
	"talk-udp":          "udp:--|517",
	"telnet":            "tcp:--|23",
	"tftp":              "udp:--|69",
	"time-tcp":          "tcp:--|37",
	"time-udp":          "udp:--|37",
	"uucp":              "tcp:--|540",
	"vxlan":             "udp:--|4789",
	"who":               "udp:--|513",
	"whois":             "tcp:--|43",
	"xdmcp":             "udp:--|177",
	"www":               "tcp:--|80",
}

var Usg_ICMP_Types = map[string]string{
	"echo":                 "8,0",
	"echo-reply":           "0,0",
	"fragmentneed-DFset":   "3,4",
	"host-redirect":        "5,1",
	"host-tos-redirect":    "5,3",
	"host-unreachable":     "3,1",
	"information-reply":    "16,0",
	"information-request":  "15,0",
	"net-redirect":         "5,0",
	"net-tos-redirect":     "5,2",
	"net-unreachable":      "3,0",
	"parameter-problem":    "12,0",
	"port-unreachable":     "3,3",
	"protocol-unreachable": "3,2",
	"reassembly-timeout":   "11,1",
	"source-quench":        "4,0",
	"source-route-failed":  "3,5",
	"timestamp-reply":      "14,0",
	"timestamp-request":    "13,0",
	"ttl-exceeded":         "11,0",
}

var Usg_ICMPv6_Types = map[string]string{
	"Redirect":               "137,0",
	"echo":                   "128,0",
	"echo-reply":             "129,0",
	"err-Header-field":       "4,0",
	"frag-time-exceeded":     "3,1",
	"hop-limit-exceeded":     "3,0",
	"host-admin-prohib":      "1,1",
	"host-unreachable":       "1,3",
	"neighbor-advertisement": "136,0",
	"neighbor-solicitation":  "135,0",
	"network-unreachable":    "1,0",
	"packet-too-big":         "2,0",
	"port-unreachable":       "1,4",
	"router-advertisement":   "134,0",
	"router-solicitation":    "133,0",
	"unknown-ipv6-opt":       "4,2",
	"unknown-next-hdr":       "4,1",
}

// UsgBuiltinService 根据内置服务名称返回对应的 service.Service 对象
func UsgBuiltinService(name string) (*service.Service, bool) {
	lowerName := strings.ToLower(name)
	definition, ok := Usg_Services[lowerName]
	if ok {
		srv, err := service.NewServiceFromString(definition)
		return srv, err == nil
	}

	// // 检查是否为ICMP类型
	// if strings.HasPrefix(lowerName, "icmp-") {
	// 	icmpType := strings.TrimPrefix(lowerName, "icmp-")
	// 	typeCode, ok := Usg_ICMP_Types[strings.ToLower(icmpType)]
	// 	if ok {
	// 		return createICMPService(service.ICMP, typeCode)
	// 	}
	// }

	// // 检查是否为ICMPv6类型
	// if strings.HasPrefix(lowerName, "icmpv6-") {
	// 	icmpv6Type := strings.TrimPrefix(lowerName, "icmpv6-")
	// 	typeCode, ok := Usg_ICMPv6_Types[strings.ToLower(icmpv6Type)]
	// 	if ok {
	// 		return createICMPService(service.ICMP6, typeCode)
	// 	}
	// }

	return nil, false
}

func createICMPService(proto service.IPProto, typeCode string) (*service.Service, bool) {
	parts := strings.Split(typeCode, ",")
	if len(parts) != 2 {
		return nil, false
	}

	icmpType := atoi(parts[0])
	icmpCode := atoi(parts[1])

	icmpProto, err := service.NewICMPProto(proto, icmpType, icmpCode)
	if err != nil {
		return nil, false
	}

	srv := &service.Service{}
	srv.Add(icmpProto)
	return srv, true
}

func atoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}
