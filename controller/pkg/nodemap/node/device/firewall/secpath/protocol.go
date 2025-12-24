package secpath

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/netxops/utils/service"
	"github.com/netxops/utils/validator"
)

var SECPATH_ProtocolToNum = map[string]int{
	"ah":      51,
	"icmp6":   58,
	"eigrp":   88,
	"esp":     50,
	"gre":     47,
	"icmp":    1,
	"igmp":    2,
	"igrp":    9,
	"ip":      255,
	"ipinip":  4,
	"nos":     94,
	"ospf":    89,
	"pcp":     108,
	"sctp":    132,
	"snp":     109,
	"tcp":     6,
	"udp":     17,
	"pim":     103,
	"ipsec":   50,
	"pptp":    47,
	"tcp-udp": 256,
}

var SECPATH_NumToProtocol = map[int]string{
	51:  "ah",
	88:  "eigrp",
	58:  "icmp6",
	50:  "esp",
	47:  "gre",
	1:   "icmp",
	2:   "igmp",
	9:   "igrp",
	255: "ip",
	4:   "ipinip",
	94:  "nos",
	89:  "ospf",
	108: "pcp",
	109: "snp",
	6:   "tcp",
	132: "sctp",
	17:  "udp",
	103: "pim",
	256: "tcp-udp",
}

var SECPATH_TCP_P2N = map[string]int{
	"3com-nbx":           2095,
	"audio-call-control": 2727,
	"bgp":                179,
	"chargen":            19,
	"cmd":                514,
	"daytime":            13,
	"discard_tcp":        9,
	"dns-tcp":            53,
	"finger":             79,
	"ftp":                21,
	"gopher":             70,
	"h323":               1720,
	"http":               80,
	"https":              443,
	"irc":                194,
	"kerberos-tcp":       88,
	"ldap-tcp":           389,
	"lotus-notes-domino": 1352,
	"lpr":                515,
	"netbios-tcp":        139,
	"netmeeting":         1720,
	"nfsd-tcp":           2049,
	"nntp":               119,
	"pop3":               110,
	"portmapper-tcp":     111,
	"pptp":               1723,
	"rexec":              512,
	"rlogin":             513,
	"rsh":                514,
	"rtsp":               554,
	"sip-tcp":            5060,
	"smb":                445,
	"smtp":               25,
	"sql-net-v1":         1521,
	"sql-net-v2":         1526,
	"ssh":                22,
	"talk":               517,
	"telnet":             23,
	"uucp":               540,
	"vnc":                5900,
	"wais":               210,
	"winframe":           1494,
	"x-windows":          6000,
}

var SECPATH_TCP_N2P = map[int]string{
	2095: "3com-nbx",
	2727: "audio-call-control",
	179:  "bgp",
	19:   "chargen",
	514:  "cmd",
	13:   "daytime",
	9:    "discard_tcp",
	53:   "dns-tcp",
	79:   "finger",
	21:   "ftp",
	70:   "gopher",
	1720: "h323",
	80:   "http",
	443:  "https",
	194:  "irc",
	88:   "kerberos-tcp",
	389:  "ldap-tcp",
	1352: "lotus-notes-domino",
	515:  "lpr",
	139:  "netbios-tcp",
	2049: "nfsd-tcp",
	119:  "nntp",
	110:  "pop3",
	111:  "portmapper-tcp",
	1723: "pptp",
	512:  "rexec",
	513:  "rlogin",
	554:  "rtsp",
	5060: "sip-tcp",
	445:  "smb",
	25:   "smtp",
	1521: "sql-net-v1",
	1526: "sql-net-v2",
	22:   "ssh",
	517:  "talk",
	23:   "telnet",
	540:  "uucp",
	5900: "vnc",
	210:  "wais",
	1494: "winframe",
	6000: "x-windows",
}

var SECPATH_UDP_P2N = map[string]int{
	"bfd-control":          3784,
	"bfd-control-multihop": 4784,
	"bfd-echo":             3785,
	"dhcp-client":          68,
	"dhcp-relay":           67,
	"dhcp-server":          67,
	"dns-udp":              53,
	"gre":                  47,
	"ike":                  500,
	"imap":                 143,
	"imapv3":               220,
	"kerberos-udp":         88,
	"l2tp":                 1701,
	"ldap-udp":             389,
	"nat-t-ipsec":          4500,
	"nbname":               137,
	"netbios-udp":          138,
	"nfsd-udp":             2049,
	"ntp":                  123,
	"portmapper-udp":       111,
	"radius-accounting":    1813,
	"radius-auth":          1812,
	"rip":                  520,
	"sip-udp":              5060,
	"sms-trap":             162,
	"snmp-request":         161,
	"snmp-trap":            162,
	"syslog":               514,
	"tftp":                 69,
	"vdo-live":             7000,
	"vrrp":                 112,
}

var SECPATH_UDP_N2P = map[int]string{
	3784: "bfd-control",
	4784: "bfd-control-multihop",
	3785: "bfd-echo",
	68:   "dhcp-client",
	67:   "dhcp-relay",
	53:   "dns-udp",
	47:   "gre",
	500:  "ike",
	143:  "imap",
	220:  "imapv3",
	88:   "kerberos-udp",
	1701: "l2tp",
	389:  "ldap-udp",
	4500: "nat-t-ipsec",
	137:  "nbname",
	138:  "netbios-udp",
	2049: "nfsd-udp",
	123:  "ntp",
	8:    "ping",
	128:  "pingv6",
	111:  "portmapper-udp",
	1813: "radius-accounting",
	1812: "radius-auth",
	520:  "rip",
	5060: "sip-udp",
	162:  "sms-trap",
	161:  "snmp-request",
	514:  "syslog",
	69:   "tftp",
	7000: "vdo-live",
	112:  "vrrp",
}

var SECPATH_TCP_UDP_P2N = map[string]int{
	"dns-tcp":        53,
	"dns-udp":        53,
	"kerberos-tcp":   88,
	"kerberos-udp":   88,
	"ldap-tcp":       389,
	"ldap-udp":       389,
	"nfsd-tcp":       2049,
	"nfsd-udp":       2049,
	"portmapper-tcp": 111,
	"portmapper-udp": 111,
	"sip-tcp":        5060,
	"sip-udp":        5060,
}

var SECPATH_ICMP_P2N = map[string]int{
	"icmp-address-mask":        17,
	"icmp-dest-unreachable":    3,
	"icmp-fragment-needed":     3,
	"icmp-fragment-reassembly": 11,
	"icmp-host-unreachable":    3,
	"icmp-info":                15,
	"icmp-parameter-problem":   12,
	"icmp-port-unreachable":    3,
	"icmp-protocol-unreach":    3,
	"icmp-redirect":            5,
	"icmp-redirect-host":       5,
	"icmp-redirect-tos-host":   5,
	"icmp-redirect-tos-net":    5,
	"icmp-source-quench":       4,
	"icmp-source-route-fail":   3,
	"icmp-time-exceeded":       11,
	"icmp-timestamp":           13,
	"icmp-traceroute":          30,
	"ping":                     8,
}

var SECPATH_ICMP_N2P = map[int]string{
	17: "icmp-address-mask",
	3:  "icmp-dest-unreachable",
	11: "icmp-time-exceeded",
	12: "icmp-parameter-problem",
	5:  "icmp-redirect",
	4:  "icmp-source-quench",
	13: "icmp-timestamp",
	30: "icmp-traceroute",
	8:  "ping",
	15: "icmp-info",
}

var SECPATH_ICMP6_P2N = map[string]int{
	"pingv6": 128,
}

var SECPATH_ICMP6_N2P = map[int]string{
	128: "pingv6",
}

func SECPATHTcpPortParse(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}

	s1 := strings.ToLower(s)
	v, ok := SECPATH_TCP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("not support tcp port %s", s))
	}
	return v, nil
}

func SECPATHUdpPortParse(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}

	s1 := strings.ToLower(s)
	v, ok := SECPATH_UDP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support udp port %s", s))
	}
	return v, nil
}

func SECPATHTcpUdpPortParse(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}

	s1 := strings.ToLower(s)
	v, ok := SECPATH_TCP_UDP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support tcp-udp port %s", s))
	}
	return v, nil
}

func SECPATHParseProtocol(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}
	s1 := strings.ToLower(s)
	v, ok := SECPATH_ProtocolToNum[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support protocol %s", s))
	}
	return v, nil
}

func SECPATHPortParse(port string, protocol string) (int, error) {
	p, err := SECPATHParseProtocol(protocol)
	if err != nil {
		return -1, err
	}
	if p == 6 {
		return SECPATHTcpPortParse(port)
	} else if p == 17 {
		return SECPATHUdpPortParse(port)
	} else if p == 256 {
		return SECPATHTcpUdpPortParse(port)
	}

	return -1, errors.New(fmt.Sprintf("Not support protocol %s(%d)", protocol, p))
}

func SECPATHIcmpParse(name string) (int, error) {
	if validator.IsInt(name) {
		p, err := strconv.Atoi(name)
		return p, err
	}
	s1 := strings.ToLower(name)

	v, ok := SECPATH_ICMP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support icmp_type %s", name))
	}
	return v, nil
}

func SECPATHIcmp6Parse(name string) (int, error) {
	if validator.IsInt(name) {
		p, err := strconv.Atoi(name)
		return p, err
	}
	s1 := strings.ToLower(name)

	v, ok := SECPATH_ICMP6_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support icmp_type %s", name))
	}
	return v, nil
}

func SECPATHNameToService(name string) (*service.Service, error) {
	// First check if it's a protocol name
	if proto, ok := SECPATH_ProtocolToNum[strings.ToLower(name)]; ok {
		switch proto {
		case 1: // ICMP
			return service.NewServiceFromString("icmp")
		case 6: // TCP
			return service.NewServiceFromString("tcp")
		case 17: // UDP
			return service.NewServiceFromString("udp")
		case 58: // ICMPv6
			return service.NewServiceFromString("icmp6")
		default:
			return service.NewServiceFromString(fmt.Sprintf("%d", proto))
		}
	}

	// Check if it's a TCP service
	if port, ok := SECPATH_TCP_P2N[strings.ToLower(name)]; ok {
		return service.NewServiceWithL4("tcp", "0-65535", fmt.Sprintf("%d", port))
	}

	// Check if it's a UDP service
	if port, ok := SECPATH_UDP_P2N[strings.ToLower(name)]; ok {
		return service.NewServiceWithL4("udp", "0-65535", fmt.Sprintf("%d", port))
	}

	// Check if it's an ICMP type
	if icmpType, ok := SECPATH_ICMP_P2N[strings.ToLower(name)]; ok {
		icmp, err := service.NewICMPProto(service.ICMP, icmpType, service.ICMP_DEFAULT_CODE)
		if err != nil {
			return nil, err
		}
		srv := &service.Service{}
		srv.Add(icmp)
		return srv, nil
	}

	// Check if it's an ICMPv6 type
	if icmp6Type, ok := SECPATH_ICMP6_P2N[strings.ToLower(name)]; ok {
		icmp6, err := service.NewICMPProto(service.ICMP6, icmp6Type, service.ICMP_DEFAULT_CODE)
		if err != nil {
			return nil, err
		}
		srv := &service.Service{}
		srv.Add(icmp6)
		return srv, nil
	}

	// Special handling for TCP-UDP services
	if port, ok := SECPATH_TCP_UDP_P2N[strings.ToLower(name)]; ok {
		// Create a service that includes both TCP and UDP with the same port
		tcpSrv, err := service.NewServiceWithL4("tcp", "0-65535", fmt.Sprintf("%d", port))
		if err != nil {
			return nil, err
		}

		udpSrv, err := service.NewServiceWithL4("udp", "0-65535", fmt.Sprintf("%d", port))
		if err != nil {
			return nil, err
		}

		// Combine the two services
		tcpSrv.Add(udpSrv)
		return tcpSrv, nil
	}

	// If we get here, the service name is not recognized
	return nil, fmt.Errorf("unknown service name: %s", name)
}

var SECPATH_ICMP_TYPE_CODE = map[string]struct {
    Type int
    Code int
}{
    "echo":                 {Type: 8, Code: 0},
    "echo-reply":           {Type: 0, Code: 0},
    "fragmentneed-DFset":   {Type: 3, Code: 4},
    "host-redirect":        {Type: 5, Code: 1},
    "host-tos-redirect":    {Type: 5, Code: 3},
    "host-unreachable":     {Type: 3, Code: 1},
    "information-reply":    {Type: 16, Code: 0},
    "information-request":  {Type: 15, Code: 0},
    "net-redirect":         {Type: 5, Code: 0},
    "net-tos-redirect":     {Type: 5, Code: 2},
    "net-unreachable":      {Type: 3, Code: 0},
    "parameter-problem":    {Type: 12, Code: 0},
    "port-unreachable":     {Type: 3, Code: 3},
    "protocol-unreachable": {Type: 3, Code: 2},
    "reassembly-timeout":   {Type: 11, Code: 1},
    "source-quench":        {Type: 4, Code: 0},
    "source-route-failed":  {Type: 3, Code: 5},
    "timestamp-reply":      {Type: 14, Code: 0},
    "timestamp-request":    {Type: 13, Code: 0},
    "ttl-exceeded":         {Type: 11, Code: 0},
}

func SECPATHICMPServiceFromString(name string) (*service.Service, error) {
    icmpInfo, ok := SECPATH_ICMP_TYPE_CODE[strings.ToLower(name)]
    if !ok {
        return nil, fmt.Errorf("unknown ICMP service name: %s", name)
    }

    icmpProto, err := service.NewICMPProto(service.ICMP, icmpInfo.Type, icmpInfo.Code)
    if err != nil {
        return nil, fmt.Errorf("error creating ICMP service: %v", err)
    }

    srv := &service.Service{}
    srv.Add(icmpProto)
    return srv, nil
}
