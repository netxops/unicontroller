package asa

import (
	"errors"
	"fmt"
	"github.com/netxops/utils/validator"
	"strconv"
	"strings"
)

var ASA_ProtocolToNum = map[string]int{
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

var ASA_NumToProtocol = map[int]string{
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
	//50:  "ipsec",
	//47:  "pptp",
	256: "tcp-udp",
}

var ASA_TCP_P2N = map[string]int{
	"aol":             5120,
	"bgp":             179,
	"chargen":         19,
	"cifs":            3020,
	"citrix-ica":      1494,
	"cmd":             514,
	"ctiqbe":          2748,
	"daytime":         13,
	"discard":         9,
	"domain":          53,
	"echo":            7,
	"exec":            512,
	"finger":          79,
	"ftp":             21,
	"ftp-data":        20,
	"gopher":          70,
	"h323":            1720,
	"hostname":        101,
	"http":            80,
	"https":           443,
	"ident":           113,
	"imap4":           143,
	"irc":             194,
	"kerberos":        88,
	"klogin":          543,
	"kshell":          544,
	"ldap":            389,
	"ldaps":           636,
	"login":           513,
	"lotusnotes":      1352,
	"lpd":             515,
	"netbios-ssn":     139,
	"nfs":             2049,
	"nntp":            119,
	"pcanywhere-data": 5631,
	"pim-auto-rp":     496,
	"pop2":            109,
	"pop3":            110,
	"pptp":            1723,
	"rsh":             514,
	"rtsp":            554,
	"sip":             5060,
	"smtp":            25,
	"sqlnet":          1521,
	"ssh":             22,
	"sunrpc":          111,
	"tacacs":          49,
	"talk":            517,
	"telnet":          23,
	"uucp":            540,
	"whois":           43,
	"www":             80,
}

var ASA_TCP_N2P = map[int]string{
	5120: "aol",
	179:  "bgp",
	19:   "chargen",
	3020: "cifs",
	1494: "citrix-ica",
	//514:  "cmd",
	2748: "ctiqbe",
	13:   "daytime",
	9:    "discard",
	53:   "domain",
	7:    "echo",
	512:  "exec",
	79:   "finger",
	21:   "ftp",
	20:   "ftp-data",
	70:   "gopher",
	1720: "h323",
	101:  "hostname",
	//80:   "http",
	443:  "https",
	113:  "ident",
	143:  "imap4",
	194:  "irc",
	88:   "kerberos",
	543:  "klogin",
	544:  "kshell",
	389:  "ldap",
	636:  "ldaps",
	513:  "login",
	1352: "lotusnotes",
	515:  "lpd",
	139:  "netbios-ssn",
	2049: "nfs",
	119:  "nntp",
	5631: "pcanywhere-data",
	496:  "pim-auto-rp",
	109:  "pop2",
	110:  "pop3",
	1723: "pptp",
	514:  "rsh",
	554:  "rtsp",
	5060: "sip",
	25:   "smtp",
	1521: "sqlnet",
	22:   "ssh",
	111:  "sunrpc",
	49:   "tacacs",
	517:  "talk",
	23:   "telnet",
	540:  "uucp",
	43:   "whois",
	80:   "www",
}

var ASA_UDP_P2N = map[string]int{
	"biff":              512,
	"bootpc":            68,
	"bootps":            67,
	"cifs":              3020,
	"discard":           9,
	"dnsix":             90,
	"domain":            53,
	"echo":              7,
	"http":              80,
	"isakmp":            500,
	"kerberos":          750,
	"mobile-ip":         434,
	"nameserver":        42,
	"netbios-dgm":       138,
	"netbios-ns":        137,
	"nfs":               2049,
	"ntp":               123,
	"pcanywhere-status": 5632,
	"pim-auto-rp":       496,
	"radius":            1645,
	"radius-acct":       1646,
	"rip":               520,
	"secureid-udp":      5510,
	"sip":               5060,
	"snmp":              161,
	"snmptrap":          162,
	"sunrpc":            111,
	"syslog":            514,
	"tacacs":            49,
	"talk":              517,
	"tftp":              69,
	"time":              37,
	"who":               513,
	"whois":             43,
	"www":               80,
	"xdmcp":             177,
}

var ASA_UDP_N2P = map[int]string{
	512:  "biff",
	68:   "bootpc",
	67:   "bootps",
	3020: "cifs",
	9:    "discard",
	90:   "dnsix",
	53:   "domain",
	7:    "echo",
	//80:   "http",
	500:  "isakmp",
	750:  "kerberos",
	434:  "mobile-ip",
	42:   "nameserver",
	138:  "netbios-dgm",
	137:  "netbios-ns",
	2049: "nfs",
	123:  "ntp",
	5632: "pcanywhere-status",
	496:  "pim-auto-rp",
	1645: "radius",
	1646: "radius-acct",
	520:  "rip",
	5510: "secureid-udp",
	5060: "sip",
	161:  "snmp",
	162:  "snmptrap",
	111:  "sunrpc",
	514:  "syslog",
	49:   "tacacs",
	517:  "talk",
	69:   "tftp",
	37:   "time",
	513:  "who",
	43:   "whois",
	80:   "www",
	177:  "xdmcp",
}

var TCP_UDP_P2N = map[string]int{
	"cifs":        3020,
	"discard":     9,
	"domain":      53,
	"echo":        7,
	"http":        80,
	"kerberos":    88,
	"nfs":         2049,
	"pim-auto-rp": 496,
	"sip":         5060,
	"sunrpc":      111,
	"tacacs":      49,
	"talk":        517,
	"www":         80,
}

var ASA_ICMP_P2N = map[string]int{
	"alternate-address":    6,
	"conversion-error":     31,
	"echo":                 8,
	"echo-reply":           0,
	"information-reply":    16,
	"information-request":  15,
	"mask-reply":           18,
	"mask-request":         17,
	"mobile-redirect":      32,
	"parameter-problem":    12,
	"redirect":             5,
	"router-advertisement": 9,
	"router-solicitation":  10,
	"source-quench":        4,
	"time-exceeded":        11,
	"timestamp-reply":      14,
	"timestamp-request":    13,
	"traceroute":           30,
	"unreachable":          3,
}

var ASA_ICMP_N2P = map[int]string{
	6:  "alternate-address",
	31: "conversion-error",
	8:  "echo",
	0:  "echo-reply",
	16: "information-reply",
	15: "information-request",
	18: "mask-reply",
	17: "mask-request",
	32: "mobile-redirect",
	12: "parameter-problem",
	5:  "redirect",
	9:  "router-advertisement",
	10: "router-solicitation",
	4:  "source-quench",
	11: "time-exceeded",
	14: "timestamp-reply",
	13: "timestamp-request",
	30: "traceroute",
	3:  "unreachable",
}

var ASA_ICMP6_P2N = map[string]int{
	"echo":                   128,
	"echo-reply":             129,
	"membership-query":       130,
	"membership-reduction":   132,
	"membership-report":      131,
	"neighbor-advertisement": 136,
	"neighbor-redirect":      137,
	"neighbor-solicitation":  135,
	"packet-too-big":         2,
	"parameter-problem":      4,
	"router-advertisement":   134,
	"router-renumbering":     138,
	"router-solicitation":    133,
	"time-exceeded":          3,
	"unreachable":            1,
}

var ASA_ICMP6_N2P = map[int]string{
	128: "echo",
	129: "echo-reply",
	130: "membership-query",
	132: "membership-reduction",
	131: "membership-report",
	136: "neighbor-advertisement",
	137: "neighbor-redirect",
	135: "neighbor-solicitation",
	2:   "packet-too-big",
	4:   "parameter-problem",
	134: "router-advertisement",
	138: "router-renumbering",
	133: "router-solicitation",
	3:   "time-exceeded",
	1:   "unreachable",
}

func ASATcpPortParse(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}

	s1 := strings.ToLower(s)
	v, ok := ASA_TCP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("not support tcp port %s", s))
	}
	return v, nil
}

func ASAUdpPortParse(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}

	s1 := strings.ToLower(s)
	v, ok := ASA_UDP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support udp port %s", s))
	}
	return v, nil
}

func ASATcpUdpPortParse(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}

	s1 := strings.ToLower(s)
	v, ok := TCP_UDP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support tcp-udp port %s", s))
	}
	return v, nil
}

func ASAParseProtocol(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}
	s1 := strings.ToLower(s)
	v, ok := ASA_ProtocolToNum[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support protocol %s", s))
	}
	return v, nil

}

func ASAPortParse(port string, protocol string) (int, error) {
	p, err := ASAParseProtocol(protocol)
	if err != nil {
		return -1, err
	}
	if p == 6 {
		return ASATcpPortParse(port)
	} else if p == 17 {
		return ASAUdpPortParse(port)
	} else if p == 256 {
		return ASATcpUdpPortParse(port)
	}

	return -1, errors.New(fmt.Sprintf("Not support protocol %s(%d)", protocol, p))
}

func ASAIcmpParse(name string) (int, error) {
	if validator.IsInt(name) {
		p, err := strconv.Atoi(name)
		return p, err
	}
	s1 := strings.ToLower(name)

	v, ok := ASA_ICMP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support icmp_type %s", name))
	}
	return v, nil

}

func ASAIcmp6Parse(name string) (int, error) {
	if validator.IsInt(name) {
		p, err := strconv.Atoi(name)
		return p, err
	}
	s1 := strings.ToLower(name)

	v, ok := ASA_ICMP6_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support icmp_type %s", name))
	}
	return v, nil

}
