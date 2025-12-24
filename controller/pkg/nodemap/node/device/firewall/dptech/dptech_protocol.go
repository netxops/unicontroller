package dptech

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/netxops/utils/service"
	"github.com/netxops/utils/validator"
)

var Dptech_ProtocolToNum = map[string]int{
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

var Dptech_NumToProtocol = map[int]string{
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

// https://github.com/xmin0s/Dptech-Session-Analyzer/blob/master/port_list.txt
// https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/ref/statement/applications-edit-destination-port.html
// var Dptech_TCP_P2N = map[string]int{
// 	"afs":            1483,
// 	"bgp":            179,
// 	"biffh":          512,
// 	"bootpc":         68,
// 	"bootps":         67,
// 	"cmd":            514,
// 	"cvspserver":     2401,
// 	"dhcp":           67,
// 	"domain":         53,
// 	"eklogin":        2105,
// 	"ekshell":        2106,
// 	"excc":           512,
// 	"finger":         79,
// 	"ftp":            21,
// 	"ftp-data":       20,
// 	"http":           80,
// 	"https":          443,
// 	"ident":          113,
// 	"imap":           143,
// 	"kerberos-sec":   88,
// 	"klogin":         543,
// 	"kpasswd":        761,
// 	"krb-prop":       754,
// 	"krbupdate":      760,
// 	"kshell":         544,
// 	"ldap":           389,
// 	"ldp":            646,
// 	"login":          513,
// 	"mobileip-agent": 434,
// 	"mobilip-mn":     435,
// 	"msdp":           639,
// 	"netbios-dgm":    138,
// 	"netbios-ns":     137,
// 	"netbios-ssn":    139,
// 	"nfsd":           2049,
// 	"nntp":           119,
// 	"ntalk":          518,
// 	"ntp":            123,
// 	"pop3":           110,
// 	"pptp":           1723,
// 	"printer":        515,
// 	"radacct":        1813,
// 	"radius":         1812,
// 	"rip":            520,
// 	"rkinit":         2108,
// 	"smtp":           25,
// 	"snmp":           161,
// 	"snmp-trap":      162,
// 	"snpp":           444,
// 	"socks":          1080,
// 	"ssh":            22,
// 	"sunrpc":         111,
// 	"syslog":         514,
// 	"tacacs":         49,
// 	"tacacs-ds":      65,
// 	"talk":           517,
// 	"telnet":         23,
// 	"tftp":           69,
// 	"timed":          525,
// 	"who":            513,
// 	"xdmcp":          177,
// 	"Zephyr-clt":     2103,
// 	"Zephyr-hm":      2104,
// 	"Zephyr-srv":     2102,
// }

// BGP            Protocol tcp source port any destination port 179
// CHARGEN        Protocol tcp source port any destination port 19
// DAYTIME        Protocol tcp source port any destination port 13
// DHCP-relay     Protocol udp source port any destination port 67
// DNS            Protocol udp source port any destination port 53
// ECHO           Protocol icmp type 8 code 0
// ECHO-reply     Protocol icmp type 0 code 0
// ECHO6          Protocol icmp6 type 128 code 0
// ECHO6-reply    Protocol icmp6 type 129 code 0
// ESP            Protocol esp
// FTP            Protocol tcp source port any destination port 21
// GOPHER         Protocol tcp source port any destination Port 70-70
// GRE            Protocol gre
// H323-TCP/389   Protocol tcp source port any destination Port 389-389
// H323-TCP/522   Protocol tcp source port any destination Port 522-522
// H323-TCP/1503  Protocol tcp source port any destination Port 1503-1503
// H323-TCP/1720  Protocol tcp source port any destination Port 1720-1720
// H323-TCP/1731  Protocol tcp source port any destination Port 1731-1731
// H323-UDP/1719  Protocol udp source port any destination Port 1719-1719
// HTTP           Protocol tcp source port any destination port 80
// HTTPS          Protocol tcp source port any destination port 443
// IMAP           Protocol tcp source port any destination port 143
// IRC            Protocol tcp source port any destination port 6660-6669
// L2TP           Protocol udp source port any destination port 1701
// LDAP           Protocol tcp source port any destination port 389
// MODBUS         Protocol tcp Source port any Destination port 502
// NNTP           Protocol tcp source port any destination port 119
// ORACLE         Protocol tcp source port any destination Port 1521-1521
// OSPF           Protocol ospf
// POP3           Protocol tcp source port any destination port 110
// PPTP           Protocol tcp source port any destination port 1723
// RDP-TCP        Protocol tcp source port any destination Port 3389-3389
// RDP-UDP        Protocol udp source port any destination Port 3389-3389
// RIP            Protocol udp source port any destination port 520
// RLOGIN         Protocol tcp source port any destination Port 513-513
// RSH            Protocol tcp source port any destination port 514
// RTSP-TCP       Protocol tcp source port any destination Port 554-554
// RTSP-UDP       Protocol udp source port any destination Port 554-554
// SIP-TCP/5060   Protocol tcp source port any destination Port 5060-5060
// SIP-UDP/5060   Protocol udp source port any destination Port 5060-5060
// SMTP           Protocol tcp source port any destination port 25
// SNMP-TCP/161   Protocol tcp source port any destination Port 161-161
// SNMP-TCP/162   Protocol tcp source port any destination Port 162-162
// SNMP-UDP/161   Protocol udp source port any destination Port 161-161
// SSH            Protocol tcp source port any destination port 22
// SYSLOG         Protocol udp source port any destination Port 514
// TALK           Protocol udp source port any destination port 517-518
// TELNET         Protocol tcp source port any destination port 23
// TFTP           Protocol udp source port any destination port 69
// TRACEROUTE     Protocol udp source port any destination Port 33434-33535
// UUCP           Protocol udp source port any destination port 540
// x-windows      Protocol tcp source port any destination port 6000-6063

var Dptech_TCP_P2N = map[string]string{
	"BGP":           "tcp:--|179",
	"CHARGEN":       "tcp:--|19",
	"DAYTIME":       "tcp:--|13",
	"DHCP-relay":    "udp:--|67",
	"DNS":           "udp:--|53",
	"ECHO":          "icmp:8|0",    // Protocol icmp type 8 code 0
	"ECHO-reply":    "icmp:0|0",    // Protocol icmp type 0 code 0
	"ECHO6":         "icmp6:128|0", // Protocol icmp6 type 128 code 0
	"ECHO6-reply":   "icmp6:129|0", // Protocol icmp6 type 129 code 0
	"ESP":           "esp",
	"FTP":           "tcp:--|21",
	"GOPHER":        "tcp:--|70-70",
	"GRE":           "gre",
	"H323-TCP/389":  "tcp:--|389-389",
	"H323-TCP/522":  "tcp:--|522-522",
	"H323-TCP/1503": "tcp:--|1503-1503",
	"H323-TCP/1720": "tcp:--|1720-1720",
	"H323-TCP/1731": "tcp:--|1731-1731",
	"H323-UDP/1719": "udp:--|1719-1719",
	"HTTP":          "tcp:--|80",
	"HTTPS":         "tcp:--|443",
	"IMAP":          "tcp:--|143",
	"IRC":           "tcp:--|6660-6669",
	"L2TP":          "udp:--|1701",
	"LDAP":          "tcp:--|389",
	"MODBUS":        "tcp:--|502",
	"NNTP":          "tcp:--|119",
	"ORACLE":        "tcp:--|1521-1521",
	"OSPF":          "ospf",
	"POP3":          "tcp:--|110",
	"PPTP":          "tcp:--|1723",
	"RDP-TCP":       "tcp:--|3389-3389",
	"RDP-UDP":       "udp:--|3389-3389",
	"RIP":           "udp:--|520",
	"RLOGIN":        "tcp:--|513-513",
	"RSH":           "tcp:--|514",
	"RTSP-TCP":      "tcp:--|554-554",
	"RTSP-UDP":      "udp:--|554-554",
	"SIP-TCP/5060":  "tcp:--|5060-5060",
	"SIP-UDP/5060":  "udp:--|5060-5060",
	"SMTP":          "tcp:--|25",
	"SNMP-TCP/161":  "tcp:--|161-161",
	"SNMP-TCP/162":  "tcp:--|162-162",
	"SNMP-UDP/161":  "udp:--|161-161",
	"SSH":           "tcp:--|22",
	"SYSLOG":        "udp:--|514",
	"TALK":          "udp:--|517-518",
	"TELNET":        "tcp:--|23",
	"TFTP":          "udp:--|69",
	"TRACEROUTE":    "udp:--|33434-33535",
	"UUCP":          "udp:--|540",
	"x-windows":     "tcp:--|6000-6063",
}

// var Dptech_TCP_N2P = map[int]string{
// 	1483: "afs",
// 	179:  "bgp",
// 	68:   "bootpc",
// 	2401: "cvspserver",
// 	67:   "dhcp",
// 	53:   "domain",
// 	2105: "eklogin",
// 	2106: "ekshell",
// 	512:  "excc",
// 	79:   "finger",
// 	21:   "ftp",
// 	20:   "ftp-data",
// 	80:   "http",
// 	443:  "https",
// 	113:  "ident",
// 	143:  "imap",
// 	88:   "kerberos-sec",
// 	543:  "klogin",
// 	761:  "kpasswd",
// 	754:  "krb-prop",
// 	760:  "krbupdate",
// 	544:  "kshell",
// 	389:  "ldap",
// 	646:  "ldp",
// 	434:  "mobileip-agent",
// 	435:  "mobilip-mn",
// 	639:  "msdp",
// 	138:  "netbios-dgm",
// 	137:  "netbios-ns",
// 	139:  "netbios-ssn",
// 	2049: "nfsd",
// 	119:  "nntp",
// 	518:  "ntalk",
// 	123:  "ntp",
// 	110:  "pop3",
// 	1723: "pptp",
// 	515:  "printer",
// 	1813: "radacct",
// 	1812: "radius",
// 	520:  "rip",
// 	2108: "rkinit",
// 	25:   "smtp",
// 	161:  "snmp",
// 	162:  "snmp-trap",
// 	444:  "snpp",
// 	1080: "socks",
// 	22:   "ssh",
// 	111:  "sunrpc",
// 	514:  "syslog",
// 	49:   "tacacs",
// 	65:   "tacacs-ds",
// 	517:  "talk",
// 	23:   "telnet",
// 	69:   "tftp",
// 	525:  "timed",
// 	513:  "who",
// 	177:  "xdmcp",
// 	2103: "Zephyr-clt",
// 	2104: "Zephyr-hm",
// 	2102: "Zephyr-srv",
// }

var Dptech_UDP_P2N = map[string]int{
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

var Dptech_UDP_N2P = map[int]string{
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

var Dptech_ICMP_P2N = map[string]int{
	"echo-request":         8,
	"echo-reply":           0,
	"info-reply":           16,
	"info-request":         15,
	"mask-reply":           18,
	"mask-request":         17,
	"mobile-redirect":      32,
	"parameter-problem":    12,
	"redirect":             5,
	"router-advertisement": 9,
	"router-solicit":       10,
	"source-quench":        4,
	"time-exceeded":        11,
	"timestamp-reply":      14,
	"timestamp":            13,
	"unreachable":          3,
}

var Dptech_ICMP_N2P = map[int]string{
	8:  "echo-request",
	0:  "echo-reply",
	16: "info-reply",
	15: "info-request",
	18: "mask-reply",
	17: "mask-request",
	32: "mobile-redirect",
	12: "parameter-problem",
	5:  "redirect",
	9:  "router-advertisement",
	10: "router-solicit",
	4:  "source-quench",
	11: "time-exceeded",
	14: "timestamp-reply",
	13: "timestamp",
	3:  "unreachable",
}

var Dptech_ICMP6_P2N = map[string]int{
	"echo-request":             128,
	"echo-reply":               129,
	"membership-query":         130,
	"membership-termination":   132,
	"membership-report":        131,
	"neighbor-advertisement":   136,
	"neighbor-redirect":        137,
	"neighbor-solicit":         135,
	"packet-too-big":           2,
	"parameter-problem":        4,
	"router-advertisement":     134,
	"router-renumbering":       138,
	"node-information-reply":   140,
	"node-information-request": 139,
	"router-solicit":           133,
	"time-exceeded":            3,
	"destination-unreachable":  1,
}

var Dptech_ICMP6_N2P = map[int]string{
	128: "echo-request",
	129: "echo-reply",
	130: "membership-query",
	132: "membership-termination",
	131: "membership-report",
	136: "neighbor-advertisement",
	137: "neighbor-redirect",
	135: "neighbor-solicit",
	2:   "packet-too-big",
	4:   "parameter-problem",
	134: "router-advertisement",
	138: "router-renumbering",
	133: "router-solicit",
	140: "node-information-reply",
	139: "node-information-request",
	3:   "time-exceeded",
	1:   "destination-unreachable",
}

// func DptechTcpPortParse(s string) (int, error) {
// 	if validator.IsInt(s) {
// 		p, err := strconv.Atoi(s)
// 		return p, err
// 	}

// 	s1 := strings.ToLower(s)
// 	v, ok := Dptech_TCP_P2N[s1]
// 	if !ok {
// 		return -1, errors.New(fmt.Sprintf("not support tcp port %s", s))
// 	}
// 	return v, nil
// }

func DptechUdpPortParse(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}

	s1 := strings.ToLower(s)
	v, ok := Dptech_UDP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support udp port %s", s))
	}
	return v, nil
}

func DptechTcpUdpPortParse(s string) (int, error) {
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

func DptechParseProtocol(s string) (int, error) {
	if validator.IsInt(s) {
		p, err := strconv.Atoi(s)
		return p, err
	}
	s1 := strings.ToLower(s)
	v, ok := Dptech_ProtocolToNum[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support protocol %s", s))
	}
	return v, nil

}

// func DptechPortParse(port string, protocol string) (int, error) {
// 	p, err := DptechParseProtocol(protocol)
// 	if err != nil {
// 		return -1, err
// 	}
// 	if p == 6 {
// 		return DptechTcpPortParse(port)
// 	} else if p == 17 {
// 		return DptechUdpPortParse(port)
// 	} else if p == 256 {
// 		return DptechTcpUdpPortParse(port)
// 	}

// 	return -1, errors.New(fmt.Sprintf("Not support protocol %s(%d)", protocol, p))
// }

func DptechIcmpParse(name string) (int, error) {
	if validator.IsInt(name) {
		p, err := strconv.Atoi(name)
		return p, err
	}
	s1 := strings.ToLower(name)

	v, ok := Dptech_ICMP_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support icmp_type %s", name))
	}
	return v, nil

}

func DptechIcmp6Parse(name string) (int, error) {
	if validator.IsInt(name) {
		p, err := strconv.Atoi(name)
		return p, err
	}
	s1 := strings.ToLower(name)

	v, ok := Dptech_ICMP6_P2N[s1]
	if !ok {
		return -1, errors.New(fmt.Sprintf("Not support icmp_type %s", name))
	}
	return v, nil

}

// DptechBuiltinService 根据内置服务名称返回对应的 service.Service 对象
func DptechBuiltinService(name string) (*service.Service, bool) {
	definition, ok := Dptech_TCP_P2N[name]
	if !ok {
		return nil, false
	}

	srv, err := service.NewServiceFromString(definition)
	
	return srv, err == nil
}
