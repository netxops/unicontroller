package secpath

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"
)

type ACLSet struct {
	objects *SecPathObjectSet
	// Sets    map[string]ACL
	Sets []*ACL
}

// 实现 TypeInterface 接口
func (as *ACLSet) TypeName() string {
	return "SecpathACLSet"
}

// aclSetJSON 用于序列化和反序列化
type aclSetJSON struct {
	Sets []*ACL `json:"sets"`
}

// MarshalJSON 实现 JSON 序列化
func (as *ACLSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(aclSetJSON{
		Sets: as.Sets,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (as *ACLSet) UnmarshalJSON(data []byte) error {
	var asj aclSetJSON
	if err := json.Unmarshal(data, &asj); err != nil {
		return err
	}

	as.Sets = asj.Sets
	// Note: objects field is not unmarshaled as it should be set separately

	return nil
}

func (as *ACLSet) GetACL(name string) *ACL {
	for _, set := range as.Sets {
		if set.Name() == name {
			return set
		}
	}
	return nil
}

type ACL struct {
	name    string
	Entries []ACLEntry
}

func (acl ACL) Name() string {
	return acl.name
}

// 实现 TypeInterface 接口
func (acl *ACL) TypeName() string {
	return "SecpathACL"
}

// aclJSON 用于序列化和反序列化
type aclJSON struct {
	Name    string     `json:"name"`
	Entries []ACLEntry `json:"entries"`
}

// MarshalJSON 实现 JSON 序列化
func (acl *ACL) MarshalJSON() ([]byte, error) {
	return json.Marshal(aclJSON{
		Name:    acl.name,
		Entries: acl.Entries,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (acl *ACL) UnmarshalJSON(data []byte) error {
	var aj aclJSON
	if err := json.Unmarshal(data, &aj); err != nil {
		return err
	}

	acl.name = aj.Name
	acl.Entries = aj.Entries

	return nil
}

func (acl ACL) Match(pe policy.PolicyEntryInf) bool {
	if len(acl.Entries) == 0 {
		return false
	}

	for _, entry := range acl.Entries {
		if entry.Match(pe) {
			return true
		}
	}

	return false
}

func (acl ACL) IsPermit(pe policy.PolicyEntryInf) bool {
	if len(acl.Entries) == 0 {
		return false
	}
	for _, entry := range acl.Entries {
		if entry.Match(pe) && entry.Action == firewall.POLICY_PERMIT {
			return true
		}
	}

	return false
}

type ACLEntry struct {
	// Name        string
	Comment     string
	Cli         string
	ID          int
	Action      firewall.Action
	Vrf         string
	PolicyEntry policy.PolicyEntryInf
}

// 实现 TypeInterface 接口
func (ae *ACLEntry) TypeName() string {
	return "SecpathACLEntry"
}

// aclEntryJSON 用于序列化和反序列化
type aclEntryJSON struct {
	Comment     string          `json:"comment"`
	Cli         string          `json:"cli"`
	ID          int             `json:"id"`
	Action      firewall.Action `json:"action"`
	Vrf         string          `json:"vrf"`
	PolicyEntry json.RawMessage `json:"policy_entry"`
}

// MarshalJSON 实现 JSON 序列化
func (ae *ACLEntry) MarshalJSON() ([]byte, error) {
	var policyEntryRaw json.RawMessage
	var err error
	if ae.PolicyEntry != nil {
		policyEntryRaw, err = registry.InterfaceToRawMessage(ae.PolicyEntry)
		if err != nil {
			return nil, fmt.Errorf("error marshaling PolicyEntry: %w", err)
		}
	}

	return json.Marshal(aclEntryJSON{
		Comment:     ae.Comment,
		Cli:         ae.Cli,
		ID:          ae.ID,
		Action:      ae.Action,
		Vrf:         ae.Vrf,
		PolicyEntry: policyEntryRaw,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ae *ACLEntry) UnmarshalJSON(data []byte) error {
	var aej aclEntryJSON
	if err := json.Unmarshal(data, &aej); err != nil {
		return err
	}

	ae.Comment = aej.Comment
	ae.Cli = aej.Cli
	ae.ID = aej.ID
	ae.Action = aej.Action
	ae.Vrf = aej.Vrf

	if string(aej.PolicyEntry) != "null" {
		policyEntry, err := registry.RawMessageToInterface[policy.PolicyEntryInf](aej.PolicyEntry)
		if err != nil {
			return fmt.Errorf("error unmarshaling PolicyEntry: %w", err)
		}
		ae.PolicyEntry = policyEntry
	} else {
		ae.PolicyEntry = nil
	}

	return nil
}

func (ae ACLEntry) Match(pe policy.PolicyEntryInf) bool {
	if ae.PolicyEntry == nil {
		return false
	}
	return ae.PolicyEntry.Match(pe)
}

func (a *ACLSet) parseAclSection(config string) error {
	// 使用 '#' 分割配置
	sections := strings.Split(config, "#")

	for _, section := range sections {
		section = strings.TrimSpace(section)
		if !strings.HasPrefix(section, "acl") {
			continue
		}

		// 使用正则表达式匹配 ACL 部分
		aclRegex := regexp.MustCompile(`^acl\s+(basic|advanced|number)\s+(\S+)`)
		match := aclRegex.FindStringSubmatch(section)

		if len(match) < 3 {
			continue
		}

		aclType := match[1]
		aclNumber := match[2]

		acl := ACL{
			name:    aclNumber,
			Entries: []ACLEntry{},
		}

		// 根据 ACL 类型调用相应的解析函数
		var err error
		switch aclType {
		case "basic", "number":
			err = a.parseBasicAcl(&acl, section)
		case "advanced":
			err = a.parseAdvancedAcl(&acl, section)
		}

		if err != nil {
			return err
		}

		a.Sets = append(a.Sets, &acl)
	}

	return nil
}

func (a *ACLSet) parseBasicAcl(acl *ACL, content string) error {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "description") {
			acl.Entries = append(acl.Entries, ACLEntry{Comment: line})
			continue
		}
		if strings.HasPrefix(line, "rule") {
			entry, err := a.parseBasicAclRule(line)
			if err != nil {
				return err
			}
			acl.Entries = append(acl.Entries, *entry)
		}
	}
	return nil
}

func (a *ACLSet) parseBasicAclRule(rule string) (*ACLEntry, error) {
	entry := &ACLEntry{Cli: rule}

	// 解析规则 ID
	idRegex := regexp.MustCompile(`rule\s+(\d+)`)
	idMatch := idRegex.FindStringSubmatch(rule)
	if len(idMatch) > 1 {
		id, _ := strconv.Atoi(idMatch[1])
		entry.ID = id
	}

	// 解析动作
	if strings.Contains(rule, "permit") {
		entry.Action = firewall.POLICY_PERMIT
	} else if strings.Contains(rule, "deny") {
		entry.Action = firewall.POLICY_DENY
	}

	// 解析 VPN 实例
	vpnRegex := regexp.MustCompile(`vpn-instance\s+(\S+)`)
	vpnMatch := vpnRegex.FindStringSubmatch(rule)
	if len(vpnMatch) > 1 {
		entry.Vrf = vpnMatch[1]
	}

	var srcNet *network.NetworkGroup
	var err error
	// 解析源地址
	if strings.Contains(rule, "source") {
		srcNet, err = a.parseAddress(rule, true)
		if err != nil {
			return nil, fmt.Errorf("error parsing source address: %v", err)
		}
	}

	// 创建 PolicyEntry 并添加源地址和目的地址
	pe := policy.NewPolicyEntry()
	if srcNet == nil {
		srcNet = network.NewAny4Group()
	}
	pe.AddSrc(srcNet)
	pe.AddDst(network.NewAny4Group())
	pe.AddService(tools.MaybeError(service.NewServiceFromString("ip")))
	entry.PolicyEntry = pe

	return entry, nil
}

func (a *ACLSet) parseAddress(rule string, isSource bool) (*network.NetworkGroup, error) {
	ng := network.NewNetworkGroup()
	// regexPattern := fmt.Sprintf(`

	// `, tools.ConditionalT(isSource, "source", "destination"))

	regexMap := map[string]string{
		"name": "address",
		"regex": `
		(source|destination)\s+
			(
				(?P<any>any) |
				(object-group\s+(?P<obj_group>\S+)) |
				((?P<addr>[.\d]+)\s+(?P<rp>\d+)) 
			)
		`,
		"flags": "mx",
		"pcre":  "true",
	}

	resultMap, err := text.SplitterProcessOneTime(regexMap, rule)
	if err != nil {
		return nil, err
	}
	result, ok := resultMap.One()
	if !ok {
		return nil, fmt.Errorf("no source address found in rule: %s", rule)
	}

	if result["any"] != "" {
		return network.NewAny4Group(), nil
	} else if result["addr"] != "" && result["rp"] != "" {
		if result["rp"] == "0" {
			result["rp"] = "0.0.0.0"
		}
		ipWC := result["addr"] + "/" + result["rp"]
		ipNet, err := network.ParseIPNetWithWildcard(ipWC)
		if err != nil {
			return nil, err
		}
		ng.Add(ipNet)
		return ng, nil
	} else if result["obj_group"] != "" {
		ng, _, ok := a.objects.Network("", result["obj_group"])
		if !ok {
			return nil, fmt.Errorf("can not find address object: %s", result["obj_group"])
		}
		return ng, nil
	}

	return nil, fmt.Errorf("invalid address format in rule: %s", rule)
}

func (a *ACLSet) parseAdvancedAcl(acl *ACL, content string) error {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "description") {
			acl.Entries = append(acl.Entries, ACLEntry{Comment: line})
			continue
		}
		if strings.HasPrefix(line, "rule") {
			entry, err := parseAdvancedAclRule(line, a.objects)
			if err != nil {
				return err
			}
			acl.Entries = append(acl.Entries, entry)
		}
	}
	return nil
}

func parseAdvancedAclRule(rule string, objects *SecPathObjectSet) (ACLEntry, error) {
	regexMap := map[string]string{
		"regex": `
        rule\s+((?P<id>\d+)\s+)?(?P<action>permit|deny)\s+
        (?P<protocol>
            (1|icmp) | (0|ip) | (2|igmp) | (47|gre) | (4|ipinip) | (89|ospf) |
            (
                ((6|tcp) | (17|udp))
            )
        )
        (
            \s
            vpn-instance\s(?P<vrf>\S+)
        )?
        (
            \s
            source\s
            (
                (?P<src_any>any) |
                (object-group\s(?P<src_obj>\S+)) |
                ((?P<src_ip>[.\d]+)\s(?P<src_wildcard>[\d.]+))
            )
        )?
        (
            \s
            destination\s
            (
                (?P<dst_any>any) |
                (object-group\s(?P<dst_obj>\S+)) |
                ((?P<dst_ip>[\d.]+)\s(?P<dst_wildcard>[\d.]+))
            )
        )?
        (
            (
                \s
                icmp-type\s(?P<icmp_type>\S+)
            ) |
            (
                (
                    \s
                    source-port\s
                    (
                        (eq\s(?P<src_port_eq>\S+)) |
                        (gt\s(?P<src_port_gt>\S+)) |
                        (lt\s(?P<src_port_lt>\S+)) |
                        (neq\s(?P<src_port_neq>\S+)) |
                        (range\s(?P<src_port_start>\S+)\s(?P<src_port_end>\S+)) |
                        (object-group\s(?P<src_port_obj>\S+))
                    )
                )?
                (
                    \s
                    destination-port\s
                    (
                        (eq\s(?P<dst_port_eq>\S+)) |
                        (gt\s(?P<dst_port_gt>\S+)) |
                        (lt\s(?P<dst_port_lt>\S+)) |
                        (neq\s(?P<dst_port_neq>\S+)) |
                        (range\s(?P<dst_port_start>\S+)\s(?P<dst_port_end>\S+)) |
                        (object-group\s(?P<dst_port_obj>\S+))
                    )
                )
            )
        )?
`,
		"flags": "mx",
		"pcre":  "true",
		"name":  "rule",
	}

	resultMap, err := text.SplitterProcessOneTime(regexMap, rule)
	if err != nil {
		return ACLEntry{}, err
	}
	result, ok := resultMap.One()
	if !ok {
		return ACLEntry{}, fmt.Errorf("no rule found in rule: %s", rule)
	}

	entry := ACLEntry{Cli: rule}

	// 解析规则 ID
	if id, err := strconv.Atoi(result["id"]); err == nil {
		entry.ID = id
	}

	// 解析动作
	if result["action"] == "permit" {
		entry.Action = firewall.POLICY_PERMIT
	} else if result["action"] == "deny" {
		entry.Action = firewall.POLICY_DENY
	}

	// 解析 VPN 实例
	entry.Vrf = result["vrf"]

	// 创建 PolicyEntry
	pe := policy.NewPolicyEntry()

	// 解析协议
	protocol := result["protocol"]
	var srv *service.Service

	switch protocol {
	case "tcp", "6", "udp", "17":
		// 创建 L3Protocol
		var l3Proto *service.L3Protocol
		if protocol == "tcp" || protocol == "6" {
			l3Proto = service.NewL3ProtocolFromString("tcp")
		} else {
			l3Proto = service.NewL3ProtocolFromString("udp")
		}

		// 解析源端口
		srcPort, err := parsePortsFromResult(result, "src")
		if err != nil {
			return ACLEntry{}, err
		}

		// 解析目的端口
		dstPort, err := parsePortsFromResult(result, "dst")
		if err != nil {
			return ACLEntry{}, err
		}

		// 创建 Service
		srv, err = service.NewService(l3Proto.Protocol(), srcPort, dstPort, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
		if err != nil {
			return ACLEntry{}, fmt.Errorf("error creating service: %v", err)
		}
	case "1", "icmp":
		// 创建 ICMPService
		if result["icmp_type"] != "" {
			srv, err = SECPATHICMPServiceFromString(result["icmp_type"])
		} else {
			srv, err = service.NewServiceWithProto("icmp")
		}
		if err != nil {
			return ACLEntry{}, fmt.Errorf("error creating ICMP service: %v", err)
		}
	default:
		// 对于其他协议，直接创建服务
		srv, err = service.NewServiceWithProto(protocol)
		if err != nil {
			return ACLEntry{}, fmt.Errorf("invalid protocol: %s", protocol)
		}
	}

	pe.AddService(srv)

	// // 解析协议
	// protocol := result["protocol"]
	// srv, err := service.NewServiceWithProto(protocol)
	// if err != nil {
	// 	return ACLEntry{}, fmt.Errorf("invalid protocol: %s", protocol)
	// }
	// pe.AddService(srv)

	// 解析源地址
	if result["src_any"] != "" || result["src_obj"] != "" || result["src_ip"] != "" {
		srcNet, err := parseAddressFromResult(result, true, objects)
		if err != nil {
			return ACLEntry{}, err
		}
		pe.AddSrc(srcNet)
	} else {
		pe.AddSrc(network.NewAny4Group())
	}

	// 解析目的地址
	if result["dst_any"] != "" || result["dst_obj"] != "" || result["dst_ip"] != "" {
		dstNet, err := parseAddressFromResult(result, false, objects)
		if err != nil {
			return ACLEntry{}, err
		}
		pe.AddDst(dstNet)
	} else {
		pe.AddDst(network.NewAny4Group())
	}

	// entry.PolicyEntry = pe

	// return entry, nil
	// dstNet, err := parseAddressFromResult(result, false)
	// if err != nil {
	// 	return ACLEntry{}, err
	// }
	// pe.AddDst(dstNet)

	// 解析端口
	// if err := parsePortsFromResult(result, pe); err != nil {
	// 	return ACLEntry{}, err
	// }

	entry.PolicyEntry = pe

	return entry, nil
}

func parseAddressFromResult(result map[string]string, isSource bool, objects *SecPathObjectSet) (*network.NetworkGroup, error) {
	prefix := tools.ConditionalT(isSource, "src", "dst")
	if result[prefix+"_any"] != "" {
		return network.NewAny4Group(), nil
	} else if result[prefix+"_obj"] != "" {
		// 这里需要从对象集合中获取网络对象，暂时返回错误
		ng, _, ok := objects.Network("", result[prefix+"_obj"])
		if !ok {
			return nil, fmt.Errorf("object not found: %s", result[prefix+"_obj"])
		}
		return ng, nil
		// return nil, fmt.Errorf("object-group not implemented for %s: %s", prefix, result[prefix+"_obj"])
	} else if result[prefix+"_ip"] != "" && result[prefix+"_wildcard"] != "" {
		ipWC := result[prefix+"_ip"] + "/" + result[prefix+"_wildcard"]
		ipnet, err := network.ParseIPNetWithWildcard(ipWC)
		if err != nil {
			return nil, err
		}
		ng := network.NewNetworkGroup()
		ng.Add(ipnet)
		return ng, nil
	}
	return nil, fmt.Errorf("no valid address found for %s", prefix)
}

func parsePortsFromResult(result map[string]string, direction string) (*service.L4Port, error) {
	var l4Port *service.L4Port
	var err error

	if result[direction+"_port_eq"] != "" {
		l4Port, err = service.NewL4Port(service.EQ, tools.MaybeError(strconv.Atoi(result[direction+"_port_eq"])), -1, 0)
	} else if result[direction+"_port_gt"] != "" {
		l4Port, err = service.NewL4Port(service.GT, tools.MaybeError(strconv.Atoi(result[direction+"_port_gt"])), -1, 0)
	} else if result[direction+"_port_lt"] != "" {
		l4Port, err = service.NewL4Port(service.LT, tools.MaybeError(strconv.Atoi(result[direction+"_port_lt"])), -1, 0)
	} else if result[direction+"_port_neq"] != "" {
		l4Port, err = service.NewL4Port(service.NEQ, tools.MaybeError(strconv.Atoi(result[direction+"_port_neq"])), -1, 0)
	} else if result[direction+"_port_start"] != "" && result[direction+"_port_end"] != "" {
		l4Port, err = service.NewL4Port(service.RANGE, tools.MaybeError(strconv.Atoi(result[direction+"_port_start"])), tools.MaybeError(strconv.Atoi(result[direction+"_port_end"])), 0)
	} else if result[direction+"_port_obj"] != "" {
		return nil, fmt.Errorf("port object-group not implemented for %s: %s", direction, result[direction+"_port_obj"])
	}

	if err != nil {
		return nil, fmt.Errorf("error parsing %s port: %v", direction, err)
	}

	return l4Port, nil
}
