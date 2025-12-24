package usg

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
)

var _ firewall.FirewallNetworkObject = &AddressGroup{}

// AddressGroup represents a NAT address group
type AddressGroup struct {
	CLI         string
	GroupNumber string
	C           string
	N           *network.NetworkGroup
	Sections    []*AddressSection
}

// addressGroupJSON 用于序列化和反序列化
type addressGroupJSON struct {
	CLI         string            `json:"cli"`
	GroupNumber string            `json:"group_number"`
	C           string            `json:"c"`
	N           json.RawMessage   `json:"n,omitempty"`
	Sections    []*AddressSection `json:"sections"`
}

// MarshalJSON 实现 JSON 序列化
func (ag *AddressGroup) MarshalJSON() ([]byte, error) {
	var nRaw json.RawMessage
	var err error
	if ag.N != nil {
		nRaw, err = json.Marshal(ag.N)
		if err != nil {
			return nil, fmt.Errorf("error marshaling NetworkGroup: %w", err)
		}
	}

	return json.Marshal(addressGroupJSON{
		CLI:         ag.CLI,
		GroupNumber: ag.GroupNumber,
		C:           ag.C,
		N:           nRaw,
		Sections:    ag.Sections,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ag *AddressGroup) UnmarshalJSON(data []byte) error {
	var agj addressGroupJSON
	if err := json.Unmarshal(data, &agj); err != nil {
		return err
	}

	ag.CLI = agj.CLI
	ag.GroupNumber = agj.GroupNumber
	ag.C = agj.C
	ag.Sections = agj.Sections

	if agj.N != nil {
		ag.N = &network.NetworkGroup{}
		if err := json.Unmarshal(agj.N, ag.N); err != nil {
			return fmt.Errorf("error unmarshaling NetworkGroup: %w", err)
		}
	}

	return nil
}

// TypeName 实现 TypedInterface 接口
func (ag *AddressGroup) TypeName() string {
	return "AddressGroup"
}

// Cli 实现 FirewallNetworkObject 接口
func (ag *AddressGroup) Cli() string {
	return ag.CLI
}

// Name 实现 FirewallNetworkObject 接口
func (ag *AddressGroup) Name() string {
	return ag.GroupNumber
}

// Type 实现 FirewallNetworkObject 接口
func (ag *AddressGroup) Type() firewall.FirewallObjectType {
	return firewall.POOL
}

// Network returns a NetworkGroup containing all IP addresses in the AddressGroup
func (ag *AddressGroup) Network(_ firewall.FirewallNode) *network.NetworkGroup {
	// If we've already computed the NetworkGroup, return it
	if ag.N != nil {
		return ag.N
	}

	// Create a new NetworkGroup
	ng := network.NewNetworkGroup()

	// Iterate through all sections and add their networks to the group
	for _, section := range ag.Sections {
		if section.Network != nil {
			ng.AddGroup(section.Network)
		} else {
			// If the section's Network is not pre-computed, create it from the IP range
			sectionNG, err := network.NewNetworkGroupFromString(section.StartIP + "-" + section.EndIP)
			if err == nil {
				ng.AddGroup(sectionNG)
			}
			// Note: We're ignoring errors here. In a production environment,
			// you might want to log these errors or handle them differently.
		}
	}

	// Cache the computed NetworkGroup
	ag.N = ng

	return ng
}

// ID 实现 NatPool 接口
func (ag *AddressGroup) ID() string {
	return ag.GroupNumber
}

// MatchNetworkGroup 实现 NatPool 接口
func (ag *AddressGroup) MatchNetworkGroup(ng *network.NetworkGroup) bool {
	if ng == nil {
		return false
	}
	// 确保 NetworkGroup 已初始化
	agNet := ag.Network(nil)
	if agNet == nil {
		return false
	}
	return agNet.Same(ng)
}

// AddressSection represents a section within an address group
type AddressSection struct {
	SectionNumber string
	StartIP       string
	EndIP         string
	Network       *network.NetworkGroup
}

// NatPool represents a NAT address pool
type NatPool struct {
	PoolID   string
	CLI      string
	PoolType string // "inside" or "global"
	Sections []*NatPoolSection
}

func (pool *NatPool) Cli() string {
	return pool.CLI
}

func (pool *NatPool) Name() string {
	return pool.PoolID
}

func (pool *NatPool) ID() string {
	return pool.PoolID
}

// func (pool *NatPool) Type() firewall.FirewallObjectType {
// 	return pool.objectType
// }

// func (pool *NatPool) NatType() firewall.NatType {
// 	return pool.natType
// }

// func (pool *NatPool) Network(_ firewall.FirewallNode) *network.NetworkGroup {
// 	return pool.network
// }

// NatPoolSection represents a section within a NAT pool
type NatPoolSection struct {
	ID      string
	StartIP string
	EndIP   string
}

// NatStaticMapping represents a static NAT mapping configuration
type NatStaticMapping struct {
	id             string
	insidePoolID   string
	globalPoolID   string
	insidePool     *NatPool
	globalPool     *NatPool
	portRangeStart string
	portRangeEnd   string
	portSize       string
	objects        *UsgObjectSet
	node           *UsgNode
	status         UsgNatStatus
	orignal        *policy.PolicyEntry
	translate      *policy.PolicyEntry
	cli            string
}

// NatStaticMappingJSON 用于 JSON 序列化和反序列化
type NatStaticMappingJSON struct {
	ID             string          `json:"id"`
	InsidePoolID   string          `json:"inside_pool_id"`
	GlobalPoolID   string          `json:"global_pool_id"`
	PortRangeStart string          `json:"port_range_start"`
	PortRangeEnd   string          `json:"port_range_end"`
	PortSize       string          `json:"port_size"`
	Status         UsgNatStatus    `json:"status"`
	Original       json.RawMessage `json:"original"`
	Translate      json.RawMessage `json:"translate"`
	CLI            string          `json:"cli"`
}

// MarshalJSON 实现 JSON 序列化
func (nsm *NatStaticMapping) MarshalJSON() ([]byte, error) {
	original, err := registry.InterfaceToRawMessage[policy.PolicyEntryInf](nsm.orignal)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal original policy: %v", err)
	}

	translate, err := registry.InterfaceToRawMessage[policy.PolicyEntryInf](nsm.translate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal translate policy: %v", err)
	}

	return json.Marshal(NatStaticMappingJSON{
		ID:             nsm.id,
		InsidePoolID:   nsm.insidePoolID,
		GlobalPoolID:   nsm.globalPoolID,
		PortRangeStart: nsm.portRangeStart,
		PortRangeEnd:   nsm.portRangeEnd,
		PortSize:       nsm.portSize,
		Status:         nsm.status,
		Original:       original,
		Translate:      translate,
		CLI:            nsm.cli,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (nsm *NatStaticMapping) UnmarshalJSON(data []byte) error {
	var nsmJSON NatStaticMappingJSON
	if err := json.Unmarshal(data, &nsmJSON); err != nil {
		return err
	}

	nsm.id = nsmJSON.ID
	nsm.insidePoolID = nsmJSON.InsidePoolID
	nsm.globalPoolID = nsmJSON.GlobalPoolID
	nsm.portRangeStart = nsmJSON.PortRangeStart
	nsm.portRangeEnd = nsmJSON.PortRangeEnd
	nsm.portSize = nsmJSON.PortSize
	nsm.status = nsmJSON.Status
	nsm.cli = nsmJSON.CLI

	var err error
	nsm.orignal, err = registry.RawMessageToInterface[*policy.PolicyEntry](nsmJSON.Original)
	if err != nil {
		return fmt.Errorf("failed to unmarshal original policy: %v", err)
	}

	nsm.translate, err = registry.RawMessageToInterface[*policy.PolicyEntry](nsmJSON.Translate)
	if err != nil {
		return fmt.Errorf("failed to unmarshal translate policy: %v", err)
	}

	// Note: objects, node, insidePool, and globalPool are not unmarshaled here
	// They should be set separately after unmarshaling

	return nil
}

// Name returns the name of the static mapping
func (mapping *NatStaticMapping) Name() string {
	return fmt.Sprintf("static-mapping-%s", mapping.id)
}

// Cli returns the CLI configuration
func (mapping *NatStaticMapping) Cli() string {
	return mapping.cli
}

// Original returns the original policy entry
func (mapping *NatStaticMapping) Original() policy.PolicyEntryInf {
	return mapping.orignal
}

// Translate returns the translated policy entry
func (mapping *NatStaticMapping) Translate() policy.PolicyEntryInf {
	return mapping.translate
}

// Extended returns extended information
func (mapping *NatStaticMapping) Extended() map[string]interface{} {
	return map[string]interface{}{
		"id":               mapping.id,
		"inside_pool_id":   mapping.insidePool.PoolID,
		"global_pool_id":   mapping.globalPool.PoolID,
		"port_range_start": mapping.portRangeStart,
		"port_range_end":   mapping.portRangeEnd,
		"port_size":        mapping.portSize,
		"status":           mapping.status,
	}
}

// Status returns the NAT status
func (mapping *NatStaticMapping) Status() firewall.NatStatus {
	switch mapping.status {
	case Usg_NAT_ACTIVE:
		return firewall.NAT_ACTIVE
	case Usg_NAT_INACTIVE:
		return firewall.NAT_INACTIVE
	default:
		return firewall.NAT_INACTIVE
	}
}

// NatType returns the NAT type
func (mapping *NatStaticMapping) NatType() firewall.NatType {
	return firewall.STATIC_NAT
}

// parseNatStaticMapping parses NAT static-mapping configurations
func (nat *Nats) parseNatStaticMapping(config string) error {
	if nat.natStaticMappings == nil {
		nat.natStaticMappings = make(map[string]*NatStaticMapping)
	}
	// if nat.insidePools == nil {
	// 	nat.insidePools = make(map[string]*NatPool)
	// }
	// if nat.globalPools == nil {
	// 	nat.globalPools = make(map[string]*NatPool)
	// }

	// Parse inside-pool configurations
	if err := nat.parseInsidePools(config); err != nil {
		return fmt.Errorf("failed to parse inside pools: %v", err)
	}

	// Parse global-pool configurations
	if err := nat.parseGlobalPools(config); err != nil {
		return fmt.Errorf("failed to parse global pools: %v", err)
	}

	// Parse static-mapping configurations
	if err := nat.parseStaticMappingRules(config); err != nil {
		return fmt.Errorf("failed to parse static mapping rules: %v", err)
	}

	return nil
}

// parseInsidePools parses inside-pool configurations
func (nat *Nats) parseInsidePools(config string) error {
	regexMap := map[string]string{
		"regex": `
            inside-ipv4-pool\s+(?P<pool_id>\d+)\s*\n
            (?P<sections>(?:\s+section\s+\d+\s+[\d\.]+\s+[\d\.]+\s*\n?)*)
        `,
		"name":  "inside_pool",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, config)
	if err != nil {
		return fmt.Errorf("failed to process inside pool regex: %v", err)
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, match := it.Next()
		poolID := match["pool_id"]
		sectionsConfig := match["sections"]

		pool := &NatPool{
			PoolID:   poolID,
			PoolType: "inside",
			Sections: make([]*NatPoolSection, 0),
		}

		// Parse sections within this inside pool
		if err := nat.parsePoolSections(pool, sectionsConfig); err != nil {
			return fmt.Errorf("failed to parse inside pool %s sections: %v", poolID, err)
		}

		nat.insidePools[poolID] = pool
	}

	return nil
}

func (nat *Nats) parseGlobalPools(config string) error {
	regexMap := map[string]string{
		"regex": `
            global-pool\s+(?P<pool_id>\d+)\s*\n
            (?P<sections>(?:\s+section\s+\d+\s+[\d\.]+\s+[\d\.]+\s*\n?)*)
        `,
		"name":  "global_pool",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, config)
	if err != nil {
		return fmt.Errorf("failed to process global pool regex: %v", err)
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, match := it.Next()
		poolID := match["pool_id"]
		sectionsConfig := match["sections"]

		pool := &NatPool{
			PoolID:   poolID,
			PoolType: "global",
			Sections: make([]*NatPoolSection, 0),
		}

		// Parse sections within this global pool
		if err := nat.parsePoolSections(pool, sectionsConfig); err != nil {
			return fmt.Errorf("failed to parse global pool %s sections: %v", poolID, err)
		}

		nat.globalPools[poolID] = pool
	}

	return nil
}

// parsePoolSections parses section configurations within a pool
func (nat *Nats) parsePoolSections(pool *NatPool, sectionsConfig string) error {
	sectionRegex := `section\s+(\d+)\s+([\d\.]+)\s+([\d\.]+)`
	regex := regexp.MustCompile(sectionRegex)
	matches := regex.FindAllStringSubmatch(sectionsConfig, -1)

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		sectionID := match[1]
		startIP := match[2]
		endIP := match[3]

		section := &NatPoolSection{
			ID:      sectionID,
			StartIP: startIP,
			EndIP:   endIP,
		}

		// Validate IP addresses
		if net.ParseIP(startIP) == nil {
			return fmt.Errorf("invalid start IP address: %s", startIP)
		}
		if net.ParseIP(endIP) == nil {
			return fmt.Errorf("invalid end IP address: %s", endIP)
		}

		pool.Sections = append(pool.Sections, section)
	}

	return nil
}

// parseStaticMappingRules parses static-mapping rule configurations
func (nat *Nats) parseStaticMappingRules(config string) error {
	regexMap := map[string]string{
		"regex": `
            static-mapping\s+(?P<mapping_id>\d+)\s+
            inside-ipv4-pool\s+(?P<inside_pool_id>\d+)\s+
            global-pool\s+(?P<global_pool_id>\d+)
            (?:\s+port-range\s+(?P<port_range_start>\d+)\s+(?P<port_range_end>\d+))?
            (?:\s+port-block-size\s+(?P<port_block_size>\d+))?
        `,
		"name":  "static_mapping",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, config)
	if err != nil {
		return fmt.Errorf("failed to process static mapping regex: %v", err)
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, match := it.Next()
		mappingID := match["mapping_id"]
		insidePoolID := match["inside_pool_id"]
		globalPoolID := match["global_pool_id"]
		portRangeStart := match["port_range_start"]
		portRangeEnd := match["port_range_end"]
		portSize := match["port_block_size"]

		// Get inside pool
		insidePool, exists := nat.insidePools[insidePoolID]
		if !exists {
			return fmt.Errorf("inside pool %s not found for static mapping %s", insidePoolID, mappingID)
		}

		// Get global pool
		globalPool, exists := nat.globalPools[globalPoolID]
		if !exists {
			return fmt.Errorf("global pool %s not found for static mapping %s", globalPoolID, mappingID)
		}

		staticMapping := &NatStaticMapping{
			id:             mappingID,
			insidePool:     insidePool,
			insidePoolID:   insidePoolID,
			globalPool:     globalPool,
			globalPoolID:   globalPoolID,
			portRangeStart: portRangeStart,
			portRangeEnd:   portRangeEnd,
			portSize:       portSize,
			objects:        nat.objects,
			node:           nat.node,
			status:         Usg_NAT_ACTIVE,
		}

		// Create policy entries for this static mapping
		if err := nat.setupStaticMappingPolicy(staticMapping); err != nil {
			return fmt.Errorf("failed to setup static mapping policy for %s: %v", mappingID, err)
		}

		nat.natStaticMappings[mappingID] = staticMapping
	}

	return nil
}

// setupStaticMappingPolicy sets up policy entries for static mapping

func (nat *Nats) setupStaticMappingPolicy(mapping *NatStaticMapping) error {
	mapping.orignal = policy.NewPolicyEntry()
	mapping.translate = policy.NewPolicyEntry()

	// Setup inside network group (original source)
	insideNG := network.NewNetworkGroup()
	for _, section := range mapping.insidePool.Sections {
		ng, err := network.NewNetworkGroupFromString(section.StartIP + "-" + section.EndIP)
		if err != nil {
			return fmt.Errorf("invalid IP range in inside pool section %s: %s-%s: %v", section.ID, section.StartIP, section.EndIP, err)
		}
		insideNG.AddGroup(ng)
	}

	// Setup global network group (translated source)
	globalNG := network.NewNetworkGroup()
	for _, section := range mapping.globalPool.Sections {
		ng, err := network.NewNetworkGroupFromString(section.StartIP + "-" + section.EndIP)
		if err != nil {
			return fmt.Errorf("invalid IP range in global pool section %s: %s-%s: %v", section.ID, section.StartIP, section.EndIP, err)
		}
		globalNG.AddGroup(ng)
	}

	mapping.orignal.AddSrc(insideNG)
	mapping.translate.AddSrc(globalNG)

	// Setup service if port range is specified
	if mapping.portRangeStart != "" && mapping.portRangeEnd != "" {
		portRange := mapping.portRangeStart + "-" + mapping.portRangeEnd
		l4port, err := service.NewL4PortFromString(portRange, 0)
		if err != nil {
			return fmt.Errorf("invalid port range: %s", portRange)
		}

		// Create TCP and UDP services
		tcpSvc, err := service.NewL4Service(service.TCP, l4port, nil)
		if err != nil {
			return err
		}
		udpSvc, err := service.NewL4Service(service.UDP, l4port, nil)
		if err != nil {
			return err
		}

		svc := &service.Service{}
		svc.Add(tcpSvc)
		svc.Add(udpSvc)

		mapping.orignal.AddService(svc)
		mapping.translate.AddService(svc)
	} else {
		// Default to IP service
		svc, err := service.NewServiceWithProto("ip")
		if err != nil {
			return err
		}
		mapping.orignal.AddService(svc)
		mapping.translate.AddService(svc)
	}

	// Set destination to any for static mapping (typically used for outbound NAT)
	anyDst := network.NewAny4Group()
	mapping.orignal.AddDst(anyDst)
	mapping.translate.AddDst(anyDst)

	return nil
}

// ipRangeToCIDR converts an IP range to CIDR notation if possible
func (nat *Nats) ipRangeToCIDR(startIP, endIP string) (string, error) {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if start == nil || end == nil {
		return "", fmt.Errorf("invalid IP addresses")
	}

	// Convert to 4-byte representation for IPv4
	start = start.To4()
	end = end.To4()

	if start == nil || end == nil {
		return "", fmt.Errorf("only IPv4 addresses are supported")
	}

	// Calculate the number of IPs in the range
	startInt := binary.BigEndian.Uint32(start)
	endInt := binary.BigEndian.Uint32(end)

	if startInt > endInt {
		return "", fmt.Errorf("start IP is greater than end IP")
	}

	numIPs := endInt - startInt + 1

	// Check if the range can be represented as a single CIDR block
	if numIPs&(numIPs-1) == 0 { // Check if numIPs is a power of 2
		// Calculate prefix length
		prefixLen := 32 - int(math.Log2(float64(numIPs)))

		// Verify that the start IP is aligned to the CIDR boundary
		mask := uint32(0xFFFFFFFF) << (32 - prefixLen)
		if startInt&mask == startInt {
			return fmt.Sprintf("%s/%d", startIP, prefixLen), nil
		}
	}

	return "", fmt.Errorf("IP range cannot be represented as a single CIDR block")
}

// nextIP returns the next IP address
func (nat *Nats) nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}

	return next
}

// parseAddressGroups parses both types of address groups
func (nat *Nats) parseAddressGroups(config string) error {
	if nat.addressGroups == nil {
		nat.addressGroups = make(map[string]*AddressGroup)
	}

	// Parse destination-nat address-group (Type 1)
	if err := nat.parseDestinationNatAddressGroups(config); err != nil {
		return err
	}

	// Parse nat address-group (Type 2)
	if err := nat.parseNatAddressGroups(config); err != nil {
		return err
	}

	return nil
}

func (nat *Nats) NextPoolId(id string) string {
	// 如果提供了 id，直接返回
	if id != "" {
		return id
	}

	maxId := 0

	// 遍历所有的地址组
	for _, ag := range nat.addressGroups {
		// 将 GroupNumber 转换为整数
		groupId, err := strconv.Atoi(ag.GroupNumber)
		if err == nil && groupId > maxId {
			maxId = groupId
		}
	}

	// 返回最大 ID + 1
	return strconv.Itoa(maxId + 1)
}

// parseDestinationNatAddressGroups parses destination-nat address-group configurations
// Format: destination-nat address-group d1 0
//
//	section 6.6.6.6 6.6.6.10
func (nat *Nats) parseDestinationNatAddressGroups(config string) error {
	sections := strings.Split(config, "#")

	for _, section := range sections {
		section = strings.TrimSpace(section)
		if !strings.Contains(section, "destination-nat address-group") {
			continue
		}

		lines := strings.Split(section, "\n")
		if len(lines) < 2 {
			continue
		}

		// Parse the header line: destination-nat address-group d1 0
		headerRegex := regexp.MustCompile(`destination-nat\s+address-group\s+(\S+)\s+(\d+)`)
		headerMatches := headerRegex.FindStringSubmatch(lines[0])
		if len(headerMatches) < 3 {
			continue
		}

		groupName := headerMatches[1]
		groupNumber := headerMatches[2]
		// if err != nil {
		// 	return fmt.Errorf("invalid group number in destination-nat address-group: %s", headerMatches[2])
		// }

		ag := &AddressGroup{
			GroupNumber: groupNumber,
			C:           section,
			Sections:    []*AddressSection{},
		}

		// Parse section lines
		sectionRegex := regexp.MustCompile(`section\s+(\S+)\s+(\S+)`)
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			sectionMatches := sectionRegex.FindStringSubmatch(line)
			if len(sectionMatches) < 3 {
				continue
			}

			// sectionNumber := sectionMatches[1]
			startIP := sectionMatches[1]
			endIP := sectionMatches[2]

			// Create network group for this section
			ng, err := network.NewNetworkGroupFromString(startIP + "-" + endIP)
			if err != nil {
				return fmt.Errorf("failed to create network group for section %s-%s: %v", startIP, endIP, err)
			}

			section := &AddressSection{
				// SectionNumber: sectionNumber, // Could be parsed if needed
				StartIP: startIP,
				EndIP:   endIP,
				Network: ng,
			}

			ag.Sections = append(ag.Sections, section)
		}

		// Store by group name hash or use a name-to-number mapping
		// For now, we'll use a simple hash of the group name
		// nameHash := simpleHash(groupName)
		nat.addressGroups[groupName] = ag
	}

	return nil
}

// parseNatAddressGroups parses nat address-group configurations
// Format: nat address-group 1 0
//
//	section 0 1.1.1.1 1.1.1.22
func (nat *Nats) parseNatAddressGroups(config string) error {
	sections := strings.Split(config, "#")

	for _, section := range sections {
		section = strings.TrimSpace(section)
		if !regexp.MustCompile(`^nat\s+address-group\s+\d+`).MatchString(section) {
			continue
		}

		lines := strings.Split(section, "\n")
		if len(lines) < 2 {
			continue
		}

		// Parse the header line: nat address-group 1 0
		headerRegex := regexp.MustCompile(`nat\s+address-group\s+(\d+)\s+(\d+)`)
		headerMatches := headerRegex.FindStringSubmatch(lines[0])
		if len(headerMatches) < 3 {
			continue
		}

		groupNumber := headerMatches[1]

		ag := &AddressGroup{
			GroupNumber: groupNumber,
			C:           section,
			Sections:    []*AddressSection{},
		}

		// Parse section lines: section 0 1.1.1.1 1.1.1.22
		sectionRegex := regexp.MustCompile(`section\s+(\d+)\s+(\S+)\s+(\S+)`)
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			sectionMatches := sectionRegex.FindStringSubmatch(line)
			if len(sectionMatches) < 4 {
				continue
			}

			sectionNumber := sectionMatches[1]

			startIP := sectionMatches[2]
			endIP := sectionMatches[3]

			// Create network group for this section
			ng, err := network.NewNetworkGroupFromString(startIP + "-" + endIP)
			if err != nil {
				return fmt.Errorf("failed to create network group for section %s %s-%s: %v", sectionNumber, startIP, endIP, err)
			}

			section := &AddressSection{
				SectionNumber: sectionNumber,
				StartIP:       startIP,
				EndIP:         endIP,
				Network:       ng,
			}

			ag.Sections = append(ag.Sections, section)
		}

		nat.addressGroups[groupNumber] = ag
	}

	return nil
}
