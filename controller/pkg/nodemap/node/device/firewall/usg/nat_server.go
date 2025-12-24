package usg

import (
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

// parseNatServer parses NAT server configurations
// func (nat *Nats) parseNatServer(config string) error {
// 	if nat.natServers == nil {
// 		nat.natServers = make(map[string]*NatServer)
// 	}

// 	natServerRegexMap := map[string]string{
// 		"regex": `nat\s+server\s+(?P<id>\S+)\s+` +
// 			`(protocol\s+(?P<protocol>\S+)\s+)?` +
// 			`global\s+(?P<global_ip>\S+)(\s+(?P<global_port>\S+))?\s+` +
// 			`inside\s+(?P<inside_ip>\S+)(\s+(?P<inside_port>\S+))?\s*` +
// 			`(vpn-instance\s+(?P<vpn_instance>\S+))?`,
// 		"name":  "natserver",
// 		"flags": "m",
// 		"pcre":  "true",
// 	}

// 	result, err := text.SplitterProcessOneTime(natServerRegexMap, config)
// 	if err != nil {
// 		return fmt.Errorf("failed to process NAT server regex: %v", err)
// 	}

// 	for it := result.Iterator(); it.HasNext(); {
// 		_, cli, natServerMap := it.Next()

// 		natServer := &NatServer{
// 			objects:     nat.objects,
// 			node:        nat.node,
// 			id:          natServerMap["id"],
// 			protocol:    natServerMap["protocol"],
// 			globalIP:    natServerMap["global_ip"],
// 			globalPort:  natServerMap["global_port"],
// 			insideIP:    natServerMap["inside_ip"],
// 			insidePort:  natServerMap["inside_port"],
// 			vpnInstance: natServerMap["vpn_instance"],
// 			cli:         strings.Join(cli, "\n"),
// 			status:      Usg_NAT_ACTIVE,
// 			orignal:     policy.NewPolicyEntry(),
// 			translate:   policy.NewPolicyEntry(),
// 		}

// 		// Set name if it's not a numeric ID
// 		if !isNumeric(natServer.id) {
// 			natServer.name = natServer.id
// 		}

// 		// Parse and set up the policy entries
// 		if err := nat.setupNatServerPolicy(natServer); err != nil {
// 			return fmt.Errorf("failed to setup NAT server policy for %s: %v", natServer.Name(), err)
// 		}

// 		nat.natServers[natServer.Name()] = natServer
// 	}

// 	return nil
// }

// setupNatServerPolicy sets up the original and translate policy entries for NAT server
// func (nat *Nats) setupNatServerPolicy(natServer *NatServer) error {
// 	// Setup global (external) side - this is what external clients see
// 	globalNG, err := network.NewNetworkGroupFromString(natServer.globalIP)
// 	if err != nil {
// 		return fmt.Errorf("invalid global IP: %s", natServer.globalIP)
// 	}
// 	natServer.orignal.AddDst(globalNG)

// 	// Setup inside (internal) side - this is the real server
// 	insideNG, err := network.NewNetworkGroupFromString(natServer.insideIP)
// 	if err != nil {
// 		return fmt.Errorf("invalid inside IP: %s", natServer.insideIP)
// 	}
// 	natServer.translate.AddDst(insideNG)

// 	// Setup service/protocol
// 	var globalService, insideService *service.Service

// 	if natServer.protocol != "" {
// 		// Handle protocol-specific configuration
// 		switch strings.ToLower(natServer.protocol) {
// 		case "tcp", "udp":
// 			globalPort := natServer.globalPort
// 			insidePort := natServer.insidePort

// 			// Default ports for common services
// 			if globalPort == "" {
// 				globalPort = nat.getDefaultPort(natServer.globalPort)
// 			}
// 			if insidePort == "" {
// 				insidePort = nat.getDefaultPort(natServer.insidePort)
// 			}

// 			// Create services

// 			if globalPort != "" {
// 				if isNumeric(globalPort) {
// 					// 如果是数字端口，直接创建服务
// 					globalService, err = service.NewServiceWithL4(natServer.protocol, "", globalPort)
// 					if err != nil {
// 						return fmt.Errorf("invalid global service: %v", err)
// 					}
// 				} else {
// 					// 如果不是数字，通过内置服务获取
// 					builtinService, ok := UsgBuiltinService(globalPort)
// 					if !ok {
// 						return fmt.Errorf("unknown global service: %s", globalPort)
// 					}
// 					globalService = builtinService
// 				}
// 			}

// 			if insidePort != "" {
// 				if isNumeric(insidePort) {
// 					// 如果是数字端口，直接创建服务
// 					insideService, err = service.NewServiceWithL4(natServer.protocol, "", insidePort)
// 					if err != nil {
// 						return fmt.Errorf("invalid inside service: %v", err)
// 					}
// 				} else {
// 					// 如果不是数字，通过内置服务获取
// 					builtinService, ok := UsgBuiltinService(insidePort)
// 					if !ok {
// 						return fmt.Errorf("unknown inside service: %s", insidePort)
// 					}
// 					insideService = builtinService
// 				}
// 			}

// 		case "icmp":
// 			globalService, err = service.NewServiceFromString("icmp")
// 			if err != nil {
// 				return err
// 			}
// 			insideService = globalService.Copy().(*service.Service)

// 		default:
// 			return fmt.Errorf("unsupported protocol: %s", natServer.protocol)
// 		}
// 	} else {
// 		// No protocol specified, use IP
// 		globalService, err = service.NewServiceFromString("ip")
// 		if err != nil {
// 			return err
// 		}
// 		insideService = globalService.Copy().(*service.Service)
// 	}

// 	if globalService != nil {
// 		natServer.orignal.AddService(globalService)
// 	}
// 	if insideService != nil {
// 		natServer.translate.AddService(insideService)
// 	}

// 	// Add any source (external clients can come from anywhere)
// 	natServer.orignal.AddSrc(network.NewAny4Group())
// 	natServer.translate.AddSrc(network.NewAny4Group())

// 	return nil
// }

func (nat *Nats) setupNatServerPolicy(natServer *NatServer) (*NatRule, error) {
	natRule := &NatRule{
		objects:   nat.objects,
		node:      nat.node,
		name:      natServer.Name(),
		natType:   firewall.STATIC_NAT,
		status:    Usg_NAT_ACTIVE,
		orignal:   policy.NewPolicyEntry(),
		translate: policy.NewPolicyEntry(),
	}

	// Setup inside (internal) side - this is the real server
	insideNG, err := network.NewNetworkGroupFromString(natServer.insideIP)
	if err != nil {
		return nil, fmt.Errorf("invalid inside IP: %s", natServer.insideIP)
	}
	natRule.orignal.AddSrc(insideNG)

	// Setup global (external) side - this is what external clients see
	globalNG, err := network.NewNetworkGroupFromString(natServer.globalIP)
	if err != nil {
		return nil, fmt.Errorf("invalid global IP: %s", natServer.globalIP)
	}
	natRule.translate.AddSrc(globalNG)

	// Setup service/protocol
	var originalService, translateService *service.Service

	if natServer.protocol != "" {
		switch strings.ToLower(natServer.protocol) {
		case "tcp", "udp":
			insidePort := natServer.insidePort
			globalPort := natServer.globalPort

			// Default ports for common services
			if insidePort == "" {
				insidePort = nat.getDefaultPort(natServer.insidePort)
			}
			if globalPort == "" {
				globalPort = nat.getDefaultPort(natServer.globalPort)
			}

			// Create services
			if insidePort != "" {
				if isNumeric(insidePort) {
					originalService, err = service.NewServiceWithL4(natServer.protocol, insidePort, "")
					if err != nil {
						return nil, fmt.Errorf("invalid inside service: %v", err)
					}
				} else {
					builtinService, ok := UsgBuiltinService(insidePort)
					if !ok {
						return nil, fmt.Errorf("unknown inside service: %s", insidePort)
					}
					originalService = builtinService
				}
			}

			if globalPort != "" {
				if isNumeric(globalPort) {
					translateService, err = service.NewServiceWithL4(natServer.protocol, globalPort, "")
					if err != nil {
						return nil, fmt.Errorf("invalid global service: %v", err)
					}
				} else {
					builtinService, ok := UsgBuiltinService(globalPort)
					if !ok {
						return nil, fmt.Errorf("unknown global service: %s", globalPort)
					}
					translateService = builtinService
				}
			}

		case "icmp":
			originalService, err = service.NewServiceFromString("icmp")
			if err != nil {
				return nil, err
			}
			translateService = originalService.Copy().(*service.Service)

		default:
			return nil, fmt.Errorf("unsupported protocol: %s", natServer.protocol)
		}
	} else {
		// No protocol specified, use IP
		originalService, err = service.NewServiceFromString("ip")
		if err != nil {
			return nil, err
		}
		translateService = originalService.Copy().(*service.Service)
	}

	if originalService != nil {
		natRule.orignal.AddService(originalService)
	}
	if translateService != nil {
		natRule.translate.AddService(translateService)
	}

	// Add any destination (can be accessed from anywhere)
	natRule.orignal.AddDst(network.NewAny4Group())
	natRule.translate.AddDst(network.NewAny4Group())
	if natServer.out != "" {
		natRule.to = append(natRule.to, natServer.out)
	} else {
		natRule.to = append(natRule.to, "any")
	}

	return natRule, nil
}

// getDefaultPort returns default port for common service names
func (nat *Nats) getDefaultPort(portName string) string {
	defaultPorts := map[string]string{
		"www":    "80",
		"http":   "80",
		"https":  "443",
		"ftp":    "21",
		"ssh":    "22",
		"telnet": "23",
		"smtp":   "25",
		"dns":    "53",
		"pop3":   "110",
		"imap":   "143",
	}

	if port, ok := defaultPorts[strings.ToLower(portName)]; ok {
		return port
	}
	return portName
}

// isNumeric checks if a string is numeric
// func isNumeric(s string) bool {
// 	_, err := strconv.Atoi(s)
// 	return err == nil
// }

// GetNatServer returns a NAT server by name
func (nat *Nats) GetNatServer(name string) (*NatRule, bool) {
	if nat.natServers == nil {
		return nil, false
	}

	for _, s := range nat.natServers {
		if s.name == name {
			return s, true
		}
	}
	return nil, false
}

// inputNatServer checks if incoming traffic matches any NAT server
// func (nat *Nats) inputNatServer(intent *policy.Intent, inPort api.Port) (bool, *policy.Intent, *NatServer) {
// 	if nat.natServers == nil {
// 		return false, nil, nil
// 	}

// 	for _, natServer := range nat.natServers {
// 		if nat.matchNatServer(intent, natServer) {
// 			// Create translated intent
// 			translateIntent := intent.Copy().(*policy.Intent)

// 			// Apply NAT translation
// 			originalEntry := intent.GenerateIntentPolicyEntry()
// 			if natServer.translate.Match(originalEntry) {
// 				// Update destination to inside IP
// 				translateIntent.AddDst(natServer.translate.Dst())
// 				if natServer.translate.Service() != nil {
// 					translateIntent.AddService(natServer.translate.Service())
// 				}
// 				return true, translateIntent, natServer
// 			}
// 		}
// 	}

// 	return false, nil, nil
// }

// matchNatServer checks if an intent matches a NAT server configuration
func (nat *Nats) matchNatServer(intent *policy.Intent, natServer *NatServer) bool {
	intentEntry := intent.GenerateIntentPolicyEntry()
	return natServer.orignal.Match(intentEntry)
}

// Update the main flyConfig method to include NAT server parsing
// func (nat *Nats) flyConfig(config string) error {
// 	// Parse NAT servers first
// 	// if err := nat.parseNatServer(config); err != nil {
// 	// 	return fmt.Errorf("failed to parse NAT servers: %v", err)
// 	// }

// 	// Parse rule sets
// 	ruleSets, err := nat.parseRuleSet(config)
// 	if err != nil {
// 		return err
// 	}

// 	for _, ruleSet := range ruleSets {
// 		var err error
// 		switch ruleSet.natType {
// 		case firewall.STATIC_NAT:
// 			err = nat.parseStaticNat(ruleSet)
// 		case firewall.DYNAMIC_NAT:
// 			err = nat.parseSourceNat(ruleSet)
// 		case firewall.DESTINATION_NAT:
// 			err = nat.parseDestinationNat(ruleSet)
// 		default:
// 			return fmt.Errorf("unknown NAT type: %s", ruleSet.natType)
// 		}

// 		if err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }
