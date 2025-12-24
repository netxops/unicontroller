package secpath

// type ObjectManager struct {
// 	// spt *SecPathTemplates
// }

// func NewObjectManager() *ObjectManager {
// 	return &ObjectManager{}
// }

// // Address Object methods
// func (om *ObjectManager) CreateAddressObject(vrf, zone, name string, ng *network.NetworkGroup) (string, error) {
// 	// Implementation for creating address object
// 	clis := []string{
// 		fmt.Sprintf("object-group ip address %s", name),
// 	}

// 	layout := ` network {if:isRange==true}range {start} {end}{else if:isHost==true}host address {ip}{else}subnet {ip} {mask:dotted}{endif}`
// 	ng.Each(func(n network.AbbrNet) bool {
// 		clis = append(clis, dsl.NetworkFormat(n, layout))
// 		return true
// 	})

// 	return strings.Join(clis, "\n"), nil
// }

// func (om *ObjectManager) FindAddressObject(vrf, zone, name string) (*network.NetworkGroup, bool) {
// 	return om.spt.Node.Network(zone, name)
// }

// func (om *ObjectManager) UpdateAddressObject(vrf, zone, name string, ng *network.NetworkGroup) (string, error) {
// 	// First, clear existing object
// 	clis := []string{
// 		fmt.Sprintf("object-group ip address %s", name),
// 	}

// 	// Then add new addresses
// 	layout := ` network {if:isRange==true}range {start} {end}{else if:isHost==true}host address {ip}{else}subnet {ip} {mask:dotted}{endif}`
// 	ng.Each(func(n network.AbbrNet) bool {
// 		clis = append(clis, dsl.NetworkFormat(n, layout))
// 		return true
// 	})

// 	return strings.Join(clis, "\n"), nil
// }

// func (om *ObjectManager) FindOrCreateAddressObject(vrf, zone, name string, ng *network.NetworkGroup) (string, bool, error) {
// 	existingNg, found := om.FindAddressObject(vrf, zone, name)
// 	if found {
// 		if existingNg.Same(ng) {
// 			return "", true, nil
// 		}
// 		cli, err := om.UpdateAddressObject(vrf, zone, name, ng)
// 		return cli, true, err
// 	}
// 	cli, err := om.CreateAddressObject(vrf, zone, name, ng)
// 	return cli, false, err
// }

// // Service Object methods
// func (om *ObjectManager) CreateServiceObject(name string, s *service.Service) (string, error) {
// 	clis := []string{fmt.Sprintf("object-group service %s", name)}

// 	layout := `{set:service.range_format=" "}` +
// 		`{set:service.l3_format.template=" service {protocol:number}"}` +
// 		`{set:service.icmp_format.template=" service {protocol:number}"}` +
// 		`{set:service.tcp_format.template=" service {protocol:lower} {if:src_port!='0 65535'}source {src_port:range} {endif}destination {dst_port:range}"}` +
// 		`{full_service}`

// 	result := dsl.ServiceFormat(s, layout)
// 	clis = append(clis, strings.Split(result, "\n")...)

// 	return strings.Join(clis, "\n"), nil
// }

// func (om *ObjectManager) FindServiceObject(name string) (*service.Service, bool) {
// 	return om.spt.Node.Service(name)
// }

// func (om *ObjectManager) UpdateServiceObject(name string, s *service.Service) (string, error) {
// 	// First, clear existing object
// 	clis := []string{
// 		fmt.Sprintf("object-group service %s", name),
// 		" clear-service",
// 	}

// 	// Then add new services
// 	layout := `{set:service.range_format=" "}` +
// 		`{set:service.l3_format.template=" service {protocol:number}"}` +
// 		`{set:service.icmp_format.template=" service {protocol:number}"}` +
// 		`{set:service.tcp_format.template=" service {protocol:lower} {if:src_port!='0 65535'}source {src_port:range} {endif}destination {dst_port:range}"}` +
// 		`{full_service}`

// 	result := dsl.ServiceFormat(s, layout)
// 	clis = append(clis, strings.Split(result, "\n")...)

// 	return strings.Join(clis, "\n"), nil
// }

// func (om *ObjectManager) FindOrCreateServiceObject(name string, s *service.Service) (string, bool, error) {
// 	existingService, found := om.FindServiceObject(name)
// 	if found {
// 		if existingService.Same(s) {
// 			return "", true, nil
// 		}
// 		cli, err := om.UpdateServiceObject(name, s)
// 		return cli, true, err
// 	}
// 	cli, err := om.CreateServiceObject(name, s)
// 	return cli, false, err
// }

// // Pool methods
// func (om *ObjectManager) CreatePool(ng *network.NetworkGroup) (int, string, error) {
// 	id := om.spt.Node.(firewall.PoolIdFirewall).NextPoolId()
// 	clis := []string{
// 		fmt.Sprintf("nat address-group %d", id),
// 	}

// 	net := ng.GenerateNetwork()
// 	clis = append(clis, fmt.Sprintf(" address %s %s", net.First().String(), net.First().String()))

// 	return id, strings.Join(clis, "\n"), nil
// }

// func (om *ObjectManager) FindPool(ng *network.NetworkGroup) (firewall.FirewallNetworkObject, bool) {
// 	return om.spt.Node.GetPoolByNetworkGroup(ng, firewall.DYNAMIC_NAT)
// }
