package aci

const (
	FvTenantApi        = "/api/node/class/fvTenant.json"
	FvAEpgApi          = "/api/node/class/fvAEPg.json"
	FvBdApi            = "/api/node/class/fvBD.json"
	EpTrackerApi       = "/api/node/class/fvCEp.json"
	VzBrCpApi          = "/api/node/class/vzBrCP.json"
	FabricPathEpApi    = "/api/node/class/fabricPathEp.json"
	ControllerApi      = "/api/node/mo/topology/pod-1/node-1.json"
	ControllersSizeApi = "/api/node/class/fabricNode.json?query-target-filter=or(eq(fabricNode.role,\"leaf\"),eq(fabricNode.role,\"controller\"))"
	FvApApi            = "/api/node/class/fvAp.json"
	FvSubnetApi        = "/api/node/class/fvSubnet.json"
	FortyPolicyApi     = "/api/node/mo/uni/tn-DevOps/ap-Public.Internet.Policy-AEP/epg-Shared.Internet.FW.Policy-EPG/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-PolicyObjects/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-IPv4FWPolicyFolder/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-65534.json?query-target=subtree"
	FortiSubnetApi     = "/api/node/mo/uni/tn-DevOps/ap-Public.Internet.Policy-AEP/epg-Shared.Internet.FW.Policy-EPG/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-PolicyObjects/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-IPv4FWAddressFolder/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-TEST_HOST_4.json?query-target=subtree"
	FortiServiceApi    = "/api/node/mo/uni/tn-DevOps/ap-Public.Internet.Policy-AEP/epg-Shared.Internet.FW.Policy-EPG/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-PolicyObjects/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-FWServiceFolder/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-TCP_5555.json?query-target=subtree"
	FirmwareApi        = "/api/node/class/topology/pod-1/node-1/firmwareCtrlrRunning.json"
	VzFilterApi        = "/api/node/mo/uni/tn-TenantB.json?query-target=children&target-subtree-class=vzFilter"
	VzEntryApi         = "/api/node/class/vzEntry.json"
	ContractApi        = "/api/node/mo/uni/tn-TenantB.json?query-target=children&target-subtree-class=vzBrCP&rsp-subtree=children"
)
