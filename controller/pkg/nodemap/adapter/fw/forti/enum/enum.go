package enum

type ApiPath string

const (
	Info                  = ApiPath("/api/v2/cmdb/system/global")
	Interfaces            = ApiPath("/api/v2/cmdb/system/interface")
	FirewallAddress       = ApiPath("/api/v2/cmdb/firewall/address")
	FirewallAddress6      = ApiPath("/api/v2/cmdb/firewall/address6")
	FirewallAddrgrp       = ApiPath("/api/v2/cmdb/firewall/addrgrp")
	FirewallAddrgrp6      = ApiPath("/api/v2/cmdb/firewall/addrgrp6")
	FirewallServiceCustom = ApiPath("/api/v2/cmdb/firewall.service/custom")
	FirewallServiceGroup  = ApiPath("/api/v2/cmdb/firewall.service/group")
	FirewallPolicy        = ApiPath("/api/v2/cmdb/firewall/policy")
	FirewallVip           = ApiPath("/api/v2/cmdb/firewall/vip")
	FirewallVipGroup      = ApiPath("/api/v2/cmdb/firewall/vipgrp")
	FirewallObjectIPPool  = ApiPath("/api/v2/cmdb/firewall/ippool")
)

type StructType string

const (
	VIP     = StructType("VIP")
	SERVICE = StructType("SERVICE")
	ADDRESS = StructType("ADDRESS")
	POLICY  = StructType("POLICY")
	POOL    = StructType("POOL")
)
