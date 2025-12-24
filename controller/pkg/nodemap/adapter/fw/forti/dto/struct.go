package dto

import "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/enum"

type FortiPort struct {
	// Portname          string `json:"portname"`
	Ip                   string `json:"ip,omitempty"`
	Alias                string `json:"alias,omitempty"`
	Status               string `json:"status,omitempty"`
	DeviceIdentification string `json:"device-identification,omitempty"`
	TCPMss               string `json:"tcp-mss,omitempty"`
	Speed                string `json:"speed,omitempty"`
	MtuOverride          string `json:"mtu-override,omitempty"`
	Mtu                  string `json:"mtu,omitempty"`
	Role                 string `json:"role,omitempty"`
	Allowaccess          string `json:"allowaccess,omitempty"`
	Mode                 string `json:"mode,omitempty"`
	DNSServerOverride    string `json:"dns-server-override,omitempty"`
	Defaultgw            string `json:"defaultgw,omitempty"`
	Distance             string `json:"distance,omitempty"`
	Description          string `json:"description"`
	Type                 string `json:"type"`
	Interface            string `json:"interface,omitempty"`
	Name                 string `json:"name"`
	Vdom                 string `json:"vdom,omitempty"`
	Vlanid               string `json:"vlanid,omitempty"`
}

type FortiResponse struct {
	Path       string           `json:"path"`
	Name       string           `json:"name"`
	Status     string           `json:"status"`
	HttpStatus float64          `json:"http_status"`
	Results    []ForiRespResult `json:"results"`
}

type ForiRespResult struct {
	//QOriginKey string         `json:"q_origin_key"`
	StructType          enum.StructType `json:"structType"`
	ObjectType          string          `json:"object-type"`
	Subnet              string          `json:"subnet"`
	Name                string          `json:"name"`
	Ip6                 string          `json:"ip6"`
	Ip                  string          `json:"ip"`
	Action              string          `json:"action"`
	PolicyId            *int64          `json:"policyid"`
	Member              []ResultMember  `json:"member"`
	SrcIntf             []ResultMember  `json:"srcintf"`
	DstIntf             []ResultMember  `json:"dstintf"`
	SrcAddr             []ResultMember  `json:"srcaddr"`
	DstAddr             []ResultMember  `json:"dstaddr"`
	SrcAddr6            []ResultMember  `json:"srcaddr6"`
	DstAddr6            []ResultMember  `json:"dstaddr6"`
	Service             []ResultMember  `json:"service"`
	PoolName            []ResultMember  `json:"poolname"`
	PoolName6           []ResultMember  `json:"poolname6"`
	AssociatedInterface string          `json:"associated-interface"`
	Status              string          `json:"status"`
	Type                string          `json:"type"`
	StartIp             string          `json:"start-ip"`
	EndIp               string          `json:"end-ip"`
	ProtocolNumber      int             `json:"protocol-number"`

	IpRange       string `json:"iprange"`
	Category      string `json:"category"`
	Protocol      string `json:"protocol"`
	TcpPortRange  string `json:"tcp-portrange"`
	UdpPortRange  string `json:"udp-portrange"`
	SctpPortRange string `json:"sctp-portrange"`

	ExtIp       string         `json:"extip"`
	ExtIntf     string         `json:"extintf"`
	MappedIp    []ResultMember `json:"mappedip"`
	ExtPort     string         `json:"extport"`
	MappedPort  string         `json:"mappedport"`
	PortForward string         `json:"portforward"`

	StartIpPool       string `json:"startip"`
	EndIpPool         string `json:"endip"`
	StartPortPool     int    `json:"startport"`
	EndPortPool       int    `json:"endport"`
	SourceStartIpPool string `json:"source-startip"`
	SourceEndIpPool   string `json:"source-endip"`

	Nat    string `json:"nat"`
	IsPool string `json:"ispool"`
}

type ResultMember struct {
	QOriginKey string `json:"q_origin_key"`
	Name       string `json:"name"`
	Range      string `json:"range"`
}
