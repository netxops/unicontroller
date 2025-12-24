package meta

type DeviceInterconnection struct {
	Interface string   `json:"interface" mapstructure:"interface"`
	Vrf       string   `json:"vrf" mapstructure:"vrf"`
	PeerVrf   []string `json:"peer_vrf" mapstructure:"peer_vrf"`
}
