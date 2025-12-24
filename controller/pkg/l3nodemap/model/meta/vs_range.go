package meta

type VsRange struct {
	Type    string `json:"type" mapstructure:"type"`
	Network string `json:"network" mapstructure:"network"`
	Vrf     string `json:"vrf" mapstructure:"vrf"`
}
