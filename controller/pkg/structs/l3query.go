package structs

type MatchType string
type Protocol string
type Action string
type MatchStrategy string

const (
	Src  = MatchType("src")
	Dst  = MatchType("dst")
	Both = MatchType("both")

	Tcp  = Protocol("tcp")
	Udp  = Protocol("udp")
	Icmp = Protocol("icmp")

	Permit         = Action("permit")
	Deny           = Action("deny")
	Reject         = Action("reject")
	ImplicitPermit = Action("implicit_permit")
	ImplicitDeny   = Action("implicit_deny")
	NatMatched     = Action("nat_matched")
	NatNoMatched   = Action("nat_nomatched")

	Overlap          = MatchStrategy("overlap")
	Contains         = MatchStrategy("contains")
	ContainedBy      = MatchStrategy("containedby")
	Exact            = MatchStrategy("exact")
	Threshold        = MatchStrategy("threshold")
	OverlapIgnoreAny = MatchStrategy("overlapignoreany")
	IsolatedInQuery  = MatchStrategy("isolatedinquery") // 孤立地址在查询范围内
)

type Condition struct {
	IpRanges      string        `json:"ip_ranges"`
	Protocol      Protocol      `json:"protocol"`
	Port          string        `json:"port"`
	Action        Action        `json:"action"`
	MatchStrategy MatchStrategy `json:"match_strategy"`
	Threshold     float64       `json:"threshold"`
	MatchType     MatchType     `json:"match_type"`
	PolicyName    string        `json:"policy_name"`
}

type L3Config struct {
	NodeMap struct {
		Name   string `yaml:"name"`
		Force  bool   `yaml:"force"`
		TaskID uint   `yaml:"task_id"`
	} `yaml:"nodemap"`
	Policy struct {
		Source       string `yaml:"source"`
		Destination  string `yaml:"destination"`
		RealIp       string `yaml:"realIp"`
		RealPort     string `yaml:"realPort"`
		TicketNumber string `yaml:"ticketNumber"`
		SubTicket    string `yaml:"subTicket"`
		Service      struct {
			Protocol string `yaml:"protocol"`
			Port     string `yaml:"port"`
		} `yaml:"service"`
		Snat string `yaml:"snat"`
	} `yaml:"policy"`
}

type PolicyData struct {
	Result []DevicePolicy `json:"result"`
}

type DevicePolicy struct {
	Device   string          `json:"device"`
	Policies []PolicyDetails `json:"policies"`
}

type PolicyDetails struct {
	Cli             string            `json:"cli"`
	RuleName        string            `json:"ruleName"`
	Action          string            `json:"action"`
	Source          string            `json:"source"`
	Destination     string            `json:"destination"`
	Service         string            `json:"service"`
	MatchType       string            `json:"matchType"`
	OverallMatch    bool              `json:"overallMatch"`
	MatchedAddress  string            `json:"matchedAddress,omitempty"`
	ObjectRelations []ObjectRelation  `json:"objectRelations"`
	MatchDetails    []MatchDetailInfo `json:"matchDetails"`
}

type ObjectRelation struct {
	Type       string `json:"type"`       // "source", "destination", or "service"
	Name       string `json:"name"`       // Object name in the policy
	CLI        string `json:"cli"`        // CLI of the object
	PolicyLine string `json:"policyLine"` // The line in the policy that references this object
}

type MatchDetailInfo struct {
	MatcherName   string                 `json:"matcherName"`
	Matched       bool                   `json:"matched"`
	MatcherType   string                 `json:"matcherType"`
	MatcherValue  string                 `json:"matcherValue"`
	OverlapDetail float64                `json:"overlapDetail"`
	MatchType     string                 `json:"matchType"`
	ExtraInfo     map[string]interface{} `json:"extraInfo"`
}

//type L3PolicyResult struct {
//	CLI            string
//	Direction      string
//	ObjectCLI      string
//	RuleName       string
//	Action         string
//	Source         string
//	Destination    string
//	Service        string
//	MatchedAddress string
//}
