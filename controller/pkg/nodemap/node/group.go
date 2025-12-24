package node

import (
	"encoding/json"
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"

	//"github.com/netxops/unify/global"
	"strings"

	"github.com/netxops/utils/validator"
)

type State int

const (
	UNKNOWN_STATE State = iota
	ACTIVE
	STANDBY
)

func (s State) String() string {
	return []string{"UNKNOWN_STATE", "ACTIVE", "STANDBY"}[s]
}

func ToState(state string) State {
	for index, m := range []string{"ACTIVE", "STANDBY"} {
		if strings.ToLower(m) == strings.ToLower(state) {
			return State(index + 1)
		}
	}
	return UNKNOWN_STATE
}

type FhrpGroup struct {
	FhrpGroupIp string                   `json:"group_ip" gorm:"group_ip"`
	FhrpMode    api.FhrpMode             `json:"fhrp_mode" gorm:"fhrp_mode"`
	Members     []api.Member             `json:"members" gorm:"members"`
	Chain       *validator.ValidateChain `json:"-" gorm:"-"`
}

func (fg *FhrpGroup) TypeName() string {
	return "FhrpGroup"
}

func (FhrpGroup) TableName() string {
	return "fhrp_group"
}

func (fg *FhrpGroup) GroupIp() string {
	return fg.FhrpGroupIp
}

type FhrpGroupValidator struct{}

func (v *FhrpGroupValidator) Validate(data map[string]interface{}) validator.Result {
	group := data["group"].(*FhrpGroup)
	member := data["member"].(*Member)

	if member.Ip() != group.FhrpGroupIp {
		return validator.NewValidateResult(false, fmt.Sprintf("group ip is not equal, member = %s, group = %s", member.Ip(), group.FhrpGroupIp))
	}

	if member.FhrpMode() != group.FhrpMode {
		return validator.NewValidateResult(false, fmt.Sprintf("mode id is not equal, member = %s, group = %s", member.FhrpMode(), group.FhrpMode))
	}

	// for _, m := range group.Members {
	a := group.Active()
	if a != nil && member.IsActive() {
		aj, _ := json.Marshal(a)
		mj, _ := json.Marshal(member)
		return validator.NewValidateResult(false, fmt.Sprintf("duplicate active member: [%s, %s]", string(aj), string(mj)))
	}
	// }

	return validator.NewValidateResult(true, "")
}

func NewFhrpGroup(FhrpGroupIp string, mode api.FhrpMode) *FhrpGroup {
	if mode == api.NONE {
		panic(fmt.Sprintf("invalid mode:%s", api.NONE))
	}

	data := map[string]interface{}{
		"ip":         FhrpGroupIp,
		"withPrefix": false,
	}
	var result validator.Result
	if strings.Index(FhrpGroupIp, ":") > 0 {
		result = validator.Ipv6Validator{}.Validate(data)
	} else {
		result = validator.Ipv4Validator{}.Validate(data)
	}

	if result.Status() == false {
		panic(result.Msg())
	}

	g := &FhrpGroup{
		FhrpGroupIp: FhrpGroupIp,
		FhrpMode:    mode,
		Members:     []api.Member{},
		Chain:       validator.NewValidateChain(),
	}
	g.Chain.Add(&FhrpGroupValidator{})
	return g
}

//
// func (g *FhrpGroup) WithConnector(connector *Connector) *FhrpGroup {
// g.Connector = connector
// return g
// }

func (g *FhrpGroup) AddMember(member api.Member) {
	d := map[string]interface{}{}
	d["group"] = g
	d["member"] = member

	result := g.Chain.Validate(d)
	if result.Status() {
		g.Members = append(g.Members, member)
	}
}

func (g *FhrpGroup) Active() api.Member {
	for _, m := range g.Members {
		if m.IsActive() {
			return m
		}
	}

	return nil
}

// MarshalJSON implements the json.Marshaler interface
//
//	func (fg FhrpGroup) MarshalJSON() ([]byte, error) {
//		type Alias FhrpGroup
//		members := make([]json.RawMessage, len(fg.Members))
//		for i, member := range fg.Members {
//			b, err := member.MarshalJSON()
//			if err != nil {
//				return nil, err
//			}
//			members[i] = json.RawMessage(b)
//		}
//		return json.Marshal(&struct {
//			Alias
//			FhrpMode string            `json:"fhrp_mode"`
//			Members  []json.RawMessage `json:"members"`
//		}{
//			Alias:    Alias(fg),
//			FhrpMode: fg.FhrpMode.String(),
//			Members:  members,
//		})
//	}
func (fg FhrpGroup) MarshalJSON() ([]byte, error) {
	type FhrpGroupAlias FhrpGroup
	return json.Marshal(&struct {
		FhrpGroupAlias
		FhrpMode string `json:"fhrp_mode"`
	}{
		FhrpGroupAlias: FhrpGroupAlias(fg),
		FhrpMode:       fg.FhrpMode.String(),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (fg *FhrpGroup) UnmarshalJSON(data []byte) error {
	type FhrpGroupAlias FhrpGroup
	aux := &struct {
		*FhrpGroupAlias
		FhrpMode string `json:"fhrp_mode"`
	}{
		FhrpGroupAlias: (*FhrpGroupAlias)(fg),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	fg.FhrpMode = api.ToMode(aux.FhrpMode)

	// Recreate the ValidateChain
	fg.Chain = validator.NewValidateChain()
	fg.Chain.Add(&FhrpGroupValidator{})

	return nil
}
