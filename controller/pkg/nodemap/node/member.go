package node

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/netxops/utils/registry"

	//"github.com/netxops/unify/constant"
	//"github.com/netxops/unify/global"
	"strings"
)

type Member struct {
	MemberPortName string       `json:"port_name" gorm:"column:port_name"`
	FrhgGroupId    int          `json:"group_id" gorm:"column:group_id"`
	MemberIp       string       `json:"ip" gorm:"column:ip"`
	Priority       int          `json:"priority" gorm:"column:priority"`
	MemberFhrpMode api.FhrpMode `json:"mode" gorm:"column:fhrp_mode"`
	State          State        `json:"state" gorm:"column:state"`
}

func (m Member) TypeName() string {
	return "Member"
}

func (Member) TableName() string {
	return "fhrp_member"
}

// func NewMember(MemberPortName, MemberIp, state, mode string, groupId, Priority int, port *Port) *Member {
func NewMember(MemberPortName, MemberIp, state, mode string, groupId, Priority int) *Member {
	s := ToState(state)
	if s == UNKNOWN_STATE {
		panic(fmt.Sprintf("invalid state:%s", state))
	}
	m := api.ToMode(mode)
	if m == api.NONE {
		panic(fmt.Sprintf("invalid mode:%s", mode))
	}
	return &Member{
		MemberPortName: MemberPortName,
		MemberIp:       MemberIp,
		Priority:       Priority,
		State:          s,
		MemberFhrpMode: m,
		FrhgGroupId:    groupId,
		// Port:     port,
	}
}

func (m Member) PortName() string {
	return m.MemberPortName
}

func (m Member) FhrpMode() api.FhrpMode {
	return m.MemberFhrpMode
}

func (m Member) Ip() string {
	return m.MemberIp
}

func (m Member) IsActive() bool {
	return m.State == ACTIVE
}

func (m Member) Hit(MemberIp string) bool {
	if m.State == ACTIVE {
		if strings.ToLower(m.Ip()) == strings.ToLower(MemberIp) {
			return true
		}
	}

	return false
}

// MarshalJSON implements the json.Marshaler interface
func (m Member) MarshalJSON() ([]byte, error) {
	type MemberAlias Member
	return json.Marshal(&struct {
		MemberAlias
		MemberFhrpMode string `json:"mode"`
		State          string `json:"state"`
	}{
		MemberAlias:    MemberAlias(m),
		MemberFhrpMode: m.MemberFhrpMode.String(),
		State:          m.State.String(),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *Member) UnmarshalJSON(data []byte) error {
	type MemberAlias Member
	aux := &struct {
		*MemberAlias
		MemberFhrpMode string `json:"mode"`
		State          string `json:"state"`
	}{
		MemberAlias: (*MemberAlias)(m),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	m.MemberFhrpMode = api.ToMode(aux.MemberFhrpMode)
	m.State = ToState(aux.State)

	return nil
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Member)(nil)).Elem(), "Member", reflect.TypeOf(Member{}))
}
