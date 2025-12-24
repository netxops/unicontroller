package node

import (
	"encoding/json"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/stretchr/testify/assert"
)

func TestFhrpGroupMarshalJSON(t *testing.T) {
	// Create a sample FhrpGroup
	group := NewFhrpGroup("192.168.1.1", api.HSRP)
	member1 := &Member{
		MemberPortName: "GigabitEthernet1/0/1",
		FrhgGroupId:    1,
		MemberIp:       "192.168.1.1",
		Priority:       100,
		MemberFhrpMode: api.HSRP,
		State:          ACTIVE,
	}
	member2 := &Member{
		MemberPortName: "GigabitEthernet1/0/2",
		FrhgGroupId:    1,
		MemberIp:       "192.168.1.1",
		Priority:       90,
		MemberFhrpMode: api.HSRP,
		State:          STANDBY,
	}
	group.AddMember(member1)
	group.AddMember(member2)

	// Marshal the FhrpGroup to JSON
	jsonData, err := json.Marshal(group)
	assert.NoError(t, err)

	// Define the expected JSON structure
	expectedJSON := `{
        "group_ip": "192.168.1.1",
        "fhrp_mode": "HSRP",
        "members": [
            {
                "port_name": "GigabitEthernet1/0/1",
                "group_id": 1,
                "ip": "192.168.1.1",
                "priority": 100,
                "mode": "HSRP",
                "state": "ACTIVE"
            },
            {
                "port_name": "GigabitEthernet1/0/2",
                "group_id": 1,
                "ip": "192.168.1.1",
                "priority": 90,
                "mode": "HSRP",
                "state": "STANDBY"
            }
        ]
    }`

	// Compare the actual JSON with the expected JSON
	var actualJSON map[string]interface{}
	err = json.Unmarshal(jsonData, &actualJSON)
	assert.NoError(t, err)

	var expectedJSONMap map[string]interface{}
	err = json.Unmarshal([]byte(expectedJSON), &expectedJSONMap)
	assert.NoError(t, err)

	assert.Equal(t, expectedJSONMap, actualJSON)
}
