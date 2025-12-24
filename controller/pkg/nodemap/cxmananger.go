package nodemap

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/registry"

	"github.com/google/uuid"
)

type ConnectorManager struct {
	ConnectorList []api.Connector
}

// connectorManagerJSON 用于序列化和反序列化
type connectorManagerJSON struct {
	ConnectorList []json.RawMessage `json:"connectorList"`
}

// MarshalJSON 实现 JSON 序列化
func (cm *ConnectorManager) MarshalJSON() ([]byte, error) {
	connectorList, err := registry.InterfacesToRawMessages(cm.ConnectorList)
	if err != nil {
		return nil, err
	}

	return json.Marshal(&connectorManagerJSON{
		ConnectorList: connectorList,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (cm *ConnectorManager) UnmarshalJSON(data []byte) error {
	var cmj connectorManagerJSON
	if err := json.Unmarshal(data, &cmj); err != nil {
		return err
	}

	connectorList, err := registry.RawMessagesToInterfaces[api.Connector](cmj.ConnectorList)
	if err != nil {
		return err
	}
	cm.ConnectorList = connectorList

	return nil
}

func (cx *ConnectorManager) NewConnector(mode api.Mode) api.Connector {
	c := node.NewConnector(uuid.New().String(), mode)
	cx.ConnectorList = append(cx.ConnectorList, c)
	return c
}

func (cx *ConnectorManager) GetConnectorByNetwork(net network.AbbrNet, vrf string) api.Connector {
	for _, c := range cx.ConnectorList {
		if c.HitByNetwork(net, vrf) {
			return c
		}
	}
	return nil
}

func (cx *ConnectorManager) GetConnectorByID(id string) api.Connector {
	for _, c := range cx.ConnectorList {
		if c.ID() == id {
			return c
		}
	}

	return nil
}

func (cx *ConnectorManager) GetConnectorByIp(ip, vrf string) api.Connector {
	for _, c := range cx.ConnectorList {
		if c.HitByIp(ip, vrf) {
			return c
		}
	}

	return nil
}

func (cx *ConnectorManager) GetOrCreateConnectorByPort(port api.Port, connections []*config.ConnectionInfo) api.Connector {
	vrf := port.Vrf()
	cs := map[api.Connector]int{}

	if vrf == "" {
		panic(fmt.Sprintf("port: %+v, vrf is empty", port))
	}

	for _, ipv4 := range port.GetIpList()[network.IPv4] {
		c1 := cx.GetConnectorByIp(ipv4, vrf)
		if c1 != nil {
			cs[c1] = 1
		}
	}

	for _, ipv6 := range port.GetIpList()[network.IPv6] {
		if strings.Index(strings.ToLower(ipv6), strings.ToLower("FE80")) == 0 {
			continue
		}

		c1 := cx.GetConnectorByIp(ipv6, vrf)
		if c1 != nil {
			cs[c1] = 1
		}
	}

	if len(cs) == 0 {
		c := cx.NewConnector(api.MP)
		return c
	} else if len(cs) == 1 {
		for c, _ := range cs {
			return c
		}
	} else {
		fmt.Println("port", port)
		//for k, c := range cs {
		//	fmt.Println("ckey=", k, " || cval=", c)
		//}
		panic("Current not support multiple connector")
	}

	return nil
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Connector)(nil)).Elem(), "NodeConnector", reflect.TypeOf(node.NodeConnector{}))
	// 注册其他 Connector 实现...
}
