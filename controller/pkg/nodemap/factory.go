package nodemap

import (
	ASA "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/asa"
	DP "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/dptech"
	FortiGate "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti"
	SANGFOR "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/sangfor"
	SECPATH "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/secpath"
	SRX "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/srx"
	USG "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/usg"
	F5 "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/lb/f5"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/router"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/router/h3c"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/asa"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/dptech"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/forti"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/sangfor"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/secpath"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/srx"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/usg"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/lb"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/lb/f5"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/netxops/cli/terminalmode"
)

func NodeMapInit() {
	node.NodeInit()
}

// normalizeDeviceType 标准化设备类型名称
// 将各种变体映射到标准设备类型
func normalizeDeviceType(deviceType string) string {
	switch deviceType {
	case "SangforOS", "SANGFOR", "sangfor":
		return "Sangfor"
	default:
		return deviceType
	}
}

// func NewDeviceBaseInfo(host, user, pass, devType, community string, port int) *DeviceBaseInfo {
// func NewAdapter(dc *config.DeviceConfig, task_id uint, dumpDb bool) api.Adapter {
func NewAdapter(dc *config.DeviceConfig) api.Adapter {
	// 标准化设备类型名称
	normalizedMode := normalizeDeviceType(dc.Mode)
	baseInfo := session.NewDeviceBaseInfo(dc.Host, dc.Username, dc.Password, normalizedMode, dc.Community, dc.Port)

	if dc.Telnet {
		baseInfo.WithTelnet(dc.Telnet)
	}
	if dc.AuthPass != "" {
		baseInfo.WithAuthPass(dc.AuthPass)
	}
	if dc.Token != "" {
		baseInfo.WithToken(dc.Token)
	}
	//if dc.DevTablesID == 0 {
	//	panic("DevTables is empty")
	//}
	switch baseInfo.Type {
	case terminalmode.ASA:
		return ASA.NewASAAdapter(baseInfo, dc.Config)
	case terminalmode.Nexus:
	case terminalmode.IOS:
		return router.NewBaseIosAdapter(baseInfo, dc.Config)
	case terminalmode.SRX:
		return SRX.NewSRXAdapter(baseInfo, dc.Config)
	case terminalmode.Comware:
		return h3c.NewH3CAdapter(baseInfo, dc.Config)
	case terminalmode.ACI:
	case terminalmode.SecPath:
		return SECPATH.NewSecPathAdapter(baseInfo, dc.Config)
	case terminalmode.F5:
		return F5.NewF5Adapter(baseInfo, dc.Config)
	case terminalmode.FortiGate:
		return FortiGate.NewFortiAdapter(baseInfo, dc.Config)
	case terminalmode.Dptech:
		return DP.NewDptechAdapter(baseInfo, dc.Config)
	case terminalmode.HuaWei:
		return USG.NewUsgAdapter(baseInfo, dc.Config)
	case terminalmode.Sangfor:
		return SANGFOR.NewSangforAdapter(baseInfo, dc.Config)
	default:
		return nil
	}

	return nil
}

func newLBNodeFromAdapter(ad api.Adapter, nodemapName string, force bool) lb.LBNode {
	switch ad.(type) {
	case *F5.F5Adapter:
		n := &f5.F5Node{
			DeviceNode: node.DeviceNode{
				NodeMapName: nodemapName,
			},
		}
		n.WithName(ad.ParseName(force))
		return n
	}

	return nil
}

func newFirewallNodeFromAdapter(ad api.Adapter, nodemapName string, force bool) firewall.FirewallNode {
	switch ad.(type) {
	case *ASA.ASAAdapter:
		n := &asa.ASANode{
			DeviceNode: &node.DeviceNode{
				NodeMapName: nodemapName,
			},
		}

		n.WithName(ad.ParseName(force))
		return n
	case *FortiGate.FortigateAdapter:
		n := &forti.FortigateNode{
			DeviceNode: &node.DeviceNode{
				NodeMapName: nodemapName,
			},
		}

		n.WithName(ad.ParseName(force))
		return n
	case *SRX.SRXAdapter:
		n := &srx.SRXNode{
			DeviceNode: &node.DeviceNode{
				NodeMapName: nodemapName,
			},
		}
		n.WithName(ad.ParseName(force))
		return n
	case *DP.DptechAdapter:
		n := &dptech.DptechNode{
			DeviceNode: &node.DeviceNode{
				NodeMapName: nodemapName,
			},
		}
		n.WithName(ad.ParseName(force))
		return n
	case *USG.UsgAdapter:
		n := &usg.UsgNode{
			DeviceNode: &node.DeviceNode{
				NodeMapName: nodemapName,
			},
		}
		n.WithName(ad.ParseName(force))
		return n
	case *SECPATH.SecPathAdapter:
		n := &secpath.SecPathNode{
			DeviceNode: &node.DeviceNode{
				NodeMapName: nodemapName,
			},
		}

		n.WithName(ad.ParseName(force))
		return n
	case *SANGFOR.SangforAdapter:
		n := &sangfor.SangforNode{
			DeviceNode: &node.DeviceNode{
				NodeMapName: nodemapName,
			},
		}
		n.WithName(ad.ParseName(force))
		return n
	}

	return nil
}

func NewNodeFromAdapter(ad api.Adapter, nodemapName string, force bool) api.Node {
	switch ad.(type) {
	case *router.BaseIosAdapter:
		n := &node.DeviceNode{
			NodeMapName: nodemapName,
		}

		return n.WithName(ad.ParseName(force))
	case *h3c.H3CAdapter:
		n := &node.DeviceNode{
			NodeMapName: nodemapName,
		}

		return n.WithName(ad.ParseName(force))
	case *F5.F5Adapter:
		return newLBNodeFromAdapter(ad, nodemapName, force).(api.Node)
	case *FortiGate.FortigateAdapter:
		return newFirewallNodeFromAdapter(ad, nodemapName, force).(api.Node)
	case *ASA.ASAAdapter, *SRX.SRXAdapter, *SECPATH.SecPathAdapter:
		return newFirewallNodeFromAdapter(ad, nodemapName, force).(api.Node)

	case *DP.DptechAdapter:
		return newFirewallNodeFromAdapter(ad, nodemapName, force).(api.Node)
	case *USG.UsgAdapter:
		return newFirewallNodeFromAdapter(ad, nodemapName, force).(api.Node)
	case *SANGFOR.SangforAdapter:
		return newFirewallNodeFromAdapter(ad, nodemapName, force).(api.Node)

		// n := &asa.ASANode{
		// DeviceNode: node.DeviceNode{
		// NodeMapName: nodemapName,
		// },
		// }
		//
		// return n.WithName(ad.ParseName(force))
		// case *SRX.SRXAdapter:
		// n := &srx.SRXNode{
		// DeviceNode: node.DeviceNode{
		// NodeMapName: nodemapName,
		// },
		// }
		// return n.WithName(ad.ParseName(force))
	}

	return nil
}
