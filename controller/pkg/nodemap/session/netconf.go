package session

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"

	//"github.com/netxops/unify/global"
	"time"

	"github.com/netxops/utils/netconf"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type NetconfSession struct {
	Session
	Info *DeviceBaseInfo
	log  *zap.Logger
}

func NewNetconfSession(info *DeviceBaseInfo) *NetconfSession {
	// if global.GVA_LOG == nil {
	// global.GVA_LOG = core.Zap()
	// }
	log := zap.NewNop()

	return &NetconfSession{
		Info: info,
		log:  log,
	}

	//
	// targetDevice := &netconf.TargetDevice{
	// IP:   "172.32.1.100",
	// Port: 830,
	// SSHConfig: ssh.ClientConfig{
	// Config: ssh.Config{
	// Ciphers:      []string{"aes128-cbc", "hmac-sha1"},
	// KeyExchanges: []string{"diffie-hellman-group1-sha1"},
	// },
	// User:            "netops",
	// Auth:            []ssh.AuthMethod{ssh.Password("dfzq600958@2017")},
	// HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	// Timeout:         30 * time.Second},
	// }

	// message := netconf.RPCMessage{
	// InnerXML:        []byte(`<get-config><source><running/></source><filter><config-format-text-cmd><text-filter-spec>interface Ethernet0/0</text-filter-spec></config-format-text-cmd></filter></get-config>`),
	// Xmlns: []string{netconf.BaseURI},
	// CustomAttrs:     []string{`xmlns:cpi="http://www.cisco.com/cpi_10/schema"`},
	// AppendXMLHeader: true,
	// Methods:         []netconf.RPCMethod{netconf.MethodGetConfig("running")},
	// }
	// rpcReply, err := targetDevice.Action(message, "")
	// if err != nil {
	// log.Fatal(rpcReply)
	// }
	// spew.Dump(rpcReply)
	// fmt.Println(string(rpcReply.Content))

}

func (ns *NetconfSession) Run(cmd *command.NetconfCmd) (*command.CacheData, error) {
	var cd *command.CacheData
	if !cmd.Force {
		cd, err := ns.Get(ns.Info.BaseInfo.Host, cmd)
		if cd != nil {
			if !cd.IsTimeout() {
				ns.log.Info("using cache data, ", zap.Any("id", cmd.Id(ns.Info.BaseInfo.Host)))
				return cd, err
			}
		}

	}

	targetDevice := &netconf.TargetDevice{
		IP:   ns.Info.BaseInfo.Host,
		Port: 830,
		SSHConfig: ssh.ClientConfig{
			Config: ssh.Config{
				// Ciphers:      []string{"aes128-cbc", "hmac-sha1"},
				// KeyExchanges: []string{"diffie-hellman-group1-sha1"},
			},
			User:            ns.Info.BaseInfo.Username,
			Auth:            []ssh.AuthMethod{ssh.Password(ns.Info.BaseInfo.Password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second},
	}

	rpcReply, err := targetDevice.Action(cmd.RPCMessage, "")

	if err != nil {
		return nil, err
		// log.Fatal(rpcReply)
	}

	if rpcReply.GetErrors() != nil {
		return nil, rpcReply.GetErrors()
	}

	cd = command.NewCacheData(rpcReply.Content)
	ns.Session.Set(ns.Info.BaseInfo.Host, cmd, cd)
	cmd.SetCacheData(cd)

	return cd, nil
}
