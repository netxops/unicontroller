package command

import (
	"encoding/json"
	"fmt"
	"github.com/netxops/utils/netconf"
)

type NetconfCmd struct {
	netconf.RPCMessage
	Ip        string
	key       string
	timeout   int
	Lock      bool
	Force     bool
	cacheData *CacheData
	msg       string
	level     CommandLevel
	ok        bool
}

// type RPCMessage struct {
// XMLName   xml.Name `xml:"rpc"`
// Xmlns     []string `xml:"xmlns,attr,omitempty"`
// MessageID string   `xml:"message-id,attr,omitempty"`
// RPC-message body without rpc tag.
// InnerXML []byte `xml:",innerxml"`
// Use CustomAttrs to set a custom attributes in rpc tag. For example custom namespaces.
// CustomAttrs []string `xml:"-"`
// Set True for add optional XML header: `<?xml version="1.0" encoding="UTF-8"?>`.
// AppendXMLHeader bool        `xml:"-"`
// Methods         []RPCMethod `xml:"-"`
// }
//

func NewNetconfCmd(timeout int, lock bool, key string, force bool) *NetconfCmd {

	// message := netconf.RPCMessage{
	// InnerXML:        []byte(`<get-config><source><running/></source><filter><config-format-text-cmd><text-filter-spec>interface Ethernet0/0</text-filter-spec></config-format-text-cmd></filter></get-config>`),
	// Xmlns: []string{netconf.BaseURI},
	// CustomAttrs:     []string{`xmlns:cpi="http://www.cisco.com/cpi_10/schema"`},
	// AppendXMLHeader: true,
	// Methods:         []netconf.RPCMethod{netconf.MethodGetConfig("running")},
	// }
	if lock {
		force = true
	}

	return &NetconfCmd{
		RPCMessage: netconf.RPCMessage{
			AppendXMLHeader: true,
			Xmlns:           []string{netconf.BaseURI},
		},
		key:     key,
		timeout: timeout,
		Lock:    lock,
		Force:   force,
	}
}

func (nc *NetconfCmd) WithOk(ok bool) {
	nc.ok = ok
}

func (nc *NetconfCmd) Ok() bool {
	return nc.ok
}

func (nc *NetconfCmd) WithLevel(level CommandLevel) {
	nc.level = level
}

func (nc *NetconfCmd) Level() CommandLevel {
	return nc.level
}

func (nc *NetconfCmd) Cmd() string {
	byteS, err := json.Marshal(&struct {
		Key string
	}{
		Key: nc.key,
	})

	if err != nil {
		panic(err)
	}

	return string(byteS)
}

func (nc *NetconfCmd) WithMsg(msg string) {
	nc.msg = msg
}

func (nc *NetconfCmd) Timeout() int {
	return nc.timeout
}

func (nc *NetconfCmd) CacheData() *CacheData {
	return nc.cacheData
}

func (nc *NetconfCmd) Msg() string {
	return nc.msg
}

func (nc *NetconfCmd) Key() string {
	return nc.key
}

func (nc *NetconfCmd) Id(ip string) string {
	return fmt.Sprintf("%s_%s", ip, nc.Key())
}

func (nc *NetconfCmd) DisableHeader() *NetconfCmd {
	nc.RPCMessage.AppendXMLHeader = false
	return nc
}

func (nc *NetconfCmd) AppendXmlns(xmlns string, truncate bool) *NetconfCmd {
	if truncate {
		nc.RPCMessage.Xmlns = nc.RPCMessage.Xmlns[:0]
	}
	nc.RPCMessage.Xmlns = append(nc.RPCMessage.Xmlns, xmlns)
	return nc
}

func (nc *NetconfCmd) AppendCustomAttrs(attr string, truncate bool) *NetconfCmd {
	if truncate {
		nc.RPCMessage.CustomAttrs = nc.RPCMessage.CustomAttrs[:0]
	}
	nc.RPCMessage.CustomAttrs = append(nc.RPCMessage.CustomAttrs, attr)
	return nc
}

func (nc *NetconfCmd) AppendMethod(method netconf.RawMethod, truncate bool) *NetconfCmd {
	if truncate {
		nc.RPCMessage.Methods = nc.RPCMessage.Methods[:0]
	}
	nc.RPCMessage.Methods = append(nc.RPCMessage.Methods, method)
	return nc
}

func (nc *NetconfCmd) WithInnerXML(xml []byte) *NetconfCmd {
	nc.RPCMessage.InnerXML = make([]byte, len(xml))
	copy(nc.RPCMessage.InnerXML, xml)
	return nc
}

func (nc *NetconfCmd) SetCacheData(data *CacheData) {
	nc.cacheData = data
}
