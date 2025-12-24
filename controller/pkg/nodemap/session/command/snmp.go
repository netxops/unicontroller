package command

import (
	"encoding/json"
	"fmt"
)

type SnmpPlan struct {
	Index         []int
	Prefix        []int
	PrefixMap     map[string]string
	PrefixCallMap map[string]func(byte, string, interface{}) (result string, err error)
	IndexCall     func(string) (result string, err error)
}

func NewSnmpPlan(index, prefix []int) *SnmpPlan {
	return &SnmpPlan{
		Index:  index,
		Prefix: prefix,
	}
}

func (sp *SnmpPlan) WithPrefixMap(prefixMap map[string]string) *SnmpPlan {
	sp.PrefixMap = prefixMap
	return sp
}

func (sp *SnmpPlan) WithPrefixCallMap(prefixCallMap map[string]func(byte, string, interface{}) (result string, err error)) *SnmpPlan {
	sp.PrefixCallMap = prefixCallMap
	return sp
}

func (sp *SnmpPlan) WithIndexCall(indexCall func(string) (result string, err error)) *SnmpPlan {
	sp.IndexCall = indexCall
	return sp
}

type SnmpCmd struct {
	Oid       string
	key       string
	Ip        string
	timeout   int
	Force     bool
	Plan      *SnmpPlan
	cacheData *CacheData
	msg       string
	level     CommandLevel
	ok        bool
}

func NewSnmpCmd(oid, key string, timeout int, force bool) *SnmpCmd {
	return &SnmpCmd{
		Oid:     oid,
		key:     key,
		timeout: timeout,
		Force:   force,
	}
}

func (sc *SnmpCmd) WithOk(ok bool) {
	sc.ok = ok
}

func (sc *SnmpCmd) Ok() bool {
	return sc.ok
}

func (sc *SnmpCmd) WithLevel(level CommandLevel) {
	sc.level = level
}

func (sc *SnmpCmd) Level() CommandLevel {
	return sc.level
}

func (sc *SnmpCmd) Cmd() string {
	byteS, err := json.Marshal(&struct {
		Key string
		Oid string
	}{
		Key: sc.Key(),
		Oid: sc.Oid,
	})

	if err != nil {
		panic(err)
	}

	return string(byteS)
}

func (sc *SnmpCmd) Id(ip string) string {
	return fmt.Sprintf("%s_%s_%s", ip, sc.Oid, sc.Key())
}

func (sc *SnmpCmd) SetCacheData(data *CacheData) {
	sc.cacheData = data
}

func (sc *SnmpCmd) SetPlan(plan *SnmpPlan) *SnmpCmd {
	sc.Plan = plan
	return sc
}

func (sc *SnmpCmd) CacheData() *CacheData {
	return sc.cacheData
}

func (sc *SnmpCmd) WithMsg(msg string) {
	sc.msg = msg
}

func (sc *SnmpCmd) Msg() string {
	return sc.msg
}

func (sc *SnmpCmd) Timeout() int {
	return sc.timeout
}
func (sc *SnmpCmd) Key() string {
	return sc.key
}
