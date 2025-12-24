package f5

import (
	"fmt"
	"runtime"
	"strings"

	F5 "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/lb"
	"github.com/influxdata/telegraf/controller/pkg/l3nodemap/l3cache"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	agentSession "github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	l2Session "github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/tools"
)

var cacheManager = l3cache.GetAdapterCacheManager()

type F5Adapter struct {
	Type       api.AdapterType
	DeviceType terminalmode.DeviceType
	info       *agentSession.DeviceBaseInfo
	//Task        *model.ExtractTask

	Partitions   []F5.Partition
	RouteDomains map[string]F5.RouteDomain
	Nodes        map[string]F5.Node
	Pools        map[string]F5.Pool
	SnatPools    map[string]F5.SnatPool
	Snats        map[string]F5.Snat
	Virtuals     map[int]map[string]F5.Virtual
}

func NewF5Adapter(info *agentSession.DeviceBaseInfo, config string) *F5Adapter {
	return &F5Adapter{
		DeviceType: terminalmode.F5,
		info:       info,
		Type:       tools.ConditionalT(info == nil, api.StringAdapter, api.LiveAdapter),

		Partitions:   []F5.Partition{},
		RouteDomains: map[string]F5.RouteDomain{},
		Nodes:        map[string]F5.Node{},
		Pools:        map[string]F5.Pool{},
		SnatPools:    map[string]F5.SnatPool{},
		Snats:        map[string]F5.Snat{},
		Virtuals:     map[int]map[string]F5.Virtual{},
	}
}

func (adapter *F5Adapter) DrityMark(funcKey string) error {
	adapterName := adapter.ParseName(false)
	return cacheManager.DrityMark(adapterName, funcKey)
}

func (adapter *F5Adapter) GetAdapterCache(funcKey string) []interface{} {
	adapterName := adapter.ParseName(false)
	caches := cacheManager.GetAdapterCaches(adapterName)
	return cacheManager.Get(caches, adapterName, funcKey)
}

func (adapter *F5Adapter) SaveAdapterCache(funcKey string, val []interface{}) error {
	adapterName := adapter.ParseName(false)
	return cacheManager.SaveAdapterCache(adapterName, funcKey, val)
}

func (bia *F5Adapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	funcName := runFuncName()
	data := bia.GetAdapterCache(funcName)
	if data != nil {
		return data[0].(*device.DeviceBaseInfo), nil
	}

	sess, err := newHttpSession(bia)
	if err != nil {
		return nil, err
	}

	info, err := F5.F5Info(sess)
	if err != nil {
		return nil, err
	}

	result := &device.DeviceBaseInfo{
		Hostname: bia.info.BaseInfo.Host,
		Version:  info.Version,
		Model:    info.Model,
		SN:       strings.Join(info.Sn, ","),
	}
	bia.WithInfo(result)

	cacheData := []interface{}{result}
	if err = bia.SaveAdapterCache(funcName, cacheData); err != nil {
		return result, err
	}
	return result, nil
}

func (adapter *F5Adapter) TaskId() uint {
	//return adapter.Task.ID
	return 1
}

func (adapter *F5Adapter) GetConfig(force bool) interface{} {
	return adapter.info
}

func (adapter *F5Adapter) ParseName(force bool) string {
	info, err := adapter.Info(force)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s|%s", info.Hostname, info.SN)
}

// 批量执行，输入[]*command.CliCmdList，就是命令列表的列表
// 这就意味着需要多次登录网络设备执行
func (adapter *F5Adapter) BatchRun(p interface{}) (interface{}, error) {
	return nil, nil
}

// 为了避免多次登录设备执行命令，需要将所有待执行命令合并到一起执行
// 但是为了前端显示方便区分阶段性执行结果，又需要将执行结果按照输入时的顺序进行保存
func (adapter *F5Adapter) BatchConfig(p ...interface{}) (interface{}, error) {
	return nil, nil
}

func (bia *F5Adapter) AttachChannel(out chan string) bool {
	return false
}

func (adapter *F5Adapter) PortList(force bool) []api.Port {
	funcName := runFuncName()
	data := adapter.GetAdapterCache(funcName)
	if data != nil {
		return data[0].([]api.Port)
	}

	result := []api.Port{}

	hs, err := newHttpSession(adapter)
	if err != nil {
		return result
	}

	//==========interfaces
	intfs, err := F5.F5Interface(hs)
	if err != nil || len(intfs) == 0 {
		return result
	}

	//==========vlan
	vlans, err := F5.F5Vlan(hs)
	if err != nil || len(vlans) == 0 {
		return result
	}

	//==========partition
	partitions, err := F5.F5Partition(hs)
	if err != nil {
		return nil
	}

	//==========routeDomain
	routeDomain, err := F5.F5RouteDomain(hs)
	if err != nil {
		return nil
	}

	//==========self
	vlans, routeDomain, err = F5.F5Self(hs, intfs, vlans, routeDomain, partitions)
	if err != nil {
		return nil
	}

	//==========interfaces build
	interfaces := F5.PrefectInterfaces(vlans)
	fmt.Println(fmt.Sprintf("interfaces = %#v", interfaces))

	ports := []api.Port{}
	for _, intf := range interfaces {
		port := node.NewPort(intf.Name, "", map[network.IPFamily][]string{}, []api.Member{})
		port.WithAliasName(intf.Name)
		port.WithVrf(intf.Vrf)
		for _, ip4 := range intf.Ipv4 {
			port.AddIpv4(ip4.(string))
		}
		for _, ip6 := range intf.Ipv6 {
			port.AddIpv6(ip6.(string))
		}
		ports = append(ports, port)
	}

	cacheData := []interface{}{ports}
	if err = adapter.SaveAdapterCache(funcName, cacheData); err != nil {
		return nil
	}
	return ports

}

func (adapter *F5Adapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	funcName := runFuncName()
	data := adapter.GetAdapterCache(funcName)
	if data != nil {
		return data[0].(map[string]*network.AddressTable), data[1].(map[string]*network.AddressTable)
	}

	hs, err := newHttpSession(adapter)
	if err != nil {
		fmt.Println("[f5 route table] http request unkown error")
		return
	}

	//==========interfaces
	intfs, err := F5.F5Interface(hs)
	if err != nil || len(intfs) == 0 {
		return
	}

	//==========vlan
	vlans, err := F5.F5Vlan(hs)
	if err != nil || len(vlans) == 0 {
		return
	}

	//==========partition
	partitions, err := F5.F5Partition(hs)
	if err != nil {
		return
	}

	//==========routeDomain
	routeDomain, err := F5.F5RouteDomain(hs)
	if err != nil {
		return
	}

	//==========self
	vlans, routeDomain, err = F5.F5Self(hs, intfs, vlans, routeDomain, partitions)
	if err != nil {
		return
	}

	//==========interfaces build
	interfaces := F5.PrefectInterfaces(vlans)
	fmt.Println(fmt.Sprintf("interfaces = %#v", interfaces))

	//==========route tables
	ipv4TableMap, err = F5.F5RouteTableIpv4(hs, partitions, interfaces)
	if err != nil {
		return
	}
	ipv6TableMap, err = F5.F5RouteTableIpv6(hs, partitions, interfaces)
	if err != nil {
		return
	}

	cacheData := []interface{}{ipv4TableMap, ipv6TableMap}
	if err = adapter.SaveAdapterCache(funcName, cacheData); err != nil {
		return
	}
	return ipv4TableMap, ipv6TableMap
}

func (adapter *F5Adapter) GetRawConfig(_ string, force bool) (any, error) {
	return adapter.GetConfig(force), nil
}

func (adapter *F5Adapter) Self(force bool) ([]F5.Vlan, map[string]F5.RouteDomain, error) {
	funcName := runFuncName()
	data := adapter.GetAdapterCache(funcName)
	if data != nil {
		return data[0].([]F5.Vlan), data[1].(map[string]F5.RouteDomain), nil
	}

	hs, err := newHttpSession(adapter)
	if err != nil {
		return nil, nil, err
	}

	//==========interfaces
	intfs, err := F5.F5Interface(hs)
	if err != nil || len(intfs) == 0 {
		return nil, nil, err
	}

	//==========vlan
	vlans, err := F5.F5Vlan(hs)
	if err != nil || len(vlans) == 0 {
		return nil, nil, err
	}

	//==========partition
	partitions, err := F5.F5Partition(hs)
	if err != nil {
		return vlans, nil, err
	}
	adapter.Partitions = partitions

	//==========routeDomain
	routeDomain, err := F5.F5RouteDomain(hs)
	if err != nil {
		return vlans, nil, err
	}
	adapter.RouteDomains = routeDomain

	//==========self
	vls, ros, err := F5.F5Self(hs, intfs, vlans, routeDomain, partitions)
	if err != nil {
		return nil, nil, err
	}
	cacheData := []interface{}{vls, ros}
	if err = adapter.SaveAdapterCache(funcName, cacheData); err != nil {
		return nil, nil, err
	}
	return vls, ros, nil
}

func (adapter *F5Adapter) GetNodes(force bool) (map[string]F5.Node, error) {
	funcName := runFuncName()
	data := adapter.GetAdapterCache(funcName)
	if data != nil {
		return data[0].(map[string]F5.Node), nil
	}
	hs, err := newHttpSession(adapter)
	if err != nil {
		return map[string]F5.Node{}, err
	}

	//==========nodes
	nodes, err := F5.F5Nodes(hs)
	if err != nil {
		return map[string]F5.Node{}, err
	}

	cacheData := []interface{}{nodes}
	if err = adapter.SaveAdapterCache(funcName, cacheData); err != nil {
		return map[string]F5.Node{}, err
	}
	return nodes, nil
}

func (adapter *F5Adapter) GetPools(force bool) (map[string]F5.Pool, error) {
	funcName := runFuncName()
	data := adapter.GetAdapterCache(funcName)
	if data != nil {
		return data[0].(map[string]F5.Pool), nil
	}

	hs, err := newHttpSession(adapter)
	if err != nil {
		return map[string]F5.Pool{}, err
	}

	//==========pools
	pools, err := F5.F5Pools(hs)
	if err != nil {
		return map[string]F5.Pool{}, err
	}
	cacheData := []interface{}{pools}
	if err = adapter.SaveAdapterCache(funcName, cacheData); err != nil {
		return map[string]F5.Pool{}, err
	}
	return pools, nil
}

func (adapter *F5Adapter) CreatePool(name string, partition string, monitor string) error {
	hs, err := newHttpSession(adapter)
	if err != nil {
		return err
	}

	//==========pools
	pools, err := adapter.GetPools(true)
	if err != nil {
		return err
	}
	_, err = F5.F5CreatePool(hs, pools, name, partition, monitor)
	if err == nil {
		return adapter.DrityMark("GetPools")
	}
	return err
}

func (adapter *F5Adapter) CreatePoolMember(pools map[string]F5.Pool, pool F5.Pool, partition F5.Partition, hosts []string, port string, routeDomain F5.RouteDomain) error {
	hs, err := newHttpSession(adapter)
	if err != nil {
		return err
	}

	//==========pool members
	_, err = F5.F5CreatePoolMember(hs, pools, pool, partition, hosts, port, routeDomain)
	if err == nil {
		return adapter.DrityMark("GetPools")
	}
	return err
}

func (adapter *F5Adapter) CreateVirtual(pool F5.Pool, vsMap map[string]F5.Virtual, virual F5.Virtual, partition F5.Partition, dst string, dport string, sourceAddressTranslation bool) error {
	hs, err := newHttpSession(adapter)
	if err != nil {
		return err
	}

	//==========virutal
	_, err = F5.F5CreateVirtual(hs, vsMap, pool, virual, partition, dst, dport, sourceAddressTranslation)
	if err == nil {
		return adapter.DrityMark("GetVirtuals")
	}
	return err
}

func (adapter *F5Adapter) GetSnatPools(force bool) (map[string]F5.SnatPool, error) {
	funcName := runFuncName()
	data := adapter.GetAdapterCache(funcName)
	if data != nil {
		return data[0].(map[string]F5.SnatPool), nil
	}

	hs, err := newHttpSession(adapter)
	if err != nil {
		return map[string]F5.SnatPool{}, err
	}

	//==========snatPools
	spools, err := F5.F5SnatPools(hs)
	if err != nil {
		return map[string]F5.SnatPool{}, err
	}
	cacheData := []interface{}{spools}
	if err = adapter.SaveAdapterCache(funcName, cacheData); err != nil {
		return map[string]F5.SnatPool{}, err
	}
	return spools, nil
}

func (adapter *F5Adapter) GetSnats(force bool) (map[string]F5.Snat, error) {
	funcName := runFuncName()
	data := adapter.GetAdapterCache(funcName)
	if data != nil {
		return data[0].(map[string]F5.Snat), nil
	}

	hs, err := newHttpSession(adapter)
	if err != nil {
		return map[string]F5.Snat{}, err
	}

	//========== snat
	snats, err := F5.F5Snat(hs)
	if err != nil {
		return map[string]F5.Snat{}, err
	}
	cacheData := []interface{}{snats}
	if err = adapter.SaveAdapterCache(funcName, cacheData); err != nil {
		return map[string]F5.Snat{}, err
	}
	return snats, nil
}

func (adapter *F5Adapter) GetVirtuals(routeDomains map[string]F5.RouteDomain, force bool) (map[int]map[string]F5.Virtual, error) {
	funcName := runFuncName()
	data := adapter.GetAdapterCache(funcName)
	if data != nil {
		return data[0].(map[int]map[string]F5.Virtual), nil
	}

	hs, err := newHttpSession(adapter)
	if err != nil {
		return map[int]map[string]F5.Virtual{}, err
	}

	//========== virtual
	vss, err := F5.F5Virtuals(hs, routeDomains)
	if err != nil {
		return map[int]map[string]F5.Virtual{}, err
	}
	cacheData := []interface{}{vss}
	if err = adapter.SaveAdapterCache(funcName, cacheData); err != nil {
		return map[int]map[string]F5.Virtual{}, err
	}
	return vss, nil
}

func (bia *F5Adapter) WithInfo(deviceInfo *device.DeviceBaseInfo) {
	bia.info.Sn = deviceInfo.SN
	bia.info.Mode = deviceInfo.Model
	bia.info.BaseInfo.Host = deviceInfo.Hostname
}

func newHttpSession(adapter *F5Adapter) (l2Session.HttpSession, error) {
	dv := structs.DeviceBase{
		Host:      adapter.info.BaseInfo.Host,
		Password:  adapter.info.BaseInfo.Password,
		Username:  adapter.info.BaseInfo.Username,
		AuthPass:  adapter.info.BaseInfo.AuthPass,
		Port:      adapter.info.BaseInfo.Port,
		Community: adapter.info.Community,
		Mode:      adapter.info.Mode,
		Telnet:    adapter.info.BaseInfo.Telnet,
	}
	return F5.NewHttpSession(dv)
}

// 获取正在运行的函数名
func runFuncName() string {
	pc := make([]uintptr, 1)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	return f.Name()
}
