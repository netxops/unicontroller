package lb

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/validator"
)

type F5Urls int

type F5 struct{}

const (
	_                F5Urls = iota
	AUTH                    // 1 /mgmt/shared/authn/login
	DEVICE_INFO             // 2 mgmt/tm/cm/device
	VIRTUAL                 // 3 mgmt/tm/ltm/virtual
	POOL                    // 4 mgmt/tm/ltm/pool
	POOL_MEMBER             // 5 mgmt/tm/ltm/pool/%s/members
	SNAT_POOL               // 6 mgmt/tm/ltm/snatpool
	SNAT_POOL_MEMBER        // 7 mgmt/tm/ltm/snat-translation/{}/
	SNAT                    // 8 mgmt/tm/ltm/snat
	POOL_STAT               // 9 /mgmt/tm/ltm/pool/stats
	NODE_INFO               // 10 mgmt/tm/ltm/node
	INTERFACE               // 11 mgmt/tm/net/interface
	TRUNK                   // 12 mgmt/tm/net/trunk
	VLAN                    // 13 mgmt/tm/net/vlan
	VLAN_INTERFACE          // 14 mgmt/tm/net/vlan/{name}/interfaces
	PARTITION               // 15 mgmt/tm/auth/partition
	ROUTE_DOMAIN            // 16 mgmt/tm/net/route-domain
	SELF                    // 17 mgmt/tm/net/self
	ROUTE                   // 18 mgmt/tm/net/route
)

func (w F5Urls) String() string {
	return []string{
		"/mgmt/shared/authn/login",
		"mgmt/tm/cm/device",
		"mgmt/tm/ltm/virtual",
		"mgmt/tm/ltm/pool",
		"mgmt/tm/ltm/pool/%s/members",
		"mgmt/tm/ltm/snatpool",
		"mgmt/tm/ltm/snat-translation/{}/",
		"mgmt/tm/ltm/snat",
		"/mgmt/tm/ltm/pool/stats",
		"mgmt/tm/ltm/node",
		"mgmt/tm/net/interface",
		"mgmt/tm/net/trunk",
		"mgmt/tm/net/vlan",
		"mgmt/tm/net/vlan/%s/interfaces",
		"mgmt/tm/auth/partition",
		"mgmt/tm/net/route-domain",
		"mgmt/tm/net/self",
		"mgmt/tm/net/route",
	}[w-1]
}

type F5OprtState int

const (
	_           F5OprtState = iota
	CREATE_POOL             // 1
	CREATE_VS               // 2
	ADD_NODE                // 3
)

func (fos F5OprtState) String() string {
	return []string{
		"CREATE_POOL",
		"CREATE_VS",
		"ADD_NODE",
	}[fos-1]
}

type ExecInfo struct {
	Err  error
	Info F5Result
}

type F5ExecResult struct {
	Pool        ExecInfo
	PoolMembers []ExecInfo
	Virtual     ExecInfo
}

type F5TableResult struct {
	Err   error
	Table F5ExecResult
}

func (f F5) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (table *clitask.Table, err error) {
	fmt.Printf("--------remoteInfo-------%#v\n", remote)
	resultKey := "F5_EXEC_RESULT"
	table = clitask.NewEmptyTableWithKeys([]string{resultKey})
	info := map[string]string{}
	result, err := f.runTask(remote, taskConfig, options)
	if err != nil {
		info[resultKey] = err.Error()
	} else {
		tableBytes, _ := json.Marshal(result)
		info[resultKey] = string(tableBytes)
	}

	table.PushRow("0", info, false, "")
	if taskConfig.IsPretty() && table != nil && err == nil {
		// table.Pretty()
	}

	return
}

type LBProcessResult struct {
	Virtual     string   `json:"virtual" mapstructure:"virtual"`
	Partition   string   `json:"partition" mapstructure:"partition"`
	Dst         string   `json:"dst" mapstructure:"dst"`
	Dport       string   `json:"dport" mapstructure:"dport"`
	Pool        string   `json:"pool" mapstructure:"pool"`
	AutoMap     bool     `json:"autoMap" mapstructure:"autoMap"`
	State       []string `json:"state" mapstructure:"state"`
	Nodes       []string `json:"nodes" mapstructure:"nodes"`
	RouteDomain string   `json:"routeDomain" mapstructure:"routeDomain"`
	NodePort    string   `json:"nodePort" mapstructure:"nodePort"`
	ErrMsg      string   `json:"errMsg" mapstructure:"errMsg"`
}

func (f F5) runTask(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (*F5ExecResult, error) {
	device := structs.DeviceBase{
		Host:      remote.Ip,
		Username:  remote.Username,
		Password:  remote.Password,
		Community: remote.Community[0],
		Port:      remote.Meta.RestfullPort,
	}

	execResult := F5ExecResult{}
	ops := options[0].([]interface{})
	r := LBProcessResult{}
	templateConfigResult := ops[0].(string)
	err := json.Unmarshal([]byte(templateConfigResult), &r)
	if err != nil {
		return nil, err
	}
	//
	// if err := mapstructure.Decode(templateConfigResult, &r); err != nil {
	//	return nil, err
	// }
	poolName := ops[1].(string)
	poolMembers := ops[2].(string)
	virtualName := ops[3].(string)
	nodePort := ops[4].(string)
	dst := ops[5].(string)
	dport := ops[6].(string)

	hs, err := NewHttpSession(device)
	if err != nil {
		return nil, err
	}

	// ==========pool
	pools, err := F5Pools(hs)
	if err != nil {
		return nil, err
	}
	//
	// //==========partition
	// partitions, err := F5Partition(hs)
	// if err != nil {
	//	return nil, err
	// }
	//
	// ==========routeDomain
	routeDomains, err := F5RouteDomain(hs)
	if err != nil {
		return nil, err
	}

	// ==========virtual
	virtuals, err := F5Virtuals(hs, routeDomains)
	if err != nil {
		return nil, err
	}

	needCreatePool := strings.Contains(templateConfigResult, CREATE_POOL.String())
	needCreatePoolMember := strings.Contains(templateConfigResult, ADD_NODE.String())
	needCreateVirutal := strings.Contains(templateConfigResult, CREATE_VS.String())
	if needCreatePool {
		pei := ExecInfo{}
		poolInfo, err := F5CreatePool(hs, pools, poolName, r.Partition, "tcp")
		pei.Info = poolInfo
		pei.Err = err
		execResult.Pool = pei
		if err != nil {
			return &execResult, nil
		}
	}

	if needCreatePoolMember {
		poolMemberInfos, err := F5CreatePoolMember(hs, pools, Pool{Name: poolName}, Partition{Name: r.Partition}, strings.Split(poolMembers, ","), nodePort, RouteDomain{Name: r.RouteDomain})
		for _, v := range poolMemberInfos {
			pmei := ExecInfo{}
			pmei.Info = v
			pmei.Err = err
			execResult.PoolMembers = append(execResult.PoolMembers, pmei)
			if err != nil {
				return &execResult, nil
			}
		}
	}

	if needCreateVirutal {
		vsMap := map[string]Virtual{}
		for _, vmap := range virtuals {
			for k, v := range vmap {
				vsMap[k] = v
			}
		}
		vei := ExecInfo{}
		vsInfo, err := F5CreateVirtual(hs, vsMap, Pool{Name: poolName}, Virtual{Name: virtualName}, Partition{Name: r.Partition}, dst, dport, false)
		vei.Info = vsInfo
		vei.Err = err
		execResult.Virtual = vei
		if err != nil {
			return &execResult, nil
		}
	}

	return &execResult, nil
}

type F5DeviceInfo struct {
	HostName string   `json:"hostname" mapstructure:"hostname"`
	Version  string   `json:"version" mapstructure:"version"`
	Model    string   `json:"model" mapstructure:"model"`
	Sn       []string `json:"sn" mapstructure:"sn"`
}

type HttpParams struct {
	Method  string
	Url     string
	Key     string
	Timeout int
	Force   bool
	Data    []byte
}

type CertReference struct {
	Link string `json:"link" mapstructure:"link"`
}

type KeyReference struct {
	Link string `json:"link" mapstructure:"link"`
}

type Node struct {
	Name      string    `json:"name" mapstructure:"name"`
	IP        string    `json:"ip" mapstructure:"ip"`
	Partition Partition `json:"partition" mapstructure:"partition"`
}

type Vlan struct {
	Name             string        `json:"name" mapstructure:"name"`
	InterfaceOrTrunk string        `json:"Interface_or_trunk" mapstructure:"Interface_or_trunk"`
	Ipv4             []interface{} `json:"ipv4" mapstructure:"ipv4"`
	Ipv6             []interface{} `json:"ipv6" mapstructure:"ipv6"`
	Vrf              string        `json:"vrf" mapstructure:"vrf"`
	RouteDomain      string        `json:"routeDomain" mapstructure:"routeDomain"`
	MacAddress       string        `json:"macAddress" mapstructure:"macAddress"`
}

type Snat struct {
	Name     string `json:"name" mapstructure:"name"`
	FullPath string `json:"fullPath" mapstructure:"fullPath"`
}

type SnatPool struct {
	Name            string           `json:"name" mapstructure:"name"`
	FullPath        string           `json:"fullPath" mapstructure:"fullPath"`
	SnatPoolMembers []SnatPoolMember `json:"snatPoolMembers" mapstructure:"snatPoolMembers"`
}

type SnatPoolMember struct {
	SnatPoolName string `json:"snatPoolName" mapstructure:"snatPoolName"`
	FullPath     string `json:"fullPath" mapstructure:"fullPath"`
	// Port     string `json:"port" mapstructure:"port"`
}

type Pool struct {
	Name        string       `json:"name" mapstructure:"name"`
	FullPath    string       `json:"fullPath" mapstructure:"fullPath"`
	PoolMembers []PoolMember `json:"poolMembers" mapstructure:"poolMembers"`
}

type PoolMember struct {
	PoolName string `json:"poolName" mapstructure:"poolName"`
	FullPath string `json:"fullPath" mapstructure:"fullPath"`
	Port     string `json:"port" mapstructure:"port"`
}

type SourceAddressTranslation struct {
	Pool string `json:"pool" mapstructure:"pool"`
	Type string `json:"type" mapstructure:"type"`
}

type Virtual struct {
	Name             string `json:"name" mapstructure:"name"`
	Vrf              string `json:"vrf" mapstructure:"vrf"`
	IpProtocol       string `json:"ipProtocol"          mapstructure:"ipProtocol"`
	Source           string `json:"source" mapstructure:"source"`
	Destination      string `json:"destination" mapstructure:"destination"`
	Port             string `json:"port" mapstructure:"port"`
	FullPath         string `json:"fullPath" mapstructure:"fullPath"`
	Enabled          bool   `json:"enabled" mapstructure:"enabled"`
	Disabled         bool   `json:"disabled" mapstructure:"disabled"`
	Mask             string `json:"mask" mapstructure:"mask"`
	VlansEnabled     bool   `json:"vlansEnabled" mapstructure:"vlansEnabled"`
	VlansDisabled    bool   `json:"vlansDisabled" mapstructure:"vlansDisabled"`
	TranslateAddress string `json:"translateAddress" mapstructure:"translateAddress"`
	TranslatePort    string `json:"translatePort" mapstructure:"translatePort"`
	VsIndex          int    `json:"vsIndex" mapstructure:"vsIndex"`

	Orignal                  policy.PolicyEntry       `json:"orignal" mapstructure:"orignal"`
	SourceAddressTranslation SourceAddressTranslation `json:"sourceAddressTranslation" mapstructure:"sourceAddressTranslation"`
	Partition                Partition                `json:"partition" mapstructure:"partition"`
	Pool                     Pool                     `json:"pool" mapstructure:"pool"`
}

type Interface struct {
	Name       string        `json:"name" mapstructure:"name"`
	Ipv4       []interface{} `json:"ipv4" mapstructure:"ipv4"`
	Ipv6       []interface{} `json:"ipv6" mapstructure:"ipv6"`
	Vrf        string        `json:"vrf" mapstructure:"vrf"`
	MacAddress string        `json:"macAddress" mapstructure:"macAddress"`
}

type Trunk struct {
	Name       string        `json:"name" mapstructure:"name"`
	Interfaces []interface{} `json:"interfaces" mapstructure:"interfaces"`
}

type Partition struct {
	Name          string `json:"name" mapstructure:"name"`
	DefaultDomain int    `json:"default_domain" mapstructure:"default_domain"`
}

type RouteDomain struct {
	Partition string        `json:"partition" mapstructure:"partition"`
	ID        string        `json:"id" mapstructure:"id"`
	Name      string        `json:"name" mapstructure:"name"`
	Strict    string        `json:"strict" mapstructure:"strict"`
	Vlans     []interface{} `json:"vlans" mapstructure:"vlans"`
	Vrf       string        `json:"vrf" mapstructure:"vrf"`
}

// type RouteTable struct {
//	Table       map[string]interface{}    `json:"table" mapstructure:"table"`
//	Type    string    `json:"type" mapstructure:"type"`
//	DefaultGw   string    `json:"default_gw" mapstructure:"default_gw"`
//	Formator   string    `json:"formator" mapstructure:"formator"`
//	NhopIp   string    `json:"nhop_ip" mapstructure:"nhop_ip"`
// }

type F5Result struct {
	Code     int            `json:"code" mapstructure:"code"`
	Kind     string         `json:"kind" mapstructure:"kind"`
	SelfLink string         `json:"selfLink" mapstructure:"selfLink"`
	Items    []F5ResultItem `json:"items" mapstructure:"items"`
	Message  string         `json:"message" mapstructure:"message"`
}

type F5ResultItem struct {
	Kind              string        `json:"kind" mapstructure:"kind"`
	Name              string        `json:"name" mapstructure:"name"`
	Partition         string        `json:"partition" mapstructure:"partition"`
	FullPath          string        `json:"fullPath" mapstructure:"fullPath"`
	Generation        int           `json:"generation" mapstructure:"generation"`
	SelfLink          string        `json:"selfLink" mapstructure:"selfLink"`
	ActiveModules     []string      `json:"activeModules" mapstructure:"activeModules"`
	AlternateIp       string        `json:"alternateIp" mapstructure:"alternateIp"`
	BaseMac           string        `json:"baseMac" mapstructure:"baseMac"`
	Build             string        `json:"build" mapstructure:"build"`
	Cert              string        `json:"cert" mapstructure:"cert"`
	ChassisId         string        `json:"chassisId" mapstructure:"chassisId"`
	ChassisType       string        `json:"chassisType" mapstructure:"chassisType"`
	ConfigsyncIp      string        `json:"configsyncIp" mapstructure:"configsyncIp"`
	Edition           string        `json:"edition" mapstructure:"edition"`
	FailoverState     string        `json:"failoverState" mapstructure:"failoverState"`
	HaCapacity        int           `json:"haCapacity" mapstructure:"haCapacity"`
	Hostname          string        `json:"hostname" mapstructure:"hostname"`
	Key               string        `json:"key" mapstructure:"key"`
	ManagementIp      string        `json:"managementIp" mapstructure:"managementIp"`
	MarketingName     string        `json:"marketingName" mapstructure:"marketingName"`
	MgmtUnicastMode   string        `json:"mgmtUnicastMode" mapstructure:"mgmtUnicastMode"`
	MirrorIp          string        `json:"mirrorIp" mapstructure:"mirrorIp"`
	MirrorSecondaryIp string        `json:"mirrorSecondaryIp" mapstructure:"mirrorSecondaryIp"`
	MulticastIp       string        `json:"multicastIp" mapstructure:"multicastIp"`
	MulticastPort     int           `json:"multicastPort" mapstructure:"multicastPort"`
	OptionalModules   []string      `json:"optionalModules" mapstructure:"optionalModules"`
	PlatformId        string        `json:"platformId" mapstructure:"platformId"`
	Product           string        `json:"product" mapstructure:"product"`
	SelfDevice        string        `json:"selfDevice" mapstructure:"selfDevice"`
	TimeZone          string        `json:"timeZone" mapstructure:"timeZone"`
	Version           string        `json:"version" mapstructure:"version"`
	Vrf               string        `json:"vrf" mapstructure:"vrf"`
	Gw                string        `json:"gw" mapstructure:"gw"`
	Network           string        `json:"network" mapstructure:"network"`
	Mtu               int           `json:"mtu" mapstructure:"mtu"`
	PoolMembers       []interface{} `json:"poolMembers" mapstructure:"poolMembers"`
	PoolMemberPort    string        `json:"poolMembersPort" mapstructure:"poolMembersPort"`
	SnatPoolMembers   []interface{} `json:"snatPoolMembers" mapstructure:"snatPoolMembers"`

	Vlan               string        `json:"vlan" mapstructure:"vlan"`
	Address            string        `json:"address" mapstructure:"address"`
	MacAddress         string        `json:"macAddress" mapstructure:"macAddress"`
	DefaultRouteDomain int           `json:"defaultRouteDomain" mapstructure:"defaultRouteDomain"`
	Strict             string        `json:"strict" mapstructure:"strict"`
	Vlans              []interface{} `json:"vlans" mapstructure:"vlans"`

	IpProtocol       string `json:"ipProtocol"          mapstructure:"ipProtocol"`
	Source           string `json:"source" mapstructure:"source"`
	Destination      string `json:"destination" mapstructure:"destination"`
	SourcePort       string `json:"sourcePort" mapstructure:"sourcePort"`
	Enabled          bool   `json:"enabled" mapstructure:"enabled"`
	Mask             string `json:"mask" mapstructure:"mask"`
	Pool             string `json:"pool" mapstructure:"pool"`
	Disabled         bool   `json:"disabled" mapstructure:"disabled"`
	VlansEnabled     bool   `json:"vlansEnabled" mapstructure:"vlansEnabled"`
	VlansDisabled    bool   `json:"vlansDisabled" mapstructure:"vlansDisabled"`
	TranslateAddress string `json:"translateAddress" mapstructure:"translateAddress"`
	TranslatePort    string `json:"translatePort" mapstructure:"translatePort"`
	VsIndex          int    `json:"vsIndex" mapstructure:"vsIndex"`

	SourceAddressTranslation SourceAddressTranslation `json:"sourceAddressTranslation" mapstructure:"sourceAddressTranslation"`
	CertReference            CertReference            `json:"certReference" mapstructure:"certReference"`
	KeyReference             KeyReference             `json:"keyReference" mapstructure:"keyReference"`
}

func NewHttpSession(device structs.DeviceBase) (session.HttpSession, error) {
	host := device.Host
	user := device.Username
	password := device.Password
	community := device.Community
	port := device.Port
	// bi := session.NewDeviceBaseInfo("192.168.100.7", "admin", "!@AsiaLink@2020", "F5", "public", 443)
	bi := session.NewDeviceBaseInfo(host, user, password, "F5", community, port)
	auth_url := AUTH.String()
	auth_data, _ := json.Marshal(map[string]string{
		"username":          user,
		"password":          password,
		"loginProviderName": "tmos",
	})

	if auth_data == nil || len(auth_data) == 0 {
		return session.HttpSession{}, errors.New("Auth data is empty ...")
	}

	hs := session.NewHttpSession(bi, auth_url)
	hs.WithAuthData(auth_data)
	hs.WithTokenField("X-F5-Auth-Token")
	return *hs, nil
}

func F5Info(hs session.HttpSession) (F5DeviceInfo, error) {
	httpParams := HttpParams{
		Key:     "info",
		Method:  "GET",
		Url:     DEVICE_INFO.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return F5DeviceInfo{}, err
	}

	if r.Items == nil || len(r.Items) == 0 {
		return F5DeviceInfo{}, errors.New("F5 info result is empty")
	}

	item := r.Items[0]
	return F5DeviceInfo{
		HostName: item.Hostname,
		Sn:       []string{item.PlatformId},
		Version:  item.Version,
		Model:    item.Product,
	}, nil
}

func F5Name(hs session.HttpSession) (string, error) {
	httpParams := HttpParams{
		Key:     "get_cm_device",
		Method:  "GET",
		Url:     DEVICE_INFO.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return "", err
	}

	if r.Items == nil || len(r.Items) == 0 {
		return "", errors.New("F5 name is empty")
	}
	item := r.Items[0]
	return item.Hostname, nil
}

func F5Interface(hs session.HttpSession) ([]Interface, error) {
	httpParams := HttpParams{
		Key:     "get_interface",
		Method:  "GET",
		Url:     INTERFACE.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return []Interface{}, err
	}

	if r.Items == nil || len(r.Items) == 0 {
		return []Interface{}, errors.New("F5 interface result is empty")
	}

	var intfs []Interface
	for _, i := range r.Items {
		intfs = append(intfs,
			Interface{
				Name:       i.FullPath,
				Ipv4:       []interface{}{},
				Ipv6:       []interface{}{},
				MacAddress: i.MacAddress,
			},
		)
	}
	return intfs, nil
}

func F5Trunk(hs session.HttpSession) (map[string]Trunk, error) {
	httpParams := HttpParams{
		Key:     "get_trunk",
		Method:  "GET",
		Url:     TRUNK.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return nil, err
	}

	m := map[string]Trunk{}
	if r.Items != nil && len(r.Items) != 0 {
		for _, item := range r.Items {
			m[item.FullPath] = Trunk{
				Name: item.FullPath,
				//	trunks[item["fullPath"]] = {"name": item["fullPath"], "interfaces": item.get("interfaces") or []}
				// Interfaces: item.,
			}
		}
	}
	return m, nil
}

func F5Vlan(hs session.HttpSession) ([]Vlan, error) {
	httpParams := HttpParams{
		Key:     "get_vlan",
		Method:  "GET",
		Url:     VLAN.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return nil, err
	}

	var vlans []Vlan
	if r.Items != nil && len(r.Items) != 0 {
		for _, item := range r.Items {
			name := strings.ReplaceAll(item.Name, "/", "~")
			httpParams = HttpParams{
				Key:     "get_vlan",
				Method:  "GET",
				Url:     fmt.Sprintf(VLAN_INTERFACE.String(), name),
				Timeout: 5,
				Force:   true,
			}
			ris, err := GetResult(hs, httpParams, nil)
			if err != nil {
				return nil, err
			}

			for _, i := range ris.Items {
				vlans = append(vlans,
					Vlan{
						Name:             item.FullPath,
						InterfaceOrTrunk: i.FullPath,
						Ipv4:             []interface{}{},
						Ipv6:             []interface{}{},
					},
				)
			}
		}
	}

	return vlans, nil
}

func F5Partition(hs session.HttpSession) ([]Partition, error) {
	httpParams := HttpParams{
		Key:     "get_partition",
		Method:  "GET",
		Url:     PARTITION.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return nil, err
	}

	if r.Items == nil || len(r.Items) == 0 {
		return nil, errors.New("F5 partition result is empty")
	}

	partitions := []Partition{}
	for _, item := range r.Items {
		partitions = append(partitions, Partition{
			Name:          item.FullPath,
			DefaultDomain: item.DefaultRouteDomain,
		})
	}
	return partitions, nil
}

func F5RouteDomain(hs session.HttpSession) (map[string]RouteDomain, error) {
	httpParams := HttpParams{
		Key:     "get_route-domain",
		Method:  "GET",
		Url:     ROUTE_DOMAIN.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return nil, err
	}

	if r.Items == nil || len(r.Items) == 0 {
		return nil, errors.New("F5 route domain result is empty")
	}

	roteDomainMap := map[string]RouteDomain{}
	for _, item := range r.Items {
		ls := strings.Split(item.FullPath, "/")
		partition := ls[1]
		domainId := ls[2]
		rd := RouteDomain{
			Name:      item.FullPath,
			Partition: partition,
			Strict:    item.Strict,
			ID:        domainId,
			Vlans:     item.Vlans,
		}
		if strings.Contains(item.FullPath, "/Common/0") {
			rd.Vrf = "default"
		} else {
			rd.Vrf = item.FullPath
		}
		roteDomainMap[item.FullPath] = rd
	}
	return roteDomainMap, nil
}

func F5Self(hs session.HttpSession, interfaces []Interface, vlans []Vlan, domains map[string]RouteDomain, patitions []Partition) ([]Vlan, map[string]RouteDomain, error) {
	httpParams := HttpParams{
		Key:     "get_self-domain",
		Method:  "GET",
		Url:     SELF.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return vlans, domains, err
	}

	if r.Items == nil || len(r.Items) == 0 {
		return vlans, domains, errors.New("F5 self info result is empty")
	}

	infMacMap := map[string]string{}
	for _, inf := range interfaces {
		infMacMap[inf.Name] = inf.MacAddress
	}

	for _, item := range r.Items {
		for k, vlan := range vlans {
			if vlan.Name == item.Vlan {
				address, domain, err := splitSelfAndDomain(item.Address, item.Partition, patitions)
				if err != nil {
					return vlans, domains, err
				}
				if address == "" || domain == "" {
					return vlans, domains, errors.New("f5 self option[address] or [domain] is nil ")
				}

				vlans[k].RouteDomain = domain
				if validator.IsIPv4AddressWithMask(address) {
					vlan.Ipv4 = append(vlan.Ipv4, address)
					vlans[k].Ipv4 = vlan.Ipv4
					vlans[k].MacAddress = infMacMap[vlan.InterfaceOrTrunk]
				} else if validator.IsIPv6AddressWithMask(address) {
					vlan.Ipv6 = append(vlan.Ipv6, address)
					vlans[k].Ipv6 = vlan.Ipv6
					vlans[k].MacAddress = infMacMap[vlan.InterfaceOrTrunk]
				} else {
					return vlans, domains, errors.New(fmt.Sprintf("unknown address format address[%s]", address))
				}
			}
		}
	}
	return vlans, domains, nil
}

func PrefectInterfaces(vlans []Vlan) (interfaces []Interface) {
	for _, vlan := range vlans {
		if vlan.RouteDomain == "/Common/0" || vlan.Vrf == "" {
			vlan.Vrf = "default"
		}

		interfaces = append(interfaces, Interface{
			Name: vlan.Name,
			Ipv4: vlan.Ipv4,
			Ipv6: vlan.Ipv6,
			Vrf:  vlan.Vrf,
		})
	}
	return
}

func F5Exist(hs session.HttpSession, target string, name string, partition string) (bool, error) {
	url := ""
	switch target {
	case "partition":
		url = fmt.Sprintf("mgmt/tm/auth/partition/%s", name)
	case "virtual":
		url = fmt.Sprintf("mgmt/tm/ltm/virtual/~%s~%s", partition, name)
	case "pool":
		url = fmt.Sprintf("mgmt/tm/ltm/pool/~%s~%s", partition, name)
	case "route-domain":
		url = fmt.Sprintf("mgmt/tm/ltm/route-domain/~%s~%s", partition, name)
	default:
		return false, errors.New(fmt.Sprintf("f5 not support target[%s] ", target))
	}
	key := url
	httpParams := HttpParams{
		Key:     key,
		Method:  "GET",
		Url:     url,
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return false, err
	}

	if r.Code != 0 {
		return false, err
	}
	return true, nil
}

func F5Virtuals(hs session.HttpSession, routeDomains map[string]RouteDomain) (map[int]map[string]Virtual, error) {
	httpParams := HttpParams{
		Key:     "get_virtual",
		Method:  "GET",
		Url:     VIRTUAL.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return map[int]map[string]Virtual{}, err
	}

	virtuals := map[int]map[string]Virtual{}
	for _, item := range r.Items {
		virtual := Virtual{
			Name:                     item.Name,
			Vrf:                      item.Vrf,
			Source:                   item.Source,
			Destination:              item.Destination,
			Port:                     item.SourcePort,
			IpProtocol:               item.IpProtocol,
			FullPath:                 item.FullPath,
			Enabled:                  item.Enabled,
			Disabled:                 item.Disabled,
			VlansEnabled:             item.VlansEnabled,
			VlansDisabled:            item.VlansDisabled,
			VsIndex:                  item.VsIndex,
			TranslateAddress:         item.TranslateAddress,
			TranslatePort:            item.TranslatePort,
			SourceAddressTranslation: item.SourceAddressTranslation,
			Mask:                     item.Mask,
			Partition:                Partition{Name: item.Partition},
			Pool:                     Pool{Name: item.Pool},
		}

		// if item.Pool == "" {
		//	fmt.Println(fmt.Sprintf("=======发现pool为空的vs信息，%#v", item))
		// }

		orignal := policy.NewPolicyEntry()
		if virtual.Destination != "" {
			dstArr := strings.Split(virtual.Destination, "/")
			if len(dstArr) != 3 {
				return map[int]map[string]Virtual{}, errors.New(fmt.Sprintf("Virtual _parse failed, destionation:%s", virtual.Destination))
			}
			var target []string
			r := regexp.MustCompile("\\.[^:\\.]+$")
			var index = len(dstArr) - 1
			if r.MatchString(dstArr[index]) {
				target = strings.Split(dstArr[index], ".")
			} else {
				target = strings.Split(dstArr[index], ":")
			}
			if len(target) != 2 {
				return map[int]map[string]Virtual{}, errors.New(fmt.Sprintf("Virtual _parse failed, destionation:%s", virtual.Destination))
			}
			virtual.Destination = target[0]
			virtual.Port = target[1]

			dstArr = strings.Split(virtual.Destination, "%")
			if len(dstArr) > 1 {
				rdName := fmt.Sprintf("/%s/%s", virtual.Partition.Name, dstArr[1])
				for _, rd := range routeDomains {
					if rd.Name == rdName {
						virtual.Vrf = rd.Vrf
						break
					}
				}
			} else {
				rdName := fmt.Sprintf("/%s/%d", virtual.Partition.Name, 0)
				for _, rd := range routeDomains {
					if rd.Name == rdName {
						virtual.Vrf = rd.Vrf
						break
					}
				}
			}
			if virtual.Vrf == "" {
				continue
			}
			virtual.Destination = dstArr[0]

			var dnet *network.IPNet
			switch virtual.Destination {
			case "any":
				switch virtual.Mask {
				case "any":
					dnet, err = network.NewIPNet("0.0.0.0/0")
				case "":
					dnet, err = network.NewIPNet("0.0.0.0/32")
				default:
					dnet, err = network.NewIPNet("0.0.0.0/" + virtual.Mask)
				}
			case "any6":
				switch virtual.Mask {
				case "any":
					dnet, err = network.NewIPNet("::/0")
				case "":
					dnet, err = network.NewIPNet("::/128")
				default:
					dnet, err = network.NewIPNet("::/" + virtual.Mask)
				}
			case "::":
				dnet, err = network.NewIPNet("::/0")
			default:
				switch virtual.Mask {
				case "any":
					dnet, err = network.NewIPNet(virtual.Destination + "/0")
				case "":
					if validator.IsIPv4Address(virtual.Destination) {
						dnet, err = network.NewIPNet(virtual.Destination + "/32")
					} else {
						dnet, err = network.NewIPNet(virtual.Destination + "/128")
					}
				default:
					dnet, err = network.NewIPNet(virtual.Destination + "/" + virtual.Mask)
				}
			}

			if err != nil {
				return map[int]map[string]Virtual{}, errors.New(fmt.Sprintf("Virtual _parse failed, destionation:%s", virtual.Destination))
			}
			dgroup := network.NewNetworkGroup()
			dgroup.Add(dnet)
			orignal.AddDst(dgroup)
		}

		if virtual.Destination == "" {
			return map[int]map[string]Virtual{}, errors.New("virtual _parse failed, destionation is nil")
		}

		if virtual.Source == "" {
			return map[int]map[string]Virtual{}, errors.New("virtual _parse failed, srouce is nil")
		}

		if virtual.Vrf == "" {
			return map[int]map[string]Virtual{}, errors.New(fmt.Sprintf("Virtual get vrf failed, partitionon:%s, destionation:%s", virtual.Partition.Name, virtual.Destination))
		}

		if virtual.Port == "" {
			return map[int]map[string]Virtual{}, errors.New("virtual _parse failed, dport is nil")
		}

		if virtual.SourceAddressTranslation.Type == "lsn" {
			return map[int]map[string]Virtual{}, errors.New(fmt.Sprintf("Virtual _parse failed, current not support snat: %#v", virtual.SourceAddressTranslation))
		}

		if virtual.IpProtocol == "" {
			virtual.IpProtocol = "tcp"
		}

		srcNet, err := network.NewIPNet(virtual.Source)
		if err != nil {
			return map[int]map[string]Virtual{}, errors.New(fmt.Sprintf("Virtual _parse failed, srouce[%s] format err", virtual.Source))
		}
		sgroup := network.NewNetworkGroup()
		sgroup.Add(srcNet)
		orignal.AddSrc(sgroup)

		var serve *service.Service
		if virtual.IpProtocol == "any" {
			serve, err = service.NewServiceFromString("ip")
		} else {
			serve, err = service.NewServiceFromString(virtual.IpProtocol + ":" + virtual.Port)
		}
		if err != nil {
			return map[int]map[string]Virtual{}, errors.New(fmt.Sprintf("Virtual _parse service err, ipProtocol[%s]", virtual.IpProtocol))
		}
		orignal.AddService(serve)
		virtual.Orignal = *orignal

		index := virtual.order()
		if virtuals[index] == nil {
			virtuals[index] = map[string]Virtual{}
		}
		virtuals[index][virtual.Name] = virtual
	}
	return virtuals, err
}

func F5Nodes(hs session.HttpSession) (map[string]Node, error) {
	httpParams := HttpParams{
		Key:     "get_node",
		Method:  "GET",
		Url:     NODE_INFO.String(),
		Timeout: 5,
		Force:   true,
	}

	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return map[string]Node{}, err
	}

	nodes := map[string]Node{}
	for _, item := range r.Items {
		node := Node{
			Name:      item.Name,
			IP:        item.Address,
			Partition: Partition{Name: item.Partition},
		}
		nodes[node.Name] = node
	}
	return nodes, err
}

func F5Pools(hs session.HttpSession) (map[string]Pool, error) {
	httpParams := HttpParams{
		Key:     "get_pool",
		Method:  "GET",
		Url:     POOL.String(),
		Timeout: 5,
		Force:   true,
	}

	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return map[string]Pool{}, err
	}

	getMembers := func(hs session.HttpSession, item F5ResultItem, resourceId string) ([]F5ResultItem, error) {
		hps := HttpParams{
			Key:     fmt.Sprintf("get_%s_member", resourceId),
			Method:  "GET",
			Url:     fmt.Sprintf(POOL_MEMBER.String(), resourceId),
			Timeout: 5,
			Force:   true,
		}

		re, e := GetResult(hs, hps, nil)
		if e != nil {
			return []F5ResultItem{}, e
		}
		return re.Items, nil
	}

	pools := map[string]Pool{}
	for _, item := range r.Items {
		pool := Pool{
			Name:     item.Name,
			FullPath: item.FullPath,
		}
		resource := strings.ReplaceAll(item.FullPath, "/", "~")
		members, err := getMembers(hs, item, resource)
		if err != nil {
			return map[string]Pool{}, err
		}
		poolMembers := []PoolMember{}
		for _, mem := range members {
			member := PoolMember{
				PoolName: pool.Name,
				FullPath: mem.FullPath,
			}
			arr := text.RegexSplit("\\.|:", mem.FullPath)
			port := arr[len(arr)-1]
			member.Port = port
			poolMembers = append(poolMembers, member)
		}
		pool.PoolMembers = poolMembers
		pools[pool.Name] = pool
	}
	return pools, err
}

func F5CreatePool(hs session.HttpSession, pools map[string]Pool, name string, partition string, monitor string) (res F5Result, err error) {
	if name == "" {
		err = errors.New("create pool : name is empty")
		return
	}

	if partition == "" {
		err = errors.New("create pool : partition is empty")
		return
	}

	if _, ok := pools[name]; !ok {
		if monitor == "" {
			monitor = "tcp"
		}
		data := map[string]string{"name": name, "partition": partition, "monitor": monitor}
		bytes, _ := json.Marshal(data)
		httpParams := HttpParams{
			Method:  "POST",
			Url:     POOL.String(),
			Timeout: 5,
			Force:   true,
		}
		fmt.Println(fmt.Sprintf("create-pool: %#v", data))
		res, err = GetResult(hs, httpParams, bytes)
		if err != nil {
			return
		}
		if res.Code != 0 {
			err = errors.New(fmt.Sprintf("create pool error : response code is %d", res.Code))
			return
		}
	}

	return
}

func F5CreateVirtual(hs session.HttpSession, virtuals map[string]Virtual, pool Pool, virual Virtual, partition Partition, dst string, dport string, sourceAddressTranslation bool) (res F5Result, err error) {
	if pool.Name == "" {
		err = errors.New("create virutal: pool name is empty")
		return
	}

	if virual.Name == "" {
		err = errors.New("create virutal: virual name is empty")
		return
	}

	if partition.Name == "" {
		err = errors.New("create virutal: partition name is empty")
		return
	}

	if dst == "" {
		err = errors.New("create virutal: dst is empty")
		return
	}

	if dport == "" {
		err = errors.New("create virutal: dport is empty")
		return
	}

	destination := strings.Split(dst, "%s")[0]
	net, err := network.ParseIPNet(destination)
	if err != nil {
		return
	}

	var dest string
	if net.Type() == network.IPv6 {
		dest = fmt.Sprintf("%s.%s", net.IP.String(), dport)
	} else {
		if strings.Contains(destination, "%") {
			dest = fmt.Sprintf("%s%s:%s", net.IP.String(), "%2", dport)
		} else {
			dest = fmt.Sprintf("%s:%s", net.IP.String(), dport)
		}
	}

	hasVirtual := false
	for _, v := range virtuals {
		if v.Partition.Name == partition.Name && v.Name == virual.Name {
			hasVirtual = true
			break
		}
	}

	if hasVirtual {
		return
	}

	data := map[string]interface{}{"name": virual.Name, "partition": partition.Name, "destination": dest, "mask": net.Mask.String(), "ipProtocol": "tcp", "pool": pool.Name}
	if sourceAddressTranslation {
		data["sourceAddressTranslation"] = map[string]string{"type": "automap"}
	}

	bytes, _ := json.Marshal(data)
	httpParams := HttpParams{
		Method:  "POST",
		Url:     VIRTUAL.String(),
		Timeout: 5,
		Force:   true,
	}
	fmt.Println(fmt.Sprintf("create-virutal: %#v", data))
	res, err = GetResult(hs, httpParams, bytes)
	if err != nil {
		return
	}
	if res.Code != 0 {
		err = errors.New(fmt.Sprintf("create virutal error : response code is %d", res.Code))
		return
	}
	return
}

func F5CreatePoolMember(hs session.HttpSession, pools map[string]Pool, pool Pool, partition Partition, hosts []string, port string, routeDomain RouteDomain) (res []F5Result, err error) {
	if pool.Name == "" {
		err = errors.New("create pool member: pool name is empty")
		return
	}

	if partition.Name == "" {
		err = errors.New("create pool member: partition name is empty")
		return
	}

	if len(hosts) > 0 && port == "" {
		err = errors.New("create pool member: port is empty")
		return
	}

	for _, h := range hosts {
		host := strings.Split(h, "%")[0]
		net, e := network.ParseIPNet(host)
		if e != nil {
			return
		}

		var poolMemberName string
		if net.Type() == network.IPv6 {
			poolMemberName = fmt.Sprintf("%s.%s", host, port)
		} else {
			poolMemberName = fmt.Sprintf("%s:%s", host, port)
		}

		if _, ok := pools[pool.Name]; !ok {
			err = errors.New(fmt.Sprintf("create pool member: pool[%s] not exist", pool.Name))
			return
		}

		hasPoolMember := false
		for _, m := range pools[pool.Name].PoolMembers {
			if strings.Contains(m.FullPath, poolMemberName) {
				hasPoolMember = true
				break
			}
		}

		if hasPoolMember {
			continue
		}

		var address string
		if routeDomain.Name == "0" {
			address = host
		} else {
			address = fmt.Sprintf("%s%s%s", host, "%", routeDomain.Name)
		}

		data := map[string]string{"name": poolMemberName, "address": address}
		bytes, _ := json.Marshal(data)
		urlSuffix := fmt.Sprintf("~%s~%s", partition.Name, pool.Name)
		httpParams := HttpParams{
			Method:  "POST",
			Url:     fmt.Sprintf(POOL_MEMBER.String(), urlSuffix),
			Timeout: 5,
			Force:   true,
		}
		fmt.Println(fmt.Sprintf("create-pool-member: %#v", data))
		memRes, e := GetResult(hs, httpParams, bytes)
		if e != nil {
			return res, e
		}
		if memRes.Code != 0 {
			err = errors.New(fmt.Sprintf("create pool member error : response code is %d , err[%s]", memRes.Code, memRes.Message))
			return
		}
		res = append(res, memRes)
	}

	return
}

func F5SnatPools(hs session.HttpSession) (map[string]SnatPool, error) {
	httpParams := HttpParams{
		Key:     "get_snatpool",
		Method:  "GET",
		Url:     SNAT_POOL.String(),
		Timeout: 5,
		Force:   true,
	}

	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return map[string]SnatPool{}, err
	}

	getMembers := func(hs session.HttpSession, item F5ResultItem, resourceId string) ([]F5ResultItem, error) {
		hps := HttpParams{
			Key:     fmt.Sprintf("get_snt_translate_%s_member", resourceId),
			Method:  "GET",
			Url:     SNAT_POOL_MEMBER.String(),
			Timeout: 5,
			Force:   true,
		}
		re, e := GetResult(hs, hps, nil)
		if e != nil {
			return []F5ResultItem{}, e
		}
		return re.Items, e
	}

	snatPools := map[string]SnatPool{}
	for _, item := range r.Items {
		snatPool := SnatPool{
			Name:     item.Name,
			FullPath: item.FullPath,
		}
		members := []SnatPoolMember{}
		for _, spm := range item.SnatPoolMembers {
			resource := strings.ReplaceAll(spm.(string), "/", "~")
			mems, err := getMembers(hs, item, resource)
			if err != nil {
				return map[string]SnatPool{}, err
			}
			for _, mem := range mems {
				member := SnatPoolMember{
					SnatPoolName: mem.Name,
					FullPath:     mem.FullPath,
				}
				members = append(members, member)
			}
		}
		snatPool.SnatPoolMembers = members
		snatPools[snatPool.Name] = snatPool
	}
	return snatPools, err
}

func F5Snat(hs session.HttpSession) (map[string]Snat, error) {
	httpParams := HttpParams{
		Key:     "get_snats",
		Method:  "GET",
		Url:     SNAT.String(),
		Timeout: 5,
		Force:   true,
	}

	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return map[string]Snat{}, err
	}

	snats := map[string]Snat{}
	for _, item := range r.Items {
		snat := Snat{
			Name:     item.Name,
			FullPath: item.FullPath,
		}
		snats[item.Name] = snat
	}
	return snats, err
}

// 此处的interfaces参数需要调用self的方法返回的值
func F5RouteTableIpv4(hs session.HttpSession, partitions []Partition, interfaces []Interface) (map[string]*network.AddressTable, error) {
	httpParams := HttpParams{
		Key:     "get_route",
		Method:  "GET",
		Url:     ROUTE.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return nil, err
	}

	if r.Items == nil || len(r.Items) == 0 {
		return nil, errors.New("f5 ipv4 route table result is empty")
	}

	// routes := []*network.AddressTable{}
	routeTableMap := map[string]*network.AddressTable{}
	for _, item := range r.Items {
		ipAddress, domainId := splitRouteAndDomain(item.Network, item.Partition, partitions)
		if validator.IsIPv6AddressWithMask(ipAddress) {
			continue
		}

		vrf := ""
		if item.Partition == "Common" && domainId == 0 {
			vrf = "default"
		} else {
			vrf = "/" + item.Partition + "/" + strconv.Itoa(domainId)
		}

		var routeTable *network.AddressTable
		if routeTableMap[vrf] == nil {
			routeTableMap[vrf] = network.NewAddressTable(network.IPv4)
		}
		routeTable = routeTableMap[vrf]

		for _, intf := range interfaces {
			ipList := []string{}
			for _, ipv4 := range intf.Ipv4 {
				ipList = append(ipList, ipv4.(string))
			}

			// 针对网关gw
			gw, _ := splitRouteAndDomain(item.Gw, item.Partition, partitions)
			port := node.NewPort(intf.Name, "", map[network.IPFamily][]string{network.IPv4: ipList}, []api.Member{})
			port.WithAliasName(intf.Name)
			port.WithVrf(intf.Vrf)
			if port.HitByIpWithoutPrefix(gw, vrf) {
				_, err := network.ParseIPNet(gw)
				if err != nil {
					return nil, err
				}
				nextHop := &network.NextHop{}
				nextHop.AddHop(intf.Name, gw, false, false, nil)
				net, err := network.ParseIPNet(ipAddress)
				if err != nil {
					return nil, err
				}
				routeTable.PushRoute(net, nextHop)
				// routes = append(routes, routeTable)
			}
		}
	}

	for _, intf := range interfaces {
		if routeTableMap[intf.Vrf] == nil {
			continue
		}
		ipList := []string{}
		for _, ipv4 := range intf.Ipv4 {
			ipList = append(ipList, ipv4.(string))
		}

		routeTable := routeTableMap[intf.Vrf]
		// 针对ip
		for _, ipv4 := range ipList {
			ip, err := network.ParseIPNet(ipv4)
			if err != nil {
				return nil, err
			}
			nextHop := &network.NextHop{}
			nextHop.AddHop(intf.Name, "", true, false, nil)
			routeTable.PushRoute(ip, nextHop)
			// routes = append(routes, routeTable)
		}
	}
	return routeTableMap, nil
}

// 此处的interfaces参数需要调用self的方法返回的值
func F5RouteTableIpv6(hs session.HttpSession, partitions []Partition, interfaces []Interface) (map[string]*network.AddressTable, error) {
	httpParams := HttpParams{
		Key:     "get_route",
		Method:  "GET",
		Url:     ROUTE.String(),
		Timeout: 5,
		Force:   true,
	}
	r, err := GetResult(hs, httpParams, nil)
	if err != nil {
		return nil, err
	}

	if r.Items == nil || len(r.Items) == 0 {
		return nil, errors.New("f5 ipv6 route table result is empty")
	}

	// routes := []*network.AddressTable{}
	routeTableMap := map[string]*network.AddressTable{}
	for _, item := range r.Items {
		ipAddress, domainId := splitRouteAndDomain(item.Network, item.Partition, partitions)
		if validator.IsIPv4AddressWithMask(ipAddress) {
			continue
		}

		vrf := ""
		if item.Partition == "Common" && domainId == 0 {
			vrf = "default"
		} else {
			vrf = "/" + item.Partition + "/" + strconv.Itoa(domainId)
		}

		var routeTable *network.AddressTable
		if routeTableMap[vrf] == nil {
			routeTableMap[vrf] = network.NewAddressTable(network.IPv6)
		}
		routeTable = routeTableMap[vrf]

		for _, intf := range interfaces {
			ipList := []string{}
			for _, ipv6 := range intf.Ipv6 {
				ipList = append(ipList, ipv6.(string))
			}

			// 针对网关gw
			gw, _ := splitRouteAndDomain(item.Gw, item.Partition, partitions)
			port := node.NewPort(intf.Name, "", map[network.IPFamily][]string{network.IPv6: ipList}, []api.Member{})
			port.WithAliasName(intf.Name)
			port.WithVrf(intf.Vrf)
			if port.HitByIpWithoutPrefix(gw, vrf) {
				_, err := network.ParseIPNet(gw)
				if err != nil {
					return nil, err
				}
				nextHop := &network.NextHop{}
				nextHop.AddHop(intf.Name, gw, false, false, nil)
				net, err := network.ParseIPNet(ipAddress)
				if err != nil {
					return nil, err
				}
				routeTable.PushRoute(net, nextHop)
				// routes = append(routes, routeTable)
			}
		}
	}

	for _, intf := range interfaces {
		if routeTableMap[intf.Vrf] == nil {
			continue
		}
		ipList := []string{}
		for _, ipv6 := range intf.Ipv6 {
			ipList = append(ipList, ipv6.(string))
		}

		routeTable := routeTableMap[intf.Vrf]
		// 针对ip
		for _, ipv4 := range ipList {
			ip, err := network.ParseIPNet(ipv4)
			if err != nil {
				return nil, err
			}
			nextHop := &network.NextHop{}
			nextHop.AddHop(intf.Name, "", true, false, nil)
			routeTable.PushRoute(ip, nextHop)
			// routes = append(routes, routeTable)
		}
	}
	return routeTableMap, nil
}

func splitRouteAndDomain(source string, partition string, sourcePartitions []Partition) (string, int) {
	srcs := strings.Split(source, "%")
	ipNet := ""
	domainId := 0
	if srcs[0] == "default" {
		srcs[0] = "0.0.0.0/0"
	} else if srcs[0] == "default-inet6" {
		srcs[0] = "::/0"
	}

	if len(srcs) > 1 {
		ipNet = srcs[0]
		domainId, _ = strconv.Atoi(srcs[1])
	} else {
		ipNet = srcs[0]
	}

	for _, p := range sourcePartitions {
		if p.Name == partition {
			domainId = p.DefaultDomain
			break
		}
	}

	return ipNet, domainId
}

func splitSelfAndDomain(addressStr string, partitionStr string, partitions []Partition) (string, string, error) {
	ls := strings.Split(addressStr, "%")
	domainId := ""
	prefix := ""
	address := ls[0]
	domainWithPrefix := ""
	if len(ls) > 1 {
		domainWithPrefix = ls[1]
	}

	if domainWithPrefix != "" {
		dwp := strings.Split(domainWithPrefix, "/")
		domainId = dwp[0]
		prefix = dwp[1]
	}

	if domainId == "" {
		for _, p := range partitions {
			if p.Name == partitionStr {
				domainId = strconv.Itoa(p.DefaultDomain)
				break
			}
		}
	}

	if domainId == "" {
		return "", "", errors.New("f5 self option unknown error")
	}

	if prefix != "" {
		address = strings.Join([]string{address, prefix}, "/")
	}

	return address, fmt.Sprintf("/%s/%s", partitionStr, domainId), nil
}

func GetResult(hs session.HttpSession, params HttpParams, data []byte) (f5Result F5Result, err error) {
	if err = validateHttpRequestParams(hs, params); err != nil {
		return
	}

	// cmd := command.NewHttpCmd("GET", DEVICE_INFO.String(), "info", 5, true)
	cmd := command.NewHttpCmd(params.Method, params.Url, params.Key, params.Timeout, params.Force)
	if data != nil && len(data) > 0 {
		cmd.WithData(data)
	}
	result, err := hs.RequestWithoutCache(cmd)
	if err != nil {
		fmt.Println(fmt.Sprintf("f5 request [%s] is error : err[%s] , data[%c]", params.Url, err.Error(), data))
		return
	}
	// fmt.Println("current request result ===== ", string(result))
	err = json.Unmarshal(result, &f5Result)
	if err != nil {
		fmt.Println(fmt.Sprintf("f5 request [%s] is error : err[%s] , data[%c]  code[%d]", params.Url, err.Error(), data, f5Result.Code))
		return
	}
	if f5Result.Code != 0 {
		fmt.Println(fmt.Sprintf("f5 request [%s] is error : err[%s] , data[%c]  code[%d]", params.Url, f5Result.Message, data, f5Result.Code))
		return
	}
	return
}

func validateHttpRequestParams(hs session.HttpSession, params HttpParams) error {
	if hs.Info == nil {
		return errors.New("Http session[info] is empty")
	}

	if hs.AuthUrl == "" {
		return errors.New("Http session[AuthUrl] is empty")
	}

	if params.Method == "" {
		return errors.New("Http request[method] is nil")
	}

	if params.Url == "" {
		return errors.New("Http request[url] is nil")
	}

	if params.Method != "POST" {
		if params.Key == "" {
			return errors.New("Http request[key] is nil")
		}
	}

	if params.Timeout == 0 {
		params.Timeout = 5
	}

	return nil
}

type VirtualMatrix struct {
	Name  string
	Value int
}

var MATRIX = []VirtualMatrix{
	{Name: "host,host,port", Value: 1},
	{Name: "host,host,any", Value: 2},
	{Name: "host,net,port", Value: 3},
	{Name: "host,net,any", Value: 4},
	{Name: "host,any,port", Value: 5},
	{Name: "host,any,any", Value: 6},

	{Name: "net,host,port", Value: 7},
	{Name: "net,host,any", Value: 8},
	{Name: "net,net,port", Value: 9},
	{Name: "net,net,any", Value: 10},
	{Name: "net,any,port", Value: 11},
	{Name: "net,any,any", Value: 12},

	{Name: "any,host,port", Value: 13},
	{Name: "any,host,any", Value: 14},
	{Name: "any,net,port", Value: 15},
	{Name: "any,net,any", Value: 16},
	{Name: "any,any,port", Value: 17},
	{Name: "any,any,any", Value: 18},
}

// F5 virtual server匹配顺序
// https://support.f5.com/csp/article/K14800
func (vs Virtual) order() int {
	srcPrefixen, _ := vs.prefexlen(vs.Source, "")
	var srcType string
	switch srcPrefixen {
	case 0:
		srcType = "any"
	case 32:
		if validator.IsIPv4AddressWithMask(vs.Source) {
			srcType = "host"
		} else {
			srcType = "net"
		}
	case 128:
		srcType = "host"
	default:
		srcType = "net"
	}

	dstPrefixen, _ := vs.prefexlen(vs.Destination, "")
	var dstType string
	switch dstPrefixen {
	case 0:
		dstType = "any"
	case 32:
		if validator.IsIPv4AddressWithMask(vs.Destination) {
			dstType = "host"
		} else {
			dstType = "net"
		}
	case 128:
		dstType = "host"
	default:
		dstType = "net"
	}

	var portType string
	if vs.Port == "any" || vs.Port == "0" {
		portType = "any"
	} else {
		portType = "port"
	}

	for _, matrix := range MATRIX {
		arr := strings.Split(matrix.Name, ",")
		if arr[0] == srcType && arr[1] == dstType && arr[2] == portType {
			return matrix.Value
		}
	}
	return -1
}

func (vs Virtual) prefexlen(addr string, mask string) (int, error) {
	if mask == "any" || mask == "any6" || addr == "" || addr == "any" || addr == "any6" {
		return 0, nil
	}
	ip, err := network.ParseIPNet(addr)
	if err != nil {
		return 0, err
	}
	return ip.Prefix(), nil
}

func (vs Virtual) Match(intent policy.Intent, sameDst bool) bool {
	if vs.Disabled || vs.Enabled == false {
		return false
	}
	thisDst := vs.Orignal.Dst()
	otherDst := intent.Dst()
	if sameDst {
		return thisDst.MatchNetworkGroup(otherDst)
	}
	return vs.Orignal.Match(intent.GenerateIntentPolicyEntry())
}
