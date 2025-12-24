package forti

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	fortiEnum "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/enum"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device"
	"github.com/mitchellh/mapstructure"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	fortigate "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/forti"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/forti-sdk-go/fortios/auth"
	forticlient "github.com/netxops/forti-sdk-go/fortios/sdkcore"

	"strings"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"

	"github.com/gofrs/uuid"
)

type FortigateAdapter struct {
	Type       api.AdapterType
	DeviceType terminalmode.DeviceType
	info       *session.DeviceBaseInfo
	CliCmdList *command.CliCmdList
}

func NewFortiAdapter(info *session.DeviceBaseInfo, config string) *FortigateAdapter {
	return &FortigateAdapter{
		Type:       tools.ConditionalT(info == nil, api.StringAdapter, api.LiveAdapter),
		DeviceType: terminalmode.FortiGate,
		info:       info,
	}
}

func (fa *FortigateAdapter) CreateClient() (*forticlient.FortiSDKClient, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: transport}
	//fa.info.Token = "zqGdrm0rH4r1GN5bsfhHnhQcnNGjdt"
	return forticlient.NewClient(auth.NewAuth(fa.info.Host, fa.info.Token, "", "", "", "", "", "", "", ""), httpClient)
}

func (fa *FortigateAdapter) Prepare(force bool) *command.CliCmdList {
	cmdList := command.NewCliCmdList(fa.info.Host, force)
	cmdList.Add("get router info routing-table all", "sh route", 5, force)
	cmdList.Add("get hardware status", "sh model", 5, force)
	cmdList.Add("show full-configuration", "sh run", 10, force)
	fa.RunCmdListAndSave(cmdList)
	return cmdList
}

func (fa *FortigateAdapter) Info(force bool) (*device.DeviceBaseInfo, error) {
	client, err := fa.CreateClient()
	if err != nil {
		return nil, err
	}

	fortiInfo, err := fa.GetResponseByApi(client, fortiEnum.Info)
	if err != nil {
		return nil, err
	}

	var hostname string
	var version string
	var serial string
	var model string

	if _, ok := fortiInfo["serial"].(string); ok {
		serial = fortiInfo["serial"].(string)
	}
	if _, ok := fortiInfo["version"].(string); ok {
		version = fortiInfo["version"].(string)
	}

	info := fortiInfo["results"]
	if _, ok := info.(map[string]any); ok {
		infoMap := info.(map[string]any)
		hostname = infoMap["hostname"].(string)
	}

	cmdList := fa.Prepare(false)
	cd, err := cmdList.Get("sh model")
	if err != nil {
		panic(err)
	}
	modelStr := string(cd.Data)
	lines := text.RegexSplit("\r\n", modelStr)
	sections := fa.getSection("\n", strings.Join(lines[0:], "\n"))
	model = fa.parseSectionModel(sections)

	if model == "" {
		return nil, errors.New("forti model is nil")
	}
	if version == "" {
		return nil, errors.New("forti version is nil")
	}
	if hostname == "" {
		return nil, errors.New("forti hostname is nil")
	}
	if serial == "" {
		return nil, errors.New("forti serial is nil")
	}

	fge := &device.DeviceBaseInfo{
		Hostname: hostname,
		Version:  version,
		Model:    model,
		SN:       serial,
	}

	return fge, nil
}

func (fa *FortigateAdapter) TaskId() uint {
	return 1
}

func (fa *FortigateAdapter) GetConfig(force bool) interface{} {
	cmdList := fa.Prepare(force)
	cd, err := cmdList.Get("sh run")
	if err != nil {
		panic(err)
	}
	shrunText := string(cd.Data)

	return shrunText
}

func (fa *FortigateAdapter) PortList(force bool) []api.Port {
	client, err := fa.CreateClient()
	if err != nil {
		panic(err)
	}

	interfaceMap, err := fa.GetResponseByApi(client, fortiEnum.Interfaces)
	if err != nil {
		panic(err)
	}
	//fmt.Println("interfaceMap--->", interfaceMap)
	var interfaceList []dto.FortiPort
	err = mapstructure.WeakDecode(interfaceMap["results"], &interfaceList)
	if err != nil {
		return nil
	}

	var portList []api.Port
	ipMap := map[network.IPFamily][]string{}
	ipMap[network.IPv4] = []string{}
	ipMap[network.IPv6] = []string{}
	var portName, aliasName string
	for _, intf := range interfaceList {
		if intf.Name == "" || intf.Ip == "" || strings.Contains(intf.Ip, "0.0.0.0") {
			continue
		}
		portName = intf.Name
		aliasName = intf.Alias
		if portName == "" && aliasName != "" {
			portName = aliasName
		}

		ipArr := strings.Split(intf.Ip, " ")
		net, err := network.ParseIPNet(ipArr[0] + "/" + ipArr[1])
		if err != nil {
			panic(err)
		}
		ip := fmt.Sprintf("%s/%d", net.IP.String(), net.Prefix())
		ipv4Map := map[network.IPFamily][]string{}
		ipv4Map[network.IPv4] = []string{ip}
		port := fortigate.NewFortigatePort(portName, "", ipv4Map, []api.Member{})
		port.WithAliasName(portName)
		port.WithVrf(enum.DefaultVrf)
		port.WithMainIpv4(ip)
		portList = append(portList, port)
	}

	return portList
}

func (fa *FortigateAdapter) RouteTable(force bool) (ipv4TableMap, ipv6TableMap map[string]*network.AddressTable) {
	cmdList := fa.Prepare(force)
	//
	cd, err := cmdList.Get("sh route")
	if err != nil {
		panic(err)
	}
	shipv4Txt := string(cd.Data)
	ipv4routeTable := fa.parseIpv4Route(shipv4Txt)
	fmt.Println("ipv4routeTable  ----------- ", ipv4routeTable.String())

	ipv4TableMap = map[string]*network.AddressTable{
		enum.DefaultVrf: ipv4routeTable,
	}

	return ipv4TableMap, ipv6TableMap
}

func (fa *FortigateAdapter) ParseName(force bool) string {
	info, _ := fa.Info(force)
	return info.Hostname
}

// 批量执行，输入[]*command.CliCmdList，就是命令列表的列表
// 这就意味着需要多次登录网络设备执行
func (fa *FortigateAdapter) BatchRun(p interface{}) (interface{}, error) {
	cmds := p.([]interface{})
	var err error

	cliSession := session.NewCliSession(fa.info)

	var mustStop bool
	for _, cmdList := range cmds {
		if !mustStop {
			for _, cmd := range cmdList.(*command.CliCmdList).Cmds {
				cmd.(*command.HttpCmd).Force = true
			}

			err = cliSession.BatchRun(cmdList.(*command.CliCmdList), true)
			if err != nil {
				return nil, err
			}
			for _, c := range cmdList.(*command.CliCmdList).Cmds {
				if c.Level() == command.MUST && !c.Ok() {
					// 如果关键命令执行出错，则停止后续命令的执行
					mustStop = true
				}
			}
		}
	}

	return p, err
}

// 为了避免多次登录设备执行命令，需要将所有待执行命令合并到一起执行
// 但是为了前端显示方便区分阶段性执行结果，又需要将执行结果按照输入时的顺序进行保存
func (fa *FortigateAdapter) BatchConfig(p ...interface{}) (interface{}, error) {
	info := fa.info.BaseInfo
	base := terminal.BaseInfo{
		Host:     info.Host,
		Username: info.Username,
		Password: info.Password,
		AuthPass: info.AuthPass,
		Telnet:   info.Telnet,
	}

	exec := terminal.NewExecute(terminalmode.CONFIG, terminalmode.FortiGate, &base)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	cmdList := []command.Command{}

	// var hasError bool
	var err error

	// p为需要进行批量执行的命令主体
	for _, cll := range p {
		switch cll.(type) {
		case []interface{}:
			// cl其实是[]*CliCmdList
			for _, cl := range cll.([]interface{}) {
				for _, cmd := range cl.(*command.CliCmdList).Cmds {
					key := cmd.Key()
					if cmd.Key() == "" {
						key = strings.ReplaceAll(cmd.Cmd(), " ", "_")
					}
					exec.Add(cmd.Cmd(), "", 2, key, "")
					c := command.NewCliCmd(cmd.Cmd(), key, 2, true)
					c.WithLevel(command.MUST)
					cmdList = append(cmdList, c)
				}
			}
		case []string:
			for _, cmd := range cll.([]string) {
				key := strings.ReplaceAll(cmd, " ", "_")
				c := command.NewCliCmd(cmd, key, 2, true)
				c.WithLevel(command.MUST)
				exec.Add(cmd, "", 2, key, "")
				cmdList = append(cmdList, c)
			}
		default:
			panic("unsupoort data type")
		}
	}

	// 需要自动填充First和Last命令
	exec.Prepare(false)
	result := exec.Run(true)

	for _, cmd := range cmdList {
		ok, data := result.GetResult(cmd.Key())
		cmd.WithMsg(strings.Join(data, "\n"))
		if !ok {
			cmd.WithOk(false)
			err = fmt.Errorf("get result failed, key:%s", cmd.Key())
			// hasError = true
		} else {
			cmd.WithOk(true)
		}
	}

	firstCmdList := []command.Command{}
	for _, fc := range exec.DeviceMode.First_Chain {
		c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
		if fc.Status == terminalmode.CMD_COMPLETED {
			c.WithOk(true)
		}
		c.WithMsg(fc.Msg)
		c.WithLevel(command.OPTION)
		firstCmdList = append(firstCmdList, c)
	}

	lastCmdList := []command.Command{}
	for _, fc := range exec.DeviceMode.Last_Chain {
		c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
		if fc.Status == terminalmode.CMD_COMPLETED {
			c.WithOk(true)
		}
		c.WithMsg(fc.Msg)
		c.WithLevel(command.OPTION)
		lastCmdList = append(lastCmdList, c)
	}

	cliCmdList := command.NewCliCmdList(base.Host, true)
	for _, cmd := range cmdList {
		cliCmdList.AddCmd(cmd)
	}

	return cliCmdList, err
}

func (fa *FortigateAdapter) AttachChannel(out chan string) bool {
	return false
}

func (fa *FortigateAdapter) RunCmdListAndSave(cl *command.CliCmdList) {
	fa.CliCmdList = cl
	cli := session.NewCliSession(fa.info)
	err := cli.BatchRun(cl, true)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}

func (fa *FortigateAdapter) GetRawConfig(apiPath string, force bool) (any, error) {
	client, err := fa.CreateClient()
	if err != nil {
		return nil, err
	}
	responseData, err := fa.GetResponseByApiWithTransform(client, fortiEnum.ApiPath(apiPath))
	if err != nil {
		return nil, err
	}
	return responseData, nil
}

func (fa *FortigateAdapter) parseIpv4Route(shrouteText string) *network.AddressTable {
	routeTable := network.NewAddressTable(network.IPv4)

	lines := text.RegexSplit("\r\n", shrouteText)
	sections := fa.getSection(`Routing table for`, strings.Join(lines[0:len(lines)-1], "\n"))
	for _, s := range sections {
		fa.parseSectionRoute(routeTable, s)
	}

	return routeTable
}

func (fa *FortigateAdapter) parseIpv4Routes(txt string) {
	sections := text.MustSectionsByRegex2(`^\w[^\n]+((\s{10,}\[[^\n]+){1,})?`, txt, "m")
	for _, s := range sections.Texts {
		net := fa.parseDst(s)
		fmt.Println(net)
		fa.parseHop(s)
	}
}

func (fa *FortigateAdapter) parseVrf(txt string) string {
	r, err := text.GetFieldByRegex(`VRF=(?P<vrf>[\d\w]+)`, txt, []string{"vrf"})
	if err != nil {
		panic(err)
	}
	return r["vrf"]
}

func (fa *FortigateAdapter) parseDst(txt string) string {
	r, err := text.GetFieldByRegex(`(?P<net>(\d{1,3}\.){1,3}\d{1,3}/\d+)`, txt, []string{"net"})
	if err != nil {
		panic(err)
	}
	return r["net"]
}

func (fa *FortigateAdapter) parseHop(txt string) []map[string]string {
	txt = strings.TrimSpace(txt)
	lines := strings.Split(txt, "\n")
	var hopResult []map[string]string
	for _, line := range lines {
		regex := `((directly connected)|(via (?P<hop>(\d{1,3}\.){3}\d{1,3}))), (?P<port>[\w\d]+),?`
		r, err := text.GetFieldByRegex(regex, line, []string{"hop", "port"})
		if err != nil {
			panic(err)
		}
		fmt.Println(r)
		hopResult = append(hopResult, r)
	}
	return hopResult
}

func (fa *FortigateAdapter) getSection(splitStr string, txt string) []string {
	sections := text.RegexSplit(splitStr, txt)
	if len(sections) > 1 {
		return sections[1:]
	}

	return []string{}
}

func (fa *FortigateAdapter) parseSectionRoute(routeTable *network.AddressTable, txt string) {
	vrf := fa.parseVrf(txt)
	fmt.Println(vrf)
	fa.parseRoutes(routeTable, strings.Join(strings.Split(txt, "\n")[1:], "\n"))
}

func (fa *FortigateAdapter) parseSectionModel(sections []string) string {
	for _, section := range sections {
		if !strings.Contains(section, "Model name: ") {
			continue
		}
		return strings.Split(section, "Model name: ")[1]
	}

	return ""
}

func (fa *FortigateAdapter) parseRoutes(routeTable *network.AddressTable, txt string) {
	sections := text.MustSectionsByRegex2(`^\w[^\n]+((\s{10,}\[[^\n]+){1,})?`, txt, "m")
	for _, s := range sections.Texts {
		netStr := fa.parseDst(s)
		fmt.Println(netStr)
		hopList := fa.parseHop(s)

		net, err := network.ParseIPNet(netStr)
		if err != nil {
			panic(err)
		}
		nextHop := &network.NextHop{}
		for _, hop := range hopList {
			//_, _ = nextHop.AddHop(hop["port"], hop["hop"], hop["hop"] == "", netStr == "0.0.0.0/0", nil)
			_, _ = nextHop.AddHop(hop["port"], hop["hop"], hop["hop"] == "", false, nil)
		}

		if err = routeTable.PushRoute(net, nextHop); err != nil {
			panic(err)
		}
	}
}

func (fa *FortigateAdapter) GetResponseByApi(client *forticlient.FortiSDKClient, apiPath fortiEnum.ApiPath) (result map[string]any, err error) {
	HTTPMethod := "GET"
	result = make(map[string]any)

	req := client.NewRequest(HTTPMethod, string(apiPath), nil, nil)
	err = req.Send2(2, true)
	if err != nil || req.HTTPResponse == nil {
		err = fmt.Errorf("cannot send request, %s", err)
		return
	}

	body, err := ioutil.ReadAll(req.HTTPResponse.Body)
	req.HTTPResponse.Body.Close() //#
	if err != nil || body == nil {
		err = fmt.Errorf("cannot get response body, %s", err)
		return
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return
	}

	return
}

func (fa *FortigateAdapter) GetResponseByApiWithTransform(client *forticlient.FortiSDKClient, apiPath fortiEnum.ApiPath) (result dto.FortiResponse, err error) {
	HTTPMethod := "GET"
	result = dto.FortiResponse{}

	req := client.NewRequest(HTTPMethod, string(apiPath), nil, nil)
	err = req.Send2(2, true)
	if err != nil || req.HTTPResponse == nil {
		err = fmt.Errorf("cannot send request, %s", err)
		return
	}

	body, err := ioutil.ReadAll(req.HTTPResponse.Body)
	req.HTTPResponse.Body.Close()
	if err != nil || body == nil {
		err = fmt.Errorf("cannot get response body, %s", err)
		return
	}
	err = json.Unmarshal(body, &result)
	return
}
