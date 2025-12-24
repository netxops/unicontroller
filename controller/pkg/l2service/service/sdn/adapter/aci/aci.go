package aci

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/utils/rest"
	"github.com/netxops/utils/rest/aci"
	clitask "github.com/netxops/utils/task"
)

type ACI struct {
	ctx *aci.ACIRest
}

func NewAci(host, username, password string) *ACI {
	ctx, err := aci.NewACIRequestContext(host, username, password, aci.DEFAULT_ACI_SDN_PORT, nil)
	if err != nil {
		panic(err)
	}
	return &ACI{ctx: ctx}
}

func (ai *ACI) base(url string) (res map[string]interface{}) {
	req := rest.NewRequest(map[string]string{
		"path":   url,
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)

	if err != nil {
		panic(err)
	}
	res = map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	return
}

func (ai *ACI) SDN_GET(url interface{}) ([]byte, error) {
	urlStr := fmt.Sprintf("%s", url)
	req := rest.NewRequest(map[string]string{
		"path":   urlStr,
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	return byteS, err
}
func (ai *ACI) FvTenant() {
	res := ai.base(FvTenantApi)
	fmt.Println(res)
}

func (ai *ACI) FvAEpg() {
	res := ai.base(FvAEpgApi)
	fmt.Println(res)

}

func (ai *ACI) FvBD() {
	res := ai.base(FvBdApi)
	fmt.Println(res)
}

func (ai *ACI) EpTracker() {
	res := ai.base(EpTrackerApi)
	fmt.Println(res)
}

func (ai *ACI) VzBrCp() {
	res := ai.base(VzBrCpApi)
	fmt.Println(res)
}

func (ai *ACI) FabricPathEp() {
	res := ai.base(FabricPathEpApi)
	fmt.Println(res)
}

func (ai *ACI) Controller() {
	res := ai.base(ControllerApi)
	fmt.Println(res)
}

func (ai *ACI) ControllersSize() {
	res := ai.base(ControllersSizeApi)
	fmt.Println(res)
}

func (ai *ACI) FvAp() {
	res := ai.base(FvApApi)
	fmt.Println(res)
}

func (ai *ACI) FvSubnet() {
	res := ai.base(FvSubnetApi)
	fmt.Println(res)
}

func (ai *ACI) FortyPolicy() {
	res := ai.base(FortyPolicyApi)
	fmt.Println(res)
}

func (ai *ACI) FortiSubnet() {
	res := ai.base(FortiSubnetApi)
	fmt.Println(res)
}

func (ai *ACI) FortiService() {
	res := ai.base(FortiServiceApi)
	fmt.Println(res)
}

func (ai *ACI) Firmware() {
	res := ai.base(FirmwareApi)
	fmt.Println(res)
}

func (ai *ACI) VzFilter() {
	res := ai.base(VzFilterApi)
	fmt.Println(res)
}

func (ai *ACI) VzEntry() {
	res := ai.base(VzEntryApi)
	fmt.Println(res)
}

func (ai *ACI) Contract() {
	res := ai.base(ContractApi)

	fmt.Println(res)
}

func (ai *ACI) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	// func (ai *ACI) Process(remote *combi.DeviceRemoteInfo, taskConfig api.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	ain := NewAci(remote.Ip, remote.Username, remote.Password)
	var byteS []byte
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "SDN_GET":
		fmt.Println("ggggggg", options[0])
		byteS, err = ain.SDN_GET(options[0])
		//fmt.Println("bbbbbb", string(byteS))
		fmt.Println("errrr", err)
	case "SDN_TENANT":
		ain.FvTenant()
	case "SDN_FVAEPG":
		ain.FvAEpg()
	case "SDN_FVBD":
		ain.FvBD()
	case "SDN_EPTRACKER":
		ain.EpTracker()
	case "SDN_VZBRCP":
		ain.VzBrCp()
	case "SDN_FABRICPATHEP":
		ain.FabricPathEp()
	case "SDN_CONTROLLER":
		ain.Controller()
	case "SDN_CONTROLLERSSIZE":
		ain.ControllersSize()
	case "SDN_FVAP":
		ain.FvAp()
	case "SDN_FVSUBNET":
		ain.FvSubnet()
	case "SDN_FORTYPOLICY":
		ain.FortyPolicy()
	case "SDN_FORTISUBNET":
		ain.FortiSubnet()
	case "SDN_FORTISERVICE":
		ain.FortiService()
	case "SDN_FIRMWARE":
		ain.Firmware()
	case "SDN_VZFILTER":
		ain.VzFilter()
	case "SDN_VZENTRY":
		ain.VzEntry()
	case "SDN_CONTRACT":
		ain.Contract()

	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))

	}
	result = clitask.NewEmptyTableWithKeys([]string{"output"})
	result.PushRow("1", map[string]string{"output": string(byteS)}, true, "")
	fmt.Println("rrrrr", result)
	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}
	return
}
