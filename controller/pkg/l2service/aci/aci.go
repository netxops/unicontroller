package aci

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"

	"github.com/influxdata/telegraf/controller/global"
	"github.com/netxops/utils/rest"
	"github.com/netxops/utils/rest/aci"
)

type Aci struct {
	ctx *aci.ACIRest
}

func NewAci(host, username, password string) *Aci {
	ctx, err := aci.NewACIRequestContext(host, username, password, aci.DEFAULT_ACI_SDN_PORT, global.Redis)
	if err != nil {
		panic(err)
	}
	return &Aci{ctx: ctx}
}

func (ai *Aci) base(url string) (res map[string]interface{}) {
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
	fmt.Println(string(byteS))
	return
}

func (ai *Aci) FvTenant() {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/class/fvTenant.json",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	fmt.Println(string(byteS))
}

func (ai *Aci) FvAEpg() {
	//req := rest.NewRequest(map[string]string{
	//	"path":   "/api/node/class/fvAEPg.json",
	//	"method": rest.GET,
	//})
	//byteS, err := ai.ctx.Ctx.Get(*req)
	//if err != nil {
	//	panic(err)
	//}
	//res := map[string]interface{}{}
	//_ = json.Unmarshal(byteS, &res)
	res := ai.base("/api/node/class/fvAEPg.json")
	fmt.Println(res)

}

func (ai *Aci) FvBD() {
	res := ai.base("/api/node/class/fvBD.json")
	fmt.Println(res)
}

func (ai *Aci) EpTracker() {
	res := ai.base("/api/node/class/fvCEp.json")
	fmt.Println(res)
}

func (ai *Aci) VzBrCp() {
	res := ai.base("/api/node/class/vzBrCP.json")
	fmt.Println(res)
}

func (ai *Aci) FabricPathEp() {
	res := ai.base("/api/node/class/fabricPathEp.json")
	fmt.Println(res)
}

func (ai *Aci) Controller() {
	res := ai.base("/api/node/mo/topology/pod-1/node-1.json")
	fmt.Println(res)
}

func (ai *Aci) ControllersSize() {
	res := ai.base("/api/node/class/fabricNode.json?query-target-filter=or(eq(fabricNode.role,\"leaf\"),eq(fabricNode.role,\"controller\"))")
	fmt.Println(res)
}

func (ai *Aci) FvAp() {
	res := ai.base("/api/node/class/fvAp.json")
	fmt.Println(res)
}

func (ai *Aci) FabricAPathEp() {
	ai.base("/api/node/class/fabricAPathEp.json")
	//fmt.Println(res)
}

func (ai *Aci) FvSubnet() {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/class/fvSubnet.json",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	fmt.Println(byteS)
}

func (ai *Aci) FortyPolicy() {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/mo/uni/tn-DevOps/ap-Public.Internet.Policy-AEP/epg-Shared.Internet.FW.Policy-EPG/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-PolicyObjects/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-IPv4FWPolicyFolder/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-65534.json?query-target=subtree",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	fmt.Println(byteS)
}

func (ai *Aci) FortiSubnet() {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/mo/uni/tn-DevOps/ap-Public.Internet.Policy-AEP/epg-Shared.Internet.FW.Policy-EPG/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-PolicyObjects/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-IPv4FWAddressFolder/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-TEST_HOST_4.json?query-target=subtree",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	fmt.Println(byteS)
}

func (ai *Aci) FortiService() {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/mo/uni/tn-DevOps/ap-Public.Internet.Policy-AEP/epg-Shared.Internet.FW.Policy-EPG/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-PolicyObjects/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-FWServiceFolder/FI_C-Shared.Internet.FW.Policy-CT-G-Forti.D600.V2.1-V3801.3810-SGT-F-N1-N-TCP_5555.json?query-target=subtree",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	fmt.Println(byteS)
}

func tableOutputForGetCommands(obj interface{}) (list []interface{}) {
	if reflect.TypeOf(obj).Kind() == reflect.Slice {
		s := reflect.ValueOf(obj)
		for i := 0; i < s.Len(); i++ {
			ele := s.Index(i)
			list = append(list, ele.Interface().(interface{}))
		}
	}
	return
}

func (ai *Aci) Firmware() (string, error) {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/class/topology/pod-1/node-1/firmwareCtrlrRunning.json",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	//for _, r := range res {
	//	rList := tableOutputForGetCommands(r)
	//	for _, k := range rList {
	//		resData, _ := json.Marshal(k)
	//		fmt.Println(string(resData))
	//	}
	//}
	//fmt.Println(111)
	fmt.Println(res) // ["firmwareCtrlrRunning"]["attributes"]["version"]
	version := ""
	r := regexp.MustCompile("version.+\"(.*)\"")
	resData := r.FindStringSubmatch(string(byteS))
	if len(resData) > 1 {
		version = resData[1]
	}
	return version, nil
}

func (ai *Aci) VzFilter() {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/mo/uni/tn-TenantB.json?query-target=children&target-subtree-class=vzFilter",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	fmt.Println(byteS)
}

func (ai *Aci) VzEntry() {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/class/vzEntry.json",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	fmt.Println(byteS)
}

func (ai *Aci) Contract() {
	req := rest.NewRequest(map[string]string{
		"path":   "/api/node/mo/uni/tn-TenantB.json?query-target=children&target-subtree-class=vzBrCP&rsp-subtree=children",
		"method": rest.GET,
	})
	byteS, _, err := ai.ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	res := map[string]interface{}{}
	_ = json.Unmarshal(byteS, &res)
	fmt.Println(byteS)
}
