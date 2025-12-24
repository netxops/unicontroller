package cpu

import (
	"fmt"
	"strings"

	RedfishBase "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish"
	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"
	"github.com/influxdata/telegraf/controller/pkg/structs"

	"github.com/netxops/utils/mygofish"
	clitask "github.com/netxops/utils/task"
)

func GofishClient(remote *structs.L2DeviceRemoteInfo) *mygofish.HardCollect {
	server := RedfishBase.NormalGofishClient(remote)
	return server
}

func GofishcpuV1Collect(remote *structs.L2DeviceRemoteInfo, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	infoList, err := server.GetCpuInfo()
	// if err==nil{
	//	tb, err:=RedfishBase.CpuBaseInfo(infoList)
	//	return tb, err
	// }else{
	//	return nil, err
	// }
	// tb := clitask.NewEmptyTableWithKeys([]string{"manufacture", "api", "socket", "totalThreads", "totalEnabledCores", "name"})
	tb := RedfishBase.CpuField()
	for _, each := range infoList {
		p := map[string]string{}
		p["manufacture"] = each.Manufacturer
		p["api"] = each.Model
		p["socket"] = each.Socket
		p["name"] = each.Name
		p["totalThreads"] = fmt.Sprintf("%d", each.TotalThreads)
		p["totalEnabledCores"] = fmt.Sprintf("%d", each.TotalEnabledCores)
		err = tb.PushRow("", p, false, "")
		if err != nil {
			return nil, err
		}
	}
	// tb.Pretty()
	return tb, err
}

func RedfishClient(remote *structs.L2DeviceRemoteInfo) (*v2.Client, error) {
	return RedfishBase.NormalRedfishClient(remote)
}

func RedfishCpuV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	// if ok != false {
	// 	jsonInterface := server.Json["CpuInfo"]
	// 	infoList := RedfishBase.InterfaceToList(jsonInterface)
	// 	tb := RedfishBase.CpuField()
	// 	// tb := clitask.NewEmptyTableWithKeys([]string{"manufacture", "api", "socket", "totalThreads", "totalEnabledCores", "name"})
	// 	for _, each := range infoList {
	// 		m := map[string]interface{}{}
	// 		odataJson, _ := json.Marshal(each)
	// 		if err := json.Unmarshal(odataJson, &m); err == nil {
	// 			p := map[string]string{}
	// 			// fmt.Printf("===cccc=%+v\n", m)
	// 			p["manufacture"] = m["Manufacturer"].(string)
	// 			p["api"] = m["Model"].(string)
	// 			p["name"] = m["Name"].(string)
	// 			p["totalThreads"] = fmt.Sprintf("%f", m["TotalThreads"])
	// 			p["socket"] = m["Socket"].(string)
	// 			p["totalEnabledCores"] = fmt.Sprintf("%f", m["TotalCores"])
	// 			err = tb.PushRow("", p, false, "")
	// 			if err != nil {
	// 				return nil, err
	// 			}
	// 		} else {
	// 			return nil, err
	// 		}
	// 	}
	// 	tb.Pretty()
	// 	return tb, err
	// }
	// return nil, err
	return
}

func CpuAllMethod(method string, remote *structs.L2DeviceRemoteInfo) (err error) {
	switch strings.ToUpper(method) {
	case "GOFISH_CPUV1":
		server := GofishClient(remote)
		defer server.OutC.Logout()
		_, err = GofishcpuV1Collect(remote, server)
	case "REDFISH_CPUV1":
		server, err2 := RedfishClient(remote)
		if err2 == nil {
			_, err = RedfishCpuV1Collect(server)
		} else {
			return err
		}
	}
	return
}
