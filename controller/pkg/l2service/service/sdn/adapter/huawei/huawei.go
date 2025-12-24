package huawei

import (
	"encoding/json"
	"fmt"

	// "github.com/netxops/unify/model"
	// "github.com/netxops/unify/model/combin"
	"strconv"
	"strings"

	"github.com/netxops/utils/rest"
	Huawei "github.com/netxops/utils/rest/huawei"
	"github.com/netxops/utils/rest/huawei/model"
	clitask "github.com/netxops/utils/task"

	"github.com/netxops/utils/container"

	"github.com/influxdata/telegraf/controller/pkg/structs"
)

type HuaWeiSDN struct{}

func (s *HuaWeiSDN) changeIdToUUID(data []byte, node string) (result []byte) {
	root, err := container.ParseJSON(data)
	if err != nil {
		panic(err)
	}
	childrens, err := root.S(node).Children()
	if err != nil {
		panic(err)
	}
	for _, c := range childrens {
		c.Set(c.S("id").Data().(string), "uuid")
		c.Delete("id")
	}

	result = root.Bytes()
	return
}

func (s *HuaWeiSDN) changeUUIDToID(data []byte, node string) (result []byte) {
	root, err := container.ParseJSON(data)
	if err != nil {
		panic(err)
	}
	childrens, err := root.S(node).Children()
	if err != nil {
		panic(err)
	}
	for _, c := range childrens {
		c.Set(c.S("uuid").Data().(string), "id")
		c.Delete("uuid")
	}

	result = root.Bytes()
	return
}

func (s *HuaWeiSDN) remoteGetData(path, node string, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	req := rest.NewRequest(map[string]string{
		"path":   path,
		"method": rest.GET,
	})
	ctx, err := Huawei.NewHuaWeiRequestContext(remote.Ip, remote.Username, remote.Password, Huawei.DEFAULT_HUAWEI_SDN_PORT, nil)
	if err != nil {
		panic(err)
	}
	byteS, code, err := ctx.Ctx.Get(*req)
	if err != nil {
		panic(err)
	}
	fmt.Println("aaaaaaaaaaaaaaaaaaa=====>", string(byteS))
	res := s.changeIdToUUID(byteS, node)
	tb := clitask.NewEmptyTableWithKeys([]string{node, "code"})
	var data = make(map[string]string)
	data[node] = string(res)
	data["code"] = strconv.Itoa(code)
	tb.PushRow("", data, true, "")
	return tb, nil
}

func (s *HuaWeiSDN) remoteDeleteData(path string, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	req := rest.NewRequest(map[string]string{
		"path":   path,
		"method": rest.DELETE,
	})
	ctx, err := Huawei.NewHuaWeiRequestContext(remote.Ip, remote.Username, remote.Password, Huawei.DEFAULT_HUAWEI_SDN_PORT, nil)
	if err != nil {
		panic(err)
	}
	bytes, code, err := ctx.Ctx.Delete(*req)
	if err != nil {
		panic(err)
	}
	tb := clitask.NewEmptyTableWithKeys([]string{"code"})
	var data = make(map[string]string)
	data["code"] = strconv.Itoa(code)
	fmt.Println("aaaa", data["code"], string(bytes))
	tb.PushRow("", data, true, "")
	return tb, nil
}

func (s *HuaWeiSDN) remotePostData(path, body, node string, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface) (*clitask.Table, error) {
	ctx, err := Huawei.NewHuaWeiRequestContext(remote.Ip, remote.Username, remote.Password, Huawei.DEFAULT_HUAWEI_SDN_PORT, nil)
	if err != nil {
		panic(err)
	}
	byteS, code, err := ctx.Ctx.Post(path, body)
	if err != nil {
		panic(err)
	}
	fmt.Println("aaaaaaaaaaaaaaaaaaa=====>", string(byteS))
	tb := clitask.NewEmptyTableWithKeys([]string{node, "code"})
	var data = make(map[string]string)
	data[node] = string(byteS)
	data["code"] = strconv.Itoa(code)
	tb.PushRow("", data, true, "")
	fmt.Println("table===========>", data)
	// tb.Pretty()
	return tb, nil
}

func (s *HuaWeiSDN) createLogicPort(path string, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	for _, b := range options {
		portList := b.([]interface{})
		for _, p := range portList {
			port := p.(string)
			result, err = s.remotePostData(path, port, "", remote, taskConfig)
		}
	}
	return
}

func (s *HuaWeiSDN) deleteLogicPort(path string, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	for _, b := range options {
		portList := b.([]interface{})
		for _, p := range portList {
			port := p.(string)
			newPath := path + "/" + port
			fmt.Println("path======================>", newPath)
			result, err = s.remoteDeleteData(newPath, remote, taskConfig)
		}
	}
	return
}

func (s *HuaWeiSDN) getDevicePort(path, node string, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	var devicePorts []string
	for _, b := range options {
		idList := b.([]interface{})
		for _, id := range idList {
			deviceId := []string{id.(string)}
			request := NewPostHuaweiDevicePortsRequest(deviceId)
			b, _ := json.Marshal(request)
			body := string(b)
			result, err = s.remotePostData(path, body, node, remote, taskConfig)
			fmt.Println("ooooooooooooo======>", result)
			ctx, err := Huawei.NewHuaWeiRequestContext(remote.Ip, remote.Username, remote.Password, Huawei.DEFAULT_HUAWEI_SDN_PORT, nil)
			if err != nil {
				panic(err)
			}
			byteS, _, err := ctx.Ctx.Post(path, body)
			if err != nil {
				panic(err)
			}
			devicePorts = append(devicePorts, string(byteS))
		}
	}
	ports, _ := json.Marshal(devicePorts)
	tb := clitask.NewEmptyTableWithKeys([]string{node})
	var data = make(map[string]string)
	data[node] = string(ports)
	tb.PushRow("", data, true, "")
	return tb, nil
}

func (s *HuaWeiSDN) getLogicPort(path, node string, remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	var devicePorts []string
	ctx, err := Huawei.NewHuaWeiRequestContext(remote.Ip, remote.Username, remote.Password, Huawei.DEFAULT_HUAWEI_SDN_PORT, nil)
	if err != nil {
		panic(err)
	}
	for _, b := range options {
		idList := b.([]interface{})
		for _, id := range idList {
			deviceId := id.(string)
			newPath := path + deviceId
			req := rest.NewRequest(map[string]string{
				"path":   newPath,
				"method": rest.GET,
			})

			byteS, _, err := ctx.Ctx.Get(*req)
			if err != nil {
				panic(err)
			}

			res := s.changeIdToUUID(byteS, node)
			fmt.Println("port===============>", string(res))
			devicePorts = append(devicePorts, string(res))
		}
	}
	ports, _ := json.Marshal(devicePorts)
	tb := clitask.NewEmptyTableWithKeys([]string{node})
	var data = make(map[string]string)
	data[node] = string(ports)
	tb.PushRow("", data, true, "")
	return tb, nil
}

func NewPostHuaweiDevicePortsRequest(devices []string) *model.DevicePortsRequest {
	request := model.DevicePortsRequest{
		DeviceIdList: []string{},
		PageIndex:    "1",
		PageSize:     "400000",
	}
	for _, d := range devices {
		request.DeviceIdList = append(request.DeviceIdList, d)
	}
	return &request
}

func (s *HuaWeiSDN) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "HUAWEI_SDN_FABRIC":
		path := "/controller/dc/v3/physicalnetwork/fabricresource/fabrics"
		result, err = s.remoteGetData(path, "fabric", remote, taskConfig)
	case "HUAWEI_SDN_VPC":
		path := "/controller/dc/v3/logicnetwork/networks"
		result, err = s.remoteGetData(path, "network", remote, taskConfig)
	case "HUAWEI_SDN_LOGICROUTER":
		path := "/controller/dc/v3/logicnetwork/routers"
		result, err = s.remoteGetData(path, "router", remote, taskConfig)
	case "HUAWEI_SDN_SUBNET":
		path := "/controller/dc/v3/logicnetwork/subnets"
		result, err = s.remoteGetData(path, "subnet", remote, taskConfig)
	case "HUAWEI_SDN_LOGICSWITCH":
		path := "controller/dc/v3/logicnetwork/switchs"
		result, err = s.remoteGetData(path, "switch", remote, taskConfig)
	case "HUAWEI_SDN_LOGICPORT":
		path := "controller/dc/v3/logicnetwork/ports?logicSwitchid="
		result, err = s.getLogicPort(path, "port", remote, taskConfig, options)
	case "HUAWEI_SDN_DEVICE":
		path := "/acdcn/v3/topoapi/dcntopo/device"
		result, err = s.remoteGetData(path, "devices", remote, taskConfig)
	case "HUAWEI_SDN_DEVICEPORT":
		path := "/acdcn/v3/topoapi/dcntopo/getPorts"
		result, err = s.getDevicePort(path, "ports", remote, taskConfig, options)
	case "HUAWEI_SDN_CREATEPORT":
		path := "controller/dc/v3/logicnetwork/ports"
		result, err = s.createLogicPort(path, remote, taskConfig, options)
	case "HUAWEI_SDN_DELETEPORT":
		path := "/controller/dc/v3/logicnetwork/ports/port"
		result, err = s.deleteLogicPort(path, remote, taskConfig, options)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}
