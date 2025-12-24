package dell

import (
	"fmt"
	"strings"

	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"

	RedfishBase "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish"
	"github.com/influxdata/telegraf/controller/pkg/structs"

	"github.com/netxops/utils/mygofish"
	clitask "github.com/netxops/utils/task"
)

type Dell struct{}

func (s *Dell) GofishClient(remote *structs.L2DeviceRemoteInfo) *mygofish.HardCollect {
	server := RedfishBase.NormalGofishClient(remote)
	return server
}

func (s *Dell) gofishcpuV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishcpuV1Collect(remote, taskConfig, server)
}

func (s *Dell) gofishmemV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishmemV1Collect(remote, taskConfig, server)
}

func (s *Dell) gofishdiskV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishdiskV1Collect(remote, taskConfig, server)
}

func (s *Dell) gofishRedfishVersionV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishRedfishVersionV1Collect(remote, taskConfig, server)
}
func (s *Dell) gofishNetworkInterfaceV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkInterfaceV1Collect(remote, taskConfig, server)
}

func (s *Dell) gofishPowerControlV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerControlV1Collect(remote, taskConfig, server)
}
func (s *Dell) gofishPowerV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerV1Collect(remote, taskConfig, server)
}
func (s *Dell) gofishNetworkV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkV1Collect(remote, taskConfig, server)
}

func (s *Dell) redfishNetWorkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetWorkV1Collect(c)
}

func (s *Dell) gofishbaseinfoV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishbaseinfoV1Collect(remote, taskConfig, server)
}
func (s *Dell) RedfishClient(remote *structs.L2DeviceRemoteInfo) (c *v2.Client, err error) {
	return RedfishBase.NormalRedfishClient(remote)
}

func (s *Dell) redfishCpuV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishCpuV1Collect(c)
}

func (s *Dell) redfishMEMV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishMEMV1Collect(c)
}

func (s *Dell) redfishBaseInfoV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBaseInfoV1Collect(c)
}

func (s *Dell) redfishVersionV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishVersionV1Collect(c)
}

func (s *Dell) redfishBMCV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBMCV1Collect(c)
}

func (s *Dell) gofishBMCV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishBMCV1Collect(remote, taskConfig, server)
}

func (s *Dell) redfishNetworkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetworkV1Collect(c)
}

func (s *Dell) redfishPowerControlV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerControlV1Collect(c)
}

func (s *Dell) redfishPowerV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerV1Collect(c)
}
func (s *Dell) redfishDiskV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishDiskV1Collect(c)
}
func (s *Dell) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "DELL_GOFISH_CPUV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishcpuV1Collect(remote, taskConfig, server)

		fmt.Println("===this is from dell cpu v1: ", remote)
	case "DELL_REDFISH_CPUV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishCpuV1Collect(client)
			fmt.Println("===eerr", err)
		}
		fmt.Println("this is from dell cpu v2: ", remote)
	case "DELL_SSH_CPUV1":
		fmt.Println("this is from dell cpu v3: ", remote)
	case "DELL_GOFISH_MEMV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishmemV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish mem v1: ", remote)
	case "DELL_REDFISH_MEMV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishMEMV1Collect(client)
		} else {
			fmt.Println("======mem err", err)
		}
		fmt.Println("===this is from dell redfish mem v1: ", remote)
	case "DELL_GOFISH_DISKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishdiskV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish disk v1: ", remote)
	case "DELL_REDFISH_DISKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishDiskV1Collect(client)
		} else {
			fmt.Println("====client err", err)
		}
		fmt.Println("===this is from dell redfish disk v1: ", remote)
	case "DELL_GOFISH_BASEINFOV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishbaseinfoV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish baseinfo v1: ", remote)
	case "DELL_REDFISH_BASEINFOV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBaseInfoV1Collect(client)
		}
		fmt.Println("===this is from dell redfish baseinfo v1: ", remote)

	case "DELL_GOFISH_NETWORKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish network v1: ", remote)
	case "DELL_REDFISH_NETWORKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetWorkV1Collect(client)
		} else {
			fmt.Println("===err", err2)
		}
		fmt.Println("===this is from dell redfish network v1: ", remote)
	case "DELL_GOFISH_REDFISHVERSIONV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishRedfishVersionV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish version v1: ", remote)
	case "DELL_REDFISH_REDFISHVERSIONV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishVersionV1Collect(client)
		}
		fmt.Println("===this is from dell redfish version v1: ", remote)
	case "DELL_GOFISH_POWERV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish power v1: ", remote)
	case "DELL_REDFISH_POWERV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerV1Collect(client)
		}
		fmt.Println("===this is from dell redfish power v1: ", remote)
	case "DELL_GOFISH_POWERCONTROLV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerControlV1Collect(remote, taskConfig, server)
	case "DELL_REDFISH_POWERCONTROLV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerControlV1Collect(client)
		}
	case "DELL_GOFISH_INTERFACEV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkInterfaceV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish networkinterface v1: ", remote)
	case "DELL_REDFISH_INTERFACEV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetworkV1Collect(client)
		} else {
			fmt.Println("====dddd", err2)
		}
		fmt.Println("===this is from dell redfish interface v1: ", remote)
	case "DELL_GOFISH_BMCV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishBMCV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from dell gofish bmc v1: ", remote)
	case "DELL_REDFISH_BMCV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBMCV1Collect(client)
		}
		fmt.Println("===this is from dell redfish bmc v1: ", remote)
	default:
		err = fmt.Errorf("task is not being executed, method=%s", strings.ToUpper(taskConfig.GetMethod()))
	}

	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}
