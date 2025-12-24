package nettrix

import (
	"fmt"
	"strings"

	v2 "github.com/influxdata/telegraf/controller/pkg/l2service/redfish/v2"

	RedfishBase "github.com/influxdata/telegraf/controller/pkg/l2service/adapter/redfish"
	"github.com/influxdata/telegraf/controller/pkg/structs"

	"github.com/netxops/utils/mygofish"
	clitask "github.com/netxops/utils/task"
)

type Nettrix struct{}

func (s *Nettrix) RedfishClient(remote *structs.L2DeviceRemoteInfo) (*v2.Client, error) {
	return RedfishBase.NormalRedfishClient(remote)
}

func (s *Nettrix) GofishClient(remote *structs.L2DeviceRemoteInfo) *mygofish.HardCollect {
	return RedfishBase.NormalGofishClient(remote)
}

func (s *Nettrix) gofishcpuV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishcpuV1Collect(remote, taskConfig, server)
}

func (s *Nettrix) gofishmemV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishmemV1Collect(remote, taskConfig, server)
}

func (s *Nettrix) gofishdiskV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishdiskV1Collect(remote, taskConfig, server)
}

func (s *Nettrix) gofishRedfishVersionV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishRedfishVersionV1Collect(remote, taskConfig, server)
}

func (s *Nettrix) redfishNetworkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetWorkV1Collect(c)
}
func (s *Nettrix) gofishNetworkInterfaceV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkInterfaceV1Collect(remote, taskConfig, server)
}

func (s *Nettrix) gofishPowerV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerV1Collect(remote, taskConfig, server)
}
func (s *Nettrix) gofishNetworkV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishNetworkV1Collect(remote, taskConfig, server)
}

func (s *Nettrix) redfishNetWorkV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishNetWorkV1Collect(c)
}

func (s *Nettrix) gofishbaseinfoV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishbaseinfoV1Collect(remote, taskConfig, server)
}

func (s *Nettrix) redfishCpuV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishCpuV1Collect(c)
}

func (s *Nettrix) redfishMEMV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishMEMV1Collect(c)
}

func (s *Nettrix) redfishBaseInfoV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBaseInfoV1Collect(c)
}

func (s *Nettrix) redfishVersionV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishVersionV1Collect(c)
}

func (s *Nettrix) redfishBMCV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishBMCV1Collect(c)
}

func (s *Nettrix) gofishBMCV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishBMCV1Collect(remote, taskConfig, server)
}
func (s *Nettrix) redfishPowerV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerV1Collect(c)
}

func (s *Nettrix) gofishPowerControlV1Collect(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, server *mygofish.HardCollect) (result *clitask.Table, err error) {
	return RedfishBase.GofishPowerControlV1Collect(remote, taskConfig, server)
}
func (s *Nettrix) redfishPowerControlV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishPowerControlV1Collect(c)
}
func (s *Nettrix) redfishDiskV1Collect(c *v2.Client) (result *clitask.Table, err error) {
	return RedfishBase.RedfishDiskV1Collect(c)
}

func (s *Nettrix) Process(remote *structs.L2DeviceRemoteInfo, taskConfig structs.L2NodemapTaskConfigInterface, options ...interface{}) (result *clitask.Table, err error) {
	switch strings.ToUpper(taskConfig.GetMethod()) {
	case "NETTRIX_GOFISH_CPUV1":
		fmt.Println("=======5555")
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishcpuV1Collect(remote, taskConfig, server)

		fmt.Println("===this is from nettrix cpu v1: ", remote)
	case "NETTRIX_REDFISH_CPUV1":
		fmt.Println("4444")
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishCpuV1Collect(client)
			fmt.Println("===eerr", err)
		}
		fmt.Println("this is from nettrix cpu v2: ", remote)
	case "NETTRIX_GOFISH_MEMV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishmemV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from nettrix gofish mem v1: ", remote)
	case "NETTRIX_REDFISH_MEMV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishMEMV1Collect(client)
		} else {
			fmt.Println("======mem err", err)
		}
		fmt.Println("===this is from nettrix redfish mem v1: ", remote)
	case "NETTRIX_GOFISH_DISKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishdiskV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from nettrix gofish disk v1: ", remote)
	case "NETTRIX_REDFISH_DISKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishDiskV1Collect(client)
		} else {
			fmt.Println("====client err", err)
		}
		fmt.Println("===this is from nettrix redfish disk v1: ", remote)
	case "NETTRIX_GOFISH_BASEINFOV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishbaseinfoV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from nettrix gofish baseinfo v1: ", remote)
	case "NETTRIX_REDFISH_BASEINFOV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBaseInfoV1Collect(client)
		}
		fmt.Println("===this is from nettrixl redfish baseinfo v1: ", remote)
	case "NETTRIX_GOFISH_NETWORKV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from nettrix gofish network v1: ", remote)
	case "NETTRIX_REDFISH_NETWORKV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetWorkV1Collect(client)
		} else {
			fmt.Println("===err", err2)
		}
		fmt.Println("===this is from nettrix redfish network v1: ", remote)
	case "NETTRIX_GOFISH_REDFISHVERSIONV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishRedfishVersionV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from nettrix gofish version v1: ", remote)
	case "NETTRIX_REDFISH_REDFISHVERSIONV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishVersionV1Collect(client)
		}
		fmt.Println("===this is from nettrix redfish version v1: ", remote)
	case "NETTRIX_GOFISH_POWERV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from nettrix gofish power v1: ", remote)
	case "NETTRIX_REDFISH_POWERV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerV1Collect(client)
		}
		fmt.Println("===this is from nettrix redfish power v1: ", remote)
	case "NETTRIX_GOFISH_POWERCONTROLV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishPowerControlV1Collect(remote, taskConfig, server)
	case "NETTRIX_REDFISH_POWERCONTROLV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishPowerControlV1Collect(client)
		}
	case "NETTRIX_GOFISH_INTERFACEV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishNetworkInterfaceV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from nettrix gofish networkinterface v1: ", remote)
	case "NETTRIX_REDFISH_INTERFACEV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishNetworkV1Collect(client)
		} else {
			fmt.Println("====dddd", err2)
		}
		fmt.Println("===this is from nettrix redfish interface v1: ", remote)
	case "NETTRIX_GOFISH_BMCV1":
		server := s.GofishClient(remote)
		defer server.OutC.Logout()
		result, err = s.gofishBMCV1Collect(remote, taskConfig, server)
		fmt.Println("===this is from nettrix gofish bmc v1: ", remote)
	case "NETTRIX_REDFISH_BMCV1":
		client, err2 := s.RedfishClient(remote)
		if err2 == nil {
			result, err = s.redfishBMCV1Collect(client)
		}
		fmt.Println("===this is from nettrix redfish bmc v1: ", remote)
	}
	if taskConfig.IsPretty() && result != nil && err == nil {
		result.Pretty()
	}

	return
}
