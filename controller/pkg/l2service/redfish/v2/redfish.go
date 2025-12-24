package v2

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/netxops/log"
	"github.com/netxops/utils/action_id"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	logger *log.Logger
)

const (
	oid = "@odata\\.id"
)

// Client internal use
type Client struct {
	Auth     *auth
	Config   *Config
	RootPath *rootPath
	RawData  rawData
	Req      *req.Client
}

// Config instance required
type Config struct {
	Host      string
	Username  string
	Password  string
	BasicAuth bool
	Insecure  bool
	SkipAuth  bool
	ActionID  action_id.ActionID
}

// auth has resp token and session info
type auth struct {
	Token   string
	Session string
}

// authPayload create session payload
type authPayload struct {
	UserName string `json:"UserName"`
	Password string `json:"Password"`
}

// rootPath redfish root service path
type rootPath struct {
	Chassis  string
	Managers string
	Systems  string
	Sessions string
}

// rawData redfish raw response json
type rawData struct {
	Root    gjson.Result
	Systems gjson.Result
	Manager gjson.Result
	Chassis gjson.Result
}

// RackInfo detailed info
type RackInfo struct {
	SKU             string
	PartNumber      string
	SerialNumber    string
	Model           string
	ChassisType     string
	Manufacturer    string
	TotalMemoryGiB  uint64
	PowerState      string
	Processor       []Processor
	Memory          []Memory
	Disk            []Disk
	PowerSupplies   []PowerSupplies
	NIC             []Nic
	FirmwareVersion FirmwareVersion
	ManagerNic      ManagerNic
}

// FirmwareVersion hardware firmware version
type FirmwareVersion struct {
	Bios          string
	BMC           string
	Redfish       string
	PowerSupplies []string
}

// Processor cpu info
type Processor struct {
	Name         string
	Model        string
	Arch         string
	Socket       string
	TotalCores   uint64
	MaxSpeedMHz  uint64
	TotalThreads uint64
	Manufacturer string
}

// Memory device mem info
type Memory struct {
	SizeGiB           uint64
	Name              string
	Manufacturer      string
	MemoryDeviceType  string
	PartNumber        string
	SerialNumber      string
	OperatingSpeedMhz uint64
}

// Disk physical drive info
type Disk struct {
	SerialNumber  string
	Name          string
	MediaType     string
	PartNumber    string
	Model         string
	Protocol      string
	CapacityGB    uint64
	Manufacturer  string
	HDDSpeedRPM   uint64
	LinkSpeedGbps uint64
}

// PowerSupplies power supplies info
type PowerSupplies struct {
	MemberId           string
	Name               string
	Model              string
	SerialNumber       string
	Manufacturer       string
	LineInputVoltage   string
	PowerCapacityWatts string
	PowerSupplyType    string
}

// Nic network adapter info
type Nic struct {
	ID              string
	Name            string
	Model           string
	Manufacturer    string
	SerialNumber    string
	PartNumber      string
	FirmwareVersion string
	Port            []NicPort
}

// NicPort network adapter port info
type NicPort struct {
	Name          string
	LinkStatus    string
	LinkSpeedMbps uint64
	MacAddress    string
}

// ManagerNic bmc interface info
type ManagerNic struct {
	HostName   string
	MACAddress string
	SpeedMbps  uint64
	IPv4       Address
}

// Address abstract
type Address struct {
	Address    string
	Origin     string
	Gateway    string
	SubnetMask string
}

// Connect create and return client instance
func Connect(config *Config) (*Client, error) {
	// init logger
	logger = log.NewLogger(config.ActionID, true)
	// create client
	c := &Client{
		Config: config,
	}
	logger.Info("Redfish.Connect", zap.String("action", fmt.Sprintf("init connect for target %s", c.Config.Host)))
	// parse redfish root path
	if err := getRootService(c); err != nil {
		logger.Error("Redfish.GetRootService", zap.Error(err))
		return nil, err
	}
	if !c.Config.SkipAuth {
		// create session and token
		if err := createSession(c); err != nil {
			logger.Error("Redfish.CreateSession", zap.Error(err))
			return nil, err
		}
	}
	// collect basic info
	if err := collect(c); err != nil {
		logger.Error("Redfish.Collect", zap.Error(err))
		return nil, err
	}
	return c, nil
}

// request custom req func
func request(c *Client, method, endpoint string, payload any) (resp *req.Response, err error) {
	reqUrl := c.Config.Host + endpoint

	if !strings.HasPrefix(reqUrl, "http") {
		return nil, errors.New("url must starts with http or https")
	}

	// once create
	if c.Req == nil {
		c.Req = req.C().SetTLSHandshakeTimeout(time.Duration(10) * time.Second)
		transport := c.Req.GetTransport()
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: c.Config.Insecure,
		}
	}

	headers := map[string]string{
		"User-Agent":   "redfish/1.0",
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	if c.Auth != nil {
		if c.Auth.Token != "" {
			headers["X-Auth-Token"] = c.Auth.Token
			headers["Cookie"] = fmt.Sprintf("sessionKey=%s", c.Auth.Token)
		} else if c.Config.BasicAuth && c.Config.Username != "" && c.Config.Password != "" {
			encodedAuth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", c.Config.Username, c.Config.Password)))
			headers["Authorization"] = fmt.Sprintf("Basic %v", encodedAuth)
		}
	}

	r := c.Req.R().SetHeaders(headers)

	switch method {
	case http.MethodGet:
		resp, err = r.Get(reqUrl)
	case http.MethodPost:
		if payload != nil {
			r.SetBody(payload)
		}
		resp, err = r.Post(reqUrl)
	case http.MethodDelete:
		resp, err = r.Delete(reqUrl)
	}

	if resp == nil {
		err = errors.New("redfish resp is null")
		return
	}

	if resp.Response != nil &&
		resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusCreated &&
		resp.StatusCode != http.StatusAccepted &&
		resp.StatusCode != http.StatusNoContent {
		err = fmt.Errorf("%d %s", resp.StatusCode, resp.String())
	}

	return
}

// Get request for get
func (c *Client) Get(endpoint string) (*req.Response, error) {
	return request(c, http.MethodGet, endpoint, nil)
}

// Post request for post
func (c *Client) Post(endpoint string, payload any) (*req.Response, error) {
	return request(c, http.MethodPost, endpoint, payload)
}

// Delete request for delete
func (c *Client) Delete(endpoint string) (*req.Response, error) {
	return request(c, http.MethodDelete, endpoint, nil)
}

// GetJSON parse raw resp to json result
func (c *Client) GetJSON(endpoint string) (result gjson.Result) {
	if resp, err := c.Get(endpoint); err == nil {
		raw := resp.String()
		if gjson.Valid(raw) {
			result = gjson.Parse(raw)
		}
	}
	return
}

// getRootService parse redfish root path
func getRootService(c *Client) error {
	logger.Info("Redfish.GetRootService", zap.String("action", "parse redfish service root"))
	resp, err := c.Get("/redfish/v1")
	if err != nil {
		return err
	}
	if !gjson.Valid(resp.String()) {
		return errors.New("redfish root service resp invalid")
	}
	data := gjson.Parse(resp.String())
	c.RawData.Root = data
	c.RootPath = &rootPath{
		Chassis:  data.Get("Chassis.*").String(),
		Systems:  data.Get("Systems.*").String(),
		Managers: data.Get("Managers.*").String(),
		Sessions: data.Get("?inks.Sessions.*").String(),
	}
	return nil
}

// createSession login and create session
func createSession(c *Client) error {
	logger.Info("Redfish.CreateSession", zap.String("action", fmt.Sprintf("creating session for %s", c.Config.Host)))

	// if basic auth, do not handle
	if c.Config.BasicAuth {
		logger.Info("Redfish.CreateSession", zap.String("action", "using basic auth"))
		return nil
	}

	if c.Config.Username == "" || c.Config.Password == "" {
		return errors.New("invalid username or password")
	}

	resp, err := c.Post(
		c.RootPath.Sessions,
		&authPayload{
			UserName: c.Config.Username,
			Password: c.Config.Password,
		},
	)
	if err != nil {
		return err
	}

	c.Auth = &auth{
		Token:   resp.Header.Get("X-Auth-Token"),
		Session: resp.Header.Get("Location"),
	}
	if urlParser, err := url.ParseRequestURI(c.Auth.Session); err == nil {
		c.Auth.Session = urlParser.RequestURI()
	}

	if c.Auth.Token == "" || c.Auth.Session == "" {
		return errors.New("session create failed")
	}

	return nil
}

// Logout destroy session
func (c *Client) Logout() {
	if c.Config.SkipAuth {
		return
	}
	if c.Auth.Token != "" && c.Auth.Session != "" {
		if _, err := c.Delete(c.Auth.Session); err == nil {
			logger.Info("Redfish.Logout", zap.String("action", fmt.Sprintf("destroy session for %s", c.Config.Host)))
			return
		}
	}
	logger.Warn("Redfish.Logout", zap.Error(errors.New("session destroy failed")))
}

// collect basic data
func collect(c *Client) error {
	logger.Info("Redfish.Collect", zap.String("action", "start collecting basic data"))
	manager := c.GetJSON(c.RootPath.Managers)
	systems := c.GetJSON(c.RootPath.Systems)
	chassis := c.GetJSON(c.RootPath.Chassis)

	// default members for index zero
	if members := manager.Get("Members").Array(); len(members) > 0 {
		c.RawData.Manager = c.GetJSON(members[0].Get(oid).String())
	}
	if members := systems.Get("Members").Array(); len(members) > 0 {
		c.RawData.Systems = c.GetJSON(members[0].Get(oid).String())
	}
	if members := chassis.Get("Members").Array(); len(members) > 0 {
		c.RawData.Chassis = c.GetJSON(members[0].Get(oid).String())
	}

	// check resp data is valid
	if !gjson.Valid(c.RawData.Root.String()) ||
		!gjson.Valid(c.RawData.Systems.String()) ||
		!gjson.Valid(c.RawData.Manager.String()) ||
		!gjson.Valid(c.RawData.Chassis.String()) {
		return errors.New("basic info collect failed")
	}
	return nil
}

// mbpsToGbps calculation
func mbpsToGbps(v uint64) uint64 {
	return v / 1000
}

// bytesToGib calculation
func bytesToGib(v uint64) uint64 {
	return v / 1024 / 1024 / 1024
}

// mibToGiB calculation
func mibToGiB(v uint64) uint64 {
	return v * 8388608 / 8589934592
}

// sToU64 string convert to uint64
func sToU64(v string) uint64 {
	if v, err := strconv.ParseUint(v, 10, 64); err == nil {
		return v
	}
	return 0
}

// GetProcessors detailed processor info
func (c *Client) GetProcessors() (result []Processor) {
	logger.Info("Redfish.GetProcessors", zap.String("action", "parse device processors data"))
	processorsOID := c.RawData.Systems.Get("Processors").Get(oid)
	// compatible hpe ilo4 some version
	if !processorsOID.Exists() {
		processorsOID = c.RawData.Systems.Get("?inks.Processors.*")
	}
	if !processorsOID.Exists() {
		return
	}
	members := c.GetJSON(processorsOID.String()).Get("Members")
	for _, member := range members.Array() {
		data := c.GetJSON(member.Get(oid).String())
		arch := data.Get("ProcessorArchitecture")
		if arch.IsArray() && len(arch.Array()) > 0 {
			arch = arch.Array()[0].Get("Member")
		}
		result = append(result, Processor{
			Name:         data.Get("Name").String(),
			Model:        data.Get("Model").String(),
			Arch:         arch.String(),
			Socket:       data.Get("Socket").String(),
			TotalCores:   data.Get("TotalCores").Uint(),
			TotalThreads: data.Get("TotalThreads").Uint(),
			MaxSpeedMHz:  data.Get("MaxSpeedMHz").Uint(),
			Manufacturer: data.Get("Manufacturer").String(),
		},
		)
	}
	return
}

// GetRedfishVersion redfish version
func (c *Client) GetRedfishVersion() string {
	logger.Info("Redfish.GetRedfishVersion", zap.String("action", "parse device redfish version"))
	return c.RawData.Root.Get("RedfishVersion").String()
}

// GetSerialNumber device serial number
func (c *Client) GetSerialNumber() string {
	logger.Info("Redfish.GetSerialNumber", zap.String("action", "parse device serial number"))
	return c.RawData.Systems.Get("SerialNumber").String()
}

// GetTotalSystemMemoryGiB total memory size
func (c *Client) GetTotalSystemMemoryGiB() uint64 {
	logger.Info("Redfish.GetTotalSystemMemoryGiB", zap.String("action", "parse device total system memory"))
	if size := c.RawData.Systems.Get("MemorySummary.TotalSystemMemoryGiB"); size.Exists() {
		return size.Uint()
	}
	return 0
}

// GetPhysicalDisk physical disk info
func (c *Client) GetPhysicalDisk() (result []Disk) {
	logger.Info("Redfish.GetPhysicalDisk", zap.String("action", "parse device physical disk data"))
	storageOID := c.RawData.Systems.Get("Storage").Get(oid)
	// if Storage field not found, try use SimpleStorage
	if !storageOID.Exists() {
		storageOID = c.RawData.Systems.Get("SimpleStorage").Get(oid)
	}
	// compatible hpe ilo some version
	if !storageOID.Exists() {
		storageOID = c.RawData.Systems.Get("Oem.Hp.?inks.SmartStorage.*")
	}
	// if as before not exist, stop this action
	if !storageOID.Exists() {
		return
	}

	controllers := c.GetJSON(storageOID.String())
	members := controllers.Get("Members").Array()
	// compatible hpe ilo some version
	if len(members) == 0 {
		members = c.GetJSON(controllers.Get("?inks.ArrayControllers.*").String()).Get("Members").Array()
	}

	for _, member := range members {
		drives := c.GetJSON(member.Get(oid).String())
		// Storage filed is Drives, SimpleStorage is Devices
		if v := drives.Get("Drives"); v.Exists() {
			drives = v
		}
		if v := drives.Get("Devices"); v.Exists() {
			drives = v
		}
		if v := drives.Get("?inks.PhysicalDrives.*"); v.Exists() {
			drives = c.GetJSON(v.String()).Get("Members")
		}
		for _, drive := range drives.Array() {
			if v := drive.Get(oid); v.Exists() {
				drive = c.GetJSON(v.String())
			}
			disk := Disk{
				SerialNumber:  drive.Get("SerialNumber").String(),
				Name:          drive.Get("Name").String(),
				MediaType:     drive.Get("MediaType").String(),
				PartNumber:    drive.Get("PartNumber").String(),
				Model:         drive.Get("Model").String(),
				Protocol:      drive.Get("Protocol").String(),
				CapacityGB:    drive.Get("CapacityGB").Uint(),
				Manufacturer:  drive.Get("Manufacturer").String(),
				HDDSpeedRPM:   drive.Get("RotationSpeedRPM").Uint(),
				LinkSpeedGbps: drive.Get("NegotiatedSpeedGbs").Uint(),
			}
			if disk.LinkSpeedGbps == 0 {
				disk.LinkSpeedGbps = mbpsToGbps(drive.Get("InterfaceSpeedMbps").Uint())
			}
			if disk.HDDSpeedRPM == 0 {
				disk.HDDSpeedRPM = drive.Get("RotationalSpeedRpm").Uint()
			}
			if disk.CapacityGB == 0 {
				disk.CapacityGB = bytesToGib(drive.Get("CapacityBytes").Uint())
			}
			if disk.Protocol == "" {
				disk.Protocol = drive.Get("InterfaceType").String()
			}
			if disk.MediaType != "HDD" {
				disk.HDDSpeedRPM = 0
			}
			if disk.LinkSpeedGbps == 0 {
				disk.LinkSpeedGbps = drive.Get("CapableSpeedGbs").Uint()
			}
			result = append(result, disk)
		}
	}
	return
}

// GetBiosVersion bios firmware version
func (c *Client) GetBiosVersion() string {
	logger.Info("Redfish.GetBiosVersion", zap.String("action", "parse device bios firmware version"))
	if v := c.RawData.Systems.Get("BiosVersion"); v.Exists() {
		return v.String()
	}
	return c.RawData.Systems.Get("BIOSVersion").String()
}

// GetBMCVersion bmc firmware version
func (c *Client) GetBMCVersion() string {
	logger.Info("Redfish.GetBMCVersion", zap.String("action", "parse device bmc firmware version"))
	return c.RawData.Manager.Get("FirmwareVersion").String()
}

// GetPowerSuppliesVersion firmware version
func (c *Client) GetPowerSuppliesVersion() (result []string) {
	logger.Info("Redfish.GetPowerSuppliesVersion", zap.String("action", "parse device power supplies firmware version"))
	powerSupplies := c.RawData.Chassis.Get("Power").Get(oid)
	powers := c.GetJSON(powerSupplies.String()).Get("PowerSupplies")
	for _, power := range powers.Array() {
		result = append(result, power.Get("FirmwareVersion").String())
	}
	return
}

// GetDeviceManufacturer rack server device manufacturer
func (c *Client) GetDeviceManufacturer() string {
	logger.Info("Redfish.GetDeviceManufacturer", zap.String("action", "parse device manufacturer info"))
	if v := c.RawData.Systems.Get("Manufacturer"); v.Exists() {
		return v.String()
	}
	return c.RawData.Chassis.Get("Manufacturer").String()
}

// GetChassisType rack server chassis type
func (c *Client) GetChassisType() string {
	logger.Info("Redfish.GetChassisType", zap.String("action", "parse device chassis type"))
	return c.RawData.Chassis.Get("ChassisType").String()
}

// GetDeviceModel rack server device model
func (c *Client) GetDeviceModel() string {
	logger.Info("Redfish.GetDeviceModel", zap.String("action", "parse device model info"))
	if v := c.RawData.Systems.Get("Model"); v.Exists() {
		return v.String()
	}
	return c.RawData.Manager.Get("Model").String()
}

// GetManagerNic manager ethernet interface info
func (c *Client) GetManagerNic() (result ManagerNic) {
	logger.Info("Redfish.GetManagerNic", zap.String("action", "parse device manager ethernet interface info"))
	member := c.RawData.Manager.Get("EthernetInterfaces").Get(oid)
	if !member.Exists() {
		return
	}
	// bmc nic member should be one, so always get index for 0
	nicOID := c.GetJSON(member.String()).Get("Members.0").Get(oid)
	if !nicOID.Exists() {
		return
	}
	data := c.GetJSON(nicOID.String())

	hostname := data.Get("HostName").String()
	if hostname == "" {
		hostname = c.RawData.Systems.Get("HostName").String()
	}

	return ManagerNic{
		HostName:   hostname,
		MACAddress: data.Get("MACAddress").String(),
		SpeedMbps:  data.Get("SpeedMbps").Uint(),
		IPv4: Address{
			Address:    data.Get("IPv4Addresses.0.Address").String(),
			Gateway:    data.Get("IPv4Addresses.0.Gateway").String(),
			Origin:     data.Get("IPv4Addresses.0.AddressOrigin").String(),
			SubnetMask: data.Get("IPv4Addresses.0.SubnetMask").String(),
		},
	}
}

// GetMemory memory info
func (c *Client) GetMemory() (result []Memory) {
	logger.Info("Redfish.GetMemory", zap.String("action", "parse device memory data"))
	memoryOID := c.RawData.Systems.Get("Memory").Get(oid)
	if !memoryOID.Exists() {
		memoryOID = c.RawData.Systems.Get("Oem.Hp.?inks.Memory.*")
	}
	if !memoryOID.Exists() {
		return
	}
	members := c.GetJSON(memoryOID.String()).Get("Members")
	for _, member := range members.Array() {
		data := c.GetJSON(member.Get(oid).String())

		speed := data.Get("OperatingSpeedMhz").String()
		if speed == "" {
			speed = data.Get("OperatingSpeedMHz").String()
		}
		if strings.HasSuffix(speed, "MT/s") {
			speed = strings.ReplaceAll(speed, "MT/s", "")
		}
		memory := Memory{
			Name:              data.Get("Name").String(),
			SizeGiB:           mibToGiB(data.Get("CapacityMiB").Uint()),
			Manufacturer:      data.Get("Manufacturer").String(),
			MemoryDeviceType:  data.Get("MemoryDeviceType").String(),
			PartNumber:        data.Get("PartNumber").String(),
			SerialNumber:      data.Get("SerialNumber").String(),
			OperatingSpeedMhz: sToU64(speed),
		}
		if memory.SizeGiB == 0 {
			memory.SizeGiB = mibToGiB(data.Get("SizeMB").Uint())
		}
		if memory.MemoryDeviceType == "" {
			memory.MemoryDeviceType = data.Get("DIMMType").String()
		}
		if memory.OperatingSpeedMhz == 0 {
			memory.OperatingSpeedMhz = data.Get("MaximumFrequencyMHz").Uint()
		}
		if memory.SizeGiB > 0 {
			result = append(result, memory)
		}
	}
	return
}

// GetGPU gpu info
func (c *Client) GetGPU() (result []Memory) {
	logger.Info("Redfish.GetGPU", zap.String("action", "parse device gpu data"))
	gpuOID := c.RawData.Systems.Get("PCIeDevices").Array()
	for _, v := range gpuOID {
		data := c.GetJSON(v.Get(oid).String())
		pcieOid := data.Get("PCIeFunctions").Get(oid)
		fmt.Println("////", c.GetJSON(pcieOid.String()))
	}
	// if !gpuOID.Exists() {
	// 	return
	// }
	// members := c.GetJSON(gpuOID.String()).Get("Members")
	// for _, member := range members.Array() {
	// 	data := c.GetJSON(member.Get(oid).String())
	//
	// 	speed := data.Get("OperatingSpeedMhz").String()
	// 	if speed == "" {
	// 		speed = data.Get("OperatingSpeedMHz").String()
	// 	}
	// 	if strings.HasSuffix(speed, "MT/s") {
	// 		speed = strings.ReplaceAll(speed, "MT/s", "")
	// 	}
	// 	memory := Memory{
	// 		Name:              data.Get("Name").String(),
	// 		SizeGiB:           mibToGiB(data.Get("CapacityMiB").Uint()),
	// 		Manufacturer:      data.Get("Manufacturer").String(),
	// 		MemoryDeviceType:  data.Get("MemoryDeviceType").String(),
	// 		PartNumber:        data.Get("PartNumber").String(),
	// 		SerialNumber:      data.Get("SerialNumber").String(),
	// 		OperatingSpeedMhz: sToU64(speed),
	// 	}
	// 	if memory.SizeGiB == 0 {
	// 		memory.SizeGiB = mibToGiB(data.Get("SizeMB").Uint())
	// 	}
	// 	if memory.MemoryDeviceType == "" {
	// 		memory.MemoryDeviceType = data.Get("DIMMType").String()
	// 	}
	// 	if memory.OperatingSpeedMhz == 0 {
	// 		memory.OperatingSpeedMhz = data.Get("MaximumFrequencyMHz").Uint()
	// 	}
	// 	if memory.SizeGiB > 0 {
	// 		result = append(result, memory)
	// 	}
	// }
	return
}

// GetPowerState get device power state
func (c *Client) GetPowerState() string {
	logger.Info("Redfish.GetPowerState", zap.String("action", "parse device power state"))
	return c.RawData.Chassis.Get("PowerState").String()
}

// GetPowerSupplies device power supplies info
func (c *Client) GetPowerSupplies() (result []PowerSupplies) {
	logger.Info("Redfish.GetPowerSupplies", zap.String("action", "parse device power supplies info"))
	powerOID := c.RawData.Chassis.Get("Power").Get(oid)
	powers := c.GetJSON(powerOID.String()).Get("PowerSupplies")
	for _, data := range powers.Array() {
		power := PowerSupplies{
			MemberId:           data.Get("MemberId").String(),
			Name:               data.Get("Name").String(),
			Model:              data.Get("Model").String(),
			Manufacturer:       data.Get("Manufacturer").String(),
			LineInputVoltage:   data.Get("LineInputVoltage").String(),
			PowerCapacityWatts: data.Get("PowerCapacityWatts").String(),
			SerialNumber:       data.Get("SerialNumber").String(),
			PowerSupplyType:    data.Get("PowerSupplyType").String(),
		}
		if power.Model != "" {
			result = append(result, power)
		}
	}
	return
}

// GetNetworkAdapters device nic info
func (c *Client) GetNetworkAdapters() (result []Nic) {
	logger.Info("Redfish.GetNetworkAdapters", zap.String("action", "parse device network adapters"))
	nicOID := c.RawData.Chassis.Get("NetworkAdapters").Get(oid)
	if !nicOID.Exists() {
		nicOID = c.RawData.Systems.Get("Oem.Hp.?inks.NetworkAdapters").Get(oid)
	}
	members := c.GetJSON(nicOID.String()).Get("Members")
	for _, member := range members.Array() {
		data := c.GetJSON(member.Get(oid).String())
		nic := Nic{
			ID:              data.Get("Id").String(),
			Name:            data.Get("Name").String(),
			Model:           data.Get("Model").String(),
			Manufacturer:    data.Get("Manufacturer").String(),
			FirmwareVersion: data.Get("Controllers.0.FirmwarePackageVersion").String(),
			SerialNumber:    data.Get("SerialNumber").String(),
			PartNumber:      data.Get("PartNumber").String(),
		}
		adapterPorts := data.Get("Controllers.0.?inks.NetworkPorts")
		if !adapterPorts.Exists() {
			adapterPorts = data.Get("PhysicalPorts")
		}
		for _, adapterPort := range adapterPorts.Array() {
			data := c.GetJSON(adapterPort.Get(oid).String())
			if !data.Exists() {
				data = gjson.Parse(adapterPort.String())
			}
			nicPort := NicPort{
				Name:          data.Get("Name").String(),
				LinkStatus:    data.Get("LinkStatus").String(),
				MacAddress:    data.Get("AssociatedNetworkAddresses.0").String(),
				LinkSpeedMbps: data.Get("CurrentLinkSpeedMbps").Uint(),
			}
			if nicPort.MacAddress == "" {
				nicPort.MacAddress = data.Get("MacAddress").String()
			}
			if nicPort.LinkSpeedMbps == 0 {
				nicPort.LinkSpeedMbps = data.Get("SpeedMbps").Uint()
			}
			nic.Port = append(nic.Port, nicPort)
		}
		result = append(result, nic)
	}
	a, _ := json.Marshal(result)
	fmt.Println("////", string(a))
	return
}

// GetSKU get device sku tag
func (c *Client) GetSKU() string {
	logger.Info("Redfish.GetSKU", zap.String("action", "parse device sku"))
	return c.RawData.Systems.Get("SKU").String()
}

// GetPartNumber get device part number tag
func (c *Client) GetPartNumber() string {
	logger.Info("Redfish.GetPartNumber", zap.String("action", "parse device part number"))
	return c.RawData.Systems.Get("PartNumber").String()
}

// FetchAll fetch device all data
func (c *Client) FetchAll() RackInfo {
	defer c.Logout()
	c.GetNetworkAdapters()
	return RackInfo{
		SKU:            c.GetSKU(),
		PartNumber:     c.GetPartNumber(),
		SerialNumber:   c.GetSerialNumber(),
		PowerState:     c.GetPowerState(),
		Model:          c.GetDeviceModel(),
		ChassisType:    c.GetChassisType(),
		Manufacturer:   c.GetDeviceManufacturer(),
		TotalMemoryGiB: c.GetTotalSystemMemoryGiB(),
		Processor:      c.GetProcessors(),
		Disk:           c.GetPhysicalDisk(),
		Memory:         c.GetMemory(),
		PowerSupplies:  c.GetPowerSupplies(),
		NIC:            c.GetNetworkAdapters(),
		FirmwareVersion: FirmwareVersion{
			BMC:           c.GetBMCVersion(),
			Bios:          c.GetBiosVersion(),
			Redfish:       c.GetRedfishVersion(),
			PowerSupplies: c.GetPowerSuppliesVersion(),
		},
		ManagerNic: c.GetManagerNic(),
	}
}
