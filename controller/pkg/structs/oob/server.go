package oob

type Cpu struct {
	Name         string `json:"name"`
	Manufacture  string `json:"manufacture"`
	Model        string `json:"model"`
	TotalThreads string `json:"totalThreads"`
	TotalCores   string `json:"totalCores"`
	Arch         string `json:"arch"`
	Socket       string `json:"socket"`
}

type SNField struct {
	SerialNumber string `json:"serialNumber"`
}

type Mem struct {
	Name              string `json:"name"`
	Manufacture       string `json:"manufacture"`
	PartNumber        string `json:"partNumber"`
	OperatingSpeedMhz string `json:"operatingSpeedMhz"`
	SizeGiB           string `json:"sizeGiB"`
	MemoryDeviceType  string `json:"memoryDeviceType"`
	SerialNumber      string `json:"serialNumber"`
}

type Disk struct {
	Name         string `json:"name"`
	Manufacture  string `json:"manufacture"`
	Model        string `json:"model"`
	PartNumber   string `json:"partNumber"`
	SerialNumber string `json:"serialNumber"`
	Protocol     string `json:"protocol"`
	CapacityGB   string `json:"capacityGB"`
}
type GPU struct {
	Name            string `json:"name"`
	SerialNumber    string `json:"serialNumber"`
	FirmwareVersion string `json:"firmware_version"`
}
type BaseInfo struct {
	HostName     string `json:"hostName"`
	Manufacture  string `json:"manufacture"`
	SKU          string `json:"sku"`
	PartNumber   string `json:"partNumber"`
	SerialNumber string `json:"serialNumber"`
	ModelType    string `json:"modelType"`
}

type Network struct {
	Name         string `json:"name"`
	Manufacture  string `json:"manufacture"`
	Model        string `json:"model"`
	PartNumber   string `json:"partNumber"`
	SerialNumber string `json:"serialNumber"`
}

type RedfishVersion struct {
	RedfishVersion string `json:"redfishVersion"`
}

type Power struct {
	Manufacture        string `json:"manufacture"`
	Model              string `json:"model"`
	PartNumber         string `json:"partNumber"`
	SerialNumber       string `json:"serialNumber"`
	PowerCapacityWatts string `json:"powerCapacityWatts"`
}

type PowerControl struct {
	PowerCapacityWatts string `json:"powerCapacityWatts"`
	PowerConsumedWatts string `json:"powerConsumedWatts"`
}

type NetworkInterface struct {
	InterfaceName string `json:"interfaceName"`
	MacAddress    string `json:"macAddress"`
}

type BMC struct {
	Ipv4Addresses string `json:"ipv4Addresses"`
	IPv6Addresses string `json:"iPv6Addresses"`
	SpeedMbps     string `json:"speedMbps"`
}
