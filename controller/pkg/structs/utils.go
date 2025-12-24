package structs

func ToDeviceIDList(devList []DeviceWithPlatform2) []string {
	var idList []string
	for _, dev := range devList {
		idList = append(idList, dev.DeviceID())
	}

	return idList
}
