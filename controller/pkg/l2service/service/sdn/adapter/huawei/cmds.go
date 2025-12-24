package huawei

func GetNumberByInterface(port string) (portNumber string) {
	return
}

func getAccessPushCmd(port, vlan, description string) (cmd []string) {
	cmd = append(cmd, "interface "+port,
		"description "+description,
		"switchport",
		"switchport mode access",
		"switchport access vlan "+vlan,
		"spanning-tree port type edge",
		"storm-control broadcast level 1",
		"vpc orphan-port suspend",
		"no cdp enable",
		"no shutdown")
	return
}

func getTrunkPushCmd(port, description string) (cmd []string) {
	cmd = append(cmd, "interface "+port,
		"description "+description,
		"switchport",
		"switchport mode trunk",
		"switch trunk allowed vlan 2-4094",
		"spanning-tree port type edge trunk",
		"storm-control broadcast level 1",
		"vpc orphan-port suspend",
		"no cdp enable",
		"no shutdown")
	return
}

func getSdnEthTrunkCmd(port, ethInterface string) (cmd []string) {
	portNumber := GetNumberByInterface(ethInterface)
	cmd = append(cmd,
		"inter "+port,
		"undo shut",
		"undo stp edged-port",
		"eth-trunk "+portNumber,
		"interface "+ethInterface,
		"undo shut",
		"commit")
	return
}

func getJyEthTrunkTrunkCmd(port, EthInterface string) (cmd []string) {
	portNumber := GetNumberByInterface(EthInterface)
	cmd = append(cmd,
		"interface "+port,
		"channel-group "+portNumber+" mode active",
		"no shutdown",
		"interface port-channel"+portNumber,
		"switchport",
		"switchport mode trunk",
		"spanning-tree port type edge trunk",
		"switchport trunk allowed vlan 2-4094",
		"vpc "+portNumber,
		"vpc orphan-port suspend",
		"storm-control broadcast level 1.00")
	return
}

func getJyEthTrunkAccessCmd(port, EthInterface, vlan string) (cmd []string) {
	portNumber := GetNumberByInterface(EthInterface)
	cmd = append(cmd,
		"interface "+port,
		"channel-group "+portNumber+" mode active",
		"no shutdown",
		"interface port-channel"+portNumber,
		"switchport",
		"switchport mode access",
		"switchport access vlan "+vlan,
		"spanning-tree port type edge vpc "+portNumber,
		"vpc "+portNumber,
		"vpc orphan-port suspend",
		"storm-control broadcast level 1.00")
	return
}

func getDefaultSdnEthTrunk(port, EthInterface string) (cmd []string) {
	portNumber := GetNumberByInterface(EthInterface)
	cmd = append(cmd,
		"inter "+port,
		"shut",
		"undo eth-trunk",
		"commit",
		"stp edged-port enable",
		"commit",
		"interaface eth-trunk "+portNumber,
		"shut",
	)
	return
}

func getDefaultJyEthTrunk(port, EthInterface string) (cmd []string) {
	portNumber := GetNumberByInterface(EthInterface)
	cmd = append(cmd,
		"no interface port-channel "+portNumber)
	return
}
