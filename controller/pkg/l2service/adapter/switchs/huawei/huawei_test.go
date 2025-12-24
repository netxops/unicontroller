package huawei

import (
	"fmt"
	"github.com/netxops/utils/text"
	"testing"
)

var ts = `
Neighbor index                     :1
Chassis type                       :macAddress
Chassis ID                         :a4be-2b7b-3150
Port ID type                       :interfaceName
Port ID                            :XGigabitEthernet4/0/1
Port description                   :XGigabitEthernet4/0/1         
System name                        :baoyang7706                   
System description                 :S7706
Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 (S7700 V200R010C00SPC600)
Copyright (C) 2000-2016 HUAWEI TECH CO., LTD
System capabilities supported      :bridge router
System capabilities enabled        :bridge router
Management address type            :ipv4
Management address                 :192.168.1.2
Expired time                       :92s
`

func TestHuawei(t *testing.T) {
	regexMap := map[string]string{
		// "regex": `\s+Port\sID\s+:(?P<peer_interface>[^\n]+).*?System\sname\s+:(?P<name>[^\n]+).*?Management\saddress\s+:(?P<ip>[^\n]+)`,
		"regex": `Port\sID\s+:(?P<peer_interface>[^\n]+).*?System\sname\s+:(?P<name>[^\n]+).*?Management\saddress\s+(value\s+)?:(?P<ip>[^\n]+)`,
		"name":  "lldp",
		"flags": "s",
		"pcre":  "true",
	}

	lldpRegexResult, err := text.SplitterProcessOneTime(regexMap, ts)
	if err != nil {
		fmt.Println("err", err)
	}
	fmt.Println("///", lldpRegexResult)
}
