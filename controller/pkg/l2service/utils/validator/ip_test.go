package validator

import (
	"fmt"
	"testing"
)

var ipv4TestList = []map[string]interface{}{
	{
		"ip":         "192.168.1.0/24",
		"withPrefix": true,
		"want":       true,
	},
	{
		"ip":         "192.168.1.0",
		"withPrefix": true,
		"want":       false,
	},
	{
		"ip":         "192.168.1.0/0",
		"withPrefix": true,
		"want":       true,
	},
	{
		"ip":         "192.168.1.0/-1",
		"withPrefix": true,
		"want":       false,
	},
	{
		"ip":         "192.168.1.0/33",
		"withPrefix": true,
		"want":       false,
	},
	{
		"ip":         "192.168.1.0/32",
		"withPrefix": true,
		"want":       true,
	},
	{
		"ip":         "192.168.1.0/128",
		"withPrefix": true,
		"want":       false,
	},
	{
		"ip":         "192.168.1.0",
		"withPrefix": true,
		"want":       false,
	},
	{
		"ip":         "192.168.2.0",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "192.168.2.255",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "192.168.2.256",
		"withPrefix": false,
		"want":       false,
	},
	{
		"ip":         "0.168.2.255",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "256.168.2.255",
		"withPrefix": false,
		"want":       false,
	},
	{
		"ip":         "0.0.0.0",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "0..0.0",
		"withPrefix": false,
		"want":       false,
	},
}

func TestIpv4(t *testing.T) {
	for _, data := range ipv4TestList {
		result := Ipv4Validator{}.Validate(data)
		if result.Status() != data["want"] {
			t.Errorf("Test %+v, got = %+v, want = %+v", data, result.Status(), data["want"])
			fmt.Println(result.Msg())
		}
	}

}

var ipv6TestList = []map[string]interface{}{
	{
		"ip":         "::192.168.1.0",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "::192:168:1:0",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "::255.255.255.255",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "2001::255:255:255:255",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "Z200::255:255:255:255",
		"withPrefix": false,
		"want":       false,
	},
	{
		"ip":         "2001::255::255:255:255",
		"withPrefix": false,
		"want":       false,
	},
	{
		"ip":         "2001::255.255:255:255",
		"withPrefix": false,
		"want":       false,
	},
	{
		"ip":         "2001::1:1:255:255",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "2001::13456:1:255:255",
		"withPrefix": false,
		"want":       false,
	},
	{
		"ip":         "1:2:3:4:5:6:7:8",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "::",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "1::",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "1::1",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "1::1:2",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "1::1:2:3",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "::2:3:4:5:6:7:8",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "2001:db8:3:4::192.0.2.33",
		"withPrefix": false,
		"want":       true,
	},
	{
		"ip":         "fe80::7:8%eth0 ",
		"withPrefix": false,
		"want":       false,
	},
}

func TestIpv6(t *testing.T) {
	for _, data := range ipv6TestList {
		result := Ipv6Validator{}.Validate(data)
		if result.Status() != data["want"] {
			t.Errorf("Test %+v, got = %+v, want = %+v", data, result.Status(), data["want"])
			fmt.Println(result.Msg())
		}
	}

}
