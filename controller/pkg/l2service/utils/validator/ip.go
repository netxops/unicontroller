package validator

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
)

type Ipv4Validator struct{}
type Ipv6Validator struct{}

func ipValidate(data string, ipv4, withPrefix bool) Result {
	v4_regex := `^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$`
	v4_prefix := `^([0-9]|(1[0-9])|(2[0-9])|(3[0-2]))$`

	v6_prefix := `^([0-9]|([1-9][0-9])|(1[0-1][0-9])|(12[0-8]))$`
	v6_regex := `^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`

	ip := data
	prefix := ""
	if withPrefix {
		ds := strings.Split(data, "/")
		if len(ds) != 2 {
			return NewValidateResult(false, fmt.Sprintf("ip address format error, ip:%s", data))
		}
		ip = ds[0]
		prefix = ds[1]
	}

	regex := ""
	pxRegex := ""
	if ipv4 {
		regex = v4_regex
		pxRegex = v4_prefix
	} else {
		regex = v6_regex
		pxRegex = v6_prefix
	}

	re := regexp.MustCompile(regex)
	if withPrefix == false {
		return NewValidateResult(re.MatchString(ip), "")
	}
	if re.MatchString(ip) == false {
		return NewValidateResult(false, fmt.Sprintf("ip address valide error, ip:%s", data))
	}
	if regexp.MustCompile(pxRegex).MatchString(prefix) {
		return NewValidateResult(true, "")
	} else {
		return NewValidateResult(false, fmt.Sprintf("ip address prefix valide error: ip:%s", data))
	}
}

//

func (v Ipv4Validator) Validate(data map[string]interface{}) Result {
	m := map[string]interface{}{}
	mapstructure.Decode(&data, &m)

	_, ok := m["withPrefix"]
	withPrefix := false
	if ok {
		withPrefix = m["withPrefix"].(bool)
	}

	ip, ok := m["ip"]

	if ok == false {
		return NewValidateResult(false, fmt.Sprintf("ip field is empty, data:%+v", m))
	}

	return ipValidate(ip.(string), true, withPrefix)
}

func (v Ipv6Validator) Validate(data map[string]interface{}) Result {
	m := map[string]interface{}{}
	mapstructure.Decode(&data, &m)

	_, ok := m["withPrefix"]
	withPrefix := false
	if ok {
		withPrefix = m["withPrefix"].(bool)
	}
	ip, ok := m["ip"]

	if ok == false {
		return NewValidateResult(false, fmt.Sprintf("ip field is empty, data:%+v", m))
	}

	prefix := ""
	if withPrefix {
		ds := strings.Split(ip.(string), "/")
		if len(ds) != 2 {
			return NewValidateResult(false, fmt.Sprintf("ip address format error, ip:%s", ip))
		}
		ip = ds[0]
		prefix = ds[1]
	}

	s := net.ParseIP(ip.(string))
	if s == nil {
		return NewValidateResult(false, fmt.Sprintf("ip address format error, ip:%s", m["ip"]))
	}

	if withPrefix {
		p, err := strconv.Atoi(prefix)
		if err != nil {
			return NewValidateResult(false, fmt.Sprintf("ip address format error, ip:%s", m["ip"]))
		}
		if p < 0 || p > 128 {
			return NewValidateResult(false, fmt.Sprintf("ip address format error, ip:%s", m["ip"]))
		}
	}

	return NewValidateResult(true, "")

	// return ipValidate(ip.(string), false, withPrefix)
}

func IsIPv4Address(ip string) bool {
	if strings.Index(ip, ":") > -1 {
		return false
	}

	s := net.ParseIP(ip)
	if s == nil {
		return false
	}

	if strings.Index(ip, ".") > -1 {
		return true
	} else {
		return false
	}
}

func IsIPv6Address(ip string) bool {
	if strings.Index(ip, ":") == -1 {
		return false
	}

	s := net.ParseIP(ip)
	if s == nil {
		return false
	}

	if strings.Index(ip, ":") > -1 {
		return true
	} else {
		return false
	}
}

// } else if validator.IsIPv4AddressWithMask(s) || validator.IsIPv6AddressWithMask(s) {
func IsIPv4AddressWithMask(data string) bool {

	index := strings.Index(data, "/")
	if index == -1 {
		return false
	}

	tokens := strings.Split(data, "/")
	if len(tokens) != 2 {
		return false
	}

	if IsIPv4Address(tokens[0]) == false {
		return false
	}

	if prefix, err := strconv.Atoi(tokens[1]); err == nil {
		if prefix < 0 || prefix > 32 {
			return false
		}
		return true
	}

	if IsIPv4Address(tokens[1]) == false {
		return false
	}

	return true

}

// } else if validator.IsIPv4AddressWithMask(s) || validator.IsIPv6AddressWithMask(s) {

func IsIPv6AddressWithMask(data string) bool {
	index := strings.Index(data, "/")
	if index == -1 {
		return false
	}

	tokens := strings.Split(data, "/")
	if len(tokens) != 2 {
		return false
	}

	if IsIPv6Address(tokens[0]) == false {
		return false
	}

	if prefix, err := strconv.Atoi(tokens[1]); err == nil {
		if prefix < 0 || prefix > 128 {
			return false
		}
		return true
	}

	if IsIPv6Address(tokens[1]) == false {
		return false
	}

	return true

}

func IsIPRange(ip string) bool {
	tokens := strings.Split(ip, "-")
	if len(tokens) != 2 {
		return false
	}

	if (IsIPv4Address(tokens[0]) && IsIPv4Address(tokens[1])) ||
		(IsIPv6Address(tokens[0]) && IsIPv6Address(tokens[1])) {

		ip1 := net.ParseIP(tokens[0])
		ip2 := net.ParseIP(tokens[1])

		if bytes.Compare(ip1, ip2) <= 0 {
			return true
		} else {
			return false
		}
	}

	return false

}

func IsInt(s string) bool {
	m, err := regexp.MatchString(`^(-)?\d+$`, s)
	if err != nil {
		return false
	}
	return m
}

func HasInt(s string) bool {
	m, err := regexp.MatchString(`\d+`, s)
	if err != nil {
		return false
	}
	return m
}
