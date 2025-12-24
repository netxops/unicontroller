package utils

import (
	"io"
	"net"
	"net/http"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/tidwall/gjson"
)

func GetIPAddress() ([]string, error) {
	address, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var ipv4s []string
	for _, addr := range address {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ipv4s = append(ipv4s, ipNet.IP.String())
			}
		}
	}
	return ipv4s, nil
}

func ParseHost(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return host, nil
}

func GetNatIPFromAPI(api string) string {
	resp, err := http.Get(api)
	if err != nil {
		xlog.Default().Error("failed to request nat address", xlog.FieldErr(err))
		return ""
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		xlog.Default().Error("failed to read response", xlog.FieldErr(err))
		return ""
	}
	return gjson.GetBytes(body, "data").String()
}

// func ParseProxyAddr(addr string) string {
// 	if global.Conf.EnableProxy {
// 		ip, err := ParseHost(addr)
// 		if err != nil {
// 			xlog.Default().Panic("failed parse server ip", xlog.FieldErr(err))
// 		}
// 		proxyAddr := net.JoinHostPort(ip, strconv.Itoa(int(global.Conf.ProxyPort)))
// 		natAddr := GetNatIPFromAPI(global.PlatformInfo.NatAddrUpdateAPI)
// 		if natAddr != "" && net.ParseIP(natAddr) != nil {
// 			return net.JoinHostPort(natAddr, strconv.Itoa(int(global.Conf.ProxyPort)))
// 		}
// 		return proxyAddr
// 	}
// 	return ""
// }
