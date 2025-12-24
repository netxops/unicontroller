package helpers

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
)

// AssertNodeMapEqual 断言两个 NodeMap 相等
func AssertNodeMapEqual(t assert.TestingT, expected, actual *nodemap.NodeMap, msgAndArgs ...interface{}) bool {
	if !assert.Equal(t, expected.Name, actual.Name, "NodeMap name should be equal") {
		return false
	}

	if !assert.Equal(t, len(expected.Nodes), len(actual.Nodes), "NodeMap nodes count should be equal") {
		return false
	}

	if !assert.Equal(t, len(expected.Ports), len(actual.Ports), "NodeMap ports count should be equal") {
		return false
	}

	if !assert.Equal(t, len(expected.Ipv4Areas), len(actual.Ipv4Areas), "NodeMap IPv4Areas count should be equal") {
		return false
	}

	if !assert.Equal(t, len(expected.Ipv6Areas), len(actual.Ipv6Areas), "NodeMap IPv6Areas count should be equal") {
		return false
	}

	return true
}

// AssertPortEqual 断言两个端口相等
func AssertPortEqual(t assert.TestingT, expected, actual api.Port, msgAndArgs ...interface{}) bool {
	if !assert.Equal(t, expected.Name(), actual.Name(), "Port name should be equal") {
		return false
	}

	if !assert.Equal(t, expected.ID(), actual.ID(), "Port ID should be equal") {
		return false
	}

	if !assert.Equal(t, expected.Vrf(), actual.Vrf(), "Port VRF should be equal") {
		return false
	}

	return true
}

// AssertNetworkEqual 断言两个网络相等
func AssertNetworkEqual(t assert.TestingT, expected, actual network.AbbrNet, msgAndArgs ...interface{}) bool {
	if !assert.Equal(t, expected.String(), actual.String(), "Network should be equal") {
		return false
	}
	return true
}

// AssertNetworkListEqual 断言两个网络列表相等
func AssertNetworkListEqual(t assert.TestingT, expected, actual *network.NetworkList, msgAndArgs ...interface{}) bool {
	expectedList := expected.List()
	actualList := actual.List()

	if !assert.Equal(t, len(expectedList), len(actualList), "NetworkList length should be equal") {
		return false
	}

	for i, expectedNet := range expectedList {
		if i >= len(actualList) {
			return assert.Fail(t, fmt.Sprintf("NetworkList index %d out of range", i), msgAndArgs...)
		}
		if !AssertNetworkEqual(t, expectedNet, actualList[i], msgAndArgs...) {
			return false
		}
	}

	return true
}
