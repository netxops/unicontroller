package sangfor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseIPGroupBlock 测试解析网络对象配置块
func TestParseIPGroupBlock(t *testing.T) {
	block := []string{
		`ipgroup "192.168.100.0-24" ipv4`,
		"type ip",
		"importance ordinary",
		"ipentry 192.168.100.0-192.168.100.255",
		"ipentry 172.32.2.0/24",
	}

	result := parseIPGroupBlock(block)
	assert.NotNil(t, result, "应该成功解析网络对象")
	assert.Equal(t, "192.168.100.0-24", result["name"])
	assert.Equal(t, "ipv4", result["addressType"])
	assert.Equal(t, "IP", result["businessType"])

	ipRanges, ok := result["ipRanges"].([]interface{})
	assert.True(t, ok, "ipRanges 应该是数组")
	assert.Greater(t, len(ipRanges), 0, "应该有 IP 范围被解析")

	// 验证第一个 IP 范围（IP 范围格式）
	if len(ipRanges) > 0 {
		ipRange1, ok := ipRanges[0].(map[string]interface{})
		assert.True(t, ok, "第一个 IP 范围应该是 map")
		if ok {
			assert.Equal(t, "192.168.100.0", ipRange1["start"])
			assert.Equal(t, "192.168.100.255", ipRange1["end"])
		}
	}

	// 验证第二个 IP 范围（CIDR 格式）
	if len(ipRanges) > 1 {
		ipRange2, ok := ipRanges[1].(map[string]interface{})
		assert.True(t, ok, "第二个 IP 范围应该是 map")
		if ok {
			assert.Equal(t, "172.32.2.0", ipRange2["start"])
			assert.NotNil(t, ipRange2["bits"], "应该有 bits 字段")
		}
	}
}

// TestParseIPGroupBlock_AddressGroup 测试解析地址组配置块（使用 member）
func TestParseIPGroupBlock_AddressGroup(t *testing.T) {
	block := []string{
		`ipgroup "test_addr_gp" ipv4`,
		"type addrgroup",
		"importance ordinary",
		`member "dest-text-2"`,
		`member "172.32.2.1"`,
		`member "172.32.2.16/28"`,
	}

	result := parseIPGroupBlock(block)
	assert.NotNil(t, result, "应该成功解析地址组")
	assert.Equal(t, "test_addr_gp", result["name"])
	assert.Equal(t, "ipv4", result["addressType"])
	assert.Equal(t, "ADDRGROUP", result["businessType"])

	members, ok := result["member"].([]string)
	assert.True(t, ok, "member 应该是字符串数组")
	assert.Equal(t, 3, len(members), "应该有 3 个成员")
	assert.Contains(t, members, "dest-text-2", "应该包含对象名称")
	assert.Contains(t, members, "172.32.2.1", "应该包含 IP 地址")
	assert.Contains(t, members, "172.32.2.16/28", "应该包含 CIDR")
}

// TestParseServiceBlock 测试解析服务对象配置块
func TestParseServiceBlock(t *testing.T) {
	block := []string{
		`service "http"`,
		"tcp-entry destination-port 80",
	}

	result := parseServiceBlock(block)
	assert.NotNil(t, result, "应该成功解析服务对象")
	assert.Equal(t, "http", result["name"])
	assert.Equal(t, "USRDEF_SERV", result["servType"])

	tcpEntrys, ok := result["tcpEntrys"].([]map[string]interface{})
	assert.True(t, ok, "tcpEntrys 应该是数组")
	assert.Greater(t, len(tcpEntrys), 0, "应该有 TCP 条目被解析")

	if len(tcpEntrys) > 0 {
		tcpEntry := tcpEntrys[0]
		dstPorts, ok := tcpEntry["dstPorts"].([]map[string]interface{})
		assert.True(t, ok, "dstPorts 应该是数组")
		if ok && len(dstPorts) > 0 {
			assert.Equal(t, float64(80), dstPorts[0]["start"])
		}
	}
}

// TestParsePolicyBlock 测试解析策略配置块
func TestParsePolicyBlock(t *testing.T) {
	block := []string{
		`policy "test-policy" bottom`,
		"enable",
		`src-ipgroup "source-3"`,
		`dst-ipgroup "dest-3"`,
		`service "any"`,
		"action permit",
	}

	result := parsePolicyBlock(block)
	assert.NotNil(t, result, "应该成功解析策略")
	assert.Equal(t, "test-policy", result["name"])
	assert.Equal(t, true, result["enable"])
	assert.Equal(t, "ALLOW", result["action"])

	srcAddrs, ok := result["srcAddrs"].(map[string]interface{})
	assert.True(t, ok, "srcAddrs 应该是 map")
	if ok {
		srcIpGroups, ok := srcAddrs["srcIpGroups"].([]interface{})
		assert.True(t, ok, "srcIpGroups 应该是数组")
		if ok && len(srcIpGroups) > 0 {
			assert.Equal(t, "source-3", srcIpGroups[0])
		}
	}

	dstIpGroups, ok := result["dstIpGroups"].([]interface{})
	assert.True(t, ok, "dstIpGroups 应该是数组")
	if ok && len(dstIpGroups) > 0 {
		assert.Equal(t, "dest-3", dstIpGroups[0])
	}

	services, ok := result["services"].([]interface{})
	assert.True(t, ok, "services 应该是数组")
	if ok && len(services) > 0 {
		assert.Equal(t, "any", services[0])
	}
}

// TestParseDNATBlock 测试解析 DNAT 规则配置块
func TestParseDNATBlock(t *testing.T) {
	block := []string{
		`dnat-rule "dest-nat-1" bottom`,
		"enable",
		`src-zone "L3_trust_B"`,
		`src-ipgroup "dest-3"`,
		"dst-ip 172.32.2.108",
		"service ssh",
		"transfer ip 192.168.100.111 port 22",
	}

	result := parseDNATBlock(block)
	assert.NotNil(t, result, "应该成功解析 DNAT 规则")
	assert.Equal(t, "dest-nat-1", result["name"])
	assert.Equal(t, "DNAT", result["natType"])
	assert.Equal(t, true, result["enable"])

	dnat, ok := result["dnat"].(map[string]interface{})
	assert.True(t, ok, "dnat 应该是 map")
	if ok {
		assert.Equal(t, "172.32.2.108", dnat["dstIp"])

		transfer, ok := dnat["transfer"].(map[string]interface{})
		assert.True(t, ok, "transfer 应该是 map")
		if ok {
			assert.Equal(t, "IP", transfer["transferType"])
			assert.Equal(t, "192.168.100.111", transfer["ip"])
			assert.Equal(t, "22", transfer["port"])
		}
	}
}

// TestParseSNATBlock 测试解析 SNAT 规则配置块
func TestParseSNATBlock(t *testing.T) {
	block := []string{
		`snat-rule "nat-text-2" bottom`,
		"enable",
		`src-zone "L3_trust_B"`,
		`src-ipgroup "dest-3"`,
		"dst-zone L3_untrust_A",
		`dst-ipgroup "dest-text-2"`,
		"service any",
		"transfer iprange 192.168.100.101-192.168.100.102 dynamic",
	}

	result := parseSNATBlock(block)
	assert.NotNil(t, result, "应该成功解析 SNAT 规则")
	assert.Equal(t, "nat-text-2", result["name"])
	assert.Equal(t, "SNAT", result["natType"])
	assert.Equal(t, true, result["enable"])

	snat, ok := result["snat"].(map[string]interface{})
	assert.True(t, ok, "snat 应该是 map")
	if ok {
		srcZones, ok := snat["srcZones"].([]string)
		assert.True(t, ok, "srcZones 应该是数组")
		if ok && len(srcZones) > 0 {
			assert.Equal(t, "L3_trust_B", srcZones[0])
		}

		dstZones, ok := snat["dstZones"].([]string)
		assert.True(t, ok, "dstZones 应该是数组")
		if ok && len(dstZones) > 0 {
			assert.Equal(t, "L3_untrust_A", dstZones[0])
		}

		transfer, ok := snat["transfer"].(map[string]interface{})
		assert.True(t, ok, "transfer 应该是 map")
		if ok {
			assert.Equal(t, "IP_RANGE", transfer["transferType"])
			assert.Equal(t, "192.168.100.101", transfer["start"])
			assert.Equal(t, "192.168.100.102", transfer["end"])
			assert.Equal(t, "DYNAMIC", transfer["mode"])
		}
	}
}

// TestParseCLIString 测试完整的 CLI 字符串解析
func TestParseCLIString(t *testing.T) {
	cli := `config
ipgroup "test-network" ipv4
type ip
importance ordinary
ipentry 192.168.1.0/24
end

config
service "test-service"
tcp-entry destination-port 80
end

config
policy "test-policy" bottom
enable
src-ipgroup "test-network"
dst-ipgroup "test-network"
service "test-service"
action permit
end

config
dnat-rule "test-dnat" bottom
enable
dst-ip 192.168.1.100
transfer ip 192.168.1.200
end

config
snat-rule "test-snat" bottom
enable
transfer ipgroup test-network
end

config
ip route 192.168.101.0/24 192.168.100.254 interface eth0 description "test" metric 0 tag 0
end

config
zone "test-zone"
forward-type route
interfaces eth0
end

config
interface eth0
wan disable
no shutdown
ip address 192.168.1.1/24
end
`

	result, err := parseCLIString(cli)
	assert.NoError(t, err, "应该成功解析 CLI 字符串")
	assert.NotNil(t, result, "结果不应该为空")

	// 验证网络对象
	networks, ok := result["NETWORK"].([]interface{})
	assert.True(t, ok, "应该有 NETWORK 键")
	assert.Greater(t, len(networks), 0, "应该有网络对象被解析")

	// 验证服务对象
	services, ok := result["SERVICE"].([]interface{})
	assert.True(t, ok, "应该有 SERVICE 键")
	assert.Greater(t, len(services), 0, "应该有服务对象被解析")

	// 验证策略
	policies, ok := result["SECURITY_POLICY"].([]interface{})
	assert.True(t, ok, "应该有 SECURITY_POLICY 键")
	assert.Greater(t, len(policies), 0, "应该有策略被解析")

	// 验证 NAT 规则
	nats, ok := result["STATIC_NAT"].([]interface{})
	assert.True(t, ok, "应该有 STATIC_NAT 键")
	assert.Greater(t, len(nats), 0, "应该有 NAT 规则被解析")

	// 验证静态路由
	routes, ok := result["STATIC_ROUTE"].([]interface{})
	assert.True(t, ok, "应该有 STATIC_ROUTE 键")
	assert.Greater(t, len(routes), 0, "应该有静态路由被解析")

	// 验证区域
	zones, ok := result["ZONE"].([]interface{})
	assert.True(t, ok, "应该有 ZONE 键")
	assert.Greater(t, len(zones), 0, "应该有区域被解析")

	// 验证接口
	interfaces, ok := result["INTERFACE"].([]interface{})
	assert.True(t, ok, "应该有 INTERFACE 键")
	assert.Greater(t, len(interfaces), 0, "应该有接口被解析")
}

// TestParseIPEntry 测试解析 IP 条目
func TestParseIPEntry(t *testing.T) {
	// 测试 CIDR 格式
	cidrResult := parseIPEntry("192.168.1.0/24")
	assert.NotNil(t, cidrResult)
	assert.Equal(t, "192.168.1.0", cidrResult["start"])
	assert.Equal(t, float64(24), cidrResult["bits"])

	// 测试 IP 范围格式
	rangeResult := parseIPEntry("192.168.1.1-192.168.1.100")
	assert.NotNil(t, rangeResult)
	assert.Equal(t, "192.168.1.1", rangeResult["start"])
	assert.Equal(t, "192.168.1.100", rangeResult["end"])

	// 测试单 IP 格式
	singleResult := parseIPEntry("192.168.1.1")
	assert.NotNil(t, singleResult)
	assert.Equal(t, "192.168.1.1", singleResult["start"])
}

// TestParseTransfer 测试解析 transfer 行
func TestParseTransfer(t *testing.T) {
	// 测试 transfer ip
	ipResult := parseTransfer("transfer ip 192.168.1.100 port 80")
	assert.NotNil(t, ipResult)
	assert.Equal(t, "IP", ipResult["transferType"])
	assert.Equal(t, "192.168.1.100", ipResult["ip"])
	assert.Equal(t, "80", ipResult["port"])

	// 测试 transfer iprange
	rangeResult := parseTransfer("transfer iprange 192.168.1.1-192.168.1.100 dynamic")
	assert.NotNil(t, rangeResult)
	assert.Equal(t, "IP_RANGE", rangeResult["transferType"])
	assert.Equal(t, "192.168.1.1", rangeResult["start"])
	assert.Equal(t, "192.168.1.100", rangeResult["end"])
	assert.Equal(t, "DYNAMIC", rangeResult["mode"])

	// 测试 transfer ipgroup
	groupResult := parseTransfer("transfer ipgroup test-group")
	assert.NotNil(t, groupResult)
	assert.Equal(t, "IPGROUP", groupResult["transferType"])
	assert.Equal(t, "test-group", groupResult["ipgroup"])
}

// TestParseIPRouteBlock 测试解析静态路由配置块
func TestParseIPRouteBlock(t *testing.T) {
	block := []string{
		`ip route 192.168.101.0/24 192.168.100.254 interface eth0 description "meg" metric 0 tag 0`,
	}

	result := parseIPRouteBlock(block)
	assert.NotNil(t, result, "应该成功解析静态路由")
	assert.Equal(t, "192.168.101.0/24", result["prefix"])
	assert.Equal(t, "192.168.100.254", result["gateway"])
	assert.Equal(t, "eth0", result["ifname"])
	assert.Equal(t, "meg", result["description"])
	assert.Equal(t, float64(0), result["metric"])
	assert.Equal(t, float64(0), result["tag"])
}

// TestParseZoneBlock 测试解析区域配置块
func TestParseZoneBlock(t *testing.T) {
	block := []string{
		`zone "L3_manage"`,
		"forward-type route",
		"interfaces eth0",
	}

	result := parseZoneBlock(block)
	assert.NotNil(t, result, "应该成功解析区域配置")
	assert.Equal(t, "L3_manage", result["name"])
	assert.Equal(t, "route", result["type"])

	interfaces, ok := result["interfaces"].([]string)
	assert.True(t, ok, "interfaces 应该是字符串数组")
	if ok && len(interfaces) > 0 {
		assert.Equal(t, "eth0", interfaces[0])
	}
}

// TestParseInterfaceBlock 测试解析接口配置块
func TestParseInterfaceBlock(t *testing.T) {
	block := []string{
		"interface eth0",
		"wan disable",
		"no shutdown",
		"default-gateway 192.168.100.254",
		"reverse-route disable",
		"manage ssh enable",
		"manage ping enable",
		"bandwidth upstream 0",
		"bandwidth downstream 0",
		"ip address 192.168.100.107/24",
	}

	result := parseInterfaceBlock(block)
	assert.NotNil(t, result, "应该成功解析接口配置")
	assert.Equal(t, "eth0", result["name"])
	assert.Equal(t, false, result["wan"])
	assert.Equal(t, false, result["shutdown"])
	assert.Equal(t, "192.168.100.254", result["defaultGateway"])
	assert.Equal(t, false, result["reverseRoute"])

	ipv4, ok := result["ipv4"].(map[string]interface{})
	assert.True(t, ok, "ipv4 应该是 map")
	if ok {
		staticIp, ok := ipv4["staticIp"].([]interface{})
		assert.True(t, ok, "staticIp 应该是数组")
		if ok && len(staticIp) > 0 {
			ipEntry, ok := staticIp[0].(map[string]interface{})
			assert.True(t, ok, "IP 条目应该是 map")
			if ok {
				ipaddress, ok := ipEntry["ipaddress"].(map[string]interface{})
				assert.True(t, ok, "ipaddress 应该是 map")
				if ok {
					assert.Equal(t, "192.168.100.107", ipaddress["start"])
					assert.Equal(t, float64(24), ipaddress["bits"])
				}
			}
		}
	}
}
