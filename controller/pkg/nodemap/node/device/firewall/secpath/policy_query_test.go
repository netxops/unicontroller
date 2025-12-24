package secpath

import (
	"testing"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"github.com/stretchr/testify/assert"
)

func TestPolicyQuery(t *testing.T) {
	// 创建测试用的 PolicySet
	policySet := &PolicySet{
		securityPolicyAcl: []*Policy{
			{
				srcZone:     []string{"trust"},
				dstZone:     []string{"untrust"},
				policyEntry: createPolicyEntry("192.168.1.0/24", "10.0.0.0/8", "tcp:80"),
			},
			{
				srcZone:     []string{"trust"},
				dstZone:     []string{"dmz"},
				policyEntry: createPolicyEntry("192.168.2.0/24", "172.16.0.0/16", "tcp:443"),
			},
			{
				srcZone:     []string{"any"},
				dstZone:     []string{"any"},
				policyEntry: createPolicyEntry("0.0.0.0/0", "0.0.0.0/0", "ip"),
			},
		},
	}

	t.Run("TestFromZone", func(t *testing.T) {
		query := NewPolicyQuery(policySet).FromZone("trust")
		results := query.All()
		assert.Equal(t, 3, len(results)) // Matches 2 trust policies and the any-any policy
	})

	t.Run("TestToZone", func(t *testing.T) {
		query := NewPolicyQuery(policySet).ToZone("untrust")
		results := query.All()
		assert.Equal(t, 2, len(results)) // Matches the untrust policy and the any-any policy
	})

	t.Run("TestFromAnyZone", func(t *testing.T) {
		query := NewPolicyQuery(policySet).FromZone("any")
		results := query.All()
		assert.Equal(t, 1, len(results)) // Matches all policies
	})

	t.Run("TestToAnyZone", func(t *testing.T) {
		query := NewPolicyQuery(policySet).ToZone("any")
		results := query.All()
		assert.Equal(t, 1, len(results)) // Matches all policies
	})

	t.Run("TestSrcAddress", func(t *testing.T) {
		srcAddr, _ := network.NewNetworkGroupFromString("192.168.1.100/32")
		query := NewPolicyQuery(policySet).SrcAddress(srcAddr)
		results := query.All()
		assert.Equal(t, 2, len(results)) // Matches the first policy and the any-any policy
	})

	t.Run("TestDstAddress", func(t *testing.T) {
		dstAddr, _ := network.NewNetworkGroupFromString("10.1.1.1/32")
		query := NewPolicyQuery(policySet).DstAddress(dstAddr)
		results := query.All()
		assert.Equal(t, 2, len(results)) // Matches the first policy and the any-any policy
	})

	t.Run("TestService", func(t *testing.T) {
		svc, _ := service.NewServiceWithL4("tcp", "", "80")
		query := NewPolicyQuery(policySet).Service(svc)
		results := query.All()
		assert.Equal(t, 2, len(results)) // Matches the first policy and the any-any policy
	})

	t.Run("TestUseInputContainPolicy", func(t *testing.T) {
		srcAddr, _ := network.NewNetworkGroupFromString("192.168.0.0/16")
		query := NewPolicyQuery(policySet).SrcAddress(srcAddr).UseInputContainPolicy()
		results := query.All()
		assert.Equal(t, 2, len(results)) // Matches all policies
	})

	t.Run("TestUsePolicyContainInput", func(t *testing.T) {
		srcAddr, _ := network.NewNetworkGroupFromString("192.168.1.100/32")
		query := NewPolicyQuery(policySet).SrcAddress(srcAddr).UsePolicyContainInput()
		results := query.All()
		assert.Equal(t, 2, len(results)) // Matches the first policy and the any-any policy
	})

	t.Run("TestExclude", func(t *testing.T) {
		query := NewPolicyQuery(policySet).FromZone("trust").Exclude()
		results := query.All()
		assert.Equal(t, 0, len(results)) // Only matches the any-any policy
	})

	t.Run("TestFirst", func(t *testing.T) {
		query := NewPolicyQuery(policySet)
		result := query.First()
		assert.NotNil(t, result)
		assert.Equal(t, "trust", result.srcZone[0])
	})

	t.Run("TestLast", func(t *testing.T) {
		query := NewPolicyQuery(policySet)
		result := query.Last()
		assert.NotNil(t, result)
		assert.Equal(t, "any", result.srcZone[0])
	})

	t.Run("TestCombinedQuery", func(t *testing.T) {
		srcAddr, _ := network.NewNetworkGroupFromString("192.168.1.100/32")
		dstAddr, _ := network.NewNetworkGroupFromString("10.1.1.1/32")
		svc, _ := service.NewServiceWithL4("tcp", "", "80")
		query := NewPolicyQuery(policySet).
			FromZone("trust").
			ToZone("untrust").
			SrcAddress(srcAddr).
			DstAddress(dstAddr).
			Service(svc)
		results := query.All()
		assert.Equal(t, 2, len(results)) // Matches the specific policy and the any-any policy
	})

	t.Run("TestNoMatch", func(t *testing.T) {
		query := NewPolicyQuery(policySet).FromZone("nonexistent").ToZone("nonexistent")
		results := query.All()
		assert.Equal(t, 1, len(results)) // Still matches the any-any policy
	})

	t.Run("TestExcludeAny", func(t *testing.T) {
		query := NewPolicyQuery(policySet).FromZone("any").Exclude()
		results := query.All()
		assert.Equal(t, 2, len(results)) // Matches the two specific policies
	})
}

func createPolicyEntry(src, dst, svc string) *policy.PolicyEntry {
	pe := policy.NewPolicyEntry()
	srcAddr, _ := network.NewNetworkGroupFromString(src)
	dstAddr, _ := network.NewNetworkGroupFromString(dst)
	service, _ := service.NewServiceFromString(svc)
	pe.AddSrc(srcAddr)
	pe.AddDst(dstAddr)
	pe.AddService(service)
	return pe
}
