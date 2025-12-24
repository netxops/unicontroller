package common

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/policy"
)

// MatchConfig 定义匹配配置
type MatchConfig struct {
	MatchThreshold      int   // 匹配阈值，默认为2
	MatchSrc            bool  // 是否匹配源地址
	MatchDst            bool  // 是否匹配目标地址
	MatchService        bool  // 是否匹配服务
	StrictZone          bool  // 是否严格匹配zone（false则允许any匹配任何zone）
	EmptyZoneMatchesAny *bool // 当zone列表为空时，是否匹配任何zone（nil表示未设置，默认为true）
}

// FindPolicyByIntent 通过intent寻找匹配的policy
func FindPolicyByIntent(node firewall.FirewallNode, intent *policy.Intent, fromZone, toZone string, config MatchConfig) []firewall.FirewallPolicy {
	matchedPolicies := []firewall.FirewallPolicy{}

	// 如果没有设置任何匹配项，默认全部匹配
	if !config.MatchSrc && !config.MatchDst && !config.MatchService {
		config.MatchSrc, config.MatchDst, config.MatchService = true, true, true
	}

	// 如果没有设置匹配阈值，默认为2
	if config.MatchThreshold == 0 {
		config.MatchThreshold = 2
	}

	// 确定空zone列表的匹配行为
	// 如果EmptyZoneMatchesAny为nil（未设置），默认使用true（空zone列表匹配任何zone）
	// 如果用户显式设置，则使用设置的值
	emptyZoneMatchesAny := true
	if config.EmptyZoneMatchesAny != nil {
		emptyZoneMatchesAny = *config.EmptyZoneMatchesAny
	} else {
		// 如果未设置，使用默认值true（空zone列表匹配任何zone）
		emptyZoneMatchesAny = true
	}

	// 创建PolicyIterator
	iterator := node.(firewall.IteratorFirewall).PolicyIterator()

	// 使用迭代器遍历策略
	for iterator.HasNext() {
		policy := iterator.Next().(firewall.FirewallPolicy)

		// 检查源和目标zone是否匹配
		if !matchZone(policy.FromZones(), fromZone, config.StrictZone, emptyZoneMatchesAny) || !matchZone(policy.ToZones(), toZone, config.StrictZone, emptyZoneMatchesAny) {
			continue
		}

		// 获取策略的PolicyEntry，如果为nil则跳过
		policyEntry := policy.PolicyEntry()
		if policyEntry == nil {
			continue
		}

		matchCount := 0

		// 检查源地址是否匹配
		if config.MatchSrc && policyEntry.Src() != nil && intent.Src() != nil && policyEntry.Src().Same(intent.Src()) {
			matchCount++
		}

		// 检查目标地址是否匹配
		if config.MatchDst && policyEntry.Dst() != nil && intent.Dst() != nil && policyEntry.Dst().Same(intent.Dst()) {
			matchCount++
		}

		// 检查服务是否匹配
		if config.MatchService && policyEntry.Service() != nil && intent.Service() != nil && policyEntry.Service().Same(intent.Service()) {
			matchCount++
		}

		// 如果匹配数达到阈值，则将该policy添加到结果中
		if matchCount >= config.MatchThreshold {
			matchedPolicies = append(matchedPolicies, policy)
		}
	}

	return matchedPolicies
}

// matchZone 检查给定的zone是否匹配策略的zone列表
func matchZone(policyZones []string, zone string, strictMatch bool, emptyMatchesAny bool) bool {
	// 如果zone列表为空，根据emptyMatchesAny参数决定是否匹配任何zone
	if len(policyZones) == 0 {
		return emptyMatchesAny
	}

	// 遍历zone列表进行匹配
	for _, policyZone := range policyZones {
		if policyZone == zone || (!strictMatch && policyZone == "any") {
			return true
		}
	}
	return false
}
