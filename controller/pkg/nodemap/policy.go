package nodemap

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/global"
	"go.uber.org/zap"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/flexrange"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
)

type MatchDetail struct {
	Matched      bool
	MatcherType  string
	MatcherValue string

	OverlapDetail float64
	ExtraInfo     map[string]interface{}
	MatchType     MatchType
}

type MatchResult struct {
	Matched        bool
	MatchType      MatchType
	MatchedAddress *network.NetworkGroup
	OverlapDetail  float64
	ExtraInfo      map[string]interface{}
}

type MatchType int

const (
	MatchNone MatchType = iota
	MatchSource
	MatchDestination
	MatchBoth
)

func (mt MatchType) String() string {
	switch mt {
	case MatchNone:
		return "无"
	case MatchSource:
		return "源匹配"
	case MatchDestination:
		return "目标匹配"
	case MatchBoth:
		return "源目匹配"
	default:
		return "未知"
	}
}

type PolicyMatchResult struct {
	Policy         firewall.FirewallPolicy
	MatchDetails   map[string]MatchDetail
	MatchType      MatchType
	MatchedAddress *network.NetworkGroup
	OverallMatch   bool
}

// PolicyMatcher 定义了防火墙策略匹配器的接口
type PolicyMatcher interface {
	Match(policy firewall.FirewallPolicy) MatchResult
}

// 保留现有的 Matcher 实现
type OrMatcher struct {
	Matchers []PolicyMatcher
}

type ActionMatcher struct {
	Action firewall.Action
}

type NameMatcher struct {
	Name string
}

type CliMatcher struct {
	CliPattern string
}

type ServiceMatcher struct {
	Service *service.Service
}

type CompositeMatcher struct {
	Matchers []PolicyMatcher
}

type MatchStrategy int

const (
	// StrategyOverlap 定义重叠匹配策略
	// 当策略地址范围与匹配器地址范围有任何交集时，视为匹配
	StrategyOverlap MatchStrategy = iota

	// StrategyContains 定义包含匹配策略
	// 策略地址范围必须完全包含匹配器地址范围，即匹配器地址范围是策略地址范围的子集
	StrategyContains

	// StrategyContainedBy 定义被包含匹配策略
	// 策略地址范围必须被匹配器地址范围完全包含，即策略地址范围是匹配器地址范围的子集
	StrategyContainedBy

	// StrategyExactMatch 定义精确匹配策略
	// 策略地址范围必须与匹配器地址范围完全相同
	StrategyExactMatch

	// StrategyThreshold 定义阈值匹配策略
	// 重叠部分占策略地址范围的比例必须大于或等于设定的阈值才视为匹配
	StrategyThreshold

	// StrategyOverlapIgnoreAny 定义忽略"Any"地址的重叠匹配策略
	// 检查地址重叠，但忽略策略中源或目的地址为"Any"的情况
	// 用于避免匹配过于宽泛的策略，提高匹配精确度
	StrategyOverlapIgnoreAny

	// StrategyIsolatedInQuery 定义孤立地址在查询范围内匹配策略
	// 遍历策略地址中的每个孤立地址（通过 iterator 遍历时，每个独立的 entry 都是孤立地址）
	// 只要策略中的任意一个孤立地址在查询范围内，就视为匹配
	// 例如：策略包含 [10.1.0.0/25, 10.1.0.222, 10.2.0.0/24, 192.168.1.0/24]
	//      查询 10.1.0.0/24 → 匹配（10.1.0.0/25 和 10.1.0.222 在查询范围内）
	//      查询 10.0.0.0/8 → 匹配（10.1.0.0/25、10.1.0.222 和 10.2.0.0/24 在查询范围内）
	//      查询 192.168.0.0/16 → 匹配（192.168.1.0/24 在查询范围内）
	//      查询 172.16.0.0/16 → 不匹配（所有孤立地址都不在查询范围内）
	StrategyIsolatedInQuery
)

func (ms MatchStrategy) String() string {
	switch ms {
	case StrategyOverlap:
		return "Overlap"
	case StrategyContains:
		return "Contains"
	case StrategyContainedBy:
		return "ContainedBy"
	case StrategyExactMatch:
		return "ExactMatch"
	case StrategyThreshold:
		return "Threshold"
	case StrategyOverlapIgnoreAny:
		return "OverlapIgnoreAny"
	case StrategyIsolatedInQuery:
		return "IsolatedContained" // 孤立地址包含匹配：策略中的孤立地址在查询范围内
	default:
		return "Unknown"
	}
}

type AddressMatcher struct {
	Address   *network.NetworkGroup
	Strategy  MatchStrategy
	Threshold float64
	IsSource  bool
}

// Match 方法实现

func (m OrMatcher) Match(policy firewall.FirewallPolicy) MatchResult {
	for _, matcher := range m.Matchers {
		result := matcher.Match(policy)
		if result.Matched {
			return result
		}
	}
	return MatchResult{Matched: false}
}

func (m ActionMatcher) Match(policy firewall.FirewallPolicy) MatchResult {
	matched := policy.Action() == m.Action
	return MatchResult{
		Matched:   matched,
		MatchType: MatchNone,
		ExtraInfo: map[string]interface{}{
			"PolicyAction": policy.Action(),
		},
	}
}

func (m NameMatcher) Match(policy firewall.FirewallPolicy) MatchResult {
	matched := strings.Contains(policy.Name(), m.Name)
	return MatchResult{
		Matched:   matched,
		MatchType: MatchNone, // 名称匹配不影响 MatchType
		ExtraInfo: map[string]interface{}{
			"PolicyName": policy.Name(),
		},
	}
}

func (m CliMatcher) Match(policy firewall.FirewallPolicy) MatchResult {
	matched := strings.Contains(policy.Cli(), m.CliPattern)
	return MatchResult{
		Matched:   matched,
		MatchType: MatchNone, // CLI 匹配不影响 MatchType
		ExtraInfo: map[string]interface{}{
			"PolicyCli": policy.Cli(),
		},
	}
}

func (m ServiceMatcher) Match(policy firewall.FirewallPolicy) MatchResult {
	matched := policy.PolicyEntry().Service().Match(m.Service)
	return MatchResult{
		Matched:   matched,
		MatchType: MatchBoth, // 服务匹配通常同时影响源和目标
		ExtraInfo: map[string]interface{}{
			"PolicyService":  policy.PolicyEntry().Service().String(),
			"MatcherService": m.Service.String(),
		},
	}
}
func (m CompositeMatcher) Match(policy firewall.FirewallPolicy) MatchResult {
	result := MatchResult{
		Matched:   true,
		MatchType: MatchNone,
		ExtraInfo: make(map[string]interface{}),
	}

	subResults := make(map[string]MatchResult)
	sourceMatched := false
	destMatched := false

	for _, matcher := range m.Matchers {
		subResult := matcher.Match(policy)
		subResults[fmt.Sprintf("%T", matcher)] = subResult

		if !subResult.Matched {
			result.Matched = false
		}

		if subResult.MatchType == MatchSource || subResult.MatchType == MatchBoth {
			sourceMatched = true
		}
		if subResult.MatchType == MatchDestination || subResult.MatchType == MatchBoth {
			destMatched = true
		}

		if subResult.MatchedAddress != nil {
			result.MatchedAddress = subResult.MatchedAddress
		}
	}

	if sourceMatched && destMatched {
		result.MatchType = MatchBoth
	} else if sourceMatched {
		result.MatchType = MatchSource
	} else if destMatched {
		result.MatchType = MatchDestination
	}

	result.ExtraInfo["SubMatchers"] = subResults

	return result
}

func (m AddressMatcher) Match(policy firewall.FirewallPolicy) MatchResult {
	var policyAddr *network.NetworkGroup
	if m.IsSource {
		policyAddr = policy.PolicyEntry().Src()
	} else {
		policyAddr = policy.PolicyEntry().Dst()
	}

	if policyAddr == nil {
		policyAddr = network.NewAny4Group()
	}
	_, mid, right := network.NetworkGroupCmp(*policyAddr, *m.Address)

	matched := false
	var matchedAddress *network.NetworkGroup
	overlapDetail := 0.0

	switch m.Strategy {
	case StrategyOverlap:
		// 策略地址必须与查询地址存在重叠部分
		matched = mid != nil && !mid.IsEmpty()
	case StrategyContains:
		// 策略地址大于等于查询地址
		matched = mid != nil && mid.Same(m.Address)
	case StrategyContainedBy:
		// 策略地址小于等于查询地址
		matched = right == nil && mid != nil && mid.Same(policyAddr)
	case StrategyExactMatch:
		// 策略地址完全等于查询地址
		matched = policyAddr.Same(m.Address)
	case StrategyThreshold:
		if mid != nil && !mid.IsEmpty() {
			overlapSize := float64(mid.IPv4().Count().Int64() + mid.IPv6().Count().Int64())
			policySize := float64(policyAddr.IPv4().Count().Int64() + policyAddr.IPv6().Count().Int64())
			overlapDetail = overlapSize / policySize
			matched = overlapDetail >= m.Threshold
		}
	case StrategyOverlapIgnoreAny:
		// 检查策略地址是否为 "Any"
		if !m.Address.IsAny(true) && policyAddr.IsAny(true) {
			matched = false
		} else {
			matched = mid != nil && !mid.IsEmpty()
		}
		if matched {
			overlapSize := float64(mid.IPv4().Count().Int64() + mid.IPv6().Count().Int64())
			policySize := float64(policyAddr.IPv4().Count().Int64() + policyAddr.IPv6().Count().Int64())
			overlapDetail = overlapSize / policySize
		}
	case StrategyIsolatedInQuery:
		// 孤立地址在查询范围内匹配：遍历策略地址中的每个孤立地址，检查是否在查询范围内
		// 只要策略中的任意一个孤立地址在查询范围内，就视为匹配
		matched = false
		matchedAddress = network.NewNetworkGroup()

		// 遍历策略地址中的 IPv4 孤立地址
		dr := policyAddr.IPv4().DataRange()
		if dr != nil {
			for _, entry := range dr.List() {
				el := flexrange.NewEntryList(32, big.NewInt(0))
				el.PushEntry(entry)
				nl, err := network.NewNetworkListFromEntryList(*el, network.IPv4)
				if err != nil {
					continue
				}
				if m.Address.Match(nl) {
					matched = true
					matchedAddress.Add(nl)
				}
			}
		}

		// 遍历策略地址中的 IPv6 孤立地址
		dr = policyAddr.IPv6().DataRange()
		if dr != nil {
			for _, entry := range dr.List() {
				el := flexrange.NewEntryList(128, big.NewInt(0))
				el.PushEntry(entry)
				nl, err := network.NewNetworkListFromEntryList(*el, network.IPv6)
				if err != nil {
					continue
				}
				if m.Address.Match(nl) {
					matched = true
					matchedAddress.Add(nl)
				}
			}
		}

		// 计算重叠详情（匹配的孤立地址数量）
		if matched {
			overlapDetail = float64(matchedAddress.IPv4().Count().Int64() + matchedAddress.IPv6().Count().Int64())
		}
	}

	matchType := MatchNone
	if matched {
		matchType = MatchSource
		// 对于 StrategyIsolatedInQuery，matchedAddress 已经在 case 中设置
		if m.Strategy != StrategyIsolatedInQuery {
			if mid != nil {
				matchedAddress = mid.Copy().(*network.NetworkGroup)
			}
		}
		if !m.IsSource {
			matchType = MatchDestination
		}
	}

	return MatchResult{
		Matched:        matched,
		MatchType:      matchType,
		OverlapDetail:  overlapDetail,
		MatchedAddress: matchedAddress,
		ExtraInfo: map[string]interface{}{
			"Strategy":  m.Strategy.String(),
			"Threshold": m.Threshold,
		},
	}
}

// 辅助函数

func mustNetworkGroup(addr string) *network.NetworkGroup {
	ng, err := network.NewNetworkGroupFromString(addr)
	if err != nil {
		panic(err)
	}
	return ng
}

func mustService(serviceString string) *service.Service {
	s, err := service.NewServiceFromString(serviceString)
	if err != nil {
		panic(err)
	}
	return s
}

// NewAddressMatcher 新增辅助函数
func NewAddressMatcher(addr string, strategy MatchStrategy, isSource bool, threshold float64) *AddressMatcher {
	return &AddressMatcher{
		Address:   mustNetworkGroup(addr),
		Strategy:  strategy,
		IsSource:  isSource,
		Threshold: threshold,
	}
}

// NodeMap 方法

// func (nm *NodeMap) Policies(matchers ...PolicyMatcher) map[string][]firewall.FirewallPolicy {
//     policies := make(map[string][]firewall.FirewallPolicy)
//     for _, node := range nm.Nodes {
//         if fw, ok := node.(firewall.FirewallNode); ok {
//             nodePolicies := fw.Policies()
//             matchedPolicies := []firewall.FirewallPolicy{}

//             for _, plc := range nodePolicies {
//                 if matchPolicy(plc, matchers) {
//                     matchedPolicies = append(matchedPolicies, plc)
//                 }
//             }

//             if len(matchedPolicies) > 0 {
//                 policies[node.Name()] = matchedPolicies
//             }
//         }
//     }

//     return policies
// }

func (nm *NodeMap) Policies(actionID string, matchers ...PolicyMatcher) map[string][]PolicyMatchResult {
	policies := make(map[string][]PolicyMatchResult)
	var count int
	for _, node := range nm.Nodes {
		fw, ok := node.(firewall.FirewallNode)
		if !ok {
			count++
			if err := nm.progressCounter(actionID, count, len(nm.Nodes)); err != nil {
				nm.logger.Error("l3 node map process progress has error: ", zap.Error(err))
				return nil
			}
			continue
		}
		nodePolicies := fw.Policies()
		var matchedPolicies []PolicyMatchResult

		for _, plc := range nodePolicies {
			// fmt.Println("Policy:", index, ":", plc.PolicyEntry().String())
			if result := matchPolicyWithDetails(plc, matchers); result != nil {
				//fmt.Printf("Policy %d matched: %+v\n", index, result)
				matchedPolicies = append(matchedPolicies, *result)
			}
		}

		if len(matchedPolicies) > 0 {
			policies[node.Name()] = matchedPolicies
		}
		count++
		if err := nm.progressCounter(actionID, count, len(nm.Nodes)); err != nil {
			nm.logger.Error("l3 node map process progress has error: ", zap.Error(err))
			return nil
		}
	}

	return policies
}

func (nm *NodeMap) progressCounter(key string, count int, nodeCount int) error {
	progress := int64(float64(count) / float64(nodeCount) * 100)

	// 优先使用 NodeMap 的 redisClient，如果没有设置则使用 global.Redis（向后兼容）
	var err error
	if nm.redisClient != nil {
		err = nm.redisClient.Set(context.Background(), key, progress, 6*time.Hour)
	} else {
		// 向后兼容：如果没有设置 redisClient，使用 global.Redis
		if global.Redis != nil {
			err = global.Redis.Set(context.Background(), key, progress, 6*time.Hour).Err()
		} else {
			return fmt.Errorf("redis client is not available")
		}
	}

	if err != nil {
		return err
	}
	nm.logger.Info(fmt.Sprintf("l3 node map process progress %d%s", progress, "%"))
	return nil
}

// func matchPolicy(policy firewall.FirewallPolicy, matchers []PolicyMatcher) bool {
// 	for _, matcher := range matchers {
// 		if !matcher.Match(policy) {
// 			return false
// 		}
// 	}
// 	return true
// }

// func matchPolicyWithDetails(policy firewall.FirewallPolicy, matchers []PolicyMatcher) *PolicyMatchResult {
// 	result := &PolicyMatchResult{
// 		Policy:       policy,
// 		MatchDetails: make(map[string]MatchDetail),
// 		OverallMatch: true,
// 	}

// 	for _, matcher := range matchers {
// 		matcherName := getMatcherName(matcher)
// 		detail := MatchDetail{
// 			MatcherType:  fmt.Sprintf("%T", matcher),
// 			MatcherValue: getMatcherValue(matcher),
// 			ExtraInfo:    make(map[string]interface{}),
// 			MatchType:    MatchNone,
// 		}

// 		switch m := matcher.(type) {
// 		case *AddressMatcher:
// 			detail.Matched = m.Match(policy)
// 			detail.OverlapDetail = calculateOverlap(policy, m)
// 			detail.ExtraInfo["Strategy"] = m.Strategy.String()
// 			detail.MatchType = MatchSource
// 			if !m.IsSource {
// 				detail.MatchType = MatchDestination
// 			}
// 			detail.ExtraInfo["Threshold"] = m.Threshold
// 		case ActionMatcher:
// 			detail.Matched = m.Match(policy)
// 			detail.ExtraInfo["PolicyAction"] = policy.Action()
// 		case ServiceMatcher:
// 			detail.Matched = m.Match(policy)
// 			detail.ExtraInfo["PolicyService"] = policy.PolicyEntry().Service().String()
// 		case CompositeMatcher:
// 			detail.Matched = m.Match(policy)
// 			subDetails := make(map[string]MatchDetail)
// 			sourceMatched := false
// 			destMatched := false
// 			for _, subMatcher := range m.Matchers {
// 				subResult := matchPolicyWithDetails(policy, []PolicyMatcher{subMatcher})
// 				if subResult != nil {
// 					for k, v := range subResult.MatchDetails {
// 						subDetails[k] = v
// 						if v.MatchType == MatchSource || v.MatchType == MatchBoth {
// 							sourceMatched = true
// 						}
// 						if v.MatchType == MatchDestination || v.MatchType == MatchBoth {
// 							destMatched = true
// 						}
// 					}
// 				}
// 			}
// 			detail.ExtraInfo["SubMatchers"] = subDetails
// 			if sourceMatched && destMatched {
// 				detail.MatchType = MatchBoth
// 			} else if sourceMatched {
// 				detail.MatchType = MatchSource
// 			} else if destMatched {
// 				detail.MatchType = MatchDestination
// 			}
// 		default:
// 			detail.Matched = matcher.Match(policy)
// 		}

// 		result.MatchDetails[matcherName] = detail
// 		if !detail.Matched {
// 			result.OverallMatch = false
// 		}
// 	}

// 	if !result.OverallMatch {
// 		return nil
// 	}

// 	return result
// }

func matchPolicyWithDetails(policy firewall.FirewallPolicy, matchers []PolicyMatcher) *PolicyMatchResult {
	result := &PolicyMatchResult{
		Policy:       policy,
		MatchDetails: make(map[string]MatchDetail),
		OverallMatch: true,
		MatchType:    MatchNone,
	}

	for _, matcher := range matchers {
		matcherName := getMatcherName(matcher)
		matchResult := matcher.Match(policy)

		detail := MatchDetail{
			Matched:       matchResult.Matched,
			MatcherType:   fmt.Sprintf("%T", matcher),
			MatcherValue:  getMatcherValue(matcher),
			OverlapDetail: matchResult.OverlapDetail,
			ExtraInfo:     matchResult.ExtraInfo,
			MatchType:     matchResult.MatchType,
		}

		result.MatchDetails[matcherName] = detail
		if !detail.Matched {
			result.OverallMatch = false
		}

		if detail.MatchType > result.MatchType {
			result.MatchType = detail.MatchType
		}

		if matchResult.Matched && matchResult.MatchedAddress != nil && !matchResult.MatchedAddress.IsEmpty() {
			result.MatchedAddress = matchResult.MatchedAddress
			//fmt.Printf("Matched Address found for matcher %s: %s\n", matcherName, matchResult.MatchedAddress.String())
		}
	}

	if !result.OverallMatch {
		return nil
	}

	return result
}

func getMatcherName(matcher PolicyMatcher) string {
	switch m := matcher.(type) {
	case *AddressMatcher:
		sourceOrDest := "Dest"
		if m.IsSource {
			sourceOrDest = "Source"
		}
		return fmt.Sprintf("%sAddress(%s)", sourceOrDest, m.Address.String())
	case ActionMatcher:
		return fmt.Sprintf("Action(%s)", m.Action)
	case ServiceMatcher:
		return fmt.Sprintf("Service(%s)", m.Service.String())
	default:
		return fmt.Sprintf("%T", matcher)
	}
}

// func calculateOverlap(policy firewall.FirewallPolicy, matcher *AddressMatcher) float64 {
// 	var policyAddr *network.NetworkGroup
// 	if matcher.IsSource {
// 		policyAddr = policy.PolicyEntry().Src()
// 	} else {
// 		policyAddr = policy.PolicyEntry().Dst()
// 	}

// 	_, mid, _ := network.NetworkGroupCmp(*policyAddr, *matcher.Address)
// 	if mid == nil || mid.IsEmpty() {
// 		return 0
// 	}

// 	overlapSize := float64(mid.IPv4().Count().Int64() + mid.IPv6().Count().Int64())
// 	policySize := float64(policyAddr.IPv4().Count().Int64() + policyAddr.IPv6().Count().Int64())
// 	return overlapSize / policySize
// }

func getMatcherValue(matcher PolicyMatcher) string {
	switch m := matcher.(type) {
	case *AddressMatcher:
		return m.Address.String()
	case ActionMatcher:
		return m.Action.String()
	case ServiceMatcher:
		return m.Service.String()
	case NameMatcher:
		return m.Name
	case CliMatcher:
		return m.CliPattern
	default:
		return "Unknown"
	}
}

// func calculateOverlap(policy firewall.FirewallPolicy, matcher *AddressMatcher) float64 {
// 	var policyAddr *network.NetworkGroup
// 	if matcher.IsSource {
// 		policyAddr = policy.PolicyEntry().Src()
// 	} else {
// 		policyAddr = policy.PolicyEntry().Dst()
// 	}

// 	_, mid, _ := network.NetworkGroupCmp(*policyAddr, *matcher.Address)
// 	if mid == nil || mid.IsEmpty() {
// 		return 0
// 	}

// 	overlapSize := float64(mid.IPv4().Count().Int64() + mid.IPv6().Count().Int64())
// 	policySize := float64(policyAddr.IPv4().Count().Int64() + policyAddr.IPv6().Count().Int64())

// 	if policySize == 0 {
// 		return 0 // 避免除以零
// 	}

// 	return overlapSize / policySize
// }
