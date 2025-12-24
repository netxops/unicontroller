package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/netxops/utils/policy"

	"go.uber.org/zap"
)

type FirewallProcess struct {
	//inEntry policy.PolicyEntryInf
	//node    FirewallNode
	//steps   map[FirewallPhase]*ProcessStep
	//logger  *zap.Logger
	processor.NodeProcessor
}

func (fp *FirewallProcess) MarshalJSON() ([]byte, error) {
	steps := fp.GetSteps()
	return json.Marshal(&struct {
		Intent       string
		Node         string
		NodeIp       string
		InputNat     *processor.ProcessStep
		InputPolicy  *processor.ProcessStep
		OutputPolicy *processor.ProcessStep
		OutputNat    *processor.ProcessStep
	}{
		Intent:       fp.GetInEntry().String(),
		Node:         fp.GetNode().(api.Node).Name(),
		NodeIp:       fp.GetNode().(api.Node).CmdIp(),
		InputNat:     steps[INPUT_NAT.String()],
		InputPolicy:  steps[INPUT_POLICY.String()],
		OutputPolicy: steps[OUTPUT_POLICY.String()],
		OutputNat:    steps[OUTPUT_NAT.String()],
	})
}

func (fp *FirewallProcess) UnmarshalJSON(b []byte) error {
	type ts struct {
		Intent       string
		Node         string
		NodeIp       string
		InputNat     processor.ProcessStep
		InputPolicy  processor.ProcessStep
		OutputPolicy processor.ProcessStep
		OutputNat    processor.ProcessStep
	}

	tsMod := ts{}
	if err := json.Unmarshal(b, &tsMod); err != nil {
		return err
	}

	steps := map[string]*processor.ProcessStep{}
	steps[INPUT_NAT.String()] = &tsMod.InputNat
	steps[INPUT_POLICY.String()] = &tsMod.InputPolicy
	steps[OUTPUT_POLICY.String()] = &tsMod.OutputPolicy
	steps[OUTPUT_NAT.String()] = &tsMod.OutputNat
	fp.SetSteps(steps)
	return nil
}

type StepIterator struct {
	phaseS  []FirewallPhase
	process *FirewallProcess
	index   int
}

func NewFirewallProcess(node FirewallNode, inEntry policy.PolicyEntryInf) *FirewallProcess {
	np := &FirewallProcess{}
	np.SetStepList(firewallPhaseList)

	np.SetInEntry(inEntry)
	np.SetNode(node.(api.Node))
	np.SetSteps(map[string]*processor.ProcessStep{})
	if inEntry.(*policy.Intent).RealIp != "" {
		np.WithInputNat()
	} else if inEntry.(*policy.Intent).Snat != "" {
		np.WithOutputNat()
	}
	node.DefaultStep(np)
	return np
}

func (fp *FirewallProcess) Intent() policy.PolicyEntryInf {
	return fp.GetInEntry()
}

func (fp *FirewallProcess) Step(phase FirewallPhase) *processor.ProcessStep {
	return fp.GetSteps()[phase.String()]
}

func (fp *FirewallProcess) Iterator() *StepIterator {
	iterator := StepIterator{
		index:   0,
		process: fp,
	}

	for _, ph := range []FirewallPhase{INPUT_NAT, INPUT_POLICY, OUTPUT_POLICY, OUTPUT_NAT} {
		if fp.GetSteps()[ph.String()] != nil {
			iterator.phaseS = append(iterator.phaseS, ph)
		}
	}

	return &iterator
}

func (it *StepIterator) HasNext() bool {
	if it.index < len(it.phaseS) {
		return true
	}

	return false
}

func (it *StepIterator) Next() (FirewallPhase, *processor.ProcessStep) {
	ph := it.phaseS[it.index]
	it.index++
	return ph, it.process.GetSteps()[ph.String()]
}

func (fp *FirewallProcess) WithLogger(logger *zap.Logger) {
	fp.SetLogger(*logger)
}

func (fp *FirewallProcess) WithInputNat() *FirewallProcess {
	// 只在 step 不存在时才创建新的，避免覆盖已有的 step 信息
	if _, ok := fp.GetSteps()[INPUT_NAT.String()]; !ok {
		fp.GetSteps()[INPUT_NAT.String()] = processor.NewProcessStep(int(INPUT_NAT))
	}
	return fp
}

func (fp *FirewallProcess) WithInputPolicy() *FirewallProcess {
	// 只在 step 不存在时才创建新的，避免覆盖已有的 step 信息
	if _, ok := fp.GetSteps()[INPUT_POLICY.String()]; !ok {
		fp.GetSteps()[INPUT_POLICY.String()] = processor.NewProcessStep(int(INPUT_POLICY))
	}
	return fp
}

func (fp *FirewallProcess) WithOutputPolicy() *FirewallProcess {
	// 只在 step 不存在时才创建新的，避免覆盖已有的 step 信息
	if _, ok := fp.GetSteps()[OUTPUT_POLICY.String()]; !ok {
		fp.GetSteps()[OUTPUT_POLICY.String()] = processor.NewProcessStep(int(OUTPUT_POLICY))
	}
	return fp
}

func (fp *FirewallProcess) WithOutputNat() *FirewallProcess {
	// 只在 step 不存在时才创建新的，避免覆盖已有的 step 信息
	if _, ok := fp.GetSteps()[OUTPUT_NAT.String()]; !ok {
		fp.GetSteps()[OUTPUT_NAT.String()] = processor.NewProcessStep(int(OUTPUT_NAT))
	}
	return fp
}

func (fp *FirewallProcess) StepCheck(intent *policy.Intent) {
	if intent.RealIp != "" {
		fp.WithInputNat()
	}

	if intent.Snat != "" {
		fp.WithOutputNat()
	}

	fp.GetNode().(FirewallNode).DefaultStep(fp)
}

func (fp *FirewallProcess) RemoveStep(step string) {
	if _, ok := fp.GetSteps()[step]; ok {
		delete(fp.GetSteps(), step)
	}
}

// PolicyContext 用于在各个阶段之间传递信息
type PolicyContext struct {
	context.Context
	Intent             *policy.Intent
	TranslateTo        *policy.Intent
	InPort             api.Port
	OutPort            api.Port
	Vrf                api.Vrf
	Force              bool
	CmdList            []interface{}
	AdditionCli        []string
	Node               FirewallNode
	Logger             *zap.Logger
	Variables          map[string]interface{}
	GlobalNaming       map[string]string
	DeviceSpecificData map[string]interface{}
	TraverseProcess    interface{} // 用于访问 TraverseProcess 以添加警告（使用 interface{} 避免循环依赖）
	// GeneratedObjects 存储已生成的对象映射，用于在 MakePolicyV3 和 MakeNatPolicyV3 之间共享
	// key: "network:<networkGroupString>" 或 "service:<serviceString>"
	// value: map[string]interface{} 包含 objectName, cliString, keys 等信息
	GeneratedObjects map[string]interface{}
	// TemplatePath 防火墙模板路径，如果为空则使用默认路径
	TemplatePath string
}

func (pc *PolicyContext) GetDeviceMetaData(node api.Node) (map[string]interface{}, bool) {
	if node == nil {
		return nil, false
	}

	cmdIp := node.CmdIp()
	if cmdIp == "" {
		return nil, false
	}

	metadata, ok := pc.DeviceSpecificData[cmdIp]
	if !ok {
		return nil, false
	}

	metadataMap, ok := metadata.(map[string]interface{})
	if !ok {
		return nil, false
	}

	return metadataMap, true
}

func (pc *PolicyContext) WithValue(key string, value interface{}) *PolicyContext {
	pc.Variables[key] = value
	return pc
}

// 在 PolicyContext 结构体中添加 GetValue 方法
func (pc *PolicyContext) GetValue(key string) (interface{}, bool) {
	if value, exists := pc.Variables[key]; exists {
		return value, true
	}
	return nil, false
}

// 为了方便使用，我们也可以添加一些类型特定的 getter 方法

// GetStringValue 获取字符串类型的值
func (pc *PolicyContext) GetStringValue(key string) (string, bool) {
	if value, exists := pc.Variables[key]; exists {
		if strValue, ok := value.(string); ok {
			return strValue, true
		}
	}
	// deviceMeta := pc.Node.(api.Node).GetDeviceConfig()
	// if deviceMeta != nil {
	// 	if strValue, ok := deviceMeta.MetaData[key]; ok {
	// 		if strValue, ok := strValue.(string); ok {
	// 			return strValue, true
	// 		}
	// 		return "", false
	// 	}
	// }
	return "", false
}

func (pc *PolicyContext) GetSiteName() (string, bool) {
	return pc.GetStringValue("site_name")
}

// GetIntValue 获取整数类型的值
func (pc *PolicyContext) GetIntValue(key string) (int, bool) {
	if value, exists := pc.Variables[key]; exists {
		if intValue, ok := value.(int); ok {
			return intValue, true
		}
	}
	return 0, false
}

// GetBoolValue 获取布尔类型的值
func (pc *PolicyContext) GetBoolValue(key string) (bool, bool) {
	if value, exists := pc.Variables[key]; exists {
		if boolValue, ok := value.(bool); ok {
			return boolValue, true
		}
	}
	return false, false
}

// func (pc *PolicyContext) GetDeviceMetaData() (map[string]interface{}, bool) {
// 	config := pc.Node.(api.Node).GetDeviceConfig()
// 	if config != nil {
// 		return config.MetaData, true
// 	}

// 	return nil, false
// }

func (pc *PolicyContext) SetSrcAddrObjName(name string) {
	pc.Variables["SrcAddrObjName"] = name
}

func (pc *PolicyContext) GetSrcAddrObjName() string {
	if name, ok := pc.Variables["SrcAddrObjName"].(string); ok {
		return name
	}
	return ""
}

func (pc *PolicyContext) SetDstAddrObjName(name string) {
	pc.Variables["DstAddrObjName"] = name
}

func (pc *PolicyContext) GetDstAddrObjName() string {
	if name, ok := pc.Variables["DstAddrObjName"].(string); ok {
		return name
	}
	return ""
}

func (pc *PolicyContext) SetServiceName(name string) {
	pc.Variables["ServiceName"] = name
}

func (pc *PolicyContext) GetServiceName() string {
	if name, ok := pc.Variables["ServiceName"].(string); ok {
		return name
	}
	return ""
}

func (pc *PolicyContext) SetAclId(id string) {
	pc.Variables["AclId"] = id
}

func (pc *PolicyContext) GetAclId() string {
	if id, ok := pc.Variables["AclId"].(string); ok {
		return id
	}
	return ""
}

func (pc *PolicyContext) SetNatPoolName(name string) {
	pc.Variables["NatPoolName"] = name
}

func (pc *PolicyContext) GetNatPoolName() string {
	if name, ok := pc.Variables["NatPoolName"].(string); ok {
		return name
	}
	return ""
}

// func (fp *FirewallProcess) MakeTemplates(ctx context.Context, intent *policy.Intent, inPort api.Port, vrf api.Vrf, force bool) (translateTo *policy.Intent, cmdList []interface{}, additionCli []string, err model.ProcessErr) {
// 	var outPort api.Port
// 	translateTo = intent
// 	cmdList = []interface{}{}

// 	newCtx := &ctx
// 	logger := fp.GetLogger()
// 	node := fp.GetNode().(FirewallNode)
// 	logger.Info("开始进行模板生成")
// 	if step, ok := fp.GetSteps()[INPUT_NAT.String()]; ok {
// 		logger.Info("INPUT_NAT: 策略检查")
// 		result := node.InputNat(intent, inPort)
// 		step.WithMatchResult(result.(processor.AbstractMatchResult))
// 		if ru, right := result.(*NatMatchResult); right {
// 			if ru.Rule() != nil {
// 				fmt.Println("INPUT_NAT现有策略：", ru.Rule().Cli())
// 				step.WithRule(ru.Rule().Cli())
// 				*newCtx = context.WithValue(*newCtx, "STATIC_NAT_NAME", ru.Rule().Name())
// 			}
// 		}

// 		if result.(*NatMatchResult).MeetStatus() == MEET_INTENT_NO {
// 			step.WithPhaseAction(processor.PHASE_GENERATED)
// 			if result.Action() == int(NAT_MATCHED) {
// 				// 表示NAT的结果与预期不一致(配置冲突)
// 				errStr := fmt.Sprintf("INPUT_NAT: nat matched, but not meet intent(INPUT_NAT: 策略检查), Rule:[%s]", result.(*NatMatchResult).Rule().Cli())
// 				err = model.NewProcessErr(errStr, model.ConfigConflict)
// 				return
// 			} else {
// 				logger.Info("INPUT_NAT: 策略生成...")
// 				nl := intent.GenerateIntentPolicyEntry().Dst().MustOne()
// 				ok, _, portList, _ := fp.GetNode().IpRouteCheck(*nl, inPort.Name(), vrf.Name(), nl.Type())
// 				if !ok || len(portList) != 1 {
// 					errStr := fmt.Sprintf("INPUT_NAT: 策略生成...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String())
// 					err = model.NewProcessErr(errStr, model.MissRoute)
// 					return
// 				}

// 				outPort = fp.GetNode().GetPort(portList[0])
// 				logger.Info("INPUT_NAT: 计算流出端口", zap.Any("OutPort", outPort))
// 				flyObjects, cmds := node.(FirewallTemplates).MakeStaticNatCli(inPort, outPort, intent, newCtx)
// 				cmdList = append(cmdList, cmds)
// 				logger.Debug("INPUT_NAT: ", zap.Any("FlyObject", flyObjects))
// 				logger.Debug("INPUT_NAT: ", zap.Any("CmdList", cmds))

// 				node.FlyConfig(flyObjects)
// 				resultFly := node.InputNat(intent, inPort)
// 				if resultFly.(*NatMatchResult).MeetStatus() != MEET_INTENT_OK {
// 					errStr := fmt.Sprintf("fly config failed(INPUT_NAT: 策略生成...), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
// 					err = model.NewProcessErr(errStr, model.SimylationVerificationFailed)
// 					return
// 				}
// 				logger.Info("INPUT_NAT: 策略FlyConfig运行正常")
// 				translateTo = resultFly.(*NatMatchResult).TranslateTo()
// 				logger.Info("INPUT_NAT: ", zap.Any("TranslateTo", translateTo))

// 				step.WithCmdList(cmds)
// 				step.WithCli(node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, newCtx))
// 			}
// 		} else {
// 			step.WithPhaseAction(processor.PHASE_MATCHED)
// 			logger.Info("INPUT_NAT: 匹配到现有策略", zap.Any("Rule", result.(*NatMatchResult).Rule()))
// 			translateTo = result.(*NatMatchResult).TranslateTo()
// 			nl := translateTo.Dst().MustOne()

// 			ok, _, portList, _ := fp.GetNode().IpRouteCheck(*nl, inPort.Name(), vrf.Name(), nl.Type())
// 			if !ok || len(portList) != 1 {
// 				errStr := fmt.Sprintf("INPUT_NAT: 匹配到现有策略...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String())
// 				err = model.NewProcessErr(errStr, model.MissRoute)
// 				return
// 			}

// 			outPort = fp.GetNode().GetPort(portList[0])
// 			logger.Info("INPUT_NAT: 计算流出端口", zap.Any("OutPort", outPort))

// 			step.WithMatchResult(result.(processor.AbstractMatchResult))
// 			result.(*NatMatchResult).WithOutPort(outPort)
// 		}
// 	}

// 	if tools.IsNil(outPort) {
// 		nl := translateTo.Dst().MustOne()
// 		ok, _, portList, routeError := fp.GetNode().IpRouteCheck(*nl, inPort.Name(), vrf.Name(), nl.Type())
// 		if !ok || len(portList) != 1 {
// 			fmt.Println(portList, inPort.Name(), vrf.Name(), *nl)
// 			errStr := fmt.Sprintf("outort检查...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s], Error:[%s]", inPort.Name(), vrf.Name(), nl.Type().String(), routeError.Error())
// 			err = model.NewProcessErr(errStr, model.MissRoute)
// 			return
// 		}

// 		outPort = fp.GetNode().GetPort(portList[0])
// 		logger.Info("MakeTemplates: 计算流出端口", zap.Any("OutPort", outPort))
// 	}

// 	if step, ok := fp.GetSteps()[INPUT_POLICY.String()]; ok {
// 		logger.Info("INPUT_POLICY: 策略检查")
// 		logger.Debug("INPUT_POLICY: ", zap.Any("Entry", translateTo))
// 		result := node.InputPolicy(translateTo, inPort, outPort)
// 		step.WithMatchResult(result.(processor.AbstractMatchResult))
// 		if ru, right := result.(*PolicyMatchResult); right {
// 			if ru.Rule() != nil {
// 				fmt.Println("INPUT_POLICY现有策略：", ru.Rule().Cli())
// 				step.WithRule(ru.Rule().Cli())
// 				*newCtx = context.WithValue(*newCtx, "INPUT_POLICY", ru)
// 			}
// 		}

// 		if result.Action() == int(POLICY_PERMIT) || result.Action() == int(POLICY_IMPLICIT_PERMIT) {
// 			step.WithPhaseAction(processor.PHASE_MATCHED)
// 			logger.Info("INPUT_POLICY: 允许通过", zap.Any("Action", result.Action()))
// 		} else if result.Action() == int(POLICY_DENY) {
// 			if force {
// 				step.WithPhaseAction(processor.PHASE_GENERATED)
// 				logger.Info("INPUT_POLICY: 强制进行策略生成", zap.Any("Action", result.Action()), zap.Any("Rule", result.(*PolicyMatchResult).Rule()))
// 				flyObjects, cmds, moveRule := node.(FirewallTemplates).MakeInputPolicyCli(inPort, outPort, translateTo, newCtx)
// 				additionCli = moveRule
// 				cmdList = append(cmdList, cmds)
// 				logger.Debug("INPUT_POLICY: ", zap.Any("FlyObject", flyObjects))
// 				logger.Debug("INPUT_POLICY: ", zap.Any("CmdList", cmds))
// 				node.FlyConfig(flyObjects)

// 				resultFly := node.InputPolicy(translateTo, inPort, outPort)
// 				if resultFly.Action() != int(POLICY_PERMIT) {
// 					errStr := fmt.Sprintf("fly config failed(INPUT_POLICY: 强制进行策略生成), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
// 					err = model.NewProcessErr(errStr, model.SimylationVerificationFailed)
// 					return
// 				}
// 				logger.Info("INPUT_POLICY: 策略FlyConfig运行正常")
// 				if ru, right := resultFly.(*PolicyMatchResult); right {
// 					if ru.Rule() != nil {
// 						*newCtx = context.WithValue(*newCtx, "INPUT_POLICY", ru)
// 					}
// 				}
// 				step.WithCmdList(cmds)
// 				step.WithCli(node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, newCtx))
// 			} else {
// 				logger.Warn("INPUT_POLICY: 拒绝通过", zap.Any("Action", result.Action()), zap.Any("Rule", result.(*PolicyMatchResult).Rule()))
// 				logger.Warn("INPUT_POLICY Deny")
// 				errStr := fmt.Sprintf("INPUT_POLICY Deny, Rule:[%s]", result.(*PolicyMatchResult).Rule().Cli())
// 				err = model.NewProcessErr(errStr, model.PolicyDeny)
// 				return
// 			}
// 		} else {
// 			step.WithPhaseAction(processor.PHASE_GENERATED)
// 			logger.Info("INPUT_POLICY: 策略生成...")
// 			flyObjects, cmds, moveRule := node.(FirewallTemplates).MakeInputPolicyCli(inPort, outPort, translateTo, newCtx)
// 			additionCli = moveRule
// 			cmdList = append(cmdList, cmds)
// 			logger.Debug("INPUT_POLICY: ", zap.Any("FlyObject", flyObjects))
// 			logger.Debug("INPUT_POLICY: ", zap.Any("CmdList", cmds))
// 			node.FlyConfig(flyObjects)
// 			resultFly := node.InputPolicy(translateTo, inPort, outPort)

// 			if resultFly.Action() != int(POLICY_PERMIT) {
// 				errStr := fmt.Sprintf("fly config failed(INPUT_POLICY: 策略生成...), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
// 				err = model.NewProcessErr(errStr, model.SimylationVerificationFailed)
// 				return
// 			}
// 			if ru, right := resultFly.(*PolicyMatchResult); right {
// 				if ru.Rule() != nil {
// 					*newCtx = context.WithValue(*newCtx, "INPUT_POLICY", ru)
// 				}
// 			}

// 			logger.Info("INPUT_POLICY: 策略FlyConfig运行正常")
// 			step.WithCmdList(cmds)
// 			step.WithMatchResult(result.(processor.AbstractMatchResult))
// 			step.WithCli(node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, newCtx))
// 		}
// 	}

// 	if step, ok := fp.GetSteps()[OUTPUT_POLICY.String()]; ok {
// 		logger.Info("OUTPUT_POLICY: 策略检查")
// 		result := node.OutputPolicy(translateTo, inPort, outPort)
// 		step.WithMatchResult(result.(processor.AbstractMatchResult))
// 		if ru, right := result.(*PolicyMatchResult); right {
// 			if ru.Rule() != nil {
// 				fmt.Println("OUTPUT_POLICY现有策略：", ru.Rule().Cli())
// 				step.WithRule(ru.Rule().Cli())
// 			}
// 		}

// 		if result.Action() == int(POLICY_PERMIT) || result.Action() == int(POLICY_IMPLICIT_PERMIT) {
// 			step.WithPhaseAction(processor.PHASE_MATCHED)
// 			logger.Info("OUTPUT_POLICY: 允许通过", zap.Any("Action", result.Action()))
// 		} else if result.Action() == int(POLICY_DENY) {
// 			if force {
// 				step.WithPhaseAction(processor.PHASE_GENERATED)
// 				logger.Info("OUTPUT_POLICY: 强制进行策略生成", zap.Any("Action", result.Action()), zap.Any("Rule", result.(*PolicyMatchResult).Rule()))

// 				flyObjects, cmds := node.(FirewallTemplates).MakeOutputPolicyCli(inPort, outPort, translateTo, newCtx)
// 				cmdList = append(cmdList, cmds)

// 				logger.Debug("INPUT_POLICY: ", zap.Any("FlyObject", flyObjects))
// 				logger.Debug("INPUT_POLICY: ", zap.Any("CmdList", cmds))

// 				node.FlyConfig(flyObjects)
// 				resultFly := node.OutputPolicy(translateTo, inPort, outPort)
// 				if resultFly.Action() != int(POLICY_PERMIT) {
// 					errStr := fmt.Sprintf("fly config failed(OUTPUT_POLICY: 强制进行策略生成), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
// 					err = model.NewProcessErr(errStr, model.SimylationVerificationFailed)
// 					return
// 				}
// 				logger.Info("OUTPUT_POLICY: 策略FlyConfig运行正常")
// 				step.WithCmdList(cmds)
// 				step.WithCli(node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, newCtx))

// 			} else {
// 				logger.Warn("OUTPUT_POLICY: 拒绝通过", zap.Any("Action", result.Action()), zap.Any("Rule", result.(*PolicyMatchResult).Rule()))
// 				errStr := fmt.Sprintf("OUTPUT_POLICY Deny, Rule:[%s]", result.(*PolicyMatchResult).Rule().Cli())
// 				err = model.NewProcessErr(errStr, model.PolicyDeny)
// 				return
// 			}
// 		} else {
// 			step.WithPhaseAction(processor.PHASE_GENERATED)
// 			logger.Info("OUTPUT_NAT: 策略生成...")
// 			flyObjects, cmds := node.(FirewallTemplates).MakeOutputPolicyCli(inPort, outPort, translateTo, newCtx)
// 			cmdList = append(cmdList, cmds)
// 			logger.Debug("OUTPUT_POLICY: ", zap.Any("FlyObject", flyObjects))
// 			logger.Debug("OUTPUT_POLICY: ", zap.Any("CmdList", cmds))

// 			node.FlyConfig(flyObjects)
// 			resultFly := node.OutputPolicy(translateTo, inPort, outPort)
// 			if resultFly.Action() != int(POLICY_PERMIT) {
// 				errStr := fmt.Sprintf("fly config failed(OUTPUT_NAT: 策略生成...), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
// 				err = model.NewProcessErr(errStr, model.SimylationVerificationFailed)
// 				return
// 			}

// 			step.WithCmdList(cmds)
// 			logger.Info("OUTPUT_POLICY: 策略FlyConfig运行正常")
// 			step.WithMatchResult(result.(processor.AbstractMatchResult))
// 		}
// 	}

// 	node.UpdateSnatStep(inPort, outPort, translateTo, fp)

// 	if step, _ := fp.GetSteps()[OUTPUT_NAT.String()]; step != nil {
// 		logger.Info("OUTPUT_NAT: 策略检查")
// 		result := node.OutputNat(intent, inPort, outPort)
// 		step.WithMatchResult(result.(processor.AbstractMatchResult))
// 		if ru, right := result.(*NatMatchResult); right {
// 			if ru.Rule() != nil {
// 				fmt.Println("OUTPUT_NAT现有策略：", ru.Rule().Cli())
// 				step.WithRule(ru.Rule().Cli())
// 			}
// 		}
// 		if result.(*NatMatchResult).MeetStatus() == MEET_INTENT_NO {
// 			if result.Action() == int(NAT_MATCHED) {
// 				// 表示NAT的结果与预期不一致
// 				errStr := fmt.Sprintf("nat matched, but not meet intent(OUTPUT_NAT: 策略检查), Rule:[%s]", result.(*NatMatchResult).Rule().Cli())
// 				err = model.NewProcessErr(errStr, model.ConfigConflict)
// 				return
// 			} else {
// 				step.WithPhaseAction(processor.PHASE_GENERATED)
// 				logger.Info("OUTPUT_NAT: 策略生成...")
// 				flyObjects, cmds := node.(FirewallTemplates).MakeDynamicNatCli(inPort, outPort, intent, newCtx)
// 				cmdList = append(cmdList, cmds)

// 				logger.Debug("OUTPUT_NAT: ", zap.Any("FlyObject", flyObjects))
// 				logger.Debug("OUTPUT_NAT: ", zap.Any("CmdList", cmds))

// 				node.FlyConfig(flyObjects)
// 				resultFly := node.OutputNat(intent, inPort, outPort)
// 				if resultFly.(*NatMatchResult).MeetStatus() != MEET_INTENT_OK {
// 					errStr := fmt.Sprintf("fly config failed(OUTPUT_NAT: 策略生成...), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
// 					err = model.NewProcessErr(errStr, model.SimylationVerificationFailed)
// 					return
// 				}
// 				logger.Info("OUTPUT_NAT: 策略FlyConfig运行正常")
// 				translateTo = resultFly.(*NatMatchResult).TranslateTo()
// 				logger.Info("OUTPUT_NAT: ", zap.Any("TranslateTo", translateTo))
// 				step.WithCmdList(cmds)
// 				step.WithCli(node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, newCtx))
// 			}
// 		} else {
// 			step.WithPhaseAction(processor.PHASE_MATCHED)
// 			logger.Info("OUTPUT_NAT: 匹配到现有策略", zap.Any("Rule", result.(*NatMatchResult).Rule()))
// 			step.WithMatchResult(result.(processor.AbstractMatchResult))
// 		}
// 	}

// 	return
// }

func (fp *FirewallProcess) calculateOutPort(ctx context.Context, translateTo *policy.Intent, inPort api.Port, vrf api.Vrf) (api.Port, model.ProcessErr) {
	nl := translateTo.Dst().MustOne()

	// 尝试使用 IpRouteCheckInternal 获取完整的警告信息（包括 matched_routes）
	var warning *model.WarningInfo
	var portList []string
	var ok bool

	// 通过接口调用 IpRouteCheckInternal 方法，替代反射
	if routeCheckNode, isRouteCheckNode := fp.GetNode().(RouteCheckFirewall); isRouteCheckNode {
		result := routeCheckNode.IpRouteCheckInternal(*nl, inPort.Name(), vrf.Name(), nl.Type())
		if result != nil {
			ok = result.Ok
			portList = result.PortList
			warning = result.Warning
		}
	}

	// 如果无法使用 IpRouteCheckInternal，回退到使用 IpRouteCheck 接口方法
	if warning == nil {
		var routeError error
		ok, _, portList, routeError = fp.GetNode().IpRouteCheck(*nl, inPort.Name(), vrf.Name(), nl.Type())
		if !ok || len(portList) != 1 {
			fmt.Println(portList, inPort.Name(), vrf.Name(), *nl)

			// 检查错误信息是否包含多路由匹配的提示
			errorMsg := ""
			if routeError != nil {
				errorMsg = routeError.Error()
			}

			// 先判断是否是多路由匹配（优先判断，确保类型正确）
			isMultiRoute := false
			if routeError != nil {
				errorMsgLower := strings.ToLower(errorMsg)
				isMultiRoute = strings.Contains(errorMsg, "多路由") ||
					strings.Contains(errorMsg, "多条不同路由") ||
					strings.Contains(errorMsgLower, "multiple match route") ||
					strings.Contains(errorMsgLower, "multiple route")
			}

			// 创建警告信息
			if isMultiRoute {
				warning = &model.WarningInfo{
					Type:      model.WarningMultiRouteMatch,
					Message:   fmt.Sprintf("outport检查...目标网络匹配到多条不同路由, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String()),
					Timestamp: time.Now(),
					Details: map[string]interface{}{
						"port_list":           portList,
						"in_port":             inPort.Name(),
						"vrf":                 vrf.Name(),
						"destination_network": nl.String(),
					},
				}
			} else {
				warning = &model.WarningInfo{
					Type:      model.WarningMissRoute,
					Message:   fmt.Sprintf("outport检查...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String()),
					Timestamp: time.Now(),
					Details: map[string]interface{}{
						"port_list":           portList,
						"in_port":             inPort.Name(),
						"vrf":                 vrf.Name(),
						"destination_network": nl.String(),
					},
				}
			}

			// 添加错误详情
			if routeError != nil {
				warning.Details["error_details"] = errorMsg
			}
		}
	}

	// 如果有警告，添加到 TraverseProcess
	if warning != nil && (!ok || len(portList) != 1) {
		// 尝试将警告添加到 TraverseProcess（如果可用）
		if policyCtx, ok := ctx.(*PolicyContext); ok && policyCtx.TraverseProcess != nil {
			if addWarning, ok := policyCtx.TraverseProcess.(interface{ AddWarning(model.WarningInfo) }); ok {
				addWarning.AddWarning(*warning)
			}
		}

		errMsg := warning.Message
		if errorDetails, ok := warning.Details["error_details"].(string); ok && errorDetails != "" {
			errMsg = fmt.Sprintf("outport检查...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s], Error:[%s]", inPort.Name(), vrf.Name(), nl.Type().String(), errorDetails)
		}
		// } else {
		// 	errMsg = fmt.Sprintf("outport检查...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String())
		// }
		err := model.NewProcessErr(errMsg, model.MissRoute)
		return nil, err
	}

	outPort := fp.GetNode().GetPortByNameOrAlias(portList[0])

	return outPort, model.ProcessErr{}
}

func (fp *FirewallProcess) MakeTemplates(ctx context.Context, intent *policy.Intent, inPort api.Port, vrf api.Vrf, force bool) (translateTo *policy.Intent, cmdList []interface{}, additionCli []string, err model.ProcessErr) {
	logger := fp.GetLogger()
	policyCtx := ctx.(*PolicyContext)
	// policyCtx := &PolicyContext{
	// 	Context:     ctx,
	// 	Intent:      intent,
	// 	TranslateTo: intent,
	// 	InPort:      inPort,
	// 	Vrf:         vrf,
	// 	Force:       force,
	// 	CmdList:     []interface{}{},
	// 	Node:        fp.GetNode().(FirewallNode),
	// 	Logger:      &logger,
	// }

	// logger := fp.GetLogger()
	node := fp.GetNode().(FirewallNode)

	// 处理 INPUT_NAT
	translateTo, cmds, addCli, outPort, err := fp.processInputNat(intent, inPort, nil, vrf, force, &logger, policyCtx)
	if err.NotNil() {
		return nil, nil, nil, err
	}
	cmdList = append(cmdList, cmds...)
	additionCli = append(additionCli, addCli...)

	// 计算出口端口
	outPort, err = fp.calculateOutPort(ctx, translateTo, inPort, vrf)
	if err.NotNil() {
		return nil, nil, nil, err
	}
	logger.Info("MakeTemplates: 计算流出端口", zap.Any("OutPort", outPort))

	// 处理 INPUT_POLICY
	translateTo, cmds, addCli, err = fp.processInputPolicy(translateTo, inPort, outPort, vrf, force, &logger, policyCtx)
	if err.NotNil() {
		return nil, nil, nil, err
	}
	cmdList = append(cmdList, cmds...)
	additionCli = append(additionCli, addCli...)

	// 处理 OUTPUT_POLICY
	translateTo, cmds, addCli, err = fp.processOutputPolicy(translateTo, inPort, outPort, vrf, force, &logger, policyCtx)
	if err.NotNil() {
		return nil, nil, nil, err
	}
	cmdList = append(cmdList, cmds...)
	additionCli = append(additionCli, addCli...)

	// 更新 SNAT 步骤
	node.UpdateSnatStep(inPort, outPort, translateTo, fp)

	// 处理 OUTPUT_NAT
	translateTo, cmds, addCli, err = fp.processOutputNat(translateTo, inPort, outPort, vrf, force, &logger, policyCtx)
	if err.NotNil() {
		return nil, nil, nil, err
	}
	cmdList = append(cmdList, cmds...)
	additionCli = append(additionCli, addCli...)

	return translateTo, cmdList, additionCli, model.ProcessErr{}

}

func (fp *FirewallProcess) updateSteps(ctx *PolicyContext) {
	// 根据需要动态更新 Step
	// 例如，UpdateSnatStep 的逻辑可以放在这里
	ctx.Node.UpdateSnatStep(ctx.InPort, ctx.OutPort, ctx.TranslateTo, fp)

}

func (fp *FirewallProcess) processInputNat(intent *policy.Intent, inPort, outPort api.Port, vrf api.Vrf, force bool, logger *zap.Logger, ctx *PolicyContext) (*policy.Intent, []interface{}, []string, api.Port, model.ProcessErr) {
	step, ok := fp.GetSteps()[INPUT_NAT.String()]
	if !ok {
		logger.Info("INPUT_NAT: 未找到步骤", zap.String("Step", INPUT_NAT.String()))
		return intent, nil, nil, nil, model.ProcessErr{}
	}

	node := fp.GetNode().(FirewallNode)
	result := node.InputNat(intent, inPort)
	step.WithMatchResult(result.(processor.AbstractMatchResult))

	logger.Info("INPUT_NAT: 策略检查")
	cmdList := []interface{}{}
	additionCli := []string{}

	if ru, ok := result.(*NatMatchResult); ok && ru.Rule() != nil {
		logger.Info("INPUT_NAT现有策略", zap.String("Rule", ru.Rule().Cli()))
		step.WithRule(ru.Rule().Cli())
		ctx.WithValue("STATIC_NAT_NAME", ru.Rule().Name())
	}

	if result.(*NatMatchResult).MeetStatus() == MEET_INTENT_NO {
		step.WithPhaseAction(processor.PHASE_GENERATED)
		if result.Action() == int(NAT_MATCHED) {
			errStr := fmt.Sprintf("INPUT_NAT: nat matched, but not meet intent(INPUT_NAT: 策略检查), Rule:[%s]", result.(*NatMatchResult).Rule().Cli())
			return nil, nil, nil, nil, model.NewProcessErr(errStr, model.ConfigConflict)
		}

		logger.Info("INPUT_NAT: 策略生成...")
		nl := intent.GenerateIntentPolicyEntry().Dst().MustOne()
		ok, _, portList, _ := fp.GetNode().IpRouteCheck(*nl, inPort.Name(), vrf.Name(), nl.Type())
		if !ok || len(portList) != 1 {
			errStr := fmt.Sprintf("INPUT_NAT: 策略生成...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String())
			return nil, nil, nil, nil, model.NewProcessErr(errStr, model.MissRoute)
		}

		outPort := fp.GetNode().GetPortByNameOrAlias(portList[0])
		logger.Info("INPUT_NAT: 计算流出端口", zap.Any("OutPort", outPort))
		ctx.OutPort = outPort

		flyObjects, cmds := node.(FirewallTemplates).MakeStaticNatCli(inPort, outPort, intent, ctx)
		cmdList = append(cmdList, cmds)
		logger.Debug("INPUT_NAT: ", zap.Any("FlyObject", flyObjects), zap.Any("CmdList", cmds))

		node.FlyConfig(flyObjects)
		resultFly := node.InputNat(intent, inPort)
		if resultFly.(*NatMatchResult).MeetStatus() != MEET_INTENT_OK {
			errStr := fmt.Sprintf("fly config failed(INPUT_NAT: 策略生成...), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", ctx.TranslateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
			return nil, nil, nil, nil, model.NewProcessErr(errStr, model.SimylationVerificationFailed)
		}

		logger.Info("INPUT_NAT: 策略FlyConfig运行正常")
		translateTo := resultFly.(*NatMatchResult).TranslateTo()
		logger.Info("INPUT_NAT: TranslateTo", zap.Any("TranslateTo", translateTo))

		step.WithCmdList(cmds)
		step.WithCli(node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, ctx))

		return translateTo, cmdList, additionCli, outPort, model.ProcessErr{}
	} else {
		step.WithPhaseAction(processor.PHASE_MATCHED)
		logger.Info("INPUT_NAT: 匹配到现有策略", zap.Any("Rule", result.(*NatMatchResult).Rule()))
		translateTo := result.(*NatMatchResult).TranslateTo()

		nl := translateTo.Dst().MustOne()
		// 尝试使用 IpRouteCheckInternal 获取完整的警告信息（包括 matched_routes）
		var warning *model.WarningInfo
		var portList []string
		var ok bool

		// 通过接口调用 IpRouteCheckInternal 方法，替代反射
		if routeCheckNode, isRouteCheckNode := fp.GetNode().(RouteCheckFirewall); isRouteCheckNode {
			result := routeCheckNode.IpRouteCheckInternal(*nl, inPort.Name(), vrf.Name(), nl.Type())
			if result != nil {
				ok = result.Ok
				portList = result.PortList
				warning = result.Warning
				// 添加 phase 信息
				if warning != nil && warning.Details != nil {
					warning.Details["phase"] = "INPUT_NAT"
				} else if warning != nil {
					warning.Details = make(map[string]interface{})
					warning.Details["phase"] = "INPUT_NAT"
				}
			}
		}

		// 如果无法使用 IpRouteCheckInternal，回退到使用 IpRouteCheck 接口方法
		if warning == nil {
			var routeError error
			ok, _, portList, routeError = fp.GetNode().IpRouteCheck(*nl, inPort.Name(), vrf.Name(), nl.Type())
			if !ok || len(portList) != 1 {
				// 检查错误信息是否包含多路由匹配的提示
				errorMsg := ""
				if routeError != nil {
					errorMsg = routeError.Error()
				}

				// 先判断是否是多路由匹配（优先判断，确保类型正确）
				isMultiRoute := false
				if routeError != nil {
					errorMsgLower := strings.ToLower(errorMsg)
					isMultiRoute = strings.Contains(errorMsg, "多路由") ||
						strings.Contains(errorMsg, "多条不同路由") ||
						strings.Contains(errorMsgLower, "multiple match route") ||
						strings.Contains(errorMsgLower, "multiple route")
				}

				// 创建警告信息
				if isMultiRoute {
					warning = &model.WarningInfo{
						Type:      model.WarningMultiRouteMatch,
						Message:   fmt.Sprintf("INPUT_NAT: 目标网络匹配到多条不同路由, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String()),
						Timestamp: time.Now(),
						Details: map[string]interface{}{
							"port_list":           portList,
							"in_port":             inPort.Name(),
							"vrf":                 vrf.Name(),
							"destination_network": nl.String(),
							"phase":               "INPUT_NAT",
						},
					}
				} else {
					warning = &model.WarningInfo{
						Type:      model.WarningMissRoute,
						Message:   fmt.Sprintf("INPUT_NAT: 匹配到现有策略...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String()),
						Timestamp: time.Now(),
						Details: map[string]interface{}{
							"port_list":           portList,
							"in_port":             inPort.Name(),
							"vrf":                 vrf.Name(),
							"destination_network": nl.String(),
							"phase":               "INPUT_NAT",
						},
					}
				}

				// 添加错误详情
				if routeError != nil {
					warning.Details["error_details"] = errorMsg
				}
			}
		}

		// 如果有警告，添加到 TraverseProcess
		if warning != nil && (!ok || len(portList) != 1) {
			// 尝试将警告添加到 TraverseProcess（如果可用）
			if ctx.TraverseProcess != nil {
				if addWarning, ok := ctx.TraverseProcess.(interface{ AddWarning(model.WarningInfo) }); ok {
					addWarning.AddWarning(*warning)
				}
			}
			errStr := fmt.Sprintf("INPUT_NAT: 匹配到现有策略...check output interface failed, PortName:[%s] VrfName:[%s], Type:[%s]", inPort.Name(), vrf.Name(), nl.Type().String())
			return nil, nil, nil, nil, model.NewProcessErr(errStr, model.MissRoute)
		}

		outPort := fp.GetNode().GetPortByNameOrAlias(portList[0])
		// ctx.OutPort = outPort
		logger.Info("INPUT_NAT: 计算流出端口", zap.Any("OutPort", outPort))

		result.(*NatMatchResult).WithOutPort(outPort)

		return translateTo, cmdList, additionCli, outPort, model.ProcessErr{}
	}
}

func (fp *FirewallProcess) processInputPolicy(intent *policy.Intent, inPort, outPort api.Port, vrf api.Vrf, force bool, logger *zap.Logger, ctx *PolicyContext) (*policy.Intent, []interface{}, []string, model.ProcessErr) {
	step, ok := fp.GetSteps()[INPUT_POLICY.String()]
	if !ok {
		logger.Info("INPUT_POLICY: 未找到步骤", zap.String("Step", INPUT_POLICY.String()))
		return intent, nil, nil, model.ProcessErr{}
	}
	node := fp.GetNode().(FirewallNode)
	translateTo := intent
	cmdList := []interface{}{}
	additionCli := []string{}

	logger.Info("INPUT_POLICY: 策略检查")
	logger.Debug("INPUT_POLICY: ", zap.Any("Entry", translateTo))

	// 打印详细的匹配请求信息
	fmt.Printf("[DEBUG processInputPolicy] ========== INPUT_POLICY 开始 ==========\n")
	fmt.Printf("  节点: %s\n", node.(api.Node).Name())
	fmt.Printf("  入接口: %s, 出接口: %s, VRF: %s\n", inPort.Name(), outPort.Name(), vrf.Name())
	if translateTo != nil {
		if src := translateTo.Src(); src != nil {
			fmt.Printf("  源网络: %s\n", src.String())
		}
		if dst := translateTo.Dst(); dst != nil {
			fmt.Printf("  目标网络: %s\n", dst.String())
		}
		if svc := translateTo.Service(); svc != nil {
			fmt.Printf("  服务: %s\n", svc.String())
		}
		fmt.Printf("  Intent完整信息: %s\n", translateTo.String())
	}

	result := node.InputPolicy(translateTo, inPort, outPort)
	step.WithMatchResult(result.(processor.AbstractMatchResult))

	// 打印匹配结果
	actionStr := "UNKNOWN"
	switch result.Action() {
	case int(POLICY_PERMIT):
		actionStr = "PERMIT"
	case int(POLICY_DENY):
		actionStr = "DENY"
	case int(POLICY_IMPLICIT_PERMIT):
		actionStr = "IMPLICIT_PERMIT"
	case int(POLICY_IMPLICIT_DENY):
		actionStr = "IMPLICIT_DENY"
	}
	fmt.Printf("[DEBUG processInputPolicy] 匹配结果: Action=%s (%d)\n", actionStr, result.Action())

	if ru, ok := result.(*PolicyMatchResult); ok && ru.Rule() != nil {
		logger.Info("INPUT_POLICY现有策略", zap.String("Rule", ru.Rule().Cli()))
		step.WithRule(ru.Rule().Cli())
		ctx.WithValue("INPUT_POLICY", ru)
		fmt.Printf("[DEBUG processInputPolicy] 匹配到的策略CLI:\n%s\n", ru.Rule().Cli())
	} else {
		fmt.Printf("[DEBUG processInputPolicy] 警告: 未找到匹配的策略规则\n")
	}
	fmt.Printf("[DEBUG processInputPolicy] ========== INPUT_POLICY 结束 ==========\n")
	fmt.Printf("[DEBUG processInputPolicy] 准备进入 switch 语句，result.Action()=%d\n", result.Action())
	fmt.Printf("[DEBUG processInputPolicy] step 对象地址: %p\n", step)
	fmt.Printf("[DEBUG processInputPolicy] step 当前 phaseAction: %d\n", int(step.GetPhaseAction()))

	switch {
	case result.Action() == int(POLICY_PERMIT) || result.Action() == int(POLICY_IMPLICIT_PERMIT):
		fmt.Printf("[DEBUG processInputPolicy] 进入 PERMIT/IMPLICIT_PERMIT 分支\n")
		step.WithPhaseAction(processor.PHASE_MATCHED)
		fmt.Printf("[DEBUG processInputPolicy] 已设置 phaseAction=PHASE_MATCHED，当前值: %d\n", int(step.GetPhaseAction()))
		step.WithMatchResult(result.(processor.AbstractMatchResult))
		// 已经匹配到策略，不需要再生成策略
		logger.Info("INPUT_POLICY: 允许通过（匹配到策略）", zap.Any("Action", result.Action()))

	case result.Action() == int(POLICY_DENY):
		fmt.Printf("[DEBUG processInputPolicy] 进入 DENY 分支\n")
		if !force {
			logger.Warn("INPUT_POLICY: 拒绝通过", zap.Any("Action", result.Action()), zap.Any("Rule", result.(*PolicyMatchResult).Rule()))
			return nil, nil, nil, model.NewProcessErr(fmt.Sprintf("INPUT_POLICY Deny, Rule:[%s]", result.(*PolicyMatchResult).Rule().Cli()), model.PolicyDeny)
		}
		fallthrough

	default:
		fmt.Printf("[DEBUG processInputPolicy] 进入 default 分支（生成策略）\n")
		step.WithPhaseAction(processor.PHASE_GENERATED)
		fmt.Printf("[DEBUG processInputPolicy] 已设置 phaseAction=PHASE_GENERATED，当前值: %d\n", int(step.GetPhaseAction()))
		logger.Info("INPUT_POLICY: 策略生成...")

		flyObjects, cmds, moveRule := node.(FirewallTemplates).MakeInputPolicyCli(inPort, outPort, translateTo, ctx)
		additionCli = append(additionCli, moveRule...)
		cmdList = append(cmdList, cmds)

		logger.Debug("INPUT_POLICY: ", zap.Any("FlyObject", flyObjects), zap.Any("CmdList", cmds))

		node.FlyConfig(flyObjects)
		resultFly := node.InputPolicy(translateTo, inPort, outPort)

		if resultFly.Action() != int(POLICY_PERMIT) {
			errStr := fmt.Sprintf("fly config failed(INPUT_POLICY: 策略生成...), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
			return nil, nil, nil, model.NewProcessErr(errStr, model.SimylationVerificationFailed)
		}

		logger.Info("INPUT_POLICY: 策略FlyConfig运行正常")
		step.WithCmdList(cmds)
		step.WithMatchResult(result.(processor.AbstractMatchResult))
		cliStr := node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, ctx)
		step.WithCli(cliStr)
		fmt.Printf("[DEBUG processInputPolicy] 已设置 CmdList 和 CLI，phaseAction: %d, hasCli: %v, hasCmdList: %v\n",
			int(step.GetPhaseAction()), step.GetCli() != "", step.GetCmdList() != nil)

		if ru, ok := resultFly.(*PolicyMatchResult); ok && ru.Rule() != nil {
			ctx.WithValue("INPUT_POLICY", ru)
		}
	}

	fmt.Printf("[DEBUG processInputPolicy] 函数返回前，step 最终状态: phaseAction=%d, hasCli=%v, hasCmdList=%v\n",
		int(step.GetPhaseAction()), step.GetCli() != "", step.GetCmdList() != nil)
	return translateTo, cmdList, additionCli, model.ProcessErr{}
}

func (fp *FirewallProcess) processOutputPolicy(intent *policy.Intent, inPort, outPort api.Port, vrf api.Vrf, force bool, logger *zap.Logger, ctx *PolicyContext) (*policy.Intent, []interface{}, []string, model.ProcessErr) {
	step, ok := fp.GetSteps()[OUTPUT_POLICY.String()]
	if !ok {
		logger.Info("OUTPUT_POLICY: 未找到步骤", zap.String("Step", OUTPUT_POLICY.String()))
		return intent, nil, nil, model.ProcessErr{}
	}
	node := fp.GetNode().(FirewallNode)
	translateTo := intent
	cmdList := []interface{}{}
	additionCli := []string{}

	logger.Info("OUTPUT_POLICY: 策略检查")
	result := node.OutputPolicy(translateTo, inPort, outPort)
	step.WithMatchResult(result.(processor.AbstractMatchResult))

	if ru, ok := result.(*PolicyMatchResult); ok && ru.Rule() != nil {
		logger.Info("OUTPUT_POLICY现有策略", zap.String("Rule", ru.Rule().Cli()))
		step.WithRule(ru.Rule().Cli())
	}

	switch {
	case result.Action() == int(POLICY_PERMIT) || result.Action() == int(POLICY_IMPLICIT_PERMIT):
		step.WithPhaseAction(processor.PHASE_MATCHED)
		logger.Info("OUTPUT_POLICY: 允许通过", zap.Any("Action", result.Action()))

	case result.Action() == int(POLICY_DENY):
		if !force {
			logger.Warn("OUTPUT_POLICY: 拒绝通过", zap.Any("Action", result.Action()), zap.Any("Rule", result.(*PolicyMatchResult).Rule()))
			return nil, nil, nil, model.NewProcessErr(fmt.Sprintf("OUTPUT_POLICY Deny, Rule:[%s]", result.(*PolicyMatchResult).Rule().Cli()), model.PolicyDeny)
		}
		fallthrough

	default:
		step.WithPhaseAction(processor.PHASE_GENERATED)
		logger.Info("OUTPUT_POLICY: 策略生成...")

		flyObjects, cmds := node.(FirewallTemplates).MakeOutputPolicyCli(inPort, outPort, translateTo, ctx)
		cmdList = append(cmdList, cmds)

		logger.Debug("OUTPUT_POLICY: ", zap.Any("FlyObject", flyObjects), zap.Any("CmdList", cmds))

		node.FlyConfig(flyObjects)
		resultFly := node.OutputPolicy(translateTo, inPort, outPort)

		if resultFly.Action() != int(POLICY_PERMIT) {
			errStr := fmt.Sprintf("fly config failed(OUTPUT_POLICY: 策略生成...), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
			return nil, nil, nil, model.NewProcessErr(errStr, model.SimylationVerificationFailed)
		}

		logger.Info("OUTPUT_POLICY: 策略FlyConfig运行正常")
		step.WithCmdList(cmds)
		step.WithMatchResult(result.(processor.AbstractMatchResult))
		step.WithCli(node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, ctx))
	}

	return translateTo, cmdList, additionCli, model.ProcessErr{}
}

func (fp *FirewallProcess) processOutputNat(intent *policy.Intent, inPort, outPort api.Port, vrf api.Vrf, force bool, logger *zap.Logger, ctx *PolicyContext) (*policy.Intent, []interface{}, []string, model.ProcessErr) {
	step, ok := fp.GetSteps()[OUTPUT_NAT.String()]
	if !ok {
		logger.Info("OUTPUT_NAT: 未找到步骤", zap.String("Step", OUTPUT_NAT.String()))
		return intent, nil, nil, model.ProcessErr{}
	}
	node := fp.GetNode().(FirewallNode)
	translateTo := intent
	cmdList := []interface{}{}
	additionCli := []string{}

	logger.Info("OUTPUT_NAT: 策略检查")
	result := node.OutputNat(intent, inPort, outPort)
	step.WithMatchResult(result.(processor.AbstractMatchResult))

	if ru, ok := result.(*NatMatchResult); ok && ru.Rule() != nil {
		logger.Info("OUTPUT_NAT现有策略", zap.String("Rule", ru.Rule().Cli()))
		step.WithRule(ru.Rule().Cli())
	}

	if result.(*NatMatchResult).MeetStatus() == MEET_INTENT_NO {
		if result.Action() == int(NAT_MATCHED) {
			errStr := fmt.Sprintf("nat matched, but not meet intent(OUTPUT_NAT: 策略检查), Rule:[%s]", result.(*NatMatchResult).Rule().Cli())
			return nil, nil, nil, model.NewProcessErr(errStr, model.ConfigConflict)
		}

		// 如果匹配结果为空（NAT_NOMATCHED）且 Intent.Snat 为空，则不进行 OutputNat 处理
		if result.Action() == int(NAT_NOMATCHED) && intent.Snat == "" {
			logger.Info("OUTPUT_NAT: 匹配结果为空且Intent.Snat为空，跳过处理")
			step.WithPhaseAction(processor.PHASE_MATCHED)
			return intent, nil, nil, model.ProcessErr{}
		}

		step.WithPhaseAction(processor.PHASE_GENERATED)
		logger.Info("OUTPUT_NAT: 策略生成...")
		flyObjects, cmds := node.(FirewallTemplates).MakeDynamicNatCli(inPort, outPort, intent, ctx)
		cmdList = append(cmdList, cmds)

		logger.Debug("OUTPUT_NAT: ", zap.Any("FlyObject", flyObjects), zap.Any("CmdList", cmds))

		node.FlyConfig(flyObjects)
		resultFly := node.OutputNat(intent, inPort, outPort)
		if resultFly.(*NatMatchResult).MeetStatus() != MEET_INTENT_OK {
			errStr := fmt.Sprintf("fly config failed(OUTPUT_NAT: 策略生成...), TranslateTo:[%s] Inport:[%s] OutPort:[%s] Fly:[%s]", translateTo.String(), inPort.Name(), outPort.Name(), resultFly.Cli())
			return nil, nil, nil, model.NewProcessErr(errStr, model.SimylationVerificationFailed)
		}

		logger.Info("OUTPUT_NAT: 策略FlyConfig运行正常")
		translateTo = resultFly.(*NatMatchResult).TranslateTo()
		logger.Info("OUTPUT_NAT: TranslateTo", zap.Any("TranslateTo", translateTo))

		step.WithCmdList(cmds)
		step.WithCli(node.(FirewallTemplates).FlyObjectToFlattenCli(flyObjects, ctx))
	} else {
		step.WithPhaseAction(processor.PHASE_MATCHED)
		logger.Info("OUTPUT_NAT: 匹配到现有策略", zap.Any("Rule", result.(*NatMatchResult).Rule()))
	}

	return translateTo, cmdList, additionCli, model.ProcessErr{}
}
