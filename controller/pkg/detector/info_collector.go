package detector

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/sshtool"
	agentStruct "github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/utils/snmp"
	clitask "github.com/netxops/utils/task"
	"gopkg.in/yaml.v2"
)

// InfoCollector 信息采集器
// MVP: 基于配置文件的信息采集模块
type InfoCollector struct {
	config *DeviceInfoCollectConfig
}

// NewInfoCollector 创建信息采集器
func NewInfoCollector(templatePath string) (*InfoCollector, error) {
	config, err := loadCollectConfig(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load collect config: %w", err)
	}

	return &InfoCollector{
		config: config,
	}, nil
}

// Collect 采集设备信息
// 基于配置文件中的策略和采集项进行采集
func (ic *InfoCollector) Collect(req *DetectionRequest, protocols map[string]bool) (CollectedData, error) {
	collectedData := make(CollectedData)

	log.Printf("Starting device info collection for %s, available protocols: %v", req.IP, protocols)

	// 按优先级排序策略
	sortedStrategies := make([]CollectStrategy, 0, len(ic.config.Strategies))
	for _, strategy := range ic.config.Strategies {
		if ic.matchConditions(strategy.Conditions, protocols) {
			sortedStrategies = append(sortedStrategies, strategy)
		}
	}

	// 简单排序（按priority）
	for i := 0; i < len(sortedStrategies)-1; i++ {
		for j := i + 1; j < len(sortedStrategies); j++ {
			if sortedStrategies[i].Priority > sortedStrategies[j].Priority {
				sortedStrategies[i], sortedStrategies[j] = sortedStrategies[j], sortedStrategies[i]
			}
		}
	}

	// 执行每个策略的采集
	hasCollectedData := false
	for _, strategy := range sortedStrategies {
		log.Printf("Executing collection strategy: %s", strategy.Name)
		if err := ic.executeStrategy(req, strategy, collectedData); err != nil {
			log.Printf("Strategy %s failed: %v", strategy.Name, err)
			// 继续执行下一个策略
			continue
		}
		// 检查是否采集到数据
		if len(collectedData) > 0 {
			hasCollectedData = true
		}
	}

	log.Printf("Total collected data for %s: %d fields", req.IP, len(collectedData))

	// 如果没有采集到任何数据，返回错误
	if !hasCollectedData && len(collectedData) == 0 {
		return nil, fmt.Errorf("no data collected from %s with available protocols: %v", req.IP, protocols)
	}

	return collectedData, nil
}

// matchConditions 匹配条件
func (ic *InfoCollector) matchConditions(conditions []Condition, protocols map[string]bool) bool {
	for _, condition := range conditions {
		available, exists := protocols[condition.Protocol]
		if !exists || available != condition.Available {
			return false
		}
	}
	return true
}

// executeStrategy 执行采集策略
func (ic *InfoCollector) executeStrategy(req *DetectionRequest, strategy CollectStrategy, data CollectedData) error {
	for _, item := range strategy.Collect {
		// 解析输出字段（支持多个字段，用逗号分隔）
		outputFields := strings.Split(item.Output, ",")
		for i := range outputFields {
			outputFields[i] = strings.TrimSpace(outputFields[i])
		}

		// 检查是否所有字段都已采集（避免重复）
		allCollected := true
		for _, field := range outputFields {
			if _, exists := data[field]; !exists {
				allCollected = false
				break
			}
		}
		if allCollected {
			continue
		}

		// 执行采集
		values, err := ic.collectItem(req, item)
		if err != nil {
			if item.Required {
				// 如果是必填项，记录错误但继续尝试其他项
				// 如果所有必填项都失败，规则匹配阶段会处理
				log.Printf("Required item %s collection failed: %v (will continue with other items)", item.Name, err)
				continue
			}
			log.Printf("Item %s collection failed: %v", item.Name, err)
			continue
		}

		// 存储采集结果（支持多个字段）
		hasValue := false
		for i, field := range outputFields {
			if i < len(values) && values[i] != "" {
				data[field] = values[i]
				hasValue = true
				log.Printf("Collected %s: %s", field, values[i][:min(100, len(values[i]))])
			}
		}
		if !hasValue {
			log.Printf("Item %s collected but no values extracted", item.Name)
		}
	}

	return nil
}

// collectItem 采集单个项
// 返回多个值（支持一次采集多个字段，如sysDescr和sysName）
func (ic *InfoCollector) collectItem(req *DetectionRequest, item CollectItem) ([]string, error) {
	timeout := parseTimeout(item.Timeout)
	if timeout == 0 {
		timeout = 10 * time.Second // 默认10秒
	}

	switch item.Method {
	case "SNMP":
		return ic.collectSNMP(req, item, timeout)

	case "SSH":
		value, err := ic.collectSSH(req, item, timeout)
		return []string{value}, err

	case "TELNET":
		value, err := ic.collectTelnet(req, item, timeout)
		return []string{value}, err

	default:
		return nil, fmt.Errorf("unsupported method: %s", item.Method)
	}
}

// collectSNMP 通过SNMP采集
// 返回多个值（支持一次采集多个字段）
func (ic *InfoCollector) collectSNMP(req *DetectionRequest, item CollectItem, timeout time.Duration) ([]string, error) {
	if req.SNMPCommunity == "" {
		return nil, fmt.Errorf("SNMP community not provided")
	}

	// 解析输出字段
	outputFields := strings.Split(item.Output, ",")
	for i := range outputFields {
		outputFields[i] = strings.TrimSpace(outputFields[i])
	}

	// 从配置中读取SNMP参数，如果没有则使用默认值
	oid := item.Target
	indexPositions := []int{1}
	classifierPositions := []int{0}
	prefixMap := make(map[string]string)

	if item.SNMPConfig != nil {
		// 使用配置中的参数
		if len(item.SNMPConfig.IndexPositions) > 0 {
			indexPositions = item.SNMPConfig.IndexPositions
		}
		if len(item.SNMPConfig.ClassifierPositions) > 0 {
			classifierPositions = item.SNMPConfig.ClassifierPositions
		}
		if len(item.SNMPConfig.PrefixMap) > 0 {
			prefixMap = item.SNMPConfig.PrefixMap
		}
	} else {
		// 默认配置：根据OID类型自动推断
		if strings.HasSuffix(oid, ".0") {
			// 单个标量OID，使用父OID
			parentOID := strings.TrimSuffix(oid, ".0")
			lastPart := parentOID[strings.LastIndex(parentOID, ".")+1:]
			oid = parentOID[:strings.LastIndex(parentOID, ".")]
			if len(outputFields) > 0 {
				prefixMap[lastPart] = outputFields[0]
			}
		} else {
			// 父OID，默认配置
			if strings.Contains(oid, "1.3.6.1.2.1.1") {
				prefixMap["1"] = "sysDescr"
				prefixMap["5"] = "sysName"
			}
		}
	}

	st, err := snmp.NewSnmpTask(
		req.IP,
		req.SNMPCommunity,
		oid,
		indexPositions,
		classifierPositions,
		prefixMap,
		map[string]func(byte, string, interface{}) (string, error){},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SNMP task: %w", err)
	}

	// 使用带超时的SNMP操作
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type snmpResult struct {
		table *clitask.Table
		err   error
	}
	resultChan := make(chan snmpResult, 1)

	go func() {
		st.Run(true)
		tbl, err := st.Table()
		resultChan <- snmpResult{table: tbl, err: err}
	}()

	select {
	case res := <-resultChan:
		if res.err != nil {
			return nil, res.err
		}
		if res.table != nil && res.table.RowCount() > 0 {
			// 提取所有输出字段的值
			values := make([]string, len(outputFields))
			for i, field := range outputFields {
				value, ok := res.table.IndexToValue(field, "0")
				if !ok {
					value, ok = res.table.IndexToValue(field, "1")
				}
				if ok && value != "" {
					values[i] = value
				}
			}
			// 如果至少有一个值，返回结果
			hasValue := false
			for _, v := range values {
				if v != "" {
					hasValue = true
					break
				}
			}
			if hasValue {
				return values, nil
			}
		}
		return nil, fmt.Errorf("no value found for %s", item.Output)
	case <-ctx.Done():
		return nil, fmt.Errorf("SNMP operation timeout after %v", timeout)
	}
}

// collectSSH 通过SSH采集
func (ic *InfoCollector) collectSSH(req *DetectionRequest, item CollectItem, timeout time.Duration) (string, error) {
	if req.SSHCredentials == nil {
		return "", fmt.Errorf("SSH credentials not provided")
	}

	remoteInfo := &agentStruct.L2DeviceRemoteInfo{
		Ip:         req.IP,
		Username:   req.SSHCredentials.Username,
		Password:   req.SSHCredentials.Password,
		PrivateKey: req.SSHCredentials.PrivateKey,
	}
	if req.SSHCredentials.Port > 0 {
		remoteInfo.Meta = agentStruct.Meta{
			SSHPort: req.SSHCredentials.Port,
		}
	} else {
		remoteInfo.Meta = agentStruct.Meta{
			SSHPort: 22,
		}
	}

	// 构建命令列表（主命令 + fallback命令）
	commands := []string{item.Target}
	for _, fallback := range item.Fallback {
		commands = append(commands, fallback.Target)
	}

	// 在一个SSH会话中执行所有命令，复用连接避免重复认证
	successfulCommand, result, err := sshtool.ExecuteSSHCommandsInteractive(
		remoteInfo,
		commands,
		timeout,
		func(output, command string) bool {
			return ic.isValidCommandOutput(output, command)
		},
	)

	if err == nil && result != "" {
		if successfulCommand == item.Target {
			log.Printf("Successfully collected %s using interactive command: %s", item.Name, item.Target)
		} else {
			log.Printf("Successfully collected %s using interactive fallback command: %s", item.Name, successfulCommand)
		}
		return result, nil
	}

	if err != nil {
		log.Printf("All SSH commands failed for %s: %v", item.Name, err)
	}

	return "", fmt.Errorf("all SSH commands failed or returned invalid output for %s", item.Name)
}

// executeSSHCommands 执行SSH命令
func (ic *InfoCollector) executeSSHCommands(remoteInfo *agentStruct.L2DeviceRemoteInfo, commands []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type sshResult struct {
		table *clitask.Table
		err   error
	}
	sshChan := make(chan sshResult, 1)

	go func() {
		tbl, err := sshtool.ExecuteSSHCommands(remoteInfo, convertToInterfaceSlice(commands))
		sshChan <- sshResult{table: tbl, err: err}
	}()

	select {
	case res := <-sshChan:
		if res.err != nil {
			return "", res.err
		}
		if res.table != nil {
			var output strings.Builder
			hasValidOutput := false
			res.table.ForEach(func(t *clitask.Table, index string, row map[string]string) error {
				// 只处理成功执行的命令
				if row["status"] == "true" && row["output"] != "" {
					outputText := strings.TrimSpace(row["output"])

					// 尝试从输出中提取命令输出部分（去除banner）
					cleanedOutput := ic.extractCommandOutput(outputText, row["command"])
					if cleanedOutput != "" && cleanedOutput != outputText {
						// 如果提取到了不同的内容，使用提取的内容
						outputText = cleanedOutput
						log.Printf("Extracted command output from banner: command=%s, original_len=%d, cleaned_len=%d",
							row["command"], len(row["output"]), len(outputText))
					}

					// 检查输出是否是有效的命令输出（不是banner或错误信息）
					if ic.isValidCommandOutput(outputText, row["command"]) {
						if output.Len() > 0 {
							output.WriteString("\n")
						}
						output.WriteString(outputText)
						hasValidOutput = true
					} else {
						log.Printf("SSH command output appears to be banner or invalid: command=%s, output_preview=%s",
							row["command"], outputText[:min(100, len(outputText))])
					}
				} else if row["status"] == "false" {
					log.Printf("SSH command failed: command=%s, error=%s", row["command"], row["msg"])
				}
				return nil
			})
			if hasValidOutput {
				return output.String(), nil
			}
			return "", fmt.Errorf("no valid output from SSH command (may be banner or error)")
		}
		return "", fmt.Errorf("no output from SSH command")
	case <-ctx.Done():
		return "", fmt.Errorf("SSH operation timeout after %v", timeout)
	}
}

// isValidCommandOutput 检查输出是否是有效的命令输出
// 过滤掉banner、错误信息等无效输出
// 如果输出包含banner但后面有命令输出，尝试提取命令输出部分
func (ic *InfoCollector) isValidCommandOutput(output, command string) bool {
	if output == "" {
		return false
	}

	// 首先尝试从输出中提取命令输出部分（去除banner）
	cleanedOutput := ic.extractCommandOutput(output, command)
	if cleanedOutput != "" && cleanedOutput != output {
		// 如果提取到了不同的内容，使用提取的内容进行验证
		output = cleanedOutput
	}

	outputLower := strings.ToLower(output)

	// 检查是否是banner（包含常见的banner关键词）
	bannerKeywords := []string{
		"copyright",
		"all rights reserved",
		"without the owner",
		"prior written",
		"login:",
		"password:",
		"welcome to",
		"****************************************************************",
	}

	// 如果输出主要是banner内容（超过50%是banner关键词），认为是无效的
	bannerCount := 0
	for _, keyword := range bannerKeywords {
		if strings.Contains(outputLower, keyword) {
			bannerCount++
		}
	}

	// 如果包含多个banner关键词，且没有其他有效内容，很可能是banner
	if bannerCount >= 2 {
		// 检查是否包含命令输出（不是纯banner）
		// 如果输出中有换行符分隔的内容，可能是banner+命令输出
		lines := strings.Split(output, "\n")
		nonBannerLines := 0
		for _, line := range lines {
			lineTrimmed := strings.TrimSpace(line)
			if lineTrimmed != "" && !ic.isBannerLine(lineTrimmed) {
				nonBannerLines++
			}
		}
		// 如果大部分行都是banner，认为是无效的
		if nonBannerLines < len(lines)/3 {
			return false
		}
	}

	// 检查输出是否看起来像错误信息
	errorPatterns := []string{
		"command not found",
		"no such file",
		"permission denied",
		"invalid command",
		"unknown command",
		"unrecognized command",
		"syntax error",
		"error:",
		"error ",
		"failed",
		"cannot",
		"unable to",
		"not found",
		"not recognized",
	}
	for _, pattern := range errorPatterns {
		if strings.Contains(outputLower, pattern) {
			return false
		}
	}

	// 检查是否以 "Error:" 开头（华为设备常见错误格式）
	outputTrimmed := strings.TrimSpace(output)
	if strings.HasPrefix(outputTrimmed, "Error:") || strings.HasPrefix(outputTrimmed, "error:") {
		return false
	}

	// 检查输出是否太短（可能是空输出或只有提示符）
	if len(strings.TrimSpace(output)) < 10 {
		return false
	}

	// 如果输出主要是星号或特殊字符，可能是banner
	nonPrintableRatio := 0.0
	if len(output) > 0 {
		nonPrintableCount := 0
		for _, r := range output {
			if r == '*' || r == '-' || r == '=' || r == '_' {
				nonPrintableCount++
			}
		}
		nonPrintableRatio = float64(nonPrintableCount) / float64(len(output))
	}
	if nonPrintableRatio > 0.3 { // 如果超过30%是特殊字符，可能是banner
		return false
	}

	return true
}

// extractCommandOutput 从混合输出中提取命令输出部分
// 尝试去除banner，只保留命令输出
func (ic *InfoCollector) extractCommandOutput(output, command string) string {
	lines := strings.Split(output, "\n")

	// 如果输出完全是banner（所有行都是banner），返回空字符串
	allBanner := true
	for _, line := range lines {
		lineTrimmed := strings.TrimSpace(line)
		if lineTrimmed != "" && !ic.isBannerLine(lineTrimmed) && !ic.isCommandPromptLine(lineTrimmed) {
			allBanner = false
			break
		}
	}
	if allBanner {
		return "" // 完全是banner，没有命令输出
	}

	// 策略1: 查找命令提示符（如 <FW-HX>show system），提取命令后的输出
	commandStartIndex := -1
	for i, line := range lines {
		lineTrimmed := strings.TrimSpace(line)
		// 检查是否是命令提示符行（包含命令）
		// 格式：<prompt>command 或 prompt>command
		if ic.isCommandPromptLine(lineTrimmed) && strings.Contains(lineTrimmed, command) {
			// 找到命令所在的行，提取命令后的输出
			commandStartIndex = i + 1
			break
		}
	}

	// 如果找到了命令，提取命令后的内容
	if commandStartIndex >= 0 && commandStartIndex < len(lines) {
		commandLines := lines[commandStartIndex:]
		// 过滤掉banner行和命令提示符行
		filteredLines := make([]string, 0)
		for _, line := range commandLines {
			lineTrimmed := strings.TrimSpace(line)
			if !ic.isBannerLine(lineTrimmed) && !ic.isCommandPromptLine(lineTrimmed) && lineTrimmed != "" {
				filteredLines = append(filteredLines, line)
			}
		}
		if len(filteredLines) > 0 {
			result := strings.Join(filteredLines, "\n")
			return strings.TrimSpace(result)
		}
	}

	// 策略2: 查找banner结束的位置
	// Banner通常以星号行开始和结束
	bannerEndIndex := -1
	for i, line := range lines {
		lineTrimmed := strings.TrimSpace(line)
		// 如果遇到空行或非banner内容，可能是命令输出的开始
		if lineTrimmed == "" || (!ic.isBannerLine(lineTrimmed) && !ic.isCommandPromptLine(lineTrimmed) && len(lineTrimmed) > 5) {
			// 检查前面是否有banner
			if i > 0 {
				prevLine := strings.TrimSpace(lines[i-1])
				if ic.isBannerLine(prevLine) || strings.Contains(strings.ToLower(prevLine), "copyright") {
					bannerEndIndex = i
					break
				}
			} else if !ic.isBannerLine(lineTrimmed) && !ic.isCommandPromptLine(lineTrimmed) {
				// 第一行就不是banner，可能是直接的命令输出
				bannerEndIndex = 0
				break
			}
		}
	}

	// 如果找到了banner结束位置，提取后面的内容
	if bannerEndIndex >= 0 && bannerEndIndex < len(lines) {
		commandLines := lines[bannerEndIndex:]
		// 过滤掉banner行和命令提示符行
		filteredLines := make([]string, 0)
		for _, line := range commandLines {
			lineTrimmed := strings.TrimSpace(line)
			if !ic.isBannerLine(lineTrimmed) && !ic.isCommandPromptLine(lineTrimmed) {
				filteredLines = append(filteredLines, line)
			}
		}
		if len(filteredLines) > 0 {
			result := strings.Join(filteredLines, "\n")
			return strings.TrimSpace(result)
		}
	}

	// 策略3: 如果没有找到明显的banner结束位置，尝试查找命令提示符后的内容
	// 网络设备通常在命令输出后会有提示符（如 >, #, ]）
	for i := len(lines) - 1; i >= 0; i-- {
		lineTrimmed := strings.TrimSpace(lines[i])
		// 如果行尾有提示符，可能是命令输出的结束
		if strings.HasSuffix(lineTrimmed, ">") ||
			strings.HasSuffix(lineTrimmed, "#") ||
			strings.HasSuffix(lineTrimmed, "]") ||
			strings.HasSuffix(lineTrimmed, "$") ||
			ic.isCommandPromptLine(lineTrimmed) {
			// 提取提示符之前的内容，并过滤掉banner行和命令提示符行
			if i > 0 {
				filteredLines := make([]string, 0)
				for j := 0; j < i; j++ {
					lineTrimmed := strings.TrimSpace(lines[j])
					if !ic.isBannerLine(lineTrimmed) && !ic.isCommandPromptLine(lineTrimmed) && lineTrimmed != "" {
						filteredLines = append(filteredLines, lines[j])
					}
				}
				if len(filteredLines) > 0 {
					result := strings.Join(filteredLines, "\n")
					return strings.TrimSpace(result)
				}
			}
		}
	}

	// 策略4: 如果无法提取，但输出不完全是banner，尝试过滤掉banner行和命令提示符行后返回
	filteredLines := make([]string, 0)
	for _, line := range lines {
		lineTrimmed := strings.TrimSpace(line)
		if !ic.isBannerLine(lineTrimmed) && !ic.isCommandPromptLine(lineTrimmed) && lineTrimmed != "" {
			filteredLines = append(filteredLines, line)
		}
	}
	if len(filteredLines) > 0 {
		result := strings.Join(filteredLines, "\n")
		return strings.TrimSpace(result)
	}

	// 如果完全是banner，返回空字符串
	return ""
}

// isCommandPromptLine 检查一行是否是命令提示符行
// 例如：<FW-HX>show system, Router>show version, [H3C]display version
func (ic *InfoCollector) isCommandPromptLine(line string) bool {
	lineTrimmed := strings.TrimSpace(line)
	if lineTrimmed == "" {
		return false
	}

	// 检查是否包含命令提示符模式
	// 格式1: <prompt>command (如 <FW-HX>show system)
	// 格式2: prompt>command (如 Router>show version)
	// 格式3: [prompt]command (如 [H3C]display version)
	if strings.HasPrefix(lineTrimmed, "<") && strings.Contains(lineTrimmed, ">") {
		return true
	}
	if strings.HasSuffix(lineTrimmed, ">") && len(lineTrimmed) < 100 {
		return true
	}
	if strings.HasPrefix(lineTrimmed, "[") && strings.Contains(lineTrimmed, "]") {
		return true
	}

	return false
}

// isBannerLine 检查一行是否是banner行
func (ic *InfoCollector) isBannerLine(line string) bool {
	lineTrimmed := strings.TrimSpace(line)
	if lineTrimmed == "" {
		return false
	}

	lineLower := strings.ToLower(lineTrimmed)

	// 检查是否是星号行或分隔线（整行都是特殊字符）
	if strings.Trim(lineTrimmed, "*") == "" ||
		strings.Trim(lineTrimmed, "-") == "" ||
		strings.Trim(lineTrimmed, "=") == "" ||
		strings.Trim(lineTrimmed, "_") == "" {
		return true
	}

	// 检查是否以星号开头（banner通常以 * 开头）
	// 例如：* no decompiling or reverse-engineering shall be allowed.
	if strings.HasPrefix(lineTrimmed, "*") {
		// 检查是否包含banner关键词
		bannerKeywords := []string{
			"copyright",
			"all rights reserved",
			"without the owner",
			"prior written",
			"no decompiling",
			"reverse-engineering",
			"shall be allowed",
		}
		for _, keyword := range bannerKeywords {
			if strings.Contains(lineLower, keyword) {
				return true
			}
		}
		// 如果以 * 开头且主要是特殊字符，也认为是banner
		if len(strings.Trim(lineTrimmed, "* \t")) < len(lineTrimmed)/2 {
			return true
		}
	}

	// 检查是否包含banner关键词（不限于以*开头）
	bannerKeywords := []string{
		"copyright",
		"all rights reserved",
		"without the owner",
		"prior written",
	}
	for _, keyword := range bannerKeywords {
		if strings.Contains(lineLower, keyword) {
			return true
		}
	}

	return false
}

// collectTelnet 通过TELNET采集
func (ic *InfoCollector) collectTelnet(req *DetectionRequest, item CollectItem, timeout time.Duration) (string, error) {
	// TODO: 实现TELNET采集
	return "", fmt.Errorf("TELNET collection not implemented yet")
}

// loadCollectConfig 加载采集配置
func loadCollectConfig(templatePath string) (*DeviceInfoCollectConfig, error) {
	configPath := filepath.Join(templatePath, "detect/device_info_collect.yaml")
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read collect config: %w", err)
	}

	var config DeviceInfoCollectConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal collect config: %w", err)
	}

	return &config, nil
}

// convertToInterfaceSlice 将字符串切片转换为interface{}切片
func convertToInterfaceSlice(strs []string) []interface{} {
	result := make([]interface{}, len(strs))
	for i, s := range strs {
		result[i] = s
	}
	return result
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
