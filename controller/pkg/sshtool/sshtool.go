package sshtool

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	clitask "github.com/netxops/utils/task"

	"golang.org/x/crypto/ssh"
)

const (
	// 交互式SSH相关常量
	loginWaitTime       = 500 * time.Millisecond // 登录后等待时间
	bannerTimeout       = 1 * time.Second        // Banner读取超时
	promptDetectTimeout = 2 * time.Second        // 提示符检测超时
	commandWaitTime     = 500 * time.Millisecond // 命令发送后等待时间
	readChunkTimeout    = 1 * time.Second        // 每次读取块超时
	promptVerifyTimeout = 2 * time.Second        // 提示符验证超时
	carriageReturnWait  = 300 * time.Millisecond // 回车后等待时间
)

// setReadDeadline 设置读取超时（如果reader支持）
func setReadDeadline(reader io.Reader, deadline time.Time) error {
	if r, ok := reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return r.SetReadDeadline(deadline)
	}
	return nil
}

// readLineWithTimeout 带超时读取一行（改进版：持续读取直到换行符或超时）
func readLineWithTimeout(reader io.Reader, timeout time.Duration) (string, error) {
	type result struct {
		line string
		err  error
	}
	resultChan := make(chan result, 1)

	go func() {
		buf := make([]byte, 4096)
		var line bytes.Buffer
		deadline := time.Now().Add(timeout)

		for time.Now().Before(deadline) {
			remainingTime := time.Until(deadline)
			if remainingTime <= 0 {
				break
			}

			// 设置读取超时
			setReadDeadline(reader, time.Now().Add(remainingTime))

			n, err := reader.Read(buf)
			if n > 0 {
				data := buf[:n]
				// 查找换行符
				for i, b := range data {
					if b == '\n' {
						line.Write(data[:i])
						// 移除可能的 \r
						lineBytes := line.Bytes()
						if len(lineBytes) > 0 && lineBytes[len(lineBytes)-1] == '\r' {
							lineBytes = lineBytes[:len(lineBytes)-1]
						}
						resultChan <- result{line: string(lineBytes), err: nil}
						return
					}
				}
				line.Write(data)
			}
			if err != nil {
				if err == io.EOF {
					// EOF时返回已读取的内容（即使没有换行符）
					if line.Len() > 0 {
						lineBytes := line.Bytes()
						if len(lineBytes) > 0 && lineBytes[len(lineBytes)-1] == '\r' {
							lineBytes = lineBytes[:len(lineBytes)-1]
						}
						resultChan <- result{line: string(lineBytes), err: nil}
						return
					}
				}
				// 其他错误，如果已有数据则返回，否则返回错误
				if line.Len() > 0 {
					lineBytes := line.Bytes()
					if len(lineBytes) > 0 && lineBytes[len(lineBytes)-1] == '\r' {
						lineBytes = lineBytes[:len(lineBytes)-1]
					}
					resultChan <- result{line: string(lineBytes), err: nil}
					return
				}
				resultChan <- result{line: "", err: err}
				return
			}
		}

		// 超时：如果有数据则返回，否则返回超时错误
		if line.Len() > 0 {
			lineBytes := line.Bytes()
			if len(lineBytes) > 0 && lineBytes[len(lineBytes)-1] == '\r' {
				lineBytes = lineBytes[:len(lineBytes)-1]
			}
			resultChan <- result{line: string(lineBytes), err: nil}
			return
		}
		resultChan <- result{line: "", err: fmt.Errorf("read timeout after %v", timeout)}
	}()

	select {
	case res := <-resultChan:
		return res.line, res.err
	case <-time.After(timeout + 100*time.Millisecond): // 额外缓冲
		return "", fmt.Errorf("read timeout after %v", timeout)
	}
}

type SSHClient struct {
	client *ssh.Client
}

func NewSSHClient(remote *structs.L2DeviceRemoteInfo) (*SSHClient, error) {
	config := &ssh.ClientConfig{
		User: remote.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(remote.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	config.SetDefaults()

	// Extend the default ciphers
	config.Config.Ciphers = append(config.Config.Ciphers, []string{
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com",
		"arcfour256", "arcfour128", "arcfour",
		"aes128-cbc", "aes192-cbc", "aes256-cbc",
		"3des-cbc",
	}...)

	// Extend the default key exchanges
	config.Config.KeyExchanges = append(config.Config.KeyExchanges, []string{
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
	}...)

	// Extend the default MACs
	config.Config.MACs = append(config.Config.MACs, []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-256",
		"hmac-sha1",
		"hmac-sha1-96",
	}...)

	// Add more host key algorithms
	// config.HostKeyAlgorithms = append(config.HostKeyAlgorithms, []string{
	// 	ssh.KeyAlgoRSA,
	// 	ssh.KeyAlgoDSA,
	// 	ssh.KeyAlgoECDSA256,
	// 	ssh.KeyAlgoECDSA384,
	// 	ssh.KeyAlgoECDSA521,
	// 	ssh.KeyAlgoED25519,
	// }...)

	timeout := time.Duration(30) * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", remote.Ip, remote.Meta.SSHPort), timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", remote.Ip, remote.Meta.SSHPort), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client connection: %v", err)
	}

	client := ssh.NewClient(c, chans, reqs)
	return &SSHClient{client: client}, nil
}

func (s *SSHClient) ExecuteCommand(command string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	err = session.Run(command)
	if err != nil {
		return "", fmt.Errorf("failed to run command: %v", err)
	}

	return stdoutBuf.String(), nil
}

func (s *SSHClient) Close() {
	s.client.Close()
}

func ExecuteSSHCommands(remote *structs.L2DeviceRemoteInfo, options []interface{}) (*clitask.Table, error) {
	sshClient, err := NewSSHClient(remote)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client: %v", err)
	}
	defer sshClient.Close()

	result := clitask.NewEmptyTableWithKeys([]string{"command", "key", "output", "msg", "status"})

	for index, ops := range options {
		cmd, ok := ops.(string)
		if !ok {
			continue
		}
		key := strings.Join(strings.Fields(cmd), "_")
		key = fmt.Sprintf("%s_%d", key, index+1)

		output, err := sshClient.ExecuteCommand(cmd)
		if err != nil {
			result.PushRow(fmt.Sprint(index+1), map[string]string{
				"command": cmd,
				"key":     key,
				"output":  output,
				"msg":     err.Error(),
				"status":  "false",
			}, true, "")
		} else {
			result.PushRow(fmt.Sprint(index+1), map[string]string{
				"command": cmd,
				"key":     key,
				"output":  output,
				"msg":     "",
				"status":  "true",
			}, true, "")
		}
	}

	return result, nil
}

// ExecuteSSHCommandsInteractive 在一个SSH会话中执行多个命令
// 依次尝试执行命令列表，返回第一个成功的命令输出
// 这样可以复用SSH连接，避免重复认证
func ExecuteSSHCommandsInteractive(remote *structs.L2DeviceRemoteInfo, commands []string, timeout time.Duration, isValidOutput func(string, string) bool) (string, string, error) {
	if len(commands) == 0 {
		return "", "", fmt.Errorf("no commands provided")
	}

	sshClient, err := NewSSHClient(remote)
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH client: %v", err)
	}
	defer sshClient.Close()

	// 创建交互式会话
	session, err := sshClient.client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// 请求伪终端（PTY）以支持交互式命令
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // 启用回显
		ssh.TTY_OP_ISPEED: 14400, // 输入速度
		ssh.TTY_OP_OSPEED: 14400, // 输出速度
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", "", fmt.Errorf("failed to request PTY: %v", err)
	}

	// 创建stdin/stdout管道
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", "", fmt.Errorf("failed to create stdin pipe: %v", err)
	}
	defer stdin.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", "", fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// 启动shell
	if err := session.Shell(); err != nil {
		return "", "", fmt.Errorf("failed to start shell: %v", err)
	}

	// 创建带超时的context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 读取输出的goroutine
	type commandResult struct {
		command string
		output  string
		err     error
	}
	resultChan := make(chan commandResult, 1)

	go func() {
		defer close(resultChan)

		var outputBuffer bytes.Buffer
		startTime := time.Now()

		// 等待登录完成
		time.Sleep(loginWaitTime)

		// 检测提示符（只检测一次）
		prompt := detectPrompt(stdout, &outputBuffer, stdin)
		if prompt == "" {
			resultChan <- commandResult{err: fmt.Errorf("failed to detect prompt")}
			return
		}

		log.Printf("[SSH] Prompt detected: '%s'", prompt)

		// 清空banner输出
		outputBuffer.Reset()

		// 依次尝试执行每个命令
		for i, command := range commands {
			// 检查是否还有剩余时间
			elapsed := time.Since(startTime)
			if elapsed >= timeout {
				log.Printf("[SSH] Timeout reached, cannot try more commands")
				break
			}

			// 清空之前的输出（保留提示符检测的输出）
			if i > 0 {
				outputBuffer.Reset()
				// 等待一下，确保提示符已经出现
				time.Sleep(carriageReturnWait)
			}

			// 发送命令并读取输出
			fmt.Fprintf(stdin, "%s\r\n", command)
			time.Sleep(commandWaitTime)

			remainingTimeout := timeout - elapsed - 1*time.Second
			if remainingTimeout < 1*time.Second {
				remainingTimeout = 1 * time.Second
			}

			commandOutput := waitForCommandOutputWithTimeout(stdout, &outputBuffer, prompt, command, remainingTimeout)
			if commandOutput != "" {
				// 如果提供了验证函数，检查输出是否有效
				if isValidOutput != nil && !isValidOutput(commandOutput, command) {
					log.Printf("[SSH] Command '%s' returned invalid output, trying next command", command)
					continue
				}
				// 找到有效的输出，返回
				resultChan <- commandResult{command: command, output: commandOutput}
				return
			} else {
				log.Printf("[SSH] Command '%s' returned no output or timed out, trying next command", command)
			}
		}

		// 所有命令都失败了
		resultChan <- commandResult{err: fmt.Errorf("all commands failed or returned invalid output")}
	}()

	// 等待结果或超时
	select {
	case result := <-resultChan:
		if result.err != nil {
			return "", "", result.err
		}
		return result.command, result.output, nil
	case <-ctx.Done():
		session.Close()
		return "", "", fmt.Errorf("command execution timeout after %v", timeout)
	}
}

// ExecuteSSHCommandInteractive 交互式执行SSH命令
// 登录后等待提示符，发送命令，基于提示符判断命令完成
func ExecuteSSHCommandInteractive(remote *structs.L2DeviceRemoteInfo, command string, timeout time.Duration) (string, error) {
	sshClient, err := NewSSHClient(remote)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH client: %v", err)
	}
	defer sshClient.Close()

	// 创建交互式会话
	session, err := sshClient.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// 请求伪终端（PTY）以支持交互式命令
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // 启用回显
		ssh.TTY_OP_ISPEED: 14400, // 输入速度
		ssh.TTY_OP_OSPEED: 14400, // 输出速度
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", fmt.Errorf("failed to request PTY: %v", err)
	}

	// 创建stdin/stdout管道
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdin pipe: %v", err)
	}
	defer stdin.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// 启动shell
	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("failed to start shell: %v", err)
	}

	// 创建带超时的context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 读取输出的goroutine
	outputChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	go func() {
		defer close(outputChan)
		defer close(errorChan)

		var outputBuffer bytes.Buffer
		startTime := time.Now()

		// 等待登录完成
		time.Sleep(loginWaitTime)

		// 检测提示符
		prompt := detectPrompt(stdout, &outputBuffer, stdin)
		if prompt == "" {
			errorChan <- fmt.Errorf("failed to detect prompt")
			return
		}

		log.Printf("[SSH] Prompt detected: '%s'", prompt)

		// 清空banner输出
		outputBuffer.Reset()

		// 发送命令并读取输出
		fmt.Fprintf(stdin, "%s\r\n", command)
		time.Sleep(commandWaitTime)

		elapsed := time.Since(startTime)
		remainingTimeout := timeout - elapsed - 1*time.Second
		if remainingTimeout < 1*time.Second {
			remainingTimeout = 1 * time.Second
		}

		commandOutput := waitForCommandOutputWithTimeout(stdout, &outputBuffer, prompt, command, remainingTimeout)
		if commandOutput == "" {
			errorChan <- fmt.Errorf("command timeout or no output")
			return
		}

		outputChan <- commandOutput
	}()

	// 等待结果或超时
	select {
	case output := <-outputChan:
		return output, nil
	case err := <-errorChan:
		return "", err
	case <-ctx.Done():
		session.Close()
		return "", fmt.Errorf("command execution timeout after %v", timeout)
	}
}

// detectPrompt 检测提示符（统一入口）
func detectPrompt(reader io.Reader, output *bytes.Buffer, stdin io.Writer) string {
	// 步骤1: 尝试从banner中找提示符
	if prompt := findPromptInBanner(reader, output); prompt != "" {
		log.Printf("[SSH] Found prompt in banner: '%s'", prompt)
		// 验证提示符
		if verified := verifyPrompt(reader, output, stdin, prompt); verified != "" {
			return verified
		}
		log.Printf("[SSH] Prompt verification failed, trying carriage return method")
	}

	// 步骤2: 通过发送回车检测提示符
	prompt := detectPromptByCarriageReturn(reader, output, stdin)
	if prompt == "" {
		log.Printf("[SSH] Failed to detect prompt via carriage return")
	}
	return prompt
}

// findPromptInBanner 从banner中查找提示符
func findPromptInBanner(reader io.Reader, output *bytes.Buffer) string {
	deadline := time.Now().Add(bannerTimeout)
	maxLines := 50
	linesRead := 0

	for i := 0; i < maxLines && time.Now().Before(deadline); i++ {
		remainingTime := time.Until(deadline)
		if remainingTime <= 0 {
			break
		}

		line, err := readLineWithTimeout(reader, remainingTime)
		if err != nil {
			if linesRead == 0 {
				log.Printf("[SSH] Banner read error: %v", err)
			}
			break
		}

		if line != "" {
			linesRead++
			output.WriteString(line)
			output.WriteString("\n")
			if isPromptLine(line) {
				return strings.TrimSpace(line)
			}
		}
	}
	if linesRead == 0 {
		log.Printf("[SSH] No banner lines read")
	}
	return ""
}

// verifyPrompt 验证提示符
func verifyPrompt(reader io.Reader, output *bytes.Buffer, stdin io.Writer, expectedPrompt string) string {
	fmt.Fprintf(stdin, "\r\n")
	time.Sleep(carriageReturnWait)

	deadline := time.Now().Add(promptVerifyTimeout)
	for i := 0; i < 2 && time.Now().Before(deadline); i++ {
		remainingTime := time.Until(deadline)
		if remainingTime <= 0 {
			break
		}

		line, err := readLineWithTimeout(reader, remainingTime)
		if err != nil {
			break
		}

		if line != "" {
			output.WriteString(line)
			output.WriteString("\n")
			lineTrimmed := strings.TrimSpace(line)
			if lineTrimmed == expectedPrompt || strings.Contains(lineTrimmed, expectedPrompt) {
				return expectedPrompt
			}
			if isPromptLine(line) {
				return "" // 不同的提示符
			}
		}
	}
	return ""
}

// detectPromptByCarriageReturn 通过发送回车检测提示符
func detectPromptByCarriageReturn(reader io.Reader, output *bytes.Buffer, stdin io.Writer) string {
	const maxAttempts = 3
	promptCandidates := make([]string, 0)
	deadline := time.Now().Add(promptDetectTimeout)

	// 使用持续读取方式，累积所有数据
	var accumulatedData bytes.Buffer

	for i := 0; i < maxAttempts && time.Now().Before(deadline); i++ {
		fmt.Fprintf(stdin, "\r\n")
		time.Sleep(carriageReturnWait)

		remainingTime := time.Until(deadline)
		attemptTimeout := readChunkTimeout
		if remainingTime < attemptTimeout {
			attemptTimeout = remainingTime
		}
		if remainingTime <= 0 {
			break
		}

		// 持续读取数据，直到超时或找到换行符
		attemptDeadline := time.Now().Add(attemptTimeout)
		for time.Now().Before(attemptDeadline) {
			readTimeout := 500 * time.Millisecond
			if time.Until(attemptDeadline) < readTimeout {
				readTimeout = time.Until(attemptDeadline)
			}
			if readTimeout <= 0 {
				break
			}

			data, err := readWithTimeout(reader, readTimeout)
			if err != nil {
				// 超时或错误，检查已累积数据
				break
			}

			if len(data) > 0 {
				accumulatedData.Write(data)
				output.Write(data)

				// 检查是否包含换行符
				allData := accumulatedData.String()
				if strings.Contains(allData, "\n") {
					// 按行处理
					lines := strings.Split(allData, "\n")
					for _, line := range lines {
						lineTrimmed := strings.TrimSpace(line)
						if lineTrimmed != "" {
							if isPromptLine(line) {
								prompt := lineTrimmed
								promptCandidates = append(promptCandidates, prompt)
								log.Printf("[SSH] Prompt candidate %d: '%s'", len(promptCandidates), prompt)
								// 如果两次相同，立即返回
								if len(promptCandidates) >= 2 && promptCandidates[0] == promptCandidates[1] {
									return promptCandidates[0]
								}
								// 找到提示符，重置累积数据，准备下一次尝试
								accumulatedData.Reset()
								break
							}
						}
					}
					// 如果找到提示符，跳出内层循环
					if len(promptCandidates) > 0 && len(promptCandidates) == i+1 {
						break
					}
				}
			}
		}
	}

	if len(promptCandidates) > 0 {
		return promptCandidates[0]
	}
	return ""
}

// isPromptLine 检查一行是否是提示符
func isPromptLine(line string) bool {
	lineTrimmed := strings.TrimSpace(line)
	if lineTrimmed == "" {
		return false
	}

	promptPatterns := []*regexp.Regexp{
		regexp.MustCompile(`^<[^>]+>$`),          // <FW-HX>
		regexp.MustCompile(`^\[[^\]]+\]$`),       // [H3C]
		regexp.MustCompile(`^[a-zA-Z0-9_-]+>$`),  // Router>
		regexp.MustCompile(`^[a-zA-Z0-9_-]+#$`),  // Router#
		regexp.MustCompile(`^[a-zA-Z0-9_-]+\$$`), // user$
	}

	// 检查是否匹配提示符模式
	for _, pattern := range promptPatterns {
		if pattern.MatchString(lineTrimmed) {
			return true
		}
	}

	// 也检查行尾提示符（可能前面有空格）
	if strings.HasSuffix(lineTrimmed, ">") ||
		strings.HasSuffix(lineTrimmed, "#") ||
		strings.HasSuffix(lineTrimmed, "]") ||
		strings.HasSuffix(lineTrimmed, "$") {
		// 确保不是命令的一部分（提示符通常较短）
		if len(lineTrimmed) < 100 {
			return true
		}
	}

	return false
}

// extractOutputFromData 从累积数据中提取命令输出（移除命令回显和提示符）
func extractOutputFromData(data string, prompt string, command string) (string, bool) {
	lines := strings.Split(data, "\n")
	if len(lines) == 0 {
		return "", false
	}

	// 跳过命令回显
	startIdx := 0
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		if firstLine == command || (command != "" && strings.Contains(firstLine, command)) {
			startIdx = 1
		}
	}

	// 检查最后一行是否是提示符
	promptNormalized := strings.TrimSpace(prompt)
	outputLines := lines[startIdx:]
	if len(outputLines) > 0 {
		lastLine := strings.TrimSpace(outputLines[len(outputLines)-1])
		// 检查是否匹配提示符
		if lastLine == promptNormalized ||
			(promptNormalized != "" && strings.Contains(lastLine, promptNormalized) && len(lastLine) < len(promptNormalized)+10) ||
			(isPromptLine(lastLine) && len(lastLine) < 50) {
			// 移除提示符行
			if len(outputLines) > 1 {
				return strings.Join(outputLines[:len(outputLines)-1], "\n"), true
			}
			return "", true
		}
	}

	return strings.Join(outputLines, "\n"), false
}

// readWithTimeout 带超时读取数据
func readWithTimeout(reader io.Reader, timeout time.Duration) ([]byte, error) {
	type readResult struct {
		n   int
		err error
	}
	resultChan := make(chan readResult, 1)

	buf := make([]byte, 4096)
	go func() {
		deadline := time.Now().Add(timeout)
		setReadDeadline(reader, deadline)
		n, err := reader.Read(buf)
		resultChan <- readResult{n: n, err: err}
	}()

	select {
	case res := <-resultChan:
		if res.n > 0 {
			return buf[:res.n], res.err
		}
		return nil, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("read timeout after %v", timeout)
	}
}

// waitForCommandOutputWithTimeout 等待命令输出，检测到提示符立即返回（不等待超时）
// 使用持续读取策略：累积所有输出，在累积数据中查找提示符
func waitForCommandOutputWithTimeout(reader io.Reader, output *bytes.Buffer, prompt string, command string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	promptNormalized := strings.TrimSpace(prompt)
	commandNormalized := strings.TrimSpace(command)
	startTime := time.Now()

	// 累积所有读取的数据
	var accumulatedData bytes.Buffer

	for time.Now().Before(deadline) {
		remainingTime := time.Until(deadline)
		if remainingTime <= 0 {
			break
		}

		readTimeout := readChunkTimeout
		if remainingTime < readTimeout {
			readTimeout = remainingTime
		}

		data, err := readWithTimeout(reader, readTimeout)
		if err != nil {
			// 检查累积数据中是否有提示符
			if accumulatedData.Len() > 0 {
				if output, completed := extractOutputFromData(accumulatedData.String(), promptNormalized, commandNormalized); completed {
					log.Printf("[SSH] Command completed: '%s', elapsed: %v", promptNormalized, time.Since(startTime))
					return output
				}
				// EOF时返回已读取数据
				if err == io.EOF {
					output, _ := extractOutputFromData(accumulatedData.String(), promptNormalized, commandNormalized)
					return output
				}
			}
			// 超时错误，继续尝试
			continue
		}

		if len(data) > 0 {
			accumulatedData.Write(data)
			output.Write(data)

			// 检查是否包含提示符
			if output, completed := extractOutputFromData(accumulatedData.String(), promptNormalized, commandNormalized); completed {
				log.Printf("[SSH] Command completed: '%s', elapsed: %v", promptNormalized, time.Since(startTime))
				return output
			}
		}
	}

	// 超时返回已读取内容
	elapsed := time.Since(startTime)
	log.Printf("[SSH] Command timeout, elapsed: %v", elapsed)
	if accumulatedData.Len() > 0 {
		output, _ := extractOutputFromData(accumulatedData.String(), promptNormalized, commandNormalized)
		return output
	}
	return ""
}
