package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/controller/telnetproxy/network"
)

// isClosedError 检查错误是否是关闭连接导致的
// 当 listener 关闭时，Accept() 会返回包含 "use of closed network connection" 的错误
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "use of closed file") ||
		errors.Is(err, net.ErrClosed)
}

// FilterTelnetControlChars 过滤掉 telnet 控制字符（IAC 0xFF 开头的协商命令）
// IAC (Interpret As Command) 是 0xFF，后面跟着命令字节
// 格式：
//   - IAC (0xFF) + WILL/WONT/DO/DONT (0xFB-0xFE) + 选项字节
//   - IAC (0xFF) + SB (0xFA) + 选项字节 + 数据 + IAC (0xFF) + SE (0xF0)
//   - IAC (0xFF) + IAC (0xFF) - 表示字面的 0xFF 字节
func FilterTelnetControlChars(data []byte) []byte {
	const IAC = 0xFF
	result := make([]byte, 0, len(data))

	for i := 0; i < len(data); i++ {
		if data[i] == IAC {
			// 检查下一个字节
			if i+1 < len(data) {
				next := data[i+1]
				switch next {
				case IAC:
					// IAC IAC 表示字面的 0xFF，保留一个
					result = append(result, IAC)
					i++ // 跳过第二个 IAC
					continue
				case 0xFB, 0xFC, 0xFD, 0xFE: // WILL, WONT, DO, DONT
					// 跳过 IAC + 命令字节 + 选项字节（共3字节）
					i += 2
					continue
				case 0xFA: // SB (Subnegotiation Begin)
					// 跳过 IAC + SB + 选项字节，直到找到 IAC + SE
					i += 2 // 跳过 IAC 和 SB
					// 跳过选项字节
					if i < len(data) {
						i++
					}
					// 跳过数据直到找到 IAC + SE
					for i+1 < len(data) {
						if data[i] == IAC && data[i+1] == 0xF0 {
							i += 2 // 跳过 IAC + SE
							break
						}
						i++
					}
					continue
				case 0xF0: // SE (Subnegotiation End)
					// 单独出现的 IAC + SE，跳过
					i++
					continue
				default:
					// 其他命令，跳过 IAC 和命令字节
					i++
					continue
				}
			} else {
				// IAC 是最后一个字节，跳过
				break
			}
		} else {
			result = append(result, data[i])
		}
	}

	return result
}

// FilterTelnetEcho 过滤掉 telnet 回显（设备回显的命令和输入）
// 移除我们发送的命令（如 enable）和密码的回显
func FilterTelnetEcho(data []byte, username, password, enableCmd, enablePassword string) []byte {
	if len(data) == 0 {
		return data
	}

	dataStr := string(data)
	result := dataStr

	// 移除用户名回显（如果存在）
	if username != "" {
		// 移除用户名本身
		result = strings.ReplaceAll(result, username, "")
		// 移除用户名后的换行（如果用户名单独一行）
		result = strings.ReplaceAll(result, username+"\r\n", "")
		result = strings.ReplaceAll(result, username+"\n", "")
	}

	// 移除密码回显（如果存在）
	if password != "" {
		// 移除密码本身（注意：某些设备可能不回显密码，但为了安全还是过滤）
		result = strings.ReplaceAll(result, password, "")
		result = strings.ReplaceAll(result, password+"\r\n", "")
		result = strings.ReplaceAll(result, password+"\n", "")
	}

	// 移除 enable 命令回显
	if enableCmd != "" {
		// 移除 enable 命令本身
		result = strings.ReplaceAll(result, enableCmd, "")
		// 移除 enable 命令后的换行
		result = strings.ReplaceAll(result, enableCmd+"\r\n", "")
		result = strings.ReplaceAll(result, enableCmd+"\n", "")
		// 移除常见的回显模式：提示符 + enable + enable（设备可能回显两次）
		// 例如：Switch>enable\r\nenable\r\n
		enablePattern := ">" + enableCmd + "\r\n" + enableCmd
		result = strings.ReplaceAll(result, enablePattern, ">")
		enablePattern2 := ">" + enableCmd + "\n" + enableCmd
		result = strings.ReplaceAll(result, enablePattern2, ">")
	}

	// 移除 enable 密码回显（如果存在）
	if enablePassword != "" {
		// 移除密码本身
		result = strings.ReplaceAll(result, enablePassword, "")
		result = strings.ReplaceAll(result, enablePassword+"\r\n", "")
		result = strings.ReplaceAll(result, enablePassword+"\n", "")
	}

	// 清理多余的空行（连续的两个换行变成一个）
	result = strings.ReplaceAll(result, "\r\n\r\n", "\r\n")
	result = strings.ReplaceAll(result, "\n\n", "\n")

	return []byte(result)
}

// UnifiedProxy 统一代理，直接连接到目标telnet服务器
// 简化架构：client -> ProxyManager -> 目标设备
type UnifiedProxy struct {
	listenPort int
	targetHost string
	targetPort int
	listener   net.Listener
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// NewUnifiedProxy 创建新的统一代理
func NewUnifiedProxy(listenPort int, targetHost string, targetPort int) *UnifiedProxy {
	return &UnifiedProxy{
		listenPort: listenPort,
		targetHost: targetHost,
		targetPort: targetPort,
		stopChan:   make(chan struct{}),
	}
}

// Start 启动代理服务
func (up *UnifiedProxy) Start() error {
	var err error
	up.listener, err = net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(up.listenPort)))
	if err != nil {
		return err
	}

	xlog.Default().Info("UnifiedProxy listening", xlog.Int("port", up.listenPort), xlog.String("target", fmt.Sprintf("%s:%d", up.targetHost, up.targetPort)))

	for {
		select {
		case <-up.stopChan:
			return nil
		default:
			conn, err := up.listener.Accept()
			if err != nil {
				// 检查是否是关闭导致的错误，如果是则静默退出
				if isClosedError(err) {
					return nil
				}
				// 检查 stopChan 是否已关闭
				select {
				case <-up.stopChan:
					return nil
				default:
					// 其他错误才记录日志
					xlog.Default().Error("Accept error", xlog.FieldErr(err))
					continue
				}
			}

			up.wg.Add(1)
			go up.handleConnection(conn)
		}
	}
}

// Stop 停止代理服务
func (up *UnifiedProxy) Stop() {
	close(up.stopChan)
	if up.listener != nil {
		up.listener.Close()
	}
	up.wg.Wait()
}

// handleConnection 处理单个客户端连接
func (up *UnifiedProxy) handleConnection(clientConn net.Conn) {
	defer up.wg.Done()
	defer clientConn.Close()

	xlog.Default().Info("New telnet client connection", xlog.String("remoteAddr", clientConn.RemoteAddr().String()))

	// 先检查目标端口是否存活，避免长时间等待
	if err := network.CheckPortAlive(up.targetHost, up.targetPort, 3*time.Second); err != nil {
		xlog.Default().Error("Target port is not alive", xlog.String("target", fmt.Sprintf("%s:%d", up.targetHost, up.targetPort)), xlog.FieldErr(err))
		return
	}

	// 连接到目标telnet服务器
	targetConn, err := net.Dial("tcp", net.JoinHostPort(up.targetHost, strconv.Itoa(up.targetPort)))
	if err != nil {
		xlog.Default().Error("Failed to connect to target", xlog.String("target", fmt.Sprintf("%s:%d", up.targetHost, up.targetPort)), xlog.FieldErr(err))
		return
	}
	defer targetConn.Close()

	network.SetKeepAlive(targetConn)

	// 双向转发数据
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			close(done)
		})
	}

	// 客户端 -> 目标服务器
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
			}

			n, err := clientConn.Read(buf)
			if err != nil || n == 0 {
				closeDone()
				return
			}

			if err := network.WriteAll(targetConn, buf[:n]); err != nil {
				closeDone()
				return
			}
		}
	}()

	// 目标服务器 -> 客户端
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
			}

			n, err := targetConn.Read(buf)
			if err != nil || n == 0 {
				closeDone()
				return
			}

			if err := network.WriteAll(clientConn, buf[:n]); err != nil {
				closeDone()
				return
			}
		}
	}()

	// 等待连接关闭
	<-done
	xlog.Default().Info("Telnet connection closed", xlog.String("client", clientConn.RemoteAddr().String()), xlog.String("target", fmt.Sprintf("%s:%d", up.targetHost, up.targetPort)))
}

// readResult 读取结果
type readResult struct {
	n    int
	err  error
	data []byte
}

// hasCommandPromptInLine 检查一行是否包含命令提示符
func hasCommandPromptInLine(line string) bool {
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return false
	}
	if (strings.HasSuffix(line, ">") || strings.HasSuffix(line, "#") ||
		strings.HasSuffix(line, "$") || strings.HasSuffix(line, "%") ||
		strings.HasSuffix(line, "]")) && len(line) > 1 {
		lineLower := strings.ToLower(line)
		// 确保不是密码提示的一部分
		if !strings.Contains(lineLower, "password") &&
			!strings.Contains(lineLower, "passwd") &&
			!strings.Contains(lineLower, "login:") &&
			!strings.Contains(lineLower, "密码") {
			return true
		}
	}
	return false
}

// checkTelnetCommandExists 检查系统是否有 telnet 命令
func checkTelnetCommandExists() bool {
	_, err := exec.LookPath("telnet")
	return err == nil
}

// ForwardConnection 按需转发连接（不监听端口，直接转发）
// 用于流式代理，客户端通过流发送数据，服务端转发到目标设备
// done channel由调用者管理，此函数不关闭它
// username和password用于自动登录，enableCmd和enablePassword用于提权
// 登录过程的数据不会发送到serverDataChan
// 函数在登录完成后立即返回，数据转发在后台goroutine中进行
// 当目标连接关闭时，会关闭serverDataChan以通知服务端
func ForwardConnection(targetHost string, targetPort int, username, password, enableCmd, enablePassword string, clientDataChan <-chan []byte, serverDataChan chan<- []byte, done <-chan struct{}) error {
	// 优先使用 Go 实现（不使用系统的 telnet 命令）
	xlog.Default().Info("Using Go implementation for telnet connection",
		xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))
	return forwardConnectionWithGo(targetHost, targetPort, username, password, enableCmd, enablePassword, clientDataChan, serverDataChan, done)
}

// forwardConnectionWithTelnetCommand 使用系统的 telnet 命令建立连接
func forwardConnectionWithTelnetCommand(targetHost string, targetPort int, username, password, enableCmd, enablePassword string, clientDataChan <-chan []byte, serverDataChan chan<- []byte, done <-chan struct{}) error {
	// 先检查目标端口是否存活
	if err := network.CheckPortAlive(targetHost, targetPort, 3*time.Second); err != nil {
		return fmt.Errorf("target port is not alive: %w", err)
	}

	// 启动 telnet 命令
	cmd := exec.Command("telnet", targetHost, strconv.Itoa(targetPort))

	// 获取 stdin/stdout/stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return fmt.Errorf("failed to start telnet command: %w", err)
	}

	xlog.Default().Info("Telnet command started",
		xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)),
		xlog.Int("pid", cmd.Process.Pid))

	// 启动 stderr 读取 goroutine，用于调试
	go func() {
		stderrReader := bufio.NewReader(stderr)
		for {
			line, err := stderrReader.ReadBytes('\n')
			if err != nil {
				if err != io.EOF {
					xlog.Default().Debug("Stderr read error", xlog.FieldErr(err))
				}
				return
			}
			if len(line) > 0 {
				xlog.Default().Debug("Telnet stderr",
					xlog.String("data", strings.TrimSpace(string(line))),
					xlog.String("hex", fmt.Sprintf("%x", line)))
			}
		}
	}()

	// 用于确保资源只关闭一次
	var closeOnce sync.Once
	closeResources := func() {
		closeOnce.Do(func() {
			stdin.Close()
			stdout.Close()
			stderr.Close()
			if cmd.Process != nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
			close(serverDataChan)
		})
	}

	// 用于通知其他goroutine连接已关闭
	connClosed := make(chan struct{})
	var connCloseOnce sync.Once
	notifyConnClosed := func() {
		connCloseOnce.Do(func() {
			close(connClosed)
		})
	}

	// 创建一个共享的 reader，用于登录和数据转发
	reader := bufio.NewReader(stdout)

	// 用于存储登录过程中读取的数据
	var loginData []byte

	// 如果需要登录，先执行登录流程
	if password != "" {
		xlog.Default().Debug("Starting login process",
			xlog.String("username", username),
			xlog.String("hasPassword", fmt.Sprintf("%v", password != "")))

		// 等待 telnet 连接建立
		time.Sleep(500 * time.Millisecond)
		xlog.Default().Debug("Waited for telnet connection establishment")

		// 读取并处理登录提示（使用带超时的读取）
		usernameSent := false
		passwordSent := false
		loginComplete := false
		loginBuffer := bytes.Buffer{}
		readAttempts := 0

		// 使用 context 控制超时
		loginCtx, loginCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer loginCancel()

		for !loginComplete {
			readAttempts++
			xlog.Default().Debug("Login loop iteration",
				xlog.Int("attempt", readAttempts),
				xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)),
				xlog.String("passwordSent", fmt.Sprintf("%v", passwordSent)),
				xlog.Int("bufferSize", loginBuffer.Len()))

			// 使用 channel 实现超时读取
			readChan := make(chan readResult, 1)
			go func() {
				xlog.Default().Debug("Starting read operation")
				line, err := reader.ReadBytes('\n')
				xlog.Default().Debug("Read operation completed",
					xlog.Int("bytes", len(line)),
					xlog.String("data", fmt.Sprintf("%q", string(line))),
					xlog.String("hex", fmt.Sprintf("%x", line)),
					xlog.FieldErr(err))
				readChan <- readResult{n: len(line), err: err, data: line}
			}()

			select {
			case <-loginCtx.Done():
				xlog.Default().Debug("Login context timeout",
					xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)),
					xlog.String("passwordSent", fmt.Sprintf("%v", passwordSent)))
				// 超时，如果还没发送用户名，尝试直接发送
				if !usernameSent && username != "" {
					usernameData := []byte(username + "\r\n")
					if n, err := stdin.Write(usernameData); err != nil {
						xlog.Default().Error("Failed to write username", xlog.FieldErr(err))
					} else {
						xlog.Default().Info("Username sent via telnet command (timeout)",
							xlog.Int("bytes", n),
							xlog.String("data", fmt.Sprintf("%q", string(usernameData))))
						usernameSent = true
						// 延长超时，等待密码提示
						loginCancel()
						loginCtx, loginCancel = context.WithTimeout(context.Background(), 5*time.Second)
					}
				} else if usernameSent && !passwordSent && password != "" {
					passwordData := []byte(password + "\r\n")
					if n, err := stdin.Write(passwordData); err != nil {
						xlog.Default().Error("Failed to write password", xlog.FieldErr(err))
					} else {
						xlog.Default().Info("Password sent via telnet command (timeout)",
							xlog.Int("bytes", n))
						passwordSent = true
						// 发送密码后，继续读取直到检测到命令提示符
						// 延长超时，等待命令提示符
						loginCancel()
						loginCtx, loginCancel = context.WithTimeout(context.Background(), 5*time.Second)
						// 不要立即退出，继续读取
					}
				} else if usernameSent && passwordSent {
					// 已经发送了用户名和密码，但还没有检测到命令提示符
					// 继续读取，直到检测到命令提示符或超时
					xlog.Default().Debug("Username and password sent, waiting for command prompt")
					// 延长超时，继续等待
					loginCancel()
					loginCtx, loginCancel = context.WithTimeout(context.Background(), 3*time.Second)
				} else {
					// 超时且没有更多操作，退出
					xlog.Default().Warn("Login timeout with no action taken")
					break
				}
			case result := <-readChan:
				xlog.Default().Debug("Received data from read channel",
					xlog.Int("bytes", result.n),
					xlog.String("hasError", fmt.Sprintf("%v", result.err != nil)),
					xlog.FieldErr(result.err))

				if result.err != nil {
					if result.err == io.EOF {
						xlog.Default().Warn("EOF while reading login prompt",
							xlog.Int("bufferSize", loginBuffer.Len()),
							xlog.String("bufferContent", fmt.Sprintf("%q", loginBuffer.String())),
							xlog.String("bufferHex", fmt.Sprintf("%x", loginBuffer.Bytes())))
						loginComplete = true
						break
					}
					xlog.Default().Warn("Error reading login prompt",
						xlog.FieldErr(result.err),
						xlog.Int("bufferSize", loginBuffer.Len()))
					loginComplete = true
					break
				}

				if result.n > 0 && len(result.data) > 0 {
					loginBuffer.Write(result.data)
					lineStr := string(result.data)
					lineLower := strings.ToLower(lineStr)

					xlog.Default().Debug("Processing received line",
						xlog.String("line", fmt.Sprintf("%q", lineStr)),
						xlog.String("hex", fmt.Sprintf("%x", result.data)),
						xlog.Int("bufferSize", loginBuffer.Len()))

					// 检查是否包含用户名提示
					if !usernameSent && (strings.Contains(lineLower, "username:") ||
						strings.Contains(lineLower, "login:") ||
						strings.Contains(lineLower, "user:")) {
						if username != "" {
							usernameData := []byte(username + "\r\n")
							if n, err := stdin.Write(usernameData); err != nil {
								xlog.Default().Error("Failed to write username", xlog.FieldErr(err))
							} else {
								xlog.Default().Info("Username sent via telnet command",
									xlog.Int("bytes", n),
									xlog.String("data", fmt.Sprintf("%q", string(usernameData))))
								usernameSent = true
								// 延长超时，等待密码提示
								loginCancel()
								loginCtx, loginCancel = context.WithTimeout(context.Background(), 5*time.Second)
							}
						}
					}

					// 检查是否包含密码提示
					if usernameSent && !passwordSent && isPasswordPrompt(lineStr) {
						if password != "" {
							passwordData := []byte(password + "\r\n")
							if n, err := stdin.Write(passwordData); err != nil {
								xlog.Default().Error("Failed to write password", xlog.FieldErr(err))
							} else {
								xlog.Default().Info("Password sent via telnet command",
									xlog.Int("bytes", n))
								passwordSent = true
								// 延长超时，等待命令提示符
								loginCancel()
								loginCtx, loginCancel = context.WithTimeout(context.Background(), 5*time.Second)
							}
						}
					}

					// 检查是否包含命令提示符（登录成功）
					if passwordSent && hasCommandPromptInLine(lineStr) {
						loginComplete = true
						loginData = loginBuffer.Bytes()
						xlog.Default().Info("Login successful, command prompt detected",
							xlog.String("prompt", lineStr),
							xlog.Int("totalBufferSize", len(loginData)))
						break
					}
				} else {
					xlog.Default().Debug("Received empty data",
						xlog.Int("n", result.n),
						xlog.Int("dataLen", len(result.data)))
				}
			}
		}

		loginCancel()

		// 如果已经发送了用户名和密码，但还没有检测到命令提示符，继续读取
		if usernameSent && passwordSent && !loginComplete {
			xlog.Default().Info("Username and password sent, but command prompt not detected, reading more data...")
			// 继续读取，直到检测到命令提示符或超时
			promptCtx, promptCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer promptCancel()

		promptLoop:
			for !loginComplete {
				readChan := make(chan readResult, 1)
				go func() {
					line, err := reader.ReadBytes('\n')
					readChan <- readResult{n: len(line), err: err, data: line}
				}()

				select {
				case <-promptCtx.Done():
					xlog.Default().Warn("Timeout waiting for command prompt after login")
					// 即使没有检测到命令提示符，也认为登录成功（可能设备不发送提示符）
					loginComplete = true
					break promptLoop
				case result := <-readChan:
					if result.err != nil {
						if result.err == io.EOF {
							xlog.Default().Warn("EOF while waiting for command prompt")
							loginComplete = true
							break promptLoop
						}
						xlog.Default().Warn("Error reading while waiting for command prompt", xlog.FieldErr(result.err))
						loginComplete = true
						break promptLoop
					}

					if result.n > 0 && len(result.data) > 0 {
						loginBuffer.Write(result.data)
						lineStr := string(result.data)

						xlog.Default().Debug("Reading data after password sent",
							xlog.String("line", fmt.Sprintf("%q", lineStr)),
							xlog.Int("bufferSize", loginBuffer.Len()))

						// 检查是否包含命令提示符
						if hasCommandPromptInLine(lineStr) {
							loginComplete = true
							loginData = loginBuffer.Bytes()
							xlog.Default().Info("Command prompt detected after password sent",
								xlog.String("prompt", lineStr),
								xlog.Int("totalBufferSize", len(loginData)))
							break promptLoop
						}
					}
				}
			}
			promptCancel()
		}

		xlog.Default().Info("Login loop completed",
			xlog.String("loginComplete", fmt.Sprintf("%v", loginComplete)),
			xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)),
			xlog.String("passwordSent", fmt.Sprintf("%v", passwordSent)),
			xlog.Int("loginDataSize", len(loginData)),
			xlog.Int("readAttempts", readAttempts))

		// 如果登录完成，转发登录数据（包括提示符）
		if loginComplete {
			// 如果 loginData 为空，使用 loginBuffer 的内容
			if len(loginData) == 0 {
				loginData = loginBuffer.Bytes()
			}

			if len(loginData) > 0 {
				filtered := FilterTelnetControlChars(loginData)
				xlog.Default().Debug("Filtering login data",
					xlog.Int("originalSize", len(loginData)),
					xlog.Int("filteredSize", len(filtered)),
					xlog.String("filtered", fmt.Sprintf("%q", string(filtered))))
				if len(filtered) > 0 {
					select {
					case <-done:
						xlog.Default().Warn("Done channel closed, skipping login data forwarding")
					case serverDataChan <- filtered:
						xlog.Default().Info("Forwarded login data via telnet command", xlog.Int("bytes", len(filtered)))
					}
				}
			} else {
				// 即使没有登录数据，也尝试读取一次提示符
				xlog.Default().Info("No login data, attempting to read prompt...")
				readChan := make(chan readResult, 1)
				go func() {
					line, err := reader.ReadBytes('\n')
					readChan <- readResult{n: len(line), err: err, data: line}
				}()

				select {
				case <-time.After(2 * time.Second):
					xlog.Default().Warn("Timeout reading prompt")
				case result := <-readChan:
					if result.err == nil && result.n > 0 && len(result.data) > 0 {
						filtered := FilterTelnetControlChars(result.data)
						if len(filtered) > 0 {
							select {
							case <-done:
								xlog.Default().Warn("Done channel closed, skipping prompt forwarding")
							case serverDataChan <- filtered:
								xlog.Default().Info("Forwarded prompt after login", xlog.Int("bytes", len(filtered)))
							}
						}
					}
				}
			}
		}

		xlog.Default().Info("Telnet login completed via system command")
	}

	// 启动数据转发 goroutines
	// 客户端数据 -> telnet stdin
	go func() {
		defer closeResources()
		for {
			select {
			case <-done:
				return
			case <-connClosed:
				return
			case data, ok := <-clientDataChan:
				if !ok {
					return
				}
				if len(data) == 0 {
					continue
				}
				if _, err := stdin.Write(data); err != nil {
					xlog.Default().Error("Failed to write to telnet stdin", xlog.FieldErr(err))
					notifyConnClosed()
					return
				}
			}
		}
	}()

	// telnet stdout -> 客户端数据
	// 注意：使用登录流程中创建的同一个 reader，避免数据丢失
	go func() {
		defer closeResources()
		defer notifyConnClosed()

		// 使用登录流程中创建的同一个 reader
		// reader 已经在登录流程中创建，这里直接使用
		// 登录完成后，继续读取并转发数据

		// 等待一小段时间，确保登录流程完成
		time.Sleep(300 * time.Millisecond)

		xlog.Default().Info("Starting data forwarding after login")

		// 持续读取并转发数据（按行读取，与登录流程一致）
		for {
			select {
			case <-done:
				xlog.Default().Debug("Data forwarding stopped (done channel)")
				return
			case <-connClosed:
				xlog.Default().Debug("Data forwarding stopped (conn closed)")
				return
			default:
			}

			// 使用带超时的读取（按行读取，与登录流程一致）
			readChan := make(chan readResult, 1)
			go func() {
				line, err := reader.ReadBytes('\n')
				readChan <- readResult{n: len(line), err: err, data: line}
			}()

			select {
			case <-time.After(5 * time.Second):
				// 超时，检查 done channel
				select {
				case <-done:
					return
				case <-connClosed:
					return
				default:
					// 继续读取
					continue
				}
			case result := <-readChan:
				if result.err != nil {
					if result.err == io.EOF {
						xlog.Default().Info("Telnet command stdout closed (EOF)")
						return
					}
					xlog.Default().Error("Error reading from telnet stdout", xlog.FieldErr(result.err))
					return
				}

				if result.n > 0 && len(result.data) > 0 {
					filtered := FilterTelnetControlChars(result.data)
					if len(filtered) > 0 {
						xlog.Default().Debug("Forwarding data from telnet stdout",
							xlog.Int("bytes", len(filtered)),
							xlog.String("data", fmt.Sprintf("%q", string(filtered))))
						select {
						case <-done:
							return
						case <-connClosed:
							return
						case serverDataChan <- filtered:
							// 数据已成功转发
						}
					}
				}
			}
		}
	}()

	// 监控命令进程
	go func() {
		cmd.Wait()
		xlog.Default().Info("Telnet command process exited")
		closeResources()
		notifyConnClosed()
	}()

	return nil
}

// forwardConnectionWithGo 使用 Go 实现建立连接（原有实现）
func forwardConnectionWithGo(targetHost string, targetPort int, username, password, enableCmd, enablePassword string, clientDataChan <-chan []byte, serverDataChan chan<- []byte, done <-chan struct{}) error {
	// 先检查目标端口是否存活，避免长时间等待
	if err := network.CheckPortAlive(targetHost, targetPort, 3*time.Second); err != nil {
		return fmt.Errorf("target port is not alive: %w", err)
	}

	// 连接到目标telnet服务器
	targetConn, err := net.Dial("tcp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))
	if err != nil {
		return err
	}
	// 注意：不在函数返回时关闭连接，由goroutine在done时关闭

	network.SetKeepAlive(targetConn)

	xlog.Default().Info("Target device connected",
		xlog.String("protocol", "Telnet"),
		xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)),
		xlog.String("host", targetHost),
		xlog.Int("port", targetPort))

	// 对于 telnet 连接，先处理初始的 telnet 选项协商
	// 主动发送 DONT ECHO 来禁用回显
	const IAC = 0xFF
	const DONT = 0xFE
	const OPT_ECHO = 0x01
	disableEchoCmd := []byte{IAC, DONT, OPT_ECHO}
	if err := network.WriteAll(targetConn, disableEchoCmd); err != nil {
		xlog.Default().Warn("Failed to send DONT ECHO command", xlog.FieldErr(err))
	} else {
		xlog.Default().Debug("Sent DONT ECHO command to disable echo")
	}

	// 使用类似系统 telnet 命令的方式：持续读取并响应协商，直到协商完成
	// 设置一个较短的超时来读取和处理 telnet 协商
	targetConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	negotiationBuf := make([]byte, 4096)
	negotiationTotal := 0
	negotiationComplete := false
	maxNegotiationRounds := 10 // 最多处理10轮协商，避免无限循环
	negotiationRounds := 0

	// 持续处理协商，直到超时（说明协商完成）
	for !negotiationComplete && negotiationRounds < maxNegotiationRounds {
		negotiationRounds++
		n, err := targetConn.Read(negotiationBuf[negotiationTotal:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超时是正常的，说明没有更多协商数据了
				negotiationComplete = true
				break
			}
			// 其他错误也停止读取
			xlog.Default().Warn("Error reading during negotiation", xlog.FieldErr(err))
			break
		}
		if n > 0 {
			// 只处理新读取的数据，避免重复处理
			newData := negotiationBuf[negotiationTotal : negotiationTotal+n]
			negotiationTotal += n

			// 立即处理 telnet 选项协商（每次读取后立即响应）
			// 这很重要，因为设备可能在等待我们的响应
			if err := handleTelnetNegotiation(targetConn, newData); err != nil {
				xlog.Default().Warn("Failed to handle initial telnet negotiation", xlog.FieldErr(err))
			}

			xlog.Default().Debug("Processed telnet negotiation data",
				xlog.Int("bytes", n),
				xlog.String("hex", fmt.Sprintf("%x", newData)),
				xlog.Int("round", negotiationRounds))

			// 继续读取，但设置更短的超时
			targetConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		} else {
			break
		}
	}
	// 清除读取超时
	targetConn.SetReadDeadline(time.Time{})
	if negotiationTotal > 0 {
		xlog.Default().Info("Completed initial telnet negotiation",
			xlog.Int("bytes", negotiationTotal),
			xlog.Int("rounds", negotiationRounds))
	}

	// 等待一小段时间，确保所有协商响应都已发送并被设备处理
	time.Sleep(200 * time.Millisecond)

	// 如果需要登录，先执行登录流程（在启动数据转发之前）
	// 登录过程中的数据会被读取但不发送到serverDataChan
	// 只要有密码就执行自动登录（支持只需要密码的设备）
	// 如果只有用户名但没有密码，不执行自动登录，让用户根据设备提示手动登录
	if password != "" {
		xlog.Default().Info("Performing telnet login", xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)), xlog.String("username", username))
		loginData, err := PerformLoginWithStateMachine(targetConn, username, password, enableCmd, enablePassword, 10*time.Second)
		if err != nil {
			targetConn.Close()
			return fmt.Errorf("login failed: %w", err)
		}
		xlog.Default().Info("Telnet login successful", xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))

		// 转发登录过程中读取到的数据（包含提示符）
		if len(loginData) > 0 {
			// 先过滤 telnet 控制字符
			filtered := FilterTelnetControlChars(loginData)
			// 再过滤回显（移除我们发送的命令和密码的回显）
			filtered = FilterTelnetEcho(filtered, username, password, enableCmd, enablePassword)
			if len(filtered) > 0 {
				select {
				case <-done:
					// 如果 done 已关闭，不发送数据
				case serverDataChan <- filtered:
					xlog.Default().Info("Forwarded login data with prompt", xlog.Int("bytes", len(filtered)))
				}
			}
		}

		// 登录完成后，等待一小段时间让设备发送更多数据
		// 然后读取并转发剩余的提示符等数据
		time.Sleep(300 * time.Millisecond)

		// 循环读取，确保获取所有登录后设备发送的数据（提示符等）
		postLoginBuf := make([]byte, 4096)
		totalRead := 0
		// 设置一个较长的超时，读取登录后设备发送的提示符
		targetConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		for {
			n, err := targetConn.Read(postLoginBuf)
			if err != nil {
				// 超时或错误，停止读取
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时是正常的，说明没有更多数据了
					break
				}
				// 其他错误也停止读取
				break
			}
			if n > 0 {
				totalRead += n
				// 先过滤掉 telnet 控制字符
				filtered := FilterTelnetControlChars(postLoginBuf[:n])
				// 再过滤回显（移除我们发送的命令和密码的回显）
				filtered = FilterTelnetEcho(filtered, username, password, enableCmd, enablePassword)
				if len(filtered) > 0 {
					select {
					case <-done:
						// 如果 done 已关闭，不发送数据
						break
					case serverDataChan <- filtered:
						// 数据已发送，继续读取
					}
				}
				// 继续读取，但设置更短的超时
				targetConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			} else {
				break
			}
		}
		if totalRead > 0 {
			xlog.Default().Info("Forwarded post-login data", xlog.Int("bytes", totalRead))
		}
		// 清除读取超时，准备正常的数据转发
		targetConn.SetReadDeadline(time.Time{})
	} else if username != "" {
		// 只有用户名但没有密码，不执行自动登录，让用户手动登录
		xlog.Default().Info("Username provided but no password, skipping auto-login", xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)), xlog.String("username", username))
	}

	// 用于确保连接只关闭一次
	var closeOnce sync.Once
	closeConn := func() {
		closeOnce.Do(func() {
			targetConn.Close()
		})
	}

	// 用于确保serverDataChan只关闭一次（当目标连接关闭时）
	var closeServerChanOnce sync.Once
	closeServerChan := func() {
		closeServerChanOnce.Do(func() {
			close(serverDataChan)
		})
	}

	// 用于通知其他goroutine连接已关闭
	// 使用一个本地channel来快速通知连接关闭
	connClosed := make(chan struct{})
	var connCloseOnce sync.Once
	notifyConnClosed := func() {
		connCloseOnce.Do(func() {
			close(connClosed)
		})
	}

	// 启动数据转发goroutines（登录已完成，现在可以开始转发数据）
	// 客户端数据 -> 目标服务器
	go func() {
		defer closeConn() // 在goroutine退出时关闭连接
		for {
			select {
			case <-done:
				// 客户端断开，立即关闭连接
				xlog.Default().Info("Client disconnected, closing telnet connection",
					xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))
				return
			case <-connClosed:
				// 连接已关闭，立即退出
				return
			case data, ok := <-clientDataChan:
				if !ok {
					// clientDataChan 关闭表示客户端断开，立即关闭连接
					xlog.Default().Info("Client data channel closed, closing telnet connection",
						xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))
					return
				}
				if len(data) == 0 {
					continue
				}

				// 直接写入，不设置超时（写入通常很快，TCP keepalive会检测连接状态）
				if err := network.WriteAll(targetConn, data); err != nil {
					xlog.Default().Error("Failed to write to target",
						xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)),
						xlog.FieldErr(err))
					notifyConnClosed() // 通知读取goroutine连接已关闭
					return
				}
			}
		}
	}()

	// 目标服务器 -> 客户端数据（登录后的数据才发送）
	go func() {
		defer closeConn()        // 在goroutine退出时关闭连接
		defer notifyConnClosed() // 通知写入goroutine连接已关闭
		defer closeServerChan()  // 关闭serverDataChan，通知服务端目标连接已关闭
		buf := make([]byte, 4096)

		// 首次读取：立即尝试读取登录后的提示符，不设置超时或设置很短的超时
		// 这样可以确保提示符被立即转发
		targetConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := targetConn.Read(buf); err == nil && n > 0 {
			// 过滤掉 telnet 控制字符后转发
			filtered := FilterTelnetControlChars(buf[:n])
			if len(filtered) > 0 {
				select {
				case <-done:
					return
				case <-connClosed:
					return
				case serverDataChan <- filtered:
					// 提示符已转发
				}
			}
		}
		// 清除读取超时，准备正常的数据转发
		targetConn.SetReadDeadline(time.Time{})

		for {
			// 在每次读取前检查 done channel，确保能及时响应客户端断开
			select {
			case <-done:
				return
			case <-connClosed:
				// 连接已关闭（由写入goroutine检测到），立即退出
				return
			default:
			}

			// 设置较短的读取超时（5秒），以便能及时响应 done channel
			// 这样可以快速检测到客户端断开连接
			targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))

			n, err := targetConn.Read(buf)
			if err != nil {
				// 检查是否是超时
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时：检查 done channel，如果客户端已断开则立即退出
					select {
					case <-done:
						return
					case <-connClosed:
						return
					default:
						// 继续读取，但先检查连接状态
						// 使用更短的超时以便快速响应客户端断开
						continue
					}
				}
				// EOF表示连接正常关闭
				if err == io.EOF {
					xlog.Default().Info("Target telnet connection closed (EOF)")
					return
				}
				// 其他错误（包括连接关闭），立即退出
				xlog.Default().Error("Target telnet connection closed or error", xlog.FieldErr(err))
				return
			}
			if n == 0 {
				// 读取到0字节，连接已关闭
				xlog.Default().Info("Target telnet connection closed (read 0 bytes)")
				return
			}

			// 清除读取超时（成功读取到数据，连接活跃）
			targetConn.SetReadDeadline(time.Time{})

			// 过滤掉 telnet 控制字符后再发送到客户端
			filtered := FilterTelnetControlChars(buf[:n])
			if len(filtered) == 0 {
				// 如果过滤后没有数据，继续下一次读取
				continue
			}

			// 发送数据到客户端
			select {
			case <-done:
				return
			case <-connClosed:
				// 连接已关闭，立即退出
				return
			case serverDataChan <- filtered:
			}
		}
	}()

	// 函数立即返回（登录已完成，数据转发在后台进行）
	// 注意：done channel由调用者管理，当done关闭时，所有goroutine会自动退出
	// 连接会在第一个退出的goroutine中关闭
	return nil
}
