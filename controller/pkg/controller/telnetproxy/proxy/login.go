package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/controller/telnetproxy/network"
)

// isPasswordPrompt 检查字符串是否包含密码提示（忽略大小写）
// 支持多种密码提示格式：password:, passwd:, pass: 等
func isPasswordPrompt(text string) bool {
	if len(text) == 0 {
		return false
	}

	// 清理不可见字符，但保留换行符以便按行检查
	// 将 \r\n 和 \r 统一为 \n
	cleaned := strings.ReplaceAll(text, "\r\n", "\n")
	cleaned = strings.ReplaceAll(cleaned, "\r", "\n")

	// 按行分割，检查每一行
	lines := strings.Split(cleaned, "\n")
	for _, line := range lines {
		// 清理每行的前后空白字符
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		lineLower := strings.ToLower(line)

		// 检查这一行是否包含密码提示
		if checkPasswordPromptInLine(lineLower) {
			return true
		}
	}

	// 如果按行检查没找到，也检查整个文本（向后兼容）
	textLower := strings.ToLower(text)
	return checkPasswordPromptInLine(textLower)
}

// checkPasswordPromptInLine 检查一行文本是否包含密码提示
func checkPasswordPromptInLine(lineLower string) bool {
	// 首先排除错误消息，这些不是密码提示
	errorMessages := []string{
		"password required, but none set",
		"password required but none set",
		"password not set",
		"no password set",
		"authentication failed",
		"login failed",
		"access denied",
		"permission denied",
	}

	for _, errMsg := range errorMessages {
		if strings.Contains(lineLower, errMsg) {
			return false
		}
	}

	// 检查常见的密码提示格式（按优先级排序）
	// 优先检查明确的密码提示格式
	passwordPatterns := []string{
		"password:",      // 最常见的格式
		"passwd:",        // 变体
		"pass:",          // 简短格式
		"密码:",            // 中文带冒号（优先检查）
		"输入密码",           // 中文完整提示
		"password",       // 不带冒号
		"passwd",         // 不带冒号
		"enter password", // 完整提示
		"enter passwd",   // 变体
		"密码",             // 中文简短（不带冒号）
	}

	// 首先检查是否包含明确的密码提示关键词
	hasPasswordKeyword := false
	for _, pattern := range passwordPatterns {
		if strings.Contains(lineLower, pattern) {
			hasPasswordKeyword = true
			break
		}
	}

	if !hasPasswordKeyword {
		return false
	}

	// 如果包含密码关键词，进一步检查是否在用户名提示中
	// 排除明显的用户名提示
	if strings.Contains(lineLower, "username:") ||
		strings.Contains(lineLower, "user name:") ||
		strings.Contains(lineLower, "user:") {
		// 如果同时包含用户名提示，需要更仔细判断
		// 检查 "password" 是否出现在 "username" 之后（更可能是密码提示）
		usernameIdx := strings.Index(lineLower, "username")
		if usernameIdx == -1 {
			usernameIdx = strings.Index(lineLower, "user:")
		}
		passwordIdx := strings.Index(lineLower, "password")
		if passwordIdx == -1 {
			passwordIdx = strings.Index(lineLower, "passwd")
		}
		if passwordIdx != -1 && usernameIdx != -1 && passwordIdx < usernameIdx {
			// password 在 username 之前，可能是误判
			return false
		}
	}

	// 如果包含明确的 "password:"、"passwd:" 或 "密码:"，认为是密码提示
	// 这是最可靠的判断方式
	if strings.Contains(lineLower, "password:") ||
		strings.Contains(lineLower, "passwd:") ||
		strings.Contains(lineLower, "密码:") {
		// 明确的密码提示格式，即使有 "login" 也接受
		return true
	}

	// 对于其他格式，排除包含 "login:" 的情况（除非是明确的密码提示）
	if strings.Contains(lineLower, "login:") {
		// 如果包含 "login:"，需要确保不是用户名提示
		// 检查是否在 "login:" 之后有 "password"
		loginIdx := strings.Index(lineLower, "login:")
		passwordIdx := strings.Index(lineLower, "password")
		if passwordIdx == -1 {
			passwordIdx = strings.Index(lineLower, "passwd")
		}
		// 如果 password 在 login 之后，认为是密码提示
		if passwordIdx != -1 && passwordIdx > loginIdx {
			return true
		}
		return false
	}

	// 其他情况，如果包含密码关键词且不在用户名提示中，认为是密码提示
	return true
}

// handleTelnetNegotiation 处理并响应 telnet 选项协商
// 返回处理后的响应数据（如果有的话）
func handleTelnetNegotiation(conn net.Conn, data []byte) error {
	const IAC = 0xFF
	const WILL = 0xFB
	const WONT = 0xFC
	const DO = 0xFD
	const DONT = 0xFE
	const SB = 0xFA
	const SE = 0xF0

	// Telnet 选项定义
	const (
		OPT_ECHO                = 0x01 // Echo
		OPT_SUPPRESS_GO_AHEAD   = 0x03 // Suppress Go Ahead
		OPT_TERMINAL_TYPE       = 0x18 // Terminal Type
		OPT_WINDOW_SIZE         = 0x1F // Negotiate About Window Size
		OPT_TERMINAL_SPEED      = 0x20 // Terminal Speed
		OPT_REMOTE_FLOW_CONTROL = 0x21 // Remote Flow Control
	)

	response := make([]byte, 0, len(data))

	for i := 0; i < len(data); i++ {
		if data[i] == IAC {
			if i+1 >= len(data) {
				break
			}
			next := data[i+1]

			switch next {
			case IAC:
				// IAC IAC 表示字面的 0xFF，跳过
				i++
				continue
			case DO: // 设备要求我们启用某个选项
				if i+2 < len(data) {
					option := data[i+2]
					// 对于常见的选项，我们应该接受
					switch option {
					case OPT_ECHO:
						// 拒绝 Echo 选项，禁用回显
						response = append(response, IAC, WONT, option)
					case OPT_SUPPRESS_GO_AHEAD:
						// 接受 Suppress Go Ahead
						response = append(response, IAC, WILL, option)
					case OPT_TERMINAL_TYPE, OPT_WINDOW_SIZE:
						// 接受 Terminal Type 和 Window Size
						response = append(response, IAC, WILL, option)
					default:
						// 对于其他选项，拒绝
						response = append(response, IAC, WONT, option)
					}
					i += 2
					continue
				}
			case DONT: // 设备要求我们禁用某个选项
				if i+2 < len(data) {
					option := data[i+2]
					// 响应 WONT（我们不会启用）
					response = append(response, IAC, WONT, option)
					i += 2
					continue
				}
			case WILL: // 设备表示它将启用某个选项
				if i+2 < len(data) {
					option := data[i+2]
					// 对于常见的选项，我们应该接受
					switch option {
					case OPT_ECHO:
						// 拒绝 Echo 选项，要求设备禁用回显
						response = append(response, IAC, DONT, option)
					case OPT_SUPPRESS_GO_AHEAD:
						// 接受 Suppress Go Ahead
						response = append(response, IAC, DO, option)
					case OPT_TERMINAL_TYPE, OPT_WINDOW_SIZE:
						// 接受 Terminal Type 和 Window Size
						response = append(response, IAC, DO, option)
					default:
						// 对于其他选项，拒绝
						response = append(response, IAC, DONT, option)
					}
					i += 2
					continue
				}
			case WONT: // 设备表示它将不启用某个选项
				if i+2 < len(data) {
					// 响应 DONT（我们也不启用）
					option := data[i+2]
					response = append(response, IAC, DONT, option)
					i += 2
					continue
				}
			case SB: // 子选项协商开始
				// 处理子选项协商
				i += 2 // 跳过 IAC 和 SB
				if i < len(data) {
					option := data[i]
					i++ // 跳过选项字节

					// 对于 Terminal Type 子选项，需要响应
					if option == OPT_TERMINAL_TYPE {
						// 跳过设备发送的终端类型请求，直到找到 IAC SE
						for i+1 < len(data) {
							if data[i] == IAC && data[i+1] == SE {
								i += 2 // 跳过 IAC + SE
								// 响应终端类型为 "VT100"
								terminalType := []byte("VT100")
								subResponse := []byte{IAC, SB, OPT_TERMINAL_TYPE, 0x00}
								subResponse = append(subResponse, terminalType...)
								subResponse = append(subResponse, IAC, SE)
								response = append(response, subResponse...)
								break
							}
							i++
						}
						continue
					}

					// 对于其他子选项，跳过直到找到 IAC + SE
					for i+1 < len(data) {
						if data[i] == IAC && data[i+1] == SE {
							i += 2 // 跳过 IAC + SE
							break
						}
						i++
					}
				}
				continue
			case SE: // 子选项协商结束
				i++
				continue
			default:
				// 其他命令，跳过
				i++
				continue
			}
		}
	}

	// 如果有响应，发送给设备
	if len(response) > 0 {
		if err := network.WriteAll(conn, response); err != nil {
			return fmt.Errorf("failed to send telnet negotiation response: %w", err)
		}
	}

	return nil
}

// PerformLogin 执行telnet登录流程和提权流程
// 读取服务器提示，发送用户名和密码，直到登录成功
// 如果提供了提权命令和提权密码，在登录成功后执行提权
// 返回登录过程中接收到的所有数据（用于调试，但不发送给客户端）
func PerformLogin(conn net.Conn, username, password, enableCmd, enablePassword string, timeout time.Duration) error {
	if username == "" && password == "" {
		// 无需登录，直接返回
		return nil
	}

	// 如果密码为空，标记为已发送密码（因为不需要发送）
	passwordSent := password == ""

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(timeout))

	var loginBuffer bytes.Buffer
	maxAttempts := 3
	usernameSent := false         // 跟踪是否已发送用户名
	passwordWaitAttempts := 0     // 等待密码提示的尝试次数
	maxPasswordWaitAttempts := 10 // 最多等待密码提示的次数
	// passwordSent 已在函数开头根据 password 是否为空设置

	// 等待并读取登录提示
	for attempt := 0; attempt < maxAttempts; attempt++ {
		xlog.Default().Info("Login attempt",
			xlog.String("attempt", fmt.Sprintf("%d/%d", attempt+1, maxAttempts)),
			xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)),
			xlog.String("passwordSent", fmt.Sprintf("%v", passwordSent)))

		// 读取数据直到遇到提示符
		data := make([]byte, 4096)
		n, err := conn.Read(data)
		xlog.Default().Info("Read result",
			xlog.String("n", fmt.Sprintf("%d", n)),
			xlog.String("err", fmt.Sprintf("%v", err)),
			xlog.String("hasData", fmt.Sprintf("%v", n > 0)))

		// 处理 EOF（连接关闭）
		if err == io.EOF {
			xlog.Default().Info("Connection closed (EOF), checking if login was successful",
				xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)),
				xlog.String("passwordSent", fmt.Sprintf("%v", passwordSent)))
			// 如果已发送用户名和密码（或不需要密码），检查是否已登录成功
			if (usernameSent && passwordSent) || passwordSent {
				// 检查缓冲区中是否有命令提示符
				rawBytes := loginBuffer.Bytes()
				filteredBytes := FilterTelnetControlChars(rawBytes)
				received := string(filteredBytes)
				receivedLower := strings.ToLower(received)

				// 检查是否包含命令提示符
				hasPrompt := strings.Contains(receivedLower, ">") ||
					strings.Contains(receivedLower, "#") ||
					strings.Contains(receivedLower, "$") ||
					strings.Contains(receivedLower, "%") ||
					strings.Contains(receivedLower, "]")

				if hasPrompt {
					xlog.Default().Info("Login success detected after EOF", xlog.String("received", strings.TrimSpace(received)))
					conn.SetReadDeadline(time.Time{})
					return nil
				}
			}
			// EOF 但未登录成功，返回错误
			return fmt.Errorf("login failed: connection closed before login completed")
		}

		if err != nil && err != io.EOF {
			// 如果是超时错误
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				xlog.Default().Info("Read timeout",
					xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)),
					xlog.String("passwordSent", fmt.Sprintf("%v", passwordSent)),
					xlog.String("attempt", fmt.Sprintf("%d", attempt)))

				if usernameSent && !passwordSent {
					// 已发送用户名但未发送密码，继续等待
					passwordWaitAttempts++
					xlog.Default().Info("Waiting for password prompt",
						xlog.String("passwordWaitAttempts", fmt.Sprintf("%d/%d", passwordWaitAttempts, maxPasswordWaitAttempts)))
					if passwordWaitAttempts >= maxPasswordWaitAttempts {
						xlog.Default().Error("Max password wait attempts reached, giving up")
						return fmt.Errorf("login failed: timeout waiting for password prompt")
					}
					// 重置超时，继续下一次读取，但不增加 attempt
					conn.SetReadDeadline(time.Now().Add(timeout))
					attempt-- // 抵消循环的 attempt++，继续等待
					continue
				} else if !usernameSent {
					// 未发送用户名，可能是设备不发送提示，尝试直接发送用户名
					if username != "" {
						xlog.Default().Info("Timeout and username not sent, attempting to send username directly",
							xlog.String("attempt", fmt.Sprintf("%d", attempt)))
						loginData := []byte(username + "\r\n")
						if err := network.WriteAll(conn, loginData); err != nil {
							return fmt.Errorf("failed to send username: %w", err)
						}
						usernameSent = true
						conn.SetReadDeadline(time.Now().Add(timeout))
						attempt-- // 不增加 attempt，继续等待
						continue
					}
				}
			}
			// 其他错误或不是等待密码的情况，返回错误
			xlog.Default().Error("Read error (not timeout)",
				xlog.String("err", err.Error()),
				xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)),
				xlog.String("passwordSent", fmt.Sprintf("%v", passwordSent)))
			return fmt.Errorf("failed to read login prompt: %w", err)
		}
		// 成功读取到数据，重置密码等待计数器
		if n > 0 {
			passwordWaitAttempts = 0
		}
		if n > 0 {
			// 处理新接收到的 telnet 选项协商（响应设备的选项请求）
			if err := handleTelnetNegotiation(conn, data[:n]); err != nil {
				return fmt.Errorf("failed to handle telnet negotiation: %w", err)
			}
			loginBuffer.Write(data[:n])
		}

		// 过滤掉 telnet 控制字符（IAC 序列）
		rawBytes := loginBuffer.Bytes()
		filteredBytes := FilterTelnetControlChars(rawBytes)

		xlog.Default().Info("Data processing",
			xlog.String("rawBytesLen", fmt.Sprintf("%d", len(rawBytes))),
			xlog.String("filteredBytesLen", fmt.Sprintf("%d", len(filteredBytes))),
			xlog.String("rawHex", fmt.Sprintf("%x", rawBytes)),
			xlog.String("filteredHex", fmt.Sprintf("%x", filteredBytes)))

		// 如果过滤后的数据为空（只有控制字符），继续等待更多数据
		if len(filteredBytes) == 0 {
			xlog.Default().Info("Filtered data is empty",
				xlog.String("n", fmt.Sprintf("%d", n)),
				xlog.String("attempt", fmt.Sprintf("%d", attempt)),
				xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)))

			if n > 0 {
				// 收到了数据（虽然是控制字符），继续等待
				xlog.Default().Info("Received control characters only, continuing to wait")
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				// 不增加 attempt，继续等待
				attempt--
				continue
			}
			// 没有收到数据，如果是第一次尝试且未发送用户名，尝试直接发送用户名
			if attempt == 0 && !usernameSent && username != "" {
				xlog.Default().Info("No data received on first read, attempting to send username directly")
				loginData := []byte(username + "\r\n")
				if err := network.WriteAll(conn, loginData); err != nil {
					return fmt.Errorf("failed to send username: %w", err)
				}
				usernameSent = true
				conn.SetReadDeadline(time.Now().Add(timeout))
				attempt-- // 不增加 attempt，继续等待
				continue
			}
			// 其他情况，继续等待
			xlog.Default().Info("No data and not first attempt, continuing to wait")
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			attempt-- // 不增加 attempt，继续等待
			continue
		}

		// 检查是否包含常见的登录提示符（使用过滤后的数据）
		received := string(filteredBytes)
		receivedLower := strings.ToLower(received)

		xlog.Default().Info("Processing filtered data",
			xlog.String("received", received),
			xlog.String("receivedEscaped", fmt.Sprintf("%q", received)),
			xlog.String("receivedLength", fmt.Sprintf("%d", len(received))))

		// 检查是否已经登录成功（出现命令提示符）
		// 注意：某些设备可能会显示 "Password required, but none set" 等信息性消息
		// 但这些消息不应该被理解为"不需要密码"，应该继续等待密码提示
		// 只有在看到明确的命令提示符时，才认为可能不需要密码
		hasPrompt := false
		lines := strings.Split(received, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
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
					hasPrompt = true
					break
				}
			}
		}

		// 如果看到命令提示符，且已发送密码（或密码为空），认为登录成功
		// 注意：即使看到 "Password required, but none set" 等消息，只要没有命令提示符，
		// 就应该继续等待密码提示，因为设备可能仍然需要密码
		if hasPrompt && passwordSent {
			xlog.Default().Info("Login success detected (command prompt found)", xlog.String("received", strings.TrimSpace(received)))
			conn.SetReadDeadline(time.Time{})
			return nil
		}

		// 如果看到 "Password required, but none set" 等信息性消息，记录日志但继续等待密码提示
		// 这些消息不应该导致跳过密码输入
		if strings.Contains(receivedLower, "password required, but none set") ||
			strings.Contains(receivedLower, "password required but none set") ||
			strings.Contains(receivedLower, "password not set") ||
			strings.Contains(receivedLower, "no password set") {
			xlog.Default().Info("Received informational message about password, continuing to wait for password prompt",
				xlog.String("message", strings.TrimSpace(received)))
			// 不清空缓冲区，继续累积数据以检测密码提示
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			attempt-- // 不增加 attempt，继续等待
			continue
		}

		// 优先检查密码提示（如果已发送用户名）
		// 这样可以更快地响应密码提示
		if usernameSent {
			// 检查密码提示
			isPwd := isPasswordPrompt(received)
			xlog.Default().Info("Checking password prompt after username sent",
				xlog.String("isPasswordPrompt", fmt.Sprintf("%v", isPwd)),
				xlog.String("received", received))

			if isPwd {
				xlog.Default().Info("Password prompt detected", xlog.String("received", received))
				// 发送密码
				if password != "" {
					loginData := []byte(password + "\r\n")
					if err := network.WriteAll(conn, loginData); err != nil {
						return fmt.Errorf("failed to send password: %w", err)
					}
					xlog.Default().Info("Password sent")
					loginBuffer.Reset()
					usernameSent = false // 重置标志
					passwordSent = true  // 标记已发送密码
					conn.SetReadDeadline(time.Now().Add(timeout))
					continue
				}
			} else {
				// 已发送用户名但未检测到密码提示，可能是用户名回显或其他数据
				// 继续等待密码提示，不增加 attempt
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				attempt-- // 不增加 attempt，继续等待
				continue
			}
		}

		// 检查用户名提示（仅在未发送用户名时检查）
		if !usernameSent && (strings.Contains(receivedLower, "login:") ||
			strings.Contains(receivedLower, "username:") ||
			strings.Contains(receivedLower, "user:") ||
			strings.Contains(receivedLower, "user name:")) {
			xlog.Default().Info("Username prompt detected", xlog.String("received", received))
			// 发送用户名
			if username != "" {
				loginData := []byte(username + "\r\n")
				if err := network.WriteAll(conn, loginData); err != nil {
					return fmt.Errorf("failed to send username: %w", err)
				}
				usernameSent = true // 标记已发送用户名
				// 等待一小段时间，让设备处理用户名
				time.Sleep(300 * time.Millisecond)
				// 不清空缓冲区，继续累积数据以检测密码提示
				conn.SetReadDeadline(time.Now().Add(timeout))
				// 不增加 attempt，继续等待密码提示
				attempt-- // 抵消循环的 attempt++，继续等待
				continue
			}
		}

		// 检查密码提示（忽略大小写）- 通用检查
		isPwdPrompt := isPasswordPrompt(received)
		xlog.Default().Info("Checking password prompt (general check)",
			xlog.String("isPasswordPrompt", fmt.Sprintf("%v", isPwdPrompt)),
			xlog.String("received", received),
			xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)))

		if isPwdPrompt {
			xlog.Default().Info("Password prompt detected", xlog.String("received", received))
			// 发送密码
			if password != "" {
				loginData := []byte(password + "\r\n")
				if err := network.WriteAll(conn, loginData); err != nil {
					return fmt.Errorf("failed to send password: %w", err)
				}
				xlog.Default().Info("Password sent")
				loginBuffer.Reset()
				passwordSent = true // 标记已发送密码
				conn.SetReadDeadline(time.Now().Add(timeout))
				continue
			}
		}

		// 重要：如果已发送用户名但未发送密码，不应该认为登录成功
		// 必须发送密码后才能认为登录成功
		// 将这个检查放在最前面，避免任何误判
		if usernameSent && !passwordSent {
			// 继续等待密码提示，绝对不检查登录成功
			if n > 0 {
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				continue
			}
			// 即使没有收到数据，也继续等待
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			continue
		}

		// 检查是否已经登录成功（出现命令提示符）
		// 注意：# 通常表示特权模式，> 表示普通模式
		// 检查提示符时，需要确保不是在密码提示中（避免误判）
		// 某些设备可能在提示符前后有换行符或空格
		// 使用统一的密码提示检测函数（忽略大小写）
		// isPwdPrompt 已在上面声明，这里重新检查
		isPwdPrompt = isPasswordPrompt(received)

		// 检查是否包含命令提示符（不在密码提示中）
		// 使用更严格的检查：提示符应该在行尾，且前面应该有文本（表示是命令提示符而不是其他字符）
		hasPrompt = false
		if !isPwdPrompt {
			// 按行检查，确保提示符在行尾
			lines := strings.Split(received, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				// 检查行尾是否有命令提示符，且前面有文本（不是单独一个提示符）
				if (strings.HasSuffix(line, ">") || strings.HasSuffix(line, "#") ||
					strings.HasSuffix(line, "$") || strings.HasSuffix(line, "%") ||
					strings.HasSuffix(line, "]")) && len(line) > 1 {
					// 确保不是密码提示的一部分
					lineLower := strings.ToLower(line)
					if !strings.Contains(lineLower, "password") &&
						!strings.Contains(lineLower, "passwd") &&
						!strings.Contains(lineLower, "login:") {
						hasPrompt = true
						break
					}
				}
			}
		}

		// 如果已经登录成功，且不在密码提示中，且已发送密码
		// 再次确认：必须已发送密码才能认为登录成功
		if hasPrompt && !isPwdPrompt && passwordSent {
			xlog.Default().Info("Login success detected", xlog.String("received", strings.TrimSpace(received)))
			// 如果提供了提权命令，执行提权流程
			if enableCmd != "" {
				xlog.Default().Info("Starting enable process", xlog.String("enableCmd", enableCmd))
				// 先清除读取超时，准备执行提权
				conn.SetReadDeadline(time.Time{})

				// 执行提权流程
				if err := performEnable(conn, enableCmd, enablePassword, timeout); err != nil {
					return fmt.Errorf("enable failed: %w", err)
				}
				xlog.Default().Info("Enable process completed successfully")
				// 提权成功，清除读取超时，允许正常通信
				conn.SetReadDeadline(time.Time{})
				return nil
			}

			// 没有提权命令，直接返回
			// 清除读取超时，允许正常通信
			conn.SetReadDeadline(time.Time{})
			return nil
		}

		// 检查登录失败
		if strings.Contains(receivedLower, "incorrect") ||
			strings.Contains(receivedLower, "invalid") ||
			strings.Contains(receivedLower, "denied") ||
			strings.Contains(receivedLower, "failed") {
			return fmt.Errorf("login failed: authentication error")
		}

		// 如果收到数据但没有明确的提示符，等待更多数据
		if n > 0 {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			continue
		}

		// 如果已发送用户名但未发送密码，且没有读取到数据，继续等待
		if usernameSent && !passwordSent {
			conn.SetReadDeadline(time.Now().Add(timeout))
			// 不增加 attempt，继续等待
			attempt--
			continue
		}

		// 如果已发送用户名但超时，尝试直接发送密码（某些设备可能不显示明确的密码提示）
		if usernameSent && password != "" && len(filteredBytes) == 0 {
			loginData := []byte(password + "\r\n")
			if err := network.WriteAll(conn, loginData); err != nil {
				return fmt.Errorf("failed to send password: %w", err)
			}
			xlog.Default().Info("Password sent (fallback)")
			loginBuffer.Reset()
			passwordSent = true // 标记已发送密码
			conn.SetReadDeadline(time.Now().Add(timeout))
			continue
		}

		// 超时，尝试发送用户名（某些设备可能不发送提示）
		if attempt == 0 && username != "" && !usernameSent {
			loginData := []byte(username + "\r\n")
			if err := network.WriteAll(conn, loginData); err != nil {
				return fmt.Errorf("failed to send username: %w", err)
			}
			usernameSent = true
			conn.SetReadDeadline(time.Now().Add(timeout))
			continue
		}
	}

	// 清除读取超时
	conn.SetReadDeadline(time.Time{})

	// 重要检查：如果已发送用户名但未发送密码，不应该返回成功
	// 必须发送密码后才能认为登录成功
	if usernameSent && !passwordSent {
		xlog.Default().Error("Login failed: username sent but password not sent",
			xlog.String("usernameSent", fmt.Sprintf("%v", usernameSent)),
			xlog.String("passwordSent", fmt.Sprintf("%v", passwordSent)))
		return fmt.Errorf("login failed: password not sent after username")
	}

	// 如果提供了提权命令，尝试执行提权（即使没有明确的登录成功提示）
	if enableCmd != "" {
		xlog.Default().Info("Attempting enable process (no clear login prompt detected)", xlog.String("enableCmd", enableCmd))
		if err := performEnable(conn, enableCmd, enablePassword, timeout); err != nil {
			// 提权失败不影响，可能已经登录成功
			// 记录警告但继续
			xlog.Default().Warn("Enable process failed, but continuing", xlog.FieldErr(err))
		} else {
			xlog.Default().Info("Enable process completed (fallback)")
		}
	}

	// 只有在已发送密码（或密码为空）的情况下才返回成功
	if passwordSent {
		return nil
	}

	// 如果既没有发送用户名也没有发送密码，可能是无需登录的情况
	// 这种情况在函数开头已经处理了，这里不应该到达
	return fmt.Errorf("login failed: unexpected state")
}

// performEnable 执行提权流程
// enableCmd 是提权命令（如 "enable", "su", "sudo su" 等）
// enablePassword 是提权密码
func performEnable(conn net.Conn, enableCmd, enablePassword string, timeout time.Duration) error {
	if enableCmd == "" {
		return nil
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(timeout))

	var enableBuffer bytes.Buffer
	// 只尝试少量次数，发送完密码后立即返回
	maxAttempts := 2

	// 发送提权命令
	enableData := []byte(enableCmd + "\r\n")
	xlog.Default().Info("Sending enable command", xlog.String("command", enableCmd))
	if err := network.WriteAll(conn, enableData); err != nil {
		return fmt.Errorf("failed to send enable command: %w", err)
	}

	// 等待一小段时间，让设备处理 enable 命令
	time.Sleep(300 * time.Millisecond)

	// 等待并读取提权提示
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// 读取数据直到遇到提示符
		data := make([]byte, 4096)
		n, err := conn.Read(data)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read enable prompt: %w", err)
		}
		if n > 0 {
			enableBuffer.Write(data[:n])
		}

		// 过滤掉 telnet 控制字符（IAC 序列）
		rawBytes := enableBuffer.Bytes()
		filteredBytes := FilterTelnetControlChars(rawBytes)

		// 检查是否包含常见的提权提示符（使用过滤后的数据）
		received := string(filteredBytes)
		receivedLower := strings.ToLower(received)

		// 检查密码提示（提权通常需要密码，忽略大小写）
		if isPasswordPrompt(received) {
			xlog.Default().Info("Enable password prompt detected")
			// 发送提权密码
			if enablePassword != "" {
				// 等待一小段时间，确保设备准备好接收密码
				time.Sleep(200 * time.Millisecond)
				passwordData := []byte(enablePassword + "\r\n")
				xlog.Default().Info("Sending enable password")
				if err := network.WriteAll(conn, passwordData); err != nil {
					return fmt.Errorf("failed to send enable password: %w", err)
				}
				// 等待一小段时间，让设备验证密码
				time.Sleep(300 * time.Millisecond)
				// 发送完密码后立即返回，不等待提权结果
				// 让数据转发立即开始，无论提权成功还是失败
				xlog.Default().Info("Enable password sent, starting data forwarding")
				conn.SetReadDeadline(time.Time{})
				return nil
			} else {
				// 没有提供提权密码，可能不需要密码，继续等待
				xlog.Default().Warn("Enable password prompt detected but no password provided")
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				continue
			}
		}

		// 检查是否已经提权成功（出现特权模式提示符 #）
		// 某些设备在提权后提示符会从 > 变为 #
		if strings.Contains(receivedLower, "#") {
			xlog.Default().Info("Enable success detected (privileged mode #)")
			// 清除读取超时，允许正常通信
			conn.SetReadDeadline(time.Time{})
			return nil
		}

		// 检查提权失败
		if strings.Contains(receivedLower, "incorrect") ||
			strings.Contains(receivedLower, "invalid") ||
			strings.Contains(receivedLower, "denied") ||
			strings.Contains(receivedLower, "failed") ||
			strings.Contains(receivedLower, "access denied") {
			return fmt.Errorf("enable failed: authentication error")
		}

		// 如果收到数据但没有明确的提示符，可能是设备不需要密码或已经成功
		// 立即返回，开始数据转发
		if n > 0 {
			xlog.Default().Info("Received data after enable command, starting data forwarding", xlog.String("data", strings.TrimSpace(received)))
			conn.SetReadDeadline(time.Time{})
			return nil
		}

		// 超时，说明设备可能不需要密码或已经成功，立即返回开始数据转发
		if attempt >= maxAttempts-1 {
			xlog.Default().Info("Timeout after enable command, starting data forwarding")
			conn.SetReadDeadline(time.Time{})
			return nil
		}
	}

	// 清除读取超时，立即返回开始数据转发
	conn.SetReadDeadline(time.Time{})
	xlog.Default().Info("Enable process completed, starting data forwarding")
	return nil
}

// ============================================================================
// 状态机实现的登录流程
// ============================================================================

// LoginState 登录状态
type LoginState int

const (
	StateInit LoginState = iota
	StateWaitUsername
	StateWaitPassword
	StateWaitLoginSuccess
	StateLoginSuccess
	StateLoginFailed
	StateEnabling
)

// String 返回状态的字符串表示
func (s LoginState) String() string {
	switch s {
	case StateInit:
		return "Init"
	case StateWaitUsername:
		return "WaitUsername"
	case StateWaitPassword:
		return "WaitPassword"
	case StateWaitLoginSuccess:
		return "WaitLoginSuccess"
	case StateLoginSuccess:
		return "LoginSuccess"
	case StateLoginFailed:
		return "LoginFailed"
	case StateEnabling:
		return "Enabling"
	default:
		return "Unknown"
	}
}

// LoginEvent 登录事件
type LoginEvent int

const (
	EventDataReceived LoginEvent = iota
	EventTimeout
	EventEOF
	EventUsernamePrompt
	EventPasswordPrompt
	EventCommandPrompt
	EventError
	EventEnableCommandSent
)

// String 返回事件的字符串表示
func (e LoginEvent) String() string {
	switch e {
	case EventDataReceived:
		return "DataReceived"
	case EventTimeout:
		return "Timeout"
	case EventEOF:
		return "EOF"
	case EventUsernamePrompt:
		return "UsernamePrompt"
	case EventPasswordPrompt:
		return "PasswordPrompt"
	case EventCommandPrompt:
		return "CommandPrompt"
	case EventError:
		return "Error"
	case EventEnableCommandSent:
		return "EnableCommandSent"
	default:
		return "Unknown"
	}
}

// LoginStateMachine 登录状态机上下文
type LoginStateMachine struct {
	conn                    net.Conn
	username                string
	password                string
	enableCmd               string
	enablePassword          string
	timeout                 time.Duration
	currentState            LoginState
	loginBuffer             bytes.Buffer
	attempt                 int
	maxAttempts             int
	passwordWaitAttempts    int
	maxPasswordWaitAttempts int
	usernameSent            bool
	passwordSent            bool
	enableCmdSent           bool // 标记 enable 命令是否已发送
	enablePasswordSent      bool // 标记 enable 密码是否已发送
}

// GetLoginData 获取登录过程中读取到的数据（包含提示符）
// 在登录成功后调用，返回的数据应该转发给客户端
func (sm *LoginStateMachine) GetLoginData() []byte {
	return sm.loginBuffer.Bytes()
}

// NewLoginStateMachine 创建新的登录状态机
func NewLoginStateMachine(conn net.Conn, username, password, enableCmd, enablePassword string, timeout time.Duration) *LoginStateMachine {
	return &LoginStateMachine{
		conn:                    conn,
		username:                username,
		password:                password,
		enableCmd:               enableCmd,
		enablePassword:          enablePassword,
		timeout:                 timeout,
		currentState:            StateInit,
		maxAttempts:             3,
		maxPasswordWaitAttempts: 10,
		passwordSent:            password == "", // 如果密码为空，标记为已发送
	}
}

// dispatch 根据当前状态和事件进行状态转换和处理
func (sm *LoginStateMachine) dispatch(event LoginEvent, data interface{}) error {
	xlog.Default().Info("State machine dispatch",
		xlog.String("state", sm.currentState.String()),
		xlog.String("event", event.String()))

	switch sm.currentState {
	case StateInit:
		return sm.handleInit(event, data)
	case StateWaitUsername:
		return sm.handleWaitUsername(event, data)
	case StateWaitPassword:
		return sm.handleWaitPassword(event, data)
	case StateWaitLoginSuccess:
		return sm.handleWaitLoginSuccess(event, data)
	case StateEnabling:
		return sm.handleEnabling(event, data)
	default:
		return fmt.Errorf("unhandled state: %s", sm.currentState.String())
	}
}

// handleInit 处理初始状态
func (sm *LoginStateMachine) handleInit(event LoginEvent, data interface{}) error {
	switch event {
	case EventDataReceived:
		received := data.(string)
		receivedLower := strings.ToLower(received)

		// 检查是否包含用户名提示
		if strings.Contains(receivedLower, "login:") ||
			strings.Contains(receivedLower, "username:") ||
			strings.Contains(receivedLower, "user:") ||
			strings.Contains(receivedLower, "user name:") {
			// 发送用户名
			if sm.username != "" {
				loginData := []byte(sm.username + "\r\n")
				if err := network.WriteAll(sm.conn, loginData); err != nil {
					sm.currentState = StateLoginFailed
					return fmt.Errorf("failed to send username: %w", err)
				}
				sm.usernameSent = true
				sm.currentState = StateWaitPassword
				xlog.Default().Info("Username sent, transitioning to WaitPassword")
				time.Sleep(300 * time.Millisecond)
				return nil
			}
		}

		// 检查是否直接是密码提示（某些设备不需要用户名）
		if isPasswordPrompt(received) {
			if sm.password != "" {
				loginData := []byte(sm.password + "\r\n")
				if err := network.WriteAll(sm.conn, loginData); err != nil {
					sm.currentState = StateLoginFailed
					return fmt.Errorf("failed to send password: %w", err)
				}
				sm.passwordSent = true
				sm.currentState = StateWaitLoginSuccess
				xlog.Default().Info("Password sent (no username required), transitioning to WaitLoginSuccess")
				return nil
			}
		}

		// 检查是否已经有命令提示符（某些设备不需要登录）
		if sm.hasCommandPrompt(received) {
			if sm.passwordSent {
				sm.currentState = StateLoginSuccess
				return nil
			}
		}

		// 如果看到 "Password required, but none set" 等信息，继续等待
		if strings.Contains(receivedLower, "password required, but none set") ||
			strings.Contains(receivedLower, "password required but none set") {
			xlog.Default().Info("Received informational message, continuing to wait")
			// 保持在 Init 状态，继续等待
			return nil
		}

		// 检查错误消息
		if strings.Contains(receivedLower, "incorrect") ||
			strings.Contains(receivedLower, "invalid") ||
			strings.Contains(receivedLower, "denied") ||
			strings.Contains(receivedLower, "failed") {
			sm.currentState = StateLoginFailed
			return fmt.Errorf("login failed: authentication error")
		}

		// 没有明确的提示，继续等待
		return nil

	case EventTimeout:
		// 超时，如果还没有发送用户名，尝试直接发送
		// 但在发送之前，确保我们已经处理了所有 telnet 协商
		if !sm.usernameSent && sm.username != "" {
			// 在发送用户名之前，先尝试读取并处理任何待处理的 telnet 协商
			// 设置一个很短的超时来检查是否有待处理的数据
			sm.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			negotiationData := make([]byte, 1024)
			if n, err := sm.conn.Read(negotiationData); err == nil && n > 0 {
				// 有数据，处理 telnet 协商
				if err := handleTelnetNegotiation(sm.conn, negotiationData[:n]); err != nil {
					xlog.Default().Warn("Failed to handle telnet negotiation before sending username", xlog.FieldErr(err))
				}
				sm.loginBuffer.Write(negotiationData[:n])
			}
			// 重置超时
			sm.conn.SetReadDeadline(time.Now().Add(sm.timeout))

			// 现在发送用户名
			loginData := []byte(sm.username + "\r\n")
			if err := network.WriteAll(sm.conn, loginData); err != nil {
				sm.currentState = StateLoginFailed
				return fmt.Errorf("failed to send username: %w", err)
			}
			sm.usernameSent = true
			sm.currentState = StateWaitPassword
			xlog.Default().Info("Timeout in Init, sent username directly, transitioning to WaitPassword")
			// 等待一小段时间，让设备处理用户名
			time.Sleep(200 * time.Millisecond)
			return nil
		}
		// 如果已经发送了用户名，不应该在 Init 状态
		return nil

	case EventEOF:
		// 连接关闭，检查是否已经登录成功
		if sm.passwordSent {
			rawBytes := sm.loginBuffer.Bytes()
			filteredBytes := FilterTelnetControlChars(rawBytes)
			received := string(filteredBytes)
			if sm.hasCommandPrompt(received) {
				sm.currentState = StateLoginSuccess
				return nil
			}
		}
		sm.currentState = StateLoginFailed
		return fmt.Errorf("login failed: connection closed before login completed")

	default:
		return nil
	}
}

// handleWaitUsername 处理等待用户名提示状态
func (sm *LoginStateMachine) handleWaitUsername(event LoginEvent, data interface{}) error {
	// 这个状态实际上很少使用，因为大多数情况下我们在 Init 状态就处理了用户名提示
	// 但保留它以便处理特殊情况
	return sm.handleInit(event, data)
}

// handleWaitPassword 处理等待密码提示状态
func (sm *LoginStateMachine) handleWaitPassword(event LoginEvent, data interface{}) error {
	switch event {
	case EventDataReceived, EventUsernamePrompt, EventPasswordPrompt:
		// 在 WaitPassword 状态下，无论事件类型如何，都要检查是否包含密码提示
		// 因为数据可能同时包含用户名和密码提示
		received := data.(string)
		receivedLower := strings.ToLower(received)

		// 优先检查密码提示（即使事件是 UsernamePrompt，数据中可能也包含密码提示）
		if isPasswordPrompt(received) {
			if sm.password != "" {
				loginData := []byte(sm.password + "\r\n")
				if err := network.WriteAll(sm.conn, loginData); err != nil {
					sm.currentState = StateLoginFailed
					return fmt.Errorf("failed to send password: %w", err)
				}
				sm.passwordSent = true
				sm.currentState = StateWaitLoginSuccess
				sm.loginBuffer.Reset()
				xlog.Default().Info("Password sent, transitioning to WaitLoginSuccess",
					xlog.String("originalEvent", event.String()))
				return nil
			}
		}

		// 检查是否已经有命令提示符（某些设备在发送密码后立即显示提示符）
		if sm.hasCommandPrompt(received) {
			if sm.passwordSent {
				sm.currentState = StateLoginSuccess
				return nil
			}
		}

		// 检查错误消息
		if strings.Contains(receivedLower, "incorrect") ||
			strings.Contains(receivedLower, "invalid") ||
			strings.Contains(receivedLower, "denied") ||
			strings.Contains(receivedLower, "failed") {
			sm.currentState = StateLoginFailed
			return fmt.Errorf("login failed: authentication error")
		}

		// 继续等待密码提示
		return nil

	case EventTimeout:
		// 超时等待密码提示
		sm.passwordWaitAttempts++
		if sm.passwordWaitAttempts >= sm.maxPasswordWaitAttempts {
			sm.currentState = StateLoginFailed
			return fmt.Errorf("login failed: timeout waiting for password prompt")
		}
		xlog.Default().Info("Timeout waiting for password prompt",
			xlog.String("attempts", fmt.Sprintf("%d/%d", sm.passwordWaitAttempts, sm.maxPasswordWaitAttempts)))
		// 某些设备可能不显示明确的密码提示，尝试直接发送密码
		if sm.password != "" && sm.passwordWaitAttempts >= 3 {
			loginData := []byte(sm.password + "\r\n")
			if err := network.WriteAll(sm.conn, loginData); err != nil {
				sm.currentState = StateLoginFailed
				return fmt.Errorf("failed to send password: %w", err)
			}
			sm.passwordSent = true
			sm.currentState = StateWaitLoginSuccess
			xlog.Default().Info("Timeout in WaitPassword, sent password directly, transitioning to WaitLoginSuccess")
			return nil
		}
		return nil

	case EventEOF:
		sm.currentState = StateLoginFailed
		return fmt.Errorf("login failed: connection closed while waiting for password")

	default:
		return nil
	}
}

// handleWaitLoginSuccess 处理等待登录成功状态
func (sm *LoginStateMachine) handleWaitLoginSuccess(event LoginEvent, data interface{}) error {
	switch event {
	case EventDataReceived, EventCommandPrompt, EventError:
		// 无论事件类型如何，都先检查是否包含命令提示符
		// 因为命令提示符是登录成功的明确标志
		received := data.(string)
		receivedLower := strings.ToLower(received)

		// 优先检查命令提示符（即使事件是 EventError，也可能包含命令提示符）
		if sm.hasCommandPrompt(received) {
			sm.currentState = StateLoginSuccess
			xlog.Default().Info("Login success detected",
				xlog.String("received", strings.TrimSpace(received)),
				xlog.String("originalEvent", event.String()),
				xlog.String("enableCmd", sm.enableCmd),
				xlog.String("hasEnablePassword", fmt.Sprintf("%v", sm.enablePassword != "")))
			// 注意：不在这里直接进入提权状态，让主循环检查并处理
			return nil
		}

		// 只有在没有命令提示符的情况下，才检查错误消息
		if event == EventError {
			// 使用更精确的错误检测
			errorPatterns := []string{
				"login failed",
				"authentication failed",
				"access denied",
				"permission denied",
				"incorrect password",
				"invalid password",
				"incorrect username",
				"invalid username",
				"authentication error",
				"login incorrect",
				"login invalid",
			}

			for _, pattern := range errorPatterns {
				if strings.Contains(receivedLower, pattern) {
					sm.currentState = StateLoginFailed
					return fmt.Errorf("login failed: authentication error")
				}
			}
		}

		// 继续等待命令提示符
		return nil

	case EventTimeout:
		// 超时，检查是否已经有命令提示符在缓冲区中
		rawBytes := sm.loginBuffer.Bytes()
		filteredBytes := FilterTelnetControlChars(rawBytes)
		received := string(filteredBytes)
		if sm.hasCommandPrompt(received) {
			sm.currentState = StateLoginSuccess
			return nil
		}
		// 否则认为登录成功（某些设备可能不发送明确的提示符）
		sm.currentState = StateLoginSuccess
		return nil

	case EventEOF:
		// 连接关闭，检查是否已经登录成功
		rawBytes := sm.loginBuffer.Bytes()
		filteredBytes := FilterTelnetControlChars(rawBytes)
		received := string(filteredBytes)
		if sm.hasCommandPrompt(received) {
			sm.currentState = StateLoginSuccess
			return nil
		}
		sm.currentState = StateLoginFailed
		return fmt.Errorf("login failed: connection closed before login completed")

	default:
		return nil
	}
}

// handleEnabling 处理提权状态
func (sm *LoginStateMachine) handleEnabling(event LoginEvent, data interface{}) error {
	xlog.Default().Info("handleEnabling called",
		xlog.String("event", event.String()),
		xlog.String("state", sm.currentState.String()))

	switch event {
	case EventEnableCommandSent:
		// 检查是否已经发送过 enable 命令（使用独立的标志，避免误判）
		if sm.enableCmdSent {
			xlog.Default().Info("Enable command already sent, skipping",
				xlog.String("enableCmd", sm.enableCmd))
			return nil
		}

		// 发送提权命令
		enableData := []byte(sm.enableCmd + "\r\n")
		xlog.Default().Info("Sending enable command",
			xlog.String("command", sm.enableCmd),
			xlog.String("data", fmt.Sprintf("%q", string(enableData))))
		if err := network.WriteAll(sm.conn, enableData); err != nil {
			sm.currentState = StateLoginFailed
			return fmt.Errorf("failed to send enable command: %w", err)
		}
		// 标记 enable 命令已发送（发送后就不能再次发送）
		sm.enableCmdSent = true
		// 将 enable 命令添加到缓冲区，用于检测是否已发送
		// 注意：这里只添加我们发送的命令，不包括设备回显
		sm.loginBuffer.Write(enableData)
		xlog.Default().Debug("Enable command written to buffer",
			xlog.String("bufferAfter", fmt.Sprintf("%q", sm.loginBuffer.String())))
		// 等待一小段时间，让设备处理 enable 命令
		time.Sleep(300 * time.Millisecond)
		// 继续读取，等待密码提示或命令提示符
		return nil

	case EventDataReceived, EventPasswordPrompt, EventCommandPrompt:
		// 读取提权过程中的数据
		received := data.(string)
		receivedLower := strings.ToLower(received)

		xlog.Default().Info("Processing data in Enabling state (case branch entered)",
			xlog.String("event", event.String()),
			xlog.String("received", fmt.Sprintf("%q", received)),
			xlog.Int("receivedLength", len(received)))

		// 注意：数据已经在主循环中被添加到缓冲区了，这里不需要再次添加
		// 优先检查是否包含 # 提示符（特权模式），如果检测到就立即退出提权状态
		// 这是最高优先级，因为 # 提示符表示提权已经成功
		// 使用更精确的检测：检查是否包含以 # 结尾的行
		// 同时检查整个缓冲区，因为可能之前的读取中已经包含了 # 提示符
		fullBufferStr := sm.loginBuffer.String()
		allLines := strings.Split(fullBufferStr, "\n")
		for _, line := range allLines {
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			// 检查是否以 # 结尾（特权模式提示符）
			if strings.HasSuffix(line, "#") && len(line) > 1 {
				lineLower := strings.ToLower(line)
				// 确保不是密码提示的一部分
				if !strings.Contains(lineLower, "password") &&
					!strings.Contains(lineLower, "passwd") &&
					!strings.Contains(lineLower, "login:") &&
					!strings.Contains(lineLower, "密码") {
					xlog.Default().Info("Enable success detected (privileged mode #)",
						xlog.String("prompt", line),
						xlog.String("fullReceived", fmt.Sprintf("%q", received)),
						xlog.String("fullBuffer", fmt.Sprintf("%q", fullBufferStr)))
					// 清空 enableCmd，标记提权已完成
					sm.enableCmd = ""
					sm.currentState = StateLoginSuccess
					return nil
				}
			}
		}

		// 也检查当前接收的数据
		lines := strings.Split(received, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			// 检查是否以 # 结尾（特权模式提示符）
			if strings.HasSuffix(line, "#") && len(line) > 1 {
				lineLower := strings.ToLower(line)
				// 确保不是密码提示的一部分
				if !strings.Contains(lineLower, "password") &&
					!strings.Contains(lineLower, "passwd") &&
					!strings.Contains(lineLower, "login:") &&
					!strings.Contains(lineLower, "密码") {
					xlog.Default().Info("Enable success detected (privileged mode #)",
						xlog.String("prompt", line),
						xlog.String("fullReceived", fmt.Sprintf("%q", received)))
					// 清空 enableCmd，标记提权已完成
					sm.enableCmd = ""
					sm.currentState = StateLoginSuccess
					return nil
				}
			}
		}

		// 如果没有检测到 # 提示符，检查密码提示（只有在密码未发送时才检查）
		// 注意：如果密码已发送，说明提权过程正在进行中，应该等待 # 提示符
		if !sm.enablePasswordSent {
			isPwdPrompt := isPasswordPrompt(received)
			xlog.Default().Info("Password prompt check result",
				xlog.String("received", fmt.Sprintf("%q", received)),
				xlog.String("hasPasswordPrompt", fmt.Sprintf("%v", isPwdPrompt)),
				xlog.String("hasCommandPrompt", fmt.Sprintf("%v", sm.hasCommandPrompt(received))),
				xlog.String("event", event.String()))

			// 如果检测到密码提示且密码未发送，立即处理
			if isPwdPrompt {
				xlog.Default().Info("Password prompt detected in Enabling state, processing immediately",
					xlog.String("received", fmt.Sprintf("%q", received)))

				xlog.Default().Info("Enable password prompt detected",
					xlog.String("hasEnablePassword", fmt.Sprintf("%v", sm.enablePassword != "")))
				// 发送提权密码
				if sm.enablePassword != "" {
					// 延迟一点时间，让设备完全准备好接收密码
					xlog.Default().Info("Waiting 200ms before sending enable password")
					time.Sleep(200 * time.Millisecond)
					passwordData := []byte(sm.enablePassword + "\r\n")
					if err := network.WriteAll(sm.conn, passwordData); err != nil {
						sm.currentState = StateLoginFailed
						return fmt.Errorf("failed to send enable password: %w", err)
					}
					xlog.Default().Info("Enable password sent",
						xlog.Int("passwordLength", len(sm.enablePassword)))
					// 标记密码已发送
					sm.enablePasswordSent = true
					// 清除 enable 命令发送标志，允许再次发送 enable 命令（如果需要重新提权）
					sm.enableCmdSent = false
					xlog.Default().Debug("Enable command sent flag cleared, allow resending enable command if needed")
					// 将密码添加到缓冲区，用于检测是否已发送
					sm.loginBuffer.Write(passwordData)
					// 继续读取，等待命令提示符
					return nil
				} else {
					xlog.Default().Warn("Enable password prompt detected but no password provided")
					return nil
				}
			}
		} else {
			xlog.Default().Debug("Enable password already sent, skipping password prompt check, waiting for # prompt")
		}

		// 如果没有检测到 # 提示符，检查是否有其他命令提示符
		if sm.hasCommandPrompt(received) {
			// 如果检测到 > 提示符，可能是提权失败（密码错误）或设备返回了普通模式
			// 检查是否包含错误信息
			if strings.Contains(received, ">") {
				// 检查是否包含错误信息
				errorPatterns := []string{
					"incorrect",
					"invalid",
					"denied",
					"failed",
					"access denied",
				}
				hasError := false
				for _, pattern := range errorPatterns {
					if strings.Contains(receivedLower, pattern) {
						hasError = true
						break
					}
				}
				if hasError {
					xlog.Default().Warn("Enable failed, detected error message",
						xlog.String("received", strings.TrimSpace(received)))
					sm.currentState = StateLoginFailed
					return fmt.Errorf("enable failed: authentication error")
				}
				// 如果没有错误信息，可能是设备返回了普通模式提示符
				// 等待一段时间，如果还是没有 # 提示符，认为提权失败但继续（放通数据）
				xlog.Default().Debug("Received > prompt during enable, waiting for # prompt",
					xlog.String("received", strings.TrimSpace(received)))
				// 继续等待，但设置一个标志，如果超时还没有 #，就退出提权状态
				return nil
			}
			// 其他提示符（$、%、]等）也可能表示提权成功
			xlog.Default().Info("Enable success detected (command prompt)",
				xlog.String("prompt", strings.TrimSpace(received)))
			// 清空 enableCmd，标记提权已完成
			sm.enableCmd = ""
			sm.currentState = StateLoginSuccess
			return nil
		}

		// 检查提权失败
		errorPatterns := []string{
			"incorrect",
			"invalid",
			"denied",
			"failed",
			"access denied",
		}
		for _, pattern := range errorPatterns {
			if strings.Contains(receivedLower, pattern) {
				xlog.Default().Warn("Enable failed, detected error message, but continuing to allow data forwarding",
					xlog.String("received", strings.TrimSpace(received)))
				// 提权失败，但不清空 enableCmd，标记为已完成（允许数据转发）
				// 状态保持为 StateLoginSuccess，允许继续使用连接
				sm.enableCmd = ""
				sm.currentState = StateLoginSuccess
				return nil
			}
		}

		// 继续等待
		return nil

	case EventTimeout:
		// 超时，检查是否已经有命令提示符（特别是 # 提示符）
		rawBytes := sm.loginBuffer.Bytes()
		filteredBytes := FilterTelnetControlChars(rawBytes)
		received := string(filteredBytes)

		// 优先检查是否有 # 提示符（特权模式）
		lines := strings.Split(received, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			if strings.HasSuffix(line, "#") && len(line) > 1 {
				lineLower := strings.ToLower(line)
				if !strings.Contains(lineLower, "password") &&
					!strings.Contains(lineLower, "passwd") &&
					!strings.Contains(lineLower, "login:") &&
					!strings.Contains(lineLower, "密码") {
					xlog.Default().Info("Enable success detected (privileged mode #) on timeout",
						xlog.String("prompt", line))
					sm.enableCmd = ""
					sm.currentState = StateLoginSuccess
					return nil
				}
			}
		}

		// 如果没有 # 提示符，检查是否有其他命令提示符
		if sm.hasCommandPrompt(received) {
			// 清空 enableCmd，标记提权已完成（即使没有进入特权模式，也放通数据）
			sm.enableCmd = ""
			sm.currentState = StateLoginSuccess
			xlog.Default().Info("Timeout during enable process, command prompt detected, allowing data forwarding")
			return nil
		}
		// 超时但没有提示符，可能设备不需要密码或已经成功，放通数据
		xlog.Default().Info("Timeout during enable process, no prompt detected, allowing data forwarding")
		// 清空 enableCmd，标记提权已完成（允许数据转发）
		sm.enableCmd = ""
		sm.currentState = StateLoginSuccess
		return nil

	case EventEOF:
		// 连接关闭，检查是否已经提权成功
		rawBytes := sm.loginBuffer.Bytes()
		filteredBytes := FilterTelnetControlChars(rawBytes)
		received := string(filteredBytes)

		// 优先检查是否有 # 提示符
		lines := strings.Split(received, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			if strings.HasSuffix(line, "#") && len(line) > 1 {
				lineLower := strings.ToLower(line)
				if !strings.Contains(lineLower, "password") &&
					!strings.Contains(lineLower, "passwd") &&
					!strings.Contains(lineLower, "login:") &&
					!strings.Contains(lineLower, "密码") {
					xlog.Default().Info("Enable success detected (privileged mode #) on EOF",
						xlog.String("prompt", line))
					sm.enableCmd = ""
					sm.currentState = StateLoginSuccess
					return nil
				}
			}
		}

		if sm.hasCommandPrompt(received) {
			// 清空 enableCmd，标记提权已完成（允许数据转发）
			sm.enableCmd = ""
			sm.currentState = StateLoginSuccess
			xlog.Default().Info("Command prompt detected on EOF, allowing data forwarding")
			return nil
		}
		// 即使没有提示符，也放通数据（连接可能已关闭，但允许继续使用）
		xlog.Default().Info("EOF during enable process, allowing data forwarding")
		sm.enableCmd = ""
		sm.currentState = StateLoginSuccess
		return nil

	default:
		return nil
	}
}

// hasCommandPrompt 检查是否包含命令提示符
func (sm *LoginStateMachine) hasCommandPrompt(received string) bool {
	lines := strings.Split(received, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
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
	}
	return false
}

// detectEvent 从接收到的数据中检测事件
func (sm *LoginStateMachine) detectEvent(received string) LoginEvent {
	receivedLower := strings.ToLower(received)

	// 优先检查命令提示符（因为命令提示符更明确，且可能与其他文本一起出现）
	if sm.hasCommandPrompt(received) {
		return EventCommandPrompt
	}

	// 检查错误消息（使用更精确的匹配，避免误判信息性消息）
	// 只检查明确的错误消息，而不是所有包含 "failed" 的文本
	errorPatterns := []string{
		"login failed",
		"authentication failed",
		"access denied",
		"permission denied",
		"incorrect password",
		"invalid password",
		"incorrect username",
		"invalid username",
		"authentication error",
		"login incorrect",
		"login invalid",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(receivedLower, pattern) {
			return EventError
		}
	}

	// 优先检查密码提示（因为密码提示更具体，且可能在用户名提示之后出现）
	if isPasswordPrompt(received) {
		return EventPasswordPrompt
	}

	// 检查用户名提示
	if strings.Contains(receivedLower, "login:") ||
		strings.Contains(receivedLower, "username:") ||
		strings.Contains(receivedLower, "user:") ||
		strings.Contains(receivedLower, "user name:") {
		return EventUsernamePrompt
	}

	// 默认返回数据接收事件
	return EventDataReceived
}

// PerformLoginWithStateMachine 使用状态机实现telnet登录流程
// 这是基于状态机的新实现，保留原有的 PerformLogin 函数不变
// 返回登录过程中读取到的数据（包含提示符），这些数据应该转发给客户端
func PerformLoginWithStateMachine(conn net.Conn, username, password, enableCmd, enablePassword string, timeout time.Duration) ([]byte, error) {
	if username == "" && password == "" {
		// 无需登录，直接返回
		return nil, nil
	}

	sm := NewLoginStateMachine(conn, username, password, enableCmd, enablePassword, timeout)
	sm.conn.SetReadDeadline(time.Now().Add(timeout))

	// 使用一个标志来控制是否增加 attempt，避免 attempt 变成负数
	for sm.attempt < sm.maxAttempts {
		shouldIncrementAttempt := true // 每次循环开始时重置为 true

		// 检查最终状态
		if sm.currentState == StateLoginSuccess {
			xlog.Default().Debug("StateLoginSuccess detected in loop start",
				xlog.String("enableCmd", sm.enableCmd),
				xlog.String("hasEnablePassword", fmt.Sprintf("%v", sm.enablePassword != "")))
			// 如果提供了提权命令且还没有执行提权，进入提权状态
			// 使用 enableCmd 作为标志，提权完成后会清空它
			if sm.enableCmd != "" {
				xlog.Default().Info("Login successful, starting enable process",
					xlog.String("enableCmd", sm.enableCmd),
					xlog.String("hasEnablePassword", fmt.Sprintf("%v", sm.enablePassword != "")))
				sm.currentState = StateEnabling
				sm.conn.SetReadDeadline(time.Now().Add(sm.timeout))
				// 发送提权命令事件，开始提权流程
				if err := sm.dispatch(EventEnableCommandSent, nil); err != nil {
					return nil, fmt.Errorf("enable failed: %w", err)
				}
				// 继续循环，等待提权完成（状态会变回 StateLoginSuccess，enableCmd 会被清空）
				shouldIncrementAttempt = false
				continue
			} else {
				// 没有提权命令或提权已完成，直接返回
				xlog.Default().Debug("No enable command or enable completed, returning login data")
				sm.conn.SetReadDeadline(time.Time{})
				loginData := sm.GetLoginData()
				return loginData, nil
			}
		}

		if sm.currentState == StateLoginFailed {
			return nil, fmt.Errorf("login failed")
		}

		xlog.Default().Info("State machine loop",
			xlog.String("state", sm.currentState.String()),
			xlog.String("attempt", fmt.Sprintf("%d/%d", sm.attempt+1, sm.maxAttempts)),
			xlog.String("usernameSent", fmt.Sprintf("%v", sm.usernameSent)),
			xlog.String("passwordSent", fmt.Sprintf("%v", sm.passwordSent)))

		// 读取数据
		data := make([]byte, 4096)
		n, err := conn.Read(data)

		if err != nil {
			if err == io.EOF {
				if err := sm.dispatch(EventEOF, nil); err != nil {
					return nil, err
				}
				if sm.currentState == StateLoginSuccess {
					sm.conn.SetReadDeadline(time.Time{})
					// 返回登录过程中读取到的数据（包含提示符）
					loginData := sm.GetLoginData()
					return loginData, nil
				}
				return nil, fmt.Errorf("login failed: connection closed before login completed")
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				xlog.Default().Info("Read timeout in state machine",
					xlog.String("state", sm.currentState.String()),
					xlog.String("attempt", fmt.Sprintf("%d", sm.attempt)))
				if err := sm.dispatch(EventTimeout, nil); err != nil {
					return nil, err
				}
				// 如果状态变为成功或失败，退出循环
				if sm.currentState == StateLoginSuccess || sm.currentState == StateLoginFailed {
					break
				}
				// 重置超时，继续下一次读取
				// 注意：某些状态下的超时不应该增加 attempt（如等待密码提示）
				if sm.currentState == StateWaitPassword {
					// 等待密码提示时超时，不增加 attempt
					sm.conn.SetReadDeadline(time.Now().Add(timeout))
					shouldIncrementAttempt = false
					continue
				}
				// 其他状态的超时，默认增加 attempt（shouldIncrementAttempt 已经是 true）
				sm.conn.SetReadDeadline(time.Now().Add(timeout))
				continue
			}

			return nil, fmt.Errorf("failed to read login prompt: %w", err)
		}

		// 处理新接收到的 telnet 选项协商（必须在处理数据之前完成）
		if n > 0 {
			// 先处理 telnet 选项协商，这很重要，因为设备可能在等待协商响应
			if err := handleTelnetNegotiation(conn, data[:n]); err != nil {
				return nil, fmt.Errorf("failed to handle telnet negotiation: %w", err)
			}
			// 协商响应已发送，现在将数据写入缓冲区
			sm.loginBuffer.Write(data[:n])
		}

		// 过滤掉 telnet 控制字符
		rawBytes := sm.loginBuffer.Bytes()
		filteredBytes := FilterTelnetControlChars(rawBytes)

		// 如果过滤后的数据为空（只有控制字符），继续等待
		if len(filteredBytes) == 0 {
			xlog.Default().Info("Filtered data is empty, continuing to wait",
				xlog.String("n", fmt.Sprintf("%d", n)),
				xlog.String("attempt", fmt.Sprintf("%d", sm.attempt)),
				xlog.String("state", sm.currentState.String()))

			if n > 0 {
				// 收到了数据（虽然是控制字符），继续等待
				xlog.Default().Info("Received control characters only, continuing to wait")
				sm.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				// 不增加 attempt，继续等待
				shouldIncrementAttempt = false
				continue
			}
			// 没有收到数据，如果是第一次尝试且未发送用户名，尝试直接发送用户名
			if sm.attempt == 0 && !sm.usernameSent && sm.username != "" {
				xlog.Default().Info("No data received on first read, attempting to send username directly")
				loginData := []byte(sm.username + "\r\n")
				if err := network.WriteAll(sm.conn, loginData); err != nil {
					return nil, fmt.Errorf("failed to send username: %w", err)
				}
				sm.usernameSent = true
				sm.currentState = StateWaitPassword
				sm.conn.SetReadDeadline(time.Now().Add(sm.timeout))
				// 不增加 attempt，继续等待
				shouldIncrementAttempt = false
				continue
			}
			// 其他情况，继续等待
			xlog.Default().Info("No data and not first attempt, continuing to wait")
			sm.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			// 不增加 attempt，继续等待
			shouldIncrementAttempt = false
			continue
		}

		received := string(filteredBytes)
		xlog.Default().Info("Processing filtered data",
			xlog.String("received", received),
			xlog.String("receivedEscaped", fmt.Sprintf("%q", received)),
			xlog.String("receivedLength", fmt.Sprintf("%d", len(received))))

		// 检测事件
		event := sm.detectEvent(received)

		// 记录分发前的状态
		prevState := sm.currentState

		// 分发事件
		if err := sm.dispatch(event, received); err != nil {
			return nil, err
		}

		// 如果状态变为成功或失败，检查是否需要提权
		if sm.currentState == StateLoginSuccess {
			xlog.Default().Debug("StateLoginSuccess detected after dispatch",
				xlog.String("enableCmd", sm.enableCmd),
				xlog.String("hasEnablePassword", fmt.Sprintf("%v", sm.enablePassword != "")))
			// 如果提供了提权命令且还没有执行提权，进入提权状态
			if sm.enableCmd != "" {
				xlog.Default().Info("Login successful, starting enable process",
					xlog.String("enableCmd", sm.enableCmd),
					xlog.String("hasEnablePassword", fmt.Sprintf("%v", sm.enablePassword != "")))
				sm.currentState = StateEnabling
				sm.conn.SetReadDeadline(time.Now().Add(sm.timeout))
				// 发送提权命令事件，开始提权流程
				if err := sm.dispatch(EventEnableCommandSent, nil); err != nil {
					return nil, fmt.Errorf("enable failed: %w", err)
				}
				// 继续循环，等待提权完成（状态会变回 StateLoginSuccess，enableCmd 会被清空）
				shouldIncrementAttempt = false
				continue
			} else {
				// 没有提权命令或提权已完成，退出循环
				xlog.Default().Debug("No enable command or enable completed, breaking loop")
				break
			}
		}

		if sm.currentState == StateLoginFailed {
			break
		}

		// 如果状态没有变化，且当前状态是等待状态，不增加 attempt
		// 这样可以避免因为收到数据但没有明确提示而过早退出
		if prevState == sm.currentState {
			// 状态没有变化，继续等待，不增加 attempt
			if sm.currentState == StateInit || sm.currentState == StateWaitPassword ||
				sm.currentState == StateWaitLoginSuccess || sm.currentState == StateEnabling {
				sm.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				shouldIncrementAttempt = false
				continue
			}
		}

		// 重置超时
		sm.conn.SetReadDeadline(time.Now().Add(timeout))

		// 根据标志决定是否增加 attempt
		if shouldIncrementAttempt {
			sm.attempt++
		}
	}

	// 清除读取超时
	sm.conn.SetReadDeadline(time.Time{})

	// 最终检查：如果登录成功但还没有执行提权，执行提权流程
	if sm.currentState == StateLoginSuccess && sm.enableCmd != "" {
		xlog.Default().Info("Login successful, starting enable process (final check)",
			xlog.String("enableCmd", sm.enableCmd),
			xlog.String("hasEnablePassword", fmt.Sprintf("%v", sm.enablePassword != "")))
		sm.currentState = StateEnabling
		sm.conn.SetReadDeadline(time.Now().Add(sm.timeout))

		// 发送提权命令
		if err := sm.dispatch(EventEnableCommandSent, nil); err != nil {
			return nil, fmt.Errorf("enable failed: %w", err)
		}

		// 继续读取，直到提权完成
		for sm.currentState == StateEnabling {
			data := make([]byte, 4096)
			n, err := sm.conn.Read(data)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时，检查是否已经有命令提示符
					if err := sm.dispatch(EventTimeout, nil); err != nil {
						return nil, err
					}
					if sm.currentState == StateLoginSuccess {
						break
					}
					// 继续等待
					sm.conn.SetReadDeadline(time.Now().Add(sm.timeout))
					continue
				}
				if err == io.EOF {
					if err := sm.dispatch(EventEOF, nil); err != nil {
						return nil, err
					}
					break
				}
				return nil, fmt.Errorf("failed to read during enable: %w", err)
			}

			if n > 0 {
				// 处理 telnet 选项协商
				if err := handleTelnetNegotiation(sm.conn, data[:n]); err != nil {
					return nil, fmt.Errorf("failed to handle telnet negotiation: %w", err)
				}
				sm.loginBuffer.Write(data[:n])

				// 过滤并检测事件
				filteredBytes := FilterTelnetControlChars(sm.loginBuffer.Bytes())
				received := string(filteredBytes)
				event := sm.detectEvent(received)

				if err := sm.dispatch(event, received); err != nil {
					return nil, err
				}

				if sm.currentState == StateLoginSuccess {
					break
				}
			}
		}
	}

	// 最终检查
	if sm.currentState == StateLoginSuccess {
		// 返回登录过程中读取到的数据（包含提示符）
		loginData := sm.GetLoginData()
		return loginData, nil
	}

	if sm.usernameSent && !sm.passwordSent {
		return nil, fmt.Errorf("login failed: password not sent after username")
	}

	return nil, fmt.Errorf("login failed: max attempts reached")
}
