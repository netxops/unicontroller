package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var (
	jumperHost       = flag.String("jumper-host", "localhost", "Jump server host")
	jumperPort       = flag.Int("jumper-port", 50022, "Jump server port")
	jumperUser       = flag.String("jumper-user", "user", "Jump server username")
	jumperPassword   = flag.String("jumper-password", "your-password", "Jump server password")
	targetHost       = flag.String("target-host", "", "Target server host (required)")
	targetPort       = flag.Int("target-port", 22, "Target server port")
	protocol         = flag.String("protocol", "ssh", "Protocol: ssh or telnet")
	telnetUser       = flag.String("telnet-user", "", "Telnet username (for telnet protocol)")
	telnetPassword   = flag.String("telnet-password", "", "Telnet password (for telnet protocol)")
	telnetEnableCmd  = flag.String("telnet-enable-cmd", "", "Telnet enable/privilege command (e.g., 'enable', 'su', 'sudo su')")
	telnetEnablePass = flag.String("telnet-enable-password", "", "Telnet enable/privilege password")
)

func main() {
	flag.Parse()

	if *targetHost == "" {
		fmt.Fprintf(os.Stderr, "Error: target-host is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// 验证目标主机不是纯数字（可能是误输入端口）
	if _, err := strconv.Atoi(*targetHost); err == nil {
		fmt.Fprintf(os.Stderr, "Error: target-host appears to be a number (%s). Did you mean to use -target-port?\n", *targetHost)
		flag.Usage()
		os.Exit(1)
	}

	// 规范化协议名称（不区分大小写）
	protocolLower := strings.ToLower(strings.TrimSpace(*protocol))

	// 验证协议值
	if protocolLower != "ssh" && protocolLower != "telnet" {
		fmt.Fprintf(os.Stderr, "Error: Invalid protocol '%s'. Must be 'ssh' or 'telnet'.\n", *protocol)
		if strings.ToLower(*protocol) == "telenet" {
			fmt.Fprintf(os.Stderr, "Hint: Did you mean 'telnet'? (you typed 'telenet')\n")
		}
		flag.Usage()
		os.Exit(1)
	}

	// 如果协议是 telnet 且端口是默认的 22，自动改为 23
	if protocolLower == "telnet" && *targetPort == 22 {
		*targetPort = 23
		fmt.Printf("Note: Using default telnet port 23 (was 22)\n")
	}

	// 如果端口是 23 但协议不是 telnet，给出警告
	if *targetPort == 23 && protocolLower != "telnet" {
		fmt.Fprintf(os.Stderr, "Warning: Port 23 is typically used for telnet, but protocol is '%s'. This may fail.\n", *protocol)
	}

	// 根据协议选择不同的连接方式
	if protocolLower == "telnet" {
		connectTelnet()
	} else {
		connectSSH()
	}
}

// connectSSH 通过 jump server 连接 SSH
func connectSSH() {
	fmt.Printf("Connecting to SSH via jump server %s:%d...\n", *jumperHost, *jumperPort)

	// 创建到跳板服务器的 SSH 客户端配置
	jumperConfig := &ssh.ClientConfig{
		User: *jumperUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(*jumperPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// 连接到跳板服务器
	jumperConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", *jumperHost, *jumperPort), jumperConfig)
	if err != nil {
		log.Fatalf("Failed to dial jumper: %v", err)
	}
	defer jumperConn.Close()

	fmt.Printf("Connected to jump server. Connecting to target %s:%d...\n", *targetHost, *targetPort)

	// 通过跳板服务器连接到目标服务器
	targetConn, err := jumperConn.Dial("tcp", fmt.Sprintf("%s:%d", *targetHost, *targetPort))
	if err != nil {
		log.Fatalf("Failed to dial target: %v", err)
	}
	defer targetConn.Close()

	// 创建目标服务器的 SSH 配置
	sshTargetCfg := ssh.ClientConfig{
		User:            *telnetUser, // 对于 SSH，使用 telnet-user 参数作为 SSH 用户名
		Auth:            []ssh.AuthMethod{ssh.Password(*telnetPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// 如果用户名或密码为空，提示输入
	if sshTargetCfg.User == "" {
		fmt.Print("SSH Username: ")
		fmt.Scanln(&sshTargetCfg.User)
	}
	if *telnetPassword == "" {
		fmt.Print("SSH Password: ")
		password, _ := term.ReadPassword(int(os.Stdin.Fd()))
		sshTargetCfg.Auth = []ssh.AuthMethod{ssh.Password(string(password))}
		fmt.Println()
	}

	// 设置默认配置
	sshTargetCfg.SetDefaults()

	// 扩展支持的加密算法
	sshTargetCfg.Config.Ciphers = append(sshTargetCfg.Config.Ciphers, []string{
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com",
		"arcfour256", "arcfour128", "arcfour",
		"aes128-cbc", "aes192-cbc", "aes256-cbc",
		"3des-cbc",
	}...)

	// 扩展支持的密钥交换算法
	sshTargetCfg.Config.KeyExchanges = append(sshTargetCfg.Config.KeyExchanges, []string{
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
	}...)

	// 扩展支持的 MAC 算法
	sshTargetCfg.Config.MACs = append(sshTargetCfg.Config.MACs, []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-256",
		"hmac-sha1",
		"hmac-sha1-96",
	}...)

	// 添加更多主机密钥算法
	sshTargetCfg.HostKeyAlgorithms = append(sshTargetCfg.HostKeyAlgorithms, []string{
		ssh.KeyAlgoRSA,
		ssh.KeyAlgoDSA,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoED25519,
	}...)

	// 创建 SSH 客户端连接
	conn, chans, reqs, err := ssh.NewClientConn(targetConn, fmt.Sprintf("%s:%d", *targetHost, *targetPort), &sshTargetCfg)
	if err != nil {
		log.Fatalf("Failed to create SSH client connection: %v", err)
	}
	defer conn.Close()

	// 使用新建立的连接创建 SSH 客户端
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	fmt.Println("SSH connection established. Starting interactive session...")

	// 创建 SSH 会话
	sess, err := client.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	defer sess.Close()

	// 设置标准输入输出
	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr
	sess.Stdin = os.Stdin

	// 获取终端大小
	fd := int(os.Stdin.Fd())
	width, height, err := term.GetSize(fd)
	if err != nil {
		width, height = 80, 40 // 默认值
	}

	// 创建伪终端
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // 启用回显
		ssh.TTY_OP_ISPEED: 14400, // 输入速度 = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // 输出速度 = 14.4kbaud
	}

	if err := sess.RequestPty("xterm-256color", width, height, modes); err != nil {
		log.Fatalf("Request for pseudo terminal failed: %s", err)
	}

	// 设置原始模式
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		log.Fatalf("Failed to set raw mode: %v", err)
	}
	defer term.Restore(fd, oldState)

	// 处理窗口大小变化
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGWINCH)
	go func() {
		for range sigChan {
			width, height, _ := term.GetSize(fd)
			sess.WindowChange(height, width)
		}
	}()

	// 启动远程 shell
	if err := sess.Shell(); err != nil {
		log.Fatalf("Failed to start shell: %s", err)
	}

	// 等待 session 结束
	if err := sess.Wait(); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			os.Exit(exitErr.ExitStatus())
		}
		log.Fatalf("Session ended with error: %v", err)
	}
}

// connectTelnet 通过 jump server 连接 Telnet
func connectTelnet() {
	fmt.Printf("Connecting to Telnet via jump server %s:%d...\n", *jumperHost, *jumperPort)

	// 构建 SSH 用户名，包含 telnet 登录信息和提权信息
	// 格式：telnet:username:password:enableCmd:enablePassword
	// 支持部分参数缺失：
	//   - telnet:username:password:enableCmd:enablePassword (完整格式)
	//   - telnet:username:password:enableCmd (有提权命令但无密码)
	//   - telnet:username:password (基本登录)
	//   - telnet:username (只有用户名，不执行自动登录)
	//   - telnet::password (只有密码，支持只需要密码的设备)
	//   - telnet: (无登录信息，直接连接)
	// 如果只提供用户名没有密码，不会执行自动登录，由用户根据设备提示手动登录
	// 如果只提供密码没有用户名，会执行自动登录（支持只需要密码的设备）
	// 如果没有提供任何登录信息，直接连接，不执行自动登录
	var jumperUserStr string
	if *telnetPassword != "" {
		// 有密码，会执行自动登录
		if *telnetUser != "" {
			// 有用户名和密码
			if *telnetEnableCmd != "" {
				// 有提权命令
				if *telnetEnablePass != "" {
					// 完整格式：telnet:username:password:enableCmd:enablePassword
					jumperUserStr = fmt.Sprintf("telnet:%s:%s:%s:%s", *telnetUser, *telnetPassword, *telnetEnableCmd, *telnetEnablePass)
				} else {
					// 有提权命令但无提权密码：telnet:username:password:enableCmd:
					jumperUserStr = fmt.Sprintf("telnet:%s:%s:%s:", *telnetUser, *telnetPassword, *telnetEnableCmd)
				}
			} else {
				// 无提权命令：telnet:username:password
				jumperUserStr = fmt.Sprintf("telnet:%s:%s", *telnetUser, *telnetPassword)
			}
		} else {
			// 只有密码，没有用户名（格式：telnet::password）
			// 注意：如果只有密码，不支持提权（因为格式限制）
			jumperUserStr = fmt.Sprintf("telnet::%s", *telnetPassword)
		}
	} else if *telnetUser != "" {
		// 只有用户名没有密码，不执行自动登录
		jumperUserStr = fmt.Sprintf("telnet:%s", *telnetUser)
	} else {
		// 如果没有提供用户名和密码，直接连接，不执行自动登录
		jumperUserStr = "telnet:"
	}

	// 创建到跳板服务器的 SSH 客户端配置
	jumperConfig := &ssh.ClientConfig{
		User: jumperUserStr,
		Auth: []ssh.AuthMethod{
			ssh.Password(*jumperPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// 连接到跳板服务器
	jumperConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", *jumperHost, *jumperPort), jumperConfig)
	if err != nil {
		log.Fatalf("Failed to dial jumper: %v", err)
	}
	defer jumperConn.Close()

	fmt.Printf("Connected to jump server. Connecting to target %s:%d...\n", *targetHost, *targetPort)

	// 通过跳板服务器连接到目标服务器（使用 direct-tcpip channel）
	channel, requests, err := jumperConn.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		TargetAddr string
		TargetPort uint32
		OriginAddr string
		OriginPort uint32
	}{
		TargetAddr: *targetHost,
		TargetPort: uint32(*targetPort),
		OriginAddr: "127.0.0.1",
		OriginPort: 0,
	}))
	if err != nil {
		log.Fatalf("Failed to open channel: %v", err)
	}
	defer channel.Close()

	// 处理 channel 请求
	go ssh.DiscardRequests(requests)

	fmt.Println("Telnet connection established. Starting interactive session...")

	// 设置原始模式以支持交互
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		log.Fatalf("Failed to set raw mode: %v", err)
	}
	defer term.Restore(fd, oldState)

	// 处理窗口大小变化（telnet 可能不需要，但保留以保持一致性）
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})

	// 从 channel 读取数据并写入 stdout
	// 注意：telnet 控制字符已在服务端过滤，这里直接输出
	go func() {
		defer close(done)
		io.Copy(os.Stdout, channel)
	}()

	// 从 stdin 读取数据并写入 channel
	go func() {
		io.Copy(channel, os.Stdin)
		channel.CloseWrite()
	}()

	// 等待信号或连接关闭
	select {
	case sig := <-sigChan:
		fmt.Printf("\nReceived signal: %v. Closing connection...\n", sig)
		channel.Close()
	case <-done:
		fmt.Println("\nConnection closed by server.")
	}
}
