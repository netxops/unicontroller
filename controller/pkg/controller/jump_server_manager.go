package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/influxdata/telegraf/controller/pkg/controller/telnetproxy/proxy"
	"golang.org/x/crypto/ssh"
)

const (
	// 默认 SSH 服务器密钥长度
	defaultSSHKeySize = 2048
	// Telnet 默认端口
	telnetDefaultPort = 23
	// 数据通道缓冲区大小
	dataChannelBufferSize = 100
	// 读取缓冲区大小
	readBufferSize = 4096
	// 服务注册间隔
	serviceRegisterInterval = 30 * time.Second
	// 服务注册 TTL
	serviceRegisterTTL = 1 * time.Minute
	// 默认连接空闲超时时间
	defaultIdleTimeout = 60 * time.Second
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

type JumperServerManager struct {
	config          *Config
	listener        net.Listener
	sshConfig       *ssh.ServerConfig
	registryManager *RegistryManager
	keymanager      *KeyManager
	ctx             context.Context
	cancel          context.CancelFunc
}

func ProvideJumperServerManager(registryManager *RegistryManager, km *KeyManager, config *Config) *JumperServerManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &JumperServerManager{
		registryManager: registryManager,
		keymanager:      km,
		config:          config,
		ctx:             ctx,
		cancel:          cancel,
	}
}

func (jsm *JumperServerManager) periodicRegister(serviceInfo *models.ServiceInfo) {
	ticker := time.NewTicker(serviceRegisterInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := jsm.registryManager.RegisterService(serviceInfo, serviceRegisterTTL)
			if err != nil {
				xlog.Default().Error("Failed to register JumpServer service",
					xlog.FieldErr(err),
					xlog.String("service", serviceInfo.Name),
					xlog.String("address", serviceInfo.Address))
			}
		case <-jsm.ctx.Done():
			xlog.Default().Info("Stopping JumpServer service registration")
			return
		}
	}
}

func (jsm *JumperServerManager) Start() error {
	if err := jsm.initSSHServerConfig(); err != nil {
		return fmt.Errorf("failed to initialize SSH server config: %w", err)
	}

	err := jsm.startSSHJumperServer()
	if err != nil {
		return err
	}

	key, err := jsm.keymanager.GenerateServiceKey(string(models.ServiceNameJumper), jsm.registryManager.HostIdentifier, fmt.Sprintf("%d", jsm.config.BaseConfig.SshProxy))
	if err != nil {
		return fmt.Errorf("failed to generate resource key: %v", err)
	}
	// 创建服务信息
	serviceInfo := &models.ServiceInfo{
		Key:      key,
		Name:     string(models.ServiceNameJumper),
		Protocol: "tcp",
		Address:  jsm.listener.Addr().String(),
	}

	// 启动周期性注册
	go jsm.periodicRegister(serviceInfo)

	return nil
}

func (jsm *JumperServerManager) Stop() error {
	jsm.cancel() // 取消 context，停止周期性注册

	if jsm.listener != nil {
		return jsm.listener.Close()
	}
	return nil
}

func (jsm *JumperServerManager) initSSHServerConfig() error {
	jsm.sshConfig = &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// 接受所有密码，因为这是跳板服务器，主要用于转发连接
			// 实际的身份验证应该在目标服务器上进行
			// 如果需要加强安全性，可以在这里添加额外的验证逻辑
			xlog.Default().Debug("SSH password authentication",
				xlog.String("user", c.User()),
				xlog.String("remoteAddr", c.RemoteAddr().String()))
			return nil, nil
		},
		// 设置服务器版本标识
		ServerVersion: "SSH-2.0-JumperServer",
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, defaultSSHKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	jsm.sshConfig.AddHostKey(signer)
	return nil
}

func (jsm *JumperServerManager) startSSHJumperServer() error {
	listener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", jsm.config.BaseConfig.SshProxy))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", jsm.config.BaseConfig.SshProxy, err)
	}

	jsm.listener = listener

	go func() {
		for {
			// 检查 context 是否已取消
			select {
			case <-jsm.ctx.Done():
				xlog.Default().Info("SSH jumper server shutting down")
				return
			default:
			}

			nConn, err := listener.Accept()
			if err != nil {
				// 检查是否是关闭导致的错误，如果是则静默退出
				if isClosedError(err) {
					// listener 已关闭，正常退出
					return
				}
				// 其他错误才记录日志
				xlog.Default().Error("Failed to accept incoming connection", xlog.FieldErr(err))
				continue
			}

			go jsm.handleSSHConnection(nConn)
		}
	}()

	xlog.Default().Info(fmt.Sprintf("SSH jumper server started on port %d", jsm.config.BaseConfig.SshProxy))
	return nil
}

func (jsm *JumperServerManager) handleSSHConnection(nConn net.Conn) {
	defer nConn.Close()

	xlog.Default().Info("New SSH connection received", xlog.String("remoteAddr", nConn.RemoteAddr().String()))

	conn, chans, reqs, err := ssh.NewServerConn(nConn, jsm.sshConfig)
	if err != nil {
		xlog.Default().Error("Failed to handshake", xlog.String("remoteAddr", nConn.RemoteAddr().String()), xlog.FieldErr(err))
		return
	}
	defer conn.Close()

	xlog.Default().Info("SSH handshake successful", xlog.String("user", conn.User()), xlog.String("clientVersion", string(conn.ClientVersion())))

	go ssh.DiscardRequests(reqs)

	// 使用 map 来跟踪所有活跃的 channel，以便在 SSH 连接关闭时关闭它们
	activeChannels := make(map[ssh.Channel]chan struct{})
	var channelsMutex sync.Mutex

	// 监控 SSH 连接状态：当 chans 关闭时，表示客户端已断开
	// 使用 goroutine 来监控，确保能及时检测到连接关闭
	go func() {
		// 等待 chans 关闭（客户端断开时，chans 会关闭）
		<-chans
		xlog.Default().Info("SSH client disconnected, closing all channels",
			xlog.String("user", conn.User()),
			xlog.String("remoteAddr", nConn.RemoteAddr().String()))

		// 关闭所有活跃的 channel
		channelsMutex.Lock()
		for ch, doneChan := range activeChannels {
			select {
			case <-doneChan:
				// 已经关闭
			default:
				close(doneChan)
				ch.Close()
			}
		}
		channelsMutex.Unlock()
	}()

	for newChannel := range chans {
		if newChannel.ChannelType() != "direct-tcpip" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			xlog.Default().Error("Failed to accept channel", xlog.String("user", conn.User()), xlog.FieldErr(err))
			continue
		}

		go ssh.DiscardRequests(requests)

		var channelData struct {
			TargetAddr string
			TargetPort uint32
			OriginAddr string
			OriginPort uint32
		}

		if err := ssh.Unmarshal(newChannel.ExtraData(), &channelData); err != nil {
			xlog.Default().Error("Failed to unmarshal channel data", xlog.String("user", conn.User()), xlog.FieldErr(err))
			channel.Close()
			continue
		}

		targetAddr := fmt.Sprintf("%s:%d", channelData.TargetAddr, channelData.TargetPort)

		// 检查是否是 telnet 连接并提取登录信息
		isTelnet, telnetUsername, telnetPassword, enableCmd, enablePassword :=
			jsm.parseTelnetInfo(conn.User(), channelData.TargetPort)

		// 创建 channel 的 done channel，用于通知连接关闭
		channelDone := make(chan struct{})
		channelsMutex.Lock()
		activeChannels[channel] = channelDone
		channelsMutex.Unlock()

		// 启动转发，并在完成时从 map 中移除
		go func(ch ssh.Channel, doneChan chan struct{}) {
			defer func() {
				channelsMutex.Lock()
				delete(activeChannels, ch)
				channelsMutex.Unlock()
			}()
			jsm.forwardConnection(ch, targetAddr, isTelnet, telnetUsername, telnetPassword, enableCmd, enablePassword, doneChan)
		}(channel, channelDone)
	}
}

// getIdleTimeout 获取连接空闲超时时间
func (jsm *JumperServerManager) getIdleTimeout() time.Duration {
	if jsm.config == nil || jsm.config.BaseConfig.JumpServerIdleTimeout <= 0 {
		return defaultIdleTimeout
	}
	return time.Duration(jsm.config.BaseConfig.JumpServerIdleTimeout) * time.Second
}

// parseTelnetInfo 解析 telnet 连接信息
// 返回：是否为 telnet 连接、用户名、密码、提权命令、提权密码
func (jsm *JumperServerManager) parseTelnetInfo(username string, targetPort uint32) (bool, string, string, string, string) {
	// 检查是否是 telnet 连接（端口 23 或通过用户名前缀 "telnet:" 标识）
	// 使用 HasPrefix 而不是 Contains，避免误判（如用户名 "telnetuser" 不会被误判）
	userLower := strings.ToLower(username)
	isTelnet := targetPort == telnetDefaultPort || strings.HasPrefix(userLower, "telnet:")

	var telnetUsername, telnetPassword, enableCmd, enablePassword string
	if isTelnet {
		parts := strings.Split(username, ":")
		if len(parts) >= 3 {
			// 格式：prefix:username:password 或 prefix::password（只有密码）
			telnetUsername = parts[1]
			telnetPassword = parts[2]
		} else if len(parts) == 2 {
			// 格式：prefix:username (无密码)
			telnetUsername = parts[1]
		}
		// 提取提权命令和提权密码（如果提供）
		if len(parts) >= 4 {
			enableCmd = parts[3]
		}
		if len(parts) >= 5 {
			enablePassword = parts[4]
		}
	}
	return isTelnet, telnetUsername, telnetPassword, enableCmd, enablePassword
}

func (jsm *JumperServerManager) forwardConnection(channel ssh.Channel, targetAddr string, isTelnet bool, telnetUsername, telnetPassword, enableCmd, enablePassword string, channelDone chan struct{}) {
	defer channel.Close()

	// 解析目标地址
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		xlog.Default().Error("Failed to parse target address", xlog.String("target", targetAddr), xlog.FieldErr(err))
		return
	}
	targetPort, err := strconv.Atoi(portStr)
	if err != nil {
		xlog.Default().Error("Failed to parse target port", xlog.String("port", portStr), xlog.FieldErr(err))
		return
	}

	// 打印目标设备信息
	protocolType := "TCP"
	if isTelnet {
		protocolType = "Telnet"
	}
	xlog.Default().Info("Connecting to target device",
		xlog.String("protocol", protocolType),
		xlog.String("target", fmt.Sprintf("%s:%d", host, targetPort)),
		xlog.String("host", host),
		xlog.Int("port", targetPort))

	// 如果是 telnet 连接，使用 telnet proxy 的 ForwardConnection（支持自动登录）
	// 只要有 telnet 标识（端口23或用户名包含telnet），就使用 telnet proxy
	if isTelnet {
		// 如果没有提供 channelDone，创建一个（用于普通 TCP 转发的情况）
		if channelDone == nil {
			channelDone = make(chan struct{})
		}
		jsm.forwardTelnetConnection(channel, host, targetPort, telnetUsername, telnetPassword, enableCmd, enablePassword, channelDone)
		return
	}

	// 普通 TCP 转发（非 telnet 或没有登录信息的 telnet）
	// 设置连接超时
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	targetConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		xlog.Default().Error("Failed to connect to target",
			xlog.String("target", targetAddr),
			xlog.String("protocol", protocolType),
			xlog.FieldErr(err))
		return
	}
	defer targetConn.Close()

	xlog.Default().Info("Target device connected",
		xlog.String("target", fmt.Sprintf("%s:%d", host, targetPort)),
		xlog.String("protocol", protocolType))

	// 如果是 telnet 但没有登录信息，给一点时间让服务器发送欢迎信息
	// 注意：这里不执行自动登录，因为可能不需要
	if isTelnet {
		time.Sleep(100 * time.Millisecond)
	}

	// 使用 done channel 来协调两个方向的复制
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			close(done)
		})
	}

	// 获取空闲超时配置
	idleTimeout := jsm.getIdleTimeout()

	// 数据活动通知 channel（用于重置空闲计时器）
	activityChan := make(chan struct{}, 1)

	// 空闲超时检测：如果配置了超时时间，启动监控
	if idleTimeout > 0 {
		go func() {
			ticker := time.NewTicker(idleTimeout)
			defer ticker.Stop()
			lastActivity := time.Now()

			for {
				select {
				case <-done:
					return
				case <-channelDone:
					// SSH 连接关闭，退出
					return
				case <-activityChan:
					// 有数据活动，重置计时器
					lastActivity = time.Now()
					ticker.Reset(idleTimeout)
				case <-ticker.C:
					// 检查是否真的空闲
					if time.Since(lastActivity) >= idleTimeout {
						xlog.Default().Info("Connection idle timeout, closing connection",
							xlog.String("target", targetAddr),
							xlog.String("protocol", protocolType),
							xlog.Duration("idleTimeout", idleTimeout))
						closeDone()
						return
					}
					// 重置 ticker 继续监控
					ticker.Reset(idleTimeout)
				}
			}
		}()
	}

	// 监控 channelDone：当 SSH 连接关闭时，立即关闭连接
	if channelDone != nil {
		go func() {
			select {
			case <-channelDone:
				xlog.Default().Info("SSH connection closed, closing target connection",
					xlog.String("target", targetAddr))
				closeDone()
			case <-done:
				// 正常关闭
			}
		}()
	}

	// 从 channel 复制到 targetConn（带活动监控）
	go func() {
		defer closeDone()
		buf := make([]byte, readBufferSize)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := channel.Read(buf)
			if err != nil {
				if err != io.EOF {
					xlog.Default().Error("Error reading from channel",
						xlog.String("target", targetAddr),
						xlog.FieldErr(err))
				}
				return
			}
			if n > 0 {
				// 通知有数据活动
				select {
				case activityChan <- struct{}{}:
				default:
				}
				_, writeErr := targetConn.Write(buf[:n])
				if writeErr != nil {
					xlog.Default().Error("Error writing to target",
						xlog.String("target", targetAddr),
						xlog.FieldErr(writeErr))
					return
				}
			}
		}
	}()

	// 从 targetConn 复制到 channel（带活动监控）
	go func() {
		defer closeDone()
		buf := make([]byte, readBufferSize)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := targetConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					xlog.Default().Error("Error reading from target",
						xlog.String("target", targetAddr),
						xlog.FieldErr(err))
				}
				return
			}
			if n > 0 {
				// 通知有数据活动
				select {
				case activityChan <- struct{}{}:
				default:
				}
				_, writeErr := channel.Write(buf[:n])
				if writeErr != nil {
					xlog.Default().Error("Error writing to channel",
						xlog.String("target", targetAddr),
						xlog.FieldErr(writeErr))
					return
				}
			}
		}
	}()

	// 等待任一方向完成
	<-done
	xlog.Default().Info("Target device connection closed", xlog.String("target", targetAddr), xlog.String("protocol", protocolType))
}

// forwardTelnetConnection 使用 telnet proxy 转发连接（支持自动登录和提权）
func (jsm *JumperServerManager) forwardTelnetConnection(channel ssh.Channel, targetHost string, targetPort int, username, password, enableCmd, enablePassword string, channelDone chan struct{}) {
	defer channel.Close() // 确保 channel 被关闭

	// 打印目标设备信息
	xlog.Default().Info("Connecting to target device",
		xlog.String("protocol", "Telnet"),
		xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)),
		xlog.String("host", targetHost),
		xlog.Int("port", targetPort),
		xlog.String("username", username),
		xlog.String("hasPassword", fmt.Sprintf("%v", password != "")),
		xlog.String("enableCmd", enableCmd),
		xlog.String("hasEnablePassword", fmt.Sprintf("%v", enablePassword != "")))

	// 创建数据通道
	clientDataChan := make(chan []byte, dataChannelBufferSize)
	serverDataChan := make(chan []byte, dataChannelBufferSize)
	done := make(chan struct{})

	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			// 关闭 done channel，这会触发 ForwardConnection 中的 goroutine 关闭目标连接
			close(done)
			xlog.Default().Info("Target device connection closing", xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)), xlog.String("protocol", "Telnet"))
		})
	}

	// 获取空闲超时配置
	idleTimeout := jsm.getIdleTimeout()

	// 数据活动通知 channel（用于重置空闲计时器）
	activityChan := make(chan struct{}, 1)

	// 空闲超时检测：如果配置了超时时间，启动监控
	if idleTimeout > 0 {
		go func() {
			ticker := time.NewTicker(idleTimeout)
			defer ticker.Stop()
			lastActivity := time.Now()

			for {
				select {
				case <-done:
					return
				case <-channelDone:
					// SSH 连接关闭，退出
					return
				case <-activityChan:
					// 有数据活动，重置计时器
					lastActivity = time.Now()
					ticker.Reset(idleTimeout)
				case <-ticker.C:
					// 检查是否真的空闲
					if time.Since(lastActivity) >= idleTimeout {
						xlog.Default().Info("Connection idle timeout, closing connection",
							xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)),
							xlog.String("protocol", "Telnet"),
							xlog.Duration("idleTimeout", idleTimeout))
						closeDone()
						return
					}
					// 重置 ticker 继续监控
					ticker.Reset(idleTimeout)
				}
			}
		}()
	}

	// 监控 channelDone：当 SSH 连接关闭时，立即关闭 telnet 连接
	go func() {
		select {
		case <-channelDone:
			xlog.Default().Info("SSH connection closed, closing telnet connection",
				xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))
			closeDone()
		case <-done:
			// 正常关闭
		}
	}()

	// 启动 telnet 连接转发（自动登录和提权）
	errChan := make(chan error, 1)
	go func() {
		err := proxy.ForwardConnection(targetHost, targetPort, username, password, enableCmd, enablePassword, clientDataChan, serverDataChan, done)
		if err != nil {
			xlog.Default().Error("Telnet forward connection failed",
				xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)),
				xlog.String("host", targetHost),
				xlog.Int("port", targetPort),
				xlog.FieldErr(err))
			select {
			case errChan <- err:
			case <-done:
				// done 已关闭，不需要发送错误
			}
			closeDone()
		}
	}()

	// 从 SSH channel 读取数据并发送到 telnet
	go func() {
		defer close(clientDataChan)
		defer closeDone() // 确保在 goroutine 退出时关闭 done channel
		buf := make([]byte, readBufferSize)
		for {
			// 在每次读取前检查 done channel
			select {
			case <-done:
				return
			default:
			}

			n, err := channel.Read(buf)
			if err != nil {
				// 客户端关闭连接时，Read 会返回错误
				if err != io.EOF {
					xlog.Default().Info("SSH channel read error, closing connection",
						xlog.FieldErr(err),
						xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))
				}
				return
			}
			if n > 0 {
				// 创建数据副本，避免并发问题
				data := make([]byte, n)
				copy(data, buf[:n])
				// 通知有数据活动
				select {
				case activityChan <- struct{}{}:
				default:
				}
				select {
				case <-done:
					return
				case clientDataChan <- data:
				}
			}
		}
	}()

	// 从 telnet 读取数据并发送到 SSH channel
	for {
		select {
		case <-done:
			xlog.Default().Info("Target device connection closed", xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)), xlog.String("protocol", "Telnet"), xlog.String("reason", "client disconnected"))
			return
		case data, ok := <-serverDataChan:
			if !ok {
				// serverDataChan 关闭表示 telnet 连接已关闭，关闭 SSH channel
				xlog.Default().Info("Telnet server closed connection, closing SSH channel", xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))
				closeDone()
				return
			}
			if len(data) > 0 {
				_, err := channel.Write(data)
				if err != nil {
					// 写入失败通常表示客户端已断开连接
					// SSH channel 在客户端断开时，写入会立即返回错误
					// 这是检测客户端断开最可靠的方法
					xlog.Default().Info("Client disconnected detected (write failed)",
						xlog.FieldErr(err),
						xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)))
					closeDone()
					return
				}
				// 通知有数据活动
				select {
				case activityChan <- struct{}{}:
				default:
				}
			}
		case err := <-errChan:
			if err != nil {
				xlog.Default().Error("Telnet forward connection error", xlog.String("target", fmt.Sprintf("%s:%d", targetHost, targetPort)), xlog.FieldErr(err))
			}
			closeDone()
			return
		}
	}
}
