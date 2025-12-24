package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/telnetproxy/network"
	"github.com/influxdata/telegraf/controller/pkg/controller/telnetproxy/proxy"
)

// 为了兼容，创建一个本地包装函数
func filterTelnetControlChars(data []byte) []byte {
	return proxy.FilterTelnetControlChars(data)
}

func main() {
	var (
		host        = flag.String("host", "", "目标主机地址 (必需)")
		port        = flag.Int("port", 23, "目标端口 (默认: 23)")
		username    = flag.String("user", "", "用户名 (可选)")
		password    = flag.String("pass", "", "密码 (可选)")
		enable      = flag.String("enable", "", "提权命令 (可选，如: enable)")
		enablePass  = flag.String("enable-pass", "", "提权密码 (可选)")
		timeout     = flag.Duration("timeout", 10*time.Second, "连接超时时间 (默认: 10s)")
		interactive = flag.Bool("interactive", false, "交互模式：登录成功后进入交互式会话")
	)
	flag.Parse()

	if *host == "" {
		fmt.Fprintf(os.Stderr, "错误: 必须指定目标主机地址\n")
		fmt.Fprintf(os.Stderr, "用法: %s -host <host> [-port <port>] [-user <user>] [-pass <pass>] [-interactive]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	target := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Printf("正在连接到 %s...\n", target)

	// 连接到目标设备
	conn, err := net.DialTimeout("tcp", target, *timeout)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	network.SetKeepAlive(conn)
	fmt.Printf("连接成功!\n\n")

	// 如果需要登录
	if *username != "" || *password != "" {
		fmt.Printf("开始登录流程...\n")
		loginData, err := proxy.PerformLoginWithStateMachine(
			conn,
			*username,
			*password,
			*enable,
			*enablePass,
			*timeout,
		)
		if err != nil {
			log.Fatalf("登录失败: %v", err)
		}

		fmt.Printf("登录成功!\n\n")

		// 如果有登录数据，显示提示符
		if len(loginData) > 0 {
			filtered := filterTelnetControlChars(loginData)
			if len(filtered) > 0 {
				fmt.Print(string(filtered))
			}
		}
	}

	// 交互模式
	if *interactive {
		fmt.Println("\n进入交互模式 (输入 'quit' 或 'exit' 退出, Ctrl+C 强制退出)")
		fmt.Println("==========================================")

		// 设置信号处理，优雅退出
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		// 从连接读取数据并显示
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					if err != io.EOF {
						fmt.Fprintf(os.Stderr, "\n读取错误: %v\n", err)
					}
					return
				}
				if n > 0 {
					filtered := filterTelnetControlChars(buf[:n])
					os.Stdout.Write(filtered)
				}
			}
		}()

		// 从标准输入读取并发送到连接
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := os.Stdin.Read(buf)
				if err != nil {
					if err != io.EOF {
						fmt.Fprintf(os.Stderr, "\n读取输入错误: %v\n", err)
					}
					return
				}
				if n > 0 {
					input := string(buf[:n])
					// 检查退出命令
					if input == "quit\n" || input == "exit\n" {
						fmt.Println("\n正在退出...")
						sigChan <- os.Interrupt
						return
					}
					// 发送到连接
					if _, err := conn.Write(buf[:n]); err != nil {
						fmt.Fprintf(os.Stderr, "\n发送数据错误: %v\n", err)
						return
					}
				}
			}
		}()

		// 等待信号
		<-sigChan
		fmt.Println("\n\n连接已关闭")
	} else {
		// 非交互模式，只显示连接信息
		fmt.Println("连接已建立 (非交互模式，使用 -interactive 进入交互模式)")
		fmt.Println("按 Ctrl+C 退出")

		// 简单等待，显示接收到的数据
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					break
				}
				if err == io.EOF {
					break
				}
				log.Printf("读取错误: %v", err)
				break
			}
			if n > 0 {
				filtered := filterTelnetControlChars(buf[:n])
				os.Stdout.Write(filtered)
			}
		}
	}
}
