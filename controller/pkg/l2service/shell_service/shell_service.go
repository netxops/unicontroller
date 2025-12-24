package shell_service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// var pipeFile = "/tmp/peco.pipe"

type Option func(*ShellService)

type ShellService struct {
	Conn        net.Conn
	Interactive int
	Name        string
	NamedPipe   string
	Args        []string
}

func NewShellService(conn net.Conn, namedPipe string, name string, args ...string) *ShellService {
	ss := &ShellService{
		Conn:      conn,
		Name:      name,
		NamedPipe: namedPipe,
	}

	ss.Args = append(ss.Args, args...)
	return ss
}

func getServerConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalln(err)
	}
	hostKey, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatalln(err)
	}
	config.AddHostKey(hostKey)
	return config
}

func (ss *ShellService) Start() {

	fmt.Println("初始化内部ssh server")
	config := getServerConfig()

	_, chans, reqs, err := ssh.NewServerConn(ss.Conn, config)
	if err != nil {
		log.Printf("Failed to handshake (%s)", err)
		return
	}
	fmt.Println("内部ssh server初始化成功")
	//
	go ssh.DiscardRequests(reqs)
	go ss.handleChannels(chans)
}

func (ss *ShellService) handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	fmt.Println("处理ssh channels")
	for newChannel := range chans {
		var cmds []string
		cmds = append(cmds, ss.Name)
		cmds = append(cmds, ss.Args...)
		fmt.Printf("ssh channel上执行:%+v", cmds)
		go ss.handle2(newChannel, cmds)
	}
}

func (ss *ShellService) handle2(newChannel ssh.NewChannel, command []string) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	conn, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	fmt.Println("Receiving connection from", conn)
	defer conn.Close()

	log.Print("creating pty...")
	pty, tty, err := pty.Open()
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		pty.Close()
		tty.Close()
		// cmd.Process.Kill()
	}()

	fmt.Println("准备执行shell程序")
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	// cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}

	cmd.Start()
	go func() {
		cmd.Wait()
		fmt.Println("command执行完成，关闭peco")
		conn.Close()
	}()
	fmt.Println("执行shell程序")
	cmd.Process.Kill()

	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				fmt.Println("处理ssh shell")
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(pty.Fd(), w, h)
				fmt.Println("处理ssh pty-req", w, h)
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				fmt.Println("处理ssh windows-change", w, h)
				SetWinsize(pty.Fd(), w, h)
			}
		}
	}()

	go func() {
		io.Copy(pty, conn)
	}()
	io.Copy(conn, pty)

	fmt.Println("ssh channel处理完毕")
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	log.Printf("window resize %dx%d", w, h)
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
