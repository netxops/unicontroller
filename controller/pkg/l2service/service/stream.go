package service

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"encoding/json"

	"github.com/influxdata/telegraf/controller/pkg/l2service/shell_service"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/structs/jsonp"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/tools"
	"github.com/smallnest/rpcx/share"
	"go.uber.org/zap"
)

var streamLogger *zap.Logger

func init() {
	streamLogger, _ = zap.NewDevelopment(zap.AddCallerSkip(1))
}

type STREAM struct {
}

func (ts *STREAM) Stream(conn net.Conn, args *share.StreamServiceArgs) {
	m := args.Meta
	rs := m[structs.SUP_REMOTE_LIST]

	var remoteInfoList []*structs.L2DeviceRemoteInfo
	err := json.Unmarshal([]byte(rs), &remoteInfoList)
	if err != nil {
		streamLogger.Info("Stream", zap.Error(err))
		return
	}

	serviceName := m[structs.SUP_REMOTE_NAME]
	switch serviceName {
	case structs.STREAM_INTERACTIVE:
		pipe, ok := m[structs.SUP_PIPE_FILE]
		var namedPipe string
		if ok {
			namedPipe = fmt.Sprintf("/tmp/%s", pipe)
		}
		fmt.Println("interactive namedPipe:", namedPipe)
		controller := NewController(remoteInfoList, conn, namedPipe)
		controller.Loop()
	case structs.STREAM_PECO:
		pipe, ok := m[structs.SUP_PIPE_FILE]
		if !ok {
			err = fmt.Errorf("pipe_file parameter error")
			streamLogger.Info("Stream", zap.Error(err))
		}
		namedPipe := fmt.Sprintf("/tmp/%s", pipe)
		fmt.Println("peco namedPipe:", namedPipe)
		controller := shell_service.NewShellService(conn, namedPipe, "bash", "-c", fmt.Sprintf("tail -f %s | peco", namedPipe))
		controller.Start()
	}
}

type Controller struct {
	remoteInfoList []*structs.L2DeviceRemoteInfo
	executeMap     map[*structs.L2DeviceRemoteInfo]*terminal.Execute
	removeMap      map[*structs.L2DeviceRemoteInfo]*terminal.Execute
	conn           net.Conn
	port           int
	pecoConn       net.Conn
	mutex          sync.Mutex
	namedPipe      string
	pipe           *os.File
}

func NewController(list []*structs.L2DeviceRemoteInfo, conn net.Conn, namedPipe string) *Controller {
	return &Controller{
		remoteInfoList: list,
		executeMap:     make(map[*structs.L2DeviceRemoteInfo]*terminal.Execute),
		removeMap:      make(map[*structs.L2DeviceRemoteInfo]*terminal.Execute),
		conn:           conn,
		namedPipe:      namedPipe,
		pecoConn:       nil,
	}
}

func (c *Controller) writePeco(data string) error {
	if c.pipe == nil {
		return nil
	}
	_, err := c.pipe.Write([]byte(data + "\n"))
	return err
}

func (c *Controller) Loop() {
	// go c.startListen()
	if c.namedPipe != "" {
		out, err := os.OpenFile(c.namedPipe, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
		if err != nil {
			streamLogger.Info("Interactive open named pipe fail", zap.Error(err))
		}
		c.pipe = out
		defer func() {
			c.pipe.Close()
			c.pipe = nil
			os.Remove(c.namedPipe)
		}()
	}

	msgChan, errChan := c.OnMessage()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-msgChan:
				switch msg.Type {
				case jsonp.InteractiveCmd:
					cmd, err := msg.InteractiveCmd()
					if err != nil {
						streamLogger.Info("Stream", zap.Error(err))
						continue
					}
					iaCmd := terminalmode.NewCommand(cmd.Command, cmd.Prompt, cmd.Timeout, cmd.Name, cmd.Pre_prompt)
					iaCmd.WithClose(cmd.Close)
					c.sendCommand(cmd.Id, iaCmd)
				default:
					err := fmt.Errorf("unsupported message type %d", msg.Type)
					streamLogger.Info("Stream", zap.Error(err))
				}
			case <-errChan:
				return
			}
		}
	}()

	loginCount := 0
	for index, _ := range c.remoteInfoList {
		remote := c.remoteInfoList[index]
		base := &terminal.BaseInfo{
			Host:       remote.Ip,
			Username:   remote.Username,
			Password:   remote.Password,
			PrivateKey: remote.PrivateKey,
			AuthUser:   remote.AuthPass,
			AuthPass:   remote.AuthCmd,
			Telnet:     tools.Conditional(*remote.Meta.EnableTelnet, true, false).(bool),
		}

		exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.NewDeviceType(remote.Platform), base)

		// 在循环中使用匿名函数来创建闭包，避免闭包代码本身被浅拷贝，虽然创建多个闭包，但多份闭包的代码应为浅拷贝，都是相同的。
		func(remote *structs.L2DeviceRemoteInfo) {
			exec.Register(terminal.LoginNotification, func(ip string, ok bool) {
				if ok {
					c.executeMap[remote] = exec
				}
				loginCount = loginCount + 1
				if len(c.remoteInfoList) == loginCount {
					raw, tp := jsonp.NewInteractiveStatus(len(c.remoteInfoList), len(c.executeMap))
					msg, _ := jsonp.NewMessage(tp, *raw)
					jsonp.SendJSON(c.conn, msg)
				}
			})
			exec.Register(terminal.DisconnectNotification, func(ip string, ok bool) {
				if ok {
					c.removeMap[remote] = exec
					if len(c.removeMap) == len(c.executeMap) {
						// 如何terminal都关闭了，则关闭c.conn
						raw, tp := jsonp.NewInteractiveStatus(len(c.remoteInfoList), 0)
						msg, _ := jsonp.NewMessage(tp, *raw)
						jsonp.SendJSON(c.conn, msg)
						c.conn.Close()
					}
				}
			})
		}(remote)

		ip := remote.Ip
		_, _, _ = exec.NewInteraction(func(output string, cmd *terminalmode.Command) {
			lines := strings.Split(output, "\n")
			withPrefixs := []string{}
			for _, line := range lines {
				withPrefixs = append(withPrefixs, fmt.Sprintf("%-16s|%s", ip, line))
			}
			data := strings.Join(withPrefixs, "\n")
			raw, tp := jsonp.NewInteractiveCmdReply(cmd.Id, true, "", data)
			msg, _ := jsonp.NewMessage(tp, *raw)
			jsonp.SendJSON(c.conn, msg)
			c.writePeco(data)
		}, func(err error, cmd *terminalmode.Command) {
			// streamLogger.Info("Stream", zap.String("ip", ip), zap.String("command", c.Command), zap.Error(err))
			output := err.Error()
			lines := strings.Split(output, "\n")
			withPrefixs := []string{}
			for _, line := range lines {
				withPrefixs = append(withPrefixs, fmt.Sprintf("%-16s|%s", ip, line))
			}

			data := strings.Join(withPrefixs, "\n")
			raw, tp := jsonp.NewInteractiveCmdReply(cmd.Id, false, data, "")
			msg, _ := jsonp.NewMessage(tp, *raw)
			jsonp.SendJSON(c.conn, msg)
			c.writePeco(data)
		})
	}

	wg.Wait()
}

func (c *Controller) closeTerminal() {
	for _, remote := range c.remoteInfoList {
		var execute *terminal.Execute
		var ok bool
		if execute, ok = c.executeMap[remote]; !ok {
			continue
		}
		if _, ok := c.removeMap[remote]; ok {
			continue
		}
		execute.GetInteraction().Close()
	}
}

func (c *Controller) sendCommand(id string, cmd *terminalmode.Command) {
	count := 0
	var wg sync.WaitGroup
	for _, remote := range c.remoteInfoList {
		wg.Add(1)
		go func(remote *structs.L2DeviceRemoteInfo) {
			defer wg.Done()
			var execute *terminal.Execute
			var ok bool
			if execute, ok = c.executeMap[remote]; !ok {
				return
			}
			if _, ok := c.removeMap[remote]; ok {
				return
			}
			cmd.WithId(id)
			execute.GetInteraction().Push(*cmd)
			count = count + 1
		}(remote)
	}

	wg.Wait()
	raw, tp := jsonp.NewInteractiveCmdAck(id, count)
	msg, _ := jsonp.NewMessage(tp, *raw)
	jsonp.SendJSON(c.conn, msg)
}

func (c *Controller) OnMessage() (chan jsonp.Message, chan error) {
	msgChan := make(chan jsonp.Message)
	errChan := make(chan error)
	go func() {
		for {
			cmd := jsonp.Message{}
			err := jsonp.ReadJSON(c.conn, &cmd)
			if err != nil {
				streamLogger.Info("Stream", zap.String("method", "on_message"), zap.Error(err))
				close(errChan)
				c.closeTerminal()
				break
			}

			msgChan <- cmd
		}
	}()
	return msgChan, errChan
}
