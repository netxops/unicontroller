package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pkg/proxy/http"
	"github.com/influxdata/telegraf/controller/pkg/proxy/socks5"
)

func isSocks5(conn net.Conn) (bool, []byte, *bufio.Reader, error) {
	reader := bufio.NewReader(conn)
	ver := []byte{0}
	if _, err := reader.Read(ver); err != nil {
		return false, ver, reader, fmt.Errorf("invaild socks5 ver: %v", ver)
	}
	if ver[0] == socks5.Socks5Version {
		return true, ver, reader, nil
	}
	return false, ver, reader, nil
}

// func Proxy(listener net.Listener) {
// 	for {
// 		conn, err := listener.Accept()
// 		if err != nil {
// 			xlog.Default().Error("error accepting connection", xlog.FieldErr(err))
// 			continue
// 		}

// 		go func() {
// 			ok, firstBytes, reader, err := isSocks5(conn)
// 			if ok {
// 				sks, err := socks5.New(&socks5.Config{})
// 				if err != nil {
// 					xlog.Default().Error("failed new socks handler", xlog.FieldErr(err))
// 				}
// 				if err = sks.Handler(conn, reader); err != nil {
// 					xlog.Default().Error("failed handle socks conn", xlog.FieldErr(err))
// 				}
// 				return
// 			}
// 			readString, err := reader.ReadString('\n')
// 			if err != nil {
// 				xlog.Default().Error("failed read http conn", xlog.FieldErr(err))
// 			}
// 			body := string(firstBytes) + readString
// 			http.Handler(body, reader, conn)
// 		}()
// 	}
// }

// func NewProxy(s *xgrpc.Server) {
// 	host, err := utils.ParseHost(s.Info().Address)
// 	if err != nil {
// 		xlog.Default().Panic("failed parse host", xlog.FieldErr(err))
// 	}
// 	addr := fmt.Sprintf("%s:%d", host, global.Conf.ProxyPort)

// 	listener, err := net.Listen("tcp", addr)
// 	if err != nil {
// 		xlog.Default().Error("error starting proxy listener", xlog.FieldErr(err))
// 		return
// 	}
// 	defer func(listener net.Listener) {
// 		_ = listener.Close()
// 	}(listener)

// 	xlog.Default().Info("proxy server is running", xlog.String("addr", addr))
// 	Proxy(listener)
// }

func Proxy(ctx context.Context, listener net.Listener) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		select {
		case <-ctx.Done():
			xlog.Default().Info("Proxy server shutting down")
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				xlog.Default().Error("error accepting connection", xlog.FieldErr(err))
				continue
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConnection(ctx, conn)
			}()
		}
	}
}

func handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	ok, firstBytes, reader, err := isSocks5(conn)
	if err != nil {
		xlog.Default().Error("error determining protocol", xlog.FieldErr(err))
		return
	}

	if ok {
		sks, err := socks5.New(&socks5.Config{})
		if err != nil {
			xlog.Default().Error("failed new socks handler", xlog.FieldErr(err))
			return
		}
		if err = sks.Handler(conn, reader); err != nil {
			xlog.Default().Error("failed handle socks conn", xlog.FieldErr(err))
		}
		return
	}

	readString, err := reader.ReadString('\n')
	if err != nil {
		xlog.Default().Error("failed read http conn", xlog.FieldErr(err))
		return
	}
	body := string(firstBytes) + readString
	http.Handler(body, reader, conn)
}

// func NewProxy(ctx context.Context, s *xgrpc.Server) {
// 	host, err := utils.ParseHost(s.Info().Address)
// 	if err != nil {
// 		xlog.Default().Panic("failed parse host", xlog.FieldErr(err))
// 	}
// 	addr := fmt.Sprintf("%s:%d", host, global.Conf.ProxyPort)

// 	listener, err := net.Listen("tcp", addr)
// 	if err != nil {
// 		xlog.Default().Error("error starting proxy listener", xlog.FieldErr(err))
// 		return
// 	}

// 	xlog.Default().Info("proxy server is running", xlog.String("addr", addr))

// 	go func() {
// 		<-ctx.Done()
// 		xlog.Default().Info("Closing proxy listener")
// 		listener.Close()
// 	}()

// 	Proxy(ctx, listener)
// }
