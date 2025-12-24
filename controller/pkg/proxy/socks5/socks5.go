package socks5

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/douyu/jupiter/pkg/xlog"
	"golang.org/x/net/context"
	"net"
)

const (
	Socks5Version = uint8(5)
)

type Config struct {
	AuthMethods []Authenticator
	Credentials CredentialStore
	Resolver    NameResolver
	Rules       RuleSet
	Rewriter    AddressRewriter
	BindIP      net.IP
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)
}

type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

func New(conf *Config) (*Server, error) {
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	server := &Server{
		config: conf,
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

func (s *Server) Handler(conn net.Conn, bufConn *bufio.Reader) error {
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		xlog.Default().Error("socks failed to authenticate", xlog.FieldErr(err))
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if errors.Is(err, unrecognizedAddrType) {
			if err = sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	if err = s.handleRequest(request, conn); err != nil {
		xlog.Default().Error("socks failed to handle request", xlog.FieldErr(err))
		return err
	}

	return nil
}
