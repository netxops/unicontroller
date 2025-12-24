package socks5

import (
	"fmt"
	"io"
)

const (
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

var (
	UserAuthFailed  = fmt.Errorf("user authentication failed")
	NoSupportedAuth = fmt.Errorf("no supported authentication mechanism")
)

type AuthContext struct {
	Method  uint8
	Payload map[string]string
}

type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error)
	GetCode() uint8
}

type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

func (a NoAuthAuthenticator) Authenticate(_ io.Reader, writer io.Writer) (*AuthContext, error) {
	_, err := writer.Write([]byte{Socks5Version, NoAuth})
	return &AuthContext{NoAuth, nil}, err
}

type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) GetCode() uint8 {
	return UserPassAuth
}

func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	if _, err := writer.Write([]byte{Socks5Version, UserPassAuth}); err != nil {
		return nil, err
	}

	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return nil, err
	}

	if header[0] != userAuthVersion {
		return nil, fmt.Errorf("unsupported auth version: %v", header[0])
	}

	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return nil, err
	}

	if _, err := reader.Read(header[:1]); err != nil {
		return nil, err
	}

	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return nil, err
	}

	if a.Credentials.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return nil, err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return nil, err
		}
		return nil, UserAuthFailed
	}

	return &AuthContext{UserPassAuth, map[string]string{"Username": string(user)}}, nil
}

func (s *Server) authenticate(conn io.Writer, bufConn io.Reader) (*AuthContext, error) {
	methods, err := readMethods(bufConn)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth methods: %v", err)
	}

	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			return cator.Authenticate(bufConn, conn)
		}
	}

	return nil, noAcceptableAuth(conn)
}

func noAcceptableAuth(conn io.Writer) error {
	_, _ = conn.Write([]byte{Socks5Version, noAcceptable})
	return NoSupportedAuth
}

func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}
