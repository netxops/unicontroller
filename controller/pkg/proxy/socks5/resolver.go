package socks5

import (
	"net"

	"golang.org/x/net/context"
)

type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

type DNSResolver struct{}

func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}
