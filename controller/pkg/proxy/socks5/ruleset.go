package socks5

import (
	"golang.org/x/net/context"
)

type RuleSet interface {
	Allow(ctx context.Context, req *Request) (context.Context, bool)
}

func PermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

func PermitNone() RuleSet {
	return &PermitCommand{false, false, false}
}

type PermitCommand struct {
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
}

func (p *PermitCommand) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	switch req.Command {
	case ConnectCommand:
		return ctx, p.EnableConnect
	case BindCommand:
		return ctx, p.EnableBind
	case AssociateCommand:
		return ctx, p.EnableAssociate
	}

	return ctx, false
}
