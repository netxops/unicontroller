package lb

import "github.com/netxops/cli/terminalmode"

type LBNode interface {
	LBType() terminalmode.DeviceType

	Host() string
}
