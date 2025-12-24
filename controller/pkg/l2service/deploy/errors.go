package deploy

import "errors"

var (
	SshLoginFailed    = errors.New("SSH Login Failed")
	NoLoginType       = errors.New("No Login Type")
	SshEmptyOperation = errors.New("SSH Empty Operation")
)
