package command

// import "github.com/netxops/unify/nodemap/session"

type Command interface {
	// run() *session.CacheData
	Id(ip string) string
	SetCacheData(data *CacheData)
	CacheData() *CacheData
	Msg() string
	WithMsg(msg string)
	Timeout() int
	Key() string
	Cmd() string
	WithLevel(CommandLevel)
	Level() CommandLevel
	WithOk(bool)
	Ok() bool
}

type CommandLevel int

const (
	OPTION CommandLevel = iota
	MUST
)
