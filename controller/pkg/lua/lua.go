package lua

import (
	"encoding/json"
	"github.com/netxops/orchestra/catalog"
	lua "github.com/yuin/gopher-lua"
	"io"
	"log"
	"os"
	"strings"
)

type LState struct {
	l         *lua.LState
	luaScript string
	tempPath  string
}

func NewLuaState(luaScript string) (*LState, error) {
	l := &LState{
		luaScript: luaScript,
		l:         lua.NewState(),
	}
	if err := l.newTempFile(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *LState) newTempFile() error {
	tempFile, err := os.CreateTemp(os.TempDir(), "UniOPS-AGENT-TEMP-*.lua")
	if err != nil {
		return err
	}
	defer func(tempFile *os.File) {
		_ = tempFile.Close()
	}(tempFile)
	reader := strings.NewReader(l.luaScript)
	if _, err = io.Copy(tempFile, reader); err != nil {
		return err
	}
	l.tempPath = tempFile.Name()
	return nil
}

func (l *LState) clearTempFile() {
	_ = os.Remove(l.tempPath)
}

func (l *LState) Run() (string, error) {
	defer l.l.Close()
	defer l.clearTempFile()

	logger := log.New(os.Stdout, "", log.LstdFlags)
	config := &catalog.Config{
		Module:      l.tempPath,
		DryRun:      false,
		Logger:      logger,
		SiteRepo:    "",
		L:           l.l,
		Concurrency: 1,
	}

	c := catalog.New(config)
	if err := c.Load(); err != nil {
		return "", err
	}

	items, err := json.Marshal(c.Run().Items)
	if err != nil {
		return "", err
	}
	return string(items), nil
}
