package l2service

// import (
// 	"fmt"

// 	"github.com/netxops/log"
// 	"go.uber.org/zap"

// 	"github.com/douyu/jupiter/pkg/conf"
// 	"github.com/douyu/jupiter/pkg/core/constant"
// 	"github.com/douyu/jupiter/pkg/core/ecode"
// 	"github.com/douyu/jupiter/pkg/xlog"
// 	"github.com/pkg/errors"

// 	"github.com/douyu/jupiter/pkg/flag"
// )

// // ModName named a mod
// const ModName = "server.l2"

// var plugins []string

// // Config HTTP config
// type Config struct {
// 	Host       string
// 	Etcd       string
// 	SiteRepo   string
// 	Deployment string
// 	// Data       string
// 	BasePath string
// 	Plugins  map[string]*PluginConfig
// 	logger   *log.Logger
// 	site     string
// 	env      string
// 	nm       string
// 	nat      string
// 	// TLS配置
// 	TLS TLSConfig
// 	Username string
// 	Password string
// 	// Debug         bool
// 	// DisableMetric bool
// 	// DisableTrace  bool
// 	// ServiceAddress service address in registry info, default to 'Host:Port'
// 	// ServiceAddress string
// }

// // TLSConfig TLS证书配置
// type TLSConfig struct {
// 	Enable   bool   `toml:"enable" json:"enable"`     // 是否启用TLS
// 	CertFile string `toml:"certFile" json:"certFile"` // 证书文件路径
// 	KeyFile  string `toml:"keyFile" json:"keyFile"`   // 私钥文件路径
// 	CAFile   string `toml:"caFile" json:"caFile"`     // CA证书文件路径(可选，用于双向认证)
// }

// type PluginConfig struct {
// 	Port        int
// 	NatPort     int
// 	Stream      int
// 	Interactive int
// 	Data        string
// 	Params      map[string]string
// }

// // DefaultConfig ...
// func DefaultConfig() *Config {
// 	c := &Config{
// 		Host: flag.String("host"),
// 		// Debug:                     false,
// 		Deployment: constant.DefaultDeployment,
// 		BasePath:   "/rpcx",
// 		Plugins:    map[string]*PluginConfig{},
// 		// SlowQueryThresholdInMilli: 500, // 500ms
// 		// logger: xlog.DefaultLogger.With(xlog.FieldMod(ModName)),
// 		logger: &log.Logger{},
// 		site:   flag.String("site"),
// 		env:    flag.String("env"),
// 		nm:     flag.String("nm"),
// 		nat:    flag.String("nat"),
// 		// Data:   flag.String("data"),
// 	}

// 	return c
// }

// // StdConfig Jupiter Standard HTTP Server config
// func StdConfig(name string) *Config {
// 	return RawConfig("jupiter.server." + name)
// }

// // RawConfig ...
// func RawConfig(key string) *Config {
// 	var config = DefaultConfig()
// 	if err := conf.UnmarshalKey(key, &config); err != nil &&
// 		errors.Cause(err) != conf.ErrInvalidKey {
// 		config.logger.Panic("l2 server parse config panic", xlog.FieldErrKind(ecode.ErrKindUnmarshalConfigErr), xlog.FieldErr(err), xlog.FieldKey(key), xlog.FieldValueAny(config))
// 	}

// 	for _, name := range plugins {
// 		if !flag.Bool(name) {
// 			continue
// 		}
// 		pc := PluginConfig{}
// 		k := fmt.Sprintf("%s.%s", key, name)
// 		if err := conf.UnmarshalKey(k, &pc); err != nil &&
// 			errors.Cause(err) != conf.ErrInvalidKey {
// 			config.logger.Panic("l2 plugin parse config panic", xlog.FieldErrKind(ecode.ErrKindUnmarshalConfigErr), xlog.FieldErr(err), xlog.FieldKey(key), xlog.FieldValueAny(config))
// 		}
// 		if pc.Port != 0 {
// 			config.Plugins[name] = &pc
// 		}
// 	}

// 	return config
// }

// // WithLogger ...
// func (config *Config) WithLogger(logger *zap.Logger) *Config {
// 	config.logger = &log.Logger{}
// 	config.logger.Logger = logger
// 	return config
// }

// // WithHost ...
// func (config *Config) WithHost(host string) *Config {
// 	config.Host = host
// 	return config
// }

// // WithPort ...
// // func (config *Config) WithPort(port int) *Config {
// // config.Port = port
// // return config
// // }

// // Build create server instance, then initialize it with necessary interceptor
// func (config *Config) Build() *Server {
// 	server := newServer(config)
// 	return server
// }

// // Address ...
// // func (config *Config) Address() string {
// // return fmt.Sprintf("%s:%d", config.Host, config.Port)
// // }

// func init() {
// 	plugins = []string{"vmware", "topo", "linux", "meta", "serveroob", "checkdevice", "syncFile", "sdn", "l3nodemap", "ansible", "orchestra", "stream", "shell", "gpon", "infiniband"}
// 	var flags []flag.Flag
// 	for _, p := range plugins {
// 		flags = append(flags, &flag.BoolFlag{
// 			Name:    p,
// 			Usage:   fmt.Sprintf("use --%s=true, (true or false)", p),
// 			Default: false,
// 		})
// 	}

// 	flags = append(flags, &flag.StringFlag{
// 		Name:    "site",
// 		Usage:   "--site=金桥数据中心",
// 		Default: "",
// 	})

// 	flags = append(flags, &flag.StringFlag{
// 		Name:    "env",
// 		Usage:   "--env=测试环境1",
// 		Default: "",
// 	})

// 	flags = append(flags, &flag.StringFlag{
// 		Name:    "nm",
// 		Usage:   "--nm=mapA",
// 		Default: "",
// 	})
// 	flags = append(flags, &flag.StringFlag{
// 		Name:    "nat",
// 		Usage:   "--nat=nat防火墙ip",
// 		Default: "",
// 	})
// 	// flags = append(flags, &flag.StringFlag{
// 	// Name:    "data",
// 	// Usage:   "--data=../data",
// 	// Default: "",
// 	// })

// 	flag.Register(flags...)
// }
