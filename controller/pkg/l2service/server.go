package l2service

// import (
// 	"context"
// 	"fmt"
// 	"os"
// 	"strings"
// 	"time"

// 	"github.com/douyu/jupiter/pkg/core/constant"

// 	"go.uber.org/zap"

// 	jupiterServer "github.com/douyu/jupiter/pkg/server"
// 	"github.com/influxdata/telegraf/controller/pkg/l2service/service"
// 	l3nodemapService "github.com/netxops/l2service/internal/app/service/l3nodemap"
// 	"github.com/netxops/log"
// 	"github.com/rcrowley/go-metrics"
// 	"github.com/rpcxio/libkv/store"
// 	etcdServerplugin "github.com/rpcxio/rpcx-etcd/serverplugin"

// 	"crypto/tls"

// 	"crypto/x509"

// 	"github.com/smallnest/rpcx/server"
// 	"github.com/smallnest/rpcx/share"
// )

// type Server struct {
// 	config  *Config
// 	Plugins map[string]*Plugin
// }

// type Closer func() error

// type Plugin struct {
// 	Name   string
// 	config *Config
// 	group  string
// 	pc     *PluginConfig
// 	serve  *server.Server
// 	close  Closer
// }

// func newServer(config *Config) *Server {
// 	s := &Server{
// 		config:  config,
// 		Plugins: map[string]*Plugin{},
// 	}

// 	for name, pc := range config.Plugins {
// 		p := newPlugin(name, config, pc)
// 		s.Plugins[name] = p
// 	}

// 	return s
// }

// // plugins = []string{"vmware", "switch", "server_oob", "linux", "meta}
// func newPlugin(name string, config *Config, pc *PluginConfig) *Plugin {
// 	s := server.NewServer()

// 	// 配置TLS
// 	if config.TLS.Enable {
// 		log.NewLogger(nil, true).Info("开始配置TLS",
// 			zap.String("plugin", name),
// 			zap.String("certFile", config.TLS.CertFile),
// 			zap.String("keyFile", config.TLS.KeyFile),
// 			zap.String("caFile", config.TLS.CAFile))

// 		tlsConfig, err := createTLSConfig(&config.TLS)
// 		if err != nil {
// 			log.NewLogger(nil, true).Error("创建TLS配置失败",
// 				zap.String("plugin", name),
// 				zap.Error(err))
// 			panic(fmt.Errorf("failed to create TLS config: %v", err))
// 		}

// 		log.NewLogger(nil, true).Info("TLS配置创建成功",
// 			zap.String("plugin", name),
// 			zap.String("serverName", tlsConfig.ServerName),
// 			zap.Uint16("minVersion", tlsConfig.MinVersion),
// 			zap.Bool("requireClientCert", tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert))

// 		s = server.NewServer(server.WithTLSConfig(tlsConfig))

// 		log.NewLogger(nil, true).Info("TLS服务器创建成功",
// 			zap.String("plugin", name))
// 	} else {
// 		log.NewLogger(nil, true).Debug("TLS未启用",
// 			zap.String("plugin", name))
// 	}

// 	host := config.Host
// 	if config.nat != "" {
// 		host = config.nat
// 	}
// 	addr := fmt.Sprintf("%s:%d", host, pc.NatPort)
// 	addRegistryPlugin(s, config.Etcd, addr, config.BasePath, config.Username, config.Password)

// 	// p := serverplugin.NewMetricsPlugin(metrics.DefaultRegistry)
// 	// s.Plugins.Add(p)
// 	// startMetrics()
// 	//
// 	group := []string{}
// 	if config.site != "" {
// 		group = append(group, config.site)
// 	}

// 	if config.env != "" {
// 		group = append(group, config.env)
// 	}

// 	// metadata := fmt.Sprintf("group=%s|%s", config.site, config.env)
// 	metadata := fmt.Sprintf("group=%s", strings.Join(group, "|"))
// 	var err error
// 	var closer Closer

// 	switch name {
// 	case "vmware":
// 		err = s.Register(&service.VMWARE{}, metadata)
// 	case "topo":
// 		err = s.Register(&service.TOPO{Data: pc.Data}, metadata)
// 	case "linux":
// 	case "meta":
// 		err = s.Register(&service.META{}, metadata)
// 	case "gpon":
// 		err = s.Register(&service.GPON{}, metadata)
// 	case "infiniband":
// 		err = s.Register(&service.INFINIBAND{}, metadata)
// 	case "serveroob":
// 		err = s.Register(&service.SERVEROOB{}, metadata)
// 	case "checkdevice":
// 		err = s.Register(&service.CHECKDEVICE{}, metadata)
// 	case "sdn":
// 		err = s.Register(&service.SDN{}, metadata)
// 	case "syncFile":
// 		err = s.Register(&service.SYNCFILE{Path: pc.Params["path"], ExcelPath: pc.Params["excelPath"]}, metadata)
// 	case "l3nodemap":
// 		err = s.Register(&l3nodemapService.L3NodeMapService{}, metadata)
// 	case "ansible":
// 		err = s.Register(&service.ANSIBLE{}, metadata)
// 	case "stream":
// 		streamAddr := fmt.Sprintf("%s:%d", config.Host, pc.Stream)
// 		st := service.STREAM{}
// 		streamService := server.NewStreamService(streamAddr, st.Stream, nil, 1000)
// 		s.EnableStreamService(share.StreamServiceName, streamService)
// 	case "orchestra":
// 		endPoint := "http://" + config.Etcd
// 		var orch *service.ORCHESTRASERVICE
// 		orch, err = service.NewOrchService(endPoint, config.SiteRepo)
// 		if err == nil {
// 			err = s.Register(orch, metadata)
// 			if err != nil {
// 				closer = orch.Close
// 			}
// 		}
// 	}
// 	if err != nil {
// 		panic(err)
// 	}

// 	return &Plugin{
// 		Name:   name,
// 		config: config,
// 		group:  metadata,
// 		pc:     pc,
// 		serve:  s,
// 		close:  closer,
// 	}
// }

// func (p *Plugin) run() error {
// 	addr := fmt.Sprintf("%s:%d", p.config.Host, p.pc.Port)
// 	var err error
// 	// 根据是否启用TLS选择不同的网络协议
// 	if p.config.TLS.Enable {
// 		// 使用TCP+TLS
// 		log.NewLogger(nil, true).Info("启动TLS服务器",
// 			zap.String("plugin", p.Name),
// 			zap.String("address", addr),
// 			zap.String("protocol", "tcp+tls"))
// 		err = p.serve.Serve("tcp", addr)
// 	} else {
// 		// 使用原来的reuseport
// 		log.NewLogger(nil, true).Info("启动非TLS服务器",
// 			zap.String("plugin", p.Name),
// 			zap.String("address", addr),
// 			zap.String("protocol", "reuseport"))
// 		err = p.serve.Serve("reuseport", addr)
// 	}

// 	if err != nil {
// 		log.NewLogger(nil, true).Error("服务器启动失败",
// 			zap.String("plugin", p.Name),
// 			zap.String("address", addr),
// 			zap.Bool("tlsEnabled", p.config.TLS.Enable),
// 			zap.Error(err))
// 	} else {
// 		log.NewLogger(nil, true).Info("服务器启动成功",
// 			zap.String("plugin", p.Name),
// 			zap.String("address", addr),
// 			zap.Bool("tlsEnabled", p.config.TLS.Enable))
// 	}

// 	return err
// }

// func (p *Plugin) Address() string {
// 	return fmt.Sprintf("%s:%d", p.config.Host, p.pc.Port)
// }

// func (s *Server) Serve() error {

// 	for name, p := range s.Plugins {
// 		logger := log.NewLogger(nil, true)
// 		logger.Info("启动插件服务",
// 			zap.String("plugin", name),
// 			zap.String("etcd", p.config.Etcd),
// 			zap.String("address", p.Address()),
// 			zap.String("group", p.group),
// 			zap.Bool("tlsEnabled", p.config.TLS.Enable))

// 		if p.config.TLS.Enable {
// 			logger.Info("插件启用TLS模式",
// 				zap.String("plugin", name),
// 				zap.String("certFile", p.config.TLS.CertFile),
// 				zap.String("keyFile", p.config.TLS.KeyFile),
// 				zap.String("caFile", p.config.TLS.CAFile))
// 		}

// 		go p.run()
// 	}

// 	return nil
// }

// func (s *Server) Stop() error {
// 	for _, plug := range s.Plugins {
// 		plug.Stop()
// 	}

// 	return nil
// }

// func (s *Server) GracefulStop(ctx context.Context) error {
// 	for _, plug := range s.Plugins {
// 		plug.GracefulStop(ctx)
// 	}

// 	return nil
// }

// func (s *Server) Info() *jupiterServer.ServiceInfo {
// 	return &jupiterServer.ServiceInfo{
// 		Name:    "l2_service",
// 		Address: "1.1.1.1",
// 		Kind:    constant.ServiceUnknown,
// 		Scheme:  "tcp",
// 	}
// }

// func (s *Server) Healthz() bool {
// 	return true
// }

// // Stop implements server.Plugin interface
// // it will terminate echo server immediately
// func (p *Plugin) Stop() error {
// 	if p.close != nil {
// 		p.close()
// 	}

// 	return nil
// }

// // GracefulStop implements server.Plugin interface
// // it will stop echo server gracefully
// func (p *Plugin) GracefulStop(ctx context.Context) error {
// 	if p.close != nil {
// 		p.close()
// 	}
// 	return nil
// }

// func addRegistryPlugin(s *server.Server, etcdAddr, srvAddr, basePath string, username, password string) error {
// 	// 启动注册插件，如果失败则重试
// 	var err error
// 	var r *etcdServerplugin.EtcdV3RegisterPlugin
// 	maxRetries := 5
// 	baseDelay := 2 * time.Second

// 	for i := 0; i < maxRetries; i++ {
// 		// 每次重试都创建新的 plugin 实例，避免重用旧的 lease
// 		r = &etcdServerplugin.EtcdV3RegisterPlugin{
// 			ServiceAddress: "tcp@" + srvAddr,
// 			EtcdServers:    []string{etcdAddr},
// 			BasePath:       basePath,
// 			Metrics:        metrics.NewRegistry(),
// 			UpdateInterval: 5 * time.Second,
// 		}
// 		if username != "" && password != "" {
// 			r.Options = &store.Config{Username: username, Password: password}
// 		}

// 		err = r.Start()
// 		if err == nil {
// 			// 成功启动，添加到插件列表
// 			s.Plugins.Add(r)
// 			log.NewLogger(nil, true).Info("etcd 注册插件启动成功",
// 				zap.String("etcdAddr", etcdAddr),
// 				zap.String("srvAddr", srvAddr),
// 				zap.String("basePath", basePath),
// 				zap.Int("attempt", i+1))
// 			return nil
// 		}

// 		// 检查是否是 lease not found 错误
// 		errStr := err.Error()
// 		isLeaseError := strings.Contains(errStr, "requested lease not found") ||
// 			strings.Contains(errStr, "etcdserver: requested lease not found")

// 		if i < maxRetries-1 {
// 			// 计算指数退避延迟：2s, 4s, 8s, 16s
// 			delay := baseDelay * time.Duration(1<<uint(i))
// 			log.NewLogger(nil, true).Warn("etcd 注册插件启动失败，准备重试",
// 				zap.String("etcdAddr", etcdAddr),
// 				zap.String("srvAddr", srvAddr),
// 				zap.String("basePath", basePath),
// 				zap.Int("retry", i+1),
// 				zap.Int("maxRetries", maxRetries),
// 				zap.Duration("delay", delay),
// 				zap.Bool("isLeaseError", isLeaseError),
// 				zap.Error(err))
// 			time.Sleep(delay)
// 		}
// 	}

// 	// 所有重试都失败了
// 	log.NewLogger(nil, true).Error("etcd 注册插件启动失败，已达到最大重试次数",
// 		zap.String("etcdAddr", etcdAddr),
// 		zap.String("srvAddr", srvAddr),
// 		zap.String("basePath", basePath),
// 		zap.Int("maxRetries", maxRetries),
// 		zap.Error(err))
// 	return fmt.Errorf("failed to start etcd register plugin after %d retries: %w", maxRetries, err)
// }

// // createTLSConfig 创建TLS配置
// func createTLSConfig(tlsConf *TLSConfig) (*tls.Config, error) {
// 	logger := log.NewLogger(nil, true)

// 	logger.Info("开始创建TLS配置",
// 		zap.String("certFile", tlsConf.CertFile),
// 		zap.String("keyFile", tlsConf.KeyFile),
// 		zap.String("caFile", tlsConf.CAFile))

// 	if tlsConf.CertFile == "" || tlsConf.KeyFile == "" {
// 		logger.Error("TLS证书文件或密钥文件未指定")
// 		return nil, fmt.Errorf("TLS enabled but cert file or key file not specified")
// 	}

// 	logger.Debug("开始加载X509密钥对",
// 		zap.String("certFile", tlsConf.CertFile),
// 		zap.String("keyFile", tlsConf.KeyFile))

// 	cert, err := tls.LoadX509KeyPair(tlsConf.CertFile, tlsConf.KeyFile)
// 	if err != nil {
// 		logger.Error("加载X509密钥对失败",
// 			zap.String("certFile", tlsConf.CertFile),
// 			zap.String("keyFile", tlsConf.KeyFile),
// 			zap.Error(err))
// 		return nil, fmt.Errorf("failed to load X509 key pair: %v", err)
// 	}

// 	logger.Info("X509密钥对加载成功",
// 		zap.String("certFile", tlsConf.CertFile),
// 		zap.String("keyFile", tlsConf.KeyFile))

// 	config := &tls.Config{
// 		Certificates: []tls.Certificate{cert},
// 		ServerName:   "l2service-rpcx-server.local",
// 		MinVersion:   tls.VersionTLS12, // 使用较新的TLS版本
// 	}

// 	logger.Info("基础TLS配置创建完成",
// 		zap.String("serverName", config.ServerName),
// 		zap.Uint16("minVersion", config.MinVersion),
// 		zap.Int("certificateCount", len(config.Certificates)))

// 	// 如果指定了CA文件，配置双向TLS认证
// 	if tlsConf.CAFile != "" {
// 		logger.Info("开始配置双向TLS认证",
// 			zap.String("caFile", tlsConf.CAFile))

// 		err := setupMutualTLS(config, tlsConf.CAFile)
// 		if err != nil {
// 			logger.Error("配置双向TLS认证失败",
// 				zap.String("caFile", tlsConf.CAFile),
// 				zap.Error(err))
// 			return nil, fmt.Errorf("failed to setup mutual TLS: %v", err)
// 		}

// 		logger.Info("双向TLS认证配置成功",
// 			zap.String("caFile", tlsConf.CAFile),
// 			zap.String("clientAuth", "RequireAndVerifyClientCert"))
// 	} else {
// 		logger.Debug("未配置CA文件，跳过双向TLS认证")
// 	}

// 	logger.Info("TLS配置创建完成",
// 		zap.String("serverName", config.ServerName),
// 		zap.Uint16("minVersion", config.MinVersion),
// 		zap.Bool("mutualTLS", tlsConf.CAFile != ""))

// 	return config, nil
// }

// // setupMutualTLS 配置双向TLS认证
// func setupMutualTLS(config *tls.Config, caFile string) error {
// 	logger := log.NewLogger(nil, true)

// 	logger.Debug("开始读取CA证书文件",
// 		zap.String("caFile", caFile))

// 	// 读取CA证书文件
// 	caCertPEM, err := os.ReadFile(caFile)
// 	if err != nil {
// 		logger.Error("读取CA证书文件失败",
// 			zap.String("caFile", caFile),
// 			zap.Error(err))
// 		return fmt.Errorf("failed to read CA certificate file: %v", err)
// 	}

// 	logger.Info("CA证书文件读取成功",
// 		zap.String("caFile", caFile),
// 		zap.Int("certSize", len(caCertPEM)))

// 	// 解析CA证书
// 	caCertPool := x509.NewCertPool()
// 	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
// 		logger.Error("解析CA证书失败",
// 			zap.String("caFile", caFile))
// 		return fmt.Errorf("failed to parse CA certificate")
// 	}

// 	logger.Info("CA证书解析成功",
// 		zap.String("caFile", caFile))

// 	// 配置客户端证书验证
// 	config.ClientAuth = tls.RequireAndVerifyClientCert
// 	config.ClientCAs = caCertPool

// 	logger.Info("双向TLS认证配置完成",
// 		zap.String("caFile", caFile),
// 		zap.String("clientAuth", "RequireAndVerifyClientCert"))

// 	return nil
// }
