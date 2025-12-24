package packages

// // type Registry struct {
// // 	registered map[string]*server.ServiceInfo
// // }

// // func NewRegistry() *Registry {
// // 	return &Registry{
// // 		registered: make(map[string]*server.ServiceInfo),
// // 	}
// // }

// func (d *PackageManager) packageRegister(schema *model.Schema) {
// 	pkg, ok := d.packages[schema.Package]
// 	if !ok {
// 		xlog.Default().Warn("package not found", xlog.String("package", schema.Package))
// 		return
// 	}
// 	stl, err := pkg.Systemdctl()
// 	if err != nil {
// 		xlog.Default().Error("failed to create systemctl", xlog.FieldErr(err))
// 		return
// 	}

// 	if !stl.IsRunning() {
// 		// 如果服务不在运行且已注册到ETCD则取消注册
// 		if info, ok := d.registered[schema.Package]; ok {
// 			_ = registry.DefaultRegisterer.UnregisterService(context.Background(), info)
// 		}
// 		delete(d.registered, schema.Package)
// 		return
// 	}

// 	for _, port := range schema.ListenPort {
// 		for _, addr := range global.MachineAddr {
// 			d.servicePortRegister(addr, port, schema.Package)
// 		}
// 	}
// }

// func (d *PackageManager) agentRegisterWithCap() {
// 	// 遍历 capabilities，检查每个 dep 服务是否运行
// 	var availableCapabilities []*config.Capability
// 	for _, capability := range global.Conf.Capabilities {
// 		if capability.Dep != "" {
// 			// 检查 dep 服务是否运行
// 			depSchema := global.PacksCache[capability.Dep]
// 			if depSchema == nil {
// 				xlog.Default().Warn("dependency service schema not found", xlog.String("dep", capability.Dep))
// 				continue
// 			}
// 			pkg, ok := d.packages[depSchema.Package]
// 			if !ok {
// 				xlog.Default().Warn("package not found", xlog.String("package", depSchema.Package))
// 				continue
// 			}
// 			depService, err := pkg.Systemdctl()
// 			if err != nil {
// 				xlog.Default().Error("failed to create systemctl for dep", xlog.FieldErr(err))
// 				continue
// 			}
// 			if !depService.IsRunning() {
// 				// 如果依赖服务未运行，跳过该 capability
// 				xlog.Default().Info("dependency service is not running, filtering out capability", xlog.String("capability", capability.Name))
// 				continue
// 			}
// 		}
// 		// 如果依赖服务正常运行，将该 capability 加入过滤后的列表
// 		availableCapabilities = append(availableCapabilities, capability)
// 	}
// 	bytes, _ := json.Marshal(availableCapabilities)
// 	global.AgentINFO.Metadata["capabilities"] = string(bytes)
// 	// if err := registry.DefaultRegisterer.RegisterService(context.Background(), global.AgentINFO); err != nil {
// 	// 	xlog.Default().Error("failed to update capability", xlog.FieldErr(err))
// 	// }

// 	if err := d.RegisterAgent(); err != nil {
// 		xlog.Default().Error("failed to update agent capabilities", xlog.FieldErr(err))
// 	}
// }

// func (d *PackageManager) servicePortRegister(lAddr string, lPort uint32, packName string) {
// 	info := &server.ServiceInfo{
// 		Scheme:  consts.DiscoverySchema,
// 		Name:    packName,
// 		Address: fmt.Sprintf("%s:%d", lAddr, lPort),
// 	}
// 	if _, ok := d.registered[info.RegistryName()]; !ok {
// 		if err := registry.DefaultRegisterer.RegisterService(context.Background(), info); err != nil {
// 			xlog.Default().Error("failed register pack to etcd", xlog.FieldErr(err))
// 		}
// 		d.registered[packName] = info
// 	}
// }

// func (d *PackageManager) StartTicker() {
// 	go func() {
// 		ticker := time.NewTicker(time.Duration(global.Conf.PackDiscoveryInterval) * time.Second)
// 		defer ticker.Stop()

// 		for range ticker.C {
// 			xlog.Default().Info("start update capability")
// 			go d.agentRegisterWithCap()
// 			xlog.Default().Info("start check packs status")
// 			for packName, packSchema := range global.PacksCache {
// 				xlog.Default().Info("currently preparing to start checking", xlog.String("pack", packName))
// 				go d.packageRegister(packSchema)
// 			}
// 		}
// 	}()
// }
