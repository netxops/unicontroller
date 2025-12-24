package initialize

// const InitConfigFilePath = "../config/device_usage_plan_config.json"
// const StartupCommandParamItem = "mnm"

// var Logger = global.GetLogger()

// type L3 struct {
// 	MetaNodeMap map[string]meta.MetaNodeMap
// }

// // Initialization L3初始化入口
// func (l3 *L3) Initialization() {
// 	l3.MetaNodeMap = global.GetNodeMaps()
// 	if len(l3.MetaNodeMap) != 0 {
// 		err := errors.New("l3 has a dirty data and it can't be initialized")
// 		Logger.Panic(err.Error())
// 		panic(err)
// 	}

// 	metaNodeMapConfigs := parserConfig()
// 	l3.makeL3MetaNodeMap(metaNodeMapConfigs)

// 	l3cache.Init()
// }

// // 解析L3配置文件
// func parserConfig() []meta.MetaNodeMap {
// 	bytes, err := os.ReadFile(InitConfigFilePath)
// 	if err != nil {
// 		Logger.Panic(err.Error())
// 		panic(err)
// 	}

// 	var nodeMaps []meta.MetaNodeMap
// 	if err = json.Unmarshal(bytes, &nodeMaps); err != nil {
// 		Logger.Panic(err.Error())
// 		panic(err)
// 	}
// 	return nodeMaps
// }

// // 根据配置文件数据，匹配有效数据并构建L3NodeMap
// func (l3 *L3) makeL3MetaNodeMap(nodeMaps []meta.MetaNodeMap) {
// 	nodeMapNames := flag.String(StartupCommandParamItem)
// 	if nodeMapNames == "" {
// 		err := errors.New(fmt.Sprintf("l3 has no parameter[%s] value in the startup command and it can't be initialized", StartupCommandParamItem))
// 		Logger.Panic(err.Error())
// 		panic(err)
// 	}

// 	mapNames := strings.Split(nodeMapNames, ",")
// 	for _, name := range mapNames {
// 		for _, v := range nodeMaps {
// 			if name == v.Name {
// 				if _, ok := l3.MetaNodeMap[name]; ok {
// 					err := errors.New("l3 contains multiple values with the same name and it can't be initialized")
// 					Logger.Panic(err.Error())
// 					panic(err)
// 				}
// 				l3.MetaNodeMap[name] = v
// 			}
// 		}
// 	}

// 	for _, v := range l3.MetaNodeMap {
// 		if err := v.ValidateStruct(); err != nil {
// 			Logger.Panic(err.Error())
// 			panic(err)
// 		}
// 	}

// 	global.InitNodeMaps(l3.MetaNodeMap)
// }
