package core

// const defaultConfigFile = "./config.yaml"

// func Init(configFile string) {
// 	v := viper.New()
// 	//ePath, _ := os.Getwd()
// 	//defaultConfigFile :=ePath+"/config.yaml"
// 	//fmt.Print("====111",defaultConfigFile)
// 	v.SetConfigFile(defaultConfigFile)
// 	// 读取配置文件中的配置信息，并将信息保存 到 v中
// 	err := v.ReadInConfig()
// 	if err != nil {
// 		panic(fmt.Errorf("Fatal error config file: #{err}\n"))
// 	}
// 	// 监控配置文件
// 	v.WatchConfig()
// 	// 配置文件改变，则将 v中的配置信息，刷新到 global.CONFIG
// 	v.OnConfigChange(func(e fsnotify.Event) {
// 		fmt.Println("config file changed:", e.Name)
// 		if err := v.Unmarshal(&global.CONFIG); err != nil {
// 			fmt.Println(err)
// 		}
// 	})
// 	// 将 v 中的配置信息 反序列化成 结构体 (将v 中配置信息 刷新到 global.CONFIG)
// 	if err := v.Unmarshal(&global.CONFIG); err != nil {
// 		fmt.Println(err)
// 	}
// 	global.VP = v
// }
