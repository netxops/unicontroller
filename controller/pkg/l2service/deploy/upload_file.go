package deploy

// const (
// 	ConfigEnv    = "GVA_CONFIG"
// 	ConfigFile   = "config.yaml"
// 	DescribeEnv  = "GVA_DESCRIBE"
// 	DescribeFile = "aaa/deployDescribe.yaml"
// )

// type TargetWithFile struct {
// 	FileName   string
// 	FileType   string
// 	TargetPath string
// 	Header     *multipart.FileHeader
// 	File       multipart.File
// 	// deployConfig DeployConfig
// 	// logger       *zap.Logger
// }

// func NewTargetWithFile(file_name, file_type, target_path string) *TargetWithFile {
// 	return &TargetWithFile{
// 		FileName:   file_name,
// 		FileType:   file_type,
// 		TargetPath: target_path,
// 	}
// }

// func (twf *TargetWithFile) WithFileName(file_name string) *TargetWithFile {
// 	twf.FileName = file_name
// 	return twf
// }

// func (twf *TargetWithFile) WithFile(file multipart.File) *TargetWithFile {
// 	twf.File = file
// 	return twf
// }

// func (twf *TargetWithFile) WithFileType(file_type string) *TargetWithFile {
// 	twf.FileType = file_type
// 	return twf
// }

// func (twf *TargetWithFile) WithHeader(header *multipart.FileHeader) *TargetWithFile {
// 	twf.Header = header
// 	return twf
// }

// func (twf *TargetWithFile) WithTargetPath(target_path string) *TargetWithFile {
// 	twf.TargetPath = target_path
// 	return twf
// }

// func (twf *TargetWithFile) CheckAndMakeSavedir() ([]byte, error) {
// 	save_path := fmt.Sprintf("%s", twf.TargetPath)
// 	cmd := fmt.Sprintf("[ -d %s ] && rm -rf %s && mkdir -p %s || mkdir -p %s", save_path, save_path, save_path, save_path)
// 	out_bytes, err := tools.BaseexecuteCMD(cmd, 0)
// 	return out_bytes, err
// }

// func (twf *TargetWithFile) TarToTmp() ([]byte, error, string) {
// 	name := tools.GetPrefix(twf.FileName, ".") + time.Now().Format("20060102150405")
// 	path := fmt.Sprintf("/tmp/netops_probe/%s", name)
// 	local_file := fmt.Sprintf("%s/%s", twf.TargetPath, twf.FileName)
// 	cmd := fmt.Sprintf("[ -d %s ] && rm -rf %s && mkdir -p %s && tar zxvf %s -C %s || mkdir -p %s && tar zxvf %s -C %s", path, path, path, local_file, path, path, local_file, path)
// 	out_bytes, err := tools.BaseexecuteCMD(cmd, 0)
// 	return out_bytes, err, path
// }

// func (twf *TargetWithFile) FolderIsExist(path string) bool {
// 	if s, err := os.Stat(path); os.IsNotExist(err) {
// 		return false
// 	} else {
// 		if s.IsDir() {
// 			return true
// 		}
// 		return false
// 	}
// }

// func (twf *TargetWithFile) FileIsExist(path string) bool {
// 	if s, err := os.Stat(path); os.IsNotExist(err) {
// 		return false
// 	} else {
// 		if s.IsDir() {
// 			return false
// 		}
// 		return true
// 	}
// }

// // func UploadTar(c *gin.Context) {
// // 	_, header, err := c.Request.FormFile("file")
// // 	if err != nil {
// // 		xlog.Error("接收文件失败!", zap.Any("err", err))
// // 		response.FailWithMessage("接收文件失败", c)
// // 		return
// // 	}
// // 	file_name := header.Filename
// // 	file_name_slice := strings.Split(file_name, ".")
// // 	file_suffix := file_name_slice[len(file_name_slice)-1]
// // 	file_prefix := file_name_slice[0] + time.Now().Format("20060102150405")
// // 	zip_suffix := []string{"zip", "rar", "z", "zipx", "gz", "tar"} //压缩文件后缀
// // 	folder_path := fmt.Sprintf("./%s", global.GVA_CONFIG.DeployFolder.Dir+"Deploy_test/")
// // 	cmd_mkdir := fmt.Sprintf("[ -d %s ] && rm -rf %s && mkdir -p %s || mkdir -p %s", folder_path, folder_path, folder_path, folder_path)
// // 	if CheckStrWithCaseSensitive(file_suffix, zip_suffix) { //创建文件夹
// // 		_, errstr, err := ExecuteCMD(cmd_mkdir)
// // 		if err != nil || errstr != "" {
// // 			xlog.Error("创建文件夹失败!", zap.Any("err", err))
// // 			response.FailWithMessage("创建文件夹失败!", c)
// // 			return
// // 		}
// // 	} else {
// // 		xlog.Error("文件格式不正确!", zap.Any("err", err))
// // 		response.FailWithMessage("文件格式不正确!", c)
// // 		return
// // 	}

// // 	path := fmt.Sprintf("%s%s", folder_path, file_name)
// // 	_ = c.SaveUploadedFile(header, path) //上传文件保存在指定位置

// // 	copy_path := fmt.Sprintf("mkdir -p /tmp/netops_probe/%s && tar zxvf %s -C /tmp/netops_probe/%s", file_prefix, path, file_prefix)
// // 	_, errstr, err := ExecuteCMD(copy_path)
// // 	if err != nil || errstr != "" {
// // 		xlog.Error("解压上传文件失败!", zap.Any("err", err))
// // 		response.FailWithMessage("解压上传文件失败!", c)
// // 		return
// // 	}

// // 	if filesInfo, err := ioutil.ReadDir(fmt.Sprintf("/tmp/netops_probe/%s", file_prefix)); err != nil { //读取指定文件夹
// // 		xlog.Error("读取指定文件夹失败!", zap.Any("err", err))
// // 		response.FailWithMessage("读取指定文件夹失败!", c)
// // 		return
// // 	} else {
// // 		swap := true
// // 		for _, file := range filesInfo {
// // 			fmt.Println("====================================================", file.Name())
// // 			file_slice := strings.Split(file.Name(), ".")
// // 			file_suf := file_slice[len(file_slice)-1]
// // 			if file_suf == "yaml" { //读取描述文件
// // 				file_desc := fmt.Sprintf("/tmp/netops_probe/%s/%s", file_prefix, file.Name())
// // 				if err := Viper(file_desc); err != nil {
// // 					xlog.Error("解析描述文件失败!", zap.Any("err", err))
// // 					response.FailWithMessage("解析描述文件失败!", c)
// // 					return
// // 				}
// // 				swap = false
// // 				// response.OkWithDetailed(global.GVA_DESCRIBE, "读取描述文件", c)
// // 				// return
// // 			}
// // 		}
// // 		main_name := global.GVA_DESCRIBE.Information.MainFileName
// // 		if utils.CheckIn(main_name, filesInfo) {
// // 			if main_files, err := ioutil.ReadDir(fmt.Sprintf("/tmp/netops_probe/%s/%s", file_prefix, main_name)); err != nil { //读取指定文件夹
// // 				xlog.Error("读取指定文件夹失败!", zap.Any("err", err))
// // 				response.FailWithMessage("读取指定文件夹失败!", c)
// // 				return
// // 			} else {
// // 				for _, main_file := range main_files {
// // 					if (main_file.Name() == "plugins") && main_file.IsDir() {
// // 						if plugin_files, err := ioutil.ReadDir(fmt.Sprintf("/tmp/netops_probe/%s/%s/plugins", file_prefix, main_name)); err != nil { //读取指定文件夹
// // 							xlog.Error("读取指定文件夹失败!", zap.Any("err", err))
// // 							response.FailWithMessage("读取指定文件夹失败!", c)
// // 							return
// // 						} else {
// // 							for _, plugin_file := range plugin_files { //判断插件是否有描述文件并读取信息
// // 								fmt.Println("====================================================", plugin_file.Name())

// // 							}
// // 						}
// // 					}
// // 				}
// // 			}
// // 		} else {
// // 			response.FailWithMessage("压缩文件中没有版本文件或者版本文件名与描述文件不符!", c)
// // 			return
// // 		}
// // 		if swap {
// // 			response.FailWithMessage("上传压缩文件中没有yaml描述文件!", c)
// // 			return
// // 		}

// // 	}
// // }

// type Infor struct {
// 	Information Information `mapstructure:"information" json:"information" yaml:"information"`
// }

// type PluginInfor struct {
// 	PInformation Information `mapstructure:"information" json:"information" yaml:"information"`
// }

// type Desc struct {
// 	Infor        Infor         `mapstructure:"infor" json:"infor" form:"infor"`
// 	PluginInfors []PluginInfor `mapstructure:"plugin_infor" json:"plugin_infor" form:"plugin_infor"`
// }

// //
// // type DeployFolder struct {
// // Dir string `mapstructure:"dir" json:"dir" yaml:"dir"`
// // }
// //
// // type PluginFolder struct {
// // Dir string `mapstructure:"dir" json:"dir" yaml:"dir"`
// // }

// type Information struct {
// 	TarName      string   `json:"tar_name" mapstructure:"tar-name" yaml:"tar-name"`
// 	MainFileName string   `json:"main_file_name" mapstructure:"main-file-name" yaml:"main-file-name"`
// 	Version      string   `mapstructure:"version" json:"version" yaml:"version"`
// 	SavePath     string   `mapstructure:"save-path" json:"save_path" yaml:"save-path"`
// 	DeployPath   string   `mapstructure:"deploy-path" json:"deploy_path" yaml:"deploy-path"`
// 	Md5          string   `mapstructure:"md5" json:"md5" yaml:"md5"`
// 	UpdateTime   string   `mapstructure:"update-time" json:"update_time" yaml:"update-time"`
// 	FileSize     int      `mapstructure:"file-size" json:"file_size" yaml:"file-size"`
// 	Plugins      []string `mapstructure:"plugins" json:"plugins" yaml:"plugins"`
// 	Plugin       string   `mapstructure:"plugin" json:"plugin" yaml:"plugin"`
// }

// type pluginTar struct {
// 	GVA_DESCRIBE    Infor
// 	GVA_PLUGIN_DESC PluginInfor
// 	GVA_DESC        Desc
// 	logger          *zap.Logger
// }

// type DeployConfig struct {
// 	GVA_DESCRIBE    Infor
// 	GVA_PLUGIN_DESC PluginInfor
// 	GVA_DESC        Desc
// 	logger          *zap.Logger
// }

// func (dc DeployConfig) Build(logger *zap.Logger) *pluginTar {
// 	return &pluginTar{
// 		GVA_DESCRIBE:    dc.GVA_DESCRIBE,
// 		GVA_PLUGIN_DESC: dc.GVA_PLUGIN_DESC,
// 		GVA_DESC:        dc.GVA_DESC,
// 		logger:          logger,
// 	}
// }

// func viperPluginDesc(path ...string) error { //解析描述文件
// 	logger := log.NewLogger(nil, true)
// 	var config string
// 	if len(path) == 0 {
// 		flag.StringVar(&config, "c", "", "choose config file.")
// 		flag.Parse()
// 		if config == "" { // 优先级: 命令行 > 环境变量 > 默认值
// 			if describeEnv := os.Getenv(DescribeEnv); describeEnv == "" {
// 				config = DescribeFile
// 				fmt.Printf("您正在使用config的默认值,config的路径为%v\n", DescribeFile)
// 			} else {
// 				config = describeEnv
// 				fmt.Printf("您正在使用GVA_CONFIG环境变量,config的路径为%v\n", config)
// 			}
// 		}
// 	} else {
// 		config = path[0]
// 		fmt.Printf("您正在使用func Viper()传递的值,config的路径为%v\n", config)
// 	}
// 	v := viper.New()
// 	v.SetConfigFile(config)
// 	err := v.ReadInConfig()
// 	if err != nil {
// 		return fmt.Errorf("Fatal error config file: %s \n", err)
// 	}
// 	v.WatchConfig()
// 	v.OnConfigChange(func(e fsnotify.Event) {
// 		fmt.Println("config file changed:", e.Name)
// 		if err := v.Unmarshal(&global.GVA_PLUGIN_DESC); err != nil {
// 			// if err := v.Unmarshal(&dc.GVA_PLUGIN_DESC); err != nil {
// 			logger.Error("viperPluginDesc!", zap.Any("err", err))
// 			// dc.logger.Error("Viper失败!", zap.Any("err", err))
// 		}
// 	})
// 	if err := v.Unmarshal(&global.GVA_PLUGIN_DESC); err != nil {
// 		// if err := v.Unmarshal(&dc.GVA_PLUGIN_DESC); err != nil {
// 		return err
// 	}
// 	global.GVA_DESC.PluginInfors = append(global.GVA_DESC.PluginInfors, global.GVA_PLUGIN_DESC)
// 	// dc.GVA_DESC.PluginInfors = append(dc.GVA_DESC.PluginInfors, dc.GVA_PLUGIN_DESC)
// 	return nil
// }

// func viperLocal(path ...string) error { //解析描述文件
// 	logger := log.NewLogger(nil, true)
// 	var config string
// 	if len(path) == 0 {
// 		flag.StringVar(&config, "c", "", "choose config file.")
// 		flag.Parse()
// 		if config == "" { // 优先级: 命令行 > 环境变量 > 默认值
// 			if describeEnv := os.Getenv(DescribeEnv); describeEnv == "" {
// 				config = DescribeFile
// 				fmt.Printf("您正在使用config的默认值,config的路径为%v\n", DescribeFile)
// 			} else {
// 				config = describeEnv
// 				fmt.Printf("您正在使用GVA_CONFIG环境变量,config的路径为%v\n", config)
// 			}
// 		}
// 	} else {
// 		config = path[0]
// 		fmt.Printf("您正在使用func Viper()传递的值,config的路径为%v\n", config)
// 	}
// 	v := viper.New()
// 	v.SetConfigFile(config)
// 	err := v.ReadInConfig()
// 	if err != nil {
// 		return fmt.Errorf("Fatal error config file: %s \n", err)
// 	}
// 	v.WatchConfig()
// 	v.OnConfigChange(func(e fsnotify.Event) {
// 		fmt.Println("config file changed:", e.Name)
// 		if err := v.Unmarshal(&global.GVA_DESC.Infor); err != nil {
// 			// if err := v.Unmarshal(&dc.GVA_DESC.Infor); err != nil {
// 			logger.Error("viperLocal!", zap.Any("err", err))
// 			// dc.logger.Error("Viper失败!", zap.Any("err", err))
// 		}
// 	})
// 	if err := v.Unmarshal(&global.GVA_DESC.Infor); err != nil {
// 		// if err := v.Unmarshal(&dc.GVA_DESC.Infor); err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (twf *TargetWithFile) readMainFile(path string) error {
// 	if filesInfo, err := ioutil.ReadDir(path); err != nil { //读取指定文件夹
// 		return fmt.Errorf("读取指定文件夹失败：%v", err)
// 	} else {
// 		swap := true
// 		for _, file := range filesInfo {
// 			file_name := file.Name()
// 			if tools.GetSuffix(file_name, ".") == "yaml" { //读取描述文件
// 				if err := viperLocal(fmt.Sprintf("%s/%s", path, file_name)); err != nil {
// 					return fmt.Errorf("读取描述文件失败：%v", err)
// 				}
// 				swap = false
// 			}
// 		}
// 		if swap {
// 			return fmt.Errorf("解压的文件中无法找到yaml文件！")
// 		} else {
// 			main_swap := true
// 			for _, f := range filesInfo {
// 				main_name := global.GVA_DESC.Infor.Information.MainFileName
// 				// main_name := twf.deployConfig.GVA_DESC.Infor.Information.MainFileName
// 				fmt.Println("global.GVA_DESCRIBE.Information.MainFileName", main_name)
// 				// fmt.Println("pt.GVA_DESCRIBE.Information.MainFileName", main_name)
// 				if (main_name == f.Name()) && (main_name != "") {
// 					main_swap = false
// 					plugin_path := fmt.Sprintf("%s/%s/plugins", path, main_name)
// 					if twf.FolderIsExist(plugin_path) {
// 						if pluginsInfo, err := ioutil.ReadDir(plugin_path); err != nil { //读取插件文件夹
// 							return fmt.Errorf("读取插件文件夹失败：%v", err)
// 						} else {
// 							for _, plugin := range pluginsInfo {
// 								plugin_name := plugin.Name()
// 								plugin_name_slice := strings.Split(plugin_name, ".")
// 								plugin_name_prefix := strings.Join(plugin_name_slice[:len(plugin_name_slice)-1], ".")
// 								plugin_name_suffix := plugin_name_slice[len(plugin_name_slice)-1]
// 								if plugin_name_suffix == "so" {
// 									desc_name := plugin_name_prefix + ".yaml"
// 									p_swap := true
// 									for _, p := range pluginsInfo {
// 										if desc_name == p.Name() {
// 											if err := viperPluginDesc(fmt.Sprintf("%s/%s", plugin_path, desc_name)); err != nil {
// 												return fmt.Errorf("读取插件描述文件失败：%v", err)
// 											}
// 											p_swap = false
// 											break
// 										}
// 									}
// 									if p_swap {
// 										return fmt.Errorf("插件%s没有描述文件", plugin_name)
// 									}
// 								}
// 							}
// 						}
// 					}
// 				}
// 			}
// 			if main_swap {
// 				return nil
// 			}
// 		}
// 	}
// 	return nil
// }

// func (twf *TargetWithFile) startDealTar(c *gin.Context) error {
// 	if _, err := twf.CheckAndMakeSavedir(); err != nil { //创建用于保存上传文件的路径
// 		return fmt.Errorf("创建用于保存上传文件的文件夹失败：%v", err)
// 	}
// 	_ = c.SaveUploadedFile(twf.Header, twf.TargetPath+"/"+twf.FileName) //上传文件保存在指定位置
// 	_, err, path := twf.TarToTmp()                                      //解压上传文件
// 	if err != nil {
// 		return fmt.Errorf("解压上传文件的文件夹失败：%v", err)
// 	}
// 	return twf.readMainFile(path) //读取文件
// }

// func DealUploadTar(header *multipart.FileHeader, c *gin.Context) error {
// 	file_name := header.Filename
// 	// file_name_slice := strings.Split(file_name, ".")
// 	// file_type := file_name_slice[len(file_name_slice)-1]
// 	file_suffix := tools.GetSuffix(file_name, ".")
// 	file_prefix := tools.GetPrefix(file_name, ".")
// 	target_path := fmt.Sprintf("./%s%s", global.GVA_CONFIG.DeployFolder.Dir, file_prefix)
// 	// target_path := fmt.Sprintf("./%s%s", pt.DeployFolder.Dir, file_prefix)
// 	twf := NewTargetWithFile(file_name, file_suffix, target_path)
// 	twf = twf.WithHeader(header)
// 	return twf.startDealTar(c)
// }

// func DealPluginUploadTar(header *multipart.FileHeader, c *gin.Context) error {
// 	file_name := header.Filename
// 	// file_name_slice := strings.Split(file_name, ".")
// 	// file_type := file_name_slice[len(file_name_slice)-1]
// 	file_suffix := tools.GetSuffix(file_name, ".")
// 	file_prefix := tools.GetPrefix(file_name, ".")
// 	target_path := fmt.Sprintf("./%s%s", global.GVA_CONFIG.PluginFolder.Dir, file_prefix)
// 	// target_path := fmt.Sprintf("./%s%s", pt.PluginFolder.Dir, file_prefix)
// 	twf := NewTargetWithFile(file_name, file_suffix, target_path)
// 	twf = twf.WithHeader(header)
// 	return twf.startDealTar(c)
// }
