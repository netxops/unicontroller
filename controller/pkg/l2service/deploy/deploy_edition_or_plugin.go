package deploy

// type Deploy struct {
// 	zlog       *zap.Logger
// 	deploy     *model.Deploy
// 	failProbe  map[string]struct{}
// 	deployFile DeployFile
// 	plugin     model.Plugin
// }

// func InitDeploy(id int) *Deploy {
// 	err_deploy, deploy := GetDeployMoudle(id)
// 	if err_deploy != nil {
// 		fmt.Println("获取部署失败：", err_deploy)
// 		os.Exit(1)
// 	}
// 	var probe_ids []int
// 	for _, deploy_probe := range deploy.Probes { //部署步骤初始化
// 		probe_ids = append(probe_ids, int(deploy_probe.ID))
// 	}
// 	var err_probe error
// 	if (model.Plugin{} == deploy.Plugin) && (deploy.PluginID == 0) { // 判断是插件部署还是版本部署
// 		err_probe = ProbesInitStepsByIds(probe_ids, 0)
// 	} else {
// 		err_probe = ProbesInitStepsByIds(probe_ids, 1)
// 	}
// 	if err_probe != nil {
// 		fmt.Println("探针部署步骤初始化失败：", err_probe)
// 		os.Exit(1)
// 	}
// 	fmt.Println("获取bushu：", deploy)
// 	df := NewEditionDeployFile(deploy.EditionID)
// 	return &Deploy{
// 		zlog:       global.GVA_LOG,
// 		deploy:     &deploy,
// 		failProbe:  make(map[string]struct{}),
// 		deployFile: df,
// 		plugin:     deploy.Plugin,
// 	}
// }

// // 开始执行版本部署
// func (d *Deploy) EditionExec() error {
// 	fmt.Println("开始执行部署")
// 	d.editionDeploy()
// 	if len(d.failProbe) > 0 {
// 		var s string
// 		for key, _ := range d.failProbe {
// 			s += key + ", "
// 		}
// 		return errors.New(fmt.Sprintf("%s 部署失败！！", s))
// 	}
// 	return nil
// }

// // 拷贝 '探针项目' 到 '探针服务器' 上, 并运行服务
// func (d *Deploy) editionDeploy() {
// 	i := 0
// 	for _, probe := range d.deploy.Probes {
// 		targetAuth := NewTargetWithAuth(probe.User, probe.Password, probe.Ip)
// 		// 1.设置管理机与探针机互信 sshpass -p Admin@123 ssh-copy-id  -i ~/.ssh/id_rsa.pub asialink@192.168.237.130
// 		// Step1CMD(deploy)
// 		//cmdStr := fmt.Sprintf("sshpass -p %s ssh-copy-id -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa.pub %s@%s", probe.Password, probe.User, probe.Ip)
// 		//cmdStr := fmt.Sprintf("sshpass -p %s ssh-copy-id -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa.pub %s@%s", probe.Password, probe.User, probe.Ip)

// 		// 2.部署前查看进程是否存在，存在就杀死 "ps -ef | grep netops_probe | grep -vE 'grep|tail' |awk '{print $2}' | xargs kill -9"
// 		err_kill := targetAuth.ProbeEditKillProcess(probe.ID, d.deployFile)
// 		d.checkError(err_kill, "KillProcess", probe.Ip)
// 		if len(d.failProbe) > 0 {
// 			continue
// 		}

// 		// 3.检查部署目录，如果存在则删除重建目录 "[ -d ~/netops_probe ] && rm -rf ~/netops_probe && mkdir -p ~/netops_probe || mkdir -p ~/netops_probe"
// 		err_cDir := targetAuth.ProbeEditCheckDir(probe.ID, d.deployFile)
// 		d.checkError(err_cDir, "CheckMakeDir", probe.Ip)
// 		if len(d.failProbe) > 0 {
// 			continue
// 		}

// 		// 4.将本地的探针项目压缩包拷贝过去 scp -p netops_probe.tar.gz asialink@192.168.237.130:~/netops_probe/
// 		err_cp := targetAuth.CopyFileToRemote(probe.ID, d.deployFile)
// 		d.checkError(err_cp, "CopyFile", probe.Ip)
// 		if len(d.failProbe) > 0 {
// 			continue
// 		}

// 		// 5.进入目录解压文件并开始后台运行 "cd ~/netops_probe/ && tar zxvf netops_probe.tar.gz && bash script/start.sh"
// 		err_EAR := targetAuth.UnzipAndExec(probe.ID, d.deployFile)
// 		d.checkError(err_EAR, "UnzipAndExec", probe.Ip)
// 		if len(d.failProbe) > 0 {
// 			continue
// 		}

// 		// 6. 检查探针服务是否启动成功
// 		err_checkProcess := targetAuth.CheckRemoteProcess(probe.ID, d.deployFile)
// 		d.checkError(err_checkProcess, "CheckRemoteProcess", probe.Ip)
// 		if len(d.failProbe) > 0 {
// 			continue
// 		}
// 		i++
// 	}
// 	if len(d.deploy.Probes) <= i {
// 		d.zlog.Info(fmt.Sprintf("所有探针部署完毕"))
// 	}
// }

// func (d *Deploy) checkError(err error, desc string, ip string) {
// 	if err != nil {
// 		d.zlog.Error(fmt.Sprintf("%s Error: %v", desc, err))
// 		d.failProbe[ip] = struct{}{}
// 	}
// }

// // 开始执行插件部署
// func (d *Deploy) PluginExec() error {
// 	fmt.Println("开始执行部署")
// 	d.pluginDeploy()
// 	if len(d.failProbe) > 0 {
// 		var s string
// 		for key, _ := range d.failProbe {
// 			s += key + ", "
// 		}
// 		return errors.New(fmt.Sprintf("%s 部署失败！！", s))
// 	}
// 	return nil
// }

// // 拷贝 '探针项目' 到 '探针服务器' 上, 并运行服务
// func (d *Deploy) pluginDeploy() {
// 	var p_ip []string
// 	deploy := d.deploy
// 	for _, probe := range deploy.Probes {
// 		targetAuth := NewTargetWithAuth(probe.User, probe.Password, probe.Ip)
// 		main_name, dir_path, tar_name := d.deployFile.MainFileName(), d.deployFile.TargetPath(), d.plugin.TarName
// 		// 3.检查插件部署目录，如果不存在则创建目录
// 		err := targetAuth.PluginMakeDir(probe, dir_path, main_name)

// 		d.checkError(err, "makedir", probe.Ip)
// 		fmt.Printf("mkdir....")
// 		if len(d.failProbe) > 0 {
// 			fmt.Printf("111")
// 			continue
// 		}

// 		// 4.将本地的插件压缩包拷贝到远程探针位置
// 		err = targetAuth.PluginCopyFile(probe, tar_name, dir_path, main_name)
// 		d.checkError(err, "copyfile", probe.Ip)
// 		fmt.Printf("copyfile....")
// 		if len(d.failProbe) > 0 {
// 			fmt.Printf("222")
// 			continue
// 		}

// 		// 5.进入目录解压文件
// 		err = targetAuth.PluginUnzipAndRm(probe, dir_path, main_name, tar_name)
// 		d.checkError(err, "UnzipandRemove", probe.Ip)
// 		fmt.Printf("upzip....")
// 		if len(d.failProbe) > 0 {
// 			fmt.Printf("333")
// 			continue
// 		}

// 		p_ip = append(p_ip, probe.Ip)
// 	}

// 	d.zlog.Info(fmt.Sprintf("%v 探针部署完毕", p_ip))
// }
