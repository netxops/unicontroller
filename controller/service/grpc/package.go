package grpc

import (
	"context"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/pb"
	"github.com/influxdata/telegraf/controller/pkg/packages"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type PackageSrv struct {
	pb.UnimplementedPackageServer
	pkgManager *packages.PackageManager
}

func NewPackageSrv(pm *packages.PackageManager) *PackageSrv {
	ps := &PackageSrv{
		pkgManager: pm,
	}

	return ps
}

func (s *PackageSrv) PackageList(ctx context.Context, _ *emptypb.Empty) (*pb.PackageListResp, error) {
	packages, err := s.pkgManager.PackageList()
	if err != nil {
		xlog.Error("Failed to get package list", xlog.FieldErr(err))
		return nil, status.Errorf(codes.Internal, "failed to get package list: %v", err)
	}

	resp := &pb.PackageListResp{
		Packages: packages,
	}

	xlog.Info("Successfully retrieved package list",
		xlog.Int("packageCount", len(packages)))

	return resp, nil
}

func (s *PackageSrv) Start(ctx context.Context, req *pb.StartReq) (*emptypb.Empty, error) {
	if req == nil || req.Package == "" {
		xlog.Default().Error("Invalid start request", xlog.String("error", "package name is empty"))
		return nil, status.Errorf(codes.InvalidArgument, "the package name cannot be empty")
	}
	xlog.Default().Info("Received start request", xlog.String("package", req.Package))
	go func() {
		xlog.Default().Info("Starting package", xlog.String("package", req.Package))
		err := s.pkgManager.Start(req.Package)
		if err != nil {
			xlog.Default().Error("Failed to start package", xlog.String("package", req.Package), xlog.FieldErr(err))
		} else {
			xlog.Default().Info("Successfully started package", xlog.String("package", req.Package))
		}
	}()
	return &emptypb.Empty{}, nil
}

func (s *PackageSrv) Stop(ctx context.Context, req *pb.StopReq) (*emptypb.Empty, error) {
	if req == nil || req.Package == "" {
		xlog.Default().Error("Invalid stop request", xlog.String("error", "package name is empty"))
		return nil, status.Errorf(codes.InvalidArgument, "the package name cannot be empty")
	}
	xlog.Default().Info("Received stop request", xlog.String("package", req.Package))
	go func() {
		xlog.Default().Info("Stopping package", xlog.String("package", req.Package))
		err := s.pkgManager.Stop(req.Package)
		if err != nil {
			xlog.Default().Error("Failed to stop package", xlog.String("package", req.Package), xlog.FieldErr(err))
		} else {
			xlog.Default().Info("Successfully stopped package", xlog.String("package", req.Package))
		}
	}()
	return &emptypb.Empty{}, nil
}

func (s *PackageSrv) Restart(ctx context.Context, req *pb.RestartReq) (*emptypb.Empty, error) {
	if req == nil || req.Package == "" {
		xlog.Default().Error("Invalid restart request", xlog.String("error", "package name is empty"))
		return nil, status.Errorf(codes.InvalidArgument, "the package name cannot be empty")
	}
	xlog.Default().Info("Received restart request", xlog.String("package", req.Package))
	go func() {
		xlog.Default().Info("Restarting package", xlog.String("package", req.Package))
		err := s.pkgManager.Restart(req.Package)
		if err != nil {
			xlog.Default().Error("Failed to restart package", xlog.String("package", req.Package), xlog.FieldErr(err))
		} else {
			xlog.Default().Info("Successfully restarted package", xlog.String("package", req.Package))
		}
	}()
	return &emptypb.Empty{}, nil
}

// func (s *PackageSrv) Install(ctx context.Context, req *pb.InstallReq) (*emptypb.Empty, error) {
// 	if req == nil || req.Url == "" {
// 		xlog.Default().Error("Invalid install request", xlog.String("error", "package URL is empty"))
// 		return nil, status.Errorf(codes.InvalidArgument, "the package url cannot be empty")
// 	}
// 	xlog.Default().Info("Received install request", xlog.String("url", req.Url))

// 	// 下载包
// 	xlog.Default().Info("Downloading package", xlog.String("url", req.Url))
// 	fth, tempFilePath, err := fetch.NewFetch(req.Url).Download()
// 	if err != nil {
// 		xlog.Default().Error("Failed to fetch package", xlog.String("url", req.Url), xlog.FieldErr(err))
// 		return nil, status.Errorf(codes.Unknown, err.Error())
// 	}
// 	defer fth.Clear()
// 	xlog.Default().Info("Package downloaded successfully", xlog.String("tempFilePath", tempFilePath))

// 	// 解析包
// 	xlog.Default().Info("Parsing package", xlog.String("tempFilePath", tempFilePath))
// 	psr := parser.NewPackageParser(tempFilePath)
// 	if err = psr.Parse(); err != nil {
// 		xlog.Default().Error("Failed to parse package", xlog.FieldErr(err))
// 		return nil, status.Errorf(codes.Unknown, err.Error())
// 	}
// 	xlog.Default().Info("Package parsed successfully")

// 	// 解压到工作目录
// 	xlog.Default().Info("Unzipping package to workspace")
// 	if err = psr.UnzipToWorkspace(); err != nil {
// 		xlog.Default().Error("Failed to unzip package", xlog.FieldErr(err))
// 		return nil, status.Errorf(codes.Unknown, err.Error())
// 	}
// 	xlog.Default().Info("Package unzipped successfully")

// 	// 对模板进行渲染
// 	xlog.Default().Info("Rendering templates")
// 	if err = s.renderTemplates(psr.PackageDIR(), psr.Schema()); err != nil {
// 		xlog.Default().Error("Failed to render templates", xlog.FieldErr(err))
// 		_ = os.RemoveAll(psr.PackageDIR())
// 		return nil, status.Errorf(codes.Unknown, err.Error())
// 	}
// 	xlog.Default().Info("Templates rendered successfully")

// 	// 读取配置文件
// 	schema := psr.Schema()
// 	configPath := path.Join(psr.PackageDIR(), consts.ParserConfDirName, schema.Configs[0].File)
// 	xlog.Default().Info("Reading config file", xlog.String("configPath", configPath))
// 	configContent, err := os.ReadFile(configPath)
// 	if err != nil {
// 		xlog.Default().Error("Failed to read config file", xlog.String("configPath", configPath), xlog.FieldErr(err))
// 		_ = os.RemoveAll(psr.PackageDIR())
// 		return nil, status.Errorf(codes.Unknown, err.Error())
// 	}
// 	xlog.Default().Info("Config file read successfully")

// 	// 使用 PackageManager 进行安装
// 	xlog.Default().Info("Installing package", xlog.String("package", schema.Package))
// 	err = s.pkgManager.Install(psr, schema, string(configContent))
// 	if err != nil {
// 		xlog.Default().Error("Failed to install package", xlog.String("package", schema.Package), xlog.FieldErr(err))
// 		_ = os.RemoveAll(psr.PackageDIR())
// 		return nil, status.Errorf(codes.Unknown, err.Error())
// 	}
// 	xlog.Default().Info("Package installed successfully", xlog.String("package", schema.Package))

// 	return &emptypb.Empty{}, nil
// }

// func (s *PackageSrv) Uninstall(ctx context.Context, req *pb.UninstallReq) (*emptypb.Empty, error) {
// 	if req == nil || req.Package == "" {
// 		xlog.Default().Error("Invalid uninstall request", xlog.String("error", "package name is empty"))
// 		return nil, status.Errorf(codes.InvalidArgument, "the package name cannot be empty")
// 	}

// 	xlog.Default().Info("Received uninstall request", xlog.String("package", req.Package))

// 	go func() {
// 		xlog.Default().Info("Starting package uninstallation", xlog.String("package", req.Package))
// 		err := s.pkgManager.Uninstall(req.Package)
// 		if err != nil {
// 			xlog.Default().Error("Failed to uninstall package",
// 				xlog.String("package", req.Package),
// 				xlog.FieldErr(err))
// 		} else {
// 			xlog.Default().Info("Successfully uninstalled package", xlog.String("package", req.Package))
// 		}
// 	}()

// 	xlog.Default().Info("Uninstall process initiated", xlog.String("package", req.Package))
// 	return &emptypb.Empty{}, nil
// }

// func (s *PackageSrv) Status(ctx context.Context, req *pb.StatusReq) (*pb.StatusResp, error) {
// 	if req == nil || req.Package == "" {
// 		return nil, status.Errorf(codes.InvalidArgument, "the package name cannot be empty")
// 	}

// 	isRunning, err := s.pkgManager.GetStatus(req.Package)
// 	if err != nil {
// 		xlog.Default().Error("get package status error", xlog.FieldErr(err))
// 		return nil, status.Errorf(codes.Unknown, err.Error())
// 	}

//		return &pb.StatusResp{
//			IsRunning: isRunning,
//		}, nil
//	}
func (s *PackageSrv) GetConfigs(ctx context.Context, req *pb.GetConfigsReq) (*pb.GetConfigsResp, error) {
	if req == nil || req.Package == "" {
		xlog.Default().Error("Invalid GetConfigs request", xlog.String("error", "package name is empty"))
		return nil, status.Errorf(codes.InvalidArgument, "the package name cannot be empty")
	}

	xlog.Default().Info("Received GetConfigs request", xlog.String("package", req.Package))

	configs, err := s.pkgManager.GetConfigs(req.Package)
	if err != nil {
		xlog.Default().Error("Failed to get package configs",
			xlog.String("package", req.Package),
			xlog.FieldErr(err))
		return nil, status.Errorf(codes.Unknown, err.Error())
	}

	configItems := make([]*pb.ConfigItem, 0, len(configs))
	for _, configMap := range configs {
		configItems = append(configItems, &pb.ConfigItem{
			FileName: configMap["source"],
			Content:  configMap["content"],
		})
	}

	xlog.Default().Info("Successfully retrieved package configs",
		xlog.String("package", req.Package),
		xlog.Int("configCount", len(configItems)))

	return &pb.GetConfigsResp{
		Configs: configItems,
	}, nil
}

func (s *PackageSrv) ApplyConfigs(ctx context.Context, req *pb.ApplyConfigsReq) (*pb.ApplyConfigsResp, error) {
	if req == nil || req.Package == "" {
		xlog.Default().Error("Invalid ApplyConfigs request", xlog.String("error", "package name is empty"))
		return &pb.ApplyConfigsResp{Success: false, Message: "The package name cannot be empty"}, status.Error(codes.InvalidArgument, "the package name cannot be empty")
	}

	xlog.Default().Info("Received ApplyConfigs request",
		xlog.String("package", req.Package),
		xlog.Int("configCount", len(req.Configs)))

	configFiles := make([]map[string]string, 0, len(req.Configs))
	for _, config := range req.Configs {
		configFiles = append(configFiles, map[string]string{
			"source":  config.FileName,
			"content": config.Content,
		})
	}

	success, message, updatedFiles := s.pkgManager.ApplyConfigs(req.Package, configFiles)
	if !success {
		xlog.Default().Error("Failed to apply package configs",
			xlog.String("package", req.Package),
			xlog.String("message", message))
		return &pb.ApplyConfigsResp{Success: false, Message: message}, nil
	}

	xlog.Default().Info("Successfully applied package configs",
		xlog.String("package", req.Package),
		xlog.Int("configCount", len(configFiles)))

	// 创建更新文件的详细信息
	updatedFileDetails := make([]*pb.UpdatedFileDetail, 0, len(updatedFiles))
	for fileName, byteCount := range updatedFiles {
		updatedFileDetails = append(updatedFileDetails, &pb.UpdatedFileDetail{
			FileName:  fileName,
			ByteCount: int32(byteCount),
		})
	}

	return &pb.ApplyConfigsResp{
		Success:      true,
		Message:      "Configs applied successfully",
		UpdatedFiles: updatedFileDetails,
	}, nil
}

// func (s *PackageSrv) DeleteConfig(ctx context.Context, req *pb.DeleteConfigReq) (*emptypb.Empty, error) {
// 	if req == nil || req.Package == "" {
// 		xlog.Default().Error("Invalid DeleteConfig request", xlog.String("error", "package name is empty"))
// 		return nil, status.Errorf(codes.InvalidArgument, "the package name cannot be empty")
// 	}

// 	xlog.Default().Info("Received DeleteConfig request",
// 		xlog.String("package", req.Package),
// 		xlog.String("confName", req.ConfName))

// 	err := s.pkgManager.DeleteConfig(req.Package, req.ConfName, req.ConfContent)
// 	if err != nil {
// 		xlog.Default().Error("Failed to delete package config",
// 			xlog.String("package", req.Package),
// 			xlog.String("confName", req.ConfName),
// 			xlog.FieldErr(err))
// 		return nil, status.Errorf(codes.Unknown, err.Error())
// 	}

// 	xlog.Default().Info("Successfully deleted package config",
// 		xlog.String("package", req.Package),
// 		xlog.String("confName", req.ConfName))

// 	return &emptypb.Empty{}, nil
// }

// func (s *PackageSrv) renderTemplates(packageDir string, schema *model.Schema) error {
// 	// 从 Schema 中获取变量列表
// 	// vars := schema.Vars

// 	// 从 Controller 获取变量值
// 	varValues, err := s.getVariablesFromController(global.Conf.Code)
// 	if err != nil {
// 		return fmt.Errorf("failed to get variables from controller: %v", err)
// 	}

// 	// 遍历所有 .tpl 文件并渲染
// 	err = filepath.Walk(packageDir, func(path string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}
// 		if !info.IsDir() && strings.HasSuffix(info.Name(), ".tpl") {
// 			if err := s.renderTemplate(path, varValues); err != nil {
// 				return fmt.Errorf("failed to render template %s: %v", path, err)
// 			}
// 		}
// 		return nil
// 	})

// 	return err
// }

// func (s *PackageSrv) renderTemplate(templatePath string, vars map[string]string) error {
// 	// 读取模板文件
// 	content, err := os.ReadFile(templatePath)
// 	if err != nil {
// 		return err
// 	}

// 	// 创建模板
// 	tmpl, err := template.New(path.Base(templatePath)).Parse(string(content))
// 	if err != nil {
// 		return err
// 	}

// 	// 渲染模板
// 	var buf bytes.Buffer
// 	if err := tmpl.Execute(&buf, vars); err != nil {
// 		return err
// 	}

// 	// 写入渲染后的内容到新文件（去掉 .tpl 后缀）
// 	newPath := strings.TrimSuffix(templatePath, ".tpl")
// 	return os.WriteFile(newPath, buf.Bytes(), 0644)
// }

// func (s *PackageSrv) getVariablesFromController(agentCode string) (map[string]string, error) {
// 	url := fmt.Sprintf("http://%s/api/v1/variables?agent_code=%s", global.Conf.Controller, agentCode)

// 	resp, err := http.Get(url)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to send GET request: %v", err)
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		return nil, fmt.Errorf("received non-OK response status: %s", resp.Status)
// 	}

// 	body, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read response body: %v", err)
// 	}

// 	var variables map[string]string
// 	if err := json.Unmarshal(body, &variables); err != nil {
// 		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
// 	}

// 	return variables, nil
// }

func (s *PackageSrv) GetRecentLogs(ctx context.Context, req *pb.GetRecentLogsReq) (*pb.GetRecentLogsResp, error) {
	if req == nil || req.Package == "" {
		xlog.Default().Error("Invalid GetRecentLogs request", xlog.String("error", "package name is empty"))
		return nil, status.Errorf(codes.InvalidArgument, "the package name cannot be empty")
	}

	if req.Count <= 0 {
		xlog.Default().Error("Invalid GetRecentLogs request", xlog.String("error", "count must be positive"))
		return nil, status.Errorf(codes.InvalidArgument, "count must be a positive integer")
	}

	xlog.Default().Info("Received GetRecentLogs request",
		xlog.String("package", req.Package),
		xlog.Int32("count", req.Count))

	logs, err := s.pkgManager.GetRecentLogs(req.Package, int(req.Count))
	if err != nil {
		xlog.Default().Error("Failed to get recent logs",
			xlog.String("package", req.Package),
			xlog.Int32("count", req.Count),
			xlog.FieldErr(err))
		return nil, status.Errorf(codes.Internal, "failed to get recent logs: %v", err)
	}

	xlog.Default().Info("Successfully retrieved recent logs",
		xlog.String("package", req.Package),
		xlog.Int("logCount", len(logs)))

	return &pb.GetRecentLogsResp{
		Logs: logs,
	}, nil
}
