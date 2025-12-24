package packages

import (
	"os"

	"github.com/influxdata/telegraf/controller/pkg/systemctl"
	"github.com/influxdata/telegraf/controller/types"
)

type Package struct {
	Name          string
	Spec          *types.PackageSpec
	ConfigManager ConfigManager
	IsRunning     bool
}

func (pkg *Package) SystemCTL() *systemctl.SystemCTL {
	return &systemctl.SystemCTL{
		Name:       pkg.Name,
		IsUserUnit: !isPrivilegedUser(),
	}

}

func isPrivilegedUser() bool {
	return os.Geteuid() == 0
}

// func (pkg *Package) SystemdCtl() (*systemctl.SystemCTL, error) {
// 	if pkg.Spec.Startup.Method != consts.SystemdStartup {
// 		return nil, errors.New("the schema file startup method is def as a script")
// 	}

// 	// 如果已经存在缓存的 systemctl 实例，直接返回
// 	if pkg.systemctl != nil {
// 		return pkg.systemctl, nil
// 	}

// 	execStart := pkg.binaryPath()
// 	for _, conf := range pkg.Spec.Configs {
// 		confFile := path.Join(global.Conf.Workspace, pkg.Spec.Package, consts.ParserConfDirName, strings.TrimSpace(conf.File))
// 		arg := strings.TrimSpace(conf.Arg) + confFile
// 		execStart = strings.Join([]string{execStart, arg}, " ")
// 	}
// 	for _, arg := range pkg.Spec.Args {
// 		execStart = strings.Join([]string{execStart, arg}, " ")
// 	}

// 	opt := []systemctl.UnitOption{
// 		{"Unit", "Description", pkg.Spec.Desc},
// 		{"Service", "Type", "simple"},
// 		{"Service", "ExecStart", execStart},
// 		{"Service", "Restart", "on-failure"},
// 		{"Install", "WantedBy", "default.target"},
// 	}
// 	bs, err := io.ReadAll(systemctl.Serialize(opt))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to serialize systemd unit options: %v", err)
// 	}

// 	ctl, err := systemctl.NewSystemCTL(pkg.Spec.Package, string(bs), global.Conf.IsUserUnit, global.Conf.EnableLingering)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// 缓存创建的 systemctl 实例
// 	pkg.systemctl = ctl
// 	return ctl, nil
// }

// func (pkg *Package) binaryPath() string {
// 	return path.Join(global.Conf.Workspace, pkg.Spec.Package, consts.ParserApplicationDirName, pkg.Spec.Binary)
// }

// func (pkg *Package) ConfigDir() string {
// 	return pkg.Paths.ConfDir
// }

// func (pkg *Package) ApplicationDir() string {
// 	return pkg.Paths.ApplicationDir
// }

// func (pkg *Package) ConfigFileFormat() string {
// 	return pkg.Spec.Format
// }

// func (pkg *Package) ConfigFile() string {
// 	if !strings.HasPrefix(pkg.Spec.ConfigFile, "/") {
// 		return filepath.Join(pkg.ConfigDir(), pkg.Spec.ConfigFile)
// 	}
// 	return pkg.Spec.ConfigFile
// }
