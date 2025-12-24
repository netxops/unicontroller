package packages

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/douyu/jupiter/pkg/server"
	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pb"
	"github.com/influxdata/telegraf/controller/types"
	"github.com/netxops/utils/tools"
)

type PackageManager struct {
	packages      *tools.SafeMap[string, *Package]
	registered    *tools.SafeMap[string, *server.ServiceInfo]
	configManager ConfigManager
}

func NewPackageManager() *PackageManager {
	return &PackageManager{
		packages:      tools.NewSafeMap[string, *Package](),
		registered:    tools.NewSafeMap[string, *server.ServiceInfo](),
		configManager: *NewConfigManager(),
	}
}

// PackageList returns a list of all registered packages with their status
func (pm *PackageManager) PackageList() ([]*pb.PackItem, error) {
	var items []*pb.PackItem

	pm.packages.Range(func(packageName string, pkg *Package) bool {
		ctl := pkg.SystemCTL()
		isRunning, since := ctl.IsRunningWithSinceTime()

		schemaBytes, err := json.Marshal(pkg.Spec)
		if err != nil {
			xlog.Error("Failed to marshal package spec",
				xlog.String("package", packageName),
				xlog.FieldErr(err))
			return true // continue to next package
		}

		item := &pb.PackItem{
			Package:         pkg.Spec.Package,
			Schema:          string(schemaBytes),
			IsRunning:       isRunning,
			Version:         pkg.Spec.Version,
			RunningDuration: int64(since.Seconds()),
		}

		items = append(items, item)
		return true
	})

	return items, nil
}

func (pm *PackageManager) scanWorkspace() error {
	xlog.Default().Info("Scanning workspace for packages")

	files, err := os.ReadDir(global.Conf.Workspace)
	if err != nil {
		return fmt.Errorf("failed to read workspace directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			packageDir := filepath.Join(global.Conf.Workspace, file.Name())
			packageJsonPath := filepath.Join(packageDir, "package.json")
			if _, err := os.Stat(packageJsonPath); err == nil {
				// package.json exists, parse it
				spec, err := pm.parsePackageJson(packageJsonPath)
				if err != nil {
					xlog.Default().Error("Failed to parse package.json",
						xlog.String("package", file.Name()),
						xlog.FieldErr(err))
					continue
				}
				if spec.Package == global.Conf.AppID {
					continue
				}
				// Update or add the package
				pm.updateOrAddPackage(spec)
			}
		}
	}

	return nil
}

// 解析package.json文件
func (pm *PackageManager) parsePackageJson(path string) (*types.PackageSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var spec types.PackageSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	return &spec, nil
}

// 更新或添加package
func (pm *PackageManager) updateOrAddPackage(spec *types.PackageSpec) {

	pkg, exists := pm.packages.Get(spec.Package)
	if exists {
		// Update existing package
		pkg.Spec = spec
		pkg.Name = spec.Package
		pm.packages.Set(spec.Package, pkg)
	} else {
		// Add new package
		newPkg := &Package{
			Name:      spec.Package,
			Spec:      spec,
			IsRunning: false,
		}

		pm.packages.Set(spec.Package, newPkg)
	}
}

// 修改Loop方法以包含周期性扫描
func (pm *PackageManager) Loop(ctx context.Context) {
	scanTicker := time.NewTicker(time.Duration(global.Conf.PackDiscoveryInterval) * time.Second)
	defer scanTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			xlog.Default().Info("PackageManager Loop is shutting down")
			return
		case <-scanTicker.C:
			if err := pm.scanWorkspace(); err != nil {
				xlog.Default().Error("Failed to scan workspace", xlog.FieldErr(err))
			}
		}
	}
}

func (pm *PackageManager) GetAllPackageStatuses() ([]*types.PackageStatus, error) {
	var statuses []*types.PackageStatus

	pm.packages.Range(func(packageName string, pkg *Package) bool {
		status, err := pm.GetPackageStatus(packageName)
		if err != nil {
			xlog.Default().Error("Failed to get package status",
				xlog.String("package", packageName),
				xlog.FieldErr(err))
			return true // continue to next package
		}

		statuses = append(statuses, status)
		return true
	})

	return statuses, nil
}

func (pm *PackageManager) GetPackageStatus(packageName string) (*types.PackageStatus, error) {
	pkg, exists := pm.packages.Get(packageName)
	if !exists {
		return nil, fmt.Errorf("package %s not found", packageName)
	}

	ctl := pkg.SystemCTL()

	isRunning, since := ctl.IsRunningWithSinceTime()
	status := &types.PackageStatus{
		Name:      pkg.Spec.Package,
		Version:   pkg.Spec.Version,
		IsRunning: isRunning,
		Duration:  time.Duration(since.Seconds()),
	}

	return status, nil
}

// Start starts a package by its name
func (pm *PackageManager) Start(packageName string) error {
	xlog.Debug("Starting package", xlog.String("package", packageName))

	pkg, exists := pm.packages.Get(packageName)
	if !exists {
		return fmt.Errorf("package %s not found", packageName)
	}

	ctl := pkg.SystemCTL()

	// Check if already running
	isRunning, _ := ctl.IsRunningWithSinceTime()
	if isRunning {
		xlog.Info("Package is already running", xlog.String("package", packageName))
		return nil
	}

	// Start the service
	if err := ctl.Start(); err != nil {
		xlog.Error("Failed to start package",
			xlog.String("package", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to start package %s: %w", packageName, err)
	}

	// Verify the service started successfully
	isRunning, since := ctl.IsRunningWithSinceTime()
	if !isRunning {
		return fmt.Errorf("failed to start package %s: service not running after start command", packageName)
	}

	xlog.Info("Package started successfully",
		xlog.String("package", packageName),
		xlog.String("version", pkg.Spec.Version),
		xlog.Duration("running_since", since))

	return nil
}

// Stop stops a package by its name
func (pm *PackageManager) Stop(packageName string) error {
	xlog.Debug("Stopping package", xlog.String("package", packageName))

	pkg, exists := pm.packages.Get(packageName)
	if !exists {
		return fmt.Errorf("package %s not found", packageName)
	}

	ctl := pkg.SystemCTL()

	// Check if already stopped
	isRunning, _ := ctl.IsRunningWithSinceTime()
	if !isRunning {
		xlog.Info("Package is already stopped", xlog.String("package", packageName))
		return nil
	}

	// Stop the service
	if err := ctl.Stop(); err != nil {
		xlog.Error("Failed to stop package",
			xlog.String("package", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to stop package %s: %w", packageName, err)
	}

	// Verify the service stopped successfully
	isRunning, _ = ctl.IsRunningWithSinceTime()
	if isRunning {
		return fmt.Errorf("failed to stop package %s: service still running after stop command", packageName)
	}

	xlog.Info("Package stopped successfully",
		xlog.String("package", packageName),
		xlog.String("version", pkg.Spec.Version))

	return nil
}

// Restart restarts a package by its name
func (pm *PackageManager) Restart(packageName string) error {
	xlog.Debug("Restarting package", xlog.String("package", packageName))

	pkg, exists := pm.packages.Get(packageName)
	if !exists {
		return fmt.Errorf("package %s not found", packageName)
	}

	ctl := pkg.SystemCTL()

	// Use the systemd restart command directly
	if err := ctl.Restart(); err != nil {
		xlog.Error("Failed to restart package",
			xlog.String("package", packageName),
			xlog.FieldErr(err))
		return fmt.Errorf("failed to restart package %s: %w", packageName, err)
	}

	// Verify the service is running after restart
	isRunning, since := ctl.IsRunningWithSinceTime()
	if !isRunning {
		return fmt.Errorf("failed to restart package %s: service not running after restart command", packageName)
	}

	xlog.Info("Package restarted successfully",
		xlog.String("package", packageName),
		xlog.String("version", pkg.Spec.Version),
		xlog.Duration("running_since", since))

	return nil
}

// GetConfigs retrieves the configuration files for a package
// GetConfigs retrieves the configuration files for a package
func (pm *PackageManager) GetConfigs(packageName string) ([]map[string]string, error) {
	xlog.Info("Starting to get configs for package", xlog.String("package", packageName))

	pkg, exists := pm.packages.Get(packageName)
	if !exists {
		errMsg := fmt.Sprintf("package %s not found", packageName)
		xlog.Error("Failed to get configs: package not found",
			xlog.String("package", packageName),
			xlog.String("error", errMsg))
		return nil, fmt.Errorf(errMsg)
	}

	xlog.Debug("Package found, registering spec with config manager",
		xlog.String("package", packageName),
		xlog.String("version", pkg.Spec.Version))

	// Register the package spec with the config manager if not already registered
	pm.configManager.packages.Set(packageName, pkg.Spec)

	xlog.Debug("Requesting config files from config manager",
		xlog.String("package", packageName))

	// Use the config manager to get the config files
	configFiles, err := pm.configManager.GetConfigFiles(packageName)
	if err != nil {
		errMsg := fmt.Sprintf("failed to get config files for package %s: %v", packageName, err)
		xlog.Error("Failed to get configs from config manager",
			xlog.String("package", packageName),
			xlog.FieldErr(err))
		return nil, fmt.Errorf(errMsg)
	}

	xlog.Debug("Config files retrieved from config manager",
		xlog.String("package", packageName),
		xlog.Int("file_count", len(configFiles)))

	// Log each config file path
	for i, file := range configFiles {
		xlog.Debug("Config file details",
			xlog.String("package", packageName),
			xlog.Int("file_index", i),
			xlog.String("file_path", file["source"]),
			xlog.Int("content_length", len(file["content"])))
	}

	xlog.Info("Successfully retrieved configs",
		xlog.String("package", packageName),
		xlog.Int("file_count", len(configFiles)))

	return configFiles, nil
}

// ApplyConfigs applies the provided configuration files to a package
func (pm *PackageManager) ApplyConfigs(packageName string, configFiles []map[string]string) (bool, string, map[string]int) {
	xlog.Debug("Applying configs for package",
		xlog.String("package", packageName),
		xlog.Int("file_count", len(configFiles)))

	pkg, exists := pm.packages.Get(packageName)
	if !exists {
		errMsg := fmt.Sprintf("package %s not found", packageName)
		xlog.Error("Failed to apply configs",
			xlog.String("package", packageName),
			xlog.String("error", errMsg))
		return false, errMsg, nil
	}

	// Register the package spec with the config manager if not already registered
	pm.configManager.packages.Set(packageName, pkg.Spec)

	// Log the files that will be updated
	xlog.Info("Files to be updated:",
		xlog.String("package", packageName))
	for _, file := range configFiles {
		if path, ok := file["source"]; ok {
			xlog.Info("- " + path)
		}
	}

	// First, stop the service
	xlog.Info("Stopping package before applying config changes",
		xlog.String("package", packageName))
	if err := pm.Stop(packageName); err != nil {
		errMsg := fmt.Sprintf("failed to stop package %s before applying config changes: %v", packageName, err)
		xlog.Error("Failed to stop package before applying config changes",
			xlog.String("package", packageName),
			xlog.FieldErr(err))
		return false, errMsg, nil
	}

	// Use the config manager to update the config files
	updatedFiles, err := pm.configManager.UpdateConfigs(pkg.Spec, configFiles)
	if err != nil {
		errMsg := fmt.Sprintf("failed to update config files for package %s: %v", packageName, err)
		xlog.Error("Failed to apply configs",
			xlog.String("package", packageName),
			xlog.FieldErr(err))
		return false, errMsg, nil
	}

	// Start the service again
	xlog.Info("Starting package after applying config changes",
		xlog.String("package", packageName))
	if err := pm.Start(packageName); err != nil {
		errMsg := fmt.Sprintf("failed to start package %s after applying config changes: %v", packageName, err)
		xlog.Error("Failed to start package after applying config changes",
			xlog.String("package", packageName),
			xlog.FieldErr(err))
		return false, errMsg, updatedFiles
	}

	xlog.Info("Successfully applied configs and restarted package",
		xlog.String("package", packageName),
		xlog.Int("file_count", len(configFiles)))

	return true, "Successfully applied configs and restarted package", updatedFiles
}

// GetRecentLogs retrieves the most recent n log entries for a package
func (pm *PackageManager) GetRecentLogs(packageName string, n int) ([]string, error) {
	xlog.Debug("Retrieving recent logs",
		xlog.String("package", packageName),
		xlog.Int("count", n))

	pkg, exists := pm.packages.Get(packageName)
	if !exists {
		return nil, fmt.Errorf("package %s not found", packageName)
	}

	// Construct the base journalctl command
	args := []string{
		"-u", pkg.Spec.Package, // Use the package name as the systemd unit name
		"-n", strconv.Itoa(n), // Get the last n entries
		"--no-pager",          // Disable paging
		"-o", "short-precise", // Use a compact output format
	}

	// Add --user flag if not a privileged user
	if !types.IsPrivilegedUser() {
		args = append([]string{"--user"}, args...)
	}

	cmd := exec.Command("journalctl", args...)

	// If not a privileged user, set necessary environment variables
	if !types.IsPrivilegedUser() {
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid()),
			fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", os.Getuid()))
	}

	// Run the command and capture the output
	output, err := cmd.CombinedOutput()
	if err != nil {
		xlog.Error("Failed to retrieve logs",
			xlog.String("package", packageName),
			xlog.FieldErr(err))
		return nil, fmt.Errorf("failed to retrieve logs for package %s: %w", packageName, err)
	}

	// Split the output into lines
	logs := strings.Split(strings.TrimSpace(string(output)), "\n")

	xlog.Info("Successfully retrieved logs",
		xlog.String("package", packageName),
		xlog.Int("log_count", len(logs)))

	return logs, nil
}
