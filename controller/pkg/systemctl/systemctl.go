package systemctl

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/influxdata/telegraf/controller/consts"
)

type SystemCTL struct {
	Name       string
	IsUserUnit bool
}

// func NewSystemCTL(name, unitContent string, IsUserUnit bool, enableLingering bool) (*SystemCTL, error) {
// 	if !strings.Contains(unitContent, "[Install]") {
// 		unitContent += "\n[Install]\nWantedBy=default.target\n"
// 	}

// 	return &SystemCTL{
// 		Name: name,
// 		// content:         unitContent,
// 		IsUserUnit: IsUserUnit,
// 		// enableLingering: enableLingering,
// 	}, nil
// }

func NewSystemCTL(name, unitContent string, IsUserUnit bool) (*SystemCTL, error) {
	return &SystemCTL{
		Name:       name,
		IsUserUnit: IsUserUnit,
	}, nil
}

func (s *SystemCTL) IsRunningWithSinceTime() (bool, time.Duration) {
	status, since, _ := s.Status()
	return status == consts.SystemdRunning, since
}

func (s *SystemCTL) Status() (status string, uptime time.Duration, err error) {
	var output string
	if s.IsUserUnit {
		output, err = s.runUserCommandOutput("--timestamp=unix", "status", s.Name)
	} else {
		output, err = s.runSystemCommandOutput("--timestamp=unix", "status", s.Name)
	}
	if err != nil {
		return consts.SystemdUnknown, 0, err
	}

	// 匹配状态和时间戳
	regex := regexp.MustCompile(`Active: (.+) since @(\d+);`)
	match := regex.FindStringSubmatch(output)

	if len(match) >= 3 {
		status = strings.TrimSpace(match[1])
		timestamp, err := strconv.ParseInt(match[2], 10, 64)
		if err != nil {
			return status, 0, fmt.Errorf("failed to parse timestamp: %v", err)
		}

		// 计算运行时间
		now := time.Now().Unix()
		uptime = time.Duration(now-timestamp) * time.Second

		// 如果状态字符串太长，可能表示服务已停止
		if len(status) > 16 {
			return consts.SystemdDead, 0, nil
		}

		return status, uptime, nil
	}

	// 如果没有匹配到预期的格式，返回未知状态
	return consts.SystemdUnknown, 0, nil
}

// func (s *SystemCTL) InstallSystemd() error {
// 	if s.IsUserUnit {
// 		return s.installUserSystemd()
// 	}
// 	return s.installSystemSystemd()
// }

// func (s *SystemCTL) UninstallSystemd() error {
// 	if s.IsUserUnit {
// 		return s.uninstallUserSystemd()
// 	}
// 	return s.uninstallSystemSystemd()
// }

// func (s *SystemCTL) installUserSystemd() error {
// 	homeDir, err := os.UserHomeDir()
// 	if err != nil {
// 		return fmt.Errorf("failed to get user home directory: %v", err)
// 	}

// 	userSystemdDir := filepath.Join(homeDir, ".config", "systemd", "user")
// 	if err := os.MkdirAll(userSystemdDir, 0755); err != nil {
// 		return fmt.Errorf("failed to create user systemd directory: %v", err)
// 	}

// 	unitFilePath := filepath.Join(userSystemdDir, s.unitName())
// 	if err := ioutil.WriteFile(unitFilePath, []byte(s.content), 0644); err != nil {
// 		return fmt.Errorf("failed to write user unit file: %v", err)
// 	}

// 	if err := s.runUserCommand("daemon-reload"); err != nil {
// 		return fmt.Errorf("failed to reload user systemd: %v", err)
// 	}

// 	if err := s.runUserCommand("enable", s.unitName()); err != nil {
// 		return fmt.Errorf("failed to enable user service: %v", err)
// 	}

// 	if s.enableLingering {
// 		if err := s.setLingering(true); err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

// func (s *SystemCTL) uninstallUserSystemd() error {
// 	if err := s.runUserCommand("stop", s.unitName()); err != nil {
// 		fmt.Printf("Warning: Failed to stop user service: %v\n", err)
// 	}

// 	if err := s.runUserCommand("disable", s.unitName()); err != nil {
// 		fmt.Printf("Warning: Failed to disable user service: %v\n", err)
// 	}

// 	unitPath := s.unitPath()
// 	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
// 		fmt.Printf("Warning: Failed to remove user unit file: %v\n", err)
// 	}

// 	if err := s.runUserCommand("daemon-reload"); err != nil {
// 		fmt.Printf("Warning: Failed to reload user systemd: %v\n", err)
// 	}

// 	if s.enableLingering {
// 		if err := s.setLingering(false); err != nil {
// 			fmt.Printf("Warning: Failed to disable lingering: %v\n", err)
// 		}
// 	}

// 	fmt.Println("User service uninstallation completed with warnings")
// 	return nil
// }

func (s *SystemCTL) Start() error {
	if s.IsUserUnit {
		return s.runUserCommand("start", s.Name)
	}
	return s.runSystemCommand("start", s.Name)
}

func (s *SystemCTL) Stop() error {
	if s.IsUserUnit {
		return s.runUserCommand("stop", s.Name)
	}
	return s.runSystemCommand("stop", s.Name)
}

func (s *SystemCTL) Restart() error {
	if s.IsUserUnit {
		return s.runUserCommand("restart", s.Name)
	}
	return s.runSystemCommand("restart", s.Name)
}

// func (s *SystemCTL) installSystemSystemd() error {
// 	unitPath := s.unitPath()
// 	if unitPath == "" {
// 		return fmt.Errorf("failed to get unit path")
// 	}

// 	// Ensure the directory exists
// 	dir := filepath.Dir(unitPath)
// 	if err := os.MkdirAll(dir, 0755); err != nil {
// 		return fmt.Errorf("failed to create directory: %v", err)
// 	}

// 	_, err := os.Stat(unitPath)
// 	if err == nil {
// 		return fmt.Errorf("unit file already exists: %s", unitPath)
// 	}

// 	f, err := os.OpenFile(unitPath, os.O_WRONLY|os.O_CREATE, 0644)
// 	if err != nil {
// 		return err
// 	}
// 	defer f.Close()

// 	_, err = f.Write([]byte(s.content))
// 	if err != nil {
// 		return err
// 	}

// 	if _, err = s.run("daemon-reload"); err != nil {
// 		return fmt.Errorf("failed to reload system systemd: %v", err)
// 	}

// 	if _, err = s.runAction("enable"); err != nil {
// 		return err
// 	}

// 	if s.IsUserUnit && s.enableLingering {
// 		if err := s.setLingering(true); err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

// func (s *SystemCTL) uninstallSystemSystemd() error {
// 	if _, err := s.runAction("stop"); err != nil {
// 		fmt.Printf("Warning: Failed to stop service: %v\n", err)
// 		// 继续执行，不要返回错误
// 	}

// 	if _, err := s.runAction("disable"); err != nil {
// 		fmt.Printf("Warning: Failed to disable service: %v\n", err)
// 		// 继续执行，不要返回错误
// 	}

// 	unitPath := s.unitPath()
// 	if unitPath == "" {
// 		return fmt.Errorf("failed to get unit path")
// 	}

// 	if err := os.Remove(unitPath); err != nil {
// 		if !os.IsNotExist(err) {
// 			fmt.Printf("Warning: Failed to remove unit file: %v\n", err)
// 		}
// 		// 继续执行，不要返回错误
// 	}

// 	if _, err := s.run("daemon-reload"); err != nil {
// 		fmt.Printf("Warning: Failed to reload systemd: %v\n", err)
// 		// 继续执行，不要返回错误
// 	}

// 	if s.IsUserUnit && s.enableLingering {
// 		if err := s.setLingering(false); err != nil {
// 			fmt.Printf("Warning: Failed to disable lingering: %v\n", err)
// 			// 继续执行，不要返回错误
// 		}
// 	}

// 	fmt.Println("Service uninstallation completed with warnings")
// 	return nil
// }

// func (s *SystemCTL) unitPath() string {
// 	if s.IsUserUnit {
// 		homeDir, err := os.UserHomeDir()
// 		if err != nil {
// 			return ""
// 		}
// 		return filepath.Join(homeDir, ".config", "systemd", "user", s.unitName())
// 	}
// 	return "/etc/systemd/system/" + s.unitName()
// }

// func (s *SystemCTL) unitName() string {
// 	return s.Name + ".service"
// }

func (s *SystemCTL) run(args ...string) (string, error) {
	var cmd *exec.Cmd
	if s.IsUserUnit {
		args = append([]string{"--user"}, args...)

		// 获取当前用户
		_, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("failed to get current user: %v", err)
		}

		// 设置 DBUS_SESSION_BUS_ADDRESS 环境变量
		uid := os.Getuid()
		dbusAddr := fmt.Sprintf("unix:path=/run/user/%d/bus", uid)
		os.Setenv("DBUS_SESSION_BUS_ADDRESS", dbusAddr)

		cmd = exec.Command("systemctl", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(os.Getgid()),
			},
		}

		fmt.Printf("Running user command: %s\n", cmd.String())
		fmt.Printf("DBUS_SESSION_BUS_ADDRESS: %s\n", dbusAddr)
	} else {
		cmd = exec.Command("systemctl", args...)
		fmt.Printf("Running system command: %s\n", cmd.String())
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command failed: %v, output: %s", err, out.String())
	}
	return out.String(), nil
}

func (s *SystemCTL) runAction(action string) (string, error) {
	var cmd *exec.Cmd
	if s.IsUserUnit {
		cmd = exec.Command("systemctl", "--user", action, s.Name)
	} else {
		cmd = exec.Command("sudo", "systemctl", action, s.Name)
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *SystemCTL) runUserCommand(args ...string) error {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	cmd.Env = append(os.Environ(), s.getDBusEnv())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("user command failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (s *SystemCTL) runUserCommandOutput(args ...string) (string, error) {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	cmd.Env = append(os.Environ(), s.getDBusEnv())
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// func (s *SystemCTL) runSystemCommand(args ...string) error {
// 	cmd := exec.Command("sudo", append([]string{"systemctl"}, args...)...)
// 	output, err := cmd.CombinedOutput()
// 	if err != nil {
// 		return fmt.Errorf("system command failed: %v, output: %s", err, string(output))
// 	}
// 	return nil
// }

func (s *SystemCTL) runSystemCommand(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("system command failed: %v, output: %s", err, string(output))
	}
	return nil
}

// func (s *SystemCTL) runSystemCommandOutput(args ...string) (string, error) {
// 	cmd := exec.Command("sudo", append([]string{"systemctl"}, args...)...)
// 	output, err := cmd.CombinedOutput()
// 	return string(output), err
// }

func (s *SystemCTL) runSystemCommandOutput(args ...string) (string, error) {
	cmd := exec.Command("systemctl", args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *SystemCTL) getDBusEnv() string {
	uid := os.Getuid()
	return fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%d/bus", uid)
}

// func (s *SystemCTL) setLingering(enable bool) error {
// 	if !s.IsUserUnit {
// 		return nil // 只有用户单元需要设置 lingering
// 	}

// 	user, err := user.Current()
// 	if err != nil {
// 		return fmt.Errorf("failed to get current user: %v", err)
// 	}

// 	action := "enable"
// 	if !enable {
// 		action = "disable"
// 	}

// 	cmd := exec.Command("loginctl", action+"-linger", user.UserName)

// 	// 设置命令以当前用户的权限运行
// 	cmd.SysProcAttr = &syscall.SysProcAttr{
// 		Credential: &syscall.Credential{
// 			Uid: uint32(os.Getuid()),
// 			Gid: uint32(os.Getgid()),
// 		},
// 	}

// 	output, err := cmd.CombinedOutput()
// 	if err != nil {
// 		return fmt.Errorf("failed to %s lingering: %v, output: %s", action, err, string(output))
// 	}

// 	fmt.Printf("Successfully %sd lingering for user %s\n", action, user.UserName)
// 	return nil
// }
