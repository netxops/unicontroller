package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/l2service/model"
)

// github.com/netxops/utils/tools"

type Mutual struct{}

type Auth struct {
	Username   string
	Password   string
	PublicKey  string
	PrivateKey string
	fileExist  bool
	err        error
}

func (auth *Auth) Error() error {
	err := auth.err
	auth.err = nil
	return err
}

func (auth *Auth) checkKeyFile() bool {
	if _, err := os.Stat(auth.PublicKey); os.IsNotExist(err) {
		auth.fileExist = false
		auth.err = err
		return false
	} else {
		var extension = filepath.Ext(auth.PublicKey)
		var privateKeyFile = auth.PublicKey[0 : len(auth.PublicKey)-len(extension)]
		if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
			auth.fileExist = false
			auth.err = err
			return false
		} else {
			auth.PrivateKey = privateKeyFile
		}

		return true
	}
}

type TargetWithAuth struct {
	Auth
	Host                    string
	LoginType               SshLoginType
	Mutualed                bool
	remoteHome              string
	remoteAuthorizedKeyFile string
	localHome               string
	step                    model.DeploySteps
}

func (twa *TargetWithAuth) WithHost(host string) *TargetWithAuth {
	twa.Host = host
	return twa
}

func (twa *TargetWithAuth) WithLoginType(lt SshLoginType) *TargetWithAuth {
	twa.LoginType = lt
	return twa
}

func (twa *TargetWithAuth) WithPublicKey(publicKey string) *TargetWithAuth {
	twa.PublicKey = publicKey
	if !twa.checkKeyFile() {
		panic(fmt.Sprintf("public key file check failed. public key: %s", publicKey))
	}
	return twa
}

func (twa *TargetWithAuth) WithForceMutual() *TargetWithAuth {
	if twa.checkKeyFile() {
		twa.Mutualed = true
		return twa
	} else {
		panic(twa.Error())
	}
}

func NewTargetWithAuth(username, password, host string) *TargetWithAuth {
	step := model.DeploySteps{}
	targetAuth := &TargetWithAuth{
		Auth: Auth{
			Username: username,
			Password: password,
		},
		Host:      host,
		LoginType: LOGIN_PASSWORD,
		step:      step,
	}
	return targetAuth
}

func (twa *TargetWithAuth) ClearAuthorizedOnRemote() error {
	name, err := os.Hostname()
	if err != nil {
		return err
	}

	id := fmt.Sprintf("%s@%s", twa.Username, name)

	cmd := fmt.Sprintf("sed -i '/%s/d' %s", id, twa.remoteAuthorizedKeyFile)

	// fmt.Println("clear:------------>", cmd)
	if twa.Mutualed && twa.LoginType == LOGIN_MUTUAL {
		baseCmd, err := twa.makeBaseSshCmd()
		if err != nil {
			return err
		}
		_, err = BaseexecuteCMD(baseCmd+cmd, 1)
		// fmt.Println("------------>", baseCmd+cmd)
		if err != nil {
			return err
		}

		// fmt.Println(string(byteS))
		twa.Mutualed = false
	}

	return nil
}

type CmdType int

const (
	SSH_CHECK_LOGIN CmdType = iota
)

func (twa *TargetWithAuth) MakeCommand(ct CmdType) (string, error) {
	var cmd string
	var err error
	switch ct {
	case SSH_CHECK_LOGIN:
		cmd, err = twa.makeCheckSshLogin()
	}

	return cmd, err
}

type SshLoginType int

const (
	LOGIN_NONE SshLoginType = iota
	LOGIN_PASSWORD
	LOGIN_MUTUAL
)

func (twa *TargetWithAuth) mutual() bool {
	if twa.LoginType != LOGIN_MUTUAL {
		return false
	}

	if twa.Mutualed {
		return true
	}
	//
	_, err := twa.CheckSshLogin()
	if err == nil {
		twa.WithForceMutual()
		return true
	}

	_, err = twa.copyKeyFile()
	if err == nil {
		twa.WithForceMutual()
	} else {
		twa.err = err
	}

	time.Sleep(1 * time.Second)
	_, err = twa.CheckSshLogin()
	if err == nil {
		return true
	}

	return false
}

func (twa *TargetWithAuth) copyKeyFile() (string, error) {
	if !twa.Mutualed && twa.LoginType == LOGIN_MUTUAL {
		cmd := fmt.Sprintf("sshpass -p '%s' ssh-copy-id -o StrictHostKeyChecking=no -i %s %s@%s", twa.Password, twa.PublicKey, twa.Username, twa.Host)
		//fmt.Println("copy key file: ", cmd)
		timeout := 2
		// ctx, _ := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)

		byteS, err := BaseexecuteCMD(cmd, timeout)
		//fmt.Println("copyKey output:", string(byteS), err)
		return string(byteS), err
	}
	return "", nil

}

func (twa *TargetWithAuth) makeBaseSshCmd() (string, error) {
	var cmd string
	if twa.LoginType == LOGIN_NONE {
		return cmd, NoLoginType
	}
	if twa.LoginType == LOGIN_PASSWORD {
		cmd = fmt.Sprintf("sshpass -p '%s' ssh -o StrictHostKeyChecking=no %s@%s ", twa.Password, twa.Username, twa.Host)
	} else if twa.LoginType == LOGIN_MUTUAL {
		cmd = fmt.Sprintf("ssh -o StrictHostKeyChecking=no -i %s %s@%s ", twa.PrivateKey, twa.Username, twa.Host)
	}

	return cmd, nil
}

func (twa *TargetWithAuth) makeCheckSshLogin() (string, error) {
	cmd, err := twa.makeBaseSshCmd()
	if err != nil {
		return "", err
	}

	cmds := []string{
		"PWD=`pwd`",
		"USER=`whoami`",
		`if test -e $PWD/.ssh/authorized_keys; then`,
		`echo '{"home": "'$PWD'", "user": "'$USER'", "key": "'$PWD/.ssh/authorized_keys'"}'`,
		`else`,
		`echo '{"home": "'$PWD'", "user": "'$USER'"}'`,
		`fi`,
		"END",
	}
	return cmd + "'bash -s' <<'END'\n" + strings.Join(cmds, "\n"), nil

}

func (twa *TargetWithAuth) makeExecuteCmd(cmds []string) (string, error) {
	cmd, err := twa.makeBaseSshCmd()
	if err != nil {
		return cmd, err
	}
	return cmd + "'bash -s' <<'END'\n" + strings.Join(cmds, "\n") + "\nEND", nil
}

func (twa *TargetWithAuth) CheckSshLogin() (string, error) {
	cmd, err := twa.makeCheckSshLogin()
	if err != nil {
		return "", err
	}

	timeout := 1
	//fmt.Println("ssh login check: cmd", cmd)
	// ctx, _ := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	byteS, err := BaseexecuteCMD(cmd, timeout)
	m := map[string]string{}
	json.Unmarshal(byteS, &m)
	//fmt.Println("ssh login check: result map: ", m)
	if twa.Mutualed {
		if m["key"] == "" {
			return "", errors.New("remote authorized_keys is check failed")
		}
	}

	// fmt.Println(m)
	twa.remoteAuthorizedKeyFile = m["key"]

	return string(byteS), err
}

func (twa *TargetWithAuth) ExecuteCmd(cmds []string, timeout int) (string, error) {
	if twa.LoginType == LOGIN_MUTUAL && !twa.Mutualed {
		twa.mutual()
	}

	cmd, err := twa.makeExecuteCmd(cmds)
	if err != nil {
		return cmd, err
	}
	twa.step.StepCommand = cmd
	fmt.Println(cmd)
	byteS, err := BaseexecuteCMD(cmd, timeout)
	return string(byteS), err

}

func (twa *TargetWithAuth) KillProcess(process string) (string, error) {
	//cmds := []string{
	//fmt.Sprintf("ps -e -o pid,comm | egrep %s | awk '{print $1}' | xargs kill -9 ", process),
	//}
	cmds := []string{
		fmt.Sprintf("COUNT=$(ps -C %s --no-header | wc -l) && bash -c 'if [ $COUNT -gt 0 ]; then ps -e -o pid,comm | egrep %s | awk \"{print $1}\" | xargs kill -9; fi'", process, process),
	}
	return twa.ExecuteCmd(cmds, 5)
}

// func (twa *TargetWithAuth) CopyFileToRemote(probe_id uint, df DeployFile) error {
// 	twa.step = model.DeploySteps{}
// 	sshCmd := fmt.Sprintf("sshpass -p '%s' ", twa.Password)
// 	loc_path, tar_name, dir_path := df.Source(), df.TarName(), df.TargetPath()
// 	cmd := fmt.Sprintf("scp -p .%s%s %s@%s:~%s/", loc_path, tar_name, twa.Username, twa.Host, dir_path)
// 	cmds := sshCmd + cmd

// 	fmt.Println(cmds)
// 	byteS, err := BaseexecuteCMD(cmds, 10)
// 	twa.step.Step = 3
// 	twa.step.Name = "CopyFileToRemote"
// 	twa.step.StepCommand = cmd
// 	if err_cp := twa.creatStep(probe_id, string(byteS), err); err_cp != nil {
// 		return err_cp
// 	}
// 	return err
// }

// func (twa *TargetWithAuth) ProbeEditKillProcess(probe_id uint, df DeployFile) error {
// 	twa.step = model.DeploySteps{}
// 	out, err := twa.KillProcess(df.MainFileName())
// 	twa.step.Step = 1
// 	twa.step.Name = "ProbeEditKillProcess"
// 	if err_step := twa.creatStep(probe_id, out, err); err_step != nil {
// 		return err_step
// 	}
// 	return err
// }

// func (twa *TargetWithAuth) creatStep(id uint, out string, err error) error {
// 	var probe model.Probe
// 	err_probe := global.GVA_DB.Find(&probe, id).Error
// 	if err_probe != nil {
// 		return err_probe
// 	}
// 	twa.step.ProbeID = int(probe.ID)
// 	twa.step.Probe = probe
// 	if err != nil {
// 		twa.step.StepStatus = 2
// 		twa.step.StepResult = fmt.Sprintf("Command Error: %v,\n%s", err, out)
// 	} else {
// 		twa.step.StepStatus = 1
// 		twa.step.StepResult = out
// 	}
// 	probe.DeployStepss = append(probe.DeployStepss, &twa.step)
// 	return global.GVA_DB.Save(&probe).Error
// }

// func (twa *TargetWithAuth) ProbeEditCheckDir(probe_id uint, df DeployFile) error {
// 	twa.step = model.DeploySteps{}
// 	dir_path := df.TargetPath()
// 	cmds := []string{
// 		fmt.Sprintf("[ -d ~%s ] && rm -rf ~%s && mkdir -p ~%s || mkdir -p ~%s", dir_path, dir_path, dir_path, dir_path),
// 	}
// 	out, err := twa.ExecuteCmd(cmds, 2)
// 	twa.step.Step = 2
// 	twa.step.Name = "ProbeEditCheckDir"
// 	if err_dir := twa.creatStep(probe_id, out, err); err_dir != nil {
// 		return err_dir
// 	}
// 	return err
// }

// func (twa *TargetWithAuth) UnzipAndExec(probe_id uint, df DeployFile) error {
// 	twa.step = model.DeploySteps{}
// 	twa.step.Step = 4
// 	twa.step.Name = "UnzipAndExec"
// 	dir_path, tar_name, main_name := df.TargetPath(), df.TarName(), df.MainFileName()
// 	cmds := []string{
// 		fmt.Sprintf("cd ~%s && tar zxvf %s && cd ~%s/%s && ./%s start", dir_path, tar_name, dir_path, main_name, main_name),
// 	}
// 	out, err := twa.ExecuteCmd(cmds, 10)
// 	if err_uae := twa.creatStep(probe_id, out, err); err_uae != nil {
// 		return err_uae
// 	}
// 	return err
// }

// func (twa *TargetWithAuth) CheckRemoteProcess(probe_id uint, df DeployFile) error {
// 	twa.step = model.DeploySteps{}
// 	twa.step.Step = 5
// 	twa.step.Name = "CheckRemoteProcess"
// 	process := df.MainFileName()
// 	cmds := []string{
// 		fmt.Sprintf("COUNT=$(ps -C %s --no-header | wc -l) && bash -c \"if [ $COUNT -gt 0 ]; then echo '%s is going'; else echo '%s is not going'; fi\"", process, process, process),
// 	}
// 	out, err := twa.ExecuteCmd(cmds, 2)
// 	if err_ch := twa.creatStep(probe_id, out, err); err_ch != nil {
// 		return err_ch
// 	}
// 	return err
// }

// func (twa *TargetWithAuth) PluginMakeDir(Probe *model.Probe, dir_path string, main_name string) error {
// 	twa.step = model.DeploySteps{}
// 	cmds := []string{
// 		fmt.Sprintf("[ -d ~%s/%s/plugins ] && echo '~%s/%s/plugins exists' || mkdir -p ~%s/%s/plugins/", dir_path, main_name, dir_path, main_name, dir_path, main_name),
// 	}
// 	out, err := twa.ExecuteCmd(cmds, 2)
// 	twa.step.Step = 1
// 	twa.step.StepType = 1
// 	if err_dir := twa.creatStep(Probe.ID, out, err); err_dir != nil {
// 		return err_dir
// 	}
// 	return err
// }

// func (twa *TargetWithAuth) PluginCopyFile(Probe *model.Probe, tar_name string, dirpath string, main_name string) error {
// 	twa.step = model.DeploySteps{}
// 	sshCmd := fmt.Sprintf("sshpass -p '%s' ", twa.Password)
// 	file_name_slice := strings.Split(tar_name, ".")
// 	file_suffix := file_name_slice[0]
// 	cmd := fmt.Sprintf("scp -p ./resource/plugin_file/%s/%s %s@%s:~%s/%s/plugins/", file_suffix, tar_name, Probe.User, Probe.Ip, dirpath, main_name)
// 	cmds := sshCmd + cmd
// 	fmt.Println(cmds)
// 	out, err := BaseexecuteCMD(cmds, 10)
// 	twa.step.Name = "CopyFileToRemote"
// 	twa.step.StepCommand = cmd
// 	twa.step.Step = 2
// 	twa.step.StepType = 1
// 	if err_dir := twa.creatStep(Probe.ID, string(out), err); err_dir != nil {
// 		return err_dir
// 	}
// 	return err
// }

// func (twa *TargetWithAuth) PluginUnzipAndRm(Probe *model.Probe, dir_path string, main_name string, tar_name string) error {
// 	twa.step = model.DeploySteps{}
// 	cmds := []string{
// 		fmt.Sprintf("cd ~%s/%s/plugins/ && tar zxvf %s && rm -r %s pluginDescribe.yaml", dir_path, main_name, tar_name, tar_name),
// 	}
// 	out, err := twa.ExecuteCmd(cmds, 2)
// 	twa.step.Step = 3
// 	twa.step.StepType = 1
// 	if err_dir := twa.creatStep(Probe.ID, out, err); err_dir != nil {
// 		return err_dir
// 	}
// 	return err
// }

func Doclient() {
	newcurrentUser, _ := user.Current()
	targetAuth := &TargetWithAuth{
		Auth: Auth{
			Username:  "asialink",
			Password:  "Admin@123",
			PublicKey: newcurrentUser.HomeDir + "/.ssh/id_rsa.pub",
		},
		Host:      "192.168.100.120",
		LoginType: LOGIN_PASSWORD,
	}

	output, err := targetAuth.ExecuteCmd([]string{"ping 192.168.100.122 -c 2"}, 1)
	//time.Sleep(5 * time.Second)
	fmt.Println("====err", err)
	fmt.Println("===out", output)

	// output, err := targetAuth.ExecuteCmd([]string{"ls", "cd /media", "ls"}, 2)
	// fmt.Println(output)
	//output, err := targetAuth.KillProcess("ping")
	//if err != nil {
	//	fmt.Printf("output: %s, err: %s", output, err)
	//	//t.Error(fmt.Sprintf("output: %s, err: %s", output, err))
	//}
	//
	//fmt.Println(output)
}
