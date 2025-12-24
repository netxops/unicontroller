package sup

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/structs/sup"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/pkg/errors"
)

func (stackup *Stackup) createCliCmd(e *terminal.Execute, cmd *sup.Command, env string) ([]*terminalmode.Command, error) {
	// var tasks []*Task
	var cmdList []*terminalmode.Command

	cwd, err := os.Getwd()
	if err != nil {
		return nil, errors.Wrap(err, "resolving CWD failed")
	}
	dp := cwd
	if stackup.LocalDataPath != "" {
		dp = stackup.LocalDataPath
	}

	// Anything to upload?
	for _, upload := range cmd.Upload {
		uploadFile := filepath.Join(dp, *upload.Src)
		// uploadFile, err := ResolveLocalPath(dp, *upload.Src, env)
		// if err != nil {
		// 	return nil, errors.Wrap(err, "upload: "+*upload.Src)
		// }

		c := terminalmode.NewFileUploadCommand(uploadFile, *upload.Dst, upload.Timeout, upload.Name)
		cmdList = append(cmdList, c)
	}

	// Script. Read the file as a multiline input command.
	if cmd.Script != nil && *cmd.Script != "" {
		scriptContent := *cmd.Script
		// Create a temporary directory
		tempDir, err := ioutil.TempDir("", "sup_script")
		if err != nil {
			return nil, errors.Wrap(err, "failed to create temporary directory")
		}
		// defer os.RemoveAll(tempDir) // Clean up the temporary directory when done

		// Generate a unique file name
		fileName := fmt.Sprintf("script_%s.sh", uuid.New().String())
		localFilePath := filepath.Join(tempDir, fileName)
		remoteFilePath := fmt.Sprintf("/tmp/%s", fileName)

		// Write the script content to the temporary file
		err = ioutil.WriteFile(localFilePath, []byte(scriptContent), 0644)
		if err != nil {
			return nil, errors.Wrap(err, "failed to write script to temporary file")
		}

		c := &terminalmode.Command{
			Command:           fmt.Sprintf("bash %s", remoteFilePath),
			Timeout:           cmd.Timeout,
			Name:              cmd.Name,
			IsScriptExecution: true,
			LocalScriptPath:   localFilePath,
			RemoteScriptPath:  remoteFilePath,
		}

		cmdList = append(cmdList, c)
	}

	// Remote command.
	if cmd.Run != nil && *cmd.Run != "" {
		c := terminalmode.NewCommand(env+*cmd.Run, "", cmd.Timeout, cmd.Name, "")

		// c := terminalmode.NewCommand(env+*cmd.Run, "", cmd.Timeout, cmd.Name, "")
		// c.WithNoShell(true)
		cmdList = append(cmdList, c)
	}

	// return tasks, nil
	return cmdList, nil
}

// func (stackup *Stackup) createCliCmd(e *terminal.Execute, cmd *sup.Command, env string) ([]*terminalmode.Command, error) {
// 	// var tasks []*Task
// 	var cmdList []*terminalmode.Command

// 	cwd, err := os.Getwd()
// 	if err != nil {
// 		return nil, errors.Wrap(err, "resolving CWD failed")
// 	}
// 	dp := cwd
// 	if stackup.LocalDataPath != "" {
// 		dp = stackup.LocalDataPath
// 	}

// 	// Anything to upload?
// 	for _, upload := range cmd.Upload {
// 		uploadFile, err := ResolveLocalPath(dp, *upload.Src, env)
// 		if err != nil {
// 			return nil, errors.Wrap(err, "upload: "+*upload.Src)
// 		}
// 		uploadTarReader, err := e.NewTarStreamReader(dp, uploadFile, upload.Exc)
// 		if err != nil {
// 			return nil, errors.Wrap(err, "upload: "+*upload.Src)
// 		}

// 		c := terminalmode.NewCommand(e.RemoteTarCommand(*upload.Dst), "", upload.Timeout, upload.Name, "")
// 		c.WithInput(uploadTarReader)
// 		cmdList = append(cmdList, c)

// 		// task := Task{
// 		// Name:   fmt.Sprintf("%s.upload%d", cmd.Name, index),
// 		// Run:    RemoteTarCommand(upload.Dst),
// 		// Input:  uploadTarReader,
// 		// TTY:    false,
// 		// Client: client,
// 		// }
// 		//
// 		// tasks = append(tasks, &task)
// 	}

// 	// Script. Read the file as a multiline input command.
// 	if cmd.Script != nil && *cmd.Script != "" {
// 		f, err := os.Open(path.Join(stackup.LocalDataPath, *cmd.Script))
// 		if err != nil {
// 			return nil, errors.Wrap(err, "can't open script")
// 		}
// 		data, err := ioutil.ReadAll(f)
// 		if err != nil {
// 			return nil, errors.Wrap(err, "can't read script")
// 		}

// 		c := terminalmode.NewCommand(env+string(data), "", cmd.Timeout, cmd.Name, "")
// 		c.WithNoShell(true)
// 		cmdList = append(cmdList, c)

// 		// task := Task{
// 		// Name:   fmt.Sprintf("%s.script", cmd.Name),
// 		// Run:    string(data),
// 		// TTY:    true,
// 		// Client: client,
// 		// }
// 		// if stackup.debug {
// 		// task.Run = "set -x;" + task.Run
// 		// }
// 		// if cmd.Stdin {
// 		// task.Input = os.Stdin
// 		// }
// 		// if cmd.Once {
// 		// task.Clients = []Client{clients[0]}
// 		// tasks = append(tasks, &task)
// 		// } else if cmd.Serial > 0 {
// 		// for i := 0; i < len(clients); i += cmd.Serial {
// 		// j := i + cmd.Serial
// 		// if j > len(clients) {
// 		// j = len(clients)
// 		// }
// 		// copy := task
// 		// copy.Clients = clients[i:j]
// 		// tasks = append(tasks, &copy)
// 		// }
// 		// } else {
// 		// task.Clients = clients
// 		// tasks = append(tasks, &task)
// 		// }
// 		// tasks = append(tasks, &task)
// 	}

// 	// Remote command.
// 	if cmd.Run != nil && *cmd.Run != "" {
// 		// task := Task{
// 		// Name:   fmt.Sprintf("%s.run", cmd.Name),
// 		// Run:    cmd.Run,
// 		// TTY:    true,
// 		// Client: client,
// 		// }
// 		// if stackup.debug {
// 		// task.Run = "set -x;" + task.Run
// 		// }
// 		// if cmd.Stdin {
// 		// task.Input = os.Stdin
// 		// }
// 		// tasks = append(tasks, &task)

// 		c := terminalmode.NewCommand(env+*cmd.Run, "", cmd.Timeout, cmd.Name, "")
// 		c.WithNoShell(true)
// 		cmdList = append(cmdList, c)
// 	}

// 	// return tasks, nil
// 	return cmdList, nil
// }

func (stackup *Stackup) BuildExecute(remote *structs.L2DeviceRemoteInfo, envVars *sup.EnvList, input io.Reader, output io.Writer, commands ...*sup.Command) (*terminal.Execute, []*terminalmode.Command, error) {
	var env string
	if envVars != nil && len(*envVars) > 0 {
		env = envVars.AsExport()
	}

	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
	}

	base.WithActionID(remote.ActionID)

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Linux, base)

	var cmdList []*terminalmode.Command

	for _, cmd := range commands {
		cmds, err := stackup.createCliCmd(exec, cmd, env)
		if err != nil {
			panic(err)
		}
		cmdList = append(cmdList, cmds...)
		for index, _ := range cmds {
			exec.AddCommand(cmds[index])
		}
	}

	return exec, cmdList, nil
}
