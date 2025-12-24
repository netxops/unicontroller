package sup

import (
	"fmt"
	"io"
)

// Task represents a set of commands to be run.
type Task struct {
	Name   string
	Run    string
	Input  io.Reader
	Client Client
	// Clients []Client
	TTY bool
}

// func (stackup *Stackup) createOneClientTasks(cmd *sup.Command, client Client, env string) ([]*Task, error) {
// var tasks []*Task
//
// cwd, err := os.Getwd()
// if err != nil {
// return nil, errors.Wrap(err, "resolving CWD failed")
// }
// dp := cwd
// if stackup.LocalDataPath != "" {
// dp = stackup.LocalDataPath
// }
//
// Anything to upload?
// for index, upload := range cmd.Upload {
// uploadFile, err := ResolveLocalPath(dp, *upload.Src, env)
// if err != nil {
// return nil, errors.Wrap(err, "upload: "+*upload.Src)
// }
// uploadTarReader, err := terminal.NewTarStreamReader(dp, uploadFile, upload.Exc)
// if err != nil {
// return nil, errors.Wrap(err, "upload: "+*upload.Src)
// }
//
// task := Task{
// Name:   fmt.Sprintf("%s.upload%d", cmd.Name, index),
// Run:    terminal.RemoteTarCommand(*upload.Dst),
// Input:  uploadTarReader,
// TTY:    false,
// Client: client,
// }
//
// tasks = append(tasks, &task)
// }
//
// Script. Read the file as a multiline input command.
// if cmd.Script != nil && *cmd.Script != "" {
// f, err := os.Open(path.Join(stackup.LocalDataPath, *cmd.Script))
// if err != nil {
// return nil, errors.Wrap(err, "can't open script")
// }
// data, err := ioutil.ReadAll(f)
// if err != nil {
// return nil, errors.Wrap(err, "can't read script")
// }
//
// task := Task{
// Name:   fmt.Sprintf("%s.script", cmd.Name),
// Run:    string(data),
// TTY:    true,
// Client: client,
// }
// if stackup.debug {
// task.Run = "set -x;" + task.Run
// }
// if cmd.Stdin {
// task.Input = os.Stdin
// }
// tasks = append(tasks, &task)
// }
//
// Remote command.
// if cmd.Run != nil && *cmd.Run != "" {
// task := Task{
// Name:   fmt.Sprintf("%s.run", cmd.Name),
// Run:    *cmd.Run,
// TTY:    true,
// Client: client,
// }
// if stackup.debug {
// task.Run = "set -x;" + task.Run
// }
// if cmd.Stdin {
// task.Input = os.Stdin
// }
// tasks = append(tasks, &task)
// }
//
// return tasks, nil
// }
type ErrTask struct {
	Task   *Task
	Reason string
}

func (e ErrTask) Error() string {
	return fmt.Sprintf(`Run("%v"): %v`, e.Task, e.Reason)
}
