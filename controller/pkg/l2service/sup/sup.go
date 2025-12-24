package sup

import (
	"fmt"
	"io"
	"os"

	"github.com/influxdata/telegraf/controller/pkg/structs/sup"
)

const VERSION = "0.5"

type Stackup struct {
	LocalDataPath string
	conf          *sup.Supfile
	debug         bool
	prefix        bool
}

func NewFromConfg(conf *sup.SupConfig, localDataPath string) (*Stackup, error) {
	cmds := &sup.Commands{}
	for _, c := range conf.Commands {
		cmds.Set(c.Name, *c)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	if localDataPath == "" {
		localDataPath = cwd
	}

	c := sup.Supfile{
		// Commands: conf.Commands,
		Commands: *cmds,
		Targets:  conf.Targets,
		Env:      conf.Env,

		Version: conf.Version,
	}
	return &Stackup{
		LocalDataPath: localDataPath,
		conf:          &c,
		debug:         true,
	}, nil
}

func New(conf *sup.Supfile) (*Stackup, error) {
	return &Stackup{
		conf: conf,
	}, nil
}

// Run runs set of commands on multiple hosts defined by network sequentially.
// TODO: This megamoth method needs a big refactor and should be split
//
//	to multiple smaller methods.

// func (stackup *Stackup) run(remote *structs.L2DeviceRemoteInfo, envVars sup.EnvList, input io.Reader, output io.Writer, commands ...*sup.Command) (*utilsTask.ExecuteResult, []*Task) {
// result := &utilsTask.ExecuteResult{
// State:  utilsTask.EXEC_INIT,
// ErrMsg: []utilsTask.StringPair{},
// ErrCmd: []string{},
// Output: []utilsTask.StringPair{},
// }
// allTasks := []*Task{}
//
// env := envVars.AsExport()
//
// var wg sync.WaitGroup
// clientCh := make(chan Client, 1)
// errCh := make(chan error, 1)
//
// wg.Add(1)
// go func(remote *structs.L2DeviceRemoteInfo) {
// defer wg.Done()
//
// SSH client.
// rm := &SSHClient{
// env:  env + `export SUP_HOST="` + remote.Ip + `";`,
// user: remote.Username,
// }
//
// host := remote.Ip
// if remote.Password != "" {
// rm.Options(PasswordAuth(remote.Password))
// }
// if remote.PrivateKey != "" {
// rm.Options(KeyAuth(remote.PrivateKey))
// }
//
// if err := rm.Connect(host); err != nil {
// errCh <- errors.Wrap(err, "connecting to remote host failed")
// return
// }
// clientCh <- rm
// }(remote)
// wg.Wait()
// close(clientCh)
// close(errCh)
//
// client := <-clientCh
// for err := range errCh {
// result.State = utilsTask.EXEC_INIT_FAILED
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{"terminal_init", []string{err.Error()}})
// return result, allTasks
// }
//
// ip := remote.Ip
// Run command or run multiple commands defined by target sequentially.
// for _, cmd := range commands {
// tasks, err := stackup.createOneClientTasks(cmd, client, env)
// allTasks = append(allTasks, tasks...)
//
// if err != nil {
// result.State = utilsTask.EXEC_INIT_FAILED
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{"create_task", []string{err.Error()}})
// return result, allTasks
// }
//
// Run tasks sequentially.
// for _, task := range tasks {
// var writers []io.Writer
// var wg sync.WaitGroup
//
// err := task.Client.Run(task)
// if err != nil {
// result.State = utilsTask.EXEC_FAILED
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{task.Name, []string{err.Error()}})
// return result, allTasks
// }
//
// Copy over tasks's STDOUT.
// var out io.Writer
// wg.Add(1)
// go func(c Client) {
// defer wg.Done()
// s := bytes.NewBuffer([]byte{})
// out = s
// if output != nil {
// out = output
// }
//
// n, err := io.Copy(out, prefixer.New(c.Stdout(), fmt.Sprintf("|%-16s|", ip)))
// if err != nil && err != io.EOF {
// result.State = utilsTask.EXEC_FAILED
// result.ErrCmd = append(result.ErrCmd, task.Name)
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{task.Name, strings.Split(s.String(), "\r\n")})
// }
//
// if n > 0 {
// result.State = utilsTask.EXEC_SUCCESS
// result.Output = append(result.Output, utilsTask.StringPair{task.Name, strings.Split(s.String(), "\r\n")})
// }
//
// }(task.Client)
//
// Copy over tasks's STDERR.
// wg.Add(1)
// go func(c Client) {
// defer wg.Done()
// s := bytes.NewBuffer([]byte{})
// n, _ := io.Copy(s, c.Stderr())
// if err != nil && err != io.EOF {
// result.State = utilsTask.EXEC_FAILED
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{task.Name, strings.Split(s.String(), "\r\n")})
// result.ErrCmd = append(result.ErrCmd, task.Name)
// }
//
// if n > 0 {
// result.State = utilsTask.EXEC_FAILED
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{task.Name, strings.Split(s.String(), "\r\n")})
// result.Output = append(result.Output, utilsTask.StringPair{task.Name, strings.Split(s.String(), "\r\n")})
// result.ErrCmd = append(result.ErrCmd, task.Name)
// }
// }(task.Client)
//
// writers = append(writers, task.Client.Stdin())
// if task.Input != nil {
// in := task.Input
// if input != nil {
// in = input
// }
// go func() {
// writer := io.MultiWriter(writers...)
// _, err := io.Copy(writer, in)
// if err != nil && err != io.EOF {
// result.State = utilsTask.EXEC_FAILED
// result.ErrCmd = append(result.ErrCmd, task.Name)
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{task.Name, []string{"copying STDIN failed"}})
// }
// client.WriteClose()
// }()
// }
//
// trap := make(chan os.Signal, 1)
// signal.Notify(trap, os.Interrupt)
// go func() {
// for {
// select {
// case sig, ok := <-trap:
// if !ok {
// return
// }
// if err := client.Signal(sig); err != nil {
// result.State = utilsTask.EXEC_FAILED
// result.ErrCmd = append(result.ErrCmd, task.Name)
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{task.Name, []string{fmt.Sprintf("sending signal failed, err:%s", err)}})
// }
// }
// }
// }()
// wg.Wait()
//
// wg.Add(1)
// go func(c Client) {
// defer wg.Done()
// if err := c.Wait(); err != nil {
// result.State = utilsTask.EXEC_FAILED
// result.ErrCmd = append(result.ErrCmd, task.Name)
// result.ErrMsg = append(result.ErrMsg, utilsTask.StringPair{task.Name, []string{fmt.Sprintf("ssh client run failed, err:%v", err)}})
// }
// }(client)
//
// wg.Wait()
// signal.Stop(trap)
// close(trap)
// }
// }
//
// return result, allTasks
// }

func (stackup *Stackup) Debug(value bool) {
	stackup.debug = value
}

func (stackup *Stackup) Prefix(value bool) {
	stackup.prefix = value
}

func connect(dst io.Writer, src io.Reader) error {
	for {
		buf := make([]byte, 1024)
		total, err := io.ReadAtLeast(src, buf, 1)
		if err != nil && err != io.EOF {
			return err
		}
		if total == 0 {
			continue
		}

		fmt.Printf("receive: %s", string(buf[0:total]))
		count := 0
		for {
			if count >= total {
				break
			}

			n, err := io.WriteString(dst, string(buf[count:total]))
			count = count + n

			if err != nil && err != io.EOF {
				return err
			}

		}
	}
}
