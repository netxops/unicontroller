package session

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"

	//"github.com/netxops/unify/global"
	"strings"

	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"

	"go.uber.org/zap"
)

type CliSession struct {
	Session
	Info   *DeviceBaseInfo
	log    *zap.Logger
	OpType terminalmode.ModeType
}

func NewCliSession(info *DeviceBaseInfo) *CliSession {
	log := zap.NewNop()
	return &CliSession{
		Info:   info,
		log:    log,
		OpType: terminalmode.VIEW,
	}
}

func (cli *CliSession) WithModeType(opType terminalmode.ModeType) {
	cli.OpType = opType
}

func (cli *CliSession) Run(cmd *command.CliCmd) (*command.CacheData, error) {
	var cd *command.CacheData
	if !cmd.Force {
		cd, err := cli.Session.Get(cli.Info.BaseInfo.Host, cmd)
		if cd != nil {
			if !cd.IsTimeout() {
				cli.log.Info("using cache data, ", zap.Any("id", cmd.Id(cli.Info.BaseInfo.Host)))
				return cd, err
			}
		}
	}

	// devType := terminalmode.NewDeviceType(cli.Info.BaseInfo.Type)
	exec := terminal.NewExecute(cli.OpType, cli.Info.BaseInfo.Type, &cli.Info.BaseInfo)
	exec.Add(cmd.Cmd(), "", cmd.Timeout(), cmd.Key(), "")
	exec.Prepare(false)
	result := exec.Run(false)
	if result.Error() == nil {
		cmd.WithOk(true)
		if result.Ok() {
			ok, data := result.GetResult(cmd.Key())
			if ok {
				cd = command.NewCacheData([]byte(strings.Join(data, "\n")))
				cli.Session.Set(cli.Info.BaseInfo.Host, cmd, cd)
				cmd.SetCacheData(cd)
				cmd.WithMsg(string(cd.Data))
				return cd, nil
			} else {
				return cd, fmt.Errorf("get result failed, key:%s", cmd.Key())
			}
		} else {
			return cd, fmt.Errorf("unknown error, state: %s", result.State)
		}
	} else {
		cmd.WithOk(false)
		return nil, result.Error()
	}
}

// 每次执行一个command.CliCmdList
// func (cli *CliSession) BatchRun(cmds interface{}, stopOnError bool) error {
// 	cmdList := cmds.(*command.CliCmdList)
// 	exec := terminal.NewExecute(cli.OpType, cli.Info.BaseInfo.Type, &cli.Info.BaseInfo)
// 	count := 0
// 	if !cmdList.Force {
// 		for _, cmd := range cmdList.Cmds {
// 			if cmd.(*command.CliCmd).Force {
// 				exec.Add(cmd.Cmd(), "", cmd.Timeout(), cmd.Key(), "")
// 				count += 1
// 			} else {
// 				cd, err := cli.Session.Get(cli.Info.BaseInfo.Host, cmd)
// 				if err != nil || cd.IsTimeout() {
// 					exec.Add(cmd.Cmd(), "", cmd.Timeout(), cmd.Key(), "")
// 					count += 1
// 				} else {
// 					if cd != nil {
// 						cmd.SetCacheData(cd)
// 						cmd.WithMsg(string(cd.Data))
// 					} else {
// 						exec.Add(cmd.Cmd(), "", cmd.Timeout(), cmd.Key(), "")
// 						count += 1
// 					}
// 				}
// 			}
// 			cmd.WithLevel(command.MUST)
// 		}
// 	} else {
// 		for _, cmd := range cmdList.Cmds {
// 			exec.Add(cmd.Cmd(), "", cmd.Timeout(), cmd.Key(), "")
// 			count += 1
// 			cmd.WithLevel(command.MUST)
// 		}
// 	}

// 	if count > 0 {
// 		exec.Prepare(false)
// 		result := exec.Run(stopOnError)
// 		for _, fc := range exec.DeviceMode.First_Chain {
// 			c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
// 			if fc.Status == terminalmode.CMD_COMPLETED {
// 				c.WithOk(true)
// 			}
// 			c.WithMsg(fc.Msg)
// 			c.WithLevel(command.OPTION)
// 		}

// 		if result.Error() != nil {
// 			if stopOnError {
// 				return result.Error()
// 			}
// 		}

// 		if exec.OpType == terminalmode.CONFIG {
// 			// 只有在CONFIG模式下，ssh terminal才会自动执行Last_Chain中命令
// 			for _, fc := range exec.DeviceMode.Last_Chain {
// 				c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
// 				if fc.Status == terminalmode.CMD_COMPLETED {
// 					c.WithOk(true)
// 				}
// 				c.WithMsg(fc.Msg)
// 				c.WithLevel(command.OPTION)
// 			}
// 		}

// 		for _, cmd := range cmdList.Cmds {
// 			ok, data := result.GetResult(cmd.Key())
// 			cmd.WithMsg(strings.Join(data, "\n"))
// 			if ok {
// 				cd := command.NewCacheData([]byte(strings.Join(data, "\n")))
// 				// cli.Session.Set(cmd.Id(cli.Info.BaseInfo.Host), cd)
// 				cli.Session.Set(cli.Info.BaseInfo.Host, cmd, cd)
// 			} else {
// 				return fmt.Errorf("get result failed, key:%s", cmd.Key())
// 			}
// 		}
// 	}

// 	return nil
// }

func (cli *CliSession) BatchRun(cmds interface{}, stopOnError bool) error {
	cmdList := cmds.(*command.CliCmdList)
	cli.log.Info("Starting BatchRun", zap.String("host", cli.Info.BaseInfo.Host), zap.Int("commandCount", len(cmdList.Cmds)))

	exec := terminal.NewExecute(cli.OpType, cli.Info.BaseInfo.Type, &cli.Info.BaseInfo)
	count := 0
	runCommands := []*command.CliCmd{}
	if !cmdList.Force {
		// 在非强制模式下运行
		cli.log.Debug("Running in non-force mode")
		for _, cmd := range cmdList.Cmds {
			cliCmd := cmd.(*command.CliCmd)
			if cliCmd.Force {
				// 如果命令被标记为强制执行，直接添加到执行列表
				cli.log.Debug("Adding forced command", zap.String("command", cliCmd.Cmd()), zap.String("key", cliCmd.Key()))
				exec.Add(cliCmd.Cmd(), "", cliCmd.Timeout(), cliCmd.Key(), "")
				runCommands = append(runCommands, cliCmd)
				count++
			} else {
				// 尝试从缓存中获取命令结果
				cd, err := cli.Session.Get(cli.Info.BaseInfo.Host, cmd)
				if err != nil || cd.IsTimeout() {
					// 如果缓存不存在或已超时，添加命令到执行列表
					cli.log.Debug("Adding command due to cache miss or timeout", zap.String("command", cliCmd.Cmd()), zap.String("key", cliCmd.Key()), zap.Error(err))
					exec.Add(cliCmd.Cmd(), "", cliCmd.Timeout(), cliCmd.Key(), "")
					runCommands = append(runCommands, cliCmd)
					count++
				} else if cd != nil {
					// 如果缓存存在且有效，使用缓存数据
					cli.log.Debug("Using cached data", zap.String("command", cliCmd.Cmd()), zap.String("key", cliCmd.Key()))
					cliCmd.SetCacheData(cd)
					cliCmd.WithMsg(string(cd.Data))
				} else {
					// 如果没有缓存数据，添加命令到执行列表
					cli.log.Debug("Adding command due to no cache data", zap.String("command", cliCmd.Cmd()), zap.String("key", cliCmd.Key()))
					exec.Add(cliCmd.Cmd(), "", cliCmd.Timeout(), cliCmd.Key(), "")
					runCommands = append(runCommands, cliCmd)
					count++
				}
			}
			// 将所有命令标记为必须执行
			cliCmd.WithLevel(command.MUST)
		}

	} else {
		cli.log.Debug("Running in force mode")
		for _, cmd := range cmdList.Cmds {
			cliCmd := cmd.(*command.CliCmd)
			cli.log.Debug("Adding command", zap.String("command", cliCmd.Cmd()), zap.String("key", cliCmd.Key()))
			exec.Add(cliCmd.Cmd(), "", cliCmd.Timeout(), cliCmd.Key(), "")
			runCommands = append(runCommands, cliCmd)
			count++
			cliCmd.WithLevel(command.MUST)
		}
	}

	cli.log.Info("Command preparation complete", zap.Int("commandsToExecute", count))

	if count > 0 {
		// 准备执行命令
		cli.log.Debug("Preparing execution")
		exec.Prepare(false)
		cli.log.Info("Running commands")
		// 执行命令并获取结果
		result := exec.Run(stopOnError)

		// 处理First_Chain命令（通常是进入特权模式或配置模式的命令）
		cli.log.Debug("Processing First_Chain commands")
		for _, fc := range exec.DeviceMode.First_Chain {
			// 为每个First_Chain命令创建一个新的CliCmd对象
			c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
			if fc.Status == terminalmode.CMD_COMPLETED {
				c.WithOk(true) // 标记命令执行成功
			}
			c.WithMsg(fc.Msg)           // 设置命令执行的消息
			c.WithLevel(command.OPTION) // 设置命令级别为可选
			cli.log.Debug("First_Chain command processed", zap.String("command", fc.Command), zap.String("status", string(fc.Status)))
		}

		// 检查命令执行过程中是否有错误
		if result.Error() != nil {
			cli.log.Error("Error during command execution", zap.Error(result.Error()))
			if stopOnError {
				return result.Error() // 如果设置了遇错停止，则返回错误
			}
		}

		// 如果是配置模式，处理Last_Chain命令（通常是退出配置模式或保存配置的命令）
		if exec.OpType == terminalmode.CONFIG {
			cli.log.Debug("Processing Last_Chain commands for CONFIG mode")
			for _, fc := range exec.DeviceMode.Last_Chain {
				// 为每个Last_Chain命令创建一个新的CliCmd对象
				c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
				if fc.Status == terminalmode.CMD_COMPLETED {
					c.WithOk(true) // 标记命令执行成功
				}
				c.WithMsg(fc.Msg)           // 设置命令执行的消息
				c.WithLevel(command.OPTION) // 设置命令级别为可选
				cli.log.Debug("Last_Chain command processed", zap.String("command", fc.Command), zap.String("status", string(fc.Status)))
			}
		}

		cli.log.Info("Processing command results")
		// 只处理实际执行的命令
		for _, cliCmd := range runCommands {
			// 从执行结果中获取命令的输出
			ok, data := result.GetResult(cliCmd.Key())
			// 将命令的输出设置为命令的消息
			cliCmd.WithMsg(strings.Join(data, "\n"))

			if ok {
				// 如果命令执行成功
				// 创建新的缓存数据
				cd := command.NewCacheData([]byte(strings.Join(data, "\n")))
				// 将命令结果存入缓存
				cli.Session.Set(cli.Info.BaseInfo.Host, cliCmd, cd)
				// 记录成功执行的命令
				cli.log.Debug("Command executed successfully",
					zap.String("command", cliCmd.Cmd()),
					zap.String("key", cliCmd.Key()))
			} else {
				// 如果命令执行失败
				// 记录失败的命令
				cli.log.Error("Failed to get result for command",
					zap.String("command", cliCmd.Cmd()),
					zap.String("key", cliCmd.Key()))
				// 如果设置了遇到错误就停止，则返回错误
				if stopOnError {
					return fmt.Errorf("get result failed, key:%s", cliCmd.Key())
				}
				// 如果没有设置遇到错误就停止，则继续处理下一个命令
			}
		}
	} else {
		cli.log.Info("No commands to execute")
	}

	cli.log.Info("BatchRun completed successfully")
	return nil
}

func (cli *CliSession) BatchConfig(cmds interface{}, stopOnError bool) error {
	cli.WithModeType(terminalmode.CONFIG)
	return cli.BatchRun(cmds, stopOnError)
}

// func (cli *CliSession) BatchConfig(cmds interface{}, stopOnError bool) error {
// cmdList := cmds.(*command.CliCmdList)
// exec := terminal.NewExecute(terminalmode.CONFIG, cli.Info.BaseInfo.Type, &cli.Info.BaseInfo)
// count := 0
// for _, cmd := range cmdList.Cmds {
// exec.Add(cmd.Cmd(), "", cmd.Timeout(), cmd.Key(), "")
// count += 1
// cmd.WithLevel(command.MUST)
// }
//
// if count > 0 {
// Prepare的参数为false，表示需要First_Chain和Last_Chain
// exec.Prepare(false)
// result := exec.Run(stopOnError)
// for _, fc := range exec.DeviceMode.First_Chain {
// c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
// if fc.Status == terminalmode.CMD_COMPLETED {
// c.WithOk(true)
// }
// c.WithMsg(fc.Msg)
// c.WithLevel(command.OPTION)
// }
//
// if result.Error() != nil {
// if stopOnError {
// return result.Error()
// }
// }
//
// if exec.OpType == terminalmode.CONFIG {
// 只有在CONFIG模式下，ssh terminal才会自动执行Last_Chain中命令
// for _, fc := range exec.DeviceMode.Last_Chain {
// c := command.NewCliCmd(fc.Command, fc.Name, fc.Timeout, true)
// if fc.Status == terminalmode.CMD_COMPLETED {
// c.WithOk(true)
// }
// c.WithMsg(fc.Msg)
// c.WithLevel(command.OPTION)
// }
// }
//
// for _, cmd := range cmdList.Cmds {
// ok, data := result.GetResult(cmd.Key())
// cmd.WithMsg(strings.Join(data, "\n"))
// if ok {
// cd := command.NewCacheData([]byte(strings.Join(data, "\n")))
// cli.Session.Set(cli.Info.BaseInfo.Host, cmd, cd)
// } else {
// return fmt.Errorf("get result failed, key:%s", cmd.Key())
// }
// }
// }
//
// return nil
// }
