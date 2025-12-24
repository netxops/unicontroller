package sup

import "fmt"

func (s *SupConfig) addCommands(command *Command) {
	s.Commands = append(s.Commands, command)
}

func (s *SupConfig) RunCommand(name, cmd, desc string) (err error) {
	if name == "" || cmd == "" {
		return fmt.Errorf("命令或命令名不可为空")
	}
	var c Command
	c.Name = name
	c.Desc = desc
	c.Run = &cmd
	s.addCommands(&c)
	return nil
}
func (s *SupConfig) UploadCommand(name string, urls []*Upload) (err error) {
	if name == "" {
		return fmt.Errorf("名称不可为空")
	}
	for _, v := range urls {
		if (v.Dst == nil || *v.Dst == "") && (v.Src == nil || *v.Src == "") {
			return fmt.Errorf("目标或源地址不可都为空")
		}
	}
	var c Command
	c.Upload = urls
	c.Name = name
	s.addCommands(&c)
	return nil
}

func (s *SupConfig) ScriptCommand(name, script string) (err error) {
	if name == "" || script == "" {
		return fmt.Errorf("脚本名或脚本路径不可为空")
	}
	var c Command
	c.Name = name
	c.Script = &script
	s.addCommands(&c)
	return nil
}
func (s *SupConfig) AddEnv(key, value string) {
	s.Env.Set(key, value)
}
