package task

type TaskConfig struct {
	ServiceName  string
	MethodName   string
	FuncSelector string
	ConfigRole   string
	SecretRole   string
	Oob          bool
	DataMap      map[string]string
}
