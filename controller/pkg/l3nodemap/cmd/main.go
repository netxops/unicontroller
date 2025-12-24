package cmd

// "github.com/douyu/jupiter/pkg/hooks"

// func main() {
// 	l3 := initialize.L3{}
// 	Logger := global.GetLogger()

// 	Logger.Info("======= l3service starting ..... ========")
// 	eng := engine.NewEngine()
// 	// eng.RegisterHooks(hooks.Stage_AfterStop, func() {
// 	// 	Logger.Info("exit jupiter app ...")
// 	// })
// 	var once = sync.Once{}
// 	once.Do(func() {
// 		l3.Initialization()
// 	})

// 	if err := eng.Run(); err != nil {
// 		Logger.Fatal("======= l3 engine.Run failed =======", zap.Error(err))
// 	}
// }
