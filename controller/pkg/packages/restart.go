package packages

// type RestartManager struct {
// 	packageName string
// 	schema      *model.Schema
// 	pm          *PackageManager
// }

// func NewRestartManager(packageName string, schema *model.Schema, pm *PackageManager) *RestartManager {
// 	return &RestartManager{
// 		packageName: packageName,
// 		schema:      schema,
// 		pm:          pm,
// 	}
// }

// func (rm *RestartManager) Restart() error {
// 	switch rm.schema.RestartPolicy {
// 	case model.RestartAlways:
// 		return rm.restartAlways()
// 	case model.RestartNever:
// 		return nil
// 	// case model.RestartOnChange:
// 	// 	return rm.restartOnChange()
// 	default:
// 		return fmt.Errorf("unknown restart policy: %s", rm.schema.RestartPolicy)
// 	}
// }

// func (rm *RestartManager) restartAlways() error {
// 	return rm.pm.Restart(rm.packageName)
// }

// // func (rm *RestartManager) restartOnChange() error {
// // 	for _, observer := range rm.schema.Observers {
// // 		switch observer.Type {
// // 		case "file":
// // 			go rm.watchFile(observer.Name)
// // 		case "directory":
// // 			go rm.watchDirectory(observer.Name)
// // 		case "signal":
// // 			go rm.watchSignal(observer.Name)
// // 		default:
// // 			return fmt.Errorf("unknown observer type: %s", observer.Type)
// // 		}
// // 	}
// // 	return nil
// // }

// // func (rm *RestartManager) watchFile(filePath string) {
// // 	watcher, err := fsnotify.NewWatcher()
// // 	if err != nil {
// // 		fmt.Printf("Error creating file watcher: %v\n", err)
// // 		return
// // 	}
// // 	defer watcher.Close()

// // 	err = watcher.Add(filePath)
// // 	if err != nil {
// // 		fmt.Printf("Error adding file to watcher: %v\n", err)
// // 		return
// // 	}

// // 	for {
// // 		select {
// // 		case event, ok := <-watcher.Events:
// // 			if !ok {
// // 				return
// // 			}
// // 			if event.Op&fsnotify.Write == fsnotify.Write {
// // 				rm.pm.Restart(rm.packageName)
// // 			}
// // 		case err, ok := <-watcher.Errors:
// // 			if !ok {
// // 				return
// // 			}
// // 			fmt.Printf("Error watching file: %v\n", err)
// // 		}
// // 	}
// // }

// // func (rm *RestartManager) watchDirectory(dirPath string) {
// // 	watcher, err := fsnotify.NewWatcher()
// // 	if err != nil {
// // 		fmt.Printf("Error creating directory watcher: %v\n", err)
// // 		return
// // 	}
// // 	defer watcher.Close()

// // 	err = watcher.Add(dirPath)
// // 	if err != nil {
// // 		fmt.Printf("Error adding directory to watcher: %v\n", err)
// // 		return
// // 	}

// // 	for {
// // 		select {
// // 		case event, ok := <-watcher.Events:
// // 			if !ok {
// // 				return
// // 			}
// // 			if event.Op&fsnotify.Write == fsnotify.Write {
// // 				rm.pm.Restart(rm.packageName)
// // 			}
// // 		case err, ok := <-watcher.Errors:
// // 			if !ok {
// // 				return
// // 			}
// // 			fmt.Printf("Error watching directory: %v\n", err)
// // 		}
// // 	}
// // }

// // func (rm *RestartManager) watchSignal(signalName string) {
// // 	signal := syscall.SIGHUP
// // 	if signalName != "" {
// // 		signal = syscall.Signal(syscall.SignalNum(signalName))
// // 	}

// // 	signalChan := make(chan os.Signal, 1)
// // 	syscall.Notify(signalChan, signal)

// // 	for {
// // 		<-signalChan
// // 		rm.pm.Restart(rm.packageName)
// // 	}
// // }

// // func (rm *RestartManager) Apply() error {
// // 	// This method is called when configuration changes are applied
// // 	if rm.schema.RestartPolicy == model.RestartOnChange {
// // 		return rm.pm.Restart(rm.packageName)
// // 	}
// // 	return nil
// // }
