package logfile

// import (
// 	"bufio"
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"os"
// 	"sync"
// 	"time"

// 	"github.com/fsnotify/fsnotify"
// 	"github.com/influxdata/telegraf/controller/pb/controller"
// 	"github.com/vjeantet/grok"
// 	"google.golang.org/grpc"
// )

// type LogFile struct {
// 	FilePath    string
// 	GrokPattern string
// }

// type LogManagerSrv struct {
// 	logFiles     []LogFile
// 	grokParser   *grok.Grok
// 	client       controller.LogManagerServiceClient
// 	watcher      *fsnotify.Watcher
// 	watcherMutex sync.Mutex
// }

// func NewLogManagerSrv(controllerAddr string) (*LogManagerSrv, error) {
// 	g, err := grok.New()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create grok parser: %v", err)
// 	}

// 	conn, err := grpc.Dial(controllerAddr, grpc.WithInsecure())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to connect to controller: %v", err)
// 	}

// 	client := controller.NewLogManagerServiceClient(conn)

// 	watcher, err := fsnotify.NewWatcher()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create file watcher: %v", err)
// 	}

// 	return &LogManagerSrv{
// 		grokParser: g,
// 		client:     client,
// 		watcher:    watcher,
// 	}, nil
// }

// func (lm *LogManagerSrv) AddLogFile(filePath, grokPattern string) error {
// 	lm.logFiles = append(lm.logFiles, LogFile{FilePath: filePath, GrokPattern: grokPattern})

// 	lm.watcherMutex.Lock()
// 	defer lm.watcherMutex.Unlock()

// 	if err := lm.watcher.Add(filePath); err != nil {
// 		return fmt.Errorf("failed to add file to watcher: %v", err)
// 	}

// 	return nil
// }

// func (lm *LogManagerSrv) parseAndForward(logFile LogFile) error {
// 	file, err := os.Open(logFile.FilePath)
// 	if err != nil {
// 		return fmt.Errorf("failed to open file: %v", err)
// 	}
// 	defer file.Close()

// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		parsed, err := lm.grokParser.Parse(logFile.GrokPattern, line)
// 		if err != nil {
// 			fmt.Printf("Failed to parse line in %s: %v\n", logFile.FilePath, err)
// 			continue
// 		}

// 		logEntry := &controller.LogEntry{
// 			Timestamp: time.Now().UnixNano(),
// 			Data:      parsed,
// 		}

// 		jsonData, err := json.Marshal(logEntry)
// 		if err != nil {
// 			fmt.Printf("Failed to marshal log entry from %s: %v\n", logFile.FilePath, err)
// 			continue
// 		}

// 		_, err = lm.client.ForwardLogs(context.Background(), &controller.LogEntry{
// 			Timestamp: logEntry.Timestamp,
// 			Data:      string(jsonData),
// 		})
// 		if err != nil {
// 			fmt.Printf("Failed to forward log from %s: %v\n", logFile.FilePath, err)
// 		}
// 	}

// 	if err := scanner.Err(); err != nil {
// 		return fmt.Errorf("error reading file %s: %v", logFile.FilePath, err)
// 	}

// 	return nil
// }

// func (lm *LogManagerSrv) Start() {
// 	go lm.watchFiles()

// 	for _, logFile := range lm.logFiles {
// 		go func(lf LogFile) {
// 			for {
// 				err := lm.parseAndForward(lf)
// 				if err != nil {
// 					fmt.Printf("Error in parse and forward for %s: %v\n", lf.FilePath, err)
// 				}
// 				time.Sleep(5 * time.Second) // Wait before trying again
// 			}
// 		}(logFile)
// 	}
// }

// func (lm *LogManagerSrv) watchFiles() {
// 	for {
// 		select {
// 		case event, ok := <-lm.watcher.Events:
// 			if !ok {
// 				return
// 			}
// 			if event.Op&fsnotify.Write == fsnotify.Write {
// 				for _, logFile := range lm.logFiles {
// 					if logFile.FilePath == event.Name {
// 						go lm.parseAndForward(logFile)
// 					}
// 				}
// 			}
// 		case err, ok := <-lm.watcher.Errors:
// 			if !ok {
// 				return
// 			}
// 			fmt.Printf("Error watching files: %v\n", err)
// 		}
// 	}
// }

// func (lm *LogManagerSrv) Stop() {
// 	lm.watcher.Close()
// }
