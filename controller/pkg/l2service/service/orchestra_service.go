package service

// import (
// 	"fmt"
// 	"regexp"
// 	"strings"
// 	"sync"
// 	"time"

// 	"github.com/gosuri/uiprogress"
// 	"github.com/influxdata/telegraf/controller/pkg/structs"
// 	"github.com/netxops/orchestra/task"
// 	clitask "github.com/netxops/utils/task"
// 	"github.com/urfave/cli"

// 	"context"

// 	"github.com/netxops/l2service/internal/app/service/orchestra"
// 	"github.com/netxops/orchestra/client"
// 	"github.com/netxops/orchestra/minion"
// 	"github.com/pborman/uuid"
// 	"go.uber.org/zap"
// )

// var orch *ORCHESTRASERVICE
// var once sync.Once

// type ORCHESTRASERVICE struct {
// 	m minion.Minion
// }

// func (o *ORCHESTRASERVICE) Close() error {
// 	if orch != nil {
// 		return orch.m.Stop()
// 	}

// 	return nil
// }

// func NewOrchService(endPoint, siteRepo string) (*ORCHESTRASERVICE, error) {
// 	once.Do(
// 		func() {
// 			m, err := orchestra.NewOrchestra(endPoint, siteRepo)
// 			if err != nil {
// 				orchLogger.Error("初始化orchestra失败, ", zap.Error(err))
// 				return
// 			}

// 			orch = &ORCHESTRASERVICE{m: m}
// 			go func() {
// 				m.Serve()
// 			}()
// 		})

// 	return orch, nil
// }

// func parseClassifierPattern(klient client.Client, pattern string) ([]uuid.UUID, error) {
// 	// If no classifier pattern provided,
// 	// return all registered minions
// 	if pattern == "" {
// 		return klient.MinionList()
// 	}

// 	data := strings.SplitN(pattern, "=", 2)
// 	key := data[0]

// 	// If only a classifier key is provided, return all
// 	// minions which contain the given classifier key
// 	if len(data) == 1 {
// 		return klient.MinionWithClassifierKey(key)
// 	}

// 	toMatch := data[1]
// 	re, err := regexp.Compile(toMatch)
// 	if err != nil {
// 		return nil, err
// 	}

// 	minions, err := klient.MinionWithClassifierKey(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var result []uuid.UUID
// 	for _, minion := range minions {
// 		klassifier, err := klient.MinionClassifier(minion, key)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if re.MatchString(klassifier.Value) {
// 			result = append(result, minion)
// 		}
// 	}

// 	return result, nil
// }

// var orchLogger *zap.Logger

// func init() {
// 	orchLogger, _ = zap.NewDevelopment(zap.AddCallerSkip(1))
// }

// func (o *ORCHESTRASERVICE) OrcheStraPush(ctx context.Context, args *structs.OrchArgs, reply *structs.OrchReply) error {
// 	fmt.Println("31111111")
// 	// Create the task that we send to our minions
// 	// The task's command is the module name that will be
// 	// loaded and processed by the remote minions
// 	luaPath := args.LuaPath
// 	if luaPath == "" {
// 		return fmt.Errorf("lua地址未空")
// 	}
// 	t := task.New(luaPath, "production")

// 	orcClient := orchestra.NewEtcdMinionClientFromFlags(args.EndPoint)

// 	cFlag := ""
// 	minions, err := parseClassifierPattern(orcClient, cFlag)

// 	if err != nil {
// 		return cli.NewExitError(err.Error(), 1)
// 	}

// 	numMinions := len(minions)
// 	if numMinions == 0 {
// 		return fmt.Errorf("未知错误")
// 	}

// 	fmt.Printf("Found %d minion(s) for task processing\n\n", numMinions)

// 	// Progress bar to display while submitting task
// 	progress := uiprogress.New()
// 	bar := progress.AddBar(numMinions)
// 	bar.AppendCompleted()
// 	bar.PrependElapsed()
// 	progress.Start()

// 	// Number of minions to which submitting the task has failed
// 	failed := 0

// 	// Submit task to minions
// 	fmt.Println("Submitting task to minion(s) ...")
// 	for _, m := range minions {
// 		err = orcClient.MinionSubmitTask(m, t)
// 		if err != nil {
// 			fmt.Printf("Failed to submit task to %s: %s\n", m, err)
// 			failed++
// 		}
// 		bar.Incr()
// 	}

// 	// Stop progress bar and sleep for a bit to make sure the
// 	// progress bar gets updated if we were too fast for it
// 	progress.Stop()
// 	time.Sleep(time.Millisecond * 100)

// 	// Display task report
// 	result := clitask.NewEmptyTableWithKeys([]string{"TASK", "SUBMITTED", "FAILED", "TOTAL"})
// 	// table := uitable.New()
// 	// table.MaxColWidth = 80
// 	// table.Wrap = true
// 	// table.AddRow("TASK", "SUBMITTED", "FAILED", "TOTAL")
// 	// table.AddRow(t.ID, numMinions-failed, failed, numMinions)
// 	// fmt.Println("---", table)
// 	data := make(map[string]string)
// 	data["TASK"] = fmt.Sprintf("%s", t.ID)
// 	data["SUBMITTED"] = fmt.Sprintf("%d", numMinions-failed)
// 	data["FAILED"] = fmt.Sprintf("%d", failed)
// 	data["TOTAL"] = fmt.Sprintf("%d", numMinions)
// 	err = result.PushRow("", data, false, "")
// 	reply.Result = result.ToSliceMap()
// 	return err
// }
