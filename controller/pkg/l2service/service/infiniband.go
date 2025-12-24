package service

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/influxdata/telegraf/controller/pkg/structs/l2struct"
	"github.com/netxops/log"
	clitask "github.com/netxops/utils/task"
	"go.uber.org/zap"
)

type INFINIBAND struct{}

func getDiscover() (result *clitask.Table, err error) {
	cmd1 := exec.Command("bash", "-c", "ibdiagnet --get_cable_info")
	_, err = cmd1.Output()
	if err != nil {
		return result, fmt.Errorf("ibdiagnet 执行错误,%s", err)
	}
	cmd2 := exec.Command("bash", "-c", "ibdiagnet_csv2xml.py /var/tmp/ibdiagnet2/ibdiagnet2.db_csv /tmp/ibdiagnet2_db.xml")
	_, err = cmd2.Output()
	if err != nil {
		return result, fmt.Errorf("ibdiagnet_csv2xml.py 执行错误,%s", err)
	}
	cmd3 := exec.Command("bash", "-c", "echo $(cat /tmp/ibdiagnet2_db.xml)")
	output, err := cmd3.Output()
	if err != nil {
		return result, fmt.Errorf("echo 执行错误,%s", err)
	}
	// lines := strings.Split(string(output), "\n")
	tb := clitask.NewEmptyTableWithKeys([]string{
		l2struct.IBNetDiscover})
	m := make(map[string]string)
	m[l2struct.IBNetDiscover] = string(output)
	err = tb.PushRow("", m, false, "")
	// for _, v := range lines {
	// 	// if strings.TrimSpace(v)==
	// 	fmt.Println("each 输出=======》", v)
	// 	m := make(map[string]string)
	// 	m[l2struct.IBNetDiscover] = strings.TrimSpace(v)
	// 	err = tb.PushRow("", m, false, "")
	// }
	cmd4 := exec.Command("bash", "-c", "rm /tmp/ibdiagnet2_db.xml")
	_, err = cmd4.Output()
	if err != nil {
		return result, fmt.Errorf("删除/tmp/ibdiagnet2_db 执行错误,%s", err)
	}
	fmt.Println("2222, len = ", len(output))
	return tb, err
}

func (ts *INFINIBAND) IbNetDiscover(ctx context.Context, arg *structs.Args, reply *structs.Reply) (err error) {
	logger := log.NewLogger(arg.Remote.ActionID, true)
	reply.StartTime = time.Now()
	logger.Debug("INFINIBAND 开始IB_NET_DISCOVER采集", zap.Any("args", arg))

	var result *clitask.Table
	result, err = getDiscover()
	if err != nil {
		reply.EndTime = time.Now()
		reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
		// reply.Table = result
		reply.Error = err
		logger.Error("IB_NET_DISCOVER采集失败", zap.Any("args", arg), zap.Error(err))
		return err
	}

	reply.Table = result
	reply.Result = result.ToSliceMap()
	reply.Total = result.RowCount()
	reply.EndTime = time.Now()
	reply.Duration = reply.EndTime.Sub(reply.StartTime).Truncate(10 * time.Millisecond).Seconds()
	reply.Table = result
	reply.Error = err
	// result.Pretty()

	logger.Debug("IB_NET_DISCOVER完成采集")
	return nil
}
