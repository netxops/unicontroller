package main

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller"
	"github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {
	// 设置测试配置文件路径
	configPath := "../../deploy/controller.yaml"
	testPort := "8081"

	// 启动测试服务器
	go func() {
		os.Args = []string{"cmd", "-config", configPath, "-port", testPort}
		main()
	}()

	// 等待服务器启动
	time.Sleep(3 * time.Second)

	// // 测试创建部署
	// t.Run("CreateDeployment", func(t *testing.T) {
	// 	deploymentReq := models.DeploymentRequest{
	// 		AppID:   "test-app",
	// 		Version: "v1.0.0",
	// 		Env:     "test",
	// 		Targets: []string{"target1", "target2"},
	// 	}
	// 	reqBody, _ := json.Marshal(deploymentReq)
	// 	resp, err := http.Post(fmt.Sprintf("http://localhost:%s/api/v1/deployments", testPort), "application/json", bytes.NewBuffer(reqBody))
	// 	assert.NoError(t, err)
	// 	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// })

	// 测试获取应用变量
	t.Run("GetAppVariables", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/api/v1/apps/test-app/variables?env=test", testPort))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// 测试获取资产
	t.Run("GetAssets", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/api/v1/assets?tags=SERVER-INSPEC-TEST", testPort))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// 模拟发送终止信号
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(os.Interrupt)

	// 等待服务器关闭
	time.Sleep(7 * time.Second)
}

// 模拟 InitializeControllerComponents 函数
func InitializeControllerComponents(configPath string) (*controller.Controller, error) {
	return &controller.Controller{}, nil
}
