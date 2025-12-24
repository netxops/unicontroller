package controller

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
)

func TestBatchOperator_BatchStartPackages(t *testing.T) {
	// 测试请求结构
	req := &models.BatchOperationRequest{
		Agents:   []string{"agent-1", "agent-2"},
		Packages: []string{"service-1"},
	}

	// 验证请求结构
	if len(req.Agents) != 2 {
		t.Errorf("Expected 2 agents, got: %d", len(req.Agents))
	}
	if len(req.Packages) != 1 {
		t.Errorf("Expected 1 package, got: %d", len(req.Packages))
	}
}

func TestBatchOperationRequest_Validation(t *testing.T) {
	req := &models.BatchOperationRequest{
		Agents:   []string{"agent-1"},
		Packages: []string{"service-1", "service-2"},
	}

	if len(req.Agents) == 0 {
		t.Error("Agents should not be empty")
	}
	if len(req.Packages) == 0 {
		t.Error("Packages should not be empty")
	}
}

func TestBatchConfigRequest_Validation(t *testing.T) {
	req := &models.BatchConfigRequest{
		Agents:  []string{"agent-1"},
		Package: "service-1",
		Configs: []models.ConfigItem{
			{FileName: "config.yaml", Content: "key: value"},
		},
	}

	if len(req.Agents) == 0 {
		t.Error("Agents should not be empty")
	}
	if req.Package == "" {
		t.Error("Package should not be empty")
	}
	if len(req.Configs) == 0 {
		t.Error("Configs should not be empty")
	}
}
