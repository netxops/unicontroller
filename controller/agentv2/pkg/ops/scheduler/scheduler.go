package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// Task 任务
type Task struct {
	ID           string
	Name         string
	Type         string // "command", "script", "file_operation", "service_operation"
	Schedule     string // Cron 表达式
	Command      string
	Args         []string
	Enabled      bool
	LastRun      *time.Time
	NextRun      *time.Time
	RunCount     int64
	SuccessCount int64
	FailCount    int64
	entryID      cron.EntryID // Cron 任务 ID
	mu           sync.RWMutex
}

// TaskExecutor 任务执行器接口
type TaskExecutor interface {
	Execute(ctx context.Context, task *Task) error
}

// Scheduler 任务调度器
type Scheduler struct {
	logger    *zap.Logger
	cron      *cron.Cron
	tasks     map[string]*Task
	executors map[string]TaskExecutor
	mu        sync.RWMutex
}

// NewScheduler 创建任务调度器
func NewScheduler(logger *zap.Logger) *Scheduler {
	// 使用秒级精度的 Cron
	c := cron.New(cron.WithSeconds())

	return &Scheduler{
		logger:    logger,
		cron:      c,
		tasks:     make(map[string]*Task),
		executors: make(map[string]TaskExecutor),
	}
}

// RegisterExecutor 注册任务执行器
func (s *Scheduler) RegisterExecutor(taskType string, executor TaskExecutor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executors[taskType] = executor
	s.logger.Info("Task executor registered", zap.String("type", taskType))
}

// AddTask 添加任务
func (s *Scheduler) AddTask(task *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tasks[task.ID]; exists {
		return fmt.Errorf("task %s already exists", task.ID)
	}

	// 验证 Cron 表达式
	if _, err := cron.ParseStandard(task.Schedule); err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	// 计算下次运行时间
	schedule, _ := cron.ParseStandard(task.Schedule)
	nextRun := schedule.Next(time.Now())
	task.NextRun = &nextRun

	s.tasks[task.ID] = task

	// 如果启用，添加到 Cron
	if task.Enabled {
		if err := s.scheduleTask(task); err != nil {
			return fmt.Errorf("failed to schedule task: %w", err)
		}
	}

	s.logger.Info("Task added",
		zap.String("task_id", task.ID),
		zap.String("name", task.Name),
		zap.String("schedule", task.Schedule))

	return nil
}

// RemoveTask 移除任务
func (s *Scheduler) RemoveTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, exists := s.tasks[taskID]
	if !exists {
		return fmt.Errorf("task %s not found", taskID)
	}

	// 从 Cron 中移除
	if task.Enabled && task.entryID > 0 {
		s.cron.Remove(task.entryID)
	}

	delete(s.tasks, taskID)

	s.logger.Info("Task removed", zap.String("task_id", taskID))
	return nil
}

// EnableTask 启用任务
func (s *Scheduler) EnableTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, exists := s.tasks[taskID]
	if !exists {
		return fmt.Errorf("task %s not found", taskID)
	}

	if task.Enabled {
		return nil // 已经启用
	}

	task.Enabled = true
	if err := s.scheduleTask(task); err != nil {
		return fmt.Errorf("failed to schedule task: %w", err)
	}

	s.logger.Info("Task enabled", zap.String("task_id", taskID))
	return nil
}

// DisableTask 禁用任务
func (s *Scheduler) DisableTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, exists := s.tasks[taskID]
	if !exists {
		return fmt.Errorf("task %s not found", taskID)
	}

	if !task.Enabled {
		return nil // 已经禁用
	}

	task.Enabled = false
	if task.entryID > 0 {
		s.cron.Remove(task.entryID)
		task.entryID = 0
	}

	s.logger.Info("Task disabled", zap.String("task_id", taskID))
	return nil
}

// RunTaskNow 立即运行任务
func (s *Scheduler) RunTaskNow(ctx context.Context, taskID string) error {
	s.mu.RLock()
	task, exists := s.tasks[taskID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("task %s not found", taskID)
	}

	return s.executeTask(ctx, task)
}

// GetTask 获取任务
func (s *Scheduler) GetTask(taskID string) (*Task, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	task, exists := s.tasks[taskID]
	return task, exists
}

// ListTasks 列出所有任务
func (s *Scheduler) ListTasks() []*Task {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tasks := make([]*Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

// Start 启动调度器
func (s *Scheduler) Start() {
	s.cron.Start()
	s.logger.Info("Scheduler started")
}

// Stop 停止调度器
func (s *Scheduler) Stop() {
	s.cron.Stop()
	s.logger.Info("Scheduler stopped")
}

// scheduleTask 调度任务
func (s *Scheduler) scheduleTask(task *Task) error {
	// 如果任务已经调度过，先移除旧的
	if task.entryID > 0 {
		s.cron.Remove(task.entryID)
		task.entryID = 0
	}

	entryID, err := s.cron.AddFunc(task.Schedule, func() {
		ctx := context.Background()
		if err := s.executeTask(ctx, task); err != nil {
			s.logger.Error("Task execution failed",
				zap.String("task_id", task.ID),
				zap.String("name", task.Name),
				zap.Error(err))
		}
	})

	if err != nil {
		return fmt.Errorf("failed to add cron job: %w", err)
	}

	// 保存任务的 EntryID
	task.entryID = entryID

	return nil
}

// executeTask 执行任务
func (s *Scheduler) executeTask(ctx context.Context, task *Task) error {
	task.mu.Lock()
	task.RunCount++
	now := time.Now()
	task.LastRun = &now
	task.mu.Unlock()

	// 获取执行器
	s.mu.RLock()
	executor, exists := s.executors[task.Type]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("executor for task type %s not found", task.Type)
	}

	// 执行任务
	err := executor.Execute(ctx, task)

	task.mu.Lock()
	if err != nil {
		task.FailCount++
	} else {
		task.SuccessCount++
	}
	// 更新下次运行时间
	schedule, _ := cron.ParseStandard(task.Schedule)
	nextRun := schedule.Next(now)
	task.NextRun = &nextRun
	task.mu.Unlock()

	return err
}
