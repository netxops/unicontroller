package deploymentservice

// import (
// 	"context"
// 	"fmt"
// 	"sync"
// 	"time"

// 	"github.com/influxdata/telegraf/controller/pkg/controller/models"
// 	"go.mongodb.org/mongo-driver/bson"
// 	"go.mongodb.org/mongo-driver/mongo"
// )

// type DeploymentService struct {
// 	mongoClient *mongo.Client
// 	dbName      string
// 	mutex       sync.RWMutex
// }

// func NewDeploymentService(mongoClient *mongo.Client, dbName string) *DeploymentService {
// 	return &DeploymentService{
// 		mongoClient: mongoClient,
// 		dbName:      dbName,
// 	}
// }
// func (s *DeploymentService) CreateDeployment(ctx context.Context, req models.Deployment) (*models.Deployment, error) {
// 	deployment := &models.Deployment{
// 		ID:            req.ID,
// 		AppID:         req.AppID,
// 		Type:          req.Type,
// 		Version:       req.Version,
// 		Env:           req.Env,
// 		Variables:     req.Variables,
// 		TargetDevices: req.TargetDevices,
// 		Status:        models.DeploymentStatusPending,
// 		StartTime:     time.Now(),
// 		Logs:          []string{},
// 	}

// 	collection := s.mongoClient.Database(s.dbName).Collection("deployments")
// 	_, err := collection.InsertOne(ctx, deployment)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to insert deployment into MongoDB: %v", err)
// 	}

// 	// 启动异步部署过程
// 	go s.runDeployment(deployment)

// 	return deployment, nil
// }

// func (s *DeploymentService) GetDeployment(ctx context.Context, deploymentID string) (*models.Deployment, error) {
// 	var deployment models.Deployment
// 	collection := s.mongoClient.Database(s.dbName).Collection("deployments")
// 	err := collection.FindOne(ctx, bson.M{"id": deploymentID}).Decode(&deployment)
// 	if err != nil {
// 		if err == mongo.ErrNoDocuments {
// 			return nil, fmt.Errorf("deployment not found: %s", deploymentID)
// 		}
// 		return nil, fmt.Errorf("error fetching deployment: %v", err)
// 	}
// 	return &deployment, nil
// }

// func (s *DeploymentService) GetDeploymentStatus(ctx context.Context, deploymentID string) (*models.DeploymentStatus, error) {
// 	deployment, err := s.GetDeployment(ctx, deploymentID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &deployment.Status, nil
// }

// func (s *DeploymentService) ListDeployments(ctx context.Context) ([]models.Deployment, error) {
// 	var deployments []models.Deployment
// 	collection := s.mongoClient.Database(s.dbName).Collection("deployments")
// 	cursor, err := collection.Find(ctx, bson.M{})
// 	if err != nil {
// 		return nil, fmt.Errorf("error listing deployments: %v", err)
// 	}
// 	defer cursor.Close(ctx)
// 	if err = cursor.All(ctx, &deployments); err != nil {
// 		return nil, fmt.Errorf("error decoding deployments: %v", err)
// 	}
// 	return deployments, nil
// }

// func (s *DeploymentService) UpdateDeploymentStatus(ctx context.Context, deploymentID string, status models.DeploymentStatusUpdate) error {
// 	collection := s.mongoClient.Database(s.dbName).Collection("deployments")
// 	update := bson.M{
// 		"$set": bson.M{
// 			"status":   status.Status,
// 			"message":  status.Message,
// 			"end_time": time.Now(),
// 		},
// 	}
// 	_, err := collection.UpdateOne(ctx, bson.M{"id": deploymentID}, update)
// 	if err != nil {
// 		return fmt.Errorf("failed to update deployment status: %v", err)
// 	}
// 	return nil
// }

// func (s *DeploymentService) UpdateDeploymentStatusAndResults(ctx context.Context, deploymentID string, status models.DeploymentStatus, results []map[string]interface{}) error {
// 	collection := s.mongoClient.Database(s.dbName).Collection("deployments")
// 	update := bson.M{
// 		"$set": bson.M{
// 			"status":   status,
// 			"end_time": time.Now(),
// 			"results":  results,
// 		},
// 	}
// 	_, err := collection.UpdateOne(ctx, bson.M{"id": deploymentID}, update)
// 	if err != nil {
// 		return fmt.Errorf("failed to update deployment status and results: %v", err)
// 	}
// 	return nil
// }

// func (s *DeploymentService) runDeployment(d *models.Deployment) {
// 	// 更新状态为 "in_progress"
// 	s.updateDeploymentStatus(context.Background(), d.ID, models.DeploymentStatusInProgress)

// 	// TODO: 实现实际的部署逻辑
// 	// 这可能涉及调用其他服务或执行脚本

// 	// 现在，我们只是模拟一个部署过程
// 	time.Sleep(10 * time.Second)

// 	// 更新状态为 "completed"
// 	s.updateDeploymentStatus(context.Background(), d.ID, models.DeploymentStatusCompleted)
// }

// func (s *DeploymentService) updateDeploymentStatus(ctx context.Context, id string, status models.DeploymentStatus) error {
// 	collection := s.mongoClient.Database(s.dbName).Collection("deployments")
// 	update := bson.M{"$set": bson.M{"status": status}}
// 	if status == models.DeploymentStatusCompleted {
// 		update["$set"].(bson.M)["end_time"] = time.Now()
// 	}
// 	_, err := collection.UpdateOne(ctx, bson.M{"id": id}, update)
// 	return err
// }
// func (s *DeploymentService) AddLog(ctx context.Context, id string, log string) error {
// 	collection := s.mongoClient.Database(s.dbName).Collection("deployments")
// 	update := bson.M{"$push": bson.M{"logs": log}}
// 	_, err := collection.UpdateOne(ctx, bson.M{"id": id}, update)
// 	return err
// }
