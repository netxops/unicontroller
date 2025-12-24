package controller

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ProvideDBClient 创建并返回一个 MongoDB 客户端
func ProvideDBClient(config *Config) (*mongo.Client, error) {
	if config.Database.Type != "mongodb" {
		return nil, fmt.Errorf("unsupported database type: %s", config.Database.Type)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(config.Database.URI)

	if config.Database.MaxPoolSize > 0 {
		clientOptions.SetMaxPoolSize(config.Database.MaxPoolSize)
	}

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	// Ping the database to verify the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	return client, nil
}
