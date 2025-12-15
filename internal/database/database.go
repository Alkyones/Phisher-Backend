package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson"
)

var DB *mongo.Database

func Initialize(mongoURI string) (*mongo.Database, error) {
	// Set client options
	clientOptions := options.Client().ApplyURI(mongoURI)
	
	// Set connection timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Connect to MongoDB
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}
	
	// Test the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}
	
	// Get database name from URI or use default
	dbName := "phishing_detector"
	DB = client.Database(dbName)
	
	log.Printf("✅ Connected to MongoDB database: %s", dbName)
	
	// Create indexes for better performance
	if err := createIndexes(); err != nil {
		log.Printf("⚠️ Warning: Failed to create indexes: %v", err)
	}
	
	return DB, nil
}

func createIndexes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// URL Analysis indexes
	analysesCollection := DB.Collection("analyses")
	
	// Index on URL for fast lookups
	urlIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "url", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	
	// Index on domain for reputation checks
	domainIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "domain", Value: 1}},
	}
	
	// Index on createdAt for time-based queries
	timeIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "createdAt", Value: -1}},
	}
	
	_, err := analysesCollection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		urlIndex, domainIndex, timeIndex,
	})
	if err != nil {
		return fmt.Errorf("failed to create analyses indexes: %w", err)
	}
	
	// Domain Reputation indexes
	domainsCollection := DB.Collection("domains")
	
	domainUniqueIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "domain", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	
	_, err = domainsCollection.Indexes().CreateOne(ctx, domainUniqueIndex)
	if err != nil {
		return fmt.Errorf("failed to create domain indexes: %w", err)
	}
	
	// API Keys indexes
	apiKeysCollection := DB.Collection("api_keys")
	
	keyHashIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "keyHash", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	
	_, err = apiKeysCollection.Indexes().CreateOne(ctx, keyHashIndex)
	if err != nil {
		return fmt.Errorf("failed to create api keys indexes: %w", err)
	}
	
	// Metrics indexes
	metricsCollection := DB.Collection("metrics")
	
	dateIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "date", Value: -1}},
		Options: options.Index().SetUnique(true),
	}
	
	_, err = metricsCollection.Indexes().CreateOne(ctx, dateIndex)
	if err != nil {
		return fmt.Errorf("failed to create metrics indexes: %w", err)
	}
	
	log.Println("✅ MongoDB indexes created successfully")
	return nil
}

// Collection helper functions
func GetAnalysesCollection() *mongo.Collection {
	return DB.Collection("analyses")
}

func GetDomainsCollection() *mongo.Collection {
	return DB.Collection("domains")
}

func GetReportsCollection() *mongo.Collection {
	return DB.Collection("reports")
}

func GetAPIKeysCollection() *mongo.Collection {
	return DB.Collection("api_keys")
}

func GetMetricsCollection() *mongo.Collection {
	return DB.Collection("metrics")
}