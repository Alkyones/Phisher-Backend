package main

import (
	"log"
	"os"

	"phishing-detector/internal/api"
	"phishing-detector/internal/config"
	"phishing-detector/internal/database"
	"phishing-detector/internal/services"

	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Initialize configuration
	cfg := config.Load()

	// Initialize MongoDB database
	db, err := database.Initialize(cfg.MongoURI)
	if err != nil {
		log.Fatalf("Failed to initialize MongoDB: %v", err)
	}

	// Initialize AI service
	aiService := services.NewAIService(cfg.OpenAIAPIKey)

	// Initialize phishing detector service
	phishingService := services.NewPhishingDetectorService(aiService, db)

	// Initialize API server
	server := api.NewServer(cfg, phishingService)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	if err := server.Run(":" + port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
