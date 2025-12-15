package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port           string
	MongoURI       string
	DatabaseName   string
	OpenAIAPIKey   string
	Environment    string
	CorsOrigins    []string
	RateLimit      int
	CacheTimeout   time.Duration
	LogLevel       string
	EnableMetrics  bool
	AIModelName    string
	MaxURLLength   int
	TrustedDomains []string
}

func Load() *Config {
	return &Config{
		Port:           getEnvOrDefault("PORT", "8080"),
		MongoURI:       getEnvOrDefault("MONGODB_URI", "mongodb://localhost:27017"),
		DatabaseName:   getEnvOrDefault("DATABASE_NAME", "phishing_detector"),
		OpenAIAPIKey:   getEnvOrDefault("OPENAI_API_KEY", ""), // Must be set by user
		Environment:    getEnvOrDefault("ENVIRONMENT", "development"),
		CorsOrigins:    []string{"chrome-extension://*", "http://localhost:*"},
		RateLimit:      getEnvIntOrDefault("RATE_LIMIT", 100),
		CacheTimeout:   time.Duration(getEnvIntOrDefault("CACHE_TIMEOUT_MINUTES", 5)) * time.Minute,
		LogLevel:       getEnvOrDefault("LOG_LEVEL", "info"),
		EnableMetrics:  getEnvBoolOrDefault("ENABLE_METRICS", true),
		AIModelName:    getEnvOrDefault("AI_MODEL_NAME", "gpt-3.5-turbo"),
		MaxURLLength:   getEnvIntOrDefault("MAX_URL_LENGTH", 2048),
		TrustedDomains: []string{"google.com", "microsoft.com", "apple.com", "github.com"},
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
