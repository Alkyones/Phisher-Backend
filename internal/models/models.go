package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// URLAnalysis represents a URL analysis record
type URLAnalysis struct {
	ID             primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	UserID         string             `json:"userId" bson:"userId"`
	URL            string             `json:"url" bson:"url"`
	Domain         string             `json:"domain" bson:"domain"`
	IsPhishing     bool               `json:"isPhishing" bson:"isPhishing"`
	RiskScore      int                `json:"riskScore" bson:"riskScore"`
	Confidence     float64            `json:"confidence" bson:"confidence"`
	Description    string             `json:"description" bson:"description"`
	Threats        []string           `json:"threats" bson:"threats"`
	Recommendation string             `json:"recommendation" bson:"recommendation"`
	AIModelUsed    string             `json:"aiModelUsed" bson:"aiModelUsed"`
	AnalysisTime   int64              `json:"analysisTime" bson:"analysisTime"` // Duration in nanoseconds
	IPAddress      string             `json:"ipAddress" bson:"ipAddress"`
	UserAgent      string             `json:"userAgent" bson:"userAgent"`
	CreatedAt      time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt      time.Time          `json:"updatedAt" bson:"updatedAt"`
}

// PhishingReport represents a user-submitted phishing report
type PhishingReport struct {
	ID          primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	UserID      string             `json:"userId" bson:"userId"`
	URL         string             `json:"url" bson:"url"`
	ReporterIP  string             `json:"reporterIp" bson:"reporterIp"`
	Details     string             `json:"details" bson:"details"`
	ReportType  string             `json:"reportType" bson:"reportType"` // "false_positive", "false_negative", "new_threat"
	Status      string             `json:"status" bson:"status"`         // "pending", "reviewed", "resolved"
	ReviewedBy  string             `json:"reviewedBy" bson:"reviewedBy"`
	ReviewNotes string             `json:"reviewNotes" bson:"reviewNotes"`
	CreatedAt   time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt" bson:"updatedAt"`
}

// DomainReputation represents domain reputation data
type DomainReputation struct {
	ID               primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Domain           string             `json:"domain" bson:"domain"`
	ReputationScore  int                `json:"reputationScore" bson:"reputationScore"`   // 0-100
	ThreatCategories []string           `json:"threatCategories" bson:"threatCategories"` // Array of threat types
	LastChecked      time.Time          `json:"lastChecked" bson:"lastChecked"`
	AnalysisCount    int                `json:"analysisCount" bson:"analysisCount"`
	ThreatCount      int                `json:"threatCount" bson:"threatCount"`
	CheckCount       int                `json:"checkCount" bson:"checkCount"`
	PhishingCount    int                `json:"phishingCount" bson:"phishingCount"`
	SafeCount        int                `json:"safeCount" bson:"safeCount"`
	Sources          []string           `json:"sources" bson:"sources"` // Sources of reputation data
	CreatedAt        time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt        time.Time          `json:"updatedAt" bson:"updatedAt"`
}

// UserWhitelist represents a user's trusted domains
type UserWhitelist struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	UserID    string             `json:"userId" bson:"userId"`
	Domains   []string           `json:"domains" bson:"domains"`
	CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt time.Time          `json:"updatedAt" bson:"updatedAt"`
}

// UserBlacklist represents a user's blocked domains
type UserBlacklist struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	UserID    string             `json:"userId" bson:"userId"`
	Domains   []string           `json:"domains" bson:"domains"`
	CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt time.Time          `json:"updatedAt" bson:"updatedAt"`
}

// UserStats represents user usage statistics
type UserStats struct {
	ID            primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	UserID        string             `json:"userId" bson:"userId"`
	CheckCount    int                `json:"checkCount" bson:"checkCount"`
	PhishingCount int                `json:"phishingCount" bson:"phishingCount"`
	SafeCount     int                `json:"safeCount" bson:"safeCount"`
	CreatedAt     time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt     time.Time          `json:"updatedAt" bson:"updatedAt"`
}

// APIKey represents API access keys
type APIKey struct {
	ID           primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	KeyHash      string             `json:"keyHash" bson:"keyHash"`
	Name         string             `json:"name" bson:"name"`
	IsActive     bool               `json:"isActive" bson:"isActive"`
	LastUsed     *time.Time         `json:"lastUsed,omitempty" bson:"lastUsed,omitempty"`
	RateLimit    int                `json:"rateLimit" bson:"rateLimit"`
	RequestCount int                `json:"requestCount" bson:"requestCount"`
	CreatedAt    time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt    time.Time          `json:"updatedAt" bson:"updatedAt"`
}

// AnalysisMetric represents system metrics
type AnalysisMetric struct {
	ID                   primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Date                 time.Time          `json:"date" bson:"date"`
	TotalAnalyses        int                `json:"totalAnalyses" bson:"totalAnalyses"`
	PhishingDetected     int                `json:"phishingDetected" bson:"phishingDetected"`
	SafeURLs             int                `json:"safeUrls" bson:"safeUrls"`
	AIAnalyses           int                `json:"aiAnalyses" bson:"aiAnalyses"`
	FallbackAnalyses     int                `json:"fallbackAnalyses" bson:"fallbackAnalyses"`
	AverageRiskScore     float64            `json:"averageRiskScore" bson:"averageRiskScore"`
	AverageConfidence    float64            `json:"averageConfidence" bson:"averageConfidence"`
	UniqueDomainsScanned int                `json:"uniqueDomainsScanned" bson:"uniqueDomainsScanned"`
	CreatedAt            time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt            time.Time          `json:"updatedAt" bson:"updatedAt"`
}
