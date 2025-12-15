package services

import (
	"context"
	"fmt"
	"phishing-detector/internal/models"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// HistoryService handles URL analysis history management
type HistoryService struct {
	db *mongo.Database
}

// HistoryFilter represents filtering options for history queries
type HistoryFilter struct {
	UserID      string     `json:"userId"`
	DateFrom    *time.Time `json:"dateFrom,omitempty"`
	DateTo      *time.Time `json:"dateTo,omitempty"`
	OnlyThreats bool       `json:"onlyThreats"`
	Domain      string     `json:"domain,omitempty"`
	MinRisk     int        `json:"minRisk,omitempty"`
	MaxRisk     int        `json:"maxRisk,omitempty"`
	Limit       int        `json:"limit"`
	Offset      int        `json:"offset"`
	SortBy      string     `json:"sortBy"`
	SortOrder   string     `json:"sortOrder"`
}

// HistoryStats represents statistics about user's analysis history
type HistoryStats struct {
	TotalAnalyses   int       `json:"totalAnalyses"`
	ThreatsDetected int       `json:"threatsDetected"`
	SafeURLs        int       `json:"safeUrls"`
	UniqueURLs      int       `json:"uniqueUrls"`
	UniqueDomains   int       `json:"uniqueDomains"`
	FirstAnalysis   time.Time `json:"firstAnalysis"`
	LastAnalysis    time.Time `json:"lastAnalysis"`
	AvgRiskScore    float64   `json:"avgRiskScore"`
	TopThreats      []string  `json:"topThreats"`
}

// HistoryResponse represents a paginated history response
type HistoryResponse struct {
	Analyses   []models.URLAnalysis `json:"analyses"`
	Total      int64                `json:"total"`
	Page       int                  `json:"page"`
	PerPage    int                  `json:"perPage"`
	TotalPages int                  `json:"totalPages"`
	HasNext    bool                 `json:"hasNext"`
	HasPrev    bool                 `json:"hasPrev"`
}

// NewHistoryService creates a new history service
func NewHistoryService(db *mongo.Database) *HistoryService {
	return &HistoryService{
		db: db,
	}
}

// GetAnalysisHistory retrieves analysis history with filtering and pagination
func (h *HistoryService) GetAnalysisHistory(ctx context.Context, filter HistoryFilter) (*HistoryResponse, error) {
	collection := h.db.Collection("analyses")

	// Build MongoDB filter
	mongoFilter := bson.M{"userId": filter.UserID}

	// Add date filters
	if filter.DateFrom != nil || filter.DateTo != nil {
		dateFilter := bson.M{}
		if filter.DateFrom != nil {
			dateFilter["$gte"] = *filter.DateFrom
		}
		if filter.DateTo != nil {
			dateFilter["$lte"] = *filter.DateTo
		}
		mongoFilter["createdAt"] = dateFilter
	}

	// Add threat filter
	if filter.OnlyThreats {
		mongoFilter["isPhishing"] = true
	}

	// Add domain filter
	if filter.Domain != "" {
		mongoFilter["domain"] = bson.M{"$regex": filter.Domain, "$options": "i"}
	}

	// Add risk score filters
	if filter.MinRisk > 0 || filter.MaxRisk > 0 {
		riskFilter := bson.M{}
		if filter.MinRisk > 0 {
			riskFilter["$gte"] = filter.MinRisk
		}
		if filter.MaxRisk > 0 {
			riskFilter["$lte"] = filter.MaxRisk
		}
		mongoFilter["riskScore"] = riskFilter
	}

	// Get total count
	total, err := collection.CountDocuments(ctx, mongoFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count documents: %w", err)
	}

	// Calculate pagination
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	page := (offset / limit) + 1
	totalPages := int((total + int64(limit) - 1) / int64(limit))

	// Build sort options
	sortField := "createdAt"
	sortOrder := -1 // desc by default

	if filter.SortBy != "" {
		switch filter.SortBy {
		case "date", "createdAt":
			sortField = "createdAt"
		case "url":
			sortField = "url"
		case "domain":
			sortField = "domain"
		case "riskScore":
			sortField = "riskScore"
		case "confidence":
			sortField = "confidence"
		}
	}

	if filter.SortOrder == "asc" {
		sortOrder = 1
	}

	// Find documents with pagination
	opts := options.Find()
	opts.SetSort(bson.D{{Key: sortField, Value: sortOrder}})
	opts.SetSkip(int64(offset))
	opts.SetLimit(int64(limit))

	cursor, err := collection.Find(ctx, mongoFilter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to find documents: %w", err)
	}
	defer cursor.Close(ctx)

	var analyses []models.URLAnalysis
	if err = cursor.All(ctx, &analyses); err != nil {
		return nil, fmt.Errorf("failed to decode documents: %w", err)
	}

	return &HistoryResponse{
		Analyses:   analyses,
		Total:      total,
		Page:       page,
		PerPage:    limit,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}, nil
}

// GetHistoryStats retrieves statistics about user's analysis history
func (h *HistoryService) GetHistoryStats(ctx context.Context, userID string) (*HistoryStats, error) {
	collection := h.db.Collection("analyses")
	filter := bson.M{"userId": userID}

	// Get total count
	totalCount, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count total analyses: %w", err)
	}

	if totalCount == 0 {
		return &HistoryStats{}, nil
	}

	// Get threat count
	threatFilter := bson.M{"userId": userID, "isPhishing": true}
	threatCount, err := collection.CountDocuments(ctx, threatFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count threats: %w", err)
	}

	safeCount := totalCount - threatCount

	// Get unique URLs count
	uniqueURLPipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{"_id": "$url"}},
		{"$count": "uniqueURLs"},
	}

	var uniqueURLResult []bson.M
	cursor, err := collection.Aggregate(ctx, uniqueURLPipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate unique URLs: %w", err)
	}
	if err = cursor.All(ctx, &uniqueURLResult); err != nil {
		return nil, fmt.Errorf("failed to decode unique URLs: %w", err)
	}

	uniqueURLs := 0
	if len(uniqueURLResult) > 0 {
		uniqueURLs = int(uniqueURLResult[0]["uniqueURLs"].(int32))
	}

	// Get unique domains count
	uniqueDomainPipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{"_id": "$domain"}},
		{"$count": "uniqueDomains"},
	}

	var uniqueDomainResult []bson.M
	cursor, err = collection.Aggregate(ctx, uniqueDomainPipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate unique domains: %w", err)
	}
	if err = cursor.All(ctx, &uniqueDomainResult); err != nil {
		return nil, fmt.Errorf("failed to decode unique domains: %w", err)
	}

	uniqueDomains := 0
	if len(uniqueDomainResult) > 0 {
		uniqueDomains = int(uniqueDomainResult[0]["uniqueDomains"].(int32))
	}

	// Get date range and average risk score
	statsPipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id":        nil,
			"avgRisk":    bson.M{"$avg": "$riskScore"},
			"minDate":    bson.M{"$min": "$createdAt"},
			"maxDate":    bson.M{"$max": "$createdAt"},
			"allThreats": bson.M{"$push": "$threats"},
		}},
	}

	var statsResult []bson.M
	cursor, err = collection.Aggregate(ctx, statsPipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate stats: %w", err)
	}
	if err = cursor.All(ctx, &statsResult); err != nil {
		return nil, fmt.Errorf("failed to decode stats: %w", err)
	}

	stats := &HistoryStats{
		TotalAnalyses:   int(totalCount),
		ThreatsDetected: int(threatCount),
		SafeURLs:        int(safeCount),
		UniqueURLs:      uniqueURLs,
		UniqueDomains:   uniqueDomains,
	}

	if len(statsResult) > 0 {
		result := statsResult[0]

		if avgRisk, ok := result["avgRisk"].(float64); ok {
			stats.AvgRiskScore = avgRisk
		}

		if minDate, ok := result["minDate"].(primitive.DateTime); ok {
			stats.FirstAnalysis = minDate.Time()
		}

		if maxDate, ok := result["maxDate"].(primitive.DateTime); ok {
			stats.LastAnalysis = maxDate.Time()
		}

		// Process top threats
		if allThreatsInterface, ok := result["allThreats"]; ok {
			threatCounts := make(map[string]int)
			if allThreats, ok := allThreatsInterface.(primitive.A); ok {
				for _, threatArrayInterface := range allThreats {
					if threatArray, ok := threatArrayInterface.(primitive.A); ok {
						for _, threatInterface := range threatArray {
							if threat, ok := threatInterface.(string); ok && threat != "" {
								threatCounts[threat]++
							}
						}
					}
				}
			}

			// Get top 5 threats
			type threatCount struct {
				threat string
				count  int
			}
			var threats []threatCount
			for threat, count := range threatCounts {
				threats = append(threats, threatCount{threat, count})
			}

			// Simple sort by count (descending)
			for i := 0; i < len(threats); i++ {
				for j := i + 1; j < len(threats); j++ {
					if threats[j].count > threats[i].count {
						threats[i], threats[j] = threats[j], threats[i]
					}
				}
			}

			// Take top 5
			for i, threat := range threats {
				if i >= 5 {
					break
				}
				stats.TopThreats = append(stats.TopThreats, threat.threat)
			}
		}
	}

	return stats, nil
}

// DeleteAnalysisHistory deletes analysis history for a user
func (h *HistoryService) DeleteAnalysisHistory(ctx context.Context, userID string, analysisIDs []string) error {
	if len(analysisIDs) == 0 {
		return fmt.Errorf("no analysis IDs provided")
	}

	collection := h.db.Collection("analyses")

	// Convert string IDs to ObjectIDs
	objectIDs := make([]primitive.ObjectID, 0, len(analysisIDs))
	for _, id := range analysisIDs {
		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return fmt.Errorf("invalid analysis ID: %s", id)
		}
		objectIDs = append(objectIDs, objectID)
	}

	// Delete only analyses belonging to the user
	filter := bson.M{
		"userId": userID,
		"_id":    bson.M{"$in": objectIDs},
	}

	result, err := collection.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete analyses: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("no analyses deleted - check IDs and permissions")
	}

	return nil
}

// ClearAllHistory deletes all analysis history for a user
func (h *HistoryService) ClearAllHistory(ctx context.Context, userID string) error {
	collection := h.db.Collection("analyses")

	filter := bson.M{"userId": userID}
	_, err := collection.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to clear history: %w", err)
	}

	return nil
}
