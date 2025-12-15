package services

import (
	"context"
	"fmt"
	"net/url"
	"phishing-detector/internal/database"
	"phishing-detector/internal/models"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PhishingDetectorService struct {
	aiService *AIService
	db        *mongo.Database
	cache     map[string]*models.URLAnalysis
}

type AnalysisRequest struct {
	URL         string `json:"url" binding:"required,url"`
	Timestamp   int64  `json:"timestamp"`
	UserAgent   string `json:"userAgent"`
	UserID      string `json:"userId"`
	Sensitivity string `json:"sensitivity"` // conservative, balanced, aggressive
}

type AnalysisResponse struct {
	URL            string        `json:"url"`
	IsPhishing     bool          `json:"isPhishing"`
	RiskScore      int           `json:"riskScore"`
	Confidence     float64       `json:"confidence"`
	Description    string        `json:"description"`
	Threats        []string      `json:"threats"`
	Recommendation string        `json:"recommendation"`
	AnalysisTime   time.Duration `json:"analysisTime"`
	CacheHit       bool          `json:"cacheHit"`
}

type ReportRequest struct {
	URL     string `json:"url" binding:"required"`
	Details string `json:"details"`
	Type    string `json:"type"` // "false_positive", "false_negative", "new_threat"
}

func NewPhishingDetectorService(aiService *AIService, db *mongo.Database) *PhishingDetectorService {
	return &PhishingDetectorService{
		aiService: aiService,
		db:        db,
		cache:     make(map[string]*models.URLAnalysis),
	}
}

func (s *PhishingDetectorService) AnalyzeURL(ctx context.Context, req AnalysisRequest, ipAddress string) (*AnalysisResponse, error) {
	startTime := time.Now()

	// Clean and validate URL
	cleanURL := strings.TrimSpace(req.URL)
	if cleanURL == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}

	parsedURL, err := url.Parse(cleanURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	domain := parsedURL.Host
	if domain == "" {
		return nil, fmt.Errorf("URL must have a valid domain")
	}

	// Check if domain is whitelisted - skip analysis if it is
	isWhitelisted, err := s.IsWhitelisted(ctx, req.UserID, domain)
	if err != nil {
		fmt.Printf("Error checking whitelist: %v\n", err)
		// Continue with analysis even if whitelist check fails
	}

	if isWhitelisted {
		// Return safe result for whitelisted domains
		return &AnalysisResponse{
			URL:            cleanURL,
			IsPhishing:     false,
			RiskScore:      0,
			Confidence:     100,
			Description:    "Domain is in your trusted whitelist",
			Threats:        []string{},
			Recommendation: "Safe - Trusted domain",
			AnalysisTime:   time.Since(startTime),
			CacheHit:       false,
		}, nil
	}

	// Check if domain is blacklisted - return threat result immediately
	isBlacklisted, err := s.IsBlacklisted(ctx, req.UserID, domain)
	if err != nil {
		fmt.Printf("Error checking blacklist: %v\n", err)
		// Continue with analysis even if blacklist check fails
	}

	if isBlacklisted {
		// Return threat result for blacklisted domains
		return &AnalysisResponse{
			URL:            cleanURL,
			IsPhishing:     true,
			RiskScore:      100,
			Confidence:     100,
			Description:    "Domain is in your personal blacklist",
			Threats:        []string{"User-blocked domain"},
			Recommendation: "Blocked - Domain manually blacklisted by user",
			AnalysisTime:   time.Since(startTime),
			CacheHit:       false,
		}, nil
	}

	// Create user-specific cache key
	cacheKey := fmt.Sprintf("%s:%s", req.UserID, cleanURL)

	// Check cache first
	if cached, exists := s.cache[cacheKey]; exists {
		// Check if cache is still valid (5 minutes)
		if time.Since(cached.CreatedAt) < 5*time.Minute {
			return &AnalysisResponse{
				URL:            cached.URL,
				IsPhishing:     cached.IsPhishing,
				RiskScore:      cached.RiskScore,
				Confidence:     cached.Confidence,
				Description:    cached.Description,
				Threats:        cached.Threats,
				Recommendation: cached.Recommendation,
				AnalysisTime:   time.Duration(cached.AnalysisTime),
				CacheHit:       true,
			}, nil
		}
	}

	// Check database for recent analysis
	analysesCollection := database.GetAnalysesCollection()

	var existingAnalysis models.URLAnalysis
	filter := bson.M{
		"userId": req.UserID,
		"url":    cleanURL,
		"createdAt": bson.M{
			"$gt": time.Now().Add(-5 * time.Minute),
		},
	}

	err = analysesCollection.FindOne(ctx, filter).Decode(&existingAnalysis)
	if err == nil {
		// Found recent analysis in database
		s.cache[cacheKey] = &existingAnalysis

		return &AnalysisResponse{
			URL:            existingAnalysis.URL,
			IsPhishing:     existingAnalysis.IsPhishing,
			RiskScore:      existingAnalysis.RiskScore,
			Confidence:     existingAnalysis.Confidence,
			Description:    existingAnalysis.Description,
			Threats:        existingAnalysis.Threats,
			Recommendation: existingAnalysis.Recommendation,
			AnalysisTime:   time.Duration(existingAnalysis.AnalysisTime),
			CacheHit:       true,
		}, nil
	}

	// Perform new analysis
	aiRequest := AIAnalysisRequest{
		URL:    cleanURL,
		Domain: domain,
	}

	// Try AI analysis first
	var result *AIAnalysisResponse
	var aiErr error

	if s.aiService != nil {
		result, aiErr = s.aiService.AnalyzeURL(ctx, aiRequest)
	}

	// Fall back to rule-based analysis if AI fails
	if result == nil || aiErr != nil {
		if aiErr != nil {
			fmt.Printf("AI analysis failed: %v, falling back to rule-based analysis\n", aiErr)
		}
		result = s.aiService.FallbackAnalysis(aiRequest)
	}

	// Calculate analysis time
	analysisTime := time.Since(startTime)

	// Apply sensitivity adjustments
	adjustedResult := s.applySensitivityAdjustment(result, req.Sensitivity)

	// Create analysis record
	analysis := models.URLAnalysis{
		ID:             primitive.NewObjectID(),
		UserID:         req.UserID,
		URL:            cleanURL,
		Domain:         domain,
		IsPhishing:     adjustedResult.IsPhishing,
		RiskScore:      adjustedResult.RiskScore,
		Confidence:     adjustedResult.Confidence,
		Description:    adjustedResult.Description,
		Threats:        adjustedResult.Threats,
		Recommendation: adjustedResult.Recommendation,
		AIModelUsed:    "gemini-2.5-flash",
		AnalysisTime:   int64(analysisTime),
		IPAddress:      ipAddress,
		UserAgent:      req.UserAgent,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Store analysis in database
	_, err = analysesCollection.InsertOne(ctx, analysis)
	if err != nil {
		fmt.Printf("Failed to store analysis: %v\n", err)
	}

	// Update cache
	s.cache[cacheKey] = &analysis

	// Update metrics
	go s.updateMetrics(result)

	return &AnalysisResponse{
		URL:            analysis.URL,
		IsPhishing:     analysis.IsPhishing,
		RiskScore:      analysis.RiskScore,
		Confidence:     analysis.Confidence,
		Description:    analysis.Description,
		Threats:        analysis.Threats,
		Recommendation: analysis.Recommendation,
		AnalysisTime:   analysisTime,
		CacheHit:       false,
	}, nil
}

func (s *PhishingDetectorService) updateDomainReputation(domain string, result *AIAnalysisResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	domainsCollection := database.GetDomainsCollection()

	// Find existing domain reputation
	var domainRep models.DomainReputation
	filter := bson.M{"domain": domain}

	err := domainsCollection.FindOne(ctx, filter).Decode(&domainRep)
	if err == mongo.ErrNoDocuments {
		// Create new domain reputation
		domainRep = models.DomainReputation{
			ID:               primitive.NewObjectID(),
			Domain:           domain,
			ReputationScore:  100 - result.RiskScore, // Inverse of risk score
			ThreatCategories: result.Threats,
			LastChecked:      time.Now(),
			CheckCount:       1,
			PhishingCount:    0,
			SafeCount:        0,
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}

		if result.IsPhishing {
			domainRep.PhishingCount = 1
		} else {
			domainRep.SafeCount = 1
		}

		_, err = domainsCollection.InsertOne(ctx, domainRep)
		if err != nil {
			fmt.Printf("Failed to create domain reputation: %v\n", err)
		}
	} else if err == nil {
		// Update existing domain reputation
		domainRep.CheckCount++
		domainRep.LastChecked = time.Now()
		domainRep.UpdatedAt = time.Now()

		if result.IsPhishing {
			domainRep.PhishingCount++
		} else {
			domainRep.SafeCount++
		}

		// Recalculate reputation score
		totalChecks := domainRep.PhishingCount + domainRep.SafeCount
		if totalChecks > 0 {
			safetyRatio := float64(domainRep.SafeCount) / float64(totalChecks)
			domainRep.ReputationScore = int(safetyRatio * 100)
		}

		// Merge threat categories
		for _, threat := range result.Threats {
			found := false
			for _, existing := range domainRep.ThreatCategories {
				if existing == threat {
					found = true
					break
				}
			}
			if !found {
				domainRep.ThreatCategories = append(domainRep.ThreatCategories, threat)
			}
		}

		update := bson.M{
			"$set": bson.M{
				"reputationScore":  domainRep.ReputationScore,
				"threatCategories": domainRep.ThreatCategories,
				"lastChecked":      domainRep.LastChecked,
				"checkCount":       domainRep.CheckCount,
				"phishingCount":    domainRep.PhishingCount,
				"safeCount":        domainRep.SafeCount,
				"updatedAt":        domainRep.UpdatedAt,
			},
		}

		_, err = domainsCollection.UpdateOne(ctx, filter, update)
		if err != nil {
			fmt.Printf("Failed to update domain reputation: %v\n", err)
		}
	}
}

func (s *PhishingDetectorService) updateMetrics(result *AIAnalysisResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	metricsCollection := database.GetMetricsCollection()

	today := time.Now().Truncate(24 * time.Hour)
	filter := bson.M{"date": today}

	update := bson.M{
		"$inc": bson.M{
			"totalAnalyses": 1,
		},
		"$setOnInsert": bson.M{
			"date":      today,
			"createdAt": time.Now(),
		},
		"$set": bson.M{
			"updatedAt": time.Now(),
		},
	}

	if result.IsPhishing {
		update["$inc"].(bson.M)["phishingDetected"] = 1
	} else {
		update["$inc"].(bson.M)["safeUrls"] = 1
	}

	opts := options.Update().SetUpsert(true)
	_, err := metricsCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		fmt.Printf("Failed to update metrics: %v\n", err)
	}
}

func (s *PhishingDetectorService) ReportPhishing(ctx context.Context, req ReportRequest, ipAddress, userID string) error {
	reportsCollection := database.GetReportsCollection()

	report := models.PhishingReport{
		ID:         primitive.NewObjectID(),
		UserID:     userID,
		URL:        req.URL,
		ReporterIP: ipAddress,
		Details:    req.Details,
		ReportType: req.Type,
		Status:     "pending",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	_, err := reportsCollection.InsertOne(ctx, report)
	if err != nil {
		return fmt.Errorf("failed to store phishing report: %w", err)
	}

	return nil
}

// applySensitivityAdjustment adjusts the AI analysis results based on user's detection sensitivity preference
func (s *PhishingDetectorService) applySensitivityAdjustment(result *AIAnalysisResponse, sensitivity string) *AIAnalysisResponse {
	adjusted := *result // Create a copy

	// Adjust thresholds based on sensitivity level
	switch sensitivity {
	case "conservative":
		// Higher threshold for marking as phishing (fewer false positives)
		if adjusted.RiskScore < 80 {
			adjusted.IsPhishing = false
		}
		// Reduce risk score slightly for conservative users
		adjusted.RiskScore = int(float64(adjusted.RiskScore) * 0.85)
		if adjusted.RiskScore > 100 {
			adjusted.RiskScore = 100
		}
		adjusted.Description = "[Conservative Mode] " + adjusted.Description

	case "aggressive":
		// Lower threshold for marking as phishing (more sensitive)
		if adjusted.RiskScore >= 40 {
			adjusted.IsPhishing = true
		}
		// Increase risk score for aggressive detection
		adjusted.RiskScore = int(float64(adjusted.RiskScore) * 1.2)
		if adjusted.RiskScore > 100 {
			adjusted.RiskScore = 100
		}
		adjusted.Description = "[Aggressive Mode] " + adjusted.Description

	default: // "balanced" or any other value
		// Keep original analysis as-is
		adjusted.Description = "[Balanced Mode] " + adjusted.Description
	}

	return &adjusted
}

// Domain list management utilities (shared between whitelist and blacklist)

// getDomainList is a generic function to get domains from either whitelist or blacklist
func (s *PhishingDetectorService) getDomainList(ctx context.Context, userID, collectionName string, result interface{}) ([]string, error) {
	collection := s.db.Collection(collectionName)

	err := collection.FindOne(ctx, bson.M{"userId": userID}).Decode(result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return []string{}, nil // Return empty slice if no list exists
		}
		return nil, err
	}

	// Use reflection to get domains field
	switch v := result.(type) {
	case *models.UserWhitelist:
		return v.Domains, nil
	case *models.UserBlacklist:
		return v.Domains, nil
	default:
		return nil, fmt.Errorf("unsupported domain list type")
	}
}

// Whitelist management methods

// GetUserWhitelist returns the user's whitelist
func (s *PhishingDetectorService) GetUserWhitelist(ctx context.Context, userID string) ([]string, error) {
	var whitelist models.UserWhitelist
	return s.getDomainList(ctx, userID, "user_whitelists", &whitelist)
}

// addToDomainList is a generic function to add domains to either whitelist or blacklist
func (s *PhishingDetectorService) addToDomainList(ctx context.Context, userID, domain, collectionName, listType string, createNew interface{}) error {
	collection := s.db.Collection(collectionName)

	// Check if list exists for user
	var existing bson.M
	err := collection.FindOne(ctx, bson.M{"userId": userID}).Decode(&existing)

	if err == mongo.ErrNoDocuments {
		// Create new list
		_, err = collection.InsertOne(ctx, createNew)
		return err
	} else if err != nil {
		return err
	}

	// Check if domain already exists
	domains, ok := existing["domains"].(primitive.A)
	if ok {
		for _, existingDomain := range domains {
			if existingDomain == domain {
				return fmt.Errorf("domain already in %s", listType)
			}
		}
	}

	// Add domain to existing list
	_, err = collection.UpdateOne(
		ctx,
		bson.M{"userId": userID},
		bson.M{
			"$push": bson.M{"domains": domain},
			"$set":  bson.M{"updatedAt": time.Now()},
		},
	)

	return err
}

// removeDomainFromList is a generic function to remove domains from either whitelist or blacklist
func (s *PhishingDetectorService) removeDomainFromList(ctx context.Context, userID, domain, collectionName string) error {
	collection := s.db.Collection(collectionName)

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"userId": userID},
		bson.M{
			"$pull": bson.M{"domains": domain},
			"$set":  bson.M{"updatedAt": time.Now()},
		},
	)

	return err
}

// AddToWhitelist adds a domain to the user's whitelist
func (s *PhishingDetectorService) AddToWhitelist(ctx context.Context, userID, domain string) error {
	newWhitelist := models.UserWhitelist{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Domains:   []string{domain},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return s.addToDomainList(ctx, userID, domain, "user_whitelists", "whitelist", newWhitelist)
}

// RemoveFromWhitelist removes a domain from the user's whitelist
func (s *PhishingDetectorService) RemoveFromWhitelist(ctx context.Context, userID, domain string) error {
	return s.removeDomainFromList(ctx, userID, domain, "user_whitelists")
}

// checkDomainInList is a generic function to check if a domain exists in a domain list
func (s *PhishingDetectorService) checkDomainInList(domains []string, domain, listType string) bool {
	fmt.Printf("🔍 Checking domain in %s: domain='%s'\n", listType, domain)
	fmt.Printf("📋 %s domains: %v\n", listType, domains)

	// Normalize domain by removing www. prefix for comparison
	normalizedDomain := s.normalizeDomain(domain)
	fmt.Printf("🔄 Normalized input domain: '%s' -> '%s'\n", domain, normalizedDomain)

	for _, listDomain := range domains {
		normalizedListDomain := s.normalizeDomain(listDomain)
		fmt.Printf("🔄 Comparing: normalized='%s' vs %s='%s' (original='%s')\n", normalizedDomain, listType, normalizedListDomain, listDomain)

		// Check exact match
		if normalizedListDomain == normalizedDomain {
			fmt.Printf("✅ EXACT MATCH FOUND: '%s' == '%s'\n", normalizedListDomain, normalizedDomain)
			return true
		}

		// Check if current domain is a subdomain of list domain
		if strings.HasSuffix(normalizedDomain, "."+normalizedListDomain) {
			fmt.Printf("✅ SUBDOMAIN MATCH FOUND: '%s' is subdomain of '%s'\n", normalizedDomain, normalizedListDomain)
			return true
		}

		// Check if list domain is a subdomain of current domain
		if strings.HasSuffix(normalizedListDomain, "."+normalizedDomain) {
			fmt.Printf("✅ REVERSE SUBDOMAIN MATCH FOUND: '%s' is subdomain of '%s'\n", normalizedListDomain, normalizedDomain)
			return true
		}
	}

	fmt.Printf("❌ NO MATCH FOUND for domain '%s' in %s\n", domain, listType)
	return false
}

// IsWhitelisted checks if a domain is in the user's whitelist
func (s *PhishingDetectorService) IsWhitelisted(ctx context.Context, userID, domain string) (bool, error) {
	domains, err := s.GetUserWhitelist(ctx, userID)
	if err != nil {
		fmt.Printf("❌ Error getting user whitelist: %v\n", err)
		return false, err
	}

	return s.checkDomainInList(domains, domain, "whitelist"), nil
}

// Blacklist management methods

// GetUserBlacklist returns the user's blacklist
func (s *PhishingDetectorService) GetUserBlacklist(ctx context.Context, userID string) ([]string, error) {
	var blacklist models.UserBlacklist
	return s.getDomainList(ctx, userID, "user_blacklists", &blacklist)
}

// AddToBlacklist adds a domain to the user's blacklist
func (s *PhishingDetectorService) AddToBlacklist(ctx context.Context, userID, domain string) error {
	newBlacklist := models.UserBlacklist{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Domains:   []string{domain},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return s.addToDomainList(ctx, userID, domain, "user_blacklists", "blacklist", newBlacklist)
}

// RemoveFromBlacklist removes a domain from the user's blacklist
func (s *PhishingDetectorService) RemoveFromBlacklist(ctx context.Context, userID, domain string) error {
	return s.removeDomainFromList(ctx, userID, domain, "user_blacklists")
}

// IsBlacklisted checks if a domain is in the user's blacklist
func (s *PhishingDetectorService) IsBlacklisted(ctx context.Context, userID, domain string) (bool, error) {
	domains, err := s.GetUserBlacklist(ctx, userID)
	if err != nil {
		fmt.Printf("❌ Error getting user blacklist: %v\n", err)
		return false, err
	}

	return s.checkDomainInList(domains, domain, "blacklist"), nil
}

// Legacy whitelist checking (keeping for backward compatibility)
func (s *PhishingDetectorService) isWhitelistedLegacy(ctx context.Context, userID, domain string) (bool, error) {
	domains, err := s.GetUserWhitelist(ctx, userID)
	if err != nil {
		return false, err
	}

	normalizedDomain := s.normalizeDomain(domain)

	for _, whitelistedDomain := range domains {
		normalizedWhitelisted := s.normalizeDomain(whitelistedDomain)

		// Check exact match
		if normalizedWhitelisted == normalizedDomain {
			return true, nil
		}

		// Check if current domain is a subdomain of whitelisted domain
		if strings.HasSuffix(normalizedDomain, "."+normalizedWhitelisted) {
			return true, nil
		}

		// Check if whitelisted domain is a subdomain of current domain
		if strings.HasSuffix(normalizedWhitelisted, "."+normalizedDomain) {
			return true, nil
		}
	}

	return false, nil
}

// normalizeDomain removes www. prefix and converts to lowercase
func (s *PhishingDetectorService) normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	if strings.HasPrefix(domain, "www.") {
		return domain[4:]
	}
	return domain
}

func (s *PhishingDetectorService) GetDomainReputation(ctx context.Context, domain string) (*models.DomainReputation, error) {
	domainsCollection := database.GetDomainsCollection()

	var domainRep models.DomainReputation
	filter := bson.M{"domain": domain}

	err := domainsCollection.FindOne(ctx, filter).Decode(&domainRep)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("domain reputation not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get domain reputation: %w", err)
	}

	return &domainRep, nil
}

func (s *PhishingDetectorService) GetAnalysisHistory(ctx context.Context, userID string, limit int) ([]models.URLAnalysis, error) {
	analysesCollection := database.GetAnalysesCollection()

	// Filter by user ID
	filter := bson.M{"userId": userID}

	opts := options.Find().
		SetSort(bson.D{{Key: "createdAt", Value: -1}}).
		SetLimit(int64(limit))

	cursor, err := analysesCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get analysis history: %w", err)
	}
	defer cursor.Close(ctx)

	var analyses []models.URLAnalysis
	if err = cursor.All(ctx, &analyses); err != nil {
		return nil, fmt.Errorf("failed to decode analysis history: %w", err)
	}

	return analyses, nil
}

// GetDatabase returns the database connection for use by other services
func (s *PhishingDetectorService) GetDatabase() *mongo.Database {
	return s.db
}
