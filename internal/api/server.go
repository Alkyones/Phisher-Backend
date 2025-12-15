package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"phishing-detector/internal/config"
	"phishing-detector/internal/services"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Server struct {
	config               *config.Config
	phishingService      *services.PhishingDetectorService
	historyExportHandler *HistoryExportHandler
	router               *gin.Engine
}

type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewServer(cfg *config.Config, phishingService *services.PhishingDetectorService) *Server {
	// Initialize additional services
	historyService := services.NewHistoryService(phishingService.GetDatabase())
	exportService := services.NewExportService()
	historyExportHandler := NewHistoryExportHandler(historyService, exportService, phishingService)

	server := &Server{
		config:               cfg,
		phishingService:      phishingService,
		historyExportHandler: historyExportHandler,
	}

	server.setupRouter()
	return server
}

func (s *Server) setupRouter() {
	if s.config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	s.router = gin.New()

	// Middleware
	s.router.Use(gin.Logger())
	s.router.Use(gin.Recovery())

	// CORS configuration
	corsConfig := cors.Config{
		AllowOrigins:     []string{"*"}, // For Chrome extension
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	s.router.Use(cors.New(corsConfig))

	// Rate limiting middleware (simplified)
	s.router.Use(s.rateLimitMiddleware())

	// Routes
	v1 := s.router.Group("/api/v1")
	{
		v1.GET("/health", s.healthCheck)
		v1.POST("/analyze", s.analyzeURL)
		v1.POST("/report", s.reportPhishing)
		v1.GET("/domain/:domain/reputation", s.getDomainReputation)

		// History and Export endpoints
		v1.GET("/history", s.getAnalysisHistoryWrapper)

		v1.GET("/history/stats", s.getHistoryStatsWrapper)
		v1.GET("/history/export", s.exportAnalysisHistoryWrapper)
		v1.DELETE("/history", s.deleteHistoryItemsWrapper)
		v1.DELETE("/history/all", s.clearAllHistoryWrapper)
		v1.GET("/export/formats", s.historyExportHandler.GetExportFormats)

		v1.GET("/stats", s.getSystemStats)

		// Whitelist management
		v1.GET("/whitelist", s.getWhitelist)
		v1.POST("/whitelist", s.addToWhitelist)
		v1.DELETE("/whitelist/:domain", s.removeFromWhitelist)

		// Blacklist management
		v1.GET("/blacklist", s.getBlacklist)
		v1.POST("/blacklist", s.addToBlacklist)
		v1.DELETE("/blacklist/:domain", s.removeFromBlacklist)
	}

	// Legacy routes for backward compatibility
	s.router.GET("/health", s.healthCheck)
	s.router.POST("/analyze", s.analyzeURL)
	s.router.POST("/report", s.reportPhishing)
	s.router.GET("/history/export", s.exportAnalysisHistoryWrapper)

	// Legacy whitelist routes
	s.router.GET("/whitelist", s.getWhitelist)
	s.router.POST("/whitelist", s.addToWhitelist)
	s.router.DELETE("/whitelist/:domain", s.removeFromWhitelist)
}

func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC(),
		Version:   "1.0.0",
	})
}

func (s *Server) analyzeURL(c *gin.Context) {
	var req services.AnalysisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	// Validate URL length
	if len(req.URL) > s.config.MaxURLLength {
		s.respondError(c, http.StatusBadRequest, "URL too long", "URL exceeds maximum length limit")
		return
	}

	// Get client IP
	clientIP := s.getClientIP(c)

	// Generate user ID from IP and User-Agent only if not provided
	userAgent := c.GetHeader("User-Agent")
	if req.UserAgent == "" {
		req.UserAgent = userAgent
	}

	// Only generate UserID if not provided by client
	if req.UserID == "" {
		req.UserID = s.generateUserID(clientIP, userAgent)
		fmt.Printf("🔑 Generated UserID: %s (from IP: %s, UA: %s)\n", req.UserID, clientIP, userAgent)
	} else {
		fmt.Printf("🔑 Using provided UserID: %s\n", req.UserID)
	}

	// Perform analysis
	result, err := s.phishingService.AnalyzeURL(c.Request.Context(), req, clientIP)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Analysis failed", err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}

func (s *Server) reportPhishing(c *gin.Context) {
	var req services.ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	clientIP := s.getClientIP(c)
	userAgent := c.GetHeader("User-Agent")
	userID := s.generateUserID(clientIP, userAgent)

	err := s.phishingService.ReportPhishing(c.Request.Context(), req, clientIP, userID)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Failed to submit report", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Report submitted successfully",
	})
}

func (s *Server) getDomainReputation(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		s.respondError(c, http.StatusBadRequest, "Domain required", "Domain parameter is required")
		return
	}

	reputation, err := s.phishingService.GetDomainReputation(c.Request.Context(), domain)
	if err != nil {
		s.respondError(c, http.StatusNotFound, "Domain not found", "No reputation data available for this domain")
		return
	}

	c.JSON(http.StatusOK, reputation)
}

// Wrapper methods to maintain compatibility and pass generateUserID function
func (s *Server) getAnalysisHistoryWrapper(c *gin.Context) {
	s.historyExportHandler.GetAnalysisHistory(c, s.generateUserIDFromContext)
}

func (s *Server) getHistoryStatsWrapper(c *gin.Context) {
	s.historyExportHandler.GetHistoryStats(c, s.generateUserIDFromContext)
}

func (s *Server) exportAnalysisHistoryWrapper(c *gin.Context) {
	s.historyExportHandler.ExportAnalysisHistory(c, s.generateUserIDFromContext)
}

func (s *Server) deleteHistoryItemsWrapper(c *gin.Context) {
	s.historyExportHandler.DeleteHistoryItems(c, s.generateUserIDFromContext)
}

func (s *Server) clearAllHistoryWrapper(c *gin.Context) {
	s.historyExportHandler.ClearAllHistory(c, s.generateUserIDFromContext)
}

// Helper method to generate user ID from context
func (s *Server) generateUserIDFromContext(c *gin.Context) string {
	clientIP := s.getClientIP(c)
	userAgent := c.GetHeader("User-Agent")
	return s.generateUserID(clientIP, userAgent)
}

func (s *Server) getAnalysisHistoryLegacy(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 1000 {
		limit = 50
	}

	// Generate user ID from client IP and User-Agent
	clientIP := s.getClientIP(c)
	userAgent := c.GetHeader("User-Agent")
	userID := s.generateUserID(clientIP, userAgent)

	history, err := s.phishingService.GetAnalysisHistory(c.Request.Context(), userID, limit)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Failed to retrieve history", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"analyses": history,
		"count":    len(history),
	})
}

func (s *Server) getSystemStats(c *gin.Context) {
	// This would typically fetch from a metrics service
	stats := gin.H{
		"total_analyses":    1000, // Replace with actual metrics
		"phishing_detected": 50,
		"safe_urls":         950,
		"uptime":            time.Since(time.Now().Add(-24 * time.Hour)).String(),
		"avg_response_time": "150ms",
	}

	c.JSON(http.StatusOK, stats)
}

func (s *Server) rateLimitMiddleware() gin.HandlerFunc {
	// Simplified rate limiting - in production use Redis or similar
	clients := make(map[string][]time.Time)

	return func(c *gin.Context) {
		clientIP := s.getClientIP(c)
		now := time.Now()

		// Clean old entries
		if requests, exists := clients[clientIP]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if now.Sub(reqTime) < time.Minute {
					validRequests = append(validRequests, reqTime)
				}
			}
			clients[clientIP] = validRequests
		}

		// Check rate limit (100 requests per minute)
		if len(clients[clientIP]) >= s.config.RateLimit {
			s.respondError(c, http.StatusTooManyRequests, "Rate limit exceeded", "Too many requests, please try again later")
			c.Abort()
			return
		}

		// Add current request
		clients[clientIP] = append(clients[clientIP], now)
		c.Next()
	}
}

func (s *Server) getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header first
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	return c.ClientIP()
}

func (s *Server) generateUserID(clientIP, userAgent string) string {
	// Create a hash from IP and User-Agent for consistent user identification
	data := clientIP + "|" + userAgent
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (s *Server) respondError(c *gin.Context, statusCode int, message string, details string) {
	c.JSON(statusCode, ErrorResponse{
		Error:   message,
		Code:    statusCode,
		Message: details,
	})
}

// WhitelistRequest represents a request to add/remove from whitelist
type WhitelistRequest struct {
	Domain string `json:"domain" binding:"required"`
	UserID string `json:"userId" binding:"required"`
}

// WhitelistResponse represents the user's whitelist
type WhitelistResponse struct {
	UserID  string   `json:"userId"`
	Domains []string `json:"domains"`
}

// BlacklistRequest represents a request to add/remove from blacklist (same structure as whitelist)
type BlacklistRequest struct {
	Domain string `json:"domain" binding:"required"`
	UserID string `json:"userId" binding:"required"`
}

// BlacklistResponse represents the user's blacklist
type BlacklistResponse struct {
	UserID  string   `json:"userId"`
	Domains []string `json:"domains"`
}

// getWhitelist returns the user's whitelist
func (s *Server) getWhitelist(c *gin.Context) {
	userID := c.Query("userId")
	if userID == "" {
		s.respondError(c, http.StatusBadRequest, "User ID required", "Missing userId parameter")
		return
	}

	whitelist, err := s.phishingService.GetUserWhitelist(c.Request.Context(), userID)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Failed to retrieve whitelist", err.Error())
		return
	}

	c.JSON(http.StatusOK, WhitelistResponse{
		UserID:  userID,
		Domains: whitelist,
	})
}

// addToWhitelist adds a domain to the user's whitelist
func (s *Server) addToWhitelist(c *gin.Context) {
	var req WhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	err := s.phishingService.AddToWhitelist(c.Request.Context(), req.UserID, req.Domain)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Failed to add domain to whitelist", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Domain added to whitelist",
		"domain":  req.Domain,
	})
}

// removeFromWhitelist removes a domain from the user's whitelist
func (s *Server) removeFromWhitelist(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		s.respondError(c, http.StatusBadRequest, "Domain required", "Missing domain parameter")
		return
	}

	var req struct {
		UserID string `json:"userId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		s.respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	err := s.phishingService.RemoveFromWhitelist(c.Request.Context(), req.UserID, domain)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Failed to remove domain from whitelist", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Domain removed from whitelist",
		"domain":  domain,
	})
}

// Blacklist management handlers

// getBlacklist returns the user's blacklist
func (s *Server) getBlacklist(c *gin.Context) {
	userID := c.Query("userId")
	if userID == "" {
		s.respondError(c, http.StatusBadRequest, "User ID required", "Missing userId parameter")
		return
	}

	blacklist, err := s.phishingService.GetUserBlacklist(c.Request.Context(), userID)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Failed to retrieve blacklist", err.Error())
		return
	}

	c.JSON(http.StatusOK, BlacklistResponse{
		UserID:  userID,
		Domains: blacklist,
	})
}

// addToBlacklist adds a domain to the user's blacklist
func (s *Server) addToBlacklist(c *gin.Context) {
	var req BlacklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	err := s.phishingService.AddToBlacklist(c.Request.Context(), req.UserID, req.Domain)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Failed to add domain to blacklist", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Domain added to blacklist",
		"domain":  req.Domain,
	})
}

// removeFromBlacklist removes a domain from the user's blacklist
func (s *Server) removeFromBlacklist(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		s.respondError(c, http.StatusBadRequest, "Domain required", "Missing domain parameter")
		return
	}

	var req struct {
		UserID string `json:"userId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		s.respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	err := s.phishingService.RemoveFromBlacklist(c.Request.Context(), req.UserID, domain)
	if err != nil {
		s.respondError(c, http.StatusInternalServerError, "Failed to remove domain from blacklist", err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Domain removed from blacklist",
		"domain":  domain,
	})
}
func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}
