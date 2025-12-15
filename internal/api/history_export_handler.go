package api

import (
	"fmt"
	"net/http"
	"phishing-detector/internal/services"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// HistoryExportHandler handles history and export related endpoints
type HistoryExportHandler struct {
	historyService  *services.HistoryService
	exportService   *services.ExportService
	phishingService *services.PhishingDetectorService
}

// NewHistoryExportHandler creates a new history and export handler
func NewHistoryExportHandler(
	historyService *services.HistoryService,
	exportService *services.ExportService,
	phishingService *services.PhishingDetectorService,
) *HistoryExportHandler {
	return &HistoryExportHandler{
		historyService:  historyService,
		exportService:   exportService,
		phishingService: phishingService,
	}
}

// GetAnalysisHistory handles GET /history with advanced filtering and pagination
func (h *HistoryExportHandler) GetAnalysisHistory(c *gin.Context, generateUserID func(*gin.Context) string) {
	// Parse query parameters
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")
	onlyThreatsStr := c.DefaultQuery("onlyThreats", "false")
	domain := c.Query("domain")
	minRiskStr := c.Query("minRisk")
	maxRiskStr := c.Query("maxRisk")
	sortBy := c.DefaultQuery("sortBy", "createdAt")
	sortOrder := c.DefaultQuery("sortOrder", "desc")
	dateFromStr := c.Query("dateFrom")
	dateToStr := c.Query("dateTo")

	// Parse and validate parameters
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 1000 {
		limit = 50
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	onlyThreats := strings.ToLower(onlyThreatsStr) == "true"

	var minRisk, maxRisk int
	if minRiskStr != "" {
		minRisk, _ = strconv.Atoi(minRiskStr)
	}
	if maxRiskStr != "" {
		maxRisk, _ = strconv.Atoi(maxRiskStr)
	}

	// Parse dates
	var dateFrom, dateTo *time.Time
	if dateFromStr != "" {
		if parsed, err := time.Parse("2006-01-02", dateFromStr); err == nil {
			dateFrom = &parsed
		}
	}
	if dateToStr != "" {
		if parsed, err := time.Parse("2006-01-02", dateToStr); err == nil {
			// Set to end of day
			endOfDay := parsed.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			dateTo = &endOfDay
		}
	}

	// Get userId from query parameter or generate one
	userID := c.Query("userId")
	if userID == "" {
		userID = generateUserID(c)
		fmt.Printf("🔑 Generated UserID for history: %s\n", userID)
	} else {
		fmt.Printf("🔑 Using provided UserID for history: %s\n", userID)
	}

	// Create filter
	filter := services.HistoryFilter{
		UserID:      userID,
		DateFrom:    dateFrom,
		DateTo:      dateTo,
		OnlyThreats: onlyThreats,
		Domain:      domain,
		MinRisk:     minRisk,
		MaxRisk:     maxRisk,
		Limit:       limit,
		Offset:      offset,
		SortBy:      sortBy,
		SortOrder:   sortOrder,
	}

	// Get history
	history, err := h.historyService.GetAnalysisHistory(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve history",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, history)
}

// GetHistoryStats handles GET /history/stats
func (h *HistoryExportHandler) GetHistoryStats(c *gin.Context, generateUserID func(*gin.Context) string) {
	// Get userId from query parameter or generate one
	userID := c.Query("userId")
	if userID == "" {
		userID = generateUserID(c)
	}

	stats, err := h.historyService.GetHistoryStats(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve history statistics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// ExportAnalysisHistory handles GET /history/export
func (h *HistoryExportHandler) ExportAnalysisHistory(c *gin.Context, generateUserID func(*gin.Context) string) {
	// Parse query parameters
	format := c.DefaultQuery("format", "csv")
	limitStr := c.DefaultQuery("limit", "1000")
	onlyThreatsStr := c.DefaultQuery("onlyThreats", "false")
	dateFromStr := c.Query("dateFrom")
	dateToStr := c.Query("dateTo")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 10000 {
		limit = 1000
	}

	onlyThreats := strings.ToLower(onlyThreatsStr) == "true"

	// Parse dates
	var dateFrom, dateTo *time.Time
	if dateFromStr != "" {
		if parsed, err := time.Parse("2006-01-02", dateFromStr); err == nil {
			dateFrom = &parsed
		}
	}
	if dateToStr != "" {
		if parsed, err := time.Parse("2006-01-02", dateToStr); err == nil {
			endOfDay := parsed.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			dateTo = &endOfDay
		}
	}

	// Get userId from query parameter or generate one
	userID := c.Query("userId")
	if userID == "" {
		userID = generateUserID(c)
	}

	// Create export request
	exportReq := services.ExportRequest{
		Format:      services.ExportFormat(format),
		DateFrom:    dateFrom,
		DateTo:      dateTo,
		Limit:       limit,
		UserID:      userID,
		OnlyThreats: onlyThreats,
	}

	// Validate request
	if err := h.exportService.ValidateExportRequest(exportReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid export parameters",
			"details": err.Error(),
		})
		return
	}

	// Get history data using legacy method for compatibility
	analyses, err := h.phishingService.GetAnalysisHistory(c.Request.Context(), userID, limit*2) // Get more to ensure we have enough after filtering
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve history for export",
			"details": err.Error(),
		})
		return
	}

	// Export data
	exportResult, err := h.exportService.ExportAnalysisHistory(analyses, exportReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to export data",
			"details": err.Error(),
		})
		return
	}

	// Set response headers
	c.Header("Content-Type", exportResult.ContentType)
	c.Header("Content-Disposition", "attachment; filename="+exportResult.Filename)

	// Return content based on format
	if exportResult.ContentType == "application/json" {
		// For JSON, we can return the structured response
		c.Header("Content-Disposition", "inline; filename="+exportResult.Filename) // Allow inline viewing
		c.String(http.StatusOK, exportResult.Content)
	} else {
		// For CSV, force download
		c.String(http.StatusOK, exportResult.Content)
	}
}

// DeleteHistoryItems handles DELETE /history
func (h *HistoryExportHandler) DeleteHistoryItems(c *gin.Context, generateUserID func(*gin.Context) string) {
	var req struct {
		AnalysisIDs []string `json:"analysisIds" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Get userId from query parameter or generate one
	userID := c.Query("userId")
	if userID == "" {
		userID = generateUserID(c)
	}

	err := h.historyService.DeleteAnalysisHistory(c.Request.Context(), userID, req.AnalysisIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete history items",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      "History items deleted successfully",
		"deletedCount": len(req.AnalysisIDs),
	})
}

// ClearAllHistory handles DELETE /history/all
func (h *HistoryExportHandler) ClearAllHistory(c *gin.Context, generateUserID func(*gin.Context) string) {
	// Get userId from query parameter or generate one
	userID := c.Query("userId")
	if userID == "" {
		userID = generateUserID(c)
	}

	err := h.historyService.ClearAllHistory(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to clear history",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "All history cleared successfully",
	})
}

// GetExportFormats handles GET /export/formats
func (h *HistoryExportHandler) GetExportFormats(c *gin.Context) {
	formats := h.exportService.GetSupportedFormats()

	c.JSON(http.StatusOK, gin.H{
		"formats": formats,
		"descriptions": map[string]string{
			"csv":  "Comma-separated values format, suitable for spreadsheet applications",
			"json": "JavaScript Object Notation format, suitable for programmatic access",
		},
	})
}
