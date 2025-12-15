package services

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"phishing-detector/internal/models"
	"strings"
	"time"
)

// ExportService handles data export functionality
type ExportService struct{}

// ExportFormat represents supported export formats
type ExportFormat string

const (
	FormatCSV  ExportFormat = "csv"
	FormatJSON ExportFormat = "json"
)

// ExportRequest represents export parameters
type ExportRequest struct {
	Format      ExportFormat `json:"format"`
	DateFrom    *time.Time   `json:"dateFrom,omitempty"`
	DateTo      *time.Time   `json:"dateTo,omitempty"`
	Limit       int          `json:"limit"`
	UserID      string       `json:"userId"`
	OnlyThreats bool         `json:"onlyThreats"`
}

// ExportResponse represents export result
type ExportResponse struct {
	Content     string    `json:"content,omitempty"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"contentType"`
	Count       int       `json:"count"`
	ExportedAt  time.Time `json:"exportedAt"`
}

// NewExportService creates a new export service
func NewExportService() *ExportService {
	return &ExportService{}
}

// ExportAnalysisHistory exports analysis history in the specified format
func (e *ExportService) ExportAnalysisHistory(analyses []models.URLAnalysis, req ExportRequest) (*ExportResponse, error) {
	if len(analyses) == 0 {
		return &ExportResponse{
			Content:     "",
			Filename:    e.generateFilename(req.Format),
			ContentType: e.getContentType(req.Format),
			Count:       0,
			ExportedAt:  time.Now().UTC(),
		}, nil
	}

	// Filter analyses based on request parameters
	filteredAnalyses := e.filterAnalyses(analyses, req)

	switch req.Format {
	case FormatCSV:
		content, err := e.generateCSV(filteredAnalyses)
		if err != nil {
			return nil, err
		}
		return &ExportResponse{
			Content:     content,
			Filename:    e.generateFilename(FormatCSV),
			ContentType: "text/csv",
			Count:       len(filteredAnalyses),
			ExportedAt:  time.Now().UTC(),
		}, nil

	case FormatJSON:
		content, err := e.generateJSON(filteredAnalyses)
		if err != nil {
			return nil, err
		}
		return &ExportResponse{
			Content:     content,
			Filename:    e.generateFilename(FormatJSON),
			ContentType: "application/json",
			Count:       len(filteredAnalyses),
			ExportedAt:  time.Now().UTC(),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported export format: %s", req.Format)
	}
}

// generateCSV creates CSV content from analyses
func (e *ExportService) generateCSV(analyses []models.URLAnalysis) (string, error) {
	var csvContent strings.Builder
	writer := csv.NewWriter(&csvContent)

	// Write header
	header := []string{
		"Date",
		"URL",
		"Domain",
		"Is Phishing",
		"Risk Score",
		"Confidence",
		"Description",
		"Threats",
		"Recommendation",
		"Analysis Time (ms)",
		"AI Model",
		"User Agent",
	}

	if err := writer.Write(header); err != nil {
		return "", fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows
	for _, analysis := range analyses {
		row := []string{
			analysis.CreatedAt.Format("2006-01-02 15:04:05"),
			analysis.URL,
			analysis.Domain,
			fmt.Sprintf("%t", analysis.IsPhishing),
			fmt.Sprintf("%d", analysis.RiskScore),
			fmt.Sprintf("%.2f", analysis.Confidence),
			analysis.Description,
			strings.Join(analysis.Threats, "; "),
			analysis.Recommendation,
			fmt.Sprintf("%.2f", float64(analysis.AnalysisTime)/1000000), // Convert to milliseconds
			analysis.AIModelUsed,
			analysis.UserAgent,
		}

		if err := writer.Write(row); err != nil {
			return "", fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("CSV writer error: %w", err)
	}

	return csvContent.String(), nil
}

// generateJSON creates JSON content from analyses
func (e *ExportService) generateJSON(analyses []models.URLAnalysis) (string, error) {
	exportData := map[string]interface{}{
		"export_info": map[string]interface{}{
			"exported_at": time.Now().UTC(),
			"format":      "json",
			"count":       len(analyses),
		},
		"analyses": analyses,
	}

	jsonBytes, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(jsonBytes), nil
}

// filterAnalyses filters analyses based on export request parameters
func (e *ExportService) filterAnalyses(analyses []models.URLAnalysis, req ExportRequest) []models.URLAnalysis {
	filtered := make([]models.URLAnalysis, 0)

	for _, analysis := range analyses {
		// Filter by date range
		if req.DateFrom != nil && analysis.CreatedAt.Before(*req.DateFrom) {
			continue
		}
		if req.DateTo != nil && analysis.CreatedAt.After(*req.DateTo) {
			continue
		}

		// Filter by threats only
		if req.OnlyThreats && !analysis.IsPhishing {
			continue
		}

		filtered = append(filtered, analysis)
	}

	// Apply limit
	if req.Limit > 0 && len(filtered) > req.Limit {
		filtered = filtered[:req.Limit]
	}

	return filtered
}

// generateFilename creates a filename for export
func (e *ExportService) generateFilename(format ExportFormat) string {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	return fmt.Sprintf("phishing_analysis_history_%s.%s", timestamp, string(format))
}

// getContentType returns the content type for the format
func (e *ExportService) getContentType(format ExportFormat) string {
	switch format {
	case FormatCSV:
		return "text/csv"
	case FormatJSON:
		return "application/json"
	default:
		return "text/plain"
	}
}

// GetSupportedFormats returns all supported export formats
func (e *ExportService) GetSupportedFormats() []ExportFormat {
	return []ExportFormat{FormatCSV, FormatJSON}
}

// ValidateExportRequest validates export request parameters
func (e *ExportService) ValidateExportRequest(req ExportRequest) error {
	if req.Format != FormatCSV && req.Format != FormatJSON {
		return fmt.Errorf("unsupported format: %s. Supported formats: csv, json", req.Format)
	}

	if req.Limit < 0 || req.Limit > 10000 {
		return fmt.Errorf("limit must be between 0 and 10000")
	}

	if req.DateFrom != nil && req.DateTo != nil && req.DateFrom.After(*req.DateTo) {
		return fmt.Errorf("dateFrom cannot be after dateTo")
	}

	return nil
}
