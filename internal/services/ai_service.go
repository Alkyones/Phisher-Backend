package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type AIService struct {
	apiKey  string
	model   string
	baseURL string
}

type AIAnalysisRequest struct {
	URL              string `json:"url"`
	Domain           string `json:"domain"`
	PageContent      string `json:"pageContent,omitempty"`
	SSLInfo          string `json:"sslInfo,omitempty"`
	DNSInfo          string `json:"dnsInfo,omitempty"`
	RegistrationInfo string `json:"registrationInfo,omitempty"`
}

type AIAnalysisResponse struct {
	IsPhishing     bool     `json:"isPhishing"`
	RiskScore      int      `json:"riskScore"`
	Confidence     float64  `json:"confidence"`
	Description    string   `json:"description"`
	Threats        []string `json:"threats"`
	Recommendation string   `json:"recommendation"`
}

// Gemini API request/response structures
type GeminiRequest struct {
	Contents         []GeminiContent `json:"contents"`
	GenerationConfig GeminiConfig    `json:"generationConfig"`
}

type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiConfig struct {
	Temperature     float64 `json:"temperature"`
	MaxOutputTokens int     `json:"maxOutputTokens"`
}

type GeminiResponse struct {
	Candidates []GeminiCandidate `json:"candidates"`
}

type GeminiCandidate struct {
	Content GeminiContent `json:"content"`
}

func NewAIService(apiKey string) *AIService {
	return &AIService{
		apiKey:  apiKey,
		model:   "gemini-2.5-flash",
		baseURL: "https://generativelanguage.googleapis.com/v1beta/models/",
	}
}

func (s *AIService) AnalyzeURL(ctx context.Context, request AIAnalysisRequest) (*AIAnalysisResponse, error) {
	// Create enhanced analysis prompt
	prompt := s.buildEnhancedAnalysisPrompt(request)

	// Combine system and user prompts
	fullPrompt := s.getSystemPrompt() + "\n\n" + prompt

	// Create request body for Gemini
	reqBody := GeminiRequest{
		Contents: []GeminiContent{
			{
				Parts: []GeminiPart{
					{Text: fullPrompt},
				},
			},
		},
		GenerationConfig: GeminiConfig{
			Temperature:     0.1,
			MaxOutputTokens: 1000,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make HTTP request to Gemini API
	url := s.baseURL + s.model + ":generateContent?key=" + s.apiKey
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error: %d - %s", resp.StatusCode, string(body))
	}

	// Parse Gemini response
	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response from AI")
	}

	responseText := geminiResp.Candidates[0].Content.Parts[0].Text

	result, err := s.parseEnhancedAIResponse(responseText)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	return result, nil
}

func (s *AIService) getSystemPrompt() string {
	return `You are an expert cybersecurity AI specialized in phishing detection and URL security analysis.

RESPONSE FORMAT (use this exact structure):
STATUS: [SAFE/SUSPICIOUS/PHISHING]
RISK_SCORE: [0-100]
CONFIDENCE: [0.0-1.0]
THREATS: [comma-separated list or "none"]
DESCRIPTION: [detailed analysis]
RECOMMENDATION: [action to take]

ANALYSIS CRITERIA:
1. DOMAIN ANALYSIS:
   - Check for typosquatting/brand impersonation
   - Suspicious TLDs (.tk, .ml, .ga, .cf)
   - Domain age and reputation
   - Subdomain abuse patterns

2. URL STRUCTURE:
   - Suspicious paths (wp-content, admin, login)
   - File extensions in wrong contexts
   - Parameter manipulation
   - URL shortening services

3. CONTENT INDICATORS:
   - Social engineering keywords
   - Urgency/fear tactics
   - Credential harvesting patterns
   - Fake security warnings

4. TECHNICAL INDICATORS:
   - HTTPS implementation
   - Certificate anomalies
   - Redirect chains
   - JavaScript obfuscation

Provide specific, actionable insights with confidence scores.`
}

func (s *AIService) buildEnhancedAnalysisPrompt(request AIAnalysisRequest) string {
	return fmt.Sprintf(`SECURITY ANALYSIS REQUEST:

URL: %s
DOMAIN: %s

PLEASE ANALYZE FOR:

1. PHISHING INDICATORS:
   - Domain spoofing (typosquatting)
   - Suspicious subdomain patterns
   - Brand impersonation attempts
   - URL parameter manipulation

2. TECHNICAL RED FLAGS:
   - Suspicious file paths
   - CMS exploitation patterns
   - Directory traversal attempts
   - Script injection indicators

3. SOCIAL ENGINEERING:
   - Urgency/scarcity tactics
   - Authority impersonation
   - Credential harvesting setup
   - Fake security alerts

4. REPUTATION FACTORS:
   - Known malicious patterns
   - Legitimate service mimicry
   - Trust signal absence

Provide detailed analysis with specific threat identification and confidence scoring.`, request.URL, request.Domain)
}

func (s *AIService) parseEnhancedAIResponse(content string) (*AIAnalysisResponse, error) {
	response := &AIAnalysisResponse{
		IsPhishing: false,
		RiskScore:  0,
		Confidence: 0.0,
		Threats:    []string{},
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Parse STATUS
		if strings.HasPrefix(line, "STATUS:") {
			status := strings.TrimSpace(strings.TrimPrefix(line, "STATUS:"))
			response.IsPhishing = strings.Contains(strings.ToUpper(status), "PHISHING")
		}
		
		// Parse RISK_SCORE
		if strings.HasPrefix(line, "RISK_SCORE:") {
			scoreStr := strings.TrimSpace(strings.TrimPrefix(line, "RISK_SCORE:"))
			if score, err := strconv.Atoi(scoreStr); err == nil {
				response.RiskScore = score
			}
		}
		
		// Parse CONFIDENCE
		if strings.HasPrefix(line, "CONFIDENCE:") {
			confStr := strings.TrimSpace(strings.TrimPrefix(line, "CONFIDENCE:"))
			if conf, err := strconv.ParseFloat(confStr, 64); err == nil {
				response.Confidence = conf
			}
		}
		
		// Parse THREATS
		if strings.HasPrefix(line, "THREATS:") {
			threatsStr := strings.TrimSpace(strings.TrimPrefix(line, "THREATS:"))
			if threatsStr != "" && threatsStr != "none" {
				threats := strings.Split(threatsStr, ",")
				for _, threat := range threats {
					threat = strings.TrimSpace(threat)
					if threat != "" {
						response.Threats = append(response.Threats, threat)
					}
				}
			}
		}
		
		// Parse DESCRIPTION
		if strings.HasPrefix(line, "DESCRIPTION:") {
			response.Description = strings.TrimSpace(strings.TrimPrefix(line, "DESCRIPTION:"))
		}
		
		// Parse RECOMMENDATION
		if strings.HasPrefix(line, "RECOMMENDATION:") {
			response.Recommendation = strings.TrimSpace(strings.TrimPrefix(line, "RECOMMENDATION:"))
		}
	}

	// Fallback parsing if structured format failed
	if response.Description == "" {
		response.Description = content
		
		// Set defaults based on content analysis
		contentLower := strings.ToLower(content)
		if strings.Contains(contentLower, "phishing") || strings.Contains(contentLower, "malicious") {
			response.IsPhishing = true
			if response.RiskScore == 0 {
				response.RiskScore = 75
			}
		}
		
		if response.Confidence == 0.0 {
			response.Confidence = 0.8
		}
		
		if response.Recommendation == "" {
			if response.IsPhishing {
				response.Recommendation = "Block this URL - potential security threat detected"
			} else {
				response.Recommendation = "URL appears safe based on analysis"
			}
		}
	}

	return response, nil
}

// FallbackAnalysis provides rule-based analysis when AI fails
func (s *AIService) FallbackAnalysis(request AIAnalysisRequest) *AIAnalysisResponse {
	result := &AIAnalysisResponse{
		IsPhishing: false,
		RiskScore:  0,
		Confidence: 0.7,
		Threats:    []string{},
	}

	domain := strings.ToLower(request.Domain)
	url := strings.ToLower(request.URL)

	// Basic rule-based checks
	riskFactors := 0

	// Check for suspicious TLDs
	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".info", ".biz", ".click"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			riskFactors += 20
			result.Threats = append(result.Threats, "Suspicious TLD: "+tld)
		}
	}

	// Check for URL shorteners
	shorteners := []string{"bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.link"}
	for _, shortener := range shorteners {
		if strings.Contains(domain, shortener) {
			riskFactors += 15
			result.Threats = append(result.Threats, "URL shortener detected")
		}
	}

	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"verify", "secure", "update", "login", "account", "suspended",
		"paypal", "amazon", "microsoft", "google", "apple", "facebook",
	}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(url, pattern) && !strings.Contains(domain, pattern) {
			riskFactors += 10
			result.Threats = append(result.Threats, "Suspicious keyword in URL")
		}
	}

	// Check for WordPress/CMS exploitation patterns
	wordPressPatterns := []string{
		"/wp-includes/", "/wp-content/", "/wp-admin/",
		"/tinymce/", "/themes/advanced/", "/plugins/",
		"/js/tinymce/", "/editor/", "/fckeditor/",
	}
	for _, pattern := range wordPressPatterns {
		if strings.Contains(url, pattern) {
			riskFactors += 40
			result.Threats = append(result.Threats, "WordPress/CMS path exploitation detected")
		}
	}

	// Check for suspicious file extensions in image directories
	if strings.Contains(url, "/img/") && (strings.HasSuffix(url, ".htm") || strings.HasSuffix(url, ".html") || strings.HasSuffix(url, ".php")) {
		riskFactors += 25
		result.Threats = append(result.Threats, "Suspicious file extension in image directory")
	}

	// Check for IP addresses in URL
	if strings.Contains(url, "://") {
		parts := strings.Split(url, "://")
		if len(parts) > 1 {
			hostPart := strings.Split(parts[1], "/")[0]
			if strings.Count(hostPart, ".") >= 3 && !strings.ContainsAny(hostPart, "abcdefghijklmnopqrstuvwxyz") {
				riskFactors += 30
				result.Threats = append(result.Threats, "IP address used instead of domain")
			}
		}
	}

	// Set final risk score
	result.RiskScore = riskFactors
	if result.RiskScore > 100 {
		result.RiskScore = 100
	}

	result.IsPhishing = result.RiskScore > 60

	// Set description and recommendation
	if result.IsPhishing {
		result.Description = "Multiple suspicious patterns detected indicating potential phishing attempt"
		result.Recommendation = "Avoid visiting this website - potential security risk"
	} else if result.RiskScore > 30 {
		result.Description = "Some suspicious elements detected, exercise caution"
		result.Recommendation = "Be cautious when visiting this website and verify its legitimacy"
	} else {
		result.Description = "No obvious threats detected"
		result.Recommendation = "Website appears safe to visit"
	}

	return result
}