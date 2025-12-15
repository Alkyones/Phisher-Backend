# Phishing URL Detector Backend

## Production-Ready Go Backend with AI-Powered Analysis

### Features
- 🤖 **Google Gemini AI Integration** (Free Tier)
- 🛡️ **Advanced Phishing Detection** with ML models
- 📊 **MongoDB Database** with comprehensive analytics
- ⚡ **High Performance** with caching and rate limiting
- 📈 **Analysis History & Export** (CSV, JSON, PDF formats)
- 🛡️ **Domain Reputation System**
- 🔄 **Whitelist/Blacklist Management**
- 📝 **Comprehensive Logging & Monitoring**
- 🚀 **Docker Support** for easy deployment
- 🌐 **CORS Support** for web integration
- 📊 **System Statistics & Metrics**

### Quick Start

1. **Set up environment**:
   ```bash
   cp .env.example .env
   # Add your Gemini API key and MongoDB URI to .env
   ```

2. **Run locally**:
   ```bash
   go run .
   ```

3. **Build and run**:
   ```bash
   ./start.sh    # Linux/macOS
   start.bat     # Windows
   ```

4. **Docker deployment**:
   ```bash
   docker build -t phishing-detector .
   docker run -p 8080:8080 phishing-detector
   ```

### API Endpoints

#### Core Analysis
- `GET /api/v1/health` - Health check with system status
- `POST /api/v1/analyze` - Analyze URL for phishing threats
- `POST /api/v1/report` - Report phishing URLs or false positives
- `GET /api/v1/domain/:domain/reputation` - Get domain reputation data
- `GET /api/v1/stats` - System statistics and performance metrics

#### Analysis History
- `GET /api/v1/history` - Retrieve analysis history with pagination
- `GET /api/v1/history/stats` - Get analysis history statistics
- `GET /api/v1/history/export` - Export history in multiple formats
- `DELETE /api/v1/history` - Delete specific history items
- `DELETE /api/v1/history/all` - Clear all analysis history
- `GET /api/v1/export/formats` - Get available export formats

#### Domain Management
- `GET /api/v1/whitelist` - Get whitelisted domains
- `POST /api/v1/whitelist` - Add domain to whitelist
- `DELETE /api/v1/whitelist/:domain` - Remove domain from whitelist
- `GET /api/v1/blacklist` - Get blacklisted domains
- `POST /api/v1/blacklist` - Add domain to blacklist
- `DELETE /api/v1/blacklist/:domain` - Remove domain from blacklist

### Environment Variables

#### Required
- `OPENAI_API_KEY` - Your Google Gemini API key
- `MONGO_URI` - MongoDB connection string (e.g., `mongodb://localhost:27017`)

#### Optional
- `PORT` - Server port (default: 8080)
- `ENVIRONMENT` - production/development (default: development)
- `DATABASE_NAME` - MongoDB database name (default: phishing_detector)
- `CORS_ORIGINS` - Allowed CORS origins (comma-separated)
- `RATE_LIMIT` - Requests per minute per IP (default: 100)
- `CACHE_TIMEOUT` - Cache timeout duration (default: 1h)
- `LOG_LEVEL` - Logging level (default: info)
- `ENABLE_METRICS` - Enable metrics collection (default: true)
- `AI_MODEL_NAME` - AI model to use (default: gemini-1.5-flash)

### Request/Response Examples

#### Analyze URL
```bash
curl -X POST http://localhost:8080/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "isPhishing": false,
  "riskScore": 15,
  "confidence": 0.95,
  "description": "Legitimate website with no suspicious indicators",
  "threats": [],
  "recommendation": "Safe to visit",
  "aiModelUsed": "gemini-1.5-flash",
  "analysisTime": 1250000000
}
```

#### Export Analysis History
```bash
curl -X GET "http://localhost:8080/api/v1/history/export?format=csv&limit=100"
```

#### Domain Management
```bash
# Add to whitelist
curl -X POST http://localhost:8080/api/v1/whitelist \
  -H "Content-Type: application/json" \
  -d '{"domain": "trusteddomain.com", "reason": "Corporate website"}'

# Check domain reputation
curl -X GET http://localhost:8080/api/v1/domain/example.com/reputation
```

### Technology Stack

- **Backend**: Go 1.24+ with Gin web framework
- **Database**: MongoDB with comprehensive indexing
- **AI/ML**: Google Gemini API integration
- **Authentication**: Rate limiting and IP-based controls
- **Containerization**: Docker with multi-stage builds
- **Monitoring**: Built-in metrics and health checks

### Key Features

#### Advanced Phishing Detection
- Multi-layered analysis using AI and heuristics
- Domain reputation scoring
- SSL certificate validation
- DNS analysis and suspicious pattern detection
- User-agent and IP tracking

#### Data Management
- Comprehensive analysis history with search/filter
- Export capabilities (CSV, JSON, PDF)
- Configurable data retention policies
- Real-time statistics and reporting

#### Security & Performance
- Rate limiting (configurable per IP)
- CORS protection with configurable origins
- Input validation and sanitization
- Caching for improved response times
- MongoDB connection pooling

### Getting Gemini API Key

1. Visit [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Sign in with Google account
3. Create new API key
4. Add to `.env` file as `OPENAI_API_KEY`

### MongoDB Setup

#### Local Development
```bash
# Using Docker
docker run -d --name mongodb -p 27017:27017 mongo:latest

# Using MongoDB Community Edition
# Download from https://www.mongodb.com/try/download/community
```

#### Cloud Options
- **MongoDB Atlas** (Recommended for production)
- **AWS DocumentDB**
- **Azure Cosmos DB**

### Project Structure
```
Phisher-Backend/
├── cmd/                    # Application entry points
├── internal/
│   ├── api/               # HTTP handlers and routes
│   ├── config/            # Configuration management
│   ├── database/          # Database connection and operations
│   ├── models/            # Data structures and schemas
│   └── services/          # Business logic
│       ├── ai_service.go         # AI/ML integration
│       ├── export_service.go     # Data export functionality
│       ├── history_service.go    # Analysis history management
│       └── phishing_detector.go  # Core detection logic
├── Dockerfile             # Container configuration
├── docker-compose.yml     # Multi-service orchestration
└── README.md              # This file
```

### Deployment Options

#### Cloud Platforms
- **Google Cloud Run** (Serverless, auto-scaling)
- **AWS ECS/Fargate** (Container orchestration)
- **Azure Container Instances**
- **Heroku** (Platform-as-a-Service)
- **Railway** (Modern PaaS)
- **Fly.io** (Global edge deployment)

#### Self-Hosted
- **Docker Compose** (Multi-container setup)
- **Kubernetes** (Enterprise orchestration)
- **VPS/Dedicated Server** (Direct deployment)

#### Example Docker Compose
```yaml
version: '3.8'
services:
  phishing-detector:
    build: .
    ports:
      - "8080:8080"
    environment:
      - MONGO_URI=mongodb://mongo:27017
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    depends_on:
      - mongo
  
  mongo:
    image: mongo:latest
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db

volumes:
  mongodb_data:
```

### Performance Optimization

- **Caching**: Intelligent caching of analysis results
- **Database Indexing**: Optimized MongoDB indexes for fast queries
- **Connection Pooling**: Efficient database connection management
- **Rate Limiting**: Configurable request throttling
- **Compression**: Gzip compression for API responses

### Monitoring & Observability

- Health check endpoints for service monitoring
- Built-in metrics collection and reporting
- Structured logging with configurable levels
- Request/response timing and performance tracking

### Security Features

- **Input Validation**: Comprehensive request validation and sanitization
- **Rate Limiting**: Configurable per-IP request throttling
- **CORS Protection**: Configurable cross-origin resource sharing
- **NoSQL Injection Prevention**: Parameterized queries and input validation
- **Error Handling**: Secure error responses without sensitive data exposure
- **SSL/TLS**: HTTPS enforcement in production
- **Authentication Ready**: Framework for API key or JWT integration

### Development

#### Prerequisites
- Go 1.24 or later
- MongoDB (local or cloud)
- Google Gemini API key

#### Setup
```bash
# Clone the repository
git clone <repository-url>
cd Phisher-Backend

# Install dependencies
go mod tidy

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Run tests
go test ./...

# Run with hot reload (optional)
go install github.com/cosmtrek/air@latest
air
```

#### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/services/...
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Support

- 📧 **Email**: [Support Email]
- 🐛 **Issues**: [GitHub Issues](issues-url)
- 📖 **Documentation**: [Wiki or Docs URL]
- 💬 **Discussions**: [GitHub Discussions or Discord]