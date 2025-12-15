# Phishing URL Detector Backend

## Production-Ready Go Backend with AI-Powered Analysis

### Features
- 🤖 **Google Gemini AI Integration** (Free Tier)
- 🛡️ **Advanced Phishing Detection**
- 📊 **SQLite Database** with analytics
- ⚡ **High Performance** with caching
- 🔄 **Rate Limiting** and security
- 📝 **Comprehensive Logging**
- 🚀 **Docker Support**

### Quick Start

1. **Set up environment**:
   ```bash
   cp .env.example .env
   # Add your Gemini API key to .env
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

- `POST /analyze` - Analyze URL for phishing
- `GET /health` - Health check
- `GET /api/v1/stats` - System statistics
- `POST /api/v1/report` - Report phishing URL

### Environment Variables

- `OPENAI_API_KEY` - Your Gemini API key
- `PORT` - Server port (default: 8080)
- `ENVIRONMENT` - production/development
- `DATABASE_URL` - SQLite database file

### Getting Gemini API Key

1. Visit [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Sign in with Google account
3. Create new API key
4. Add to `.env` file

### Deployment Options

- **Docker Container**
- **Cloud Run** (Google Cloud)
- **Heroku**
- **VPS/Dedicated Server**
- **Railway**
- **Fly.io**

### Security Features

- Input validation
- Rate limiting
- CORS protection
- SQL injection prevention
- Error handling without data exposure