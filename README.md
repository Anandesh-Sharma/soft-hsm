# HSM Edwards API

A production-ready FastAPI backend for Edwards Curve (Ed25519) key generation and digital signing using Hardware Security Module (HSM) integration.

## =� Features

- **Ed25519 Key Management**: Generate, retrieve, and securely delete Ed25519 key pairs in HSM
- **Digital Signing**: Sign data and verify signatures using EdDSA algorithm
- **HSM Integration**: Full PKCS#11 interface support with SoftHSM for development
- **Enterprise Security**: JWT authentication, API keys, rate limiting, and comprehensive audit logging
- **Production Ready**: Docker containerization, health checks, monitoring, and structured logging
- **Database**: PostgreSQL with Neon cloud database integration
- **Comprehensive API**: RESTful endpoints with OpenAPI documentation

## =� Requirements

- Python 3.11+
- PostgreSQL 15+
- HSM with PKCS#11 interface (SoftHSM for development)
- Docker & Docker Compose (for containerized deployment)

## <� Architecture

```
hsm-edwards-api/
   app/
      main.py                 # FastAPI application entry point
      config.py              # Configuration management
      database.py            # Database connection and models
      auth/                  # Authentication & authorization
      hsm/                   # HSM integration layer
      api/v1/               # API endpoints
      models/               # Database and Pydantic models
      services/             # Business logic layer
      utils/                # Utilities and helpers
   tests/                    # Test suite
   docker-compose.yml        # Development environment
   Dockerfile               # Production container
   README.md               # This file
```

## =� Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd hsm-edwards-api

# Copy environment configuration
cp .env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Database Setup (Neon)

The project is pre-configured to use Neon PostgreSQL. The database has been created with ID: `green-mouse-74012137`

Update your `.env` file with the Neon connection string:
```env
DATABASE_URL=postgresql://neondb_owner:npg_nG1vwCqSA9lU@ep-shiny-night-add803yn-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require
```

### 3. Docker Development

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down
```

### 4. Local Development

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up SoftHSM (Linux/macOS)
sudo apt-get install softhsm2  # Ubuntu/Debian
# or
brew install softhsm          # macOS

# Initialize SoftHSM token
softhsm2-util --init-token --slot 0 --label "HSM_TOKEN" --pin 1234 --so-pin 1234

# Run the application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## =' Configuration

### Environment Variables

Key configuration options in `.env`:

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost/hsm_api

# HSM Configuration
HSM_LIBRARY_PATH=/usr/lib/softhsm/libsofthsm2.so
HSM_SLOT_ID=0
HSM_PIN=1234

# JWT Security
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=RS256
JWT_EXPIRATION_HOURS=24

# API Security
SECRET_KEY=your-app-secret
MAX_REQUEST_SIZE=1048576
RATE_LIMIT_REQUESTS=100

# CORS
CORS_ORIGINS=["https://yourdomain.com"]
```

## =� API Documentation

### Base URL
```
https://your-domain.com/api/v1
```

### Authentication

The API supports two authentication methods:

**JWT Bearer Token:**
```bash
curl -H "Authorization: Bearer <jwt-token>" https://api.example.com/api/v1/keys/
```

**API Key:**
```bash
curl -H "X-API-Key: <api-key>" https://api.example.com/api/v1/keys/
```

### Key Management Endpoints

#### Generate Key Pair
```http
POST /api/v1/keys/generate
Content-Type: application/json
Authorization: Bearer <token>

{
  "purpose": "Document signing key",
  "expires_in_days": 365,
  "metadata": {
    "project": "my-project",
    "environment": "production"
  }
}
```

#### Get Key Information
```http
GET /api/v1/keys/{key_id}
Authorization: Bearer <token>
```

#### List Keys
```http
GET /api/v1/keys/?page=1&page_size=50&status=active
Authorization: Bearer <token>
```

#### Delete Key
```http
DELETE /api/v1/keys/{key_id}
Authorization: Bearer <token>
```

### Signing Operations

#### Sign Data
```http
POST /api/v1/sign/{key_id}/sign
Content-Type: application/json
Authorization: Bearer <token>

{
  "data": "SGVsbG8sIFdvcmxkIQ=="  // base64 encoded data
}
```

#### Batch Sign
```http
POST /api/v1/sign/batch-sign
Content-Type: application/json
Authorization: Bearer <token>

{
  "key_id": "uuid-here",
  "data_items": [
    "SGVsbG8sIFdvcmxkIQ==",
    "QW5vdGhlciBkb2N1bWVudA=="
  ]
}
```

#### Get Signing History
```http
GET /api/v1/sign/{key_id}/sign-history?page=1&page_size=50
Authorization: Bearer <token>
```

### Verification

#### Verify Signature
```http
POST /api/v1/verify/verify
Content-Type: application/json
Authorization: Bearer <token>

{
  "data": "SGVsbG8sIFdvcmxkIQ==",
  "signature": "base64-encoded-signature",
  "public_key": "base64-encoded-public-key"
}
```

### Health & Monitoring

#### Health Status
```http
GET /api/v1/health/status
```

#### HSM Status
```http
GET /api/v1/health/hsm-status
```

#### Readiness Check
```http
GET /api/v1/health/readiness
```

#### Liveness Check
```http
GET /api/v1/health/liveness
```

## >� Testing

### Run Tests
```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_api/test_keys.py -v
```

### Test Structure
```
tests/
   conftest.py              # Test configuration and fixtures
   test_api/               # API endpoint tests
   test_hsm/               # HSM integration tests
   test_services/          # Service layer tests
```

## = Security Features

### Authentication & Authorization
- JWT-based authentication with configurable expiration
- API key authentication for service-to-service calls
- Role-based access control (admin/user)
- Secure password hashing with bcrypt

### Input Validation
- Strict Pydantic models for all requests
- Data size limits (1MB for signing, 5MB for batch)
- Base64 validation for cryptographic data
- SQL injection prevention with SQLAlchemy ORM

### Security Headers
- HSTS for HTTPS enforcement
- CSP, X-Frame-Options, X-Content-Type-Options
- CORS configuration for allowed origins
- Request size limitations

### Rate Limiting
- 100 requests per minute per user (configurable)
- Separate limits for authentication endpoints
- IP-based and user-based rate limiting

### Audit Logging
- Comprehensive audit trail for all operations
- Correlation IDs for request tracking
- Structured JSON logging
- Security event logging

## =3 Docker Deployment

### Production Deployment
```bash
# Build production image
docker build -t hsm-edwards-api .

# Run with environment file
docker run -d \
  --name hsm-api \
  --env-file .env \
  -p 8000:8000 \
  hsm-edwards-api
```

### Docker Compose (Development)
```bash
# Start all services (API, PostgreSQL, Redis, Nginx)
docker-compose up -d

# Scale API instances
docker-compose up -d --scale api=3

# View logs
docker-compose logs -f api

# Update and restart
docker-compose pull && docker-compose up -d
```

## =� Monitoring & Observability

### Health Checks
- Database connectivity monitoring
- HSM availability checking
- Readiness and liveness probes for Kubernetes

### Logging
- Structured JSON logging with correlation IDs
- Configurable log levels
- Request/response logging with performance metrics
- HSM operation logging with duration tracking

### Metrics
- API request duration and status codes
- HSM operation performance
- Database query performance
- Rate limiting metrics

## =� Troubleshooting

### Common Issues

**HSM Connection Errors:**
```bash
# Check SoftHSM configuration
echo $SOFTHSM2_CONF
softhsm2-util --show-slots

# Verify library path
ls -la /usr/lib/softhsm/libsofthsm2.so
```

**Database Connection Issues:**
```bash
# Test database connectivity
psql "postgresql://user:pass@host/db"

# Check database logs in Docker
docker-compose logs postgres
```

**Authentication Problems:**
```bash
# Verify JWT token
python -c "
from app.auth.jwt_handler import jwt_handler
print(jwt_handler.decode_token('your-token-here'))
"
```

### Performance Tuning

**Database Optimization:**
- Connection pooling configuration
- Index optimization for frequently queried fields
- Database query monitoring

**HSM Performance:**
- Session management optimization
- Concurrent operation limits
- Hardware HSM vs SoftHSM performance

## > Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation for API changes
- Use type hints for all functions
- Include docstrings for public methods

## =� License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## <� Support

For support and questions:
- Create an issue in the GitHub repository
- Check the API documentation at `/api/v1/docs`
- Review the troubleshooting section above

## =. Roadmap

- [ ] Multi-tenant support
- [ ] Hardware HSM integration guides
- [ ] Prometheus metrics endpoint
- [ ] Kubernetes deployment manifests
- [ ] GraphQL API interface
- [ ] Advanced key rotation features