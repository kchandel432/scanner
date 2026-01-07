## Development Setup

### Environment Variables (.env)
```env
# App
ENVIRONMENT=development
DEBUG=True
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=sqlite:///./dev.db

# Redis
REDIS_URL=redis://localhost:6379

# External APIs
VIRUSTOTAL_API_KEY=your-key
SHODAN_API_KEY=your-key
ABUSEIPDB_API_KEY=your-key
```

### Backend Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start development server
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Development
The frontend uses server-rendered templates with HTMX, no Node.js build needed!

```bash
# The frontend automatically loads from backend
# Visit http://localhost:8000
```

### Running Tests
```bash
# All tests
pytest

# Specific test file
pytest tests/unit/test_scanner.py

# With coverage
pytest --cov=backend tests/

# Integration tests
pytest tests/integration/
```

### Database Migrations
```bash
# Create new migration
alembic revision --autogenerate -m "Add new table"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

## Production Deployment

### Docker Build
```bash
docker-compose -f docker/docker-compose.prod.yml build
```

### Deploy to Kubernetes
```bash
kubectl apply -f k8s/
```

## Monitoring

### View Logs
```bash
docker-compose logs -f backend
```

### Health Check
```bash
curl http://localhost:8000/health
```

### Prometheus Metrics
```bash
curl http://localhost:9090
```
