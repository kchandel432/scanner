## System Architecture

### Overview
```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ HTTP/WebSocket
       ▼
┌──────────────────────────────────────────────┐
│        FastAPI Web Server (8000)             │
│  ┌────────────────────────────────────────┐  │
│  │    Routes & API Endpoints              │  │
│  │  - Web routes (Jinja2)                 │  │
│  │  - REST API (/api/v1)                  │  │
│  │  - WebSocket (real-time updates)       │  │
│  │  - HTMX partials                       │  │
│  └────────────────────────────────────────┘  │
└──────┬────────────────────────────────────────┘
       │
   ┌───┼───┬─────────────────┐
   │   │   │                 │
   ▼   ▼   ▼                 ▼
┌──────┐┌──────┐        ┌──────────┐
│  DB  ││Redis │        │  Worker  │
└──────┘└──────┘        │ (Celery) │
                        └──────────┘
```

### Components

#### Frontend Layer
- **Server-rendered HTML** (Jinja2 templates)
- **HTMX** for dynamic partial updates
- **Alpine.js** for client-side interactivity
- **Tailwind CSS** for styling

#### API Layer
- **FastAPI** for high-performance REST API
- **WebSocket** for real-time updates
- **OpenAPI/Swagger** for documentation
- **JWT** for authentication

#### Business Logic
- **Services** - Core business logic
- **Use Cases** - Application scenarios
- **Domain Models** - Data models

#### Data Layer
- **SQLAlchemy ORM** - Database abstraction
- **PostgreSQL** - Primary database
- **Redis** - Caching & sessions
- **S3** - File storage (optional)

#### Worker Layer
- **Celery** - Task queue
- **Redis** - Message broker
- **Async Processing** - Long-running scans

### Data Flow

1. **User uploads file** → FastAPI endpoint
2. **File validated** → Store in temp location
3. **Scan task queued** → Redis
4. **Worker picks up task** → Runs ML models
5. **Results stored** → Database
6. **WebSocket notification** → Browser updates in real-time
7. **Report generated** → PDF/JSON/HTML

### Security
- **JWT tokens** for API authentication
- **CSRF tokens** for form submissions
- **SQL injection prevention** via ORM
- **XSS protection** via Jinja2 auto-escaping
- **Rate limiting** on endpoints
- **HTTPS only** in production

---
See [data-flow.mmd](data-flow.mmd) for detailed message flows.
