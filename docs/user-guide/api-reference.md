## API Reference

### Authentication
All API endpoints require Bearer token authentication.

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://api/endpoint
```

### Scan Endpoints

#### Start File Scan
```
POST /api/v1/scan/file
Content-Type: multipart/form-data

file: <binary file data>
```

**Response:**
```json
{
  "scan_id": "scan_abc123",
  "status": "queued",
  "created_at": "2024-01-04T12:00:00Z"
}
```

#### Get Scan Status
```
GET /api/v1/scan/{scan_id}
```

**Response:**
```json
{
  "scan_id": "scan_abc123",
  "status": "completed",
  "progress": 100,
  "detections": {
    "malware": 2,
    "suspicious": 5,
    "clean": 1
  },
  "completed_at": "2024-01-04T12:05:00Z"
}
```

#### Scan Website
```
POST /api/v1/scan/website
Content-Type: application/json

{
  "url": "https://example.com",
  "check_ssl": true
}
```

### Report Endpoints

#### Generate Report
```
POST /api/v1/report/{scan_id}

{
  "format": "pdf",
  "template": "investor",
  "include_evidence": true
}
```

#### Download Report
```
GET /api/v1/report/{report_id}/download
```

### Error Responses

#### 400 Bad Request
```json
{
  "detail": "Invalid file format",
  "error_code": "INVALID_FILE"
}
```

#### 401 Unauthorized
```json
{
  "detail": "Invalid or expired token"
}
```

#### 429 Too Many Requests
```json
{
  "detail": "Rate limit exceeded",
  "retry_after": 60
}
```

### Rate Limiting
- 100 requests per minute per API key
- 10 concurrent scans per organization
- File size limit: 1GB

---
See OpenAPI documentation at `/docs` for interactive testing.
