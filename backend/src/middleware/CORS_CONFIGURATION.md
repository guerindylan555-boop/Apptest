# CORS Middleware Configuration

This document explains the comprehensive CORS middleware configuration for the AutoApp UI Map & Intelligent Flow Engine system.

## Overview

The CORS middleware provides flexible Cross-Origin Resource Sharing configuration with support for:

- Remote Dockploy domain access
- Development localhost support
- Environment-based configuration
- Security validation and logging
- Configurable policies

## Environment Variables

### Core Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `CORS_ALLOWED_ORIGINS` | Comma-separated list of allowed origins | (development defaults) | `https://app.yourdomain.com,https://admin.yourdomain.com` |
| `CORS_ADDITIONAL_ORIGINS` | Additional origins to allow (merged with defaults) | (empty) | `http://localhost:3000,https://staging.yourdomain.com` |
| `CORS_CREDENTIALS` | Allow credentials (cookies, auth headers) | `true` | `false` |
| `CORS_METHODS` | Allowed HTTP methods | `GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD` | `GET,POST,PUT` |
| `CORS_ALLOWED_HEADERS` | Allowed request headers | (see below) | `Content-Type,Authorization,X-API-Key` |
| `CORS_EXPOSED_HEADERS` | Headers exposed to clients | (see below) | `X-Total-Count,X-Trace-ID` |
| `CORS_MAX_AGE` | Preflight cache duration in seconds | `86400` (24h) | `3600` (1h) |
| `CORS_PREFLIGHT_STATUS` | Preflight success status code | `204` | `200` |
| `CORS_LOG_REQUESTS` | Enable CORS request logging | `true` | `false` |

### Development Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `CORS_DEV_ALLOW_WILDCARD` | Allow wildcard origins in development | `true` | `false` |
| `CORS_DEV_PERMISSIVE_LOGGING` | Enable detailed logging in development | `true` | `false` |

### Production Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `CORS_PROD_STRICT_VALIDATION` | Enable strict origin validation | `true` | `false` |
| `CORS_PROD_PREFLIGHT_RATE_LIMIT` | Preflight request rate limit | `100` | `50` |
| `CORS_PROD_ENFORCE_HTTPS` | Require HTTPS in production | `true` | `false` |

## Configuration Examples

### Development Environment

```bash
# Allow localhost development
CORS_ALLOWED_ORIGINS="http://localhost:5173,http://localhost:3000"
CORS_CREDENTIALS=true
CORS_LOG_REQUESTS=true
NODE_ENV=development
```

### Production Dockploy Deployment

```bash
# Production Dockploy domains
CORS_ALLOWED_ORIGINS="https://app.yourdomain.com,https://admin.yourdomain.com"
CORS_CREDENTIALS=true
CORS_LOG_REQUESTS=false
CORS_PROD_ENFORCE_HTTPS=true
CORS_PROD_STRICT_VALIDATION=true
NODE_ENV=production
```

### Multi-Environment Setup

```bash
# Allow both development and production origins
CORS_ALLOWED_ORIGINS="https://app.yourdomain.com,https://staging.yourdomain.com"
CORS_ADDITIONAL_ORIGINS="http://localhost:5173,http://localhost:3000"
CORS_CREDENTIALS=true
CORS_LOG_REQUESTS=true
```

### Wildcard Configuration (Use with caution)

```bash
# Allow all origins (development only)
CORS_ALLOWED_ORIGINS="*"
CORS_CREDENTIALS=false
CORS_LOG_REQUESTS=true
NODE_ENV=development
```

## Default Origins

### Development Defaults
- `http://localhost:5173`
- `http://127.0.0.1:5173`
- `http://localhost:3000`
- `http://127.0.0.1:3000`
- `http://localhost:3001`
- `http://127.0.0.1:3001`
- `http://localhost:8080`
- `http://127.0.0.1:8080`

### Production Defaults (Dockploy)
- `https://app.yourdomain.com`
- `https://autoapp.yourdomain.com`

**Note:** Update these defaults in `src/middleware/cors.ts` for your actual Dockploy domains.

## Security Features

### Origin Validation
- Exact origin matching
- Subdomain matching (production)
- HTTPS enforcement (production)
- Custom origin validation functions

### Header Management
- Dangerous header protection
- Configurable allowed headers
- Exposed headers for API clients
- Automatic trace ID handling

### Preflight Handling
- Configurable cache duration
- Rate limiting (production)
- Proper status codes
- Performance monitoring

## API Endpoints

### CORS Health Check
```http
GET /api/cors/health
```

Returns CORS middleware status and configuration:
```json
{
  "status": "ok",
  "cors": {
    "healthy": true,
    "config": {
      "environment": "development",
      "allowedOriginsCount": 8,
      "credentials": true,
      "methodsCount": 8,
      "logRequests": true
    }
  }
}
```

### CORS Configuration
```http
GET /api/cors/config
```

Returns current CORS configuration:
```json
{
  "status": "ok",
  "config": {
    "allowedOrigins": ["http://localhost:5173"],
    "credentials": true,
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "allowedHeaders": ["Content-Type", "Authorization"],
    "maxAge": 86400
  }
}
```

### Origin Test
```http
POST /api/cors/test
Content-Type: application/json

{
  "origin": "https://example.com"
}
```

Tests if an origin is allowed:
```json
{
  "status": "ok",
  "test": {
    "origin": "https://example.com",
    "allowed": false,
    "reason": "Origin not in allowed list"
  }
}
```

## Integration with Express

The middleware automatically selects the appropriate configuration based on `NODE_ENV`:

```typescript
import { createServer } from './api/server';

// Uses developmentCorsMiddleware when NODE_ENV=development
// Uses productionCorsMiddleware when NODE_ENV=production
// Uses corsMiddleware for other environments
const app = createServer();
```

## Monitoring and Logging

### Request Logging
All CORS requests are logged when `CORS_LOG_REQUESTS=true`:
```json
{
  "service": "cors-middleware",
  "event": "cors_request",
  "severity": "info",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "trace_id": "abc123",
  "message": "CORS request allowed: POST https://app.yourdomain.com",
  "origin": "https://app.yourdomain.com",
  "method": "POST",
  "allowed": true,
  "reason": "Exact origin match"
}
```

### Health Monitoring
Use the `/api/cors/health` endpoint for monitoring:
- Check if CORS is properly configured
- Monitor configuration changes
- Validate origin policies
- Performance metrics

## Best Practices

### Production Deployment
1. **Never use wildcard origins** (`*`) in production
2. **Always enforce HTTPS** for production domains
3. **Enable strict validation** for security
4. **Disable detailed logging** to reduce noise
5. **Set appropriate cache durations** for preflight requests

### Development Setup
1. **Enable permissive logging** for debugging
2. **Allow localhost origins** for local development
3. **Use wildcard origins carefully** only when needed
4. **Test origin validation** with `/api/cors/test`

### Security Considerations
1. **Validate all origins** before allowing
2. **Limit credentials** to trusted origins only
3. **Monitor blocked requests** for potential attacks
4. **Use HTTPS** in production environments
5. **Review logs regularly** for unusual patterns

## Troubleshooting

### Common Issues

#### CORS Policy Errors
```bash
# Check current configuration
curl http://localhost:3001/api/cors/health

# Test specific origin
curl -X POST http://localhost:3001/api/cors/test \
  -H "Content-Type: application/json" \
  -d '{"origin": "https://yourdomain.com"}'
```

#### Missing Headers
- Verify `CORS_ALLOWED_HEADERS` includes all required headers
- Check that client requests include proper headers
- Ensure preflight requests are being handled

#### Credential Issues
- Set `CORS_CREDENTIALS=true` when using cookies/auth
- Verify frontend includes `credentials: 'include'`
- Check that allowed origins are specific (not wildcard)

#### Performance Issues
- Reduce `CORS_MAX_AGE` for more frequent preflight checks
- Monitor `/api/cors/health` for configuration status
- Check logs for frequent preflight requests

### Debug Mode
Enable detailed logging for troubleshooting:
```bash
CORS_LOG_REQUESTS=true
CORS_DEV_PERMISSIVE_LOGGING=true
NODE_ENV=development
```

This will provide detailed logs for all CORS requests and decisions.