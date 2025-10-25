# Traefik Reverse Proxy Configuration
# AutoApp UI Map & Intelligent Flow Engine

## Overview

This document describes the Traefik reverse proxy configuration for the AutoApp UI Map & Intelligent Flow Engine. Traefik provides secure routing, SSL termination, CORS handling, and load balancing for all application services.

## Architecture

The Traefik configuration provides:

- **Reverse Proxy**: Routes incoming requests to appropriate backend services
- **SSL Termination**: Automatic HTTPS with Let's Encrypt certificates
- **CORS Handling**: Configurable cross-origin resource sharing
- **Security Headers**: Enhanced security through HTTP headers
- **Rate Limiting**: Protection against abuse and DDoS attacks
- **Health Checks**: Automatic service health monitoring
- **WebSocket Support**: Real-time WebRTC streaming capabilities

## Service Routing

### Frontend Service
- **Container**: `apptest-frontend`
- **Internal Port**: 80
- **Routes**:
  - `http://localhost` → Frontend React application
  - `https://localhost` → Frontend React application (HTTPS)

### Backend API Service
- **Container**: `apptest-backend`
- **Internal Port**: 3001
- **Routes**:
  - `http://localhost/api/*` → Backend Express API
  - `https://localhost/api/*` → Backend Express API (HTTPS)
  - Health endpoints: `/api/healthz`, `/api/health`

### WebRTC Streaming Service
- **Container**: `apptest-envoy`
- **Internal Port**: 8080
- **Routes**:
  - WebSocket connections for WebRTC streaming
  - gRPC-Web proxy for Android emulator control

## Configuration Files

### Static Configuration: `/infra/traefik/traefik.yml`

Global Traefik settings including:
- Entry points (HTTP, HTTPS, WebSocket)
- Docker provider configuration
- Certificate management
- Logging and monitoring

### Dynamic Configuration: `/infra/traefik/dynamic/middlewares.yml`

Runtime configuration including:
- Security headers middleware
- CORS configuration
- Rate limiting
- Compression
- Error handling

## Docker Compose Integration

The Traefik service is defined in `docker-compose.yml` with:

```yaml
traefik:
  image: traefik:v3.1
  container_name: apptest-traefik
  ports:
    - "80:80"       # HTTP
    - "443:443"     # HTTPS
    - "8080:8080"   # Dashboard and WebSocket
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
    - ./infra/traefik/traefik.yml:/etc/traefik/traefik.yml:ro
    - ./infra/traefik/dynamic:/etc/traefik/dynamic:ro
```

## Service Labels

Each application service includes Traefik labels for routing:

### Backend Service Labels
```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.backend-api.rule=Host(`localhost`) && PathPrefix(`/api`)"
  - "traefik.http.routers.backend-api.middlewares=cors-headers@file,api-ratelimit@file"
  - "traefik.http.services.backend-api.loadbalancer.server.port=3001"
```

### Frontend Service Labels
```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.frontend.rule=Host(`localhost`)"
  - "traefik.http.routers.frontend.middlewares=compress@file,security-headers@file"
  - "traefik.http.services.frontend.loadbalancer.server.port=80"
```

## Security Features

### CORS Configuration
- Allowed origins: Development localhost URLs
- Allowed methods: GET, POST, PUT, DELETE, OPTIONS, PATCH
- Allowed headers: Standard HTTP headers + gRPC headers
- Max age: 86400 seconds (24 hours)

### Security Headers
- **X-Content-Type-Options**: nosniff
- **X-Frame-Options**: DENY
- **X-XSS-Protection**: 1; mode=block
- **Content-Security-Policy**: Strict CSP policy
- **Strict-Transport-Security**: HSTS with preload

### Rate Limiting
- API endpoints: 100 requests per minute with 200 burst capacity
- Prevents abuse and DDoS attacks

## Health Monitoring

### Service Health Checks
- **Backend**: `/api/healthz` endpoint
- **Frontend**: `/` root path
- **Envoy**: `/healthz` endpoint
- **Interval**: 30 seconds
- **Timeout**: 5 seconds

### Traefik Dashboard
- **URL**: `http://localhost:8080/dashboard/`
- **Features**: Service monitoring, routing rules, metrics
- **Security**: Basic authentication (configure for production)

## SSL/TLS Configuration

### Development
- Self-signed certificates or development mode
- HTTP-to-HTTPS redirection enabled
- Insecure API dashboard enabled

### Production
- Let's Encrypt automatic certificate management
- HTTPS-only access
- Secure API dashboard (disable `api.insecure`)

## WebSocket Support

### WebRTC Streaming
- WebSocket endpoint: `ws://localhost/webrtc`
- Headers: Connection: Upgrade, Upgrade: websocket
- CORS: Configured for WebRTC applications

### gRPC-Web
- Protocol translation for gRPC over HTTP
- Used by Android emulator control interface
- Optimized for Envoy proxy integration

## Monitoring and Logging

### Access Logs
- **Format**: JSON structured logging
- **Location**: `/var/log/traefik/access.log`
- **Filters**: HTTP error codes (400-599)
- **Buffering**: 100 entries

### Metrics
- **Prometheus**: Enabled for monitoring
- **Labels**: Service and entry point metrics
- **Integration**: Compatible with monitoring systems

## Environment Variables

Key environment variables for Traefik:

```bash
# Traefik Configuration
TRAEFIK_LOG_LEVEL=INFO
TRAEFIK_API_INSECURE=false  # Set to false in production
TRAEFIK_PROVIDERS_DOCKER_EXPOSEDBYDEFAULT=false

# SSL Configuration
TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_EMAIL=admin@yourdomain.com
TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_STORAGE=/etc/traefik/acme/acme.json

# Security
TRAEFIK_ACCESSLOG=true
TRAEFIK_ACCESSLOG_FILEPATH=/var/log/traefik/access.log
```

## Deployment with Dockploy

When deploying with Dockploy:

1. **Domain Configuration**: Update Traefik rules with production domains
2. **SSL Certificates**: Let's Encrypt automatically configured
3. **Environment Variables**: Set production values
4. **Security**: Disable insecure dashboard and enable authentication

### Production Domain Example
```yaml
# Replace localhost with production domains
- "traefik.http.routers.backend-api.rule=Host(`api.yourdomain.com`) && PathPrefix(`/`)"
- "traefik.http.routers.frontend.rule=Host(`app.yourdomain.com`)"
```

## Troubleshooting

### Common Issues

1. **502 Bad Gateway**: Service not responding
   - Check service logs: `docker-compose logs backend`
   - Verify service health: `curl http://localhost:3001/api/healthz`

2. **CORS Errors**: Cross-origin requests blocked
   - Review CORS middleware configuration
   - Check allowed origins list

3. **WebSocket Connection Failed**: Real-time streaming issues
   - Verify WebSocket middleware applied
   - Check Envoy proxy configuration

4. **SSL Certificate Issues**: HTTPS not working
   - Verify domain DNS configuration
   - Check Let's Encrypt email settings
   - Review ACME challenge configuration

### Debug Commands

```bash
# Check Traefik logs
docker-compose logs traefik

# View routing configuration
curl http://localhost:8080/api/http/routers

# Test service health
curl http://localhost/api/healthz
curl -k https://localhost/api/healthz

# Check metrics
curl http://localhost:8080/metrics
```

## Maintenance

### Regular Tasks

1. **Log Rotation**: Configure log rotation for access logs
2. **Certificate Renewal**: Let's Encrypt handles automatically
3. **Backup Configuration**: Backup Traefik configuration files
4. **Security Updates**: Update Traefik image regularly

### Performance Tuning

1. **Buffer Size**: Adjust based on traffic patterns
2. **Rate Limits**: Tune based on application requirements
3. **Timeouts**: Configure appropriate timeouts for services
4. **Connection Limits**: Set reasonable connection limits

## Migration from Direct Port Access

If migrating from direct port access:

1. **Update Frontend Configuration**: Change API URLs from `http://localhost:3001` to `/api`
2. **Update Environment Variables**: Use service names instead of ports
3. **Update Documentation**: Reflect new routing structure
4. **Update Monitoring**: Use Traefik metrics instead of direct port monitoring

## Security Best Practices

1. **Production Dashboard**: Enable authentication
2. **CORS Restrictions**: Limit origins in production
3. **Rate Limiting**: Adjust based on legitimate usage patterns
4. **SSL Only**: Redirect HTTP to HTTPS in production
5. **Regular Updates**: Keep Traefik image updated
6. **Monitor Logs**: Review access logs for suspicious activity