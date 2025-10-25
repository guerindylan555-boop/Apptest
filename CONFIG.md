# Configuration Reference

This document describes all configuration options for the MaynDrive automation system.

## Environment Variables

### Core Application Settings

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `NODE_ENV` | Environment (development, production, test) | `development` | No |
| `PORT` | Backend API server port | `3000` | No |
| `FRONTEND_URL` | Frontend application URL | `http://localhost:5173` | No |
| `WEBRTC_URL` | WebRTC bridge URL for emulator streaming | `ws://localhost:8081` | No |

### State Detection Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `STATE_DETECTOR_CONFIDENCE_MIN` | Minimum confidence score (0-100) to consider a match valid | `70` | No |
| `STATE_DETECTOR_CONFIDENCE_AMBIGUOUS` | Threshold above which matches are considered ambiguous (50-69) | `50` | No |
| `STATE_DETECTOR_MAX_CANDIDATES` | Maximum number of candidate nodes to return | `5` | No |
| `STATE_DETECTOR_SELECTOR_WEIGHTS` | JSON string defining selector type weights | See below | No |

**Default Selector Weights:**
```json
{
  "resource-id": 3,
  "content-desc": 2,
  "text": 1,
  "accessibility": 1.5,
  "xpath": 0.5,
  "coords": 0.2
}
```

### UI Graph Storage

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `UI_GRAPH_STORAGE_PATH` | Base path for UI graph artifacts | `var` | No |
| `UI_GRAPH_MAX_VERSIONS` | Maximum number of graph versions to retain | `10` | No |
| `UI_GRAPH_AUTO_CLEANUP` | Enable automatic cleanup of old versions | `true` | No |
| `UI_GRAPH_CHECKSUM_ALGORITHM` | Algorithm for artifact checksums | `sha256` | No |

### Flow Execution

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `FLOW_DEFAULT_TIMEOUT_MS` | Default timeout for flow steps | `30000` | No |
| `FLOW_MAX_RETRY_ATTEMPTS` | Maximum retry attempts for failed steps | `3` | No |
| `FLOW_RETRY_DELAY_MS` | Delay between retry attempts | `1000` | No |
| `FLOW_RECOVERY_ENABLED` | Enable automatic recovery mechanisms | `true` | No |

### Capture Workflow

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `CAPTURE_SCREENSHOT_FORMAT` | Screenshot image format | `png` | No |
| `CAPTURE_SCREENSHOT_QUALITY` | Screenshot quality (0-100 for jpeg) | `90` | No |
| `CAPTURE_MAX_SELECTOR_CANDIDATES` | Maximum selector candidates to extract | `50` | No |
| `CAPTURE_MIN_SELECTOR_CONFIDENCE` | Minimum confidence for selector candidates | `0.3` | No |

### Emulator Integration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `EMULATOR_SERIAL` | ADB serial for target emulator | `emulator-5554` | No |
| `EMULATOR_BOOT_TIMEOUT_MS` | Maximum time to wait for emulator boot | `120000` | No |
| `EMULATOR_WEBRTC_PORT` | WebRTC bridge port for emulator | `8081` | No |

### Logging and Telemetry

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LOG_LEVEL` | Logging level (error, warn, info, debug) | `info` | No |
| `TELEMETRY_ENABLED` | Enable collection of execution telemetry | `true` | No |
| `TELEMETRY_RETENTION_DAYS` | Days to retain telemetry data | `30` | No |

## Configuration Files

### Backend Configuration

Configuration is loaded from:
1. Environment variables (highest priority)
2. `.env` file in project root
3. Default values in code

### Frontend Configuration

Frontend configuration is provided through:
1. Build-time environment variables
2. Runtime configuration from `/api/config` endpoint
3. Default values in stores

## Docker Configuration

### Docker Compose

Services are configured in `docker-compose.yml`:
- `backend`: Node.js API server
- `frontend`: Nginx serving React app
- `emulator`: Android emulator with WebRTC bridge
- `envoy`: Reverse proxy and load balancer

### Environment-specific Overrides

Use `.env.<environment>` files for environment-specific configuration:
- `.env.development` - Development defaults
- `.env.production` - Production overrides
- `.env.test` - Test configuration

## Security Configuration

### API Keys and Secrets

Sensitive configuration should be provided through environment variables:
- Database credentials
- API keys for external services
- Encryption keys for artifact storage

### CORS Configuration

Frontend-origin access is controlled via CORS settings in the backend:
```bash
CORS_ORIGINS=http://localhost:5173,https://your-domain.com
```

## Performance Tuning

### Memory Usage

- `STATE_DETECTOR_CACHE_SIZE`: Maximum cached detection results (default: 100)
- `UI_GRAPH_CACHE_TTL_MS`: Cache TTL for graph data (default: 60000)

### Concurrency

- `MAX_CONCURRENT_FLOWS`: Maximum flows running simultaneously (default: 3)
- `MAX_CONCURRENT_CAPTURES`: Maximum concurrent capture operations (default: 2)

## Troubleshooting

### Common Issues

1. **State detection confidence too low**: Adjust `STATE_DETECTOR_CONFIDENCE_MIN`
2. **Flow execution timeouts**: Increase `FLOW_DEFAULT_TIMEOUT_MS`
3. **Artifact storage full**: Enable `UI_GRAPH_AUTO_CLEANUP` or increase storage
4. **Emulator connection issues**: Check `EMULATOR_SERIAL` and WebRTC configuration

### Debug Mode

Enable debug logging with:
```bash
LOG_LEVEL=debug
TELEMETRY_ENABLED=true
```

### Configuration Validation

Validate configuration on startup:
```bash
npm run config:validate
```

This will check:
- Required environment variables
- Valid ranges for numeric values
- Accessibility of storage paths
- Network connectivity for external services