# Remote API Accessibility Integration Tests

This directory contains comprehensive integration tests for verifying remote API accessibility through Dockploy domain configurations.

## Overview

The remote accessibility test suite ensures that the AutoApp system works correctly when deployed remotely through Dockploy with custom domains, Traefik proxy configurations, and various network access scenarios.

## Test Coverage

### CORS Configuration Tests
- **Preflight request validation**: Tests OPTIONS requests for various origins
- **Origin validation**: Verifies CORS headers for different domain origins
- **Header validation**: Ensures proper CORS headers are present and valid
- **Multiple origin testing**: Tests localhost, remote domains, and Dockploy domains

### Health Check Endpoint Tests
- **Basic health checks**: `/api/health`, `/api/healthz`
- **Container orchestration**: `/api/health/ready`, `/api/health/live`
- **Detailed health monitoring**: `/api/health/detailed`
- **Response structure validation**: Ensures proper health response format
- **Performance validation**: Verifies response times under 500ms

### Graph Management API Tests
- **Graph retrieval**: `/api/graph` endpoint accessibility
- **State management**: `/api/state/current`, `/api/state/:id` endpoints
- **Session management**: `/api/sessions` endpoints
- **Device validation**: `/api/device/validate`, `/api/device/info` endpoints
- **Response structure validation**: Ensures proper API response formats

### Flow Management API Tests
- **Flow listing**: `/api/flows` endpoint with filtering
- **Flow templates**: `/api/flows/templates` endpoint
- **Flow library**: `/api/flows/library` endpoint
- **Flow validation**: `/api/flows/validate` endpoint
- **API structure validation**: Verifies flow API response formats

### WebRTC Configuration Tests
- **Stream URL configuration**: `/api/stream/url` endpoint
- **ICE server validation**: Verifies WebRTC server configuration
- **Endpoint accessibility**: Tests WebRTC endpoint reachability
- **Configuration validation**: Ensures proper WebRTC setup

### Domain Simulation Tests
- **Host header testing**: Tests different host headers for domain routing
- **User agent testing**: Tests various client access scenarios
- **Proxy configuration**: Tests Traefik proxy accessibility
- **Cross-origin access**: Validates cross-domain API access

## Environment Setup

### Prerequisites

1. **Node.js**: Version 16 or higher
2. **npm**: For dependency management
3. **Docker**: (Optional) For container testing
4. **Network access**: For testing remote endpoints

### Environment Variables

Configure these environment variables before running tests:

```bash
# Test Configuration
TEST_BASE_URL=http://localhost:3001          # Base URL for API testing
TEST_TIMEOUT=10000                           # Request timeout in milliseconds
TEST_RETRY_ATTEMPTS=3                        # Number of retry attempts
TEST_RETRY_DELAY=1000                        # Delay between retries (ms)

# Dockploy Configuration
DOCKPLOY_DOMAIN=autoapp.dockploy.io         # Your Dockploy domain
TRAEFIK_PROXY=traefik.local                 # Traefik proxy URL

# CORS Configuration
CORS_ALLOWED_ORIGINS=https://autoapp.dockploy.io,https://maydrive.fr

# Application Configuration
NODE_ENV=test                                # Environment mode
PORT=3001                                    # Application port
HOST=0.0.0.0                                 # Application host
EXTERNAL_EMULATOR=false                      # External emulator mode
```

### Installation

1. Install dependencies:
```bash
npm install
```

2. Ensure the backend server is running:
```bash
npm run dev
# or
npm start
```

3. Verify server accessibility:
```bash
curl http://localhost:3001/api/health
```

## Running Tests

### Basic Test Execution

Run the complete test suite:
```bash
npx ts-node tests/integration/remote-access.test.ts
```

### Running with Different Configurations

Test against localhost:
```bash
TEST_BASE_URL=http://localhost:3001 npx ts-node tests/integration/remote-access.test.ts
```

Test against Dockploy domain:
```bash
TEST_BASE_URL=https://autoapp.dockploy.io DOCKPLOY_DOMAIN=autoapp.dockploy.io npx ts-node tests/integration/remote-access.test.ts
```

Test with custom timeouts:
```bash
TEST_TIMEOUT=30000 TEST_RETRY_ATTEMPTS=5 npx ts-node tests/integration/remote-access.test.ts
```

### Test Output

The test suite provides:
- **Real-time progress**: Shows test execution progress
- **Detailed results**: Comprehensive test result information
- **Failed test analysis**: Detailed information about test failures
- **Summary report**: Overall test suite success rate

Test results are saved to `test-results/remote-access-results-{timestamp}.json`.

## Test Results

### Result Structure

```typescript
interface TestSuiteResults {
  testConfig: TestConfig;
  timestamp: string;
  environment: {
    nodeVersion: string;
    platform: string;
    dockerContainer: boolean;
    envVars: Record<string, string>;
  };
  cors: CorsTestResult[];
  health: HealthCheckResult[];
  api: ApiEndpointResult[];
  webrtc: WebRTCResult[];
  summary: {
    totalTests: number;
    passedTests: number;
    failedTests: number;
    successRate: number;
    overallStatus: 'passed' | 'failed' | 'partial';
  };
}
```

### Success Criteria

- **Passed**: 90%+ success rate, all critical tests passing
- **Partial**: 70-89% success rate, some non-critical tests failing
- **Failed**: <70% success rate, critical tests failing

### Critical Tests

These tests must pass for successful deployment:
1. Health check endpoint accessibility
2. Basic API endpoint responses
3. CORS configuration for primary domain
4. WebRTC configuration presence

## Troubleshooting

### Common Issues

#### Connection Timeout
```bash
# Increase timeout and retry attempts
TEST_TIMEOUT=30000 TEST_RETRY_ATTEMPTS=5 npx ts-node tests/integration/remote-access.test.ts
```

#### CORS Failures
- Verify `CORS_ALLOWED_ORIGINS` environment variable
- Check that the target domain is included in allowed origins
- Ensure server CORS configuration is properly set

#### Health Check Failures
- Verify server is running on the expected port
- Check that health check endpoints are accessible
- Ensure all required services (ADB, WebRTC, etc.) are available

#### Domain Access Issues
- Verify DNS resolution for target domains
- Check firewall and network connectivity
- Ensure Traefik proxy is properly configured

### Debug Mode

Run tests with additional debugging:
```bash
DEBUG=* npx ts-node tests/integration/remote-access.test.ts
```

### Test Isolation

Each test runs independently with:
- Separate HTTP client instances
- Individual timeout configurations
- Isolated error handling
- Detailed result tracking

## CI/CD Integration

### GitHub Actions

Add to your `.github/workflows/test.yml`:

```yaml
name: Remote Accessibility Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  remote-access-tests:
    runs-on: ubuntu-latest

    strategy:
      matrix:
        test-scenario:
          - localhost
          - dockploy-domain
          - traefik-proxy

    steps:
    - uses: actions/checkout@v3

    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci

    - name: Start application
      run: npm run dev &
      env:
        NODE_ENV: test
        PORT: 3001

    - name: Wait for application
      run: |
        timeout 60 bash -c 'until curl -f http://localhost:3001/api/health; do sleep 2; done'

    - name: Run remote accessibility tests
      run: |
        case "${{ matrix.test-scenario }}" in
          localhost)
            TEST_BASE_URL=http://localhost:3001 npx ts-node tests/integration/remote-access.test.ts
            ;;
          dockploy-domain)
            TEST_BASE_URL=https://autoapp.dockploy.io DOCKPLOY_DOMAIN=autoapp.dockploy.io npx ts-node tests/integration/remote-access.test.ts
            ;;
          traefik-proxy)
            TEST_BASE_URL=http://traefik-proxy:80 TRAEFIK_PROXY=traefik-proxy npx ts-node tests/integration/remote-access.test.ts
            ;;
        esac
      env:
        TEST_TIMEOUT: 30000
        TEST_RETRY_ATTEMPTS: 5

    - name: Upload test results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: remote-access-results-${{ matrix.test-scenario }}
        path: test-results/
```

### Docker Testing

Create a Docker test environment:

```dockerfile
# Dockerfile.test
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy test files
COPY tests/ ./tests/
COPY src/ ./src/
COPY tsconfig*.json ./

# Install TypeScript for testing
RUN npm install -g typescript ts-node

# Run tests
CMD ["npx", "ts-node", "tests/integration/remote-access.test.ts"]
```

Build and run:
```bash
docker build -f Dockerfile.test -t autoapp-remote-tests .
docker run --network host \
  -e TEST_BASE_URL=http://localhost:3001 \
  -e DOCKPLOY_DOMAIN=autoapp.dockploy.io \
  autoapp-remote-tests
```

### Monitoring Integration

Integrate with monitoring services:

```typescript
// Add to test suite
if (process.env.MONITORING_WEBHOOK) {
  await fetch(process.env.MONITORING_WEBHOOK, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      testSuite: 'remote-accessibility',
      status: results.summary.overallStatus,
      successRate: results.summary.successRate,
      timestamp: results.timestamp
    })
  });
}
```

## Advanced Configuration

### Custom Test Scenarios

Create custom test configurations:

```typescript
const customConfig: TestConfig = {
  baseUrl: 'https://custom-domain.example.com',
  timeout: 15000,
  retryAttempts: 3,
  retryDelay: 2000,
  dockployDomain: 'custom-domain.example.com',
  customHeaders: {
    'Authorization': 'Bearer test-token',
    'X-Custom-Header': 'test-value'
  }
};

const testSuite = new RemoteAccessibilityTestSuite(customConfig);
const results = await testSuite.runCompleteTestSuite();
```

### Extended Test Coverage

Add custom endpoint tests:

```typescript
// Extend ApiEndpointTester
async testCustomEndpoints(): Promise<ApiEndpointResult[]> {
  const endpoints = [
    { method: 'GET', endpoint: '/api/custom/endpoint' },
    { method: 'POST', endpoint: '/api/custom/action' }
  ];

  const results: ApiEndpointResult[] = [];
  for (const { method, endpoint } of endpoints) {
    const result = await this.testApiEndpoint(method, endpoint);
    results.push(result);
  }

  return results;
}
```

### Performance Testing

Add performance benchmarks:

```typescript
// Performance validation
const performanceThresholds = {
  maxResponseTime: 5000,
  minSuccessRate: 95,
  maxErrorRate: 5
};

if (results.summary.successRate < performanceThresholds.minSuccessRate) {
  throw new Error(`Success rate ${results.summary.successRate}% below threshold ${performanceThresholds.minSuccessRate}%`);
}
```

## Maintenance

### Regular Updates

1. **Update test scenarios**: Add new endpoints as they're added to the API
2. **Adjust thresholds**: Update performance thresholds based on monitoring data
3. **Environment maintenance**: Keep test environments up to date
4. **Dependencies**: Regularly update test dependencies

### Test Data Management

- Clean up old test results regularly
- Monitor test result storage usage
- Archive historical test data
- Set up automated cleanup processes

## Support

For issues with the remote accessibility test suite:

1. Check the troubleshooting section above
2. Review test logs and error messages
3. Verify environment configuration
4. Check network connectivity and firewall settings
5. Review the test implementation for recent changes

## License

These tests are part of the AutoApp UI Map & Intelligent Flow Engine project and follow the same license terms.