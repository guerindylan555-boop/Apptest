# 📊 MaynDrive API Analysis Report

**Generated:** October 24, 2025
**App Version:** 1.1.34
**APK Signature:** 69875bf1

## 🏗️ API Infrastructure

### Base URLs
- **Production:** `https://api.knotcity.io/`
- **Staging:** `https://staging.api.knotcity.io/`
- **API Prefix:** `/api/application/`

### Architecture
- **Type:** RESTful API
- **Client:** Retrofit with OkHttp
- **Timeout:** 20 seconds
- **Authentication:** HTTP headers + session tokens
- **SSL/TLS:** Likely enforced with certificate pinning

### Development Features
- Debug mode detection in code
- Environment switching (production/staging)
- Comprehensive error handling
- Multi-language support (French, English)

## 🛵 Critical Vehicle Control APIs

### Unlock Operations
```
POST /api/application/vehicles/unlock
POST /api/application/vehicles/unlock/admin
POST /api/application/vehicles/freefloat/identify
POST /api/application/vehicles/freefloat/identify/admin
```

### Lock Operations
```
POST /api/application/vehicles/freefloat/lock
POST /api/application/vehicles/freefloat/lock/admin
POST /api/application/vehicles/freefloat/lock/temporary
POST /api/application/vehicles/freefloat/shutdown
```

### Vehicle Information
```
GET  /api/application/vehicles/models
GET  /api/application/vehicles/nearest-parkings
GET  /api/application/vehicles/sn/{serial_number}
GET  /api/application/vehicles/sn/{serial_number}/admin
POST /api/application/vehicles/sn/{serial_number}/admin-refresh
GET  /api/application/vehicles/external-locks/{id}/code
POST /api/application/vehicles/battery/open
```

## 🗺️ Location & Map APIs

### Clusters & Zones
```
GET  /api/application/clusters/{id}
GET  /api/application/clusters/closests
GET  /api/application/clusters/{id}/vehicles
GET  /api/application/clusters/{id}/spots
GET  /api/application/clusters/{id}/name
GET  /api/application/clusters/{id}/location
GET  /api/application/clusters/{id}/areas
POST /api/application/clusters
```

### Stations & Infrastructure
```
GET  /api/application/stations/cluster/{id}
GET  /api/application/stations/{id}/mainboard
GET  /api/application/stations/{id}/mainboard/status
GET  /api/application/stations
POST /api/application/stations/volume
POST /api/application/stations/alarm
```

### Spots & Parking
```
GET  /api/application/spots
POST /api/application/spots/unlock/admin
GET  /api/application/parking-zones
GET  /api/application/parking-zones/areas
```

## 👤 User Management APIs

### Account Operations
```
POST /api/application/logout
POST /api/application/users/
GET  /api/application/users/rides
```

## 💳 Payment & Subscription APIs

### Payment Methods
```
GET  /api/application/payment-methods
POST /api/application/payment-methods
PUT  /api/application/payment-methods/{user_method_id}
DELETE /api/application/payment-methods/{user_method_id}
POST /api/application/payment-methods/{user_method_id}/default
POST /api/application/payment-methods/intents/{intent_id}
GET  /api/application/payment-methods/available
POST /api/application/payment-methods/{method_id}
```

### Subscriptions & Pricing
```
GET  /api/application/subscriptions/
POST /api/application/subscriptions/subscribed
GET  /api/application/subscriptions/subscribed/{user_subscription_id}
POST /api/application/subscriptions/subscribed/{user_subscription_id}/confirm-payment
GET  /api/application/subscriptions/{id}/payment-methods
DELETE /api/application/subscriptions/subscribed/{user_subscription_id}
POST /api/application/subscriptions/{price_id}/subscribe
```

## 🔧 Application Configuration APIs

### App Configuration
```
GET  /api/application/config
GET  /api/application/features
GET  /api/application/versions
```

### Legal & Consents
```
GET  /api/application/consents/types
POST /api/application/consents
GET  /api/application/consents
```

## 📊 Analytics & Monitoring

```
POST /api/application/analytics/events
```

## 🎯 Key Findings for Unlock Capture

### Primary Unlock Routes
1. **`/api/application/vehicles/unlock`** - Main user unlock endpoint
2. **`/api/application/vehicles/freefloat/identify`** - Vehicle identification (pre-unlock)

### Request Flow Analysis
Based on decompiled code analysis, the typical unlock flow appears to be:

1. **Vehicle Identification** → `POST /api/application/vehicles/freefloat/identify`
2. **Vehicle Status Check** → `GET /api/application/vehicles/sn/{serial_number}`
3. **Unlock Request** → `POST /api/application/vehicles/unlock`
4. **Confirmation** → Response contains rental session data

### Hook Points for Capture

#### Recommended Hook Targets:
1. **Retrofit/OkHttp Interceptor Chain**
   - Hook into HTTP client interceptors
   - Capture all outgoing requests
   - Bypass SSL/TLS if needed

2. **Vehicle Service Interface (InterfaceC5131I)**
   - Hook the implementation class
   - Monitor method calls to unlock endpoints
   - Capture request parameters and responses

3. **Network Layer (Class C4185e)**
   - Target the dependency injection system
   - Hook into Retrofit instance creation
   - Monitor API service instantiation

#### Critical Classes for Hooking:
- `C4185e` - API service provider (Dependency Injection)
- `InterfaceC5131I` - Vehicle control interface
- `C4186f` - HTTP client configuration
- `C4456v` - Request interceptor chain

### Authentication Analysis
- Session-based authentication
- Multiple authentication headers
- Debug mode has special privileges
- App signature verification may affect API access

### Network Security
- SSL/TLS encryption
- Potential certificate pinning
- Timeout handling (20 seconds)
- Multiple fallback endpoints

## 🔍 Decompilation Insights

### Code Analysis Results
- **Total Java Files:** 1,000+ classes analyzed
- **API Endpoints:** 50+ endpoints discovered
- **Network Libraries:** Retrofit 2.x + OkHttp 3.x
- **Security:** Certificate pinning detected
- **Debug Features:** Enabled in debug builds

### Key Classes Identified
- **API Gateway:** `C4185e` (Service provider)
- **Vehicle Control:** `InterfaceC5131I`
- **User Management:** Multiple user service classes
- **Payment Processing:** Stripe integration detected
- **Location Services:** GPS and mapping APIs

### Environment Detection
```java
// From decompiled code:
boolean isProduction = hostSelection.equals("https://api.knotcity.io/");
boolean isStaging = hostSelection.equals("https://staging.api.knotcity.io/");
```

## 🚀 Recommended Implementation Strategy

### For Capture Script Development:
1. **Use existing working scripts as base**
2. **Focus on Retrofit/OkHttp hooks**
3. **Implement SSL bypass techniques**
4. **Monitor API service instantiation**
5. **Capture both request and response data**

### Critical Success Factors:
- **Timing:** Hook early in app lifecycle
- **Compatibility:** Support both debug and production builds
- **Reliability:** Handle network failures gracefully
- **Stealth:** Avoid detection by anti-tampering mechanisms

## 📝 Notes & Observations

1. **API Versioning:** No explicit versioning in URLs
2. **Rate Limiting:** Not visible in decompiled code
3. **Error Handling:** Comprehensive error responses
4. **Caching:** Local caching mechanisms in place
5. **Background Services:** Background sync operations detected

## ⚠️ Security Considerations

- **Certificate Pinning:** Likely implemented
- **API Authentication:** Multi-layer security
- **Anti-Tampering:** Debug detection mechanisms
- **Network Security:** TLS 1.2+ enforced
- **App Signing:** Signature verification affects API access

---

**Report Summary:** The MaynDrive app uses a comprehensive REST API with well-defined vehicle control endpoints. The unlock functionality centers around `/api/application/vehicles/unlock` with proper authentication and security measures. Successful hooking requires careful consideration of SSL/TLS bypass and anti-tampering mechanisms.