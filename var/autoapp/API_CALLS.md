# MaynDrive Lock/Unlock API Calls

Successfully captured on 2025-10-24

## 🔒 LOCK API (Pause/Temporary Lock)

**Endpoint:** `https://api.knotcity.io/api/application/vehicles/freefloat/lock/temporary`

**Method:** `POST`

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMTc5NTMsInNlc3Npb25faWQiOiJmNGVmODNkYS0yMWIwLTRkZWItYjdmNi1mODAxYzc0Mzg1NzciLCJpYXQiOjE3NjEyOTU5ODAsImV4cCI6MTc2MTI5OTU4MH0.Cq5J-wI-qwIGWi03TGpOyTVMEMqI-xUQY3eZsOHOt2w
```

**Request Body:**
```
LockVehicleRequest(vehicleId=909, force=false)
```

**JSON Equivalent:**
```json
{
  "vehicleId": 909,
  "force": false
}
```

**Interface Method:** `T3.I.o()`

**cURL Example:**
```bash
curl -X POST 'https://api.knotcity.io/api/application/vehicles/freefloat/lock/temporary' \
  -H 'Authorization: Bearer YOUR_JWT_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"vehicleId": 909, "force": false}'
```

---

## 🔓 UNLOCK API (Resume Trip)

**Endpoint:** `https://api.knotcity.io/api/application/trips/{tripId}/resume`

**Example:** `https://api.knotcity.io/api/application/trips/321668/resume`

**Method:** `PUT`

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMTc5NTMsInNlc3Npb25faWQiOiJmNGVmODNkYS0yMWIwLTRkZWItYjdmNi1mODAxYzc0Mzg1NzciLCJpYXQiOjE3NjEyOTU5ODAsImV4cCI6MTc2MTI5OTU4MH0.Cq5J-wI-qwIGWi03TGpOyTVMEMqI-xUQY3eZsOHOt2w
```

**URL Parameters:**
- `tripId`: The ID of the trip to resume (e.g., `321668`)

**Request Body:** (empty)

**Interface Method:** `T3.G.b()`

**cURL Example:**
```bash
curl -X PUT 'https://api.knotcity.io/api/application/trips/321668/resume' \
  -H 'Authorization: Bearer YOUR_JWT_TOKEN'
```

---

## Notes

- Both endpoints require a valid JWT Bearer token
- The JWT token expires after 1 hour (exp claim)
- Vehicle ID for LOCK: `909` (TUF055)
- Trip ID for UNLOCK: `321668`
- Authorization token format includes user_id, session_id, iat (issued at), and exp (expiration)

## JWT Token Decoded

```json
{
  "user_id": 117953,
  "session_id": "f4ef83da-21b0-4deb-b7f6-f801c7438577",
  "iat": 1761295980,
  "exp": 1761299580
}
```

## Capture Method

Captured using Frida with `mayndrive_simple_capture.js` hooking `qh.e (RunnableC3022e)` for HTTP request interception.

**Lock flow script:** `/home/blhack/project/Apptest/scripts/working/mayndrive_lock_flow.js`
**Unlock flow script:** `/home/blhack/project/Apptest/scripts/working/mayndrive_unlock_flow.js`
