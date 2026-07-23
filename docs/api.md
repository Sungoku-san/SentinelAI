# Administration API Reference

This document lists the REST API endpoints exposed by the SentinelAI FastAPI administration server on port `8000`. All endpoints (except `/api/auth/login`) require a valid JWT bearer token in the `Authorization` header.

---

## 1. Authentication

### `POST /api/auth/login`
Authenticates administration username/password and issues a JWT token.
- **Request Body**:
  ```json
  {
    "username": "mujeeb",
    "password": "12345"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer"
  }
  ```

### `GET /api/auth/me`
Validates JWT token and returns profile details.
- **Response**:
  ```json
  {
    "username": "admin"
  }
  ```

---

## 2. Dashboard Metrics

### `GET /api/dashboard/stats`
Retrieves aggregated statistics and attack graphs.
- **Response**:
  ```json
  {
    "total_sessions": 482,
    "total_attacks": 3105,
    "critical_alerts": 12,
    "unique_ips": 34,
    "protocol_distribution": {
      "SSH": 150,
      "HTTP": 220,
      "FTP": 50,
      "Telnet": 62
    },
    "threat_level_distribution": {
      "Low": 210,
      "Medium": 180,
      "High": 80,
      "Critical": 12
    },
    "top_ips": [
      {
        "ip_address": "198.51.100.5",
        "attack_count": 215,
        "max_score": 95.0,
        "protocols": ["SSH", "FTP"],
        "country": "US"
      }
    ]
  }
  ```

### `GET /api/dashboard/status`
Checks if honeypot protocol emulators are actively running on their designated ports and returns sniffer stats.
- **Response**:
  ```json
  {
    "ssh_port": 2222,
    "http_port": 8080,
    "ftp_port": 2121,
    "telnet_port": 2323,
    "ssh_running": true,
    "http_running": true,
    "ftp_running": true,
    "telnet_running": true,
    "packet_stats": {
      "total_packets": 240,
      "tcp_packets": 240,
      "udp_packets": 0,
      "ip_counts": {},
      "port_counts": {}
    }
  }
  ```

---

## 3. Session Transcripts

### `GET /api/sessions`
Retrieves paginated connection logs. Supports filtering by `protocol` or `threat_level` query parameters.
- **Query Parameters**:
  - `limit` (default: 20)
  - `offset` (default: 0)
  - `protocol` (optional: SSH, HTTP, FTP, Telnet)
  - `threat_level` (optional: Low, Medium, High, Critical)
- **Response**: List of session documents (matching schemas).

### `GET /api/sessions/{session_id}`
Retrieves complete forensic connection transcripts for a single connection.
- **Response**: Contains full array of credentials tried, commands typed (with responses), quarantined file paths, geo-location parameters, and the AI classification analysis block.

---

## 4. Reports

### `GET /api/reports/pdf`
Compiles captured threat database states and triggers a PDF download stream.

### `GET /api/reports/csv`
Dumps full connection log tables and triggers a raw CSV file stream.
