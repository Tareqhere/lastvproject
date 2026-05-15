# Sample API Requests

All examples use `http://localhost:3001` as the backend URL.

## Health Check

```bash
curl http://localhost:3001/api/health
```

## Authentication

### Sign Up
```bash
curl -X POST http://localhost:3001/api/signup \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email": "user@example.com", "password": "SecurePass1"}'
```

### Sign In
```bash
curl -X POST http://localhost:3001/api/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email": "user@example.com", "password": "SecurePass1"}'
```

### Check Auth Status
```bash
curl http://localhost:3001/api/me -b cookies.txt
```

### Sign Out
```bash
curl -X POST http://localhost:3001/api/logout -b cookies.txt
```

## Analysis

### Analyze Code (SQL Injection example)
```bash
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "inputType": "code",
    "content": "query = \"SELECT * FROM users WHERE id = \" + req.params.id; db.query(query);"
  }'
```

### Analyze URL
```bash
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "inputType": "link",
    "content": "https://example.com/search?q=<script>alert(1)</script>"
  }'
```

### Analyze CVE-like Description
```bash
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "inputType": "cve",
    "content": "A buffer overflow in the login handler allows unauthenticated remote code execution via a crafted username field exceeding 256 bytes."
  }'
```

## Reports

### List Reports
```bash
curl http://localhost:3001/api/reports -b cookies.txt
```

### Get Single Report
```bash
curl http://localhost:3001/api/reports/REPORT_ID -b cookies.txt
```

### Delete Report
```bash
curl -X DELETE http://localhost:3001/api/reports/REPORT_ID -b cookies.txt
```

## Account

### Delete Account (and all data)
```bash
curl -X DELETE http://localhost:3001/api/account -b cookies.txt
```
