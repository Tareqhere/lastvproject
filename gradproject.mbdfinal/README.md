# AI Secure Code Analyzer

Educational AI-powered vulnerability analysis tool. Paste code, enter a URL, or describe a CVE, and get a structured defensive analysis report with CVSS scoring and remediation recommendations.

> ⚠️ **For educational and defensive purposes only.** This tool does NOT generate exploit payloads or attack instructions.

## Quick Start

### Prerequisites
- **Node.js** v18+ (v24 recommended)
- An OpenAI-compatible API key (or any LLM that accepts the OpenAI chat completions format)

### 1. Clone & Install

```bash
# Install backend dependencies
cd backend
cp .env.example .env   # Edit .env with your API key
npm install

# Install frontend dependencies
cd ../frontend
npm install
```

### 2. Configure Environment

Edit `backend/.env`:

```env
LLM_API_KEY=sk-your-api-key-here
LLM_API_ENDPOINT=https://api.openai.com/v1/chat/completions
LLM_MODEL=gpt-4o-mini
JWT_SECRET=your-random-secret-change-this
PORT=3001
DB_PATH=./data/analyzer.db
CORS_ORIGIN=http://localhost:5173
```

### 3. Run Locally

```bash
# Terminal 1: Start backend
cd backend
npm run dev

# Terminal 2: Start frontend
cd frontend
npm run dev
```

Open **http://localhost:5173** in your browser.

### 4. Run Tests

```bash
cd backend
npm test
```

## Project Structure

```
├── backend/
│   ├── src/
│   │   ├── db/           # SQLite schema & database layer
│   │   ├── middleware/    # JWT auth middleware
│   │   ├── routes/       # API endpoints (auth, analyze, reports)
│   │   ├── services/     # LLM client & CVSS scoring engine
│   │   ├── utils/        # Validation (Zod) & audit logging
│   │   └── index.ts      # Express entry point with security middleware
│   ├── tests/            # Vitest unit tests
│   └── .env.example      # Environment variable template
├── frontend/
│   └── src/
│       ├── App.tsx        # Main UI (preserved Figma design)
│       ├── api.ts         # Backend API client
│       └── types.ts       # TypeScript interfaces
├── samples/               # 5 sample inputs with expected outputs
├── DESIGN.md              # Architecture & security documentation
├── SAMPLE_REQUESTS.md     # curl examples for all API endpoints
└── SECURITY_CHECKLIST.md  # Pre-deployment security checklist
```

## Deployment (Render)

### Backend

1. Create a new **Web Service** on [render.com](https://render.com)
2. Set **Build Command**: `cd backend && npm install && npm run build`
3. Set **Start Command**: `cd backend && npm start`
4. Add environment variables from `.env.example`
5. Ensure `NODE_ENV=production`

### Frontend

1. Create a new **Static Site** on Render
2. Set **Build Command**: `cd frontend && npm install && npm run build`
3. Set **Publish Directory**: `frontend/dist`
4. Set the environment variable `VITE_API_URL` to your backend URL

### TLS/HTTPS

Render provides automatic TLS certificates for custom domains. The backend enforces HSTS headers via Helmet. For other providers:

- **Let's Encrypt**: Use certbot to obtain free TLS certificates
- **Reverse Proxy**: Place Nginx/Caddy in front and configure TLS termination
- The backend sets `Strict-Transport-Security` headers automatically

## API Overview

| Endpoint | Method | Description |
|---|---|---|
| `/api/analyze` | POST | Submit code/URL/text for analysis |
| `/api/signup` | POST | Create account |
| `/api/login` | POST | Authenticate |
| `/api/logout` | POST | Clear session |
| `/api/me` | GET | Current user info |
| `/api/reports` | GET | List reports |
| `/api/reports/:id` | GET | Get single report |
| `/api/reports/:id` | DELETE | Delete report |
| `/api/health` | GET | Health check |

## License

MIT
