# InputGuard Team Rules & Locked Interfaces
---
## 1. API Response Format (Frontend ↔ Backend)

All API endpoints return JSON with this exact envelope structure:

```json
{
  "success": boolean,
  "blocked": boolean,
  "message": string,
  "reason": string | null
}
```

### Field Rules

| Field | Type | Description |
|-------|------|-------------|
| `success` | `bool` | `true` if the operation succeeded (login/register worked). |
| `blocked` | `bool` | `true` if the Security Gateway stopped the request. |
| `message` | `string` | Human-readable result text. |
| `reason` | `string \| null` | Why it was blocked. Must be `null` when `blocked: false`. |

### Response Examples

**Legitimate login succeeds:**
```json
{
  "success": true,
  "blocked": false,
  "message": "Login successful",
  "reason": null
}
```

**Attack blocked by gateway:**
```json
{
  "success": false,
  "blocked": true,
  "message": "Request blocked by InputGuard",
  "reason": "SQL Injection detected"
}
```

**Wrong credentials (not blocked, just incorrect):**
```json
{
  "success": false,
  "blocked": false,
  "message": "Invalid credentials",
  "reason": null
}
```

### Locked Endpoints

| Method | Path | Purpose | Returns |
|--------|------|---------|---------|
| `GET` | `/` | Serve login page | HTML |
| `GET` | `/register` | Serve register page | HTML |
| `GET` | `/dashboard` | Serve dashboard page | HTML |
| `POST` | `/api/login` | Login API | JSON envelope |
| `POST` | `/api/register` | Register API | JSON envelope |
| `GET` | `/api/threat-log` | Fetch blocked attacks | `{ "threats": [...] }` |

---

## 2. Security Gateway Interface (Backend ↔ Security Module)

The Backend (Member A) imports and calls the Security module (Member B) using this exact function signature:

```python
from security.gateway import process_request

result = process_request(
    data={"username": "admin", "password": "' OR '1'='1"}
)
```

### Return Contract

`process_request()` MUST return a `dict` with this exact structure:

```python
{
    "sanitized_data": {"username": "admin", "password": "' OR '1'='1"},
    "is_blocked": True,
    "reason": "SQL Injection detected",
    "attack_type": "sqli"
}
```

### Field Rules

| Field | Type | Description |
|-------|------|-------------|
| `sanitized_data` | `dict` | The cleaned version of the input data. Always returned even if not blocked. |
| `is_blocked` | `bool` | `True` if the request should be rejected. |
| `reason` | `string \| None` | Human-readable block reason. `None` if `is_blocked` is `False`. |
| `attack_type` | `string` | Must be exactly one of: `"sqli"`, `"xss"`, `"cmdi"`, `"none"` (all lowercase). Use `"none"` when not blocked. |

### Implementation Note for Member B

Do not print to stdout. Write threat events to the log file using the format defined in Contract #6.

---

## 3. Database Schema (Backend ↔ Models)

One table only. No schema changes after Friday 10:00 AM without team vote.

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Rules

- **Password storage:** Always hash with `bcrypt` before storing, and verify with `bcrypt.checkpw` on login.
- **Password field length:** 128 characters (bcrypt hash string).
- **Username constraints:** Max 50 chars, unique, not null.

---

## 4. Environment Configuration (DevOps ↔ Everyone)

Member C owns the `.env` file. Everyone else reads these variables using the exact names below.

### `.env` Variables (DO NOT RENAME)

```bash
SECURITY_ENABLED=True
DATABASE_URL=sqlite:///./inputguard.db
LOG_FILE=threats.log
```

### Python Access Pattern

All members use this exact pattern to read settings:

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECURITY_ENABLED: bool = True
    DATABASE_URL: str = "sqlite:///./inputguard.db"
    LOG_FILE: str = "threats.log"
    
    class Config:
        env_file = ".env"

settings = Settings()
```

### Toggle Behavior

- `SECURITY_ENABLED=True`: Gateway is active. Attacks are blocked.
- `SECURITY_ENABLED=False`: Gateway is bypassed. Attacks succeed (for demo purposes).

---

## 5. Frontend HTML IDs & CSS Classes (Frontend ↔ JS)

Member C writes HTML. JS logic depends on these exact element identifiers.

### Locked HTML IDs

| Element | HTML ID | Used By |
|---------|---------|---------|
| Login form | `id="loginForm"` | JS event listener |
| Register form | `id="registerForm"` | JS event listener |
| Username input | `name="username"` | `FormData.get('username')` |
| Password input | `name="password"` | `FormData.get('password')` |
| Alert toast box | `id="alertBox"` | JS alert display |
| Threat log panel | `id="threatLog"` | JS threat log rendering |

### Locked CSS Alert Classes

| State | Class Name | Color |
|-------|-----------|-------|
| Success | `alert-success` | Green |
| Blocked / Attack | `alert-danger` | Red |
| Error / Warning | `alert-warning` | Yellow |

---

## 6. Threat Log Format (Security ↔ Backend ↔ Frontend)

### Log File Format

Member B writes one JSON line per blocked attack to the file specified by `LOG_FILE` (default: `threats.log`).

**Single line structure:**

```json
{"timestamp": "2026-07-24T14:30:00", "attack_type": "sqli", "payload": "' OR '1'='1", "ip": "127.0.0.1"}
```

### Field Rules

| Field | Type | Format |
|-------|------|--------|
| `timestamp` | `string` | ISO 8601 format (`YYYY-MM-DDTHH:MM:SS`) |
| `attack_type` | `string` | One of: `"sqli"`, `"xss"`, `"cmdi"` |
| `payload` | `string` | The raw blocked input (truncate to 500 chars if needed) |
| `ip` | `string` | Client IP address |

### API Response Format

Member A's `/api/threat-log` endpoint returns:

```json
{
  "threats": [
    {"timestamp": "2026-07-24T14:30:00", "attack_type": "sqli", "payload": "' OR '1'='1", "ip": "127.0.0.1"},
    {"timestamp": "2026-07-24T14:32:00", "attack_type": "xss", "payload": "<script>alert(1)</script>", "ip": "127.0.0.1"}
  ]
}
```

---

## 7. Project Structure (Locked)

```
inputguard/
├── 📂 frontend/                    # Member C
│   ├── 📂 pages/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── register.html
│   │   └── dashboard.html
│   ├── 📂 css/
│   │   └── style.css
│   └── 📂 js/
│       └── app.js
│
├── 📂 app/                         # Member A
│   ├── __init__.py
│   ├── main.py
│   ├── routes.py
│   ├── models.py
│   ├── database.py
│   └── config.py
│
├── 📂 security/                    # Member B
│   ├── __init__.py
│   ├── gateway.py
│   ├── sanitizers.py
│   └── logger.py
│
├── 📂 tests/                       # Member D + B
│   └── payloads.py
│
├── 📂 docs/                        # Member D
│   └── Rules.md
│
├── 📄 .env                         # Member C
├── 📄 Dockerfile                   # Member C
├── 📄 docker-compose.yml           # Member C
├── 📄 requirements.txt             # Member A / C
└── 📄 README.md                    # Member D
```

---

## 8. Team Responsibilities

| Role | Member | Deliverables |
|------|--------|--------------|
| **Backend Lead** | Member A | `app/` — FastAPI app, routes, models, database, config |
| **Security Engineer** | Member B | `security/` — gateway, sanitizers, logger, `tests/payloads.py` |
| **Frontend + DevOps** | Member C | `frontend/`, `Dockerfile`, `docker-compose.yml`, demo video |
| **Docs + QA** | Member D | `README.md`, `docs/`, project report, QA testing |

---

## 9. Pre-Code Acknowledgement

**Signed-off:**

- [x] Member A (Backend)
- [ ] Member B (Security)
- [ ] Member C (Frontend + DevOps)
- [ ] Member D (Docs + QA)
