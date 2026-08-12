# Security Hardening — Walkthrough

## Summary

Fixed **15 security vulnerabilities** across the Ticket Management System. Created 4 new files and modified 4 existing files.

---

## New Files Created

| File | Purpose |
|---|---|
| [.env](file:///c:/Users/Dell/enosh/code/Project1.1/.env) | Stores all secrets & config (DB credentials, secret key, port) |
| [.env.example](file:///c:/Users/Dell/enosh/code/Project1.1/.env.example) | Template showing required vars — safe to commit to git |
| [.gitignore](file:///c:/Users/Dell/enosh/code/Project1.1/.gitignore) | Prevents `.env` and `node_modules` from being committed |
| [env.js](file:///c:/Users/Dell/enosh/code/Project1.1/env.js) | Custom `.env` parser — no external packages needed |

## Modified Files

### [database.js](file:///c:/Users/Dell/enosh/code/Project1.1/database.js)
- ❌ **Before**: Hardcoded `user: 'postgres'`, `password: 'enosh123'`, `host: 'localhost'`
- ✅ **After**: Uses `process.env.DATABASE_URL` connection string + production SSL support

### [server.js](file:///c:/Users/Dell/enosh/code/Project1.1/server.js) (11 fixes)
| Fix | What Changed |
|---|---|
| Env vars | `PORT` and `SECRET_KEY` read from `.env` instead of hardcoded |
| Startup validation | Server refuses to start if `SECRET_KEY` is missing or < 32 chars |
| Security headers | Every response now includes CSP, X-Frame-Options, HSTS, Referrer-Policy, etc. |
| Body size limit | Requests over 10KB are rejected (prevents memory DoS) |
| Safe JSON parsing | Malformed JSON returns 400 error instead of crashing the server |
| Input validation | Email format, name length (2–100), password length (6–128), ticket title (3–200), category/priority whitelists |
| Role escalation fix | Registration always sets `role = 'customer'` — client-sent `role` is ignored |
| Path traversal | Static file serving uses a whitelist; no arbitrary file paths allowed |
| Ticket ID validation | IDs must be numeric integers — prevents SQL injection via URL params |
| Token expiry | Session tokens expire after 8 hours (configurable via `SESSION_MAX_AGE_HOURS`) |
| Rate limiting | Max 5 login attempts per IP per 15 minutes; returns 429 when exceeded |
| Cookie hardening | Added `Max-Age` matching token expiry; `Secure` flag enabled in production |
| Timing-safe comparison | Token signature and password hash use `crypto.timingSafeEqual` |

### [login.html](file:///c:/Users/Dell/enosh/code/Project1.1/login.html)
- Fixed reflected XSS: URL error parameter now rendered via `.textContent` instead of HTML injection

### [dashboard.html](file:///c:/Users/Dell/enosh/code/Project1.1/dashboard.html)
- Replaced all `.innerHTML` table rendering with DOM API (`createElement` + `.textContent`)
- Malicious ticket titles like `<img onerror=alert(1)>` now display as plain text

### [admin.html](file:///c:/Users/Dell/enosh/code/Project1.1/admin.html)
- Same DOM-based rendering fix as dashboard
- User names, emails, and ticket data all safely escaped

---

## Verification Results

| Check | Result |
|---|---|
| `.env` loading | ✅ All variables read correctly |
| SECRET_KEY validation | ✅ 64-char key loaded |
| Module imports | ✅ All modules load without errors |
| Zero external packages added | ✅ Still only uses `pg` |

---

## How to Start the Server

```bash
node server.js
```

> [!IMPORTANT]
> **Admin accounts**: New registrations are now always `customer`. To create an admin, run this SQL directly in your PostgreSQL:
> ```sql
> UPDATE users SET role = 'admin' WHERE email = 'your-admin@email.com';
> ```

> [!TIP]
> **For production deployment**, generate a truly random secret key:
> ```bash
> node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```
> Then paste the output into your `.env` file as `SECRET_KEY`.
