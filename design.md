### System Architecture Flow

User -> Authentication -> Authorization -> Dashboard -> Core Actions [Booking, Cancel, History, My Tickets] -> Security/Sanitization Layer -> Database Storage

### Core Requirements & Constraints

1. Zero External Libraries / NPM Packages:
   - Use ONLY built-in runtime modules (e.g., Node.js `http`, `crypto`, `fs`, `path`, `url`, `querystring`).
   - Do NOT use Express, Fastify, Prisma, ORMs, JWT libraries, or Bcrypt.
   - Build custom HTTP routing, JSON request parsing, and response helpers from scratch.

2. Security Measures:
   - Implement password hashing using native `crypto.scrypt` or `crypto.pbkdf2` with unique salts.
   - Implement secure session tokens or signed cookies using native `crypto.createHmac`.
   - Add manual input sanitization to prevent XSS and SQL/Injection attacks.
   - Manually set security headers (CORS, CSP, X-Content-Type-Options, Strict-Transport-Security).

3. Authentic & Standard Documentation:
   - Document all API endpoints, data models, and custom utility functions using clear JSDoc comments.
   - Provide a clean README.md detailing setup, architecture layout, and execution without `npm install`.

4. AI Usage Policy:
   - Maintain pure, readable, maintainable, and hand-crafted standard code without bloated AI-generated boilerplate.

5. Functional Modules:
   - Authentication: User registration, login, logout, and password hashing.
   - Authorization: Role-based access control (RBAC) middleware for authenticated endpoints.
   - Dashboard & Core Features: Endpoints to handle ticket creation (Booking), revocation (Cancel), audit logs (History), and user ticket listings (My Tickets).
   - Data Layer: Pure file-system JSON persistence (`fs/promises`) or direct native TCP database adapter.

Please generate the directory layout and the clean, modular source code step-by-step.
