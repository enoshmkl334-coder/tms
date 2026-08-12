// server.js — Secure Ticket Management System Server
// Load environment variables FIRST (before anything else)
require('./env');

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./database');

// ─── Configuration from Environment ─────────────────────────────────
const PORT = parseInt(process.env.PORT, 10) || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const SESSION_MAX_AGE_HOURS = parseInt(process.env.SESSION_MAX_AGE_HOURS, 10) || 8;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Validate that SECRET_KEY is set and strong enough
if (!SECRET_KEY || SECRET_KEY.length < 32) {
  console.error('❌ FATAL: SECRET_KEY must be set in .env and be at least 32 characters.');
  process.exit(1);
}

// ─── Security Constants ─────────────────────────────────────────────
const MAX_BODY_SIZE = 10 * 1024; // 10KB max request body
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_ATTEMPTS = 5; // max login attempts per window

// Whitelist of static files that can be served (prevents path traversal)
const STATIC_FILE_WHITELIST = new Set([
  'login.html', 'login.css',
  'register.html', 'register.css',
  'dashboard.html', 'dashboard.css',
  'admin.html', 'admin.css',
]);

// ─── Rate Limiter (in-memory) ───────────────────────────────────────
const loginAttempts = new Map(); // IP -> { count, resetTime }

function checkRateLimit(ip) {
  // Don't rate limit local development traffic
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    return true;
  }

  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (!record || now > record.resetTime) {
    loginAttempts.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return true; // allowed
  }

  if (record.count >= RATE_LIMIT_MAX_ATTEMPTS) {
    return false; // blocked
  }

  record.count++;
  return true; // allowed
}

// Clean up expired rate limit entries every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts) {
    if (now > record.resetTime) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ─── HTML Escaping (prevents XSS in stored data) ───────────────────
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ─── Input Validation Helpers ───────────────────────────────────────
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  // Basic but effective email validation
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function isValidName(name) {
  return typeof name === 'string' && name.trim().length >= 2 && name.length <= 100;
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 6 && password.length <= 128;
}

const VALID_CATEGORIES = new Set(['General', 'Billing', 'Technical', 'Feature']);
const VALID_PRIORITIES = new Set(['low', 'medium', 'high', 'urgent']);
const VALID_STATUSES = new Set(['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CANCELLED']);
const VALID_ROLES = new Set(['customer', 'agent', 'admin']);


function isValidTicketId(id) {
  return /^\d+$/.test(id);
}

// ─── Security Headers ───────────────────────────────────────────────
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  if (IS_PRODUCTION) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

// ─── Token Functions (with expiry) ──────────────────────────────────
function createToken(userData) {
  const payload = {
    ...userData,
    exp: Date.now() + (SESSION_MAX_AGE_HOURS * 60 * 60 * 1000),
  };
  const text = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', SECRET_KEY).update(text).digest('hex');
  return Buffer.from(text).toString('base64url') + '.' + signature;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [base64Text, signature] = parts;

  let originalText;
  try {
    originalText = Buffer.from(base64Text, 'base64url').toString('utf-8');
  } catch {
    return null;
  }

  const expectedSignature = crypto.createHmac('sha256', SECRET_KEY).update(originalText).digest('hex');

  // Timing-safe comparison to prevent timing attacks
  if (signature.length !== expectedSignature.length) return null;
  const sigBuffer = Buffer.from(signature, 'utf-8');
  const expectedBuffer = Buffer.from(expectedSignature, 'utf-8');
  if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) return null;

  let payload;
  try {
    payload = JSON.parse(originalText);
  } catch {
    return null;
  }

  // Check token expiry
  if (payload.exp && Date.now() > payload.exp) {
    return null; // Token expired
  }

  return payload;
}

function getLoggedInUser(req) {
  const cookieHeader = req.headers['cookie'];
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';').reduce((acc, item) => {
    const [key, ...valParts] = item.trim().split('=');
    acc[key] = valParts.join('='); // handles '=' in cookie values
    return acc;
  }, {});

  const token = cookies['session_token'];
  return verifyToken(token);
}

// ─── Audit Log Recorder Helper ──────────────────────────────────────
async function recordAuditLog(userId, action, details) {
  try {
    await db.query(
      'INSERT INTO audit_logs (user_id, action, details) VALUES ($1, $2, $3)',
      [userId, action, details]
    );
  } catch (err) {
    console.error('Audit Log Error:', err);
  }
}

// ─── Password Hashing ───────────────────────────────────────────────
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve({ hash: derivedKey.toString('hex'), salt });
    });
  });
}

function verifyPassword(password, storedHash, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      // Timing-safe comparison
      const derivedHex = derivedKey.toString('hex');
      if (derivedHex.length !== storedHash.length) return resolve(false);
      const a = Buffer.from(derivedHex, 'utf-8');
      const b = Buffer.from(storedHash, 'utf-8');
      resolve(crypto.timingSafeEqual(a, b));
    });
  });
}

// ─── Cookie Helper ──────────────────────────────────────────────────
function buildSessionCookie(token) {
  const maxAgeSec = SESSION_MAX_AGE_HOURS * 60 * 60;
  let cookie = `session_token=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${maxAgeSec}`;
  if (IS_PRODUCTION) {
    cookie += '; Secure';
  }
  return cookie;
}

// ─── JSON Response Helper ───────────────────────────────────────────
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ─── Client IP Helper ───────────────────────────────────────────────
function getClientIp(req) {
  // Support reverse proxies (Nginx, Render, Railway)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

// ═══════════════════════════════════════════════════════════════════════
// HTTP SERVER
// ═══════════════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  // Apply security headers to EVERY response
  setSecurityHeaders(res);

  // 1. Serve static HTML & CSS files (GET only, whitelisted)
  if (req.method === 'GET') {
    const cleanUrl = req.url.split('?')[0];
    let filePath = cleanUrl === '/' ? 'login.html' : cleanUrl.substring(1);

    // 🛡️ Path traversal protection: only serve whitelisted files
    if (!STATIC_FILE_WHITELIST.has(filePath)) {
      // Not a static file — fall through to API handling below
    } else {
      // 🛡️ SECURITY GUARD FOR DASHBOARD!
      if (filePath === 'dashboard.html') {
        const user = getLoggedInUser(req);
        if (!user) {
          const errorMsg = encodeURIComponent('Please sign in first to access the dashboard.');
          res.writeHead(302, { 'Location': `/login.html?error=${errorMsg}` });
          return res.end();
        }
      }

      // 🛡️ SECURITY GUARD FOR ADMIN PAGE: Must be Logged in AND role === 'admin'!
      if (filePath === 'admin.html') {
        const user = getLoggedInUser(req);
        if (!user) {
          const errorMsg = encodeURIComponent('Please sign in as Admin to access Admin Panel.');
          res.writeHead(302, { 'Location': `/login.html?error=${errorMsg}` });
          return res.end();
        }
        if (user.role !== 'admin') {
          const errorMsg = encodeURIComponent('Access Denied: Admin privileges required.');
          res.writeHead(302, { 'Location': `/login.html?error=${errorMsg}` });
          return res.end();
        }
      }

      const ext = path.extname(filePath);
      const mimeType = ext === '.html' ? 'text/html' : 'text/css';
      const fullPath = path.join(__dirname, filePath);

      // Double-check resolved path stays within project directory
      if (!fullPath.startsWith(__dirname)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        return res.end('403 Forbidden');
      }

      fs.readFile(fullPath, (err, content) => {
        if (err) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('404 File Not Found');
        } else {
          res.writeHead(200, { 'Content-Type': mimeType });
          res.end(content);
        }
      });
      return;
    }
  }

  // 2. Parse JSON Request Body for API requests (with size limit)
  let body = '';
  let bodyTooLarge = false;

  req.on('data', chunk => {
    body += chunk.toString();
    if (body.length > MAX_BODY_SIZE) {
      bodyTooLarge = true;
      req.destroy(); // Stop reading
    }
  });

  req.on('end', async () => {
    if (bodyTooLarge) {
      return sendJson(res, 413, { error: 'Request body too large (max 10KB)' });
    }

    // Safe JSON parsing — won't crash server on malformed input
    let data = {};
    if (body) {
      try {
        data = JSON.parse(body);
      } catch {
        return sendJson(res, 400, { error: 'Invalid JSON in request body' });
      }
    }

    // --- REGISTER ENDPOINT ---
    if (req.method === 'POST' && req.url === '/api/register') {
      try {
        const { name, email, password } = data;

        // 🛡️ Input validation
        if (!isValidName(name)) {
          return sendJson(res, 400, { error: 'Name must be 2–100 characters' });
        }
        if (!isValidEmail(email)) {
          return sendJson(res, 400, { error: 'Invalid email address' });
        }
        if (!isValidPassword(password)) {
          return sendJson(res, 400, { error: 'Password must be 6–128 characters' });
        }

        const { hash, salt } = await hashPassword(password);

        // 🛡️ ALWAYS register as 'customer' — never trust client-sent role
        const userRole = 'customer';

        const result = await db.query(
          'INSERT INTO users (name, email, password_hash, salt, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
          [escapeHtml(name.trim()), email.toLowerCase().trim(), hash, salt, userRole]
        );

        await recordAuditLog(result.rows[0].id, 'USER_REGISTER', `Account created for ${escapeHtml(email)} (${userRole})`);

        sendJson(res, 201, { message: 'Account created successfully! Redirecting...' });
      } catch (err) {
        console.error('Registration Error:', err);
        sendJson(res, 400, { error: 'User already exists or invalid data' });
      }
    }

    // --- LOGIN ENDPOINT ---
    else if (req.method === 'POST' && req.url === '/api/login') {
      const clientIp = getClientIp(req);

      // 🛡️ Rate limiting
      if (!checkRateLimit(clientIp)) {
        return sendJson(res, 429, { error: 'Too many login attempts. Please try again in 15 minutes.' });
      }

      try {
        const { email, password } = data;

        if (!email || !password) {
          return sendJson(res, 400, { error: 'Email and password are required' });
        }

        const result = await db.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
        if (result.rows.length === 0) {
          return sendJson(res, 401, { error: 'Invalid email or password' });
        }

        const user = result.rows[0];
        const isValid = await verifyPassword(password, user.password_hash, user.salt);

        if (!isValid) {
          return sendJson(res, 401, { error: 'Invalid email or password' });
        }

        const token = createToken({ id: user.id, name: user.name, email: user.email, role: user.role });
        res.setHeader('Set-Cookie', buildSessionCookie(token));

        await recordAuditLog(user.id, 'USER_LOGIN', `User ${user.email} logged in`);

        sendJson(res, 200, { message: `Welcome back, ${escapeHtml(user.name)}!`, role: user.role });
      } catch (err) {
        console.error('Login Error:', err);
        sendJson(res, 500, { error: 'Server error during login' });
      }
    }

    // --- LOGOUT ENDPOINT ---
    else if (req.method === 'POST' && req.url === '/api/logout') {
      const user = getLoggedInUser(req);
      if (user) {
        await recordAuditLog(user.id, 'USER_LOGOUT', `User ${user.email} logged out`);
      }
      res.setHeader('Set-Cookie', 'session_token=; HttpOnly; Path=/; Max-Age=0');
      sendJson(res, 200, { message: 'Logged out successfully' });
    }

    // --- GET CURRENT USER ---
    else if (req.method === 'GET' && req.url === '/api/me') {
      const user = getLoggedInUser(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Not authenticated' });
      }
      // Return user without the exp field
      const { exp, ...safeUser } = user;
      sendJson(res, 200, { user: safeUser });
    }

    // --- BOOKING: CREATE TICKET ---
    else if (req.method === 'POST' && req.url === '/api/tickets') {
      const user = getLoggedInUser(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }

      try {
        const { title, category, priority } = data;

        // 🛡️ Input validation
        if (!title || typeof title !== 'string' || title.trim().length < 3 || title.length > 200) {
          return sendJson(res, 400, { error: 'Title must be 3–200 characters' });
        }
        if (category && !VALID_CATEGORIES.has(category)) {
          return sendJson(res, 400, { error: 'Invalid category' });
        }
        if (priority && !VALID_PRIORITIES.has(priority)) {
          return sendJson(res, 400, { error: 'Invalid priority' });
        }

        const ticketNumber = 'TCK-' + Math.floor(100000 + Math.random() * 900000);

        const result = await db.query(
          'INSERT INTO tickets (ticket_number, title, category, priority, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
          [ticketNumber, escapeHtml(title.trim()), category || 'General', priority || 'medium', user.id]
        );

        await recordAuditLog(user.id, 'TICKET_CREATE', `Created ticket ${ticketNumber}: ${escapeHtml(title.trim())}`);

        sendJson(res, 201, { message: 'Ticket booked successfully!', ticket: result.rows[0] });
      } catch (err) {
        console.error('Create Ticket Error:', err);
        sendJson(res, 400, { error: 'Failed to create ticket' });
      }
    }

    // --- MY TICKETS: GET USER TICKETS ---
    else if (req.method === 'GET' && req.url === '/api/tickets/my') {
      const user = getLoggedInUser(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }

      try {
        const result = await db.query(
          `SELECT tickets.*, agent.name as assigned_agent_name, agent.email as assigned_agent_email 
           FROM tickets 
           LEFT JOIN users agent ON tickets.assigned_to = agent.id 
           WHERE tickets.user_id = $1 
           ORDER BY tickets.created_at DESC`,
          [user.id]
        );
        sendJson(res, 200, { tickets: result.rows });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to fetch tickets' });
      }
    }

    // --- CANCEL TICKET ---
    else if (req.method === 'POST' && req.url.startsWith('/api/tickets/') && req.url.endsWith('/cancel')) {
      const user = getLoggedInUser(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }

      try {
        const parts = req.url.split('/');
        const ticketId = parts[3];

        if (!isValidTicketId(ticketId)) {
          return sendJson(res, 400, { error: 'Invalid ticket ID' });
        }

        const result = await db.query(
          "UPDATE tickets SET status = 'CANCELLED' WHERE id = $1 AND user_id = $2 RETURNING *",
          [parseInt(ticketId, 10), user.id]
        );

        if (result.rows.length === 0) {
          return sendJson(res, 404, { error: 'Ticket not found or not owned by you' });
        }

        await recordAuditLog(user.id, 'TICKET_CANCEL', `Cancelled ticket ${result.rows[0].ticket_number}`);

        sendJson(res, 200, { message: 'Ticket cancelled successfully!', ticket: result.rows[0] });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to cancel ticket' });
      }
    }

    // --- HISTORY: GET AUDIT LOGS ---
    else if (req.method === 'GET' && req.url === '/api/history') {
      const user = getLoggedInUser(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }

      try {
        const result = await db.query(
          'SELECT * FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC',
          [user.id]
        );
        sendJson(res, 200, { logs: result.rows });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to fetch history' });
      }
    }

    // ---------------------------------------------------------
    // 💬 TICKET THREAD & COMMENTS ENDPOINTS
    // ---------------------------------------------------------

    // --- GET TICKET COMMENTS ---
    else if (req.method === 'GET' && req.url.startsWith('/api/tickets/') && req.url.endsWith('/comments')) {
      const user = getLoggedInUser(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }

      try {
        const parts = req.url.split('/');
        const ticketId = parts[3];

        if (!isValidTicketId(ticketId)) {
          return sendJson(res, 400, { error: 'Invalid ticket ID' });
        }

        const ticketCheck = await db.query('SELECT user_id, assigned_to FROM tickets WHERE id = $1', [parseInt(ticketId, 10)]);
        if (ticketCheck.rows.length === 0) {
          return sendJson(res, 404, { error: 'Ticket not found' });
        }

        const ticket = ticketCheck.rows[0];
        const isStaff = user.role === 'admin' || user.role === 'agent';
        if (!isStaff && ticket.user_id !== user.id) {
          return sendJson(res, 403, { error: 'Forbidden' });
        }

        const commentsQuery = isStaff
          ? `SELECT ticket_comments.*, users.name as user_name, users.role as user_role 
             FROM ticket_comments 
             JOIN users ON ticket_comments.user_id = users.id 
             WHERE ticket_id = $1 ORDER BY ticket_comments.created_at ASC`
          : `SELECT ticket_comments.*, users.name as user_name, users.role as user_role 
             FROM ticket_comments 
             JOIN users ON ticket_comments.user_id = users.id 
             WHERE ticket_id = $1 AND is_internal = FALSE ORDER BY ticket_comments.created_at ASC`;

        const result = await db.query(commentsQuery, [parseInt(ticketId, 10)]);
        sendJson(res, 200, { comments: result.rows });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to fetch comments' });
      }
    }

    // --- POST TICKET COMMENT ---
    else if (req.method === 'POST' && req.url.startsWith('/api/tickets/') && req.url.endsWith('/comments')) {
      const user = getLoggedInUser(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Unauthorized' });
      }

      try {
        const parts = req.url.split('/');
        const ticketId = parts[3];

        if (!isValidTicketId(ticketId)) {
          return sendJson(res, 400, { error: 'Invalid ticket ID' });
        }

        const { message, isInternal } = data;
        if (!message || typeof message !== 'string' || message.trim().length === 0) {
          return sendJson(res, 400, { error: 'Message cannot be empty' });
        }

        const isStaff = user.role === 'admin' || user.role === 'agent';
        const internalFlag = isStaff && Boolean(isInternal);

        const result = await db.query(
          `INSERT INTO ticket_comments (ticket_id, user_id, message, is_internal) 
           VALUES ($1, $2, $3, $4) 
           RETURNING *`,
          [parseInt(ticketId, 10), user.id, escapeHtml(message.trim()), internalFlag]
        );

        sendJson(res, 201, { message: 'Comment added successfully!', comment: result.rows[0] });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to add comment' });
      }
    }

    // ---------------------------------------------------------
    // 🛠️ SUPPORT AGENT ENDPOINTS
    // ---------------------------------------------------------

    // --- AGENT: GET MY ASSIGNED TICKETS ---
    else if (req.method === 'GET' && req.url === '/api/agent/tickets') {
      const user = getLoggedInUser(req);
      if (!user || (user.role !== 'agent' && user.role !== 'admin')) {
        return sendJson(res, 403, { error: 'Forbidden: Support Agent access required' });
      }

      try {
        const result = await db.query(
          `SELECT tickets.*, u.name as user_name, u.email as user_email 
           FROM tickets 
           JOIN users u ON tickets.user_id = u.id 
           WHERE tickets.assigned_to = $1 
           ORDER BY tickets.created_at DESC`,
          [user.id]
        );
        sendJson(res, 200, { tickets: result.rows });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to fetch assigned tickets' });
      }
    }

    // --- AGENT: RESOLVE ASSIGNED TICKET ---
    else if (req.method === 'PUT' && req.url.startsWith('/api/agent/tickets/') && req.url.endsWith('/resolve')) {
      const user = getLoggedInUser(req);
      if (!user || (user.role !== 'agent' && user.role !== 'admin')) {
        return sendJson(res, 403, { error: 'Forbidden: Support Agent access required' });
      }

      try {
        const parts = req.url.split('/');
        const ticketId = parts[4];

        if (!isValidTicketId(ticketId)) {
          return sendJson(res, 400, { error: 'Invalid ticket ID' });
        }

        const { resolutionSummary } = data;
        if (!resolutionSummary || typeof resolutionSummary !== 'string' || resolutionSummary.trim().length < 5) {
          return sendJson(res, 400, { error: 'Resolution summary must be at least 5 characters' });
        }

        const result = await db.query(
          `UPDATE tickets 
           SET status = 'RESOLVED', resolution_summary = $1, resolved_at = NOW() 
           WHERE id = $2 AND (assigned_to = $3 OR $4 = 'admin') 
           RETURNING *`,
          [escapeHtml(resolutionSummary.trim()), parseInt(ticketId, 10), user.id, user.role]
        );

        if (result.rows.length === 0) {
          return sendJson(res, 404, { error: 'Ticket not found or not assigned to you' });
        }

        await recordAuditLog(user.id, 'TICKET_RESOLVED', `Agent resolved ticket ${result.rows[0].ticket_number}`);

        sendJson(res, 200, { message: 'Ticket marked as resolved!', ticket: result.rows[0] });
      } catch (err) {
        console.error('Resolve Ticket Error:', err);
        sendJson(res, 500, { error: 'Failed to resolve ticket' });
      }
    }

    // ---------------------------------------------------------
    // 🛡️ ADMIN-ONLY ENDPOINTS
    // ---------------------------------------------------------

    // --- ADMIN: GET SYSTEM STATS ---
    else if (req.method === 'GET' && req.url === '/api/admin/stats') {
      const user = getLoggedInUser(req);
      if (!user || user.role !== 'admin') {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      try {
        const totalTickets = await db.query('SELECT COUNT(*) FROM tickets');
        const openTickets = await db.query("SELECT COUNT(*) FROM tickets WHERE status = 'OPEN'");
        const inProgress = await db.query("SELECT COUNT(*) FROM tickets WHERE status = 'IN_PROGRESS'");
        const resolvedTickets = await db.query("SELECT COUNT(*) FROM tickets WHERE status = 'RESOLVED'");
        const cancelledTickets = await db.query("SELECT COUNT(*) FROM tickets WHERE status = 'CANCELLED'");

        sendJson(res, 200, {
          stats: {
            total: parseInt(totalTickets.rows[0].count),
            open: parseInt(openTickets.rows[0].count),
            inProgress: parseInt(inProgress.rows[0].count),
            resolved: parseInt(resolvedTickets.rows[0].count),
            cancelled: parseInt(cancelledTickets.rows[0].count)
          }
        });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to fetch admin stats' });
      }
    }

    // --- ADMIN: GET ALL TICKETS FROM ALL USERS ---
    else if (req.method === 'GET' && req.url === '/api/admin/tickets') {
      const user = getLoggedInUser(req);
      if (!user || user.role !== 'admin') {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      try {
        const result = await db.query(`
          SELECT tickets.*, 
                 u.name as user_name, 
                 u.email as user_email,
                 agent.name as assigned_agent_name, 
                 agent.email as assigned_agent_email 
          FROM tickets 
          JOIN users u ON tickets.user_id = u.id 
          LEFT JOIN users agent ON tickets.assigned_to = agent.id
          ORDER BY tickets.created_at DESC
        `);
        sendJson(res, 200, { tickets: result.rows });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to fetch all tickets' });
      }
    }

    // --- ADMIN: GET LIST OF AGENTS FOR ASSIGNMENT ---
    else if (req.method === 'GET' && req.url === '/api/admin/agents') {
      const user = getLoggedInUser(req);
      if (!user || user.role !== 'admin') {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      try {
        const result = await db.query(
          "SELECT id, name, email, department, role FROM users WHERE role IN ('agent', 'admin') ORDER BY name ASC"
        );
        sendJson(res, 200, { agents: result.rows });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to fetch agents' });
      }
    }

    // --- ADMIN: GET ALL USERS (FOR ROLE MANAGEMENT) ---
    else if (req.method === 'GET' && req.url === '/api/admin/users') {
      const user = getLoggedInUser(req);
      if (!user || user.role !== 'admin') {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      try {
        const result = await db.query(
          "SELECT id, name, email, role, department, created_at FROM users ORDER BY created_at DESC"
        );
        sendJson(res, 200, { users: result.rows });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to fetch users' });
      }
    }

    // --- ADMIN: UPDATE USER ROLE / DEPARTMENT ---
    else if (req.method === 'PUT' && req.url.startsWith('/api/admin/users/') && req.url.endsWith('/role')) {
      const user = getLoggedInUser(req);
      if (!user || user.role !== 'admin') {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      try {
        const parts = req.url.split('/');
        const targetUserId = parts[4];

        if (!isValidTicketId(targetUserId)) {
          return sendJson(res, 400, { error: 'Invalid user ID' });
        }

        const { role, department } = data;
        if (!VALID_ROLES.has(role)) {
          return sendJson(res, 400, { error: 'Invalid role' });
        }

        const result = await db.query(
          'UPDATE users SET role = $1, department = $2 WHERE id = $3 RETURNING id, name, email, role, department',
          [role, escapeHtml((department || 'General').trim()), parseInt(targetUserId, 10)]
        );

        if (result.rows.length === 0) {
          return sendJson(res, 404, { error: 'User not found' });
        }

        await recordAuditLog(user.id, 'ADMIN_USER_ROLE_UPDATE', `Updated user ${result.rows[0].email} role to ${role}`);

        sendJson(res, 200, { message: 'User role updated successfully!', user: result.rows[0] });
      } catch (err) {
        sendJson(res, 500, { error: 'Failed to update user role' });
      }
    }

    // --- ADMIN: ASSIGN TICKET TO AGENT ---
    else if (req.method === 'PUT' && req.url.startsWith('/api/admin/tickets/') && req.url.endsWith('/assign')) {
      const user = getLoggedInUser(req);
      if (!user || user.role !== 'admin') {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      try {
        const parts = req.url.split('/');
        const ticketId = parts[4];

        if (!isValidTicketId(ticketId)) {
          return sendJson(res, 400, { error: 'Invalid ticket ID' });
        }

        const { agentId } = data;
        let assignedAgentId = agentId ? parseInt(agentId, 10) : null;

        let result;
        if (assignedAgentId) {
          const agentCheck = await db.query("SELECT id, name FROM users WHERE id = $1 AND role IN ('agent', 'admin')", [assignedAgentId]);
          if (agentCheck.rows.length === 0) {
            return sendJson(res, 400, { error: 'Selected agent does not exist or is not a support agent' });
          }

          result = await db.query(
            "UPDATE tickets SET assigned_to = $1, assigned_at = NOW(), status = 'IN_PROGRESS' WHERE id = $2 RETURNING *",
            [assignedAgentId, parseInt(ticketId, 10)]
          );

          await recordAuditLog(user.id, 'TICKET_ASSIGNED', `Assigned ticket ${result.rows[0].ticket_number} to agent ${agentCheck.rows[0].name}`);
        } else {
          result = await db.query(
            "UPDATE tickets SET assigned_to = NULL, assigned_at = NULL, status = 'OPEN' WHERE id = $1 RETURNING *",
            [parseInt(ticketId, 10)]
          );

          await recordAuditLog(user.id, 'TICKET_UNASSIGNED', `Unassigned ticket ${result.rows[0].ticket_number}`);
        }

        if (result.rows.length === 0) {
          return sendJson(res, 404, { error: 'Ticket not found' });
        }

        sendJson(res, 200, { message: 'Ticket assignment updated!', ticket: result.rows[0] });
      } catch (err) {
        console.error('Assign Ticket Error:', err);
        sendJson(res, 500, { error: 'Failed to assign ticket' });
      }
    }

    // --- ADMIN: UPDATE TICKET STATUS ---
    else if (req.method === 'PUT' && req.url.startsWith('/api/admin/tickets/') && req.url.endsWith('/status')) {
      const user = getLoggedInUser(req);
      if (!user || user.role !== 'admin') {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      try {
        const parts = req.url.split('/');
        const ticketId = parts[4];

        if (!isValidTicketId(ticketId)) {
          return sendJson(res, 400, { error: 'Invalid ticket ID' });
        }

        const { status } = data;

        if (!VALID_STATUSES.has(status)) {
          return sendJson(res, 400, { error: 'Invalid status value' });
        }

        const result = await db.query(
          'UPDATE tickets SET status = $1 WHERE id = $2 RETURNING *',
          [status, parseInt(ticketId, 10)]
        );

        if (result.rows.length === 0) {
          return sendJson(res, 404, { error: 'Ticket not found' });
        }

        await recordAuditLog(user.id, 'ADMIN_STATUS_UPDATE', `Admin updated ticket ${result.rows[0].ticket_number} status to ${status}`);

        sendJson(res, 200, { message: 'Ticket status updated!', ticket: result.rows[0] });
      } catch (err) {
        console.error('Update Status Error:', err);
        sendJson(res, 500, { error: 'Failed to update status' });
      }
    }

    // --- 404: UNKNOWN ROUTE ---
    else {
      sendJson(res, 404, { error: 'Endpoint not found' });
    }
  });
});

// Initialize database schema on startup
db.initDb().then(() => {
  server.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT} [${IS_PRODUCTION ? 'PRODUCTION' : 'DEVELOPMENT'}]`);
  });
});

