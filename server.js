const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'editorscraft_responsive_verified_secret_2026';

// Allow handling Base64 uploaded portfolio/work files (up to 25MB)
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ limit: '25mb', extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname)));

const db = new sqlite3.Database(path.join(__dirname, 'homecraft.db'), (err) => {
  if (err) console.error('❌ Error opening database:', err.message);
  else console.log('✅ Connected to SQLite database: homecraft.db');
});

// Database Initialization
db.serialize(() => {
  // 1. Users Table (Shared Auth for Clients & Editors with Dual Verification)
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      phone TEXT NOT NULL,
      discord TEXT NOT NULL,
      role TEXT CHECK(role IN ('customer', 'lister')) NOT NULL,
      editing_app TEXT NOT NULL,
      is_phone_verified INTEGER DEFAULT 0,
      is_email_verified INTEGER DEFAULT 0,
      phone_otp TEXT,
      email_otp TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 2. Editor Profiles Table (With Mandatory Portfolio Showcase & Styles)
  db.run(`
    CREATE TABLE IF NOT EXISTS lister_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL,
      editing_style TEXT NOT NULL,
      rate REAL NOT NULL,
      experience_years INTEGER DEFAULT 1,
      profile_pic TEXT NOT NULL,
      work_samples TEXT,
      bio TEXT,
      is_active INTEGER DEFAULT 1,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  // 3. Project Orders Table
  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      lister_user_id INTEGER NOT NULL,
      category TEXT NOT NULL,
      amount REAL NOT NULL,
      payment_method TEXT NOT NULL,
      status TEXT DEFAULT 'Confirmed',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(customer_id) REFERENCES users(id),
      FOREIGN KEY(lister_user_id) REFERENCES users(id)
    )
  `);
});

// --- PROTECTED ROUTE MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. Please sign in.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired. Please sign in again.' });
    req.user = user;
    next();
  });
};

/* ==========================================================================
   1. AUTHENTICATION & DUAL VERIFICATION (SMS PHONE + EMAIL OTP)
   ========================================================================== */

// Stage 1: Registration & Dual OTP Dispatch
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, phone, discord, role, editing_app, editing_style, rate, experience_years, profile_pic, work_samples, bio } = req.body;

  if (!name || !email || !password || !phone || !discord || !role || !editing_app) {
    return res.status(400).json({ error: 'All basic registration fields including Discord tag are required.' });
  }

  if (role === 'lister' && (!profile_pic || profile_pic.trim() === '')) {
    return res.status(400).json({ error: 'Profile photo is MANDATORY for Editors.' });
  }

  if (role === 'lister' && (!editing_style || editing_style.trim() === '')) {
    return res.status(400).json({ error: 'Editing style specialty is MANDATORY for Editors.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const phoneOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const emailOtp = Math.floor(100000 + Math.random() * 900000).toString();

    db.run(
      `INSERT INTO users (name, email, password, phone, discord, role, editing_app, phone_otp, email_otp, is_phone_verified, is_email_verified) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)`,
      [name, email, hashedPassword, phone, discord, role, editing_app, phoneOtp, emailOtp],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'This email address is already registered.' });
          }
          return res.status(500).json({ error: err.message });
        }

        const userId = this.lastID;

        console.log(`\n==================================================`);
        console.log(`📲 [PHONE SMS OTP] Sent to ${phone}: ${phoneOtp}`);
        console.log(`✉️ [EMAIL VERIFICATION OTP] Sent to ${email}: ${emailOtp}`);
        console.log(`==================================================\n`);

        if (role === 'lister') {
          db.run(
            `INSERT INTO lister_profiles (user_id, editing_style, rate, experience_years, profile_pic, work_samples, bio) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [userId, editing_style || 'Movie Editing', rate || 30, experience_years || 1, profile_pic, JSON.stringify(work_samples || []), bio || ''],
            (pErr) => {
              if (pErr) return res.status(500).json({ error: pErr.message });
              res.status(201).json({ requiresVerification: true, userId, phone, email, message: 'Phone & Email OTP sent!' });
            }
          );
        } else {
          res.status(201).json({ requiresVerification: true, userId, phone, email, message: 'Phone & Email OTP sent!' });
        }
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Authentication processing failed.' });
  }
});

// Stage 2: Verify Both Phone and Email OTPs
app.post('/api/auth/verify-dual', (req, res) => {
  const { userId, phoneOtp, emailOtp } = req.body;

  if (!userId || !phoneOtp || !emailOtp) {
    return res.status(400).json({ error: 'Both Phone OTP and Email OTP are required.' });
  }

  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User account not found.' });

    if (String(user.phone_otp).trim() !== String(phoneOtp).trim()) {
      return res.status(400).json({ error: 'Invalid Phone OTP. Check terminal output.' });
    }

    if (String(user.email_otp).trim() !== String(emailOtp).trim()) {
      return res.status(400).json({ error: 'Invalid Email OTP. Check terminal output.' });
    }

    db.run(
      `UPDATE users SET is_phone_verified = 1, is_email_verified = 1, phone_otp = NULL, email_otp = NULL WHERE id = ?`,
      [userId],
      (upErr) => {
        if (upErr) return res.status(500).json({ error: upErr.message });
        sendAuthResponse(user.id, user.name, user.email, user.role, user.editing_app, user.phone, user.discord, res);
      }
    );
  });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid email or password.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid email or password.' });

    if (user.is_phone_verified === 0 || user.is_email_verified === 0) {
      return res.status(403).json({ error: 'Verification incomplete. Both Phone and Email must be verified.' });
    }

    sendAuthResponse(user.id, user.name, user.email, user.role, user.editing_app, user.phone, user.discord, res);
  });
});

function sendAuthResponse(id, name, email, role, editing_app, phone, discord, res) {
  const token = jwt.sign({ id, name, email, role, editing_app, phone, discord }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id, name, email, role, editing_app, phone, discord } });
}

/* ==========================================================================
   2. PROFILE WEBPAGE & MARKETPLACE API ENDPOINTS
   ========================================================================== */

app.get('/api/user/profile', authenticateToken, (req, res) => {
  db.get(`SELECT id, name, email, phone, discord, role, editing_app, is_phone_verified, is_email_verified, created_at FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Profile not found.' });

    if (user.role === 'lister') {
      db.get(`SELECT * FROM lister_profiles WHERE user_id = ?`, [user.id], (pErr, profile) => {
        res.json({ user, profile });
      });
    } else {
      res.json({ user, profile: null });
    }
  });
});

app.get('/api/workers', (req, res) => {
  const { editing_app, editing_style } = req.query;

  let query = `
    SELECT u.id as lister_user_id, u.name, u.email, u.phone, u.discord, u.editing_app, 
           lp.editing_style, lp.rate, lp.experience_years, lp.profile_pic, lp.work_samples, lp.bio
    FROM users u
    JOIN lister_profiles lp ON u.id = lp.user_id
    WHERE u.role = 'lister' AND lp.is_active = 1 AND u.is_phone_verified = 1 AND u.is_email_verified = 1
  `;
  let params = [];

  if (editing_app) {
    query += ` AND LOWER(u.editing_app) = ?`;
    params.push(editing_app.toLowerCase());
  }
  if (editing_style && editing_style !== 'All') {
    query += ` AND lp.editing_style = ?`;
    params.push(editing_style);
  }

  query += ` ORDER BY u.id DESC`;

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Enforce Compulsory Dual Verification Before Ordering
app.post('/api/orders', authenticateToken, (req, res) => {
  db.get(`SELECT is_phone_verified, is_email_verified FROM users WHERE id = ?`, [req.user.id], (uErr, user) => {
    if (uErr || !user) return res.status(400).json({ error: 'User validation failed.' });

    if (user.is_phone_verified === 0 || user.is_email_verified === 0) {
      return res.status(403).json({ error: 'Compulsory: Both Phone and Email verification are required to make purchases.' });
    }

    if (req.user.role !== 'customer') {
      return res.status(403).json({ error: 'Only logged-in client accounts can hire editors.' });
    }

    const { listerUserId, category, amount, paymentMethod } = req.body;

    db.run(
      `INSERT INTO orders (customer_id, lister_user_id, category, amount, payment_method) VALUES (?, ?, ?, ?, ?)`,
      [req.user.id, listerUserId, category, amount, paymentMethod || 'Escrow Hold'],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ success: true, orderId: this.lastID, message: 'Video editing project hired successfully!' });
      }
    );
  });
});

app.get('/api/customer/orders', authenticateToken, (req, res) => {
  db.all(
    `SELECT o.id, o.category, o.amount, o.payment_method, o.status, o.created_at, u.name as lister_name, u.phone as lister_phone, u.discord as lister_discord 
     FROM orders o JOIN users u ON o.lister_user_id = u.id 
     WHERE o.customer_id = ? ORDER BY o.id DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.get('/api/lister/dashboard', authenticateToken, (req, res) => {
  if (req.user.role !== 'lister') return res.status(403).json({ error: 'Access restricted to Editor accounts.' });

  db.get(`SELECT * FROM lister_profiles WHERE user_id = ?`, [req.user.id], (err, profile) => {
    if (err) return res.status(500).json({ error: err.message });

    db.all(
      `SELECT o.id, o.category, o.amount, o.payment_method, o.status, o.created_at, u.name as customer_name, u.phone as customer_phone, u.discord as customer_discord 
       FROM orders o JOIN users u ON o.customer_id = u.id 
       WHERE o.lister_user_id = ? ORDER BY o.id DESC`,
      [req.user.id],
      (orderErr, orders) => {
        if (orderErr) return res.status(500).json({ error: orderErr.message });
        res.json({ profile, orders });
      }
    );
  });
});

app.listen(PORT, () => {
  console.log(`🚀 EditorsCraft Fully Responsive Platform Active on http://localhost:${PORT}`);
});