// ================================
// APPOINTMENT SYSTEM - Rest API
// ================================

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
const winston = require('winston');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const fs = require('fs').promises;
const path = require('path');
const cron = require('node-cron');
const validator = require('validator');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ================================
// CONFIGURATION
// ================================
const config = {
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key-change-in-production',
  passwordMinLength: 8,
  tokenExpiry: '8h',
  dbBackupSchedule: '0 2 * * *', // Every day at 2 AM
  passwordCheckSchedule: '0 9 * * *', // Every day at 9 AM
  rateLimitWindow: 15 * 60 * 1000, // 15 minutes
  rateLimitMax: 100,
  authRateLimitMax: 5,
  passwordExpiryDays: 90,
  passwordWarningDays: 85,
  workingHours: { start: '09:00', end: '17:00' },
  appointmentSlotDuration: 60 // minutes
};

// ================================
// LOGGING CONFIGURATION
// ================================
const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'appointment-system' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.File({ filename: 'logs/security.log', level: 'warn' }),
    new winston.transports.File({ filename: 'logs/user-actions.log' })
  ],
});

// Add console logging in non-production environments
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// ================================
// SECURITY MIDDLEWARE
// ================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

app.use(xss());
app.use(hpp());
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: config.rateLimitWindow,
  max: config.rateLimitMax,
  message: 'Too many requests from this IP, please try again later.',
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path
    });
    res.status(429).json({ error: 'Rate limit exceeded' });
  }
});

const authLimiter = rateLimit({
  windowMs: config.rateLimitWindow,
  max: config.authRateLimitMax,
  message: 'Too many login attempts, please try again later.'
});

app.use(limiter);
app.use('/api/auth', authLimiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ================================
// DATABASE SETUP
// ================================
const db = new sqlite3.Database('appointment_system.db', (err) => {
  if (err) {
    logger.error('Error opening database:', err);
    process.exit(1);
  } else {
    logger.info('Connected to SQLite database');
    initializeDatabase();
  }
});

// Database initialization with better error handling
async function initializeDatabase() {
  try {
    const tables = [
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'front-officer', 'supervisor')),
        is_active BOOLEAN DEFAULT 1,
        password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
      
      `CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT NOT NULL,
        address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
      
      `CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        appointment_date DATE NOT NULL,
        start_time TIME NOT NULL,
        end_time TIME NOT NULL,
        status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'completed', 'cancelled', 'no-show')),
        created_by INTEGER NOT NULL,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users (id)
      )`,
      
      `CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        logout_time DATETIME NULL,
        ip_address TEXT,
        user_agent TEXT,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )`,
      
      `CREATE TABLE IF NOT EXISTS user_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        resource_id INTEGER,
        details TEXT,
        ip_address TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )`,
      
      `CREATE TABLE IF NOT EXISTS csrf_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )`
    ];

    // Execute table creation sequentially
    for (let i = 0; i < tables.length; i++) {
      await new Promise((resolve, reject) => {
        db.run(tables[i], (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }

    // Create indexes for better performance
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(appointment_date)',
      'CREATE INDEX IF NOT EXISTS idx_appointments_status ON appointments(status)',
      'CREATE INDEX IF NOT EXISTS idx_appointments_customer ON appointments(customer_id)',
      'CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(is_active)',
      'CREATE INDEX IF NOT EXISTS idx_user_actions_timestamp ON user_actions(timestamp)',
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email)'
    ];
    
    for (const sql of indexes) {
      await new Promise((resolve, reject) => {
        db.run(sql, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }

    // Create default admin user
    await createDefaultAdmin();
    
    logger.info('Database initialization completed successfully');
  } catch (error) {
    logger.error('Database initialization failed:', error);
    process.exit(1);
  }
}

async function createDefaultAdmin() {
  try {
    const hashedPassword = await bcrypt.hash('Admin@123!', 12);
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        ['admin', 'admin@system.com', hashedPassword, 'admin'],
        function(err) {
          if (err) reject(err);
          else {
            if (this.changes > 0) {
              logger.info('Default admin user created');
            } else {
              logger.info('Default admin user already exists');
            }
            resolve();
          }
        }
      );
    });
  } catch (error) {
    logger.error('Error creating default admin:', error);
  }
}

// ================================
// UTILITY FUNCTIONS
// ================================

// Password strength checker
function isStrongPassword(password) {
  if (typeof password !== 'string') return false;
  
  const minLength = config.passwordMinLength;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasNonalphas = /\W/.test(password);
  
  return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasNonalphas;
}

// Input validation and sanitization
function validateAndSanitize(input, type) {
  if (input === null || input === undefined) return null;
  if (typeof input !== 'string') input = String(input);
  
  input = input.trim();
  if (!input) return null;
  
  switch (type) {
    case 'email':
      return validator.isEmail(input) ? validator.normalizeEmail(input) : null;
    case 'phone':
      return validator.isMobilePhone(input, 'any') ? input.replace(/\D/g, '') : null;
    case 'text':
      return validator.escape(input);
    case 'username':
      return validator.isAlphanumeric(input) && input.length >= 3 ? input : null;
    case 'date':
      return validator.isISO8601(input) ? input : null;
    case 'time':
      return validator.matches(input, /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/) ? input : null;
    case 'id':
      return validator.isInt(input, { min: 1 }) ? parseInt(input, 10) : null;
    default:
      return validator.escape(input);
  }
}

// CSRF Token generation
function generateCSRFToken(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
  
  db.run(
    'INSERT INTO csrf_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
    [userId, token, expiresAt.toISOString()],
    (err) => {
      if (err) {
        logger.error('Error storing CSRF token:', err);
      }
    }
  );
  
  return token;
}

// Validate CSRF token
function validateCSRFToken(userId, token) {
  return new Promise((resolve) => {
    db.get(
      'SELECT * FROM csrf_tokens WHERE user_id = ? AND token = ? AND expires_at > datetime("now")',
      [userId, token],
      (err, row) => {
        if (err || !row) {
          resolve(false);
        } else {
          resolve(true);
        }
      }
    );
  });
}

// Action logger
function logUserAction(userId, action, resource, resourceId = null, details = null, req) {
  db.run(
    'INSERT INTO user_actions (user_id, action, resource, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
    [userId, action, resource, resourceId, details, req.ip],
    (err) => {
      if (err) {
        logger.error('Error logging user action:', err);
      }
    }
  );
  
  logger.info('User action logged', {
    userId,
    action,
    resource,
    resourceId,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
}

// Database query helper
function dbGet(query, params = []) {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function dbAll(query, params = []) {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function dbRun(query, params = []) {
  return new Promise((resolve, reject) => {
    db.run(query, params, function(err) {
      if (err) reject(err);
      else resolve({ changes: this.changes, lastID: this.lastID });
    });
  });
}

// ================================
// AUTHENTICATION MIDDLEWARE
// ================================
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    // Verify CSRF token for non-GET requests
    if (req.method !== 'GET') {
      const csrfToken = req.headers['x-csrf-token'];
      if (!csrfToken) {
        return res.status(401).json({ error: 'CSRF token required' });
      }
    }

    const user = jwt.verify(token, config.jwtSecret);
    
    // Check if user is still active
    const dbUser = await dbGet('SELECT * FROM users WHERE id = ? AND is_active = 1', [user.userId]);
    if (!dbUser) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    
    // Check password expiry
    const passwordAge = Date.now() - new Date(dbUser.password_changed_at).getTime();
    if (passwordAge > config.passwordExpiryDays * 24 * 60 * 60 * 1000) {
      return res.status(403).json({ error: 'Password expired. Please change your password.' });
    }
    
    // Verify CSRF token for non-GET requests
    if (req.method !== 'GET') {
      const csrfToken = req.headers['x-csrf-token'];
      const isValidCSRF = await validateCSRFToken(user.userId, csrfToken);
      if (!isValidCSRF) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
      }
    }
    
    req.user = user;
    req.dbUser = dbUser;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      logger.warn('Invalid token attempt', {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    logger.error('Authentication error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Role-based authorization
function authorize(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.dbUser.role)) {
      logUserAction(req.user.userId, 'UNAUTHORIZED_ACCESS', 'system', null, `Attempted to access ${req.path}`, req);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// ================================
// EMAIL SERVICE
// ================================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER || 'your-email@gmail.com',
    pass: process.env.GMAIL_PASS || 'your-app-password'
  }
});

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: process.env.GMAIL_USER || 'your-email@gmail.com',
      to,
      subject,
      html
    });
    logger.info('Email sent successfully', { to, subject });
    return true;
  } catch (error) {
    logger.error('Email sending failed', { error: error.message, to, subject });
    return false;
  }
}

// ================================
// PDF REPORT GENERATION
// ================================
function generateAppointmentReport(appointments, callback) {
  try {
    const doc = new PDFDocument();
    const filename = `appointment-report-${Date.now()}.pdf`;
    const filepath = path.join(__dirname, 'reports', filename);
    
    // Ensure reports directory exists
    fs.mkdir(path.dirname(filepath), { recursive: true })
      .then(() => {
        doc.pipe(fs.createWriteStream(filepath));
        
        doc.fontSize(20).text('Appointment Report', 50, 50);
        doc.fontSize(12).text(`Generated on: ${new Date().toLocaleDateString()}`, 50, 80);
        
        let yPosition = 120;
        appointments.forEach((apt, index) => {
          if (yPosition > 700) {
            doc.addPage();
            yPosition = 50;
          }
          
          doc.text(`${index + 1}. ${apt.title}`, 50, yPosition);
          doc.text(`   Date: ${apt.appointment_date} ${apt.start_time}-${apt.end_time}`, 50, yPosition + 15);
          doc.text(`   Status: ${apt.status}`, 50, yPosition + 30);
          doc.text(`   Customer: ${apt.customer_name}`, 50, yPosition + 45);
          yPosition += 80;
        });
        
        doc.end();
        
        doc.on('end', () => {
          callback(null, filepath);
        });
        
        doc.on('error', (error) => {
          callback(error, null);
        });
      })
      .catch(error => {
        callback(error, null);
      });
  } catch (error) {
    callback(error, null);
  }
}

// ================================
// VALIDATION MIDDLEWARES
// ================================

// Validate customer data
function validateCustomer(req, res, next) {
  const { name, email, phone, address } = req.body;
  
  const sanitizedName = validateAndSanitize(name, 'text');
  const sanitizedEmail = validateAndSanitize(email, 'email');
  const sanitizedPhone = validateAndSanitize(phone, 'phone');
  const sanitizedAddress = address ? validateAndSanitize(address, 'text') : null;

  if (!sanitizedName || !sanitizedEmail || !sanitizedPhone) {
    return res.status(400).json({ error: 'Invalid input data' });
  }

  req.sanitizedData = { name: sanitizedName, email: sanitizedEmail, phone: sanitizedPhone, address: sanitizedAddress };
  next();
}

// Validate appointment data
function validateAppointment(req, res, next) {
  const { customer_id, title, description, appointment_date, start_time, end_time, notes } = req.body;

  const sanitizedTitle = validateAndSanitize(title, 'text');
  const sanitizedDescription = description ? validateAndSanitize(description, 'text') : null;
  const sanitizedDate = validateAndSanitize(appointment_date, 'date');
  const sanitizedStartTime = validateAndSanitize(start_time, 'time');
  const sanitizedEndTime = validateAndSanitize(end_time, 'time');
  const sanitizedNotes = notes ? validateAndSanitize(notes, 'text') : null;
  const sanitizedCustomerId = validateAndSanitize(customer_id, 'id');

  if (!sanitizedCustomerId || !sanitizedTitle || !sanitizedDate || !sanitizedStartTime || !sanitizedEndTime) {
    return res.status(400).json({ error: 'Missing required fields or invalid data' });
  }

  // Validate time format and logic
  if (sanitizedStartTime >= sanitizedEndTime) {
    return res.status(400).json({ error: 'End time must be after start time' });
  }

  req.sanitizedData = {
    customer_id: sanitizedCustomerId,
    title: sanitizedTitle,
    description: sanitizedDescription,
    appointment_date: sanitizedDate,
    start_time: sanitizedStartTime,
    end_time: sanitizedEndTime,
    notes: sanitizedNotes
  };
  next();
}

// Validate user data
function validateUser(req, res, next) {
  const { username, email, password, role } = req.body;

  const sanitizedUsername = validateAndSanitize(username, 'username');
  const sanitizedEmail = validateAndSanitize(email, 'email');

  if (!sanitizedUsername || !sanitizedEmail || !password || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (!['admin', 'front-officer', 'supervisor'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({ 
      error: 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters' 
    });
  }

  req.sanitizedData = { username: sanitizedUsername, email: sanitizedEmail, password, role };
  next();
}

// ================================
// API ROUTES
// ================================

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const sanitizedUsername = validateAndSanitize(username, 'username');
    if (!sanitizedUsername) {
      return res.status(400).json({ error: 'Invalid username format' });
    }

    const user = await dbGet('SELECT * FROM users WHERE username = ? AND is_active = 1', [sanitizedUsername]);
    if (!user) {
      logger.warn('Login attempt with invalid username', {
        username: sanitizedUsername,
        ip: req.ip
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      return res.status(423).json({ error: 'Account temporarily locked due to multiple failed attempts' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      // Increment failed login attempts
      const newFailedAttempts = user.failed_login_attempts + 1;
      let lockedUntil = null;
      
      if (newFailedAttempts >= 5) {
        lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // Lock for 30 minutes
      }

      await dbRun(
        'UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?',
        [newFailedAttempts, lockedUntil, user.id]
      );

      logger.warn('Failed login attempt', {
        userId: user.id,
        username: user.username,
        ip: req.ip,
        attempts: newFailedAttempts
      });

      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset failed login attempts on successful login
    await dbRun(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
      [user.id]
    );

    // Create session
    await dbRun(
      'INSERT INTO user_sessions (user_id, ip_address, user_agent) VALUES (?, ?, ?)',
      [user.id, req.ip, req.get('User-Agent')]
    );

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      config.jwtSecret,
      { expiresIn: config.tokenExpiry }
    );

    const csrfToken = generateCSRFToken(user.id);

    logUserAction(user.id, 'LOGIN', 'auth', null, 'Successful login', req);

    res.json({
      token,
      csrfToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    // Update session
    await dbRun(
      'UPDATE user_sessions SET logout_time = CURRENT_TIMESTAMP, is_active = 0 WHERE user_id = ? AND is_active = 1',
      [req.user.userId]
    );

    logUserAction(req.user.userId, 'LOGOUT', 'auth', null, 'User logged out', req);
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Dashboard endpoint
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const queries = [
      'SELECT COUNT(*) as total FROM appointments WHERE status = "scheduled"',
      'SELECT COUNT(*) as completed FROM appointments WHERE status = "completed"',
      'SELECT COUNT(*) as cancelled FROM appointments WHERE status = "cancelled"',
      'SELECT COUNT(*) as no_show FROM appointments WHERE status = "no-show"'
    ];

    const results = await Promise.all(queries.map(query => dbGet(query)));
    
    res.json({
      scheduled: results[0].total,
      completed: results[1].completed,
      cancelled: results[2].cancelled,
      noShow: results[3].no_show,
      total: results[0].total + results[1].completed + results[2].cancelled + results[3].no_show
    });
  } catch (error) {
    logger.error('Dashboard query error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Customer routes
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const customers = await dbAll('SELECT * FROM customers ORDER BY created_at DESC');
    res.json(customers);
  } catch (error) {
    logger.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

app.post('/api/customers', authenticateToken, validateCustomer, async (req, res) => {
  try {
    const { name, email, phone, address } = req.sanitizedData;
    
    const result = await dbRun(
      'INSERT INTO customers (name, email, phone, address) VALUES (?, ?, ?, ?)',
      [name, email, phone, address]
    );

    logUserAction(req.user.userId, 'CREATE', 'customer', result.lastID, `Created customer: ${name}`, req);
    res.status(201).json({ id: result.lastID, message: 'Customer created successfully' });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Customer with this email already exists' });
    }
    logger.error('Error creating customer:', error);
    res.status(500).json({ error: 'Failed to create customer' });
  }
});

// Appointment routes with role-based access
app.get('/api/appointments', authenticateToken, async (req, res) => {
  try {
    const { date, status, customer_id } = req.query;
    let query = `
      SELECT a.*, c.name as customer_name, c.email as customer_email, c.phone as customer_phone,
            u.username as created_by_name
      FROM appointments a
      JOIN customers c ON a.customer_id = c.id
      JOIN users u ON a.created_by = u.id
      WHERE 1=1
    `;
    const params = [];

    if (date) {
      query += ' AND a.appointment_date = ?';
      params.push(date);
    }
    if (status) {
      query += ' AND a.status = ?';
      params.push(status);
    }
    if (customer_id) {
      const sanitizedCustomerId = validateAndSanitize(customer_id, 'id');
      if (sanitizedCustomerId) {
        query += ' AND a.customer_id = ?';
        params.push(sanitizedCustomerId);
      }
    }

    query += ' ORDER BY a.appointment_date DESC, a.start_time DESC';

    const appointments = await dbAll(query, params);
    res.json(appointments);
  } catch (error) {
    logger.error('Error fetching appointments:', error);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});

app.post('/api/appointments', authenticateToken, authorize(['admin', 'front-officer', 'supervisor']), validateAppointment, async (req, res) => {
  try {
    const { customer_id, title, description, appointment_date, start_time, end_time, notes } = req.sanitizedData;

    // Check for time conflicts
    const conflictCheck = await dbGet(
      `SELECT COUNT(*) as count FROM appointments 
        WHERE appointment_date = ? AND status != 'cancelled' 
        AND ((start_time <= ? AND end_time > ?) OR (start_time < ? AND end_time >= ?))`,
      [appointment_date, start_time, start_time, end_time, end_time]
    );

    if (conflictCheck.count > 0) {
      return res.status(409).json({ error: 'Time slot already booked' });
    }

    const result = await dbRun(
      'INSERT INTO appointments (customer_id, title, description, appointment_date, start_time, end_time, created_by, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [customer_id, title, description, appointment_date, start_time, end_time, req.user.userId, notes]
    );

    logUserAction(req.user.userId, 'CREATE', 'appointment', result.lastID, `Created appointment: ${title}`, req);
    res.status(201).json({ id: result.lastID, message: 'Appointment created successfully' });
  } catch (error) {
    logger.error('Error creating appointment:', error);
    res.status(500).json({ error: 'Failed to create appointment' });
  }
});

app.put('/api/appointments/:id', authenticateToken, authorize(['admin', 'supervisor']), validateAppointment, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, appointment_date, start_time, end_time, notes } = req.sanitizedData;
    const { status } = req.body;

    const result = await dbRun(
      'UPDATE appointments SET title = ?, description = ?, appointment_date = ?, start_time = ?, end_time = ?, status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [title, description, appointment_date, start_time, end_time, status, notes, id]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    logUserAction(req.user.userId, 'UPDATE', 'appointment', id, `Updated appointment: ${title}`, req);
    res.json({ message: 'Appointment updated successfully' });
  } catch (error) {
    logger.error('Error updating appointment:', error);
    res.status(500).json({ error: 'Failed to update appointment' });
  }
});

app.delete('/api/appointments/:id', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const sanitizedId = validateAndSanitize(id, 'id');
    
    if (!sanitizedId) {
      return res.status(400).json({ error: 'Invalid appointment ID' });
    }

    const result = await dbRun('DELETE FROM appointments WHERE id = ?', [sanitizedId]);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    logUserAction(req.user.userId, 'DELETE', 'appointment', sanitizedId, 'Deleted appointment', req);
    res.json({ message: 'Appointment deleted successfully' });
  } catch (error) {
    logger.error('Error deleting appointment:', error);
    res.status(500).json({ error: 'Failed to delete appointment' });
  }
});

// Free slots endpoint
app.get('/api/appointments/free-slots', authenticateToken, async (req, res) => {
  try {
    const { date, start_date, end_date, time_from, time_to } = req.query;
    
    let dateCondition = '';
    const params = [];
    
    if (date) {
      dateCondition = 'WHERE appointment_date = ?';
      params.push(date);
    } else if (start_date && end_date) {
      dateCondition = 'WHERE appointment_date BETWEEN ? AND ?';
      params.push(start_date, end_date);
    } else {
      return res.status(400).json({ error: 'Date or date range required' });
    }
    
    const timeCondition = time_from && time_to ? 
      ` AND ((start_time >= ? AND start_time < ?) OR (end_time > ? AND end_time <= ?))` : '';
    
    if (timeCondition) {
      params.push(time_from, time_to, time_from, time_to);
    }
    
    const query = `
      SELECT appointment_date, start_time, end_time 
      FROM appointments 
      ${dateCondition} AND status != 'cancelled' 
      ${timeCondition}
      ORDER BY appointment_date, start_time
    `;
    
    const bookedSlots = await dbAll(query, params);
    
    res.json({
      bookedSlots,
      workingHours: config.workingHours,
      slotDuration: config.appointmentSlotDuration,
      message: 'Use booked slots to determine availability'
    });
  } catch (error) {
    logger.error('Error fetching booked slots:', error);
    res.status(500).json({ error: 'Failed to fetch available slots' });
  }
});

// Report generation
app.get('/api/reports/appointments', authenticateToken, authorize(['admin', 'supervisor']), async (req, res) => {
  try {
    const { start_date, end_date, status } = req.query;
    
    let query = `
      SELECT a.*, c.name as customer_name, c.email as customer_email,
            u.username as created_by_name
      FROM appointments a
      JOIN customers c ON a.customer_id = c.id
      JOIN users u ON a.created_by = u.id
      WHERE 1=1
    `;
    const params = [];

    if (start_date && end_date) {
      query += ' AND a.appointment_date BETWEEN ? AND ?';
      params.push(start_date, end_date);
    }
    
    if (status) {
      query += ' AND a.status = ?';
      params.push(status);
    }

    query += ' ORDER BY a.appointment_date, a.start_time';

    const appointments = await dbAll(query, params);
    
    generateAppointmentReport(appointments, async (err, filepath) => {
      if (err) {
        logger.error('Error generating PDF report:', err);
        return res.status(500).json({ error: 'Failed to generate PDF report' });
      }

      logUserAction(req.user.userId, 'GENERATE_REPORT', 'appointments', null, 'Generated appointment report', req);
      
      res.download(filepath, async (err) => {
        if (err) {
          logger.error('Error downloading report:', err);
        } else {
          // Clean up the file after download
          setTimeout(async () => {
            try {
              await fs.unlink(filepath);
            } catch (unlinkErr) {
              logger.error('Error cleaning up report file:', unlinkErr);
            }
          }, 60000); // Delete after 1 minute
        }
      });
    });
  } catch (error) {
    logger.error('Error fetching appointments for report:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// User management routes (admin only)
app.get('/api/users', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const users = await dbAll(
      'SELECT id, username, email, role, is_active, created_at, updated_at, password_changed_at FROM users ORDER BY created_at DESC'
    );
    res.json(users);
  } catch (error) {
    logger.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users', authenticateToken, authorize(['admin']), validateUser, async (req, res) => {
  try {
    const { username, email, password, role } = req.sanitizedData;
    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await dbRun(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, role]
    );

    logUserAction(req.user.userId, 'CREATE', 'user', result.lastID, `Created user: ${username}`, req);
    res.status(201).json({ id: result.lastID, message: 'User created successfully' });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    logger.error('Error creating user:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/users/:id', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, role, is_active } = req.body;

    const sanitizedUsername = validateAndSanitize(username, 'username');
    const sanitizedEmail = validateAndSanitize(email, 'email');
    const sanitizedId = validateAndSanitize(id, 'id');

    if (!sanitizedUsername || !sanitizedEmail || !role || !sanitizedId) {
      return res.status(400).json({ error: 'Username, email, role, and valid ID are required' });
    }

    if (!['admin', 'front-officer', 'supervisor'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const result = await dbRun(
      'UPDATE users SET username = ?, email = ?, role = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [sanitizedUsername, sanitizedEmail, role, is_active !== undefined ? is_active : 1, sanitizedId]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    logUserAction(req.user.userId, 'UPDATE', 'user', sanitizedId, `Updated user: ${sanitizedUsername}`, req);
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    logger.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/users/:id', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const sanitizedId = validateAndSanitize(id, 'id');
    
    if (!sanitizedId) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    // Prevent admin from deleting themselves
    if (parseInt(sanitizedId) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    const result = await dbRun('DELETE FROM users WHERE id = ?', [sanitizedId]);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    logUserAction(req.user.userId, 'DELETE', 'user', sanitizedId, 'Deleted user', req);
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    logger.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Password change endpoint
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new passwords are required' });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({ 
        error: 'New password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters' 
      });
    }

    const isValidPassword = await bcrypt.compare(currentPassword, req.dbUser.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await dbRun(
      'UPDATE users SET password = ?, password_changed_at = CURRENT_TIMESTAMP WHERE id = ?',
      [hashedPassword, req.user.userId]
    );

    logUserAction(req.user.userId, 'CHANGE_PASSWORD', 'auth', null, 'Password changed successfully', req);
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    logger.error('Password change error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User activity logs (admin only)
app.get('/api/logs/user-actions', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const { user_id, action, start_date, end_date, limit = 100 } = req.query;
    
    let query = `
      SELECT ua.*, u.username 
      FROM user_actions ua
      JOIN users u ON ua.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (user_id) {
      const sanitizedUserId = validateAndSanitize(user_id, 'id');
      if (sanitizedUserId) {
        query += ' AND ua.user_id = ?';
        params.push(sanitizedUserId);
      }
    }

    if (action) {
      query += ' AND ua.action = ?';
      params.push(action);
    }

    if (start_date && end_date) {
      query += ' AND DATE(ua.timestamp) BETWEEN ? AND ?';
      params.push(start_date, end_date);
    }

    query += ' ORDER BY ua.timestamp DESC LIMIT ?';
    params.push(parseInt(limit));

    const logs = await dbAll(query, params);
    res.json(logs);
  } catch (error) {
    logger.error('Error fetching user action logs:', error);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// User sessions (admin only)
app.get('/api/logs/user-sessions', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const { user_id, is_active } = req.query;
    
    let query = `
      SELECT us.*, u.username 
      FROM user_sessions us
      JOIN users u ON us.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (user_id) {
      const sanitizedUserId = validateAndSanitize(user_id, 'id');
      if (sanitizedUserId) {
        query += ' AND us.user_id = ?';
        params.push(sanitizedUserId);
      }
    }

    if (is_active !== undefined) {
      query += ' AND us.is_active = ?';
      params.push(is_active === 'true' ? 1 : 0);
    }

    query += ' ORDER BY us.login_time DESC LIMIT 1000';

    const sessions = await dbAll(query, params);
    res.json(sessions);
  } catch (error) {
    logger.error('Error fetching user sessions:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    await dbGet('SELECT 1');
    res.json({ status: 'healthy', database: 'connected', timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', database: 'disconnected', timestamp: new Date().toISOString() });
  }
});

// ================================
// AUTOMATED BACKUP SYSTEM
// ================================
async function backupDatabase() {
  try {
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const backupPath = path.join(__dirname, 'backups', `backup-${timestamp}.db`);
    
    // Ensure backup directory exists
    await fs.mkdir(path.dirname(backupPath), { recursive: true });

    // Create backup using SQLite's backup API for more reliability
    const backupDb = new sqlite3.Database(backupPath);
    const sourceDb = new sqlite3.Database('appointment_system.db');
    
    await new Promise((resolve, reject) => {
      sourceDb.backup(backupDb, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
    
    await new Promise((resolve) => {
      backupDb.close(resolve);
    });
    
    await new Promise((resolve) => {
      sourceDb.close(resolve);
    });
    
    logger.info(`Database backup created: ${backupPath}`);
    
    // Clean up old backups (keep only last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const files = await fs.readdir(path.dirname(backupPath));
    
    for (const file of files) {
      if (file.startsWith('backup-')) {
        const filePath = path.join(path.dirname(backupPath), file);
        const stats = await fs.stat(filePath);
        
        if (stats.mtime < thirtyDaysAgo) {
          await fs.unlink(filePath);
          logger.info(`Old backup deleted: ${file}`);
        }
      }
    }
  } catch (error) {
    logger.error('Backup failed:', error);
  }
}

// Schedule automatic backup
cron.schedule(config.dbBackupSchedule, () => {
  logger.info('Starting scheduled database backup');
  backupDatabase();
});

// ================================
// PASSWORD EXPIRY NOTIFICATIONS
// ================================
async function checkPasswordExpiry() {
  try {
    const users = await dbAll(`
      SELECT id, username, email, password_changed_at 
      FROM users 
      WHERE is_active = 1
    `);
    
    const now = new Date();
    const warningPeriod = config.passwordWarningDays * 24 * 60 * 60 * 1000;
    const expiryPeriod = config.passwordExpiryDays * 24 * 60 * 60 * 1000;
    
    for (const user of users) {
      const passwordAge = now.getTime() - new Date(user.password_changed_at).getTime();
      
      // Warn when approaching expiry
      if (passwordAge >= warningPeriod && passwordAge < expiryPeriod) {
        const daysLeft = Math.ceil((expiryPeriod - passwordAge) / (24 * 60 * 60 * 1000));
        await sendEmail(
          user.email,
          'Password Expiry Warning',
          `<p>Your password will expire in ${daysLeft} days. Please change your password to continue using the system.</p>`
        );
        
        logger.info(`Password expiry warning sent to user: ${user.username}`);
      }
    }
  } catch (error) {
    logger.error('Error checking password expiry:', error);
  }
}

// Check password expiry daily
cron.schedule(config.passwordCheckSchedule, () => {
  logger.info('Checking password expiry');
  checkPasswordExpiry();
});

// ================================
// ERROR HANDLING MIDDLEWARE
// ================================
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(500).json({
    error: 'Internal server error',
    ...(isDevelopment && { details: err.message })
  });
});

// 404 handler
app.use('*', (req, res) => {
  logger.warn(`404 - Route not found: ${req.method} ${req.originalUrl}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.status(404).json({ error: 'Route not found' });
});

// ================================
// SERVER STARTUP
// ================================
function gracefulShutdown() {
  logger.info('Received shutdown signal, closing database connection...');
  
  db.close((err) => {
    if (err) {
      logger.error('Error closing database:', err);
      process.exit(1);
    } else {
      logger.info('Database connection closed');
      process.exit(0);
    }
  });
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Initialize server
async function startServer() {
  try {
    // Ensure necessary directories exist
    await fs.mkdir('logs', { recursive: true });
    await fs.mkdir('backups', { recursive: true });
    await fs.mkdir('reports', { recursive: true });
    
    app.listen(PORT, () => {
      logger.info(`Appointment System API running on port ${PORT}`);
      console.log(`🚀 Appointment System API running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
      console.log(`🔐 Default admin credentials: admin / Admin@123!`);
    });
  } catch (error) {
    logger.error('Server startup failed:', error);
    process.exit(1);
  }
}

startServer();

// ================================
// EXPORT FOR TESTING
// ================================

module.exports = app;
