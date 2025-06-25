require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const csv = require('csv-parser');
const cors = require('cors');
const axios = require('axios');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
const multer = require('multer');
const fetch = require('node-fetch'); // ✅ Node.js fetch
const FormData = require('form-data'); // ✅ to send image as multipart


// For JSON and Base64 uploads
app.use(bodyParser.json({ limit: '20mb' })); 
app.use(bodyParser.urlencoded({ extended: true, limit: '20mb' }));

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database connection
const db = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres.xxotzadlcmmromgruaoi:Vimalboss@45@aws-0-ap-south-1.pooler.supabase.com:6543/postgres',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Google Apps Script URL for PDF uploads
const APPSCRIPT_PDF_UPLOAD_URL = process.env.APPSCRIPT_PDF_UPLOAD_URL || 'https://script.google.com/macros/s/AKfycbxEIT_M2tGkM1lqKf0Oer6sqLmzIWg-qGtBfkDdVE5BLG0AILBEomp4MDp-pS9_zB-B/exec';

// Utility functions
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
};

// Routes

/* --------------------- AUTHENTICATION --------------------- */
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role = 'participant', contact_no } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const { rows } = await db.query(
      `INSERT INTO users (name, email, password_hash, role, contact_no) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, name, email, role, contact_no, created_at`,
      [name, email, hashedPassword, role, contact_no]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const { rows } = await db.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    await db.query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );
    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* --------------------- EVENTS --------------------- */
app.get('/api/events', async (req, res) => {
  try {
    const { status } = req.query;
    let query = 'SELECT * FROM events';
    let params = [];
    
    if (status) {
      query += ' WHERE status = $1 ORDER BY start_date ASC';
      params.push(status);
    } else {
      query += ' ORDER BY start_date ASC';
    }
    
    const { rows } = await db.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/events/:id', async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT e.*, u.name as organizer_name 
       FROM events e 
       LEFT JOIN users u ON e.organizer_id = u.id 
       WHERE e.id = $1`,
      [req.params.id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }
    
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/events', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const {
    title,
    description,
    detailed_description,
    rules,
    event_type,
    poster_url,
    banner_url,
    start_date,
    end_date,
    registration_deadline,
    max_participants,
    status = 'upcoming'
  } = req.body;
  
  try {
    const { rows } = await db.query(
      `INSERT INTO events (
        title, description, detailed_description, rules, event_type, 
        poster_url, banner_url, start_date, end_date, registration_deadline, 
        max_participants, status, organizer_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
      RETURNING *`,
      [
        title, description, detailed_description, rules, event_type,
        poster_url, banner_url, start_date, end_date, registration_deadline,
        max_participants, status, req.user.id
      ]
    );
    
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/events/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const eventId = req.params.id;
  const {
    title,
    description,
    detailed_description,
    rules,
    event_type,
    poster_url,
    banner_url,
    start_date,
    end_date,
    registration_deadline,
    max_participants,
    status
  } = req.body;
  
  try {
    const { rows } = await db.query(
      `UPDATE events SET 
        title = $1, 
        description = $2, 
        detailed_description = $3, 
        rules = $4, 
        event_type = $5, 
        poster_url = $6, 
        banner_url = $7, 
        start_date = $8, 
        end_date = $9, 
        registration_deadline = $10, 
        max_participants = $11, 
        status = $12,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $13
      RETURNING *`,
      [
        title, description, detailed_description, rules, event_type,
        poster_url, banner_url, start_date, end_date, registration_deadline,
        max_participants, status, eventId
      ]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }
    
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/userpayments', authenticateToken, async (req, res) => {
  const userId = req.user.id; // ✅ Extracted from JWT

  try {
    const result = await db.query(`
      SELECT
        p.id AS participant_id,
        p.event_id,
        e.title AS event_title,
        p.registration_data,
        p.transaction_id,
        p.payment_verified,
        p.verified_at,
        p.registered_at,
        e.event_fee
      FROM participants p
      JOIN events e ON p.event_id = e.id
      WHERE p.user_id = $1
      ORDER BY p.registered_at DESC
    `, [userId]);

    res.json({
      user_id: userId,
      payments: result.rows
    });

  } catch (err) {
    console.error('Error fetching payment details:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/events/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const { rowCount } = await db.query(
      'DELETE FROM events WHERE id = $1',
      [req.params.id]
    );
    
    if (rowCount === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* --------------------- EVENT REGISTRATION --------------------- */
app.post('/api/events/:id/register', authenticateToken, async (req, res) => {
  const eventId = req.params.id;
  const userId = req.user.id;

  const {
    registration_data = {},
    transaction_id = null // Add transaction_id from request body
  } = req.body;

  try {
    // Check if event exists and is open for registration
    const eventResult = await db.query(
      `SELECT * FROM events 
       WHERE id = $1 
       AND status IN ($2, $3)
       AND (registration_deadline IS NULL OR registration_deadline > NOW())`,
      [eventId, 'upcoming', 'ongoing']
    );

    if (eventResult.rows.length === 0) {
      return res.status(400).json({ error: 'Event not available for registration' });
    }

    const event = eventResult.rows[0];

    // Check if user is already registered
    const existingRegistration = await db.query(
      'SELECT * FROM participants WHERE user_id = $1 AND event_id = $2',
      [userId, eventId]
    );

    if (existingRegistration.rows.length > 0) {
      return res.status(409).json({ error: 'Already registered for this event' });
    }

    // Check if event has reached max participants
    if (event.max_participants && event.current_participants >= event.max_participants) {
      return res.status(400).json({ error: 'Event has reached maximum participants' });
    }

    // Register participant with transaction_id
    const { rows } = await db.query(
      `INSERT INTO participants 
        (user_id, event_id, registration_data, transaction_id)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [userId, eventId, registration_data, transaction_id]
    );

    // Increment current_participants count
    await db.query(
      'UPDATE events SET current_participants = current_participants + 1 WHERE id = $1',
      [eventId]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: err.message });
  }
});

// --------------------- UPDATE PAYMENT STATUS (PUT) ---------------------
app.put('/api/participants/:id/payment', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const participantId = req.params.id;
  const { payment_verified } = req.body;

  if (typeof payment_verified !== 'boolean') {
    return res.status(400).json({ error: 'payment_verified must be a boolean' });
  }

  try {
    const result = await db.query(
      `UPDATE participants
       SET payment_verified = $1,
           verified_at = CASE WHEN $1 = true THEN NOW() ELSE NULL END
       WHERE id = $2
       RETURNING *`,
      [payment_verified, participantId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Participant not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Payment status update failed:', err);
    res.status(500).json({ error: err.message });
  }
});




app.get('/api/events/:id/participants', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT p.*, u.name, u.email 
       FROM participants p
       JOIN users u ON p.user_id = u.id
       WHERE p.event_id = $1`,
      [req.params.id]
    );
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* --------------------- RESULTS --------------------- */
app.get('/api/events/:id/results', async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT r.*, u.name, u.email 
       FROM results r
       JOIN participants p ON r.participant_id = p.id
       JOIN users u ON p.user_id = u.id
       WHERE r.event_id = $1
       ORDER BY r.rank`,
      [req.params.id]
    );
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/events/:id/results', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const eventId = req.params.id;
  const { participant_id, score, rank, remarks } = req.body;
  
  try {
    // Check if participant belongs to the event
    const participantCheck = await db.query(
      'SELECT * FROM participants WHERE id = $1 AND event_id = $2',
      [participant_id, eventId]
    );
    
    if (participantCheck.rows.length === 0) {
      return res.status(400).json({ error: 'Participant not registered for this event' });
    }
    
    const { rows } = await db.query(
      `INSERT INTO results (event_id, participant_id, score, rank, remarks)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (event_id, participant_id) 
       DO UPDATE SET score = EXCLUDED.score, rank = EXCLUDED.rank, remarks = EXCLUDED.remarks
       RETURNING *`,
      [eventId, participant_id, score, rank, remarks]
    );
    
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* --------------------- CERTIFICATES --------------------- */
app.get('/api/certificates', authenticateToken, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT c.*, e.title as event_title, e.event_type, u.name as participant_name
       FROM certificates c
       JOIN events e ON c.event_id = e.id
       JOIN participants p ON c.participant_id = p.id
       JOIN users u ON p.user_id = u.id
       WHERE p.user_id = $1`,
      [req.user.id]
    );
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/certificates/:code', async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT c.*, e.title as event_title, e.event_type, u.name as participant_name
       FROM certificates c
       JOIN events e ON c.event_id = e.id
       JOIN participants p ON c.participant_id = p.id
       JOIN users u ON p.user_id = u.id
       WHERE c.unique_code = $1`,
      [req.params.code]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/events/:id/certificates', async (req, res) => {
  const eventId = req.params.id;
  const { participant_id, certificate_url, unique_code, issued_at } = req.body;

  console.log('➡️ Saving certificate without PDF upload...');
  console.log({ eventId, participant_id, certificate_url, unique_code, issued_at });

  try {
    const participantCheck = await db.query(
      'SELECT * FROM participants WHERE id = $1 AND event_id = $2',
      [participant_id, eventId]
    );

    if (participantCheck.rows.length === 0) {
      return res.status(400).json({ error: 'Participant not registered for this event' });
    }

    const { rows } = await db.query(
      `INSERT INTO certificates (event_id, participant_id, certificate_url, unique_code, issued_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [eventId, participant_id, certificate_url, unique_code, issued_at]
    );

    console.log('✅ Certificate record saved:', rows[0]);
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('🚨 Save error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /events/:eventId/certificates/:participantId
app.get('/api/events/:eventId/certificates/:participantId', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { eventId, participantId } = req.params;

  try {
    const { rows } = await db.query(
      `SELECT * FROM certificates WHERE event_id = $1 AND participant_id = $2`,
      [eventId, participantId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "No certificate found" });
    }
    res.status(200).json(rows[0]);
  } catch (err) {
    console.error("🚨 Fetch cert error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/participants/:id/email
app.get('/api/participants/:id/email', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const participantId = req.params.id;

  try {
    const query = `
      SELECT users.email
      FROM participants
      JOIN users ON participants.user_id = users.id
      WHERE participants.id = $1
    `;
    const { rows } = await db.query(query, [participantId]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Participant not found" });
    }

    res.json({ email: rows[0].email });
  } catch (err) {
    console.error("🚨 Error fetching participant email:", err.message);
    res.status(500).json({ error: err.message });
  }
});




// Configure multer for memory storage (since we're uploading directly to imgBB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
});



app.post(
  '/api/events/:id/gallery',
  authenticateToken,
  authorizeRole('admin'),
  upload.single('image'),
  async (req, res) => {
    const eventId = req.params.id;
    const { caption } = req.body;
    const file = req.file;
    console.log(req.body);
    
    // Validate input
    if (!file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    // Check if the file is an image
    if (!file.mimetype.startsWith('image/')) {
      return res.status(400).json({ error: 'Only image files are allowed' });
    }

    try {
      // Prepare form data for imgBB
      const form = new FormData();
      form.append('key', '76954d664f0beaf57b8c5a5b0eca84e6'); // Your imgBB API key
      form.append('image', file.buffer.toString('base64')); // Convert buffer to base64

      // Upload to imgBB
      const imgbbResponse = await fetch('https://api.imgbb.com/1/upload', {
        method: 'POST',
        body: form,
      });

      const imgbbData = await imgbbResponse.json();

      if (!imgbbResponse.ok || !imgbbData.success) {
        console.error('imgBB upload failed:', imgbbData);
        return res.status(500).json({ error: 'Image upload failed' });
      }

      // Save to database
      const { rows } = await db.query(
        `INSERT INTO event_gallery (event_id, image_url, caption)
         VALUES ($1, $2, $3)
         RETURNING *`,
        [eventId, imgbbData.data.url, caption || null]
      );

      res.status(201).json(rows[0]);
    } catch (error) {
      console.error('Image upload error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);


app.get('/api/events/:id/gallery', async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT * FROM event_gallery WHERE event_id = $1 ORDER BY uploaded_at DESC',
      [req.params.id]
    );
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* --------------------- USER PROFILE --------------------- */
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT id, name, email, role, contact_no, created_at, last_login 
       FROM users 
       WHERE id = $1`,
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:email', async (req, res) => {
  const email = req.params.email;
  const { name, contact_no, role } = req.body;

  try {
    const { rowCount, rows } = await db.query(
      `UPDATE users 
       SET name = $1, contact_no = $2, role = COALESCE($3, role)
       WHERE email = $4
       RETURNING id, name, email, role, contact_no, created_at, last_login`,
      [name, contact_no, role, email]
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.delete('/api/users/:email', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const email = req.params.email;

  try {
    const { rowCount } = await db.query(
      `DELETE FROM users WHERE email = $1`,
      [email]
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: `User with email ${email} deleted successfully.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



app.get('/api/profile/events', authenticateToken, async (req, res) => {
  try {
    // Get events user is participating in
    const { rows } = await db.query(
      `SELECT e.*, p.registered_at, r.score, r.rank
       FROM events e
       JOIN participants p ON e.id = p.event_id
       LEFT JOIN results r ON r.event_id = e.id AND r.participant_id = p.id
       WHERE p.user_id = $1
       ORDER BY e.start_date DESC`,
      [req.user.id]
    );
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* --------------------- PASSWORD RESET --------------------- */

// Generate and send reset token
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const { rows } = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (rows.length === 0) {
      return res.status(200).json({ message: 'If this email exists, a reset token has been sent' });
    }

    const user = rows[0];
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour

    await db.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
      [resetToken, resetTokenExpires, user.id]
    );

    // 🚫 REMOVE link part if not needed
    // ✅ ONLY return token in development
    console.log('Reset token:', resetToken);

    res.status(200).json({
      message: 'If this email exists, a reset token has been sent',
      resetLink: `http://localhost:4000/reset-password?token=${resetToken}` // ⚠️ Optional: remove in prod
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const query = `
      WITH user_data AS (
        SELECT 
          u.*,
          (
            SELECT json_agg(
              json_build_object(
                'event_id', p.event_id,
                'event_title', e.title,
                'event_type', e.event_type,
                'status', e.status,
                'registration_data', p.registration_data,
                'attendance', p.attendance_status,
                'registered_at', p.registered_at,
                'result', (
                  SELECT json_build_object(
                    'score', r.score,
                    'rank', r.rank,
                    'remarks', r.remarks
                  )
                  FROM results r
                  WHERE r.event_id = p.event_id AND r.participant_id = p.id
                ),
                'certificate', (
                  SELECT json_build_object(
                    'url', c.certificate_url,
                    'code', c.unique_code
                  )
                  FROM certificates c
                  WHERE c.event_id = p.event_id AND c.participant_id = p.id
                )
              )
            )
            FROM participants p
            JOIN events e ON e.id = p.event_id
            WHERE p.user_id = u.id
          ) AS participations,
          (
            SELECT json_agg(
              json_build_object(
                'event_id', e.id,
                'title', e.title,
                'type', e.event_type,
                'status', e.status,
                'participants', e.current_participants,
                'start_date', e.start_date,
                'end_date', e.end_date
              )
            )
            FROM events e
            WHERE e.organizer_id = u.id
          ) AS organized_events,
          (
            SELECT json_agg(
              json_build_object(
                'event_id', eg.event_id,
                'image_url', eg.image_url,
                'caption', eg.caption
              )
            )
            FROM event_gallery eg
            JOIN participants p ON p.event_id = eg.event_id
            WHERE p.user_id = u.id
          ) AS gallery_images
        FROM users u
      )
      SELECT * FROM user_data
      ORDER BY created_at DESC
    `;

    const { rows: users } = await db.query(query);

    const formattedUsers = users.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      verified: user.verified,
      contact_no: user.contact_no,
      created_at: user.created_at instanceof Date
        ? user.created_at.toISOString()
        : new Date(user.created_at).toISOString(),
      last_login: user.last_login
        ? (user.last_login instanceof Date
            ? user.last_login.toISOString()
            : new Date(user.last_login).toISOString())
        : null,
      participations: Array.isArray(user.participations)
        ? user.participations.map(p => ({
            ...p,
            registered_at: p.registered_at
              ? new Date(p.registered_at).toISOString()
              : null
          }))
        : [],
      organized_events: Array.isArray(user.organized_events)
        ? user.organized_events.map(e => ({
            ...e,
            start_date: e.start_date
              ? new Date(e.start_date).toISOString()
              : null,
            end_date: e.end_date
              ? new Date(e.end_date).toISOString()
              : null
          }))
        : [],
      gallery_images: user.gallery_images || []
    }));

    res.json({
      success: true,
      count: users.length,
      data: formattedUsers
    });

  } catch (error) {
    console.error('Admin user fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user data',
      details: process.env.NODE_ENV === 'development' ? error.message : null
    });
  }
});



app.post('/api/events/:id/certificates', async (req, res) => {
  const eventId = req.params.id;
  const { participant_id, certificate_url, unique_code, issued_at } = req.body;

  console.log('➡️ Saving certificate without PDF upload...');
  console.log({ eventId, participant_id, certificate_url, unique_code, issued_at });

  try {
    const participantCheck = await db.query(
      'SELECT * FROM participants WHERE id = $1 AND event_id = $2',
      [participant_id, eventId]
    );

    if (participantCheck.rows.length === 0) {
      return res.status(400).json({ error: 'Participant not registered for this event' });
    }

    const { rows } = await db.query(
      `INSERT INTO certificates (event_id, participant_id, certificate_url, unique_code, issued_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [eventId, participant_id, certificate_url, unique_code, issued_at]
    );

    console.log('✅ Certificate record saved:', rows[0]);
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('🚨 Save error:', err.message);
    res.status(500).json({ error: err.message });
  }
});



app.get('/api/email/:email', async (req, res) => {
    try {
        const email = req.params.email;

        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Valid email address is required' });
        }

        // Query to get user's results and certificates
        const query = `
            SELECT 
                u.id AS user_id,
                u.name AS user_name,
                u.email AS user_email,
                e.id AS event_id,
                e.title AS event_title,
                e.event_type,
                e.start_date,
                e.end_date,
                e.status AS event_status,
                p.id AS participant_id,
                p.attendance_status,
                r.score,
                r.rank,
                r.remarks,
                r.published_at AS result_published_at,
                c.certificate_url,
                c.unique_code AS certificate_code,
                c.issued_at AS certificate_issued_at
            FROM 
                users u
            JOIN 
                participants p ON u.id = p.user_id
            JOIN 
                events e ON p.event_id = e.id
            LEFT JOIN 
                results r ON r.event_id = e.id AND r.participant_id = p.id
            LEFT JOIN 
                certificates c ON c.event_id = e.id AND c.participant_id = p.id
            WHERE 
                u.email = $1
            ORDER BY 
                e.start_date DESC;
        `;

        const { rows } = await db.query(query, [email]);

        if (rows.length === 0) {
            return res.status(404).json({ 
                message: 'No results found for this email address',
                hasResults: false
            });
        }

        // Transform the data
        const response = {
            user: {
                id: rows[0].user_id,
                name: rows[0].user_name,
                email: rows[0].user_email
            },
            events: rows.map(row => ({
                event: {
                    id: row.event_id,
                    title: row.event_title,
                    type: row.event_type,
                    startDate: row.start_date,
                    endDate: row.end_date,
                    status: row.event_status
                },
                participation: {
                    id: row.participant_id,
                    attended: row.attendance_status
                },
                result: row.score !== null ? {
                    score: row.score,
                    rank: row.rank,
                    remarks: row.remarks,
                    publishedAt: row.result_published_at
                } : null,
                certificate: row.certificate_url ? {
                    url: row.certificate_url,
                    uniqueCode: row.certificate_code,
                    issuedAt: row.certificate_issued_at
                } : null
            })),
            stats: {
                totalEvents: rows.length,
                eventsAttended: rows.filter(r => r.attendance_status).length,
                eventsWithResults: rows.filter(r => r.score !== null).length,
                eventsWithCertificates: rows.filter(r => r.certificate_url).length
            }
        };

        res.json(response);

    } catch (error) {
        console.error('Error fetching results by email:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});






// Validate reset token
app.get('/api/auth/validate-reset-token/:token', async (req, res) => {
  const { token } = req.params;

  try {
    // 1. Find user with this token
    const { rows } = await db.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
      [token]
    );
    
    if (rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    res.status(200).json({ valid: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Reset password with token
app.post('/api/auth/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    // 1. Find user with this token
    const { rows } = await db.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
      [token]
    );
    
    if (rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    const user = rows[0];
    
    // 2. Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 3. Update password and clear reset token
    await db.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [hashedPassword, user.id]
    );
    
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// Error handling middleware
app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
