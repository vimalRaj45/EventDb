

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
const APPSCRIPT_PDF_UPLOAD_URL = process.env.APPSCRIPT_PDF_UPLOAD_URL || 'https://script.google.com/macros/s/AKfycbyVB5_MKM4mFUDNpOFDh8ASxGspDN0V4UDru7kyAwR1L6XLP354jBth22WH_KsPZT_z/exec';

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
    status = 'upcoming',
    event_fee = 0  // Accept numeric(10,2)
  } = req.body;

  try {
    const { rows } = await db.query(
      `INSERT INTO events (
        title, description, detailed_description, rules, event_type,
        poster_url, banner_url, start_date, end_date, registration_deadline,
        max_participants, status, organizer_id, event_fee
      ) VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10,
        $11, $12, $13, $14
      )
      RETURNING *`,
      [
        title, description, detailed_description, rules, event_type,
        poster_url, banner_url, start_date, end_date, registration_deadline,
        max_participants, status, req.user.id, event_fee
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
    status,
    event_fee = 0  // Accept updated fee
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
        event_fee = $13,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $14
      RETURNING *`,
      [
        title, description, detailed_description, rules, event_type,
        poster_url, banner_url, start_date, end_date, registration_deadline,
        max_participants, status, event_fee, eventId
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
        p.referral_code AS referral_code,
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

// --------------------- GET ALL PAYMENTS (ADMIN) ---------------------
app.get('/api/payments', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        p.id AS participant_id,
        p.user_id,
        u.name AS user_name,
        u.email AS user_email,
        p.event_id,
        e.title AS event_title,
        e.event_fee,
        p.registration_data,
        p.transaction_id,
        p.referral_code AS referral_code,
        p.payment_verified,
        p.verified_at,
        p.registered_at
      FROM participants p
      JOIN users u ON p.user_id = u.id
      JOIN events e ON p.event_id = e.id
      ORDER BY p.registered_at DESC
    `);

    res.json({
      payments: result.rows
    });

  } catch (err) {
    console.error('Error fetching all payments:', err);
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
  transaction_id = null,
  referral_code = null // Add this line
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
    (user_id, event_id, registration_data, transaction_id, referral_code)
   VALUES ($1, $2, $3, $4, $5)
   RETURNING *`,
  [userId, eventId, registration_data, transaction_id, referral_code]
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



// 📥 APPLY to Internship
app.post('/api/internships/:id/apply', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const internshipId = req.params.id;
  try {
    const result = await db.query(
      `INSERT INTO applications (user_id, internship_id)
       VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING *`,
      [userId, internshipId]
    );
    if (result.rowCount === 0) {
      return res.status(409).json({ message: 'Already applied' });
    }
    res.json({ message: 'Applied successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📄 GET Your Applications
// 📄 GET Your Applications (with status)
app.get('/api/internships/applied', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await db.query(
      `SELECT i.*, a.status
       FROM internships i
       JOIN applications a ON i.id = a.internship_id
       WHERE a.user_id = $1
       ORDER BY a.applied_at DESC`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// POST /api/admin/internships/:id/set-payment-qr
app.post('/api/admin/internships/:id/set-payment-qr', async (req, res) => {
  const internshipId = req.params.id;
  const { paymentQr } = req.body;
  try {
    await db.query(
      `UPDATE internships SET payment_qr = $1 WHERE id = $2`,
      [paymentQr, internshipId]
    );
    res.json({ message: 'Payment QR updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// 💳 SUBMIT PAYMENT and trigger APPLY if needed
// 💳 SUBMIT PAYMENT and trigger APPLY if needed
app.post('/api/internships/:id/submit-payment', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const internshipId = req.params.id;
  const { transactionNo, referralCode } = req.body;

  console.log('💳 [submit-payment] Start');
  console.log('➡️ User ID:', userId);
  console.log('➡️ Internship ID:', internshipId);
  console.log('➡️ Transaction No:', transactionNo);
  console.log('➡️ Referral Code from frontend:', referralCode);

  if (!transactionNo) {
    return res.status(400).json({ message: 'Transaction number is required' });
  }

  try {
    // ✅ Check if user already applied
    const existingApp = await db.query(
      `SELECT id FROM applications WHERE user_id = $1 AND internship_id = $2`,
      [userId, internshipId]
    );

    let referralCodeUsed = referralCode;

    // If not applied, insert application
    if (existingApp.rows.length === 0) {
      const userResult = await db.query(
        `SELECT referral_code FROM students WHERE id = $1`,
        [userId]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Use fallback referral code from DB
      if (!referralCodeUsed) {
        referralCodeUsed = userResult.rows[0].referral_code;
        console.log('🧠 Referral Code fallback from DB:', referralCodeUsed);
      }

      const applyResult = await db.query(
        `INSERT INTO applications (user_id, internship_id, referral_code)
         VALUES ($1, $2, $3)
         RETURNING id`,
        [userId, internshipId, referralCodeUsed]
      );

      if (applyResult.rowCount === 0) {
        return res.status(500).json({ message: 'Failed to apply while submitting payment' });
      }

      console.log('✅ New application inserted with referral:', referralCodeUsed);
    } else {
      // ✅ Update referralCode if missing (in case application already exists)
      if (!referralCodeUsed) {
        const userResult = await db.query(
          `SELECT referral_code FROM students WHERE id = $1`,
          [userId]
        );
        if (userResult.rows.length > 0) {
          referralCodeUsed = userResult.rows[0].referral_code;
        }
      }
    }

    // ✅ Update payment details + referral_code
    await db.query(
      `UPDATE applications
       SET payment_status = 'paid',
           transaction_no = $1,
           referral_code = $4
       WHERE user_id = $2 AND internship_id = $3`,
      [transactionNo, userId, internshipId, referralCodeUsed]
    );

    console.log('💰 Payment & referral updated for user:', userId);

    res.json({
      message: 'Payment submitted and application confirmed',
      referralCodeUsed
    });

  } catch (err) {
    console.error('❌ Submit payment error:', err);
    res.status(500).json({ error: err.message });
  }
});





// POST /api/admin/applications/:id/verify-payment
app.post('/api/admin/applications/:id/verify-payment', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const applicationId = req.params.id;
  try {
    const result = await db.query(
      `UPDATE applications
       SET payment_status = 'verified', status = 'approved'
       WHERE id = $1 RETURNING *`,
      [applicationId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Application not found' });
    }

    res.json({ message: 'Payment verified and application approved.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// 📄 ADMIN: View all applications (with referral_code from applications table)
app.get('/api/admin/applications', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        a.id, 
        u.id AS user_id,
        u.name AS student_name, 
        u.email,
        a.referral_code,
        i.company_name, 
        i.position, 
        a.applied_at,
        a.status,
        a.transaction_no,
        a.payment_status
      FROM applications a
      JOIN users u ON u.id = a.user_id
      JOIN internships i ON i.id = a.internship_id
      ORDER BY a.applied_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
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

app.post('/api/internships', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const userId = req.user.id;
  const {
    company_name,
    position,
    duration,
    start_date,
    end_date,
    imgurl,
    description,
    application_fee
  } = req.body;

  try {
    const result = await db.query(
      `INSERT INTO internships 
        (user_id, company_name, position, duration, start_date, end_date, imgurl, description, application_fee)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        userId,
        company_name,
        position,
        duration,
        start_date,
        end_date,
        imgurl,
        description,
        application_fee
      ]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📄 READ All Internships (GET)
app.get('/api/internships', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM internships ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📄 READ Internships (only for logged-in user)
app.get('/api/getyour/internships', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await db.query('SELECT * FROM internships WHERE user_id = $1 ORDER BY id DESC', [userId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📄 READ One Internship (GET)
app.get('/api/internships/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.query('SELECT * FROM internships WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Internship not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/internships/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      company_name,
      position,
      duration,
      start_date,
      end_date,
      imgurl,
      status,
      description,
      application_fee
    } = req.body;

    const result = await db.query(
      `UPDATE internships SET
        company_name = $1,
        position = $2,
        duration = $3,
        start_date = $4,
        end_date = $5,
        imgurl = $6,
        status = $7,
        description = $8,
        application_fee = $9
      WHERE id = $10 RETURNING *`,
      [
        company_name,
        position,
        duration,
        start_date,
        end_date,
        imgurl,
        status,
        description,
        application_fee,
        id
      ]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ Update error:", err.message);
    res.status(500).json({ error: err.message });
  }
});




// ❌ DELETE Internship (DELETE)
app.delete('/api/internships/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    await db.query('DELETE FROM internships WHERE id = $1', [id]);
    res.json({ message: 'Internship deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// ✅ Change Application Status (Admin Only)
app.put('/api/admin/applications/:id/status', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // expected values: 'approved' or 'rejected'

  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  try {
    const result = await db.query(
      'UPDATE applications SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Application not found' });
    res.json({ message: `Application ${status}`, application: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ✅ Get User by ID (Admin Only)
app.get('/api/users/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query(
      `SELECT id, name, email, role, created_at, last_login, verified, contact_no
       FROM users WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('❌ Error fetching user by ID:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});






//std referer 




// 🔄 Enhanced Referral Code Generator
function generateReferralCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';

  for (let i = 0; i < 11; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  return code;
}


async function uploadToImgBB(buffer) {
  const base64 = buffer.toString('base64');
  const form = new URLSearchParams();
  form.append('key', '76954d664f0beaf57b8c5a5b0eca84e6');
  form.append('image', base64);

  const response = await axios.post('https://api.imgbb.com/1/upload', form);
  return response.data.data.url;
}

// 🔐 Student Login
app.post('/stdlogin', async (req, res) => {
  try {
    const { contact_number, email } = req.body;
    const query = `SELECT * FROM students WHERE contact_number = $1 AND email = $2`;
    const result = await db.query(query, [contact_number, email]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Student not found' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 📝 Enhanced Register Student (Pending) with Referral Validation
app.post('/students', upload.fields([
  { name: 'clg_id_photo' },
  { name: 'photo' },
  { name: 'signature_photo' }
]), async (req, res) => {
  try {
    const {
      first_name, last_name, gender, contact_number, whatsapp_number,
      email, college_name, study_year, district,
      payment_method, payment_number, target = 0, attained = 0,
      referrer_code, assigned_by = 'admin'
    } = req.body;

    // Validate referrer code if provided
    if (referrer_code) {
      const referrerExists = await db.query(
        'SELECT id FROM students WHERE referral_code = $1 AND status = $2',
        [referrer_code, 'approved']
      );
      if (referrerExists.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid or inactive referral code' });
      }
    }

    const check = await db.query(
      `SELECT id FROM students WHERE contact_number = $1 OR email = $2`,
      [contact_number, email]
    );
    if (check.rows.length > 0) return res.status(409).json({ error: 'Student already exists.' });

    const clg_id_photo_url = req.files?.clg_id_photo ? await uploadToImgBB(req.files.clg_id_photo[0].buffer) : null;
    const photo_url = req.files?.photo ? await uploadToImgBB(req.files.photo[0].buffer) : null;
    const signature_photo_url = req.files?.signature_photo ? await uploadToImgBB(req.files.signature_photo[0].buffer) : null;

    const insertQuery = `
      INSERT INTO students (
        first_name, last_name, gender, contact_number, whatsapp_number,
        email, college_name, study_year, district, referral_code,
        payment_method, payment_number, clg_id_photo_url, photo_url,
        signature_photo_url, target, attained, status,
        is_mentor, role, referrer_code, assigned_by
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, NULL,
        $10, $11, $12, $13, $14, $15, $16, 'pending',
        false, 'student', $17, $18
      ) RETURNING id
    `;

    const values = [
      first_name, last_name, gender, contact_number, whatsapp_number,
      email, college_name, study_year, district,
      payment_method, payment_number, clg_id_photo_url, photo_url,
      signature_photo_url, target, attained,
      referrer_code, assigned_by
    ];

    const result = await db.query(insertQuery, values);
    res.json({ message: 'Student registered successfully. Awaiting approval.', id: result.rows[0].id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ✅ Enhanced Admin Approves Student with Referral Tracking
app.put('/students/approve/:id', async (req, res) => {
  try {
    const referral_code = generateReferralCode();
    const query = `
      UPDATE students
      SET status = 'approved', referral_code = $1
      WHERE id = $2
      RETURNING *
    `;
    const result = await db.query(query, [referral_code, req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    
    const student = result.rows[0];
    
    // If this student was referred by someone, update referrer's stats
    if (student.referrer_code) {
      await db.query(
        `UPDATE students 
         SET attained = attained + 1 
         WHERE referral_code = $1`,
        [student.referrer_code]
      );
      
      // Check if referrer achieved their target and promote if needed
      const referrer = await db.query(
        `SELECT id, target, attained, is_mentor 
         FROM students 
         WHERE referral_code = $1`,
        [student.referrer_code]
      );
      
      if (referrer.rows.length > 0) {
        const { id, target, attained, is_mentor } = referrer.rows[0];
        if (!is_mentor && attained >= target) {
          await db.query(
            `UPDATE students 
             SET is_mentor = true, role = 'mentor' 
             WHERE id = $1`,
            [id]
          );
        }
      }
    }
    
    res.json({ message: 'Approved', student: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🧑‍🏫 Admin Creates Mentor
app.post('/admin/create-mentor', async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      gender,
      contact_number,
      whatsapp_number,
      email,
      college_name,
      study_year,
      district,
      payment_method,
      payment_number,
      admin_intern_target = 0,
      admin_intern_attained = 0
    } = req.body;

    const check = await db.query(
      `SELECT id FROM students WHERE contact_number = $1 OR email = $2`,
      [contact_number, email]
    );
    if (check.rows.length > 0) {
      return res.status(409).json({ error: 'Mentor already exists.' });
    }

    const referral_code = generateReferralCode();

    const insert = `
      INSERT INTO students (
        first_name, last_name, gender, contact_number, whatsapp_number, email,
        college_name, study_year, district, referral_code, payment_method, payment_number,
        status, is_mentor, role, admin_intern_target, admin_intern_attained
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'approved',true,'mentor',$13,$14)
      RETURNING *`;

    const result = await db.query(insert, [
      first_name, last_name, gender, contact_number, whatsapp_number, email,
      college_name, study_year, district, referral_code, payment_method, payment_number,
      admin_intern_target, admin_intern_attained
    ]);

    res.json({ message: 'Mentor created', mentor: result.rows[0] });

  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// 📥 Enhanced Referral Tree with Performance Metrics
app.get('/students/referral-tree/:code', async (req, res) => {
  try {
    const query = `
      WITH RECURSIVE referral_tree AS (
        SELECT 
          id, first_name, last_name, email, referral_code, 
          referrer_code, role, target, attained, status,
          0 AS level
        FROM students 
        WHERE referral_code = $1
        
        UNION ALL
        
        SELECT 
          s.id, s.first_name, s.last_name, s.email, 
          s.referral_code, s.referrer_code, s.role, 
          s.target, s.attained, s.status,
          rt.level + 1
        FROM students s
        JOIN referral_tree rt ON s.referrer_code = rt.referral_code
      )
      SELECT 
        id, first_name, last_name, email, 
        referral_code, referrer_code, role, 
        target, attained, status, level,
        (attained >= target) AS target_achieved,
        (SELECT COUNT(*) FROM students WHERE referrer_code = rt.referral_code) AS referral_count
      FROM referral_tree rt
      ORDER BY level, id
    `;
    const result = await db.query(query, [req.params.code]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🧍 Promote to Mentor
app.put('/students/promote/:id',  async (req, res) => {
  try {
    const query = `UPDATE students SET is_mentor = true, role = 'mentor' WHERE id = $1 RETURNING *`;
    const result = await db.query(query, [req.params.id]);
    res.json({ message: 'Promoted to mentor', student: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🎯 Enhanced Mentor Assigns Target with Validation
app.post('/mentors/assign-target', async (req, res) => {
  try {
    const { student_id, target, mentor_email } = req.body;

    // Verify mentor exists and get their referral code
    const mentor = await db.query(
      `SELECT referral_code FROM students WHERE email = $1 AND role = 'mentor'`,
      [mentor_email]
    );
    
    if (mentor.rows.length === 0) {
      return res.status(403).json({ error: 'Mentor not found' });
    }
    
    const mentorCode = mentor.rows[0].referral_code;

    // Verify the student was referred by this mentor
    const student = await db.query(
      `SELECT id FROM students WHERE id = $1 AND referrer_code = $2`,
      [student_id, mentorCode]
    );
    
    if (student.rows.length === 0) {
      return res.status(403).json({ error: 'Student not referred by this mentor' });
    }

    // Update target
    await db.query(
      `UPDATE students SET target = $1, assigned_by = $2 WHERE id = $3`,
      [target, mentor_email, student_id]
    );
    
    res.json({ message: 'Target assigned successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.post('/admin/assign-students', async (req, res) => {
  try {
    const { mentor_id, student_ids } = req.body;

    if (!Array.isArray(student_ids) || student_ids.length === 0) {
      return res.status(400).json({ error: 'No students selected' });
    }

    const mentor = await db.query(`
      SELECT referral_code FROM students
      WHERE id = $1 AND is_mentor = true
    `, [mentor_id]);

    if (mentor.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid mentor ID' });
    }

    const referral_code = mentor.rows[0].referral_code;

    const assignQuery = `
      UPDATE students
      SET assigned_by = $1, referrer_code = $2
      WHERE id = ANY($3::int[])
    `;
    await db.query(assignQuery, [mentor_id, referral_code, student_ids]);

    res.json({ message: 'Students assigned to mentor successfully.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// 🎯 Get Students Ready for Promotion
app.get('/students/ready-for-promotion', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT s.*, 
       (SELECT first_name || ' ' || last_name FROM students WHERE referral_code = s.referrer_code) as referrer_name
       FROM students s 
       WHERE attained >= target AND is_mentor = false AND role = 'student'`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📊 List All Students with Referrer Info
app.get('/students', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT s.*, 
       (SELECT first_name || ' ' || last_name FROM students WHERE referral_code = s.referrer_code) as referrer_name
       FROM students s 
       ORDER BY id DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🗑️ Delete Student
app.delete('/students/:id', async (req, res) => {
  try {
    await db.query(`DELETE FROM students WHERE id = $1`, [req.params.id]);
    res.json({ message: 'Student deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🏆 New Endpoint: Get Referral Leaderboard
app.get('/referral/leaderboard', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT 
        s.id, s.first_name, s.last_name, s.referral_code,
        COUNT(r.id) as total_referrals,
        COUNT(r.id) FILTER (WHERE r.status = 'approved') as approved_referrals,
        COALESCE(SUM(r.attained), 0) as total_attained
       FROM students s
       LEFT JOIN students r ON r.referrer_code = s.referral_code
       WHERE s.status = 'approved'
       GROUP BY s.id
       ORDER BY approved_referrals DESC, total_attained DESC
       LIMIT 50`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



app.get('/admin/students', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        s.*, 
        r.first_name || ' ' || r.last_name AS referrer_name
      FROM students s
      LEFT JOIN students r ON s.referrer_code = r.referral_code
      ORDER BY s.id DESC
    `);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/admin/mentors', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        m.id AS mentor_id,
        m.first_name || ' ' || m.last_name AS mentor_name,
        m.referral_code,
        COUNT(s.id) AS downline_count,
        COALESCE(SUM(s.attained), 0) AS total_attained
      FROM students m
      LEFT JOIN students s ON s.referrer_code = m.referral_code
      WHERE m.is_mentor = true
      GROUP BY m.id
    `);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/admin/referral-tree/:mentorId', async (req, res) => {
  const { mentorId } = req.params;
  try {
    const mentor = await db.query(`SELECT referral_code FROM students WHERE id = $1 AND is_mentor = true`, [mentorId]);
    if (mentor.rows.length === 0) {
      return res.status(404).json({ error: 'Mentor not found' });
    }

    const referral_code = mentor.rows[0].referral_code;

    const downlines = await db.query(`
      SELECT *
      FROM students
      WHERE referrer_code = $1
    `, [referral_code]);

    res.json(downlines.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/admin/stats', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        COUNT(*) FILTER (WHERE role = 'student') AS total_students,
        COUNT(*) FILTER (WHERE is_mentor = true) AS total_mentors,
        COUNT(*) FILTER (WHERE status = 'pending') AS pending_approvals,
        COUNT(*) FILTER (WHERE status = 'approved') AS approved_students
      FROM students
    `);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/admin/student/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const student = await db.query(`SELECT * FROM students WHERE id = $1`, [id]);
    if (student.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    let result = { ...student.rows[0] };

    // Optional: Get referrer
    if (result.referrer_code) {
      const referrer = await db.query(`SELECT * FROM students WHERE referral_code = $1`, [result.referrer_code]);
      if (referrer.rows.length > 0) {
        result.referrer = referrer.rows[0];
      }
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/report/:referrerCode', async (req, res) => {
  const referrerCode = req.params.referrerCode;

  try {
    // 1. Referrer name
    const referrerResult = await db.query(
      `SELECT first_name, last_name
       FROM students
       WHERE referral_code = $1
       LIMIT 1`,
      [referrerCode]
    );

    const referrerName = referrerResult.rows[0]
      ? `${referrerResult.rows[0].first_name} ${referrerResult.rows[0].last_name}`
      : 'Unknown';

    // 2. Students referred by this code
    const referredResult = await db.query(
      `SELECT id, first_name, last_name, attained
       FROM students
       WHERE referrer_code = $1`,
      [referrerCode]
    );

    const referredStudents = referredResult.rows.map(s => ({
      id: s.id,
      name: `${s.first_name} ${s.last_name}`,
      attained: s.attained || 0
    }));

    const totalAttained = referredStudents.reduce((sum, s) => sum + s.attained, 0);

    // 3. Students with no referrer (not mentor or admin)
    const noReferrerResult = await db.query(
      `SELECT id, first_name, last_name, attained
       FROM students
       WHERE (referrer_code IS NULL OR TRIM(referrer_code) = '')
         AND is_mentor = false
         AND role != 'admin'`
    );

    const noReferrerStudents = noReferrerResult.rows.map(s => ({
      id: s.id,
      name: `${s.first_name} ${s.last_name}`,
      attained: s.attained || 0
    }));

    // 4. Response
    res.json({
      referrer_code: referrerCode,
      referrer_name: referrerName,
      total_referred_students: referredStudents.length,
      total_attained_by_referred: totalAttained,
      referred_students: referredStudents,
      students_without_referrer: noReferrerStudents
    });

  } catch (err) {
    console.error('Error fetching report:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/api/referral-data', async (req, res) => {
  try {
    // Get all referrers (mentors or admins)
    const referrersQuery = await db.query(`
      SELECT 
        id, 
        first_name, 
        last_name, 
        email, 
        college_name, 
        referral_code, 
        attained,
        is_mentor,
        role
      FROM students 
      WHERE is_mentor = true OR role = 'admin'
    `);
    const referrers = referrersQuery.rows;

    // Get all students (excluding mentors and admins)
    const studentsQuery = await db.query(`
      SELECT 
        id, 
        first_name, 
        last_name, 
        email, 
        college_name, 
        status, 
        referrer_code
      FROM students 
      WHERE is_mentor = false AND role = 'student'
    `);
    const students = studentsQuery.rows;

    // Process each referrer to find their referred students
    const processedReferrers = await Promise.all(referrers.map(async (referrer) => {
      const referredStudentsQuery = await db.query(
        `SELECT id, first_name, last_name, email, college_name, status 
         FROM students 
         WHERE referrer_code = $1`,
        [referrer.referral_code]
      );
      const referredStudents = referredStudentsQuery.rows;

      return {
        id: referrer.id,
        name: `${referrer.first_name} ${referrer.last_name}`,
        email: referrer.email,
        referral_code: referrer.referral_code,
        total_referred: referredStudents.length,
        total_attained: referrer.attained || 0,
        referred_students: referredStudents
      };
    }));

    // Find students without valid referral codes
    const activeReferralCodes = referrers.map(r => r.referral_code);
    const studentsWithoutReferral = students.filter(student => {
      return !student.referrer_code || !activeReferralCodes.includes(student.referrer_code);
    });

    // Summary
    const summary = {
      total_referrers: referrers.length,
      total_students: students.length,
      total_with_referral: students.length - studentsWithoutReferral.length,
      total_without_referral: studentsWithoutReferral.length,
      total_attained: referrers.reduce((sum, r) => sum + (r.attained || 0), 0)
    };

    // Final Response
    const response = {
      success: true,
      data: {
        referrers: processedReferrers,
        students_without_referral: studentsWithoutReferral.map(s => ({
          id: s.id,
          name: `${s.first_name} ${s.last_name}`,
          email: s.email,
          college: s.college_name,
          status: s.status,
          invalid_referrer_code: s.referrer_code && !activeReferralCodes.includes(s.referrer_code)
            ? s.referrer_code
            : null
        })),
        summary
      }
    };

    res.json(response);

  } catch (error) {
    console.error('Referral data error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch referral data',
      details: error.message
    });
  }
});



// 🎯 Admin Sets Target for Any User
// 🎯 Admin Sets Target (student target + mentor intern target)
app.post('/admin/set-target', async (req, res) => {
  try {
    const { user_id, target, is_mentor, admin_intern_target } = req.body;

    if (!user_id || target === undefined || target === null) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if user exists and get role
    const userResult = await db.query(
      `SELECT id, attained, target, is_mentor, role FROM students WHERE id = $1`,
      [user_id]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Build update fields dynamically
    const fields = [`target = $1`];
    const values = [target];
    let paramIdx = 2;

    if (is_mentor && typeof admin_intern_target === 'number') {
      fields.push(`admin_intern_target = $${paramIdx++}`);
      values.push(admin_intern_target);
    }

    values.push(user_id);
    const updateQuery = `UPDATE students SET ${fields.join(', ')} WHERE id = $${paramIdx}`;
    await db.query(updateQuery, values);

    // Promote to mentor if eligible
    const user = userResult.rows[0];
    if (is_mentor && user.attained >= target && !user.is_mentor) {
      await db.query(
        `UPDATE students SET is_mentor = true, role = 'mentor' WHERE id = $1`,
        [user_id]
      );
    }

    res.json({ message: 'Target(s) set successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 🎯 Get All Targets
// 🎯 Get All Targets + Internship Target Tracking
app.get('/admin/targets', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        id,
        first_name || ' ' || last_name AS name,
        role,
        target,
        attained,
        (attained >= target) AS target_achieved,
        admin_intern_target,
        admin_intern_attained,
        (admin_intern_attained >= admin_intern_target) AS intern_target_achieved
      FROM students
      WHERE status = 'approved'
      ORDER BY role DESC, name ASC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});






app.post('/visits/untracked', async (req, res) => {
  try {
    await db.query('INSERT INTO unreferd_visits DEFAULT VALUES');
    res.json({ message: 'Untracked visit recorded' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



app.post('/students/increment-attained', async (req, res) => {
  try {
    const { referral_code } = req.body;

    // Increment attained by 1 for the given referral code
    const updateQuery = `
      UPDATE students
      SET attained = COALESCE(attained, 0) + 1
      WHERE referral_code = $1
      RETURNING attained
    `;

    const result = await db.query(updateQuery, [referral_code]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Referral code not found' });
    }

    res.json({
      message: 'Attained updated successfully',
      attained: result.rows[0].attained
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// 🚀 Increment Mentor + Upline admin_intern_attained by 1
app.post('/referrals/increment-intern-chain', async (req, res) => {
  try {
    const { used_referral_code } = req.body;

    if (!used_referral_code) {
      return res.status(400).json({ error: 'Referral code is required' });
    }

    // 🔍 1. Get the user who owns this referral code
    const userResult = await db.query(
      `SELECT id, referrer_code, first_name, role FROM students WHERE referral_code = $1`,
      [used_referral_code]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Referral code not found' });
    }

    const userId = userResult.rows[0].id;
    const userRole = userResult.rows[0].role;
    const userName = userResult.rows[0].first_name;
    const uplineRefCode = userResult.rows[0].referrer_code;

    // ✅ 2. Increment for this user
    const updatedUser = await db.query(
      `UPDATE students 
       SET admin_intern_attained = admin_intern_attained + 1 
       WHERE id = $1 
       RETURNING first_name, admin_intern_attained, role`,
      [userId]
    );

    const updatedUserData = updatedUser.rows[0];

    let uplineMentorData = null;

    // ✅ 3. Only if the referral code owner is NOT a mentor, increment their upline mentor (if exists)
    if (userRole !== 'mentor' && uplineRefCode) {
      const updatedMentor = await db.query(
        `UPDATE students 
         SET admin_intern_attained = admin_intern_attained + 1 
         WHERE referral_code = $1 AND role = 'mentor'
         RETURNING first_name, admin_intern_attained, role`,
        [uplineRefCode]
      );

      if (updatedMentor.rows.length > 0) {
        uplineMentorData = updatedMentor.rows[0];
      }
    }

    // ✅ 4. Final response
    res.json({
      message: 'admin_intern_attained incremented for referral code owner and upline mentor (if applicable)',
      updated_user: updatedUserData,
      updated_upline_mentor: uplineMentorData || 'No upline increment (either none or user is mentor)'
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


app.get('/mentor/:id/students/intern-attained', async (req, res) => {
  try {
    const { id } = req.params;

    // Get mentor details by ID
    const mentorResult = await db.query(
      `SELECT id, first_name, email, role, admin_intern_attained FROM students WHERE id = $1 AND role = 'mentor'`,
      [id]
    );

    if (mentorResult.rows.length === 0) {
      return res.status(404).json({ error: 'Mentor with that ID not found' });
    }

    const mentor = mentorResult.rows[0];

    // Get all students assigned to this mentor
    const studentResult = await db.query(
      `SELECT first_name, email, admin_intern_attained FROM students WHERE assigned_by = $1 AND role = 'student'`,
      [id]
    );

    res.json({
      mentor: {
        name: mentor.first_name,
        email: mentor.email,
        admin_intern_attained: mentor.admin_intern_attained,
      },
      total_students: studentResult.rows.length,
      students: studentResult.rows,
    });
  } catch (err) {
    console.error('Error fetching mentor student intern attained:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/all-mentors/students/intern-attained', async (req, res) => {
  try {
    // Step 1: Get all mentors
    const mentorsResult = await db.query(
      `SELECT id, first_name, email, admin_intern_attained FROM students WHERE role = 'mentor'`
    );

    const mentors = mentorsResult.rows;

    // Step 2: For each mentor, get their assigned students
    const mentorDetails = await Promise.all(
      mentors.map(async (mentor) => {
        const studentsResult = await db.query(
          `SELECT first_name, email, admin_intern_attained FROM students WHERE assigned_by = $1 AND role = 'student'`,
          [mentor.id]
        );

        return {
          mentor_id: mentor.id,
          mentor_name: mentor.first_name,
          mentor_email: mentor.email,
          mentor_admin_intern_attained: mentor.admin_intern_attained,
          total_students: studentsResult.rows.length,
          students: studentsResult.rows,
        };
      })
    );

    res.json({ count: mentorDetails.length, data: mentorDetails });
  } catch (err) {
    console.error('Error fetching all mentor-student intern attained data:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});






// API Routes
app.get('/api/announcements', async (req, res) => {
    try {
        const { active, priority, category, limit, page } = req.query;
        
        let query = 'SELECT * FROM announcements';
        const conditions = [];
        const params = [];
        let paramIndex = 1;
        
        if (active === 'true') {
            conditions.push(`is_active = $${paramIndex++}`);
            params.push(true);
        }
        
        if (priority) {
            conditions.push(`priority = $${paramIndex++}`);
            params.push(parseInt(priority));
        }
        
        if (category) {
            conditions.push(`$${paramIndex++} = ANY(categories)`);
            params.push(category);
        }
        
        if (conditions.length > 0) {
            query += ' WHERE ' + conditions.join(' AND ');
        }
        
        query += ' ORDER BY priority ASC, created_at DESC';
        
        // Add pagination if requested
        if (limit && page) {
            const offset = (parseInt(page) - 1) * parseInt(limit);
            query += ` LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
            params.push(parseInt(limit), offset);
        }
        
        const result = await db.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching announcements:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/announcements/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await db.query('SELECT * FROM announcements WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Announcement not found' });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error fetching announcement:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/announcements',  async (req, res) => {
    try {
        const { title, content, author, priority, end_date, is_active, categories } = req.body;
        
        const result = await db.query(
            `INSERT INTO announcements 
             (title, content, author, priority, end_date, is_active, categories) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) 
             RETURNING *`,
            [title, content, author, priority, end_date, is_active, categories]
        );
        
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error creating announcement:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/announcements/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content, author, priority, end_date, is_active, categories } = req.body;
        
        const result = await db.query(
            `UPDATE announcements 
             SET title = $1, content = $2, author = $3, priority = $4, 
                 end_date = $5, is_active = $6, categories = $7 
             WHERE id = $8 
             RETURNING *`,
            [title, content, author, priority, end_date, is_active, categories, id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Announcement not found' });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating announcement:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/announcements/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await db.query('DELETE FROM announcements WHERE id = $1 RETURNING *', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Announcement not found' });
        }
        
        res.json({ message: 'Announcement deleted successfully' });
    } catch (err) {
        console.error('Error deleting announcement:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});




// 🔽 1. Download participants as CSV
app.get('/api/events/:eventId/participants-csv', async (req, res) => {
  const { eventId } = req.params;

  try {
    const query = `
      SELECT u.id AS participant_id, u.name, u.email, p.event_id
      FROM participants p
      JOIN users u ON u.id = p.user_id
      WHERE p.event_id = $1
    `;
    const { rows } = await db.query(query, [eventId]);

    if (!rows.length) return res.status(404).send('No participants found');

    let csv = 'participant_id,name,email,event_id\n';
    rows.forEach(r => {
      csv += `${r.participant_id},"${r.name}","${r.email}",${r.event_id}\n`;
    });

    res.header('Content-Type', 'text/csv');
    res.attachment(`participants_event_${eventId}.csv`);
    res.send(csv);
  } catch (err) {
    console.error('CSV error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Util: read Google Sheet
async function readSheet(sheetId, sheetName) {
  const auth = new google.auth.GoogleAuth({
    keyFile:'auth.json'),
    scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
  });

  const client = await auth.getClient();
  const sheets = google.sheets({ version: 'v4', auth: client });

  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: sheetName,
  });

  const rows = res.data.values;
  if (!rows || rows.length === 0) return [];

  const headers = rows[0];
  return rows.slice(1).map((row, i) => {
    const rowData = {};
    headers.forEach((header, j) => {
      rowData[header.trim().toLowerCase()] = row[j] || '';
    });
    rowData._rowIndex = i + 1;
    return rowData;
  });
}

// POST SSE route
app.post('/api/certificates/generate', async (req, res) => {
  const { sheetId, sheetName, templateId, folderId, eventId } = req.body;

  if (!sheetId || !sheetName || !templateId || !folderId || !eventId) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }

  // SSE headers
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.flushHeaders();

  const sendEvent = (data) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  try {
    const rows = await readSheet(sheetId, sheetName);
    const scriptUrl = 'https://script.google.com/macros/s/AKfycbw_X7JrrnoA2JFApciTHeIKRbYckvE0sdns-wFHFAOZYhQjM8LVYmZHU0Wv_1tb1fi5/exec';

    for (const row of rows) {
      const { email, name, _rowIndex } = row;
      if (!email || !name) {
        sendEvent({ row: _rowIndex, status: 'skipped', reason: 'Missing email or name' });
        continue;
      }

      // Check participant in DB
      const participantResult = await db.query(`
        SELECT p.id FROM participants p
        JOIN users u ON u.id = p.user_id
        WHERE u.email = $1 AND p.event_id = $2
      `, [email, eventId]);

      if (!participantResult.rows.length) {
        sendEvent({ row: _rowIndex, email, status: 'skipped', reason: 'Participant not found' });
        continue;
      }

      const participantId = participantResult.rows[0].id;

      // Check if certificate already exists
      const certExists = await db.query(`
        SELECT 1 FROM certificates WHERE event_id = $1 AND participant_id = $2
      `, [eventId, participantId]);

      if (certExists.rows.length > 0) {
        sendEvent({ row: _rowIndex, email, status: 'skipped', reason: 'Already exists' });
        continue;
      }

      // Call Apps Script
      const url = `${scriptUrl}?sheetId=${sheetId}&sheetName=${sheetName}&templateId=${templateId}&folderId=${folderId}&row=${_rowIndex}`;
      let result;
      try {
        const response = await fetch(url);
        result = await response.json();
      } catch (err) {
        sendEvent({ row: _rowIndex, email, status: 'skipped', reason: 'Invalid JSON' });
        continue;
      }

      if (!result.success || !Array.isArray(result.certificates)) {
        sendEvent({ row: _rowIndex, email, status: 'skipped', reason: result.error || 'No certificate returned' });
        continue;
      }

      const cert = result.certificates[0];
      const { url: certUrl, uniqueCode } = cert;

      // Insert new certificate
      const insertResult = await db.query(`
        INSERT INTO certificates (event_id, participant_id, certificate_url, unique_code, issued_at)
        VALUES ($1, $2, $3, $4, NOW())
        RETURNING *
      `, [eventId, participantId, certUrl, uniqueCode]);

      sendEvent({ row: _rowIndex, email, status: 'inserted', url: certUrl });
    }

    sendEvent({ done: true });
    res.end();
  } catch (err) {
    sendEvent({ success: false, error: err.message });
    res.end();
  }
});





//new 10 july 
// 🔹 Assign to mentor
app.post('/api/targets/assign-to-mentor', async (req, res) => {
  const { mentor_id, event_id, target, assigned_by } = req.body;

  if (!mentor_id || !event_id || !target || !assigned_by) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    // Check for existing assignment
    const check = await db.query(
      `SELECT * FROM event_targets 
       WHERE user_id = $1 AND event_id = $2 AND role = 'mentor'`,
      [mentor_id, event_id]
    );

    if (check.rows.length > 0) {
      return res.status(409).json({ error: 'Target already assigned to this mentor for this event.' });
    }

    // Insert new assignment
    const result = await db.query(`
      INSERT INTO event_targets (user_id, assigned_by, event_id, role, target)
      VALUES ($1, $2, $3, 'mentor', $4)
      RETURNING *`,
      [mentor_id, assigned_by, event_id, target]
    );

    res.json({ success: true, message: 'Target assigned to mentor', data: result.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});


// 🔹 Admin assigns to student
app.post('/api/targets/assign-to-student-by-admin', async (req, res) => {
  const { student_id, event_id, target, assigned_by } = req.body;

  if (!student_id || !event_id || !target || !assigned_by) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    // Check if target already assigned
    const check = await db.query(`
      SELECT * FROM event_targets 
      WHERE user_id = $1 AND event_id = $2 AND role = 'student'`,
      [student_id, event_id]
    );

    if (check.rows.length > 0) {
      return res.status(409).json({ error: 'Target already assigned to this student for this event.' });
    }

    // Insert new target
    const result = await db.query(`
      INSERT INTO event_targets (user_id, assigned_by, event_id, role, target)
      VALUES ($1, $2, $3, 'student', $4) RETURNING *`,
      [student_id, assigned_by, event_id, target]
    );

    res.json({ success: true, message: 'Target assigned to student by admin', data: result.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});




// 🔹 View all targets (Admin)
app.get('/api/targets/admin/view-all', async (req, res) => {
  const result = await db.query(`
    SELECT t.*, s.first_name, s.last_name, s.role AS user_role, e.title AS event_title
    FROM event_targets t
    JOIN students s ON s.id = t.user_id
    JOIN events e ON e.id = t.event_id
    ORDER BY t.assigned_at DESC
  `);

  res.json({ success: true, data: result.rows });
});



app.get('/api/targets/admin/view-allAdvanced', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        t.id AS target_id,
        t.user_id,
        s.first_name,
        s.last_name,
        s.role AS user_role,
        e.title AS event_title,
        t.target,
        t.attained,
        t.assigned_at,

        -- Downline count and totals
        (
          SELECT COUNT(*) 
          FROM students sub 
          WHERE sub.referrer_code = s.referral_code
        ) AS downline_count,

        (
          SELECT COALESCE(SUM(et.target), 0)
          FROM event_targets et
          JOIN students sub ON sub.id = et.user_id
          WHERE sub.referrer_code = s.referral_code
        ) AS downline_total_target,

        (
          SELECT COALESCE(SUM(et.attained), 0)
          FROM event_targets et
          JOIN students sub ON sub.id = et.user_id
          WHERE sub.referrer_code = s.referral_code
        ) AS downline_total_attained

      FROM event_targets t
      JOIN students s ON s.id = t.user_id
      JOIN events e ON e.id = t.event_id
      ORDER BY t.assigned_at DESC
    `);

    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});



// 🔹 Mentor views assigned and received targets
app.get('/api/targets/admin/downlines-with-progress/:mentor_id', async (req, res) => {
  const mentorId = req.params.mentor_id;

  try {
    // 1. Get mentor's referral code
    const mentorResult = await db.query(`SELECT referral_code FROM students WHERE id = $1`, [mentorId]);
    if (mentorResult.rows.length === 0) {
      return res.status(404).json({ error: 'Mentor not found' });
    }

    const referralCode = mentorResult.rows[0].referral_code;

    // 2. Get downlines with their event targets (now includes event_targets.id as target_id)
    const downlineResult = await db.query(`
      SELECT 
        s.id AS student_id,
        s.first_name,
        s.last_name,
        s.email,
        e.id AS event_id,
        e.title AS event_title,
        et.id AS target_id,
        et.target,
        et.attained
      FROM students s
      JOIN event_targets et ON et.user_id = s.id
      JOIN events e ON e.id = et.event_id
      WHERE s.referrer_code = $1
      ORDER BY s.id, e.id
    `, [referralCode]);

    res.json({ success: true, data: downlineResult.rows });
  } catch (err) {
    console.error('Error fetching downlines with progress:', err);
    res.status(500).json({ error: err.message });
  }
});


// 🔹 Student views own targets (pass student_id as query param)
app.get('/api/targets/student/view-mine', async (req, res) => {
  const studentId = req.query.student_id;
  if (!studentId) return res.status(400).json({ error: 'Missing student_id' });

  const result = await db.query(`
    SELECT t.*, e.title AS event_title
    FROM event_targets t
    JOIN events e ON e.id = t.event_id
    WHERE t.user_id = $1
    ORDER BY t.assigned_at DESC
  `, [studentId]);

  res.json({ success: true, data: result.rows });
});

// 🔹 Get mentor details for a student
app.get('/api/students/:studentId/mentor', async (req, res) => {
  const studentId = req.params.studentId;

  try {
    // Get student's referrer_code
    const studentRes = await db.query(
      `SELECT referrer_code FROM students WHERE id = $1`,
      [studentId]
    );

    if (studentRes.rows.length === 0 || !studentRes.rows[0].referrer_code) {
      return res.status(404).json({ error: 'Mentor not assigned yet' });
    }

    const referrerCode = studentRes.rows[0].referrer_code;

    // Get mentor details
    const mentorRes = await db.query(
      `SELECT id, first_name, last_name, email, whatsapp_number, contact_number, referral_code
       FROM students
       WHERE referral_code = $1 AND is_mentor = true`,
      [referrerCode]
    );

    if (mentorRes.rows.length === 0) {
      return res.status(404).json({ error: 'Mentor not found' });
    }

    res.json({ success: true, data: mentorRes.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/referral/treeupdated/:referral_code', async (req, res) => {
  const { referral_code } = req.params;

  try {

    // 1. Fetch self
    const selfRes = await db.query(
      `SELECT id, first_name, last_name, referral_code, referrer_code, role, target, attained,
              email, contact_number, whatsapp_number
       FROM students WHERE referral_code = $1`,
      [referral_code]
    );

    if (selfRes.rowCount === 0) {
      return res.status(404).json({ error: 'Referral code not found' });
    }

    const self = selfRes.rows[0];

    // 2. Fetch upline
    let upline = null;
    if (self.referrer_code) {
      const upRes = await db.query(
        `SELECT first_name, last_name, referral_code, role, target, attained,
                email, contact_number, whatsapp_number
         FROM students WHERE referral_code = $1`,
        [self.referrer_code]
      );
      if (upRes.rowCount > 0) {
        const u = upRes.rows[0];
        upline = {
          full_name: `${u.first_name} ${u.last_name}`,
          referral_code: u.referral_code,
          role: u.role,
          target: u.target,
          attained: u.attained,
          email: u.email,
          contact_number: u.contact_number,
          whatsapp_number: u.whatsapp_number
        };
      }
    }

    // 3. Fetch downlines
    const downRes = await db.query(
      `SELECT first_name, last_name, referral_code, role, target, attained,
              email, contact_number, whatsapp_number
       FROM students WHERE referrer_code = $1`,
      [referral_code]
    );

    const downlines = downRes.rows.map(d => ({
      full_name: `${d.first_name} ${d.last_name}`,
      referral_code: d.referral_code,
      role: d.role,
      target: d.target,
      attained: d.attained,
      email: d.email,
      contact_number: d.contact_number,
      whatsapp_number: d.whatsapp_number
    }));

    // 4. Fetch event targets (optional progress tracking)
    const eventsRes = await db.query(
      `SELECT event_id, target, attained, role, assigned_at
       FROM event_targets WHERE user_id = $1`,
      [self.id]
    );

    const events = eventsRes.rows.map(e => ({
      event_id: e.event_id,
      target: e.target,
      attained: e.attained,
      role: e.role,
      assigned_at: e.assigned_at
    }));

    // 5. Return response
    res.json({
      referral_code,
      upline,
      self: {
        full_name: `${self.first_name} ${self.last_name}`,
        referral_code: self.referral_code,
        role: self.role,
        target: self.target,
        attained: self.attained,
        email: self.email,
        contact_number: self.contact_number,
        whatsapp_number: self.whatsapp_number,
        events
      },
      downlines
    });

  } catch (err) {
    console.error('Error fetching referral tree with contact:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// 🔹 Increment referral progress
app.post('/api/targets/increment-by-referral', async (req, res) => {
  const { used_referral_code, event_id } = req.body;

  if (!used_referral_code || !event_id) {
    return res.status(400).json({ error: 'Referral code and event_id are required' });
  }

  try {
    // Step 1: Find student ID using referral code
    const refStudentRes = await db.query(
      `SELECT id FROM students WHERE referral_code = $1`,
      [used_referral_code]
    );

    if (refStudentRes.rows.length === 0) {
      return res.status(404).json({ error: 'Referral code not found' });
    }

    const studentId = refStudentRes.rows[0].id;

    // Step 2: Get latest target for that student in that event
    const targetRes = await db.query(
      `SELECT id FROM event_targets
       WHERE user_id = $1 AND event_id = $2
       ORDER BY assigned_at DESC
       LIMIT 1`,
      [studentId, event_id]
    );

    if (targetRes.rows.length === 0) {
      return res.status(404).json({ error: 'No target found for this referral and event' });
    }

    const targetId = targetRes.rows[0].id;

    // Step 3: Increment attained count
    const updated = await db.query(
      `UPDATE event_targets
       SET attained = attained + 1
       WHERE id = $1
       RETURNING *`,
      [targetId]
    );

    res.json({
      success: true,
      message: 'Progress incremented for referral target',
      data: updated.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


app.put('/api/targets/:id', async (req, res) => {
  const { target } = req.body;

  if (!target) {
    return res.status(400).json({ error: 'Target value is required' });
  }

  try {
    const result = await db.query(
      `
      UPDATE event_targets
      SET target = $1
      WHERE id = $2
      RETURNING *
      `,
      [target, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Target not found' });
    }

    res.json({ success: true, message: 'Target updated (attained unchanged)', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});



app.delete('/api/targets/:id', async (req, res) => {
  try {
    await db.query(`DELETE FROM event_targets WHERE id = $1`, [req.params.id]);
    res.json({ success: true, message: 'Target deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//gemini
app.post('/api/chatbot/internships', async (req, res) => {
  const { user_id } = req.body;

  if (!user_id) {
    return res.status(400).json({ error: 'user_id is required' });
  }

  try {
    const result = await db.query(
      `SELECT company_name, position, status, start_date, end_date
       FROM internships
       WHERE user_id = $1
       ORDER BY submitted_at DESC
       LIMIT 5`,
      [user_id]
    );

    const internships = result.rows;

    return res.json({
      status: "success",
      message: internships.length
        ? `💼 You have ${internships.length} internship(s).`
        : "No internships found for this user.",
      data: internships
    });
  } catch (err) {
    console.error("Internship fetch error:", err);
    return res.status(500).json({
      status: "error",
      message: "Server error while fetching internships."
    });
  }
});

app.get('/api/chatbot/general', async (req, res) => {
  try {
    const general = {};

    // 📢 Active Announcements
    const announcements = await db.query(`
      SELECT title, content, author, start_date
      FROM announcements
      WHERE is_active = true
      ORDER BY priority ASC, start_date DESC
    
    `);
    general.announcements = announcements.rows;

    // 🎉 Upcoming Events
    const upcomingEvents = await db.query(`
      SELECT title, start_date, description
      FROM events
      WHERE status = 'upcoming'
      ORDER BY start_date ASC
      
    `);
    general.upcoming_events = upcomingEvents.rows;

    // 💼 Latest Internships
    const internships = await db.query(`
      SELECT company_name, position, status
      FROM internships
      ORDER BY submitted_at DESC
      
    `);
    general.internships = internships.rows;

    // ✅ Return response
    return res.json({
      status: "success",
      message: "Here is the general information",
      data: general
    });
  } catch (err) {
    console.error("General info error:", err);
    return res.status(500).json({
      status: "error",
      message: "Something went wrong while fetching general info."
    });
  }
});

// 📄 Get Direct Downline IDs and Names for a given referral_code
app.get('/studentsormentor/downlines/:code', async (req, res) => {
  try {
    const query = `
      SELECT id, first_name, last_name, role
      FROM students
      WHERE referrer_code = $1
      ORDER BY id
    `;
    const result = await db.query(query, [req.params.code]);
    
    // Format response with role
    const downlines = result.rows.map(row => ({
      id: row.id,
      name: `${row.first_name} ${row.last_name}`,
      role: row.role
    }));

    res.json(downlines);
  } catch (err) {
    console.error('Error fetching downlines:', err.message);
    res.status(500).json({ error: err.message });
  }
});


// Referral Income API

// ✅ Get all referrals
app.get('/referrals', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM referral_income ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Get one referral by ID
app.get('/referrals/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.query('SELECT * FROM referral_income WHERE id = $1', [id]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Create new referral
// ✅ Create new referral
app.post('/referrals', async (req, res) => {
  const {
    email,
    stud_name,
    total_participants,
    reward_amount_inr,
    payment_date,
    transaction_id,
    downline_name,
    downline_participants,
    total_downline_participants,
    current_participants,
    total_invitations,
    inter_total,
    profile_picture_url,
    role,
    msg,
    ph_no,
    refer_code,
  } = req.body;

  try {
    const result = await db.query(
      `INSERT INTO referral_income (
        email, stud_name, total_participants, reward_amount_inr, payment_date, transaction_id,
        downline_name, downline_participants, total_downline_participants, current_participants,
        total_invitations, inter_total, profile_picture_url, role, msg,ph_no,refer_code
      ) VALUES (
        $1, $2, $3, $4, $5, $6,
        $7, $8, $9, $10,
        $11, $12, $13, $14, $15,$16,$17
      ) RETURNING *`,
      [
        email,
        stud_name,
        total_participants,
        reward_amount_inr,
        payment_date,
        transaction_id,
        downline_name,
        downline_participants,
        total_downline_participants,
        current_participants,
        total_invitations,
        inter_total,
        profile_picture_url,
        role,
        msg,
        ph_no,
        refer_code,
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Update referral
app.put('/referrals/:id', async (req, res) => {
  const { id } = req.params;
  const {
    email,
    stud_name,
    total_participants,
    reward_amount_inr,
    payment_date,
    transaction_id,
    downline_name,
    downline_participants,
    total_downline_participants,
    current_participants,
    total_invitations,
    inter_total,
    profile_picture_url,
    role,
    msg,
    ph_no,
  } = req.body;

  try {
    const result = await db.query(
      `UPDATE referral_income SET
        email = $1,
        stud_name = $2,
        total_participants = $3,
        reward_amount_inr = $4,
        payment_date = $5,
        transaction_id = $6,
        downline_name = $7,
        downline_participants = $8,
        total_downline_participants = $9,
        current_participants = $10,
        total_invitations = $11,
        inter_total = $12,
        profile_picture_url = $13,
        role = $14,
        msg = $15,
        ph_no = $16
      WHERE id = $17
      RETURNING *`,
      [
        email,
        stud_name,
        total_participants,
        reward_amount_inr,
        payment_date,
        transaction_id,
        downline_name,
        downline_participants,
        total_downline_participants,
        current_participants,
        total_invitations,
        inter_total,
        profile_picture_url,
        role,
        msg,
        ph_no,
        id
      ]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




//login for see 

app.get('/referralslogin/:email', async (req, res) => {
  const { email } = req.params;

  try {
    const result = await db.query(
      'SELECT * FROM referral_income WHERE email = $1',
      [email]
    );

    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching referral data:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/referralsedit/:email', async (req, res) => {
  const { email } = req.params;
  const { stud_name, profile_picture_url } = req.body;

  try {
    const result = await db.query(
      `UPDATE referral_income
       SET stud_name = $1,
           profile_picture_url = $2
       WHERE email = $3
       RETURNING *`,
      [stud_name, profile_picture_url, email]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'No referral found with this email' });
    }

    res.json({ message: 'Referral updated successfully', data: result.rows[0] });
  } catch (err) {
    console.error('Error updating referral:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});





// for uptime Express example
app.get('/ping', (req, res) => res.send('Pong!'));


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
