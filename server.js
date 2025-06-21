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
  const { name, email, password, role = 'participant' } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const { rows } = await db.query(
      `INSERT INTO users (name, email, password_hash, role) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, name, email, role, created_at`,
      [name, email, hashedPassword, role]
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
  const registrationData = req.body.registration_data || {};
  
  try {
    // Check if event exists and is open for registration
    const event = await db.query(
      'SELECT * FROM events WHERE id = $1 AND status IN ($2, $3) AND (registration_deadline IS NULL OR registration_deadline > NOW())',
      [eventId, 'upcoming', 'ongoing']
    );
    
    if (event.rows.length === 0) {
      return res.status(400).json({ error: 'Event not available for registration' });
    }
    
    // Check if user is already registered
    const existingRegistration = await db.query(
      'SELECT * FROM participants WHERE user_id = $1 AND event_id = $2',
      [userId, eventId]
    );
    
    if (existingRegistration.rows.length > 0) {
      return res.status(409).json({ error: 'Already registered for this event' });
    }
    
    // Check if event has reached max participants
    if (event.rows[0].max_participants && 
        event.rows[0].current_participants >= event.rows[0].max_participants) {
      return res.status(400).json({ error: 'Event has reached maximum participants' });
    }
    
    // Register participant
    const { rows } = await db.query(
      `INSERT INTO participants (user_id, event_id, registration_data)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [userId, eventId, registrationData]
    );
    
    // Update participant count
    await db.query(
      'UPDATE events SET current_participants = current_participants + 1 WHERE id = $1',
      [eventId]
    );
    
    res.status(201).json(rows[0]);
  } catch (err) {
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

app.post('/api/events/:id/certificates', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const eventId = req.params.id;
  const { participant_id, pdf_base64, file_name } = req.body;

  console.log('➡️ Certificate Upload Request Received');
  console.log('📌 Event ID:', eventId);
  console.log('📌 Participant ID:', participant_id);
  console.log('📌 File Name:', file_name);
  console.log('📌 PDF Base64 present:', !!pdf_base64);

  if (!pdf_base64) {
    console.warn('⚠️ No PDF data provided');
    return res.status(400).json({ error: 'No PDF data provided' });
  }

  try {
    // Check if participant belongs to the event
    const participantCheck = await db.query(
      'SELECT * FROM participants WHERE id = $1 AND event_id = $2',
      [participant_id, eventId]
    );

    if (participantCheck.rows.length === 0) {
      console.warn('❌ Participant not found or not registered for this event');
      return res.status(400).json({ error: 'Participant not registered for this event' });
    }

    // Generate unique code
    const uniqueCode = crypto.randomBytes(8).toString('hex');
    console.log('🆔 Generated Unique Code:', uniqueCode);

    // Prepare upload payload
    const formData = new URLSearchParams();
    formData.append('fileData', pdf_base64);
    formData.append('fileName', file_name || `certificate_${eventId}_${participant_id}.pdf`);
    formData.append('mimeType', 'application/pdf');
    formData.append('description', `Certificate for event ${eventId}`);

    console.log('📤 Uploading to Google Apps Script...');
    const response = await axios.post(APPSCRIPT_PDF_UPLOAD_URL, formData.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    console.log('✅ Upload Response:', response.data);

    const fileUrl = response.data.fileUrl;
    if (!fileUrl) {
      console.error('❌ No fileUrl returned from Apps Script');
      throw new Error('Google Apps Script did not return a fileUrl');
    }

    // Save certificate record
    const { rows } = await db.query(
      `INSERT INTO certificates (event_id, participant_id, certificate_url, unique_code)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [eventId, participant_id, fileUrl, uniqueCode]
    );

    console.log('✅ Certificate saved to DB:', rows[0]);

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error('🚨 Certificate upload error:', err.message);
    console.error(err.stack);
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
      'SELECT id, name, email, role, created_at, last_login FROM users WHERE id = $1',
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