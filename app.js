// ============================================
// COLLEGE DE BETHEL - NEWS MANAGEMENT SYSTEM
// Complete Backend API - Single File
// ============================================

const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sanitizeHtml = require('sanitize-html');


// Initialize Express
const app = express();

// ============================================
// CONFIGURATION
// ============================================

const CONFIG = {
  PORT: process.env.PORT || 5000,
  DB_HOST: process.env.DB_HOST || 'localhost',
  DB_USER: process.env.DB_USER || 'root',
  DB_PASSWORD: process.env.DB_PASSWORD || '',
  DB_NAME: process.env.DB_NAME || 'college_bethel_new',
  JWT_SECRET: process.env.JWT_SECRET || 'college-bethel-secret-key-2026',
  JWT_EXPIRE: '7d',
  UPLOAD_DIR: path.join(__dirname, 'uploads'),
  MAX_FILE_SIZE: 5 * 1024 * 1024, // 5MB
};

// Create uploads directory if it doesn't exist
if (!fs.existsSync(CONFIG.UPLOAD_DIR)) {
  fs.mkdirSync(CONFIG.UPLOAD_DIR, { recursive: true });
}

// ============================================
// DATABASE CONNECTION
// ============================================

const pool = mysql.createPool({
  host: CONFIG.DB_HOST,
  user: CONFIG.DB_USER,
  password: CONFIG.DB_PASSWORD,
  database: CONFIG.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Test database connection
pool.getConnection()
  .then(connection => {
    console.log('✅ Database connected successfully');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
  });

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(CONFIG.UPLOAD_DIR));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ============================================
// FILE UPLOAD CONFIGURATION
// ============================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, CONFIG.UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'news-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: CONFIG.MAX_FILE_SIZE },
  fileFilter: fileFilter
});

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    jwt.verify(token, CONFIG.JWT_SECRET, async (err, decoded) => {
      if (err) {
        return res.status(403).json({
          success: false,
          message: 'Invalid or expired token'
        });
      }

      // Get user from database
      const [users] = await pool.execute(
        'SELECT id, username, email, full_name, role FROM admin_users WHERE id = ?',
        [decoded.userId]
      );

      if (users.length === 0) {
        return res.status(403).json({
          success: false,
          message: 'User not found'
        });
      }

      req.user = users[0];
      next();
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Authentication error',
      error: error.message
    });
  }
};

// ============================================
// HELPER FUNCTIONS
// ============================================

// Generate slug from title
const generateSlug = (title) => {
  return title
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/--+/g, '-')
    .trim();
};

// Format date for MySQL
const formatDateForMySQL = (date) => {
  if (!date) return null;
  const d = new Date(date);
  return d.toISOString().slice(0, 19).replace('T', ' ');
};

// ============================================
// AUTH ROUTES
// ============================================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    // Get user
    const [users] = await pool.execute(
      'SELECT * FROM admin_users WHERE username = ? OR email = ?',
      [username, username]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const user = users[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Update last login
    await pool.execute(
      'UPDATE admin_users SET last_login = NOW() WHERE id = ?',
      [user.id]
    );

    // Generate token
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      CONFIG.JWT_SECRET,
      { expiresIn: CONFIG.JWT_EXPIRE }
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          full_name: user.full_name,
          role: user.role
        }
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: error.message
    });
  }
});

// Register new user (Protected - Only admins can create users)
app.post('/api/auth/register', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only administrators can create new users'
      });
    }

    const { username, email, password, full_name, role } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username, email, and password are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    // Check if username already exists
    const [existingUsername] = await pool.execute(
      'SELECT id FROM admin_users WHERE username = ?',
      [username]
    );

    if (existingUsername.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Username already exists'
      });
    }

    // Check if email already exists
    const [existingEmail] = await pool.execute(
      'SELECT id FROM admin_users WHERE email = ?',
      [email]
    );

    if (existingEmail.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Email already exists'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    const query = `
      INSERT INTO admin_users (username, email, password, full_name, role)
      VALUES (?, ?, ?, ?, ?)
    `;

    const [result] = await pool.execute(query, [
      username,
      email,
      hashedPassword,
      full_name || username,
      role || 'editor'
    ]);

    // Get created user (without password)
    const [newUser] = await pool.execute(
      'SELECT id, username, email, full_name, role, created_at FROM admin_users WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: newUser[0]
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed',
      error: error.message
    });
  }
});

// Get all users (Protected - Admin only)
app.get('/api/auth/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only administrators can view users'
      });
    }

    const [users] = await pool.execute(`
      SELECT 
        id, 
        username, 
        email, 
        full_name, 
        role, 
        last_login,
        created_at,
        updated_at
      FROM admin_users
      ORDER BY created_at DESC
    `);

    res.json({
      success: true,
      data: users
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users',
      error: error.message
    });
  }
});

// Delete user (Protected - Admin only)
app.delete('/api/auth/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only administrators can delete users'
      });
    }

    const { id } = req.params;

    // Prevent deleting self
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({
        success: false,
        message: 'You cannot delete your own account'
      });
    }

    // Check if user exists
    const [user] = await pool.execute('SELECT id FROM admin_users WHERE id = ?', [id]);

    if (user.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Delete user
    await pool.execute('DELETE FROM admin_users WHERE id = ?', [id]);

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete user',
      error: error.message
    });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({
    success: true,
    data: req.user
  });
});

// ============================================
// NEWS ROUTES
// ============================================

// Get all news (with filters, pagination)
app.get('/api/news', async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      status,
      category,
      search,
      sort = 'latest'
    } = req.query;

    const offset = (page - 1) * limit;
    let conditions = [];
    let params = [];

    // Build WHERE conditions
    if (status) {
      conditions.push('n.status = ?');
      params.push(status);
    }

    if (category) {
      conditions.push('c.slug = ?');
      params.push(category);
    }

    if (search) {
      conditions.push('(n.title LIKE ? OR n.excerpt LIKE ? OR n.content LIKE ?)');
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

    // Determine sort order
    let orderBy = 'n.created_at DESC';
    if (sort === 'latest') orderBy = 'n.published_date DESC, n.created_at DESC';
    if (sort === 'oldest') orderBy = 'n.published_date ASC, n.created_at ASC';
    if (sort === 'popular') orderBy = 'n.views DESC';
    if (sort === 'title') orderBy = 'n.title ASC';

    // Get news
    const query = `
      SELECT 
        n.id,
        n.title,
        n.slug,
        n.excerpt,
        n.image,
        n.status,
        n.published_date,
        n.views,
        n.author,
        n.created_at,
        n.updated_at,
        c.id as category_id,
        c.name as category,
        c.slug as category_slug
      FROM news n
      LEFT JOIN categories c ON n.category_id = c.id
      ${whereClause}
      ORDER BY ${orderBy}
      LIMIT ? OFFSET ?
    `;

    params.push(parseInt(limit), offset);

    const [news] = await pool.execute(query, params);

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM news n
      LEFT JOIN categories c ON n.category_id = c.id
      ${whereClause}
    `;

    const [countResult] = await pool.execute(
      countQuery,
      params.slice(0, -2) // Remove limit and offset
    );

    const total = countResult[0].total;

    res.json({
      success: true,
      data: news,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / limit),
        hasMore: offset + news.length < total
      }
    });
  } catch (error) {
    console.error('Get news error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch news',
      error: error.message
    });
  }
});

// ============================================
// IMPORTANT: Single combined route for GET /api/news/:identifier
// Handles BOTH numeric IDs and slugs — do NOT add a second route for this path!
// ============================================
app.get('/api/news/:identifier', async (req, res) => {
  try {
    const { identifier } = req.params;

    const query = `
      SELECT 
        n.*,
        c.id as category_id,
        c.name as category,
        c.slug as category_slug
      FROM news n
      LEFT JOIN categories c ON n.category_id = c.id
      WHERE n.id = ? OR n.slug = ?
    `;

    const [news] = await pool.execute(query, [identifier, identifier]);

    if (news.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Article not found'
      });
    }

    let article = news[0];

    // Fix relative image paths in content
    if (article.content) {
      article.content = article.content.replace(
        /src="(?!http)([^"]+)"/g,
        (match, p1) => {
         return `src="${process.env.BASE_URL}/${p1.replace(/^\/?/, '')}"`;
        }
      );
    }

    // Increment view count
    await pool.execute('UPDATE news SET views = views + 1 WHERE id = ?', [article.id]);

    res.json({
      success: true,
      data: article
    });
  } catch (error) {
    console.error('Get news by identifier error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch article',
      error: error.message
    });
  }
});

// Create news (Protected)
app.post('/api/news', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const {
      title,
      excerpt,
      content,
      category_id,
      status,
      published_date
    } = req.body;

    if (!title || !category_id) {
      return res.status(400).json({
        success: false,
        message: 'Title and category are required'
      });
    }

    const slug = generateSlug(title);

    const cleanContent = sanitizeHtml(content || '', {
      allowedTags: [
        'p','b','i','em','strong',
        'h2','h3','h4',
        'ul','ol','li',
        'a','img','figure','figcaption','blockquote'
      ],
      allowedAttributes: {
        a: ['href','target'],
        img: ['src','alt'],
        figure: ['class']
      },
      allowedSchemes: ['http','https']
    });

    let imagePath = null;

    if (req.file) {
      imagePath = `/uploads/${req.file.filename}`;
    } else if (req.body.image) {
      imagePath = req.body.image;
    }

    const query = `
      INSERT INTO news
      (title, slug, excerpt, content, category_id, image, status, published_date, author_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const [result] = await pool.execute(query, [
      title,
      slug,
      excerpt || '',
      cleanContent,
      category_id,
      imagePath,
      status || 'draft',
      formatDateForMySQL(published_date),
      req.user.id
    ]);

    res.status(201).json({
      success: true,
      message: 'Article created successfully',
      id: result.insertId
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Failed to create article'
    });
  }
});

// Update news (Protected)
app.put('/api/news/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;

    const {
      title,
      excerpt,
      content,
      category_id,
      status,
      published_date
    } = req.body;

    const slug = generateSlug(title);

    const cleanContent = sanitizeHtml(content || '', {
      allowedTags: [
        'p','b','i','em','strong',
        'h2','h3','h4',
        'ul','ol','li',
        'a','img','figure','figcaption','blockquote'
      ],
      allowedAttributes: {
        a: ['href','target'],
        img: ['src','alt'],
        figure: ['class']
      },
      allowedSchemes: ['http','https']
    });

    let imagePath = req.body.image || null;

    if (req.file) {
      imagePath = `/uploads/${req.file.filename}`;
    }

    const query = `
      UPDATE news
      SET title=?, slug=?, excerpt=?, content=?, category_id=?, image=?, status=?, published_date=?
      WHERE id=?
    `;

    await pool.execute(query, [
      title,
      slug,
      excerpt || '',
      cleanContent,
      category_id,
      imagePath,
      status,
      formatDateForMySQL(published_date),
      id
    ]);

    res.json({
      success: true,
      message: 'Article updated successfully'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to update article'
    });
  }
});

// Delete news (Protected)
app.delete('/api/news/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Get news to delete image
    const [news] = await pool.execute('SELECT image FROM news WHERE id = ?', [id]);

    if (news.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'News not found'
      });
    }

    // Delete image file
    if (news[0].image) {
      const imagePath = path.join(__dirname, news[0].image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }

    // Delete news
    await pool.execute('DELETE FROM news WHERE id = ?', [id]);

    res.json({
      success: true,
      message: 'News deleted successfully'
    });
  } catch (error) {
    console.error('Delete news error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete news',
      error: error.message
    });
  }
});

// ============================================
// CATEGORIES ROUTES
// ============================================

// Get all categories
app.get('/api/categories', async (req, res) => {
  try {
    const [categories] = await pool.execute(`
      SELECT 
        c.id,
        c.name,
        c.slug,
        COUNT(n.id) as news_count
      FROM categories c
      LEFT JOIN news n ON n.category_id = c.id
      GROUP BY c.id
      ORDER BY c.name ASC
    `);

    res.json({
      success: true,
      data: categories
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch categories'
    });
  }
});

// Create category (Protected)
app.post('/api/categories', authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({
        success: false,
        message: 'Category name is required'
      });
    }

    const slug = generateSlug(name);

    const query = 'INSERT INTO categories (name, slug, description) VALUES (?, ?, ?)';
    const [result] = await pool.execute(query, [name, slug, description]);

    const [created] = await pool.execute('SELECT * FROM categories WHERE id = ?', [result.insertId]);

    res.status(201).json({
      success: true,
      message: 'Category created successfully',
      data: created[0]
    });
  } catch (error) {
    console.error('Create category error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create category',
      error: error.message
    });
  }
});

// ============================================
// DASHBOARD STATS ROUTES
// ============================================

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const [newsStats] = await pool.execute(`
      SELECT 
        COUNT(*) as total_news,
        SUM(CASE WHEN status = 'published' THEN 1 ELSE 0 END) as published_count,
        SUM(CASE WHEN status = 'draft' THEN 1 ELSE 0 END) as draft_count,
        SUM(views) as total_views,
        AVG(views) as avg_views
      FROM news
    `);

    const [categoryStats] = await pool.execute(`
      SELECT 
        c.id,
        c.name,
        c.slug,
        COUNT(n.id) as news_count,
        SUM(n.views) as total_views
      FROM categories c
      LEFT JOIN news n ON c.id = n.category_id
      GROUP BY c.id, c.name, c.slug
      ORDER BY news_count DESC
    `);

    const [recentNews] = await pool.execute(`
      SELECT id, title, status, views, created_at
      FROM news
      ORDER BY created_at DESC
      LIMIT 5
    `);

    const [popularNews] = await pool.execute(`
      SELECT id, title, views, published_date
      FROM news
      WHERE status = 'published'
      ORDER BY views DESC
      LIMIT 5
    `);

    const [monthlyStats] = await pool.execute(`
      SELECT 
        DATE_FORMAT(created_at, '%Y-%m') as month,
        COUNT(*) as count
      FROM news
      WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
      GROUP BY DATE_FORMAT(created_at, '%Y-%m')
      ORDER BY month DESC
    `);

    res.json({
      success: true,
      data: {
        overview: newsStats[0],
        categories: categoryStats,
        recentNews,
        popularNews,
        monthlyStats
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch statistics',
      error: error.message
    });
  }
});

// ============================================
// UTILITY ROUTES
// ============================================

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString()
  });
});

app.post('/api/upload', authenticateToken, upload.single('image'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    const imageUrl = `/uploads/${req.file.filename}`;

    res.json({
      success: true,
      url: `${process.env.BASE_URL}${imageUrl}`
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Upload failed',
      error: error.message
    });
  }
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

// ============================================
// START SERVER
// ============================================

app.listen(CONFIG.PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════╗
║                                               ║
║   🎓 COLLEGE DE BETHEL NEWS SYSTEM API       ║
║                                               ║
║   Server running on port ${CONFIG.PORT}               ║
API URL: ${process.env.BASE_URL || `http://localhost:${CONFIG.PORT}`}/api      ║
║                                               ║
╚═══════════════════════════════════════════════╝
  `);
});

module.exports = app;
