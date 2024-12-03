import bcrypt from 'bcrypt';
import bodyParser from 'body-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import pg from 'pg';

let mode = null;
if (process.env.NODE_ENV == 'production') {
  dotenv.config({ path: '.env.prod.db' });
  dotenv.config({ path: '.env.prod.auth' });
  mode = 'production';
}
if (process.env.NODE_ENV == 'development') {
  dotenv.config({ path: '.env.db' });
  dotenv.config({ path: '.env.auth' });
  mode = 'development';
}
if (mode === null) {
  throw new Error('Error: NODE_ENV not set');
}

const is_prod = mode === 'production';

console.log(`Running in "${mode}" mode`);

const app = express();
// Store revoked JWT tokens
const denylist = new Set();

// Set up Helmet for security headers
app.use(helmet());

// Enable CORS for trusted origins
app.use(cors({ origin: 'https://yourgame.com' }));

if (is_prod) {
  app.set('trust proxy', 1); // Trust the first proxy
}

// Apply rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Middleware
app.use(bodyParser.json());

// PostgreSQL connection pool
const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
  ssl: is_prod
    ? {
        rejectUnauthorized: false,
      }
    : false,
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  const err = 'Token is invalid, revoked or expired.';

  if (!token) {
    return res.status(401).json({ error: err });
  }

  // Check if the token is in the denylist
  if (denylist.has(token)) {
    return res.status(403).json({ error: err });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ error: err });
  }
};

app.get('/', (req, res) => {
  res.status(200).send('Ready.');
});

app.get('/test_auth', authenticateToken, (req, res) => {
  res.status(200).json({
    message: 'Access granted to protected route',
    user: req.user, // Contains user data from the token
  });
});

// Route to handle login requests
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      console.log(`Invalid email: ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      console.log(`Invalid password: ${password}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate a JWT token
    const token = jwt.sign(
      { id: user.id, display_name: user.display_name }, // Payload
      process.env.JWT_SECRET, // Secret key
      { expiresIn: process.env.JWT_EXPIRATION } // Token expiration
    );

    res.status(200).json({
      message: 'Login successful',
      token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/logout', authenticateToken, (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];

  // Add the token to the denylist
  denylist.add(token);

  res.status(200).json({ message: 'Logged out successfully' });
});

const PORT = process.env.PORT || 3000;

// Start the server
app.listen(PORT, () => {
  console.log('Server is running on port 3000');
});
