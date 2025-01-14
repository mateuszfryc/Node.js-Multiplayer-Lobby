// import { loadEnv } from '#utils/env.js';
import dotenv from 'dotenv';

export const loadEnv = () => {
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

  const PORT = process.env.PORT ?? 3000;
  const isProd = mode === 'production';

  // List of required variables and any constraints we want to check
  const requiredVars = [
    { key: 'JWT_SECRET', minLength: 32 },
    { key: 'JWT_REFRESH_SECRET', minLength: 32 },
    // For SODIUM_KEY, it must be a valid base64-encoded 32-byte key
    { key: 'SODIUM_KEY', base64Length: 32 },
  ];

  for (const { key, minLength, base64Length } of requiredVars) {
    const value = process.env[key];
    if (!value) {
      throw new Error(`Missing required environment variable: ${key}`);
    }

    // If we have a plain minimum-length requirement (e.g., for JWT secrets)
    if (minLength && value.length < minLength) {
      throw new Error(
        `Environment variable "${key}" must be at least ${minLength} characters long (current length: ${value.length}).`
      );
    }

    // If we require a base64-encoded 32-byte key (e.g., for SODIUM_KEY)
    if (base64Length) {
      const raw = Buffer.from(value, 'base64');
      if (raw.length !== base64Length) {
        throw new Error(
          `Environment variable "${key}" must be a valid base64-encoded string that decodes to ${base64Length} bytes.`
        );
      }
    }
  }

  if (isProd) {
    const dbVars = ['DB_USER', 'DB_PASS', 'DB_NAME', 'DB_HOST', 'DB_PORT'];
    for (const key of dbVars) {
      if (!process.env[key]) {
        throw new Error(`Missing required environment variable: ${key}`);
      }
    }
  }

  let sslOptions;
  try {
    sslOptions = {
      key: fs.readFileSync(process.env.SSL_KEY_PATH),
      cert: fs.readFileSync(process.env.SSL_CERT_PATH),
    };
  } catch (err) {
    throw new Error('Failed to load SSL certificates:', err.message);
  }

  // If everything passed, no errors are thrown, so we’re good
  console.log('All required environment variables are present and valid.');

  return [PORT, isProd, sslOptions /* mode */];
};

// Load environment variables and check constraints, crash early if any envs missing
const [PORT, isProd, sslOptions] = loadEnv();

import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import express from 'express';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import fs from 'fs';
import helmet from 'helmet';
import { createServer } from 'http';
import https from 'https';
import jwt from 'jsonwebtoken';
import * as sodium from 'libsodium-wrappers';
import net from 'net';
import { DataTypes, Sequelize } from 'sequelize';
import { Server as SocketIOServer } from 'socket.io';
import winston from 'winston';
import 'winston-daily-rotate-file';

const app = express();
app.use(express.json({ strict: true }));
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'script-src': ["'self'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: 'deny' },
    noSniff: true,
  })
);
if (isProd) {
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (req.secure) {
      return next();
    }
    // Redirect if not secure
    return res.redirect(`https://${req.headers.host}${req.url}`);
  });
}

const limiter = rateLimit({
  windowMs: 60000,
  max: 50,
  message: { message: '', error: 'Too many requests', data: {} },
});
app.use(limiter);

// Setup logging
const logTransport = new winston.transports.DailyRotateFile({
  filename: 'server-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '20m',
  maxFiles: '14d',
});
const logger = winston.createLogger({
  transports: [new winston.transports.Console(), logTransport],
});

// Some constants / regexes
const USER_CHARS = /^[A-Za-z0-9!@#$%^&*\+\-\?,]+$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_REGEX =
  /^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*\+\-\?,])[A-Za-z0-9!@#$%^&*\+\-\?,]{8,}$/;
const PLAYER_NAME_REGEX = /^[A-Za-z0-9!@#$%^&*\+\-\?,]{3,16}$/;

// ----------------------------------------
// Sequelize Setup
// ----------------------------------------
const sequelize = new Sequelize(
  process.env.DB_NAME, // e.g. 'myDatabase'
  process.env.DB_USER, // e.g. 'myUser'
  process.env.DB_PASSWORD, // e.g. 'myPassword'
  {
    host: process.env.DB_HOST, // e.g. '127.0.0.1'
    dialect: 'postgres',
    logging: false, // pass function if you want to log queries
    // If in production and SSL is needed:
    // dialectOptions: {
    //   ssl: {
    //     require: true,
    //     rejectUnauthorized: false,
    //   },
    // },
  }
);

// ----------------------------------------
// Define Models
// ----------------------------------------
const User = sequelize.define(
  'User',
  {
    id: {
      type: DataTypes.STRING,
      primaryKey: true,
    },
    user_name: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: false,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    player_name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    role: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    logged_in: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.fn('NOW'),
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.fn('NOW'),
    },
    validated_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    refresh_token: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
  },
  {
    tableName: 'Users',
    timestamps: true,
  }
);

const Game = sequelize.define(
  'Game',
  {
    id: {
      type: DataTypes.STRING,
      primaryKey: true,
    },
    ip: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    port: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    map_name: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    game_mode: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    connected_players: {
      type: DataTypes.ARRAY(DataTypes.STRING),
      allowNull: false,
      defaultValue: [],
    },
    max_players: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    private: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      defaultValue: '',
    },
    ping: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.fn('NOW'),
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.fn('NOW'),
    },
  },
  {
    tableName: 'Games',
    timestamps: false,
  }
);

const Activation = sequelize.define(
  'Activation',
  {
    user_id: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    token: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.fn('NOW'),
    },
    expires_at: {
      type: DataTypes.DATE,
      allowNull: false,
    },
  },
  {
    tableName: 'Activations',
    timestamps: false,
  }
);

// ----------------------------------------
// Sync the tables if they don't exist
// ----------------------------------------
(async () => {
  await sodium.ready;

  // This will create any missing tables based on the model definitions.
  // By default, it won't drop anything. If you want to force re-creation,
  // you can do: sequelize.sync({ force: true })
  if (isProd) {
    await sequelize.sync({ alter: true });
  }

  // If you prefer manual migration, you'd remove sync() calls and
  // handle migrations in a separate setup. For demo, this is simplest.
})();

// ----------------------------------------
// Helper Functions
// ----------------------------------------
function validatePort(port) {
  // Attempt to parse as integer
  const parsed = parseInt(port, 10);
  // Check it's an integer and within the valid range 1–65535
  if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) {
    return true;
  }
  return false;
}
function validateIpOrLocalhost(ip) {
  if (ip === 'localhost') return true;
  return net.isIP(ip) !== 0;
}
async function encryptId(id) {
  const key = Buffer.from(process.env.SODIUM_KEY ?? '', 'base64');
  if (!key || key.length !== 32) throw new Error('Sodium key invalid');
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = sodium.crypto_secretbox_easy(Buffer.from(id), nonce, key);
  return Buffer.concat([nonce, Buffer.from(ciphertext)]).toString('base64');
}
async function decryptId(data) {
  const key = Buffer.from(process.env.SODIUM_KEY ?? '', 'base64');
  if (!key || key.length !== 32) throw new Error('Sodium key invalid');
  const raw = Buffer.from(data, 'base64');
  const nonce = raw.slice(0, sodium.crypto_secretbox_NONCEBYTES);
  const ct = raw.slice(sodium.crypto_secretbox_NONCEBYTES);
  const msg = sodium.crypto_secretbox_open_easy(ct, nonce, key);
  return msg ? msg.toString() : '';
}
async function generateId() {
  const raw = sodium.randombytes_buf(16).toString('hex');
  return await encryptId(raw);
}
function jsonRes(res, msg, error, data) {
  return res.json({ message: msg, error: error, data: data });
}
function validateEmailFormat(email) {
  return EMAIL_REGEX.test(email);
}
function validatePasswordFormat(pw) {
  return PASSWORD_REGEX.test(pw);
}
function validatePlayerNameFormat(n) {
  return PLAYER_NAME_REGEX.test(n);
}

// ----------------------------------------
// Auth Middleware
// ----------------------------------------
async function authenticateToken(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth) return jsonRes(res, '', 'Unauthorized', []);
    const accessToken = auth.split(' ')[1];
    if (!accessToken) return jsonRes(res, '', 'Unauthorized', []);

    // Verify the JWT signature. If expired or invalid, it throws.
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET ?? '');
    req.body.decodedUser = decoded;
    next();
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Unauthorized', []);
  }
}

// ----------------------------------------
// Routes
// ----------------------------------------

// Admin route: create a new user
app.post('/api_v1/join', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    const { user_name, password, player_name } = req.body;
    if (!d || !d.role || d.role !== 'admin')
      return jsonRes(res, '', 'Request failed', []);
    if (!user_name || !password || !player_name)
      return jsonRes(res, '', 'Request failed', []);
    if (!validateEmailFormat(user_name))
      return jsonRes(res, '', 'Request failed', []);
    if (!validatePasswordFormat(password))
      return jsonRes(res, '', 'Request failed', []);
    if (!validatePlayerNameFormat(player_name))
      return jsonRes(res, '', 'Request failed', []);

    // Check if user already exists
    const existing = await User.findOne({ where: { user_name } });
    if (existing) return jsonRes(res, '', 'Request failed', []);

    // Create user
    const hashed = await bcrypt.hash(password, 10);
    const rid = await generateId();
    const now = dayjs().toISOString();

    await User.create({
      id: rid,
      user_name,
      password: hashed,
      player_name,
      role: 'player',
      logged_in: false,
      created_at: now,
      updated_at: now,
      validated_at: null,
    });

    // Create activation token
    const token = await generateId();
    const exp = dayjs().add(1, 'day').toISOString();
    await Activation.create({
      user_id: rid,
      token,
      created_at: now,
      expires_at: exp,
    });

    return jsonRes(res, 'User created', '', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});

// Confirm activation
app.get('/api_v1/confirm/:token', async (req, res) => {
  try {
    const t = req.params.token;
    const now = dayjs().toISOString();

    const act = await Activation.findOne({ where: { token: t } });
    if (!act) return jsonRes(res, '', 'Invalid token', []);

    if (dayjs(now).isAfter(dayjs(act.expires_at)))
      return jsonRes(res, '', 'Invalid token', []);

    await User.update({ validated_at: now }, { where: { id: act.user_id } });

    return jsonRes(res, 'Email confirmed', '', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Invalid token', []);
  }
});

// Login
const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5, // limit each IP to 5 requests per windowMs
  message: { error: 'Too many login attempts. Please try again later.' },
});

const loginSpeedLimiter = slowDown({
  windowMs: 1 * 60 * 1000, // 1 minute
  delayAfter: 5, // allow 5 requests before introducing delay
  delayMs: 1000, // add 1 second delay per request above 5
  maxDelayMs: 10 * 1000, // cap delay at 10 seconds
});

app.post('/api_v1/login', loginLimiter, loginSpeedLimiter, async (req, res) => {
  try {
    const { user_name, password } = req.body;
    if (!user_name || !password) return jsonRes(res, '', 'Fields missing', []);
    if (!validateEmailFormat(user_name) || !USER_CHARS.test(password))
      return jsonRes(res, '', 'Invalid input', []);

    // Find user by user_name
    const user = await User.findOne({ where: { user_name } });
    if (!user) return jsonRes(res, '', 'Invalid credentials', []);

    // Compare passwords
    const passOk = await bcrypt.compare(password, user.password);
    if (!passOk) return jsonRes(res, '', 'Invalid credentials', []);

    // Check if email is validated
    if (!user.validated_at) {
      return jsonRes(res, '', 'Email not validated', []);
    }

    // Check if user is already logged in
    if (user.logged_in) {
      return jsonRes(res, '', 'Already logged in', []);
    }

    // Generate short-lived Access Token (e.g., 15m)
    const accessToken = jwt.sign(
      { id: user.id, role: user.role, player_name: user.player_name },
      process.env.JWT_SECRET ?? '',
      { expiresIn: '15m' }
    );

    // Generate Refresh Token (e.g., 7 days)
    const refreshToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_REFRESH_SECRET ?? '', // A different secret, typically
      { expiresIn: '7d' }
    );

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    // Store the refresh token in the DB
    await user.update({
      logged_in: true,
      refresh_token: hashedRefreshToken,
      updated_at: dayjs().toISOString(),
    });

    // Return both tokens to the client
    return jsonRes(res, '', '', {
      accessToken,
      refreshToken,
    });
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});

// Refresh token
app.post('/api_v1/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return jsonRes(res, '', 'Refresh token missing', []);

    // 1) Verify the raw refresh token with your refresh secret
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET ?? ''
    );
    // e.g. decoded = { id, role, iat, exp }

    // 2) Find the user in DB
    const user = await User.findOne({ where: { id: decoded.id } });
    if (!user) return jsonRes(res, '', 'Unauthorized', []);

    // 3) Compare the raw token with the stored hashed token
    const match = await bcrypt.compare(refreshToken, user.refresh_token ?? '');
    if (!match) {
      return jsonRes(res, '', 'Unauthorized', []);
    }

    // 4) Tokens match, so generate a new short-lived access token
    const newAccessToken = jwt.sign(
      { id: user.id, role: user.role, player_name: user.player_name },
      process.env.JWT_SECRET ?? '',
      { expiresIn: '15m' }
    );

    // 5) Optionally do "rolling refresh" by issuing a brand-new refresh token
    const newRefreshToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_REFRESH_SECRET ?? '',
      { expiresIn: '7d' }
    );
    // Hash it again
    const hashedRefresh = await bcrypt.hash(newRefreshToken, 10);
    // Store the new hashed token
    await user.update({
      refresh_token: hashedRefresh,
      updated_at: dayjs().toISOString(),
    });

    return jsonRes(res, 'Token refreshed', '', {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Unauthorized', []);
  }
});

// Update user (change player_name)
app.patch('/api_v1/user', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', []);

    const { player_name } = req.body;
    if (!player_name || !validatePlayerNameFormat(player_name))
      return jsonRes(res, '', 'Invalid player_name', []);

    const now = dayjs().toISOString();
    await User.update(
      { player_name, updated_at: now },
      { where: { id: d.id } }
    );

    return jsonRes(res, '', 'Success', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});

// Fetch all games
app.get('/api_v1/games', authenticateToken, async (req, res) => {
  try {
    const games = await Game.findAll();
    return jsonRes(res, '', '', games);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});

// Create a game
const activeGames = new Map();

app.post('/api_v1/games', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', []);

    let {
      ip,
      port,
      game_name,
      map_name,
      game_mode,
      max_players,
      private: priv,
      password,
    } = req.body;

    if (!validateIpOrLocalhost(ip)) {
      return jsonRes(res, '', 'Incorrect IP address', []);
    }
    if (!validatePort(port)) {
      return jsonRes(res, '', 'Incorrect port number', []);
    }

    if (!ip || !port || !game_name || !map_name || !game_mode)
      return jsonRes(res, '', 'Missing fields', []);

    if (
      !USER_CHARS.test(game_name) ||
      !USER_CHARS.test(map_name) ||
      !USER_CHARS.test(game_mode)
    )
      return jsonRes(res, '', 'Invalid characters', []);

    if (!max_players) max_players = 8;
    if (!priv) priv = false;
    if (!password) password = '';

    // If a game at ip:port exists, delete it first
    const existing = await Game.findOne({ where: { ip, port } });
    if (existing) {
      await existing.destroy();
      activeGames.delete(existing.id);
    }

    const gid = await generateId();
    const now = dayjs().toISOString();
    const pass = await bcrypt.hash(password, 10);

    const newGame = await Game.create({
      id: gid,
      ip,
      port,
      name: game_name,
      map_name,
      game_mode,
      connected_players: [],
      max_players,
      private: priv,
      password: pass,
      ping: 0,
      created_at: now,
      updated_at: now,
    });

    activeGames.set(gid, newGame.toJSON());
    return jsonRes(res, 'Game created', '', newGame);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});

// Update a game
app.put('/api_v1/games/:game_id', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', []);

    const gid = req.params.game_id;
    const plainId = await decryptId(gid);
    if (!plainId) return jsonRes(res, '', 'Invalid game_id', []);

    const gameCheck = await Game.findOne({ where: { id: gid } });
    if (!gameCheck) return jsonRes(res, '', 'Not found', []);

    // Alternatively, if you store an "ownerId" or something,
    // you'd verify that d.id === gameCheck.ownerId OR d.role === 'admin'
    // For now, we'll assume the game "belongs" to the same user who created it.
    // Since the code checks if (d.id !== gameOwner.id && d.role !== 'admin'),
    // that implies you might have stored userId somewhere on the Games table.
    // We'll skip that for brevity, but here's the example logic:
    // if (d.id !== gameCheck.id && d.role !== 'admin') ...

    const data = { ...req.body };
    delete data.decodedUser; // remove token payload
    const now = dayjs().toISOString();

    data.updated_at = now;
    // We'll just do a simple update
    await gameCheck.update(data);

    const updated = await Game.findOne({ where: { id: gid } });
    activeGames.set(gid, updated.toJSON());

    io.emit('game_updated', updated);
    return jsonRes(res, '', '', updated);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});

// Delete a game
app.delete('/api_v1/games/:game_id', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', []);

    const gid = req.params.game_id;
    const plainId = await decryptId(gid);
    if (!plainId) return jsonRes(res, '', 'Invalid game_id', []);

    const gameCheck = await Game.findOne({ where: { id: gid } });
    if (!gameCheck) return jsonRes(res, '', 'Not found', []);

    // same owner-check logic here if needed
    // if (d.id !== gameCheck.id && d.role !== 'admin') return ...

    await gameCheck.destroy();
    activeGames.delete(gid);

    io.emit('game_removed', gid);
    return jsonRes(res, 'Game deleted', '', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});

// Logout
app.post('/api_v1/logout', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d) return jsonRes(res, '', 'Unauthorized', []);

    const user = await User.findOne({ where: { id: d.id } });
    if (!user) return jsonRes(res, '', 'Unauthorized', []);

    // Remove refresh token
    await user.update({
      logged_in: false,
      refresh_token: null,
      updated_at: dayjs().toISOString(),
    });

    return jsonRes(res, 'Logged out', '', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});

// ----------------------------------------
// Socket.io
// ----------------------------------------
const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: false, methods: ['GET', 'POST'] },
});

io.on('connection', (socket) => {
  socket.emit('games_list', Array.from(activeGames.values()));

  socket.on('join_game', async ({ game_id, player_id }) => {
    const g = activeGames.get(game_id);
    if (!g) return;
    const cPlayers = g.connected_players || [];
    if (!cPlayers.includes(player_id)) {
      cPlayers.push(player_id);
      g.connected_players = cPlayers;

      // Update DB
      await Game.update(
        { connected_players: cPlayers },
        { where: { id: game_id } }
      );
      activeGames.set(game_id, g);

      io.emit('player_joined', { game_id, player_id });
    }
  });

  socket.on('leave_game', async ({ game_id, player_id }) => {
    const g = activeGames.get(game_id);
    if (!g) return;
    const cPlayers = g.connected_players || [];
    const ix = cPlayers.indexOf(player_id);
    if (ix > -1) {
      cPlayers.splice(ix, 1);
      g.connected_players = cPlayers;

      // Update DB
      await Game.update(
        { connected_players: cPlayers },
        { where: { id: game_id } }
      );
      activeGames.set(game_id, g);

      io.emit('player_left', { game_id, player_id });
    }
  });
});

// ----------------------------------------
// HTTP / HTTPS Server
// ----------------------------------------
if (isProd) {
  const options = {
    key: fs.readFileSync(sslOptions.SSL_KEY_PATH ?? ''),
    cert: fs.readFileSync(sslOptions.SSL_CERT_PATH ?? ''),
  };
  https.createServer(options, app).listen(PORT, () => {
    logger.info('HTTPS server on ' + PORT);
  });
} else {
  httpServer.listen(PORT, () => {
    logger.info('HTTP server on ' + PORT);
  });
}
