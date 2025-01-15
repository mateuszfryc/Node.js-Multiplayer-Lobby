import dotenv from 'dotenv';

const loadEnv = (envDefinitions) => {
  const envs = {};
  const isProd = process.env.NODE_ENV === 'production';

  if (isProd) {
    dotenv.config({ path: '.env.prod.db' });
    dotenv.config({ path: '.env.prod.auth' });
  } //
  else {
    dotenv.config({ path: '.env.db' });
    dotenv.config({ path: '.env.auth' });
  }

  const parseBoolean = (value) => {
    if (value === 'true') return true;
    if (value === 'false') return false;
    throw new Error(
      `Invalid boolean value: "${value}". Expected "true" or "false".`
    );
  };

  for (const {
    key,
    minLength,
    base64Length,
    filePath,
    type,
  } of envDefinitions) {
    const value = process.env[key];

    if (!value) {
      throw new Error(`Missing required environment variable: ${key}`);
    }

    if (minLength && value.length < minLength) {
      throw new Error(
        `Environment variable "${key}" must be at least ${minLength} characters long (current length: ${value.length}).`
      );
    }

    if (base64Length && value) {
      const raw = Buffer.from(value, 'base64');
      if (raw.length !== base64Length) {
        throw new Error(
          `Environment variable "${key}" must be a valid base64-encoded string that decodes to ${base64Length} bytes.`
        );
      }
    }

    if (filePath && value) {
      try {
        fs.accessSync(value, fs.constants.R_OK);
      } catch {
        throw new Error(
          `File specified in environment variable "${key}" does not exist or is not readable: ${value}`
        );
      }
    }

    switch (type) {
      case 'bool':
        envs[key] = parseBoolean(value);
        break;
      case 'number':
        const numericValue = Number(value);
        if (isNaN(numericValue)) {
          throw new Error(
            `Environment variable "${key}" must be a valid number.`
          );
        }
        envs[key] = numericValue;
        break;
      default:
        envs[key] = value;

      // console.log(`Loaded environment variable: ${key}, value: ${value}`);
    }
  }

  console.log('All required environment variables are present and valid.');

  return [envs, isProd];
};

const [ENVS, isProd] = loadEnv([
  { key: 'PORT' /*, type: 'number' */ },
  { key: 'JWT_SECRET', minLength: 32 },
  { key: 'JWT_REFRESH_SECRET', minLength: 32 },
  { key: 'SODIUM_KEY', base64Length: 32 },
  { key: 'DB_USER' },
  { key: 'DB_PASSWORD' },
  { key: 'DB_NAME' },
  { key: 'DB_HOST' },
  { key: 'DB_PORT', type: 'number' },
  { key: 'SSL_KEY_PATH' /*, filePath: true */ },
  { key: 'SSL_CERT_PATH' /*, filePath: true */ },
  { key: 'USE_SSL', type: 'bool' },
  { key: 'SMTP_HOST' },
  { key: 'FROM_EMAIL' },
  { key: 'SMTP_USER' },
  { key: 'SMTP_PASS' },
]);

let sslOptions;
if (ENVS.USE_SSL === 'true') {
  try {
    sslOptions = {
      key: fs.readFileSync(process.env.SSL_KEY_PATH),
      cert: fs.readFileSync(process.env.SSL_CERT_PATH),
    };
  } catch (err) {
    throw new Error(`Failed to load SSL certificates: ${err.message}`);
  }
}

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
import nodemailer from 'nodemailer';
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
  filename: './.logs/lobby-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '20m',
  maxFiles: '14d',
});
const logger = winston.createLogger({
  transports: [new winston.transports.Console(), logTransport],
});

// ----------------------------------------
// Some constants / regexes
// ----------------------------------------
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
    protocol: 'postgres',
    logging: isProd ? false : console.log, // pass function if you want to log queries
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false, // Heroku's SSL requires this
      },
    },
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
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535;
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

function jsonRes(res, msg, error, data, status = 200) {
  return res.status(status).json({ message: msg, error, data });
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
    if (!auth) return jsonRes(res, '', 'Unauthorized', [], 401);
    const accessToken = auth.split(' ')[1];
    if (!accessToken) return jsonRes(res, '', 'Unauthorized', [], 401);

    // Verify the JWT signature. If expired or invalid, it throws.
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET ?? '');
    req.body.decodedUser = decoded;
    next();
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Unauthorized', [], 401);
  }
}

// ----------------------------------------
// Routes
// ----------------------------------------

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST, // e.g. 'smtp.gmail.com'
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: false, // true if port is 465, otherwise false
  auth: {
    user: ENVS.SMTP_USER, // email address
    pass: ENVS.SMTP_PASS,
  },
});

// Admin route: create a new user
app.post('/api_v1/join', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    const { user_name, password, player_name } = req.body;
    if (!d || !d.role || d.role !== 'admin')
      return jsonRes(res, '', 'Request failed', [], 400);
    if (!user_name || !password || !player_name)
      return jsonRes(res, '', 'Request failed', [], 400);
    if (!validateEmailFormat(user_name))
      return jsonRes(res, '', 'Request failed', [], 400);
    if (!validatePasswordFormat(password))
      return jsonRes(res, '', 'Request failed', [], 400);
    if (!validatePlayerNameFormat(player_name))
      return jsonRes(res, '', 'Request failed', [], 400);

    // Check if user already exists
    const existing = await User.findOne({ where: { user_name } });
    if (existing) return jsonRes(res, '', 'Request failed', [], 400);

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

    try {
      const verificationLink = `${isProd ? 'https' : 'http'}://${
        req.headers.host
      }/api_v1/confirm/${token}`;

      await transporter.sendMail({
        from: ENVS.FROM_EMAIL,
        to: user_name,
        subject: 'Please Confirm Your Email',
        text: `Hello! Confirm your email by visiting: ${verificationLink}`,
        html: `
          <p>Hello!</p>
          <p>Please confirm your email by clicking the link below:</p>
          <p><a href="${verificationLink}">${verificationLink}</a></p>
        `,
      });
    } catch (emailError) {
      logger.error('Failed to send verification email:', emailError);
    }

    return jsonRes(res, 'User created', '', {}, 201);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

// Confirm activation
app.get('/api_v1/confirm/:token', async (req, res) => {
  try {
    const t = req.params.token;
    const now = dayjs().toISOString();

    const act = await Activation.findOne({ where: { token: t } });
    if (!act) return jsonRes(res, '', 'Invalid token', [], 404);

    if (dayjs(now).isAfter(dayjs(act.expires_at)))
      return jsonRes(res, '', 'Invalid token', [], 400);

    await User.update({ validated_at: now }, { where: { id: act.user_id } });

    return jsonRes(res, 'Email confirmed', '', {}, 200);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Invalid token', [], 500);
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
  delayMs: () => 1000, // fixed delay of 1 second per request after limit
  maxDelayMs: 10 * 1000, // cap delay at 10 seconds
});

app.post('/api_v1/login', loginLimiter, loginSpeedLimiter, async (req, res) => {
  try {
    const { user_name, password } = req.body;
    if (!user_name || !password)
      return jsonRes(res, '', 'Fields missing', [], 400);
    if (!validateEmailFormat(user_name) || !USER_CHARS.test(password))
      return jsonRes(res, '', 'Invalid input', [], 400);

    // Find user by user_name
    const user = await User.findOne({ where: { user_name } });
    if (!user) return jsonRes(res, '', 'Invalid credentials', [], 401);

    // Compare passwords
    const passOk = await bcrypt.compare(password, user.password);
    if (!passOk) return jsonRes(res, '', 'Invalid credentials', [], 401);

    // Check if email is validated
    if (!user.validated_at) {
      return jsonRes(res, '', 'Email not validated', [], 403);
    }

    // Check if user is already logged in
    if (user.logged_in) {
      return jsonRes(res, '', 'Already logged in', [], 409);
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
    return jsonRes(
      res,
      '',
      '',
      {
        accessToken,
        refreshToken,
      },
      200
    );
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

// Refresh token
app.post('/api_v1/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return jsonRes(res, '', 'Refresh token missing', [], 400);

    // 1) Verify the raw refresh token with your refresh secret
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET ?? ''
    );
    // e.g. decoded = { id, role, iat, exp }

    // 2) Find the user in DB
    const user = await User.findOne({ where: { id: decoded.id } });
    if (!user) return jsonRes(res, '', 'Unauthorized', [], 401);

    // 3) Compare the raw token with the stored hashed token
    const match = await bcrypt.compare(refreshToken, user.refresh_token ?? '');
    if (!match) {
      return jsonRes(res, '', 'Unauthorized', [], 401);
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

    return jsonRes(
      res,
      'Token refreshed',
      '',
      {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      },
      200
    );
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Unauthorized', [], 401);
  }
});

// Update user (change player_name)
app.patch('/api_v1/user', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', [], 401);

    const { player_name } = req.body;
    if (!player_name || !validatePlayerNameFormat(player_name))
      return jsonRes(res, '', 'Invalid player_name', [], 400);

    const now = dayjs().toISOString();
    await User.update(
      { player_name, updated_at: now },
      { where: { id: d.id } }
    );

    return jsonRes(res, '', 'Success', {}, 200);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

// ----------------------------------------
// Games CRUD
// ----------------------------------------
const activeGames = new Map();

// Fetch all games
app.get('/api_v1/games', authenticateToken, async (req, res) => {
  try {
    const games = await Game.findAll();
    return jsonRes(res, '', '', games, 200);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

// Create a game
app.post('/api_v1/games', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', [], 401);

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

    if (!ip || !port || !game_name || !map_name || !game_mode)
      return jsonRes(res, '', 'Missing fields', [], 400);

    if (!validateIpOrLocalhost(ip)) {
      return jsonRes(res, '', 'Incorrect IP address', [], 400);
    }
    if (!validatePort(port)) {
      return jsonRes(res, '', 'Incorrect port number', [], 400);
    }
    if (
      !USER_CHARS.test(game_name) ||
      !USER_CHARS.test(map_name) ||
      !USER_CHARS.test(game_mode)
    )
      return jsonRes(res, '', 'Invalid characters', [], 400);

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

    // Notify lobby via Socket.io
    // 1) game_created
    // 2) updated full games_list
    io.emit('game_created', newGame);
    io.emit('games_list', Array.from(activeGames.values()));

    return jsonRes(res, 'Game created', '', newGame, 201);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

// Update a game
app.put('/api_v1/games/:game_id', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', [], 401);

    const gid = req.params.game_id;
    const plainId = await decryptId(gid);
    if (!plainId) return jsonRes(res, '', 'Invalid game_id', [], 400);

    const gameCheck = await Game.findOne({ where: { id: gid } });
    if (!gameCheck) return jsonRes(res, '', 'Not found', [], 404);

    const data = { ...req.body };
    delete data.decodedUser; // remove token payload
    const now = dayjs().toISOString();

    data.updated_at = now;
    await gameCheck.update(data);

    const updated = await Game.findOne({ where: { id: gid } });
    activeGames.set(gid, updated.toJSON());

    // Notify lobby
    io.emit('game_updated', updated);
    io.emit('games_list', Array.from(activeGames.values()));

    return jsonRes(res, '', '', updated, 200);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

// Delete a game
app.delete('/api_v1/games/:game_id', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', [], 401);

    const gid = req.params.game_id;
    const plainId = await decryptId(gid);
    if (!plainId) return jsonRes(res, '', 'Invalid game_id', [], 400);

    const gameCheck = await Game.findOne({ where: { id: gid } });
    if (!gameCheck) return jsonRes(res, '', 'Not found', [], 404);

    await gameCheck.destroy();
    activeGames.delete(gid);

    // Notify lobby
    io.emit('game_removed', gid);
    io.emit('games_list', Array.from(activeGames.values()));

    return jsonRes(res, 'Game deleted', '', {}, 200);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

// ----------------------------------------
// New REST endpoints: join or leave a game
// ----------------------------------------
app.post('/api_v1/games/:game_id/join', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', [], 401);

    const gid = req.params.game_id;
    const plainId = await decryptId(gid);
    if (!plainId) return jsonRes(res, '', 'Invalid game_id', [], 400);

    const g = activeGames.get(gid);
    if (!g) return jsonRes(res, '', 'Game not found', [], 404);

    const cPlayers = g.connected_players || [];
    if (!cPlayers.includes(d.id)) {
      cPlayers.push(d.id);
      g.connected_players = cPlayers;

      // Update DB
      await Game.update(
        { connected_players: cPlayers },
        { where: { id: gid } }
      );
      activeGames.set(gid, g);

      // Notify via Socket.io
      io.emit('player_joined', { game_id: gid, player_id: d.id });
      io.emit('games_list', Array.from(activeGames.values()));
    }

    return jsonRes(
      res,
      'Joined game',
      '',
      { game_id: gid, player_id: d.id },
      200
    );
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.post(
  '/api_v1/games/:game_id/leave',
  authenticateToken,
  async (req, res) => {
    try {
      const d = req.body.decodedUser;
      if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', [], 401);

      const gid = req.params.game_id;
      const plainId = await decryptId(gid);
      if (!plainId) return jsonRes(res, '', 'Invalid game_id', [], 400);

      const g = activeGames.get(gid);
      if (!g) return jsonRes(res, '', 'Game not found', [], 404);

      const cPlayers = g.connected_players || [];
      const ix = cPlayers.indexOf(d.id);
      if (ix > -1) {
        cPlayers.splice(ix, 1);
        g.connected_players = cPlayers;

        // Update DB
        await Game.update(
          { connected_players: cPlayers },
          { where: { id: gid } }
        );
        activeGames.set(gid, g);

        // Notify via Socket.io
        io.emit('player_left', { game_id: gid, player_id: d.id });
        io.emit('games_list', Array.from(activeGames.values()));
      }

      return jsonRes(
        res,
        'Left game',
        '',
        { game_id: gid, player_id: d.id },
        200
      );
    } catch (e) {
      logger.error(e);
      return jsonRes(res, '', 'Server error', [], 500);
    }
  }
);

// Logout
app.post('/api_v1/logout', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d) return jsonRes(res, '', 'Unauthorized', [], 401);

    const user = await User.findOne({ where: { id: d.id } });
    if (!user) return jsonRes(res, '', 'Unauthorized', [], 401);

    await user.update({
      logged_in: false,
      refresh_token: null,
      updated_at: dayjs().toISOString(),
    });

    return jsonRes(res, 'Logged out', '', {}, 200);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', [], 500);
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
  // Send all current active games to the newly connected socket
  socket.emit('games_list', Array.from(activeGames.values()));

  // The following Socket.io event handlers remain if you still want
  // to support real-time joins/leaves through sockets.
  // (Now you also have REST endpoints for them.)
  socket.on('join_game', async ({ game_id, player_id }) => {
    const g = activeGames.get(game_id);
    if (!g) {
      return; // or socket.emit('error', 'Game not found');
    }
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
      io.emit('games_list', Array.from(activeGames.values()));
    }
  });

  socket.on('leave_game', async ({ game_id, player_id }) => {
    const g = activeGames.get(game_id);
    if (!g) {
      return; // or socket.emit('error', 'Game not found');
    }
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
      io.emit('games_list', Array.from(activeGames.values()));
    }
  });
});

// ----------------------------------------
// HTTP / HTTPS Server
// ----------------------------------------
const port = ENVS.PORT;
if (isProd && sslOptions) {
  const options = {
    key: fs.readFileSync(sslOptions.SSL_KEY_PATH ?? ''),
    cert: fs.readFileSync(sslOptions.SSL_CERT_PATH ?? ''),
  };
  https.createServer(options, app).listen(port, () => {
    logger.info('HTTPS server on ' + port);
  });
} else {
  httpServer.listen(port, () => {
    logger.info('HTTP server on ' + port);
  });
}
