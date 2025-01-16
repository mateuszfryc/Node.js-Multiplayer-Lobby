import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import dotenv from 'dotenv';
import express from 'express';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import fs from 'fs';
import helmet from 'helmet';
import { createServer } from 'http';
import https from 'https';
import jwt from 'jsonwebtoken';
import net from 'net';
import nodemailer from 'nodemailer';
import process from 'process';
import { DataTypes, Sequelize } from 'sequelize';
import { Server as SocketIOServer } from 'socket.io';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import 'winston-daily-rotate-file';

const sensitiveKeys = [
  'password',
  'token',
  'refresh_token',
  'user_name',
  'ip',
  'port',
  'Authorization',
  'accessToken',
  'refreshToken',
];

const redactSensitiveData = winston.format((info) => {
  for (const key of sensitiveKeys) {
    if (info[key]) {
      info[key] = '[REDACTED]';
    }
  }
  return info;
});

const logger = winston.createLogger({
  level: 'debug',
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
        winston.format.errors({ stack: true }),
        redactSensitiveData(),
        winston.format.colorize(),
        winston.format.printf(
          ({ level, message, timestamp, stack, ...meta }) => {
            const metaString = Object.keys(meta).length
              ? Object.entries(meta)
                  .map(([key, value]) => `${key}: "${value}"`)
                  .join(', ')
              : '';
            return `${timestamp} [${level}] ${stack || message} ${
              metaString ? `| ${metaString}` : ''
            }`;
          }
        )
      ),
    }),
    new winston.transports.DailyRotateFile({
      filename: './.logs/lobby-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
        winston.format.errors({ stack: true }),
        redactSensitiveData(),
        winston.format.json()
      ),
    }),
  ],
});

const loadEnv = (envDefinitions) => {
  const envs = {};
  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction) {
    dotenv.config({ path: '.env.prod.db' });
    dotenv.config({ path: '.env.prod.auth' });
  } else {
    dotenv.config({ path: '.env.db' });
    dotenv.config({ path: '.env.auth' });
  }
  const parseBoolean = (value) => {
    if (value === 'true') return true;
    if (value === 'false') return false;
    throw new Error(`Invalid boolean value: "${value}".`);
  };
  for (const {
    key,
    minLength,
    base64Length,
    filePath,
    type,
  } of envDefinitions) {
    const value = process.env[key];
    if (!value)
      throw new Error(`Missing required environment variable: ${key}`);
    if (minLength && value.length < minLength) {
      throw new Error(
        `Environment variable "${key}" must be at least ${minLength} characters.`
      );
    }
    if (base64Length && value) {
      const raw = Buffer.from(value, 'base64');
      if (raw.length !== base64Length) {
        throw new Error(
          `Environment variable "${key}" must decode to ${base64Length} bytes.`
        );
      }
    }
    if (filePath && value) {
      try {
        fs.accessSync(value, fs.constants.R_OK);
      } catch {
        throw new Error(
          `File in "${key}" does not exist or is not readable: ${value}`
        );
      }
    }
    switch (type) {
      case 'bool':
        envs[key] = parseBoolean(value);
        break;
      case 'number': {
        const numericValue = Number(value);
        if (isNaN(numericValue)) {
          throw new Error(
            `Environment variable "${key}" must be a valid number.`
          );
        }
        envs[key] = numericValue;
        break;
      }
      default:
        envs[key] = value;
    }
  }
  logger.info('All required environment variables are present and valid.');
  return [envs, isProduction];
};

const [ENVS, isProduction] = loadEnv([
  { key: 'PORT' },
  { key: 'JWT_SECRET', minLength: 32 },
  { key: 'JWT_REFRESH_SECRET', minLength: 32 },
  { key: 'DB_USER' },
  { key: 'DB_PASSWORD' },
  { key: 'DB_NAME' },
  { key: 'DB_HOST' },
  { key: 'DB_PORT', type: 'number' },
  { key: 'DB_FORCE_SYNC', type: 'bool' },
  { key: 'SSL_KEY_PATH' },
  { key: 'SSL_CERT_PATH' },
  { key: 'USE_SSL', type: 'bool' },
  { key: 'SMTP_HOST' },
  { key: 'FROM_EMAIL' },
  { key: 'SMTP_USER' },
  { key: 'SMTP_PASS' },
  { key: 'SMTP_PORT' },
  { key: 'ADMIN_USER_NAME' },
  { key: 'ADMIN_PASSWORD' },
  { key: 'ADMIN_PLAYER_NAME' },
]);

let sslOptions;
if (ENVS.USE_SSL === 'true') {
  try {
    sslOptions = {
      key: fs.readFileSync(ENVS.SSL_KEY_PATH),
      cert: fs.readFileSync(ENVS.SSL_CERT_PATH),
    };
  } catch (err) {
    throw new Error(`Failed to load SSL certificates: ${err.message}`);
  }
}

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
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    noSniff: true,
  })
);

if (isProduction) {
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (req.secure) return next();
    return res.redirect(`https://${req.headers.host}${req.url}`);
  });
}

const limiter = rateLimit({
  windowMs: 60000,
  max: 50,
  message: { message: '', error: 'Too many requests', data: {} },
});
app.use(limiter);

const USER_CHARS = /^[A-Za-z0-9!@#$%^&*\+\-\?, ]+$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_REGEX =
  /^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*\+\-\?,])[A-Za-z0-9!@#$%^&*\+\-\?,]{8,}$/;
const PLAYER_NAME_REGEX = /^[A-Za-z0-9!@#$%^&*\+\-\?,]{3,16}$/;

class UserModel {
  constructor(model) {
    this.model = model;
  }
  async createUser(data) {
    return this.model.create(data);
  }
  async findUserByName(user_name) {
    return this.model.findOne({ where: { user_name } });
  }
  async findUserById(id) {
    return this.model.findOne({ where: { id } });
  }
  async updateUser(id, newData) {
    return this.model.update(newData, { where: { id } });
  }
  async loginUser(user, refreshToken) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.updateUser(user.id, {
      logged_in: true,
      refresh_token: hashedRefreshToken,
      updated_at: dayjs().toISOString(),
    });
  }
  async logoutUser(userId) {
    await this.updateUser(userId, {
      logged_in: false,
      refresh_token: null,
      updated_at: dayjs().toISOString(),
    });
  }

  async deleteUser(userId) {
    return this.model.destroy({ where: { id: userId } });
  }
}

class GameModel {
  constructor(model) {
    this.model = model;
  }
  async findAllGames() {
    return this.model.findAll();
  }
  async findByIpPort(ip, port) {
    return this.model.findOne({ where: { ip, port } });
  }
  async findById(id) {
    return this.model.findOne({ where: { id } });
  }
  async createGame(data) {
    return this.model.create(data);
  }
  async updateGame(id, newData) {
    return this.model.update(newData, { where: { id } });
  }
  async deleteGame(id) {
    return this.model.destroy({ where: { id } });
  }
}

class ActivationModel {
  constructor(model) {
    this.model = model;
  }
  async createActivation(data) {
    return this.model.create(data);
  }
  async findByToken(token) {
    return this.model.findOne({ where: { token } });
  }
}

class Database {
  constructor() {
    this.sequelize = new Sequelize(
      ENVS.DB_NAME,
      ENVS.DB_USER,
      ENVS.DB_PASSWORD,
      {
        host: ENVS.DB_HOST,
        dialect: 'postgres',
        protocol: 'postgres',
        logging: false,
        dialectOptions: isProduction
          ? {
              ssl: {
                require: true,
                rejectUnauthorized: false,
              },
            }
          : {},
      }
    );
    this.UsersTable = this.sequelize.define(
      'user',
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
        },
        user_name: { type: DataTypes.STRING, unique: true, allowNull: false },
        password: { type: DataTypes.STRING, allowNull: false },
        player_name: { type: DataTypes.STRING, allowNull: false },
        role: { type: DataTypes.STRING, allowNull: false },
        logged_in: {
          type: DataTypes.BOOLEAN,
          allowNull: false,
          defaultValue: false,
        },
        validated_at: { type: DataTypes.DATE, allowNull: true },
        refresh_token: { type: DataTypes.TEXT, allowNull: true },
      },
      {
        tableName: 'users',
        timestamps: true,
        createdAt: 'created_at',
        updatedAt: 'updated_at',
      }
    );
    this.GamesTable = this.sequelize.define(
      'game',
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
        },
        ip: { type: DataTypes.STRING, allowNull: false },
        port: { type: DataTypes.INTEGER, allowNull: false },
        name: { type: DataTypes.STRING, allowNull: false },
        map_name: { type: DataTypes.STRING, allowNull: false },
        game_mode: { type: DataTypes.STRING, allowNull: false },
        connected_players: {
          type: DataTypes.ARRAY(DataTypes.STRING),
          allowNull: false,
          defaultValue: [],
        },
        max_players: { type: DataTypes.INTEGER, allowNull: false },
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
        ping: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      },
      {
        tableName: 'games',
        timestamps: true,
        createdAt: 'created_at',
        updatedAt: 'updated_at',
      }
    );
    this.ActivationsTable = this.sequelize.define(
      'activation',
      {
        user_id: { type: DataTypes.UUID, allowNull: false },
        token: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          allowNull: false,
        },
        expires_at: { type: DataTypes.DATE, allowNull: false },
      },
      {
        tableName: 'activations',
        timestamps: true,
        createdAt: 'created_at',
        updatedAt: 'updated_at',
      }
    );
    this.user = new UserModel(this.UsersTable);
    this.game = new GameModel(this.GamesTable);
    this.activation = new ActivationModel(this.ActivationsTable);
  }
  async init() {
    if (!isProduction || ENVS.DB_FORCE_SYNC === 'true') {
      await this.sequelize.sync({ alter: true });
    }
  }
  async seedUsers(usersSeed) {
    if (!usersSeed || !Array.isArray(usersSeed) || usersSeed.length === 0) {
      throw new Error('Invalid users seed data');
    }
    await this.sequelize.sync({ force: true });
    for (const user of usersSeed) {
      await this.user.createUser(user);
    }
  }
}

const db = new Database();
await db.init();
await (async () => {
  try {
    if (
      !ENVS.ADMIN_USER_NAME ||
      !ENVS.ADMIN_PASSWORD ||
      !ENVS.ADMIN_PLAYER_NAME
    ) {
      throw new Error('Admin user environment variables are missing.');
    }
    const existingAdmin = await db.user.findUserByName(ENVS.ADMIN_USER_NAME);
    if (existingAdmin) {
      logger.info('Admin user already exists');
    } else {
      const adminId = uuidv4();
      const hashedPassword = await bcrypt.hash(ENVS.ADMIN_PASSWORD, 10);
      const now = dayjs().toISOString();
      await db.user.createUser({
        id: adminId,
        user_name: ENVS.ADMIN_USER_NAME,
        password: hashedPassword,
        player_name: ENVS.ADMIN_PLAYER_NAME,
        role: 'admin',
        logged_in: false,
        created_at: now,
        updated_at: now,
        validated_at: now,
      });
      logger.info('Admin user created successfully');
    }
  } catch (error) {
    logger.error('Failed to create admin user', { error: error.message });
    process.exit(1);
  }
})();

function validatePort(port) {
  const parsed = parseInt(port, 10);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535;
}

function validateIpOrLocalhost(ip) {
  if (ip === 'localhost') return true;
  return net.isIP(ip) !== 0;
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

async function authenticateToken(req, res, next) {
  logger.info('Authenticating token for incoming request', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      logger.warn('No Authorization header found');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const accessToken = authHeader.split(' ')[1];
    if (!accessToken) {
      logger.warn('No access token found in Authorization header');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const decoded = jwt.verify(accessToken, ENVS.JWT_SECRET ?? '');
    logger.debug('Token decoded successfully', { role: decoded.role });
    req.body.decodedUser = decoded;
    next();
  } catch (e) {
    logger.error('Failed to authenticate token', { error: e.message });
    return jsonRes(res, '', 'Unauthorized', [], 401);
  }
}

const smptPort = parseInt(ENVS.SMTP_PORT || '587', 10);
const transporter = nodemailer.createTransport({
  host: ENVS.SMTP_HOST,
  port: smptPort,
  secure: smptPort === 465,
  auth: {
    user: ENVS.SMTP_USER,
    pass: ENVS.SMTP_PASS,
  },
});

transporter.verify((error, success) => {
  if (error) {
    logger.error('SMTP Connection Error', { error: error.message });
  } else {
    logger.info('SMTP Connection Successful');
  }
});

app.post('/api_v1/user', authenticateToken, async (req, res) => {
  logger.info('POST /api_v1/user called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const decoded = req.body.decodedUser;
    logger.debug('Decoded user role for register route', {
      role: decoded?.role,
    });
    const { user_name, password, player_name } = req.body;
    if (!decoded || decoded.role !== 'admin') {
      logger.warn('Non-admin attempted to create new user');
      return jsonRes(res, '', 'Request failed', [], 400);
    }
    if (!user_name || !password || !player_name) {
      logger.warn('Missing fields in /api_v1/register');
      return jsonRes(res, '', 'Request failed', [], 400);
    }
    if (!validateEmailFormat(user_name)) {
      logger.warn('Invalid email format in /api_v1/register');
      return jsonRes(res, '', 'Request failed', [], 400);
    }
    if (!validatePasswordFormat(password)) {
      logger.warn('Invalid password format in /api_v1/register');
      return jsonRes(res, '', 'Request failed', [], 400);
    }
    if (!validatePlayerNameFormat(player_name)) {
      logger.warn('Invalid player_name format in /api_v1/register');
      return jsonRes(res, '', 'Request failed', [], 400);
    }
    const existing = await db.user.findUserByName(user_name);
    if (existing) {
      logger.warn('Attempt to create existing user');
      return jsonRes(res, '', 'Request failed', [], 400);
    }
    const hashed = await bcrypt.hash(password, 10);
    const newId = uuidv4();
    const now = dayjs().toISOString();
    await db.user.createUser({
      id: newId,
      user_name,
      password: hashed,
      player_name,
      role: 'player',
      logged_in: false,
      created_at: now,
      updated_at: now,
      validated_at: null,
    });
    logger.info('New user created successfully');
    const token = uuidv4();
    const exp = dayjs().add(1, 'day').toISOString();
    await db.activation.createActivation({
      user_id: newId,
      token,
      created_at: now,
      expires_at: exp,
    });
    logger.debug('Activation token created for new user (token redacted)');
    try {
      const verificationLink = `${isProduction ? 'https' : 'http'}://${
        req.headers.host
      }/api_v1/confirm/${token}`;
      await transporter.sendMail({
        from: ENVS.FROM_EMAIL,
        to: user_name,
        subject: 'Please Confirm Your Email',
        text: `Hello! Confirm your email by visiting: ${verificationLink}`,
        html: `<p>Hello!</p><p>Please confirm your email by clicking the link below:</p><p><a href="${verificationLink}">${verificationLink}</a></p>`,
      });
      logger.info('Verification email sent (recipient redacted)');
    } catch (emailError) {
      logger.error('Failed to send verification email', {
        error: emailError.message,
      });
    }
    return jsonRes(res, 'User created', '', { id: newId, player_name }, 201);
  } catch (e) {
    logger.error('Error in /api_v1/user route', { error: e.message });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.get('/api_v1/confirm/:token', async (req, res) => {
  logger.info('GET /api_v1/confirm/:token called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const token = req.params.token;
    const now = dayjs().toISOString();
    const act = await db.activation.findByToken(token);
    if (!act) {
      logger.warn('Invalid token used for email confirmation');
      return jsonRes(res, '', 'Invalid token', [], 404);
    }
    if (dayjs(now).isAfter(dayjs(act.expires_at))) {
      logger.warn('Expired token used for email confirmation');
      return jsonRes(res, '', 'Invalid token', [], 400);
    }
    await db.user.updateUser(act.user_id, { validated_at: now });
    logger.info('Email confirmed for a user');
    return jsonRes(res, 'Email confirmed', '', {}, 200);
  } catch (e) {
    logger.error('Error in /api_v1/confirm/:token route', { error: e.message });
    return jsonRes(res, '', 'Invalid token', [], 500);
  }
});

const loginLimiter = rateLimit({
  windowMs: 60000,
  max: 5,
  message: { error: 'Too many login attempts. Please try again later.' },
});
const loginSpeedLimiter = slowDown({
  windowMs: 60000,
  delayAfter: 5,
  delayMs: () => 1000,
  maxDelayMs: 10000,
});

app.post('/api_v1/login', loginLimiter, loginSpeedLimiter, async (req, res) => {
  logger.info('POST /api_v1/login called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const { user_name, password } = req.body;
    if (!user_name || !password || !validateEmailFormat(user_name)) {
      logger.warn('Fields missing in login request');
      return jsonRes(res, '', 'Invalid credentials', [], 400);
    }
    if (!validateEmailFormat(user_name)) {
      logger.warn('Invalid email input during login');
      return jsonRes(res, '', 'Invalid credentials', [], 400);
    }
    const user = await db.user.findUserByName(user_name);
    if (!user) {
      logger.warn('Invalid credentials: user not found');
      return jsonRes(res, '', 'Invalid credentials', [], 401);
    }
    const passOk = await bcrypt.compare(password, user.password);
    if (!passOk) {
      logger.warn('Invalid credentials: wrong password');
      return jsonRes(res, '', 'Invalid credentials', [], 401);
    }
    if (!user.validated_at) {
      logger.warn('Email not validated for this user');
      return jsonRes(res, '', 'Email not validated', [], 403);
    }
    if (user.logged_in) {
      logger.warn('User already logged in');
      return jsonRes(res, '', 'Already logged in', [], 409);
    }
    const accessToken = jwt.sign(
      { id: user.id, role: user.role, player_name: user.player_name },
      ENVS.JWT_SECRET ?? '',
      { expiresIn: '15m' }
    );
    const refreshToken = jwt.sign(
      { id: user.id, role: user.role },
      ENVS.JWT_REFRESH_SECRET ?? '',
      { expiresIn: '7d' }
    );
    await db.user.loginUser(user, refreshToken);
    logger.info('User logged in successfully');
    return jsonRes(res, '', '', { accessToken, refreshToken }, 200);
  } catch (e) {
    logger.error('Error in /api_v1/login route', { error: e.message });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.post('/api_v1/refresh', async (req, res) => {
  logger.info('POST /api_v1/refresh called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      logger.warn('Refresh token missing');
      return jsonRes(res, '', 'Refresh token missing', [], 400);
    }
    const decoded = jwt.verify(refreshToken, ENVS.JWT_REFRESH_SECRET ?? '');
    logger.debug('Refresh token decoded successfully', { role: decoded?.role });
    const user = await db.user.findUserById(decoded.id);
    if (!user) {
      logger.warn('User not found for refresh token');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const match = await bcrypt.compare(refreshToken, user.refresh_token ?? '');
    if (!match) {
      logger.warn('Refresh token mismatch');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const newAccessToken = jwt.sign(
      { id: user.id, role: user.role, player_name: user.player_name },
      ENVS.JWT_SECRET ?? '',
      { expiresIn: '15m' }
    );
    const newRefreshToken = jwt.sign(
      { id: user.id, role: user.role },
      ENVS.JWT_REFRESH_SECRET ?? '',
      { expiresIn: '7d' }
    );
    await db.user.loginUser(user, newRefreshToken);
    logger.info('Token refreshed successfully');
    return jsonRes(
      res,
      'Token refreshed',
      '',
      { accessToken: newAccessToken, refreshToken: newRefreshToken },
      200
    );
  } catch (e) {
    logger.error('Error in /api_v1/refresh route', { error: e.message });
    return jsonRes(res, '', 'Unauthorized', [], 401);
  }
});

app.patch('/api_v1/user', authenticateToken, async (req, res) => {
  logger.info('PATCH /api_v1/user called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const decoded = req.body.decodedUser;
    logger.debug('Decoded user role for user update', { role: decoded?.role });
    if (!decoded || !decoded.id) {
      logger.warn('Unauthorized update request (no user id)');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const { player_name } = req.body;
    if (!player_name || !validatePlayerNameFormat(player_name)) {
      logger.warn('Invalid player_name in update request');
      return jsonRes(res, '', 'Invalid player_name', [], 400);
    }
    await db.user.updateUser(decoded.id, {
      player_name,
      updated_at: dayjs().toISOString(),
    });
    logger.info('User updated successfully');
    return jsonRes(res, '', 'Success', {}, 200);
  } catch (e) {
    logger.error('Error in PATCH /api_v1/user route', { error: e.message });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.delete('/api_v1/user/:user_id', authenticateToken, async (req, res) => {
  logger.info('DELETE /api_v1/user/:user_id called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const decoded = req.body.decodedUser;
    logger.debug('Decoded user role for user deletion', {
      role: decoded?.role,
    });
    if (!decoded || decoded.role !== 'admin') {
      logger.warn('Unauthorized user deletion attempt');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const userId = req.params.user_id;
    const plainId = userId;
    if (!plainId) {
      logger.warn('Unable to decrypt user_id');
      return jsonRes(res, '', 'Invalid user_id', [], 400);
    }
    const user = await db.user.findUserById(userId);
    if (!user) {
      logger.warn('User not found for deletion');
      return jsonRes(res, '', 'Not found', [], 404);
    }
    await db.user.deleteUser(userId);
    logger.info('User deleted successfully');
    return jsonRes(res, '', 'Success', {}, 200);
  } catch (e) {
    logger.error('Error in DELETE /api_v1/user/:user_id route', {
      error: e.message,
    });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

const activeGames = new Map();

app.get('/api_v1/games', authenticateToken, async (req, res) => {
  logger.info('GET /api_v1/games called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const games = await db.game.findAllGames();
    logger.debug('Fetched games list', { count: games.length });
    return jsonRes(res, '', '', games, 200);
  } catch (e) {
    logger.error('Error in GET /api_v1/games route', { error: e.message });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.post('/api_v1/games', authenticateToken, async (req, res) => {
  logger.info('POST /api_v1/games called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const decoded = req.body.decodedUser;
    logger.debug('Decoded user role for creating game', {
      role: decoded?.role,
    });
    if (!decoded || !decoded.id) {
      logger.warn('Unauthorized attempt to create game');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    let {
      ip,
      port,
      game_name,
      map_name,
      game_mode,
      max_players,
      private: isPrivate,
      password,
    } = req.body;
    if (!ip || !port || !game_name || !map_name || !game_mode) {
      logger.warn('Missing required fields in create game request');
      return jsonRes(res, '', 'Missing fields', [], 400);
    }
    if (!validateIpOrLocalhost(ip)) {
      logger.warn('Invalid IP address for game creation');
      return jsonRes(res, '', 'Incorrect IP address', [], 400);
    }
    if (!validatePort(port)) {
      logger.warn('Invalid port number for game creation');
      return jsonRes(res, '', 'Incorrect port number', [], 400);
    }
    if (
      !USER_CHARS.test(game_name) ||
      !USER_CHARS.test(map_name) ||
      !USER_CHARS.test(game_mode)
    ) {
      logger.warn('Invalid characters in game fields');
      return jsonRes(res, '', 'Invalid characters', [], 400);
    }
    if (!max_players) max_players = 8;
    if (!isPrivate) isPrivate = false;
    if (!password) password = '';
    const existing = await db.game.findByIpPort(ip, port);
    if (existing) {
      logger.debug('Existing game found for IP:Port. Replacing game entry');
      await db.game.deleteGame(existing.id);
      activeGames.delete(existing.id);
    }
    const newId = uuidv4();
    const now = dayjs().toISOString();
    const pass = await bcrypt.hash(password, 10);
    const newGame = await db.game.createGame({
      id: newId,
      ip,
      port,
      name: game_name,
      map_name,
      game_mode,
      connected_players: [],
      max_players,
      private: isPrivate,
      password: pass,
      ping: 0,
      created_at: now,
      updated_at: now,
    });
    activeGames.set(newId, newGame.toJSON());
    logger.info('Game created successfully', {
      game_name,
      map_name,
      game_mode,
      max_players,
      private: isPrivate,
    });
    io.emit('game_created', newGame);
    io.emit('games_list', Array.from(activeGames.values()));
    return jsonRes(res, 'Game created', '', newGame, 201);
  } catch (e) {
    logger.error('Error in POST /api_v1/games route', { error: e.message });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.put('/api_v1/games/:game_id', authenticateToken, async (req, res) => {
  logger.info('PUT /api_v1/games/:game_id called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const decoded = req.body.decodedUser;
    logger.debug('Decoded user role for updating game', {
      role: decoded?.role,
    });
    if (!decoded || !decoded.id) {
      logger.warn('Unauthorized attempt to update game');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const gameId = req.params.game_id;
    const plainId = gameId;
    if (!plainId) {
      logger.warn('Unable to decrypt game_id');
      return jsonRes(res, '', 'Invalid game_id', [], 400);
    }
    const gameCheck = await db.game.findById(gameId);
    if (!gameCheck) {
      logger.warn('Game not found for update');
      return jsonRes(res, '', 'Not found', [], 404);
    }
    const newData = { ...req.body };
    delete newData.decodedUser;
    await db.game.updateGame(gameId, newData);
    logger.debug('Game updated in database');
    const updated = await db.game.findById(gameId);
    activeGames.set(gameId, updated.toJSON());
    io.emit('game_updated', updated);
    io.emit('games_list', Array.from(activeGames.values()));
    logger.info('Game updated successfully');
    return jsonRes(res, '', '', updated, 200);
  } catch (e) {
    logger.error('Error in PUT /api_v1/games/:game_id route', {
      error: e.message,
    });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.delete('/api_v1/games/:game_id', authenticateToken, async (req, res) => {
  logger.info('DELETE /api_v1/games/:game_id called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const decoded = req.body.decodedUser;
    logger.debug('Decoded user role for deleting game', {
      role: decoded?.role,
    });
    if (!decoded || !decoded.id) {
      logger.warn('Unauthorized attempt to delete game');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const gameId = req.params.game_id;
    const plainId = gameId;
    if (!plainId) {
      logger.warn('Unable to decrypt game_id for deletion');
      return jsonRes(res, '', 'Invalid game_id', [], 400);
    }
    const gameCheck = await db.game.findById(gameId);
    if (!gameCheck) {
      logger.warn('Game not found for deletion');
      return jsonRes(res, '', 'Not found', [], 404);
    }
    await db.game.deleteGame(gameId);
    activeGames.delete(gameId);
    io.emit('game_removed', gameId);
    io.emit('games_list', Array.from(activeGames.values()));
    logger.info('Game deleted successfully');
    return jsonRes(res, 'Game deleted', '', {}, 200);
  } catch (e) {
    logger.error('Error in DELETE /api_v1/games/:game_id route', {
      error: e.message,
    });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.post('/api_v1/games/:game_id/join', authenticateToken, async (req, res) => {
  logger.info('POST /api_v1/games/:game_id/join called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const decoded = req.body.decodedUser;
    logger.debug('Decoded user role for joining game', { role: decoded?.role });
    if (!decoded || !decoded.id) {
      logger.warn('Unauthorized attempt to join game');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const gameId = req.params.game_id;
    const plainId = gameId;
    if (!plainId) {
      logger.warn('Unable to decrypt game_id for join');
      return jsonRes(res, '', 'Invalid game_id', [], 400);
    }
    const gameData = activeGames.get(gameId);
    if (!gameData) {
      logger.warn('Game not found in activeGames for join');
      return jsonRes(res, '', 'Game not found', [], 404);
    }
    const cPlayers = gameData.connected_players || [];
    if (!cPlayers.includes(decoded.id)) {
      cPlayers.push(decoded.id);
      gameData.connected_players = cPlayers;
      await db.game.updateGame(gameId, { connected_players: cPlayers });
      activeGames.set(gameId, gameData);
      logger.info('Player joined the game', {
        connectedPlayersCount: cPlayers.length,
      });
      io.emit('player_joined', { game_id: gameId, player_id: decoded.id });
      io.emit('games_list', Array.from(activeGames.values()));
    }
    return jsonRes(res, 'Joined game', '', { game_id: gameId }, 200);
  } catch (e) {
    logger.error('Error in POST /api_v1/games/:game_id/join route', {
      error: e.message,
    });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

app.post(
  '/api_v1/games/:game_id/leave',
  authenticateToken,
  async (req, res) => {
    logger.info('POST /api_v1/games/:game_id/leave called', {
      method: req.method,
      url: req.url,
      clientIp: req.ip,
    });
    try {
      const decoded = req.body.decodedUser;
      logger.debug('Decoded user role for leaving game', {
        role: decoded?.role,
      });
      if (!decoded || !decoded.id) {
        logger.warn('Unauthorized attempt to leave game');
        return jsonRes(res, '', 'Unauthorized', [], 401);
      }
      const gameId = req.params.game_id;
      const plainId = gameId;
      if (!plainId) {
        logger.warn('Unable to decrypt game_id for leave');
        return jsonRes(res, '', 'Invalid game_id', [], 400);
      }
      const gameData = activeGames.get(gameId);
      if (!gameData) {
        logger.warn('Game not found in activeGames for leave');
        return jsonRes(res, '', 'Game not found', [], 404);
      }
      const cPlayers = gameData.connected_players || [];
      const idx = cPlayers.indexOf(decoded.id);
      if (idx > -1) {
        cPlayers.splice(idx, 1);
        gameData.connected_players = cPlayers;
        await db.game.updateGame(gameId, { connected_players: cPlayers });
        activeGames.set(gameId, gameData);
        logger.info('Player left the game', {
          connectedPlayersCount: cPlayers.length,
        });
        io.emit('player_left', { game_id: gameId, player_id: decoded.id });
        io.emit('games_list', Array.from(activeGames.values()));
      }
      return jsonRes(res, 'Left game', '', { game_id: gameId }, 200);
    } catch (e) {
      logger.error('Error in POST /api_v1/games/:game_id/leave route', {
        error: e.message,
      });
      return jsonRes(res, '', 'Server error', [], 500);
    }
  }
);

app.post('/api_v1/logout', authenticateToken, async (req, res) => {
  logger.info('POST /api_v1/logout called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const { decodedUser } = req.body;
    logger.debug('Decoded user role for logout', { role: decodedUser?.role });
    if (!decodedUser) {
      logger.warn('Unauthorized');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    const user = await db.user.findUserById(decodedUser.id);
    if (!user) {
      logger.warn('User not found during logout');
      return jsonRes(res, '', 'Unauthorized', [], 401);
    }
    await db.user.logoutUser(decodedUser.id);
    logger.info('User logged out successfully');
    return jsonRes(res, 'Logged out', '', {}, 200);
  } catch (e) {
    logger.error('Error in POST /api_v1/logout route', { error: e.message });
    return jsonRes(res, '', 'Server error', [], 500);
  }
});

const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: false, methods: ['GET', 'POST'] },
});

io.on('connection', (socket) => {
  logger.info('New socket connection established', { socketId: socket.id });
  socket.emit('games_list', Array.from(activeGames.values()));
  socket.on('join_game', async ({ game_id, player_id }) => {
    logger.debug('Socket join_game event received');
    const g = activeGames.get(game_id);
    if (!g) return;
    const cPlayers = g.connected_players || [];
    if (!cPlayers.includes(player_id)) {
      cPlayers.push(player_id);
      g.connected_players = cPlayers;
      await db.game.updateGame(game_id, { connected_players: cPlayers });
      activeGames.set(game_id, g);
      logger.info('Player joined game via socket', {
        connectedPlayersCount: cPlayers.length,
      });
      io.emit('player_joined', { game_id, player_id });
      io.emit('games_list', Array.from(activeGames.values()));
    }
  });
  socket.on('leave_game', async ({ game_id, player_id }) => {
    logger.debug('Socket leave_game event received');
    const g = activeGames.get(game_id);
    if (!g) return;
    const cPlayers = g.connected_players || [];
    const ix = cPlayers.indexOf(player_id);
    if (ix > -1) {
      cPlayers.splice(ix, 1);
      g.connected_players = cPlayers;
      await db.game.updateGame(game_id, { connected_players: cPlayers });
      activeGames.set(game_id, g);
      logger.info('Player left game via socket', {
        connectedPlayersCount: cPlayers.length,
      });
      io.emit('player_left', { game_id, player_id });
      io.emit('games_list', Array.from(activeGames.values()));
    }
  });
});

app.get('/health', (req, res) => {
  res.status(200).send('Server is healthy');
});

app.all('*', (req, res) => {
  logger.warn('Unhandled route', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  res.status(404).send('Route not found');
});

const port = ENVS.PORT;
if (isProduction && sslOptions) {
  const httpsOptions = {
    key: sslOptions.key,
    cert: sslOptions.cert,
  };
  https.createServer(httpsOptions, app).listen(port, () => {
    logger.info(`HTTPS server listening on port ${port}`);
  });
} else {
  httpServer.listen(port, () => {
    logger.info(`HTTP server listening on port ${port}`);
  });
}
