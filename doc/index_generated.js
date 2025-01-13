import { loadEnv } from '#config/dotenv.js';
import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import express from 'express';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import helmet from 'helmet';
import { createServer } from 'http';
import https from 'https';
import jwt from 'jsonwebtoken';
import * as sodium from 'libsodium-wrappers';
import { Pool } from 'pg';
import { Server as SocketIOServer } from 'socket.io';
import winston from 'winston';
import 'winston-daily-rotate-file';

const envLoaded = loadEnv();
const app = express();
app.use(express.json({ strict: true }));
app.use(helmet());
const limiter = rateLimit({
  windowMs: 60000,
  max: 50,
  message: { message: '', error: 'Too many requests', data: {} },
});
app.use(limiter);
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
const USER_CHARS = /^[A-Za-z0-9!@#$%^&*\+\-\?,]+$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_REGEX =
  /^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*\+\-\?,])[A-Za-z0-9!@#$%^&*\+\-\?,]{8,}$/;
const PLAYER_NAME_REGEX = /^[A-Za-z0-9!@#$%^&*\+\-\?,]{3,16}$/;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,
});
(async () => {
  await sodium.ready;
  await pool.query(
    `CREATE TABLE IF NOT EXISTS Users(id TEXT PRIMARY KEY,user_name TEXT UNIQUE NOT NULL,password TEXT NOT NULL,player_name TEXT NOT NULL,role TEXT NOT NULL,logged_in BOOLEAN NOT NULL,created_at TIMESTAMP NOT NULL,updated_at TIMESTAMP NOT NULL,validated_at TIMESTAMP)`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS Games(id TEXT PRIMARY KEY,ip TEXT NOT NULL,port INT NOT NULL,name TEXT NOT NULL,map_name TEXT NOT NULL,game_mode TEXT NOT NULL,connected_players TEXT[],max_players INT NOT NULL,private BOOLEAN NOT NULL,password TEXT NOT NULL,ping INT NOT NULL,created_at TIMESTAMP NOT NULL,updated_at TIMESTAMP NOT NULL)`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS Activations(user_id TEXT NOT NULL,token TEXT NOT NULL,created_at TIMESTAMP NOT NULL,expires_at TIMESTAMP NOT NULL)`
  );
})();
const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: false, methods: ['GET', 'POST'] },
});
const activeGames = new Map();
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
async function authenticateToken(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth) return jsonRes(res, '', 'Unauthorized', []);
    const token = auth.split(' ')[1];
    if (!token) return jsonRes(res, '', 'Unauthorized', []);
    const blacklisted = await pool.query(
      'SELECT * FROM Activations WHERE token=$1',
      [token]
    );
    if (blacklisted.rowCount > 0) return jsonRes(res, '', 'Token invalid', []);
    const decoded = jwt.verify(token, process.env.JWT_SECRET ?? '');
    req.body.decodedUser = decoded;
    next();
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Unauthorized', []);
  }
}
function validateEmailFormat(email) {
  return EMAIL_REGEX.test(email) && USER_CHARS.test(email);
}
function validatePasswordFormat(pw) {
  return PASSWORD_REGEX.test(pw);
}
function validatePlayerNameFormat(n) {
  return PLAYER_NAME_REGEX.test(n);
}
app.post('/api_v1/join', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    const { user_name, password, player_name } = req.body;
    if (!d || !d.role || d.role !== 'admin')
      return jsonRes(res, '', 'Not allowed', []);
    if (!user_name || !password || !player_name)
      return jsonRes(res, '', 'Invalid fields', []);
    if (!validateEmailFormat(user_name))
      return jsonRes(res, '', 'Email invalid', []);
    if (!validatePasswordFormat(password))
      return jsonRes(res, '', 'Password invalid', []);
    if (!validatePlayerNameFormat(player_name))
      return jsonRes(res, '', 'Player name invalid', []);
    const q = await pool.query('SELECT * FROM Users WHERE user_name=$1', [
      user_name,
    ]);
    if (q.rowCount > 0) return jsonRes(res, '', 'User exists', []);
    const hashed = await bcrypt.hash(password, 10);
    const rid = await generateId();
    const now = dayjs().toISOString();
    await pool.query(
      'INSERT INTO Users(id,user_name,password,player_name,role,logged_in,created_at,updated_at,validated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [rid, user_name, hashed, player_name, 'player', false, now, now, null]
    );
    const token = await generateId();
    const exp = dayjs().add(1, 'day').toISOString();
    await pool.query(
      'INSERT INTO Activations(user_id,token,created_at,expires_at) VALUES($1,$2,$3,$4)',
      [rid, token, now, exp]
    );
    return jsonRes(res, 'User created', '', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});
app.get('/api_v1/confirm/:token', async (req, res) => {
  try {
    const t = req.params.token;
    const now = dayjs().toISOString();
    const act = await pool.query('SELECT * FROM Activations WHERE token=$1', [
      t,
    ]);
    if (act.rowCount < 1) return jsonRes(res, '', 'Invalid token', []);
    const row = act.rows[0];
    if (dayjs(now).isAfter(dayjs(row.expires_at)))
      return jsonRes(res, '', 'Invalid token', []);
    const uid = row.user_id;
    await pool.query('UPDATE Users SET validated_at=$1 WHERE id=$2', [
      now,
      uid,
    ]);
    return jsonRes(res, 'Email confirmed', '', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Invalid token', []);
  }
});
app.post('/api_v1/login', async (req, res) => {
  try {
    const { user_name, password } = req.body;
    if (!user_name || !password) return jsonRes(res, '', 'Fields missing', []);
    if (!validateEmailFormat(user_name) || !USER_CHARS.test(password))
      return jsonRes(res, '', 'Invalid input', []);
    const user = await pool.query('SELECT * FROM Users WHERE user_name=$1', [
      user_name,
    ]);
    if (user.rowCount < 1) return jsonRes(res, '', 'Invalid credentials', []);
    const u = user.rows[0];
    const passOk = await bcrypt.compare(password, u.password);
    if (!passOk) return jsonRes(res, '', 'Invalid credentials', []);
    if (u.logged_in) return jsonRes(res, '', 'Already logged in', []);
    const tok = jwt.sign(
      { id: u.id, role: u.role, player_name: u.player_name },
      process.env.JWT_SECRET ?? '',
      { expiresIn: '24h' }
    );
    const now = dayjs().toISOString();
    await pool.query(
      'UPDATE Users SET logged_in=$1,updated_at=$2 WHERE id=$3',
      [true, now, u.id]
    );
    return jsonRes(res, '', '', { token: tok });
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});
app.patch('/api_v1/user', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', []);
    const { player_name } = req.body;
    if (!player_name || !validatePlayerNameFormat(player_name))
      return jsonRes(res, '', 'Invalid player_name', []);
    const now = dayjs().toISOString();
    await pool.query(
      'UPDATE Users SET player_name=$1,updated_at=$2 WHERE id=$3',
      [player_name, now, d.id]
    );
    return jsonRes(res, '', 'Success', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});
app.get('/api_v1/games', authenticateToken, async (req, res) => {
  try {
    const games = await pool.query('SELECT * FROM Games');
    return jsonRes(res, '', '', games.rows);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});
app.post('/api_v1/games', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', []);
    const {
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
    const exist = await pool.query(
      'SELECT * FROM Games WHERE ip=$1 AND port=$2',
      [ip, port]
    );
    if (exist.rowCount > 0) {
      await pool.query('DELETE FROM Games WHERE ip=$1 AND port=$2', [ip, port]);
      activeGames.delete(exist.rows[0].id);
    }
    const gid = await generateId();
    const now = dayjs().toISOString();
    const pass = await bcrypt.hash(password, 10);
    const insert = await pool.query(
      'INSERT INTO Games(id,ip,port,name,map_name,game_mode,connected_players,max_players,private,password,ping,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *',
      [
        gid,
        ip,
        port,
        game_name,
        map_name,
        game_mode,
        [],
        max_players,
        priv,
        pass,
        0,
        now,
        now,
      ]
    );
    activeGames.set(gid, insert.rows[0]);
    return jsonRes(res, 'Game created', '', insert.rows[0]);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});
app.put('/api_v1/games/:game_id', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', []);
    const gid = req.params.game_id;
    const plainId = await decryptId(gid);
    if (!plainId) return jsonRes(res, '', 'Invalid game_id', []);
    const gameCheck = await pool.query('SELECT * FROM Games WHERE id=$1', [
      gid,
    ]);
    if (gameCheck.rowCount < 1) return jsonRes(res, '', 'Not found', []);
    const gameOwner = gameCheck.rows[0];
    if (d.id !== gameOwner.id && d.role !== 'admin')
      return jsonRes(res, '', 'Not allowed', []);
    const data = req.body;
    delete data.decodedUser;
    const now = dayjs().toISOString();
    data.updated_at = now;
    const fields = [];
    const values = [];
    let idx = 1;
    for (const k in data) {
      fields.push(k + '=$' + idx);
      values.push(data[k]);
      idx++;
    }
    const query = 'UPDATE Games SET ' + fields.join(', ') + ' WHERE id=$' + idx;
    values.push(gid);
    await pool.query(query, values);
    const updated = await pool.query('SELECT * FROM Games WHERE id=$1', [gid]);
    activeGames.set(gid, updated.rows[0]);
    io.emit('game_updated', updated.rows[0]);
    return jsonRes(res, '', '', updated.rows[0]);
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});
app.delete('/api_v1/games/:game_id', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d || !d.id) return jsonRes(res, '', 'Unauthorized', []);
    const gid = req.params.game_id;
    const plainId = await decryptId(gid);
    if (!plainId) return jsonRes(res, '', 'Invalid game_id', []);
    const gameCheck = await pool.query('SELECT * FROM Games WHERE id=$1', [
      gid,
    ]);
    if (gameCheck.rowCount < 1) return jsonRes(res, '', 'Not found', []);
    const gameOwner = gameCheck.rows[0];
    if (d.id !== gameOwner.id && d.role !== 'admin')
      return jsonRes(res, '', 'Not allowed', []);
    await pool.query('DELETE FROM Games WHERE id=$1', [gid]);
    activeGames.delete(gid);
    io.emit('game_removed', gid);
    return jsonRes(res, 'Game deleted', '', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
});
app.post('/api_v1/logout', authenticateToken, async (req, res) => {
  try {
    const d = req.body.decodedUser;
    if (!d) return jsonRes(res, '', 'Unauthorized', []);
    const now = dayjs().toISOString();
    await pool.query(
      'UPDATE Users SET logged_in=$1,updated_at=$2 WHERE id=$3',
      [false, now, d.id]
    );
    const token = req.headers.authorization?.split(' ')[1] ?? '';
    await pool.query(
      'INSERT INTO Activations(user_id,token,created_at,expires_at) VALUES($1,$2,$3,$4)',
      [d.id, token, now, now]
    );
    return jsonRes(res, 'Logged out', '', {});
  } catch (e) {
    logger.error(e);
    return jsonRes(res, '', 'Server error', []);
  }
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
      await pool.query('UPDATE Games SET connected_players=$1 WHERE id=$2', [
        cPlayers,
        game_id,
      ]);
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
      await pool.query('UPDATE Games SET connected_players=$1 WHERE id=$2', [
        cPlayers,
        game_id,
      ]);
      activeGames.set(game_id, g);
      io.emit('player_left', { game_id, player_id });
    }
  });
});
if (process.env.FORCE_HTTPS === 'true') {
  const options = {
    key: fs.readFileSync(process.env.SSL_KEY_PATH ?? ''),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH ?? ''),
  };
  https.createServer(options, app).listen(envLoaded.PORT, () => {
    logger.info('HTTPS server on ' + envLoaded.PORT);
  });
} else {
  httpServer.listen(envLoaded.PORT, () => {
    logger.info('HTTP server on ' + envLoaded.PORT);
  });
}
