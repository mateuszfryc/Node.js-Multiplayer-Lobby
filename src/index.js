/*
Copyright (c) 2025 Mateusz Fryc

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program.
If not, see <https://www.gnu.org/licenses/>.
 */

import express from 'express';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import helmet from 'helmet';
import { createServer } from 'http';
import https from 'https';

import { Server as SocketIOServer } from 'socket.io';
import 'winston-daily-rotate-file';

import { authRoutes } from '#auth/auth_routes.js';
import { loadEnv } from '#config/env.js';
import { logger } from '#config/logger.js';
import { transporter } from '#config/smpt.js';
import { gamesRoutes } from '#games/games_routes.js';
import { gamesSchema } from '#games/schema/games_schema.js';
import { websocketsJwtAuth } from '#games/websockets/auth_middleware.js';
import { DatabaseManager } from '#persistence/DatabaseManager.js';
import { activationsSchema } from '#persistence/schema/activations_schema.js';
import { userSchema } from '#users/schema/users_schema.js';
import { usersRoutes } from '#users/users_routes.js';

const envs = await loadEnv([
  { key: 'PORT', log: true },
  { key: 'JWT_SECRET', minLength: 32 },
  { key: 'JWT_REFRESH_SECRET', minLength: 32 },
  { key: 'DB_USER' },
  { key: 'DB_PASSWORD' },
  { key: 'DB_NAME' },
  { key: 'DB_HOST' },
  { key: 'DB_PORT', type: 'number' },
  { key: 'DB_FORCE_SYNC', type: 'bool', log: true },
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
  { key: 'NODE_ENV' },
]);

let sslOptions;
if (envs.USE_SSL) {
  try {
    sslOptions = {
      key: fs.readFileSync(envs.SSL_KEY_PATH),
      cert: fs.readFileSync(envs.SSL_CERT_PATH),
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
if (envs.NODE_ENV === 'production') {
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
const database = new DatabaseManager(
  envs,
  userSchema,
  gamesSchema,
  activationsSchema
);
const activeGames = new Map();
await database.init(envs, activeGames);
const mailer = transporter(envs);
const httpServer = createServer(app);
const websockets = new SocketIOServer(httpServer, {
  cors: { origin: false, methods: ['GET', 'POST'] },
});

const services = {
  database,
  envs,
  mailer,
  websockets,
  activeGames,
};

// prettier-ignore
[
  authRoutes,
  usersRoutes,
  gamesRoutes,
]
.forEach((initRoutes) => app.use(initRoutes('/api_v1', services)));

websockets.use(websocketsJwtAuth(envs));
websockets.on('connection', (socket) => {
  logger.info('WebSocket connected', { socketId: socket.id });
  socket.on('subscribeToGamesList', () => {
    socket.emit('games_list', Array.from(activeGames.values()));
  });
  socket.on('error', (err) => {
    logger.error('WebSocket error', { error: err });
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

if (envs.USE_SSL && sslOptions) {
  const httpsOptions = {
    key: sslOptions.key,
    cert: sslOptions.cert,
  };
  https.createServer(httpsOptions, app).listen(envs.PORT, () => {
    logger.info(`HTTPS server listening on port ${envs.PORT}`);
  });
} else {
  httpServer.listen(envs.PORT, () => {
    logger.info(`HTTP server listening on port ${envs.PORT}`);
  });
}
