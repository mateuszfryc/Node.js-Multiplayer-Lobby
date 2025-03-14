/**
 * Copyright (c) 2025 Dyson Sphere Games, Mateusz Fryc
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

// if envs are not set as expected crash early
import { envDefinitions } from '#config/env.js';
import { ensureEnvs } from '#utils/env.js';
const envs = await ensureEnvs(envDefinitions);

import express from 'express';
import fs from 'fs';
import { createServer } from 'http';
import https from 'https';

import { Server as SocketIOServer } from 'socket.io';
import 'winston-daily-rotate-file';

import { authRoutes } from '#auth/auth_routes.js';
import { activationsSchema } from '#auth/persistence/activations_schema.js';
import { errorBoundry } from '#config/bounds.js';
import { DatabaseManager } from '#config/database.js';
import { helmetMid } from '#config/helmet.js';
import { limiter } from '#config/limiter.js';
import { logger, requestLogger } from '#config/logger.js';
import { transporter } from '#config/smpt.js';
import { gamesRoutes } from '#games/games_routes.js';
import { gamesSchema } from '#games/persistence/games_schema.js';
import { websocketsJwtAuth } from '#games/websockets/auth_middleware.js';
import { setupGamesFeed } from '#games/websockets/setup_games_feed.js';
import { setupInactiveGamesCleanup } from '#games/websockets/setup_inactive_games_cleanup.js';
import { userSchema } from '#users/persistence/users_schema.js';
import { usersRoutes } from '#users/users_routes.js';

const app = express();
app.use(express.json({ strict: true }));
app.use(helmetMid);
app.use(limiter);
app.use(requestLogger);

if (envs.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (req.secure) return next();
    return res.redirect(`https://${req.headers.host}${req.url}`);
  });
}

const database = new DatabaseManager(
  envs,
  userSchema,
  gamesSchema,
  activationsSchema
);
await database.init(database, envs);
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
};

const baseUrl = '/api_v1';
// prettier-ignore
[
  authRoutes,
  usersRoutes,
  gamesRoutes,
]
.forEach((initRoutes) => app.use(initRoutes(baseUrl, services)));

app.use(errorBoundry);

websockets.use(websocketsJwtAuth(envs));
websockets.on('connection', (socket) => {
  setupGamesFeed(database)(socket);
  socket.on('host_heartbeat', async ({ game_id }) => {
    await database.game.refresh(game_id);
  });
});

setInterval(
  setupInactiveGamesCleanup(database, websockets, envs),
  envs.GAME_HEARTBEAT_INTERVAL * 1000
);

app.all('*', (req, res) => {
  logger.warn('Unhandled route', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  res.status(404).send('Route not found');
});

if (envs.USE_SSL) {
  let sslOptions;
  try {
    sslOptions = {
      key: fs.readFileSync(envs.SSL_KEY_PATH),
      cert: fs.readFileSync(envs.SSL_CERT_PATH),
    };
  } catch (err) {
    throw new Error(`Failed to load SSL certificates: ${err.message}`);
  }

  const httpsOptions = {
    key: sslOptions.key,
    cert: sslOptions.cert,
  };

  https.createServer(httpsOptions, app).listen(envs.PORT, () => {
    logger.info(`HTTPS server listening on port ${envs.PORT}`);
  });
} //
else {
  httpServer.listen(envs.PORT, () => {
    logger.info(`HTTP server listening on port ${envs.PORT}`);
  });
}
