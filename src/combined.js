import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import winston from 'winston';
import { DataTypes } from 'sequelize';
import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import { v4 } from 'uuid';
import dotenv from 'dotenv';
import fs from 'fs';
import { Sequelize } from 'sequelize';
import nodemailer from 'nodemailer';
import express from 'express';
import slowDown from 'express-slow-down';
import jwt from 'jsonwebtoken';
import net from 'net';
import { createServer } from 'http';
import https from 'https';
import { Server } from 'socket.io';
import 'winston-daily-rotate-file';
// C:\Dev\lobby\src\config\consts.js
const USER_CHARS = /^[A-Za-z0-9!@#$%^&*\+\-\?, ]+$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_REGEX =
  /^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$%^&*\+\-\?,])[A-Za-z0-9!@#$%^&*\+\-\?,]{8,}$/;
const PLAYER_NAME_REGEX = /^[A-Za-z0-9!@#$%^&*\+\-\?,]{3,16}$/;
// C:\Dev\lobby\src\config\env.js
const envDefinitions = [
  { key: 'NODE_ENV' },
  { key: 'PORT', type: 'int', log: true },
  { key: 'USE_SSL', type: 'bool' },
  { key: 'SSL_KEY_PATH' },
  { key: 'SSL_CERT_PATH' },
  { key: 'JWT_SECRET', minLength: 32 },
  { key: 'JWT_REFRESH_SECRET', minLength: 32 },
  { key: 'ADMIN_USER_NAME' },
  { key: 'ADMIN_PASSWORD' },
  { key: 'ADMIN_PLAYER_NAME' },
  { key: 'ALLOW_USER_REGISTRATION', log: true },
  { key: 'DB_USER' },
  { key: 'DB_PASSWORD' },
  { key: 'DB_NAME' },
  { key: 'DB_HOST' },
  { key: 'DB_PORT', type: 'int' },
  { key: 'DB_FORCE_SYNC', type: 'bool', log: true },
  { key: 'SMTP_HOST' },
  { key: 'FROM_EMAIL' },
  { key: 'SMTP_USER' },
  { key: 'SMTP_PASS' },
  { key: 'SMTP_PORT' },
  { key: 'GAME_HEARTBEAT_INTERVAL', type: 'int', log: true },
  { key: 'NUMBER_OF_ALLOWED_SKIPPED_HEARTBEATS', type: 'int', log: true },
  { key: 'INACTIVE_GAME_TIMEOUT', type: 'int', log: true },
  { key: 'ALLOW_MULTIPLE_GAMES_PER_HOST', type: 'bool', log: true },
];
// C:\Dev\lobby\src\modules\auth\persistence\activations_repository.js
class ActivationsRepository {
  constructor(model) {
    this.model = model;
  }
  async create(data) {
    return this.model.create(data);
  }
  async findByToken(token) {
    return this.model.findOne({ where: { token } });
  }
  async invalidate(token) {
    return this.model.destroy({ where: { token } });
  }
}
// C:\Dev\lobby\src\utils\html.js
const cssReset = `
  *, *::before, *::after {
    box-sizing: border-box;
  }
  * {
    margin: 0;
  }
  body {
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  img, picture, video, canvas, svg {
    display: block;
    max-width: 100%;
  }
  input, button, textarea, select {
    font: inherit;
  }
  p, h1, h2, h3, h4, h5, h6 {
    overflow-wrap: break-word;
  }
  p {
    text-wrap: pretty;
  }
  h1, h2, h3, h4, h5, h6 {
    text-wrap: balance;
  }
  #root, #__next {
    isolation: isolate;
  }
`;
const htmlMessage = (message) =>
  `<html>
    <head>
      <style>
        ${cssReset}
        p { padding: 20px; }
      </style>
    </head>
    <body>
      <p>${message}</p>
    </body>
  </html>`;
// C:\Dev\lobby\src\utils\response.js
function jsonRes(res, error, data, status = 200) {
  return res.status(status).json({ error, data });
}
// C:\Dev\lobby\src\config\bounds.js
const asyncBoundry = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};
const errorBoundry = (err, req, res, next) => {
  logger.error(`${err.message}`, { stack: err.stack });
  if (res.headersSent) {
    return next(err);
  }
  jsonRes(res, 'Internal Server Error', [], err.status || 500);
};
// C:\Dev\lobby\src\modules\auth\controller\auth_logout_action.js
const logoutAction = (database) => async (req, res) => {
  const { requestingUser } = req.body;
  const user = await database.user.findById(requestingUser.id);
  if (!user) {
    logger.warn('User not found during logout');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  await database.user.logout(requestingUser.id);
  logger.info('User logged out successfully');
  return jsonRes(res, '', [], 200);
};
// C:\Dev\lobby\src\modules\games\controller\create_game_action.js
const createGameAction =
  (database, activeGames, websockets, envs) => async (req, res) => {
    const { requestingUser } = req.body;
    if (!requestingUser || !requestingUser.id) {
      logger.warn('Unauthorized attempt to create game');
      return jsonRes(res, 'Unauthorized', [], 401);
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
      return jsonRes(res, 'Missing fields', [], 400);
    }
    if (!validateIpOrLocalhost(ip)) {
      logger.warn('Invalid IP address for game creation');
      return jsonRes(res, 'Incorrect IP address', [], 400);
    }
    if (!validatePort(port)) {
      logger.warn('Invalid port number for game creation');
      return jsonRes(res, 'Incorrect port number', [], 400);
    }
    if (
      !USER_CHARS.test(game_name) ||
      !USER_CHARS.test(map_name) ||
      !USER_CHARS.test(game_mode)
    ) {
      logger.warn('Invalid characters in game fields');
      return jsonRes(res, 'Invalid characters', [], 400);
    }
    if (!max_players) max_players = 8;
    if (!isPrivate) isPrivate = false;
    if (!envs.ALLOW_MULTIPLE_GAMES_PER_HOST) {
      const user = await database.user.findById(requestingUser.id);
      const hostedGames = user.hosted_games ?? [];
      if (hostedGames.length > 0) {
        logger.warn(
          'User tried to create more than one game when ALLOW_MULTIPLE_GAMES_PER_HOST is set to false.'
        );
        return jsonRes(res, 'Multiple games hosting not allowed', [], 403);
      }
    }
    const existing = await database.game.findByIpPort(ip, port);
    if (existing) {
      logger.debug('Existing game found for IP:Port. Replacing game entry');
      await database.game.delete(existing.id);
      activeGames.delete(existing.id);
    }
    const newGame = await database.game.create(
      requestingUser.id,
      ip,
      port,
      game_name,
      map_name,
      game_mode,
      max_players,
      isPrivate,
      password
    );
    activeGames.set(newGame.id, newGame.toJSON());
    websockets.emit(gamesFeedEvents.gameCreated, newGame);
    logger.info('Game created successfully', {
      game_name,
      map_name,
      game_mode,
      max_players,
      private: isPrivate,
    });
    const user = await database.user.findById(requestingUser.id);
    logger.info('user: ', requestingUser);
    const hostedGames = user.hosted_games ?? [];
    await database.user.update(requestingUser.id, {
      hosted_games: [...hostedGames, newGame.id],
    });
    return jsonRes(
      res,
      '',
      {
        game: newGame,
        settings: { heartbeatIntervalSeconds: envs.GAME_HEARTBEAT_INTERVAL },
      },
      201
    );
  };
// C:\Dev\lobby\src\modules\games\controller\delete_game_action.js
const deleteGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    const { requestingUser } = req.body;
    if (!requestingUser || !requestingUser.id) {
      logger.warn('Unauthorized attempt to delete game');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const gameId = req.params.game_id;
    if (!gameId) {
      logger.warn('Unable to decrypt game_id for deletion');
      return jsonRes(res, 'Invalid game id', [], 400);
    }
    const game = await database.game.findById(gameId);
    if (!game) {
      logger.warn('Game not found for deletion');
      return jsonRes(res, 'Not found', [], 404);
    }
    if (
      requestingUser.role !== 'admin' &&
      game.owner_id !== requestingUser.id
    ) {
      logger.warn('Unauthorized attempt to delete game');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    await database.game.delete(gameId);
    activeGames.delete(gameId);
    websockets.emit(gamesFeedEvents.gameDeleted, { id: gameId });
    const ownerUser = await database.user.findById(game.owner_id);
    const updatedHostedGames = ownerUser.hosted_games.filter(
      (g) => g !== gameId
    );
    await database.user.update(ownerUser.id, {
      hosted_games: updatedHostedGames,
    });
    logger.info('Game deleted successfully');
    return jsonRes(res, '', [], 200);
  };
// C:\Dev\lobby\src\modules\games\controller\game_heartbeat_action.js
const gameHeartbeatAction =
  (database, activeGames) => async (req, res) => {
    const { game_id } = req.params;
    let updatedGame = await database.game.findById(game_id);
    if (!updatedGame) {
      logger.error('Game not found for heartbeat', { game_id });
      return res.status(404).json({ error: 'Game not found' });
    }
    await database.game.refresh(game_id);
    updatedGame = await database.game.findById(game_id);
    activeGames.set(game_id, updatedGame.toJSON());
    logger.info('Game heartbeat: ', { game_id });
    return jsonRes(res, '', [], 200);
  };
// C:\Dev\lobby\src\modules\games\controller\get_all_games_action.js
const getAllGamesAction = (database) => async (req, res) => {
  const games = await database.game.findAll();
  logger.debug('Fetched games list', { count: games.length });
  return jsonRes(res, '', games, 200);
};
// C:\Dev\lobby\src\modules\games\controller\join_game_action.js
const joinGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    const { requestingUser } = req.body;
    if (!requestingUser || !requestingUser.id) {
      logger.warn('Unauthorized attempt to join game');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const gameId = req.params.game_id;
    const plainGameId = gameId;
    if (!plainGameId) {
      logger.warn('Unable to decrypt game_id for join');
      return jsonRes(res, 'Invalid game_id', [], 400);
    }
    const gameData = activeGames.get(gameId);
    if (!gameData) {
      logger.warn('Game not found in activeGames for join');
      return jsonRes(res, 'Game not found', [], 404);
    }
    if (gameData.owner_id === requestingUser.id) {
      logger.warn('Player tried to join game hosted by himself.');
      return jsonRes(
        res,
        'Player cannot join game hosted by himself.',
        [],
        404
      );
    }
    const connectedPlayers = gameData.connected_players || [];
    if (connectedPlayers.length > gameData.max_players) {
      logger.warn('Game is full');
      return jsonRes(res, 'Game is full', [], 403);
    }
    if (!connectedPlayers.includes(requestingUser.id)) {
      connectedPlayers.push(requestingUser.id);
      gameData.connected_players = connectedPlayers;
      await database.game.update(gameId, {
        connected_players: connectedPlayers,
      });
      activeGames.set(gameId, gameData);
      websockets.emit(gamesFeedEvents.userJoined, {
        game_id: gameId,
        user_id: requestingUser.id,
      });
      logger.info('Player joined the game', {
        connectedPlayersCount: connectedPlayers.length,
      });
    }
    return jsonRes(res, '', { game_id: gameId }, 200);
  };
// C:\Dev\lobby\src\modules\games\controller\leave_game_action.js
const leaveGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    const { requestingUser } = req.body;
    if (!requestingUser || !requestingUser.id) {
      logger.warn('Unauthorized attempt to leave game');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const gameId = req.params.game_id;
    const plainGameId = gameId;
    if (!plainGameId) {
      logger.warn('Unable to decrypt game_id for leave');
      return jsonRes(res, 'Invalid game_id', [], 400);
    }
    const gameData = activeGames.get(gameId);
    if (!gameData) {
      logger.warn('Game not found in activeGames for leave');
      return jsonRes(res, 'Game not found', [], 404);
    }
    if (gameData.owner_id === requestingUser.id) {
      logger.warn('Player tried to leave the game hosted by himself.');
      return jsonRes(
        res,
        'Player cannot leave the game hosted by himself.',
        [],
        404
      );
    }
    const connectedPlayers = gameData.connected_players || [];
    const playerIndex = connectedPlayers.indexOf(requestingUser.id);
    if (playerIndex > -1) {
      connectedPlayers.splice(playerIndex, 1);
      gameData.connected_players = connectedPlayers;
      await database.game.update(gameId, {
        connected_players: connectedPlayers,
      });
      activeGames.set(gameId, gameData);
      websockets.emit(gamesFeedEvents.gamesUpdate, gameData);
      logger.info('Player left the game', {
        connectedPlayersCount: connectedPlayers.length,
      });
      return jsonRes(res, '', { game_id: gameId }, 200);
    }
    logger.warn(
      `Player id: ${requestingUser.id} that is not part of the game: ${gameData.id} tried to leave that game.`
    );
    return jsonRes(res, 'Bad request', [], 404);
  };
// C:\Dev\lobby\src\modules\games\controller\update_game_action.js
const updateGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    const { requestingUser } = req.body;
    if (!requestingUser || !requestingUser.id) {
      logger.warn('Unauthorized attempt to update game');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const gameId = req.params.game_id;
    const plainGameId = gameId;
    if (!plainGameId) {
      logger.warn('Unable to decrypt game_id');
      return jsonRes(res, 'Invalid game id', [], 400);
    }
    const gameCheck = await database.game.findById(gameId);
    if (!gameCheck) {
      logger.warn('Game not found for update');
      return jsonRes(res, 'Not found', [], 404);
    }
    if (gameCheck.owner_id !== requestingUser.id) {
      logger.warn('Unauthorized attempt to update game');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const newData = { ...req.body };
    delete newData.requestingUser;
    await database.game.update(gameId, newData);
    if (gameCheck.owner_id === requestingUser.id) {
      await database.game.refresh(gameId);
    }
    logger.debug('Game updated in database');
    const updatedGame = await database.game.findById(gameId);
    activeGames.set(gameId, updatedGame.toJSON());
    websockets.emit(gamesFeedEvents.gamesUpdate, updatedGame);
    logger.info('Game updated successfully');
    return jsonRes(res, '', updatedGame, 200);
  };
// C:\Dev\lobby\src\modules\games\websockets\setup_games_feed.js
const gamesFeedEvents = {
  gamesList: 'games_list',
  gameCreated: 'game_created',
  gameDeleted: 'game_deleted',
  gameUpdated: 'game_updated',
  gameUnresponsive: 'game_unresponsive',
  userJoined: 'user_joined',
  useLeft: 'user_left',
};
const setupGamesFeed = (database, activeGames) => (socket) => {
  logger.info('WebSocket connected', { socketId: socket.id });
  socket.on('error', (err) => {
    logger.error('WebSocket error', { error: err });
  });
  socket.on('subscribeToGamesList', () => {
    socket.emit(gamesFeedEvents.gamesList, Array.from(activeGames.values()));
  });
};
// C:\Dev\lobby\src\modules\games\websockets\setup_inactive_games_cleanup.js
const checkGameResponsiveness = async (
  database,
  websockets,
  activeGames,
  envs,
  gameId,
  game
) => {
  const lastHeartbeat = new Date(game.last_host_action_at) / 1000;
  const secondsDelta = Date.now() / 1000 - lastHeartbeat;
  const unreachableTime =
    envs.GAME_HEARTBEAT_INTERVAL * envs.NUMBER_OF_ALLOWED_SKIPPED_HEARTBEATS;
  if (
    game.status !== GamesRepository.STATUS_UNRESPONSIVE &&
    secondsDelta > unreachableTime
  ) {
    await database.game.setStatus(gameId, GamesRepository.STATUS_UNRESPONSIVE);
    activeGames.set(gameId, {
      ...game,
      status: GamesRepository.STATUS_UNRESPONSIVE,
    });
    websockets.emit(gamesFeedEvents.gameUnresponsive, { id: gameId });
    logger.warn('Game marked as unresponsive due to missing heartbeats', {
      id: gameId,
    });
    return;
  }
  else if (secondsDelta > envs.INACTIVE_GAME_TIMEOUT + unreachableTime) {
    const game = await database.game.findById(gameId);
    if (!gameId) {
      logger.error('Game not found for deletion', { id: gameId });
      return;
    }
    const ownerId = game.owner_id;
    const owner = await database.user.findById(ownerId);
    if (!owner) {
      logger.error('Owner not found for game', { id: gameId, ownerId });
      return;
    }
    const hostedGames = (owner.hosted_games ?? []).filter(
      (id) => id !== gameId
    );
    await database.user.update(ownerId, { hosted_games: hostedGames });
    await database.game.delete(gameId);
    activeGames.delete(gameId);
    websockets.emit(gamesFeedEvents.gameDeleted, { id: gameId });
    logger.warn('Game deleted due to inactivity', { id: gameId });
    return;
  }
};
const setupInactiveGamesCleanup =
  (database, websockets, activeGames, envs) => async () => {
    for (const [id, game] of activeGames.entries()) {
      await checkGameResponsiveness(
        database,
        websockets,
        activeGames,
        envs,
        id,
        game
      );
    }
  };
// C:\Dev\lobby\src\modules\users\controller\delete_user_action.js
const deleteUserAction =
  (database, activeGames, websockets) => async (req, res) => {
    const { requestingUser } = req.body;
    if (!requestingUser || requestingUser.role !== 'admin') {
      logger.warn('Unauthorized user deletion attempt');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const userId = req.params.user_id;
    const plainId = userId;
    if (!plainId) {
      logger.warn('Unable to decrypt user_id');
      return jsonRes(res, 'Invalid user_id', [], 400);
    }
    const user = await database.user.findById(userId);
    if (!user) {
      logger.warn('User not found for deletion');
      return jsonRes(res, 'Not found', [], 404);
    }
    if (user.hosted_games && user.hosted_games.length) {
      for (const gId of user.hosted_games) {
        await database.game.delete(gId);
        activeGames.delete(gId);
        websockets.emit(gamesFeedEvents.gameDeleted, { id: gId });
      }
    }
    await database.user.delete(userId);
    logger.info('User deleted successfully');
    return jsonRes(res, '', [], 200);
  };
// C:\Dev\lobby\src\modules\users\controller\get_user_action.js
const getUserAction = (database) => async (req, res) => {
  const { requestingUser } = req.body;
  const { user_id } = req.params;
  if (!requestingUser) {
    logger.warn('Unauthorized user request attempt');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  if (requestingUser.role !== 'admin' && requestingUser.id !== user_id) {
    logger.warn('Unauthorized user request attempt (mismatched user id)');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  if (!user_id) {
    logger.warn('User id missing in request');
    return jsonRes(res, 'Bad Request', [], 400);
  }
  const user = await database.user.findById(user_id);
  if (!user) {
    logger.warn('User not found for user_id', { user_id });
    return jsonRes(res, 'Bad Request', [], 404);
  }
  logger.info('User found successfully', { user_id });
  const data = {
    id: user.id,
    player_name: user.player_name,
  };
  return jsonRes(res, '', data, 200);
};
// C:\Dev\lobby\src\config\helmet.js
const helmetMid = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'self'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  noSniff: true,
});
// C:\Dev\lobby\src\config\limiter.js
const limiter = rateLimit({
  windowMs: 60000,
  max: 50,
  message: { message: '', error: 'Too many requests', data: {} },
});
// C:\Dev\lobby\src\config\logger.js
const isProduction = process.env.NODE_ENV !== 'production';
const sensitiveKeys = [
  'accessToken',
  'Authorization',
  'clientIp',
  'ip',
  'password',
  'player_name',
  'port',
  'refresh_token',
  'refreshToken',
  'token',
  'user_name',
];
const redactSensitiveData = winston.format((info) => {
  for (const key of sensitiveKeys) {
    if (info[key]) {
      info[key] = '[REDACTED]';
    }
  }
  return info;
});
const formats = [
  winston.format.errors({ stack: true }),
  redactSensitiveData(),
  winston.format.colorize(),
  winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
    const metaString = Object.keys(meta).length
      ? Object.entries(meta)
          .map(([key, value]) => `${key}=${value}`)
          .join(', ')
      : '';
    return `${timestamp ? `${timestamp} ` : ''}[${level}] ${stack || message} ${
      metaString ? `${metaString}` : ''
    }`;
  }),
];
if (isProduction) {
  formats.unshift(
    winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' })
  );
}
const logger = winston.createLogger({
  level: isProduction ? 'info' : 'debug',
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(...formats),
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
const requestLogger = (req, res, next) => {
  const { method, url, body, query, ip } = req;
  logger.info('Request', {
    method,
    url,
    ...body,
    ...query,
    ip,
  });
  next();
};
// C:\Dev\lobby\src\modules\auth\persistence\activations_schema.js
const activationsSchema = (database_manager) =>
  database_manager.define(
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
// C:\Dev\lobby\src\modules\games\persistence\games_schema.js
const gamesSchema = (database_manager) =>
  database_manager.define(
    'game',
    {
        id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
        owner_id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, allowNull: false },
        ip: { type: DataTypes.STRING, allowNull: false },
        port: { type: DataTypes.INTEGER, allowNull: false },
        name: { type: DataTypes.STRING, allowNull: false },
        map_name: { type: DataTypes.STRING, allowNull: false },
        game_mode: { type: DataTypes.STRING, allowNull: false },
        connected_players: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: false, defaultValue: [] },
        max_players: { type: DataTypes.INTEGER, allowNull: false },
        private: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
        password: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
        ping: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
        last_host_action_at: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
        status: { type: DataTypes.STRING, allowNull: false, defaultValue: 'alive' },
      },
    {
      tableName: 'games',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
    }
  );
// C:\Dev\lobby\src\modules\users\persistence\users_repository.js
class UsersRepository {
  constructor(model) {
    this.model = model;
  }
  async create(
    user_name,
    password,
    player_name,
    role = 'player',
    validated = false
  ) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const now = dayjs().toISOString();
    const data = {
      id: v4(),
      user_name,
      password: hashedPassword,
      player_name,
      role,
      created_at: now,
      updated_at: now,
      validated_at: validated ? now : null,
      refresh_token: null,
    };
    return this.model.create(data);
  }
  async findById(id) {
    return this.model.findOne({ where: { id } });
  }
  async findByUserName(user_name) {
    return this.model.findOne({ where: { user_name } });
  }
  async update(id, newData) {
    return this.model.update(newData, { where: { id } });
  }
  async login(user, refreshToken) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.update(user.id, {
      refresh_token: hashedRefreshToken,
      updated_at: dayjs().toISOString(),
    });
  }
  async logout(userId) {
    await this.update(userId, {
      refresh_token: null,
      updated_at: dayjs().toISOString(),
    });
  }
  async delete(userId) {
    return this.model.destroy({ where: { id: userId } });
  }
}
// C:\Dev\lobby\src\modules\users\persistence\users_schema.js
const userSchema = (database_manager) =>
  database_manager.define(
    'user',
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      user_name: { type: DataTypes.STRING, unique: true, allowNull: false },
      password: { type: DataTypes.STRING, allowNull: false },
      player_name: { type: DataTypes.STRING, allowNull: false },
      role: { type: DataTypes.STRING, allowNull: false },
      hosted_games: { type: DataTypes.ARRAY(DataTypes.UUID), allowNull: false, defaultValue: [] },
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
// C:\Dev\lobby\src\utils\env.js
function parseEnv(value, type) {
  switch (type) {
    case 'bool':
      return value.toLowerCase() === 'true'; 
    case 'int':
      return parseInt(value, 10); 
    case 'float':
      return parseFloat(value); 
    case 'string':
    default:
      return value; 
  }
}
const ensureEnvs = async (envDefinitions) => {
  const envs = {};
  const isProduction = process.env.NODE_ENV === 'production';
  dotenv.config({ path: isProduction ? '.env.prod' : '.env' });
  for (const {
    key,
    minLength,
    base64Length,
    filePath,
    type,
    log,
  } of envDefinitions) {
    const value = process.env[key];
    if (!value) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
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
    if (log) {
      console.log(`${key}: ${value}.`);
    }
    envs[key] = parseEnv(value, type);
  }
  console.log('All required environment variables are present and valid.');
  return envs;
};
// C:\Dev\lobby\src\config\database.js
class DatabaseManager {
  constructor(envs, inUsersSchema, inGamesSchema, inActivationsSchema) {
    const isProduction = envs.NODE_ENV === 'production';
    this.sequelize = new Sequelize(
      envs.DB_NAME,
      envs.DB_USER,
      envs.DB_PASSWORD,
      {
        host: envs.DB_HOST,
        dialect: 'postgres',
        protocol: 'postgres',
        logging: false,
        define: {
          schema: 'public',
        },
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
    this.user = new UsersRepository(inUsersSchema(this.sequelize));
    this.game = new GamesRepository(inGamesSchema(this.sequelize));
    this.activation = new ActivationsRepository(
      inActivationsSchema(this.sequelize)
    );
  }
  async init(database, envs, activeGames) {
    try {
      await this.sequelize.authenticate();
      logger.info('Database connection successful.');
    } catch (error) {
      logger.error('Database connection failed:', error.message);
      process.exit(1);
    }
    if (envs.DB_FORCE_SYNC) {
      logger.info('Syncing database tables');
      await this.sequelize.sync({ force: true });
    }
    try {
      if (
        !envs.ADMIN_USER_NAME ||
        !envs.ADMIN_PASSWORD ||
        !envs.ADMIN_PLAYER_NAME
      ) {
        throw new Error('Admin user environment variables are missing.');
      }
      const existingAdmin = await this.user.findByUserName(
        envs.ADMIN_USER_NAME
      );
      if (existingAdmin) {
        logger.info('Admin user already exists');
      } else {
        await database.user.create(
          envs.ADMIN_USER_NAME,
          envs.ADMIN_PASSWORD,
          envs.ADMIN_PLAYER_NAME,
          'admin',
          true
        );
        logger.info('Admin user created successfully');
      }
    } catch (error) {
      logger.error('Failed to create admin user', { error: error.message });
      process.exit(1);
    }
    const games = await this.game.findAll();
    games.forEach((game) => {
      activeGames.set(game.id, game.toJSON());
    });
  }
}
// C:\Dev\lobby\src\config\smpt.js
const transporter = (envs) => {
  const smptPort = parseInt(envs.SMTP_PORT || '587', 10);
  const client = nodemailer.createTransport({
    host: envs.SMTP_HOST,
    port: smptPort,
    secure: smptPort === 465,
    auth: {
      user: envs.SMTP_USER,
      pass: envs.SMTP_PASS,
    },
  });
  client.verify((error, success) => {
    if (error) {
      logger.error('SMTP Connection Error', { error: error.message });
    } else {
      logger.info('SMTP Connection Successful');
    }
  });
  return client;
};
// C:\Dev\lobby\src\modules\auth\auth_routes.js
const authRoutes = (baseUrl, services) => {
  const router = express.Router();
  const authUrl = `${baseUrl}/auth`;
  const { database, envs } = services;
  const auth = authenticateToken(database);
  router
    .route(authUrl)
    .post(loginLimiter, loginSpeedLimiter, asyncBoundry(loginAction(database, envs)))
    .patch(asyncBoundry(refreshAction(database, envs)))
    .delete(auth, asyncBoundry(logoutAction(database)));
  return router;
};
// C:\Dev\lobby\src\modules\auth\controller\auth_login_action.js
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
const loginAction = (database, envs) => async (req, res) => {
  const { user_name, password } = req.body;
  if (!user_name) {
    logger.warn('No user_name in login request');
    return jsonRes(res, 'Invalid credentials', [], 400);
  }
  if (!password) {
    logger.warn('No password in login request');
    return jsonRes(res, 'Invalid credentials', [], 400);
  }
  if (!validateEmailFormat(user_name)) {
    logger.warn('Invalid email format in login request');
    return jsonRes(res, 'Invalid credentials', [], 400);
  }
  const user = await database.user.findByUserName(user_name);
  if (!user) {
    logger.warn('User not found in database');
    return jsonRes(res, 'Invalid credentials', [], 401);
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    logger.warn('Password mismatch');
    return jsonRes(res, 'Invalid credentials', [], 401);
  }
  if (!user.validated_at) {
    logger.warn('Email not validated');
    return jsonRes(res, 'Email not validated', [], 403);
  }
  const accessToken = jwt.sign(
    { id: user.id, role: user.role, player_name: user.player_name },
    envs.JWT_SECRET ?? '',
    { expiresIn: '15m' }
  );
  const refreshToken = jwt.sign(
    { id: user.id, role: user.role },
    envs.JWT_REFRESH_SECRET ?? '',
    { expiresIn: '1d' }
  );
  await database.user.login(user, refreshToken);
  logger.info('User logged in successfully');
  const data = { accessToken, refreshToken };
  return jsonRes(res, '', data, 200);
};
// C:\Dev\lobby\src\modules\auth\controller\auth_refresh_action.js
const refreshAction = (database, envs) => async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    logger.warn('Refresh authentication missing');
    return jsonRes(res, 'Bad Request', [], 400);
  }
  const decodedUser = jwt.verify(refreshToken, envs.JWT_REFRESH_SECRET ?? '');
  if (!decodedUser) {
    logger.warn('Invalid refresh authentication');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const user = await database.user.findById(decodedUser.id);
  if (!user) {
    logger.warn('User not found for refresh authentication');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const match = await bcrypt.compare(refreshToken, user.refresh_token ?? '');
  if (!match) {
    logger.warn('Refresh authentication mismatch');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const newAccessToken = jwt.sign(
    { id: user.id, role: user.role, player_name: user.player_name },
    envs.JWT_SECRET ?? '',
    { expiresIn: '15m' }
  );
  const newRefreshToken = jwt.sign(
    { id: user.id, role: user.role },
    envs.JWT_REFRESH_SECRET ?? '',
    { expiresIn: '7d' }
  );
  await database.user.login(user, newRefreshToken);
  logger.info('Authentication refreshed successfully');
  const data = { accessToken: newAccessToken, refreshToken: newRefreshToken };
  return jsonRes(res, '', data, 200);
};
// C:\Dev\lobby\src\modules\auth\middleware\authenticateToken.js
const authenticateToken = (database) => async (req, res, next) => {
  logger.info('Authenticating request', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    logger.warn('No Authorization header found');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const accessToken = authHeader?.split(' ')[1];
  if (!accessToken) {
    logger.warn('Invalid Authorization header');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  try {
    const decodedUser = jwt.verify(accessToken, process.env.JWT_SECRET ?? '');
    const user = await database.user.findById(decodedUser.id);
    if (!user) {
      logger.warn('User not found in database', { userId: decodedUser.id });
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    logger.debug('User decoded successfully', { role: decodedUser.role });
    req.body.requestingUser = decodedUser;
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      logger.info('Authentication expired', { error: e.message });
    } 
    else {
      logger.error('Failed to authenticate', { error: e.message });
    }
    return jsonRes(res, 'Unauthorized', [], 401);
  }
};
// C:\Dev\lobby\src\modules\games\games_routes.js
const gamesRoutes = (baseUrl, services) => {
  const router = express.Router();
  const gamesUrl = `${baseUrl}/games`;
  const { database, activeGames, websockets, envs } = services;
  const auth = authenticateToken(database);
  router
    .route(gamesUrl)
    .get(auth, asyncBoundry(getAllGamesAction(database)))
    .post(
      auth,
      asyncBoundry(createGameAction(database, activeGames, websockets, envs))
    );
  router
    .route(`${gamesUrl}/:game_id`)
    .put(auth, asyncBoundry(updateGameAction(database, activeGames, websockets)))
    .delete(auth, asyncBoundry(deleteGameAction(database, activeGames, websockets)));
  router
    .route(`${gamesUrl}/:game_id/heartbeat`)
    .put(auth, asyncBoundry(gameHeartbeatAction(database, activeGames)));
  return router;
};
// C:\Dev\lobby\src\modules\games\persistence\games_repository.js
class GamesRepository {
  static STATUS_ALIVE = 'alive';
  static STATUS_UNRESPONSIVE = 'unresponsive';
  constructor(model) {
    this.model = model;
  }
  async findAll() {
    return this.model.findAll();
  }
  async findByIpPort(ip, port) {
    return this.model.findOne({ where: { ip, port } });
  }
  async findById(id) {
    return this.model.findOne({ where: { id } });
  }
  async create(
    ownerId,
    ip,
    port,
    name,
    map_name,
    game_mode,
    max_players = 8,
    isPrivate = false,
    pass = null
  ) {
    const now = dayjs().toISOString();
    const password = pass ? await bcrypt.hash(pass, 10) : '';
    const data = {
      id: v4(),
      owner_id: ownerId,
      ip,
      port,
      name,
      map_name,
      game_mode,
      connected_players: [ownerId], 
      max_players,
      private: isPrivate,
      password,
      ping: 0,
      created_at: now,
      updated_at: now,
      last_host_action_at: now,
      status: GamesRepository.STATUS_ALIVE,
    };
    return this.model.create(data);
  }
  async update(id, newData) {
    return this.model.update(newData, { where: { id } });
  }
  async setStatus(id, status) {
    if (
      ![
        GamesRepository.STATUS_ALIVE,
        GamesRepository.STATUS_UNRESPONSIVE,
      ].includes(status)
    ) {
      logger.error(`Invalid game status value: ${status}`);
      return;
    }
    return this.model.update({ status }, { where: { id } });
  }
  async delete(id) {
    return this.model.destroy({ where: { id } });
  }
  async refresh(id) {
    return this.model.update(
      { last_host_action_at: new Date(), status: GamesRepository.STATUS_ALIVE },
      { where: { id } }
    );
  }
}
// C:\Dev\lobby\src\modules\games\websockets\auth_middleware.js
const websocketsJwtAuth = (envs) => (socket, next) => {
  try {
    const token =
      socket.handshake.auth?.token ??
      socket.handshake.headers?.authorization?.split(' ')[1];
    if (!token) {
      throw new Error('Missing token');
    }
    const decoded = jwt.verify(token, envs.JWT_SECRET);
    socket.requestingUser = decoded;
    return next();
  } catch (err) {
    logger.error('WebSocket auth error', { error: err.message });
    return next(err);
  }
};
// C:\Dev\lobby\src\modules\users\controller\confirm_user_action.js
const confirmUserAction = (database) => async (req, res) => {
  const token = req.params.token;
  const now = dayjs().toISOString();
  const activation = await database.activation.findByToken(token);
  if (!activation) {
    logger.warn('Invalid authentication used for email confirmation');
    return res.status(404).send(htmlMessage('Link no longer valid.'));
  }
  if (dayjs(now).isAfter(dayjs(activation.expires_at))) {
    logger.warn('Expired authentication used for email confirmation');
    return res.status(400).send(htmlMessage('Link has expired.'));
  }
  const user = await database.user.findById(activation.user_id);
  if (user.validated_at) {
    logger.info('User is already validated');
    return res
      .status(200)
      .send(htmlMessage('Your account is already confirmed!'));
  }
  await database.user.update(activation.user_id, { validated_at: now });
  await database.activation.invalidate(token);
  logger.info('Email confirmed for a user');
  return res.status(200).send(htmlMessage('Email confirmed successfully!'));
};
// C:\Dev\lobby\src\modules\users\controller\create_user_action.js
const createUserAction =
  (database, envs, mailer) => async (req, res) => {
    const { requestingUser } = req.body;
    const { user_name, password, player_name } = req.body;
    const notAdmin = !requestingUser || requestingUser.role !== 'admin';
    if (!envs.ALLOW_USER_REGISTRATION && notAdmin) {
      logger.warn('Non-admin attempted to create new user');
      return jsonRes(res, 'Request failed', [], 400);
    }
    if (!user_name || !password || !player_name) {
      logger.warn('Missing fields in /api_v1/register');
      return jsonRes(res, 'Request failed', [], 400);
    }
    if (!validateEmailFormat(user_name)) {
      logger.warn('Invalid email format in /api_v1/register');
      return jsonRes(res, 'Request failed', [], 400);
    }
    if (!validatePasswordFormat(password)) {
      logger.warn('Invalid password format in /api_v1/register');
      return jsonRes(res, 'Request failed', [], 400);
    }
    if (!validatePlayerNameFormat(player_name)) {
      logger.warn('Invalid player_name format in /api_v1/register');
      return jsonRes(res, 'Request failed', [], 400);
    }
    const existing = await database.user.findByUserName(user_name);
    if (existing) {
      logger.warn('Attempt to create existing user');
      return jsonRes(res, 'Request failed', [], 400);
    }
    const now = dayjs().toISOString();
    const newUser = await database.user.create(
      user_name,
      password,
      player_name,
      'player'
    );
    logger.info('New user created successfully');
    const token = v4();
    const exp = dayjs().add(1, 'day').toISOString();
    await database.activation.create({
      user_id: newUser.id,
      token,
      created_at: now,
      expires_at: exp,
    });
    logger.debug('Activation authentication created for new user');
    try {
      const verificationLink = `${envs.USE_SSL ? 'https' : 'http'}://${
        req.headers.host
      }/api_v1/users/verify/${token}`;
      await mailer.sendMail({
        from: envs.FROM_EMAIL,
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
    const data = { id: newUser.id, player_name };
    return jsonRes(res, '', data, 201);
  };
// C:\Dev\lobby\src\modules\users\controller\update_user_action.js
const updateUserAction = (database) => async (req, res) => {
  const updateId = req.params.user_id;
  const selfUpdate = updateId === 'update';
  const { requestingUser } = req.body;
  if (!requestingUser) {
    logger.warn('Requesting user not found in request body');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  if (!requestingUser.id) {
    logger.warn('Unauthorized update request (no user id)');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  if (
    requestingUser.role !== 'admin' && 
    requestingUser.id !== updateId && 
    !selfUpdate 
  ) {
    logger.warn(
      'Unauthorized update request (no user id or mismatched user id)'
    );
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const { player_name } = req.body;
  if (!player_name || !validatePlayerNameFormat(player_name)) {
    logger.warn('Invalid player_name in update request');
    return jsonRes(res, 'Invalid player_name', [], 400);
  }
  await database.user.update(selfUpdate ? requestingUser.id : updateId, {
    player_name,
    updated_at: dayjs().toISOString(),
  });
  logger.info('User updated successfully');
  return jsonRes(res, '', [], 200);
};
// C:\Dev\lobby\src\modules\users\users_routes.js
const usersRoutes = (baseUrl, services) => {
  const router = express.Router();
  const { database, envs, mailer, activeGames, websockets } = services;
  const auth = authenticateToken(database);
  if (envs.ALLOW_USER_REGISTRATION) {
    router
      .route(`${baseUrl}/users`)
      .post(asyncBoundry(createUserAction(database, envs, mailer)));
  } else {
    router
      .route(`${baseUrl}/users`)
      .post(auth, asyncBoundry(createUserAction(database, envs, mailer)));
  }
  router
    .route(`${baseUrl}/users/:user_id`)
    .get(auth, asyncBoundry(getUserAction(database)))
    .put(auth, asyncBoundry(updateUserAction(database)))
    .delete(auth, asyncBoundry(deleteUserAction(database, activeGames, websockets)));
  router
    .route(`${baseUrl}/users/verify/:token`)
    .get(asyncBoundry(confirmUserAction(database)));
  return router;
};
// C:\Dev\lobby\src\utils\validators.js
function validatePort(port) {
  const parsed = parseInt(port, 10);
  return Number.isInteger(parsed) && parsed > 0 && parsed <= 65535;
}
function validateIpOrLocalhost(ip) {
  if (ip === 'localhost') return true;
  return net.isIP(ip) !== 0;
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
// C:\Dev\lobby\src\index.js
const envs = await ensureEnvs(envDefinitions);
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
const activeGames = new Map();
await database.init(database, envs, activeGames);
const mailer = transporter(envs);
const httpServer = createServer(app);
const websockets = new Server(httpServer, {
  cors: { origin: false, methods: ['GET', 'POST'] },
});
const services = {
  database,
  envs,
  mailer,
  websockets,
  activeGames,
};
const baseUrl = '/api_v1';
[
  authRoutes,
  usersRoutes,
  gamesRoutes,
]
.forEach((initRoutes) => app.use(initRoutes(baseUrl, services)));
app.use(errorBoundry);
websockets.use(websocketsJwtAuth(envs));
websockets.on('connection', (socket) => {
  setupGamesFeed(database, activeGames)(socket);
  socket.on('host_heartbeat', async ({ game_id }) => {
    await database.games.refresh(game_id);
    const updatedGame = await database.games.findById(game_id);
    if (updatedGame) activeGames.set(game_id, updatedGame.toJSON());
  });
});
setInterval(
  setupInactiveGamesCleanup(database, websockets, activeGames, envs),
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
} 
else {
  httpServer.listen(envs.PORT, () => {
    logger.info(`HTTP server listening on port ${envs.PORT}`);
  });
}
