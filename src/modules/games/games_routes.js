import express from 'express';

import { authenticateToken } from '#auth/middleware/authenticateToken.js';
import { asyncBoundry as bounds } from '#config/bounds.js';
import { createGameAction } from './controller/create_game_action.js';
import { deleteGameAction } from './controller/delete_game_action.js';
import { gameHeartbeatAction } from './controller/game_heartbeat_action.js';
import { getAllGamesAction } from './controller/get_all_games_action.js';
import { joinGameAction } from './controller/join_game_action.js';
import { leaveGameAction } from './controller/leave_game_action.js';
import { updateGameAction } from './controller/update_game_action.js';

export const gamesRoutes = (baseUrl, services) => {
  const router = express.Router();
  const gamesUrl = `${baseUrl}/games`;
  const { database, websockets, envs } = services;
  const auth = authenticateToken(database);

  router
    .route(gamesUrl)
    .get(auth, bounds(getAllGamesAction(database)))
    .post(auth, bounds(createGameAction(database, websockets, envs)));

  router
    .route(`${gamesUrl}/:game_id`)
    .put(auth, bounds(updateGameAction(database, websockets)))
    .delete(auth, bounds(deleteGameAction(database, websockets)));

  router
    .route(`${gamesUrl}/:game_id/join`)
    .post(auth, bounds(joinGameAction(database, websockets)));

  router
    .route(`${gamesUrl}/:game_id/leave`)
    .post(auth, bounds(leaveGameAction(database, websockets)));

  router
    .route(`${gamesUrl}/:game_id/heartbeat`)
    .put(auth, bounds(gameHeartbeatAction(database)));

  return router;
};
