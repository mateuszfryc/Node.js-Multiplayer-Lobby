import { Router } from 'express';

import { authenticateToken } from '#auth/middleware/auth_jwt.js';
import { createGameAction } from './actions/create_game_action.js';
import { deleteGameAction } from './actions/delete_game_action.js';
import { getAllGamesAction } from './actions/get_all_games_action.js';
import { joinGameAction } from './actions/join_game_action.js';
import { leaveGameAction } from './actions/leave_game_action.js';
import { updateGameAction } from './actions/update_game_action.js';

export const gamesRoutes = (baseUrl, services) => {
  const router = Router();
  const url = `${baseUrl}/games`;
  const { database, activeGames, websockets } = services;
  const jwtAuth = authenticateToken(database);

  // prettier-ignore
  {
    router.get(url, jwtAuth, getAllGamesAction(database));
    router.post(url, jwtAuth, createGameAction(database, activeGames, websockets));
    router.put(`${url}/:game_id`, jwtAuth, updateGameAction(database, activeGames, websockets));
    router.post(`${url}/:game_id/join`, jwtAuth, joinGameAction(database, activeGames, websockets));
    router.post(`${url}/:game_id/leave`, jwtAuth, leaveGameAction(database, activeGames, websockets));
    router.delete(`${url}/:game_id`, jwtAuth, deleteGameAction(database, activeGames, websockets));
  }

  return router;
};
