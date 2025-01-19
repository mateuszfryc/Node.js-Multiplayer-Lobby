import { asyncBoundry } from '#config/bounds.js';
import { DELETE, GET, POST, PUT } from '#config/consts.js';
import { Router } from 'express';

import { authenticateToken } from '#auth/middleware/authenticateToken.js';
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
  [
    [GET, url, getAllGamesAction(database), [jwtAuth]],
    [POST, url, createGameAction(database, activeGames, websockets), [jwtAuth]],
    [PUT, `${url}/:game_id`, updateGameAction(database, activeGames, websockets), [jwtAuth]],
    [POST, `${url}/:game_id/join`, joinGameAction(database, activeGames, websockets), [jwtAuth]],
    [POST, `${url}/:game_id/leave`, leaveGameAction(database, activeGames, websockets), [jwtAuth]],
    [DELETE, `${url}/:game_id`, deleteGameAction(database, activeGames, websockets), [jwtAuth]],
  ]
  .forEach(([method, url, action, middleware = []]) => {
    if (router[method]) router[method](url, ...middleware, asyncBoundry(action));
  });

  return router;
};
