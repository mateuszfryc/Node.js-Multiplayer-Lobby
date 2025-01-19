import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const getAllGamesAction = (database) => async (req, res) => {
  const games = await database.game.findAllGames();
  logger.debug('Fetched games list', { count: games.length });
  return jsonRes(res, '', games, 200);
};
