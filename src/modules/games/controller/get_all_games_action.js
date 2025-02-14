import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const getAllGamesAction = (database) => async (req, res) => {
  const gamesList = await database.game.getCurrentGamesList();
  if (gamesList === undefined || gamesList === null) {
    logger.warn('Could not retrieve games list from database');
    return jsonRes(res, 'Internal Server Error', [], 500);
  }
  logger.debug('Fetched games list', { count: gamesList.length });
  return jsonRes(res, '', gamesList, 200);
};
