import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const getAllGamesAction = (database) => async (req, res) => {
  logger.info('GET /api_v1/games called', {
    method: req.method,
    url: req.url,
    clientIp: req.ip,
  });
  try {
    const games = await database.game.findAllGames();
    logger.debug('Fetched games list', { count: games.length });
    return jsonRes(res, '', games, 200);
  } catch (e) {
    logger.error('Error in GET /api_v1/games route', { error: e.message });
    return jsonRes(res, 'Server Error', [], 500);
  }
};
