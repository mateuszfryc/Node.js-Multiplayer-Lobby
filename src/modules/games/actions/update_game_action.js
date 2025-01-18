import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const updateGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    logger.info('PUT /api_v1/games/:game_id called', {
      method: req.method,
      url: req.url,
      clientIp: req.ip,
    });
    try {
      const requestingUser = req.body.requestingUser;
      logger.debug('Decoded user role for updating game', {
        role: requestingUser?.role,
      });
      if (!requestingUser || !requestingUser.id) {
        logger.warn('Unauthorized attempt to update game');
        return jsonRes(res, '', 'Unauthorized', [], 401);
      }
      const gameId = req.params.game_id;
      const plainGameId = gameId;
      if (!plainGameId) {
        logger.warn('Unable to decrypt game_id');
        return jsonRes(res, '', 'Invalid game_id', [], 400);
      }
      const gameCheck = await database.game.findById(gameId);
      if (!gameCheck) {
        logger.warn('Game not found for update');
        return jsonRes(res, '', 'Not found', [], 404);
      }
      const newData = { ...req.body };
      delete newData.requestingUser;
      await database.game.updateGame(gameId, newData);
      logger.debug('Game updated in database');
      const updatedGame = await database.game.findById(gameId);
      activeGames.set(gameId, updatedGame.toJSON());
      websockets.emit('game_updated', updatedGame);
      logger.info('Game updated successfully');
      return jsonRes(res, '', '', updatedGame, 200);
    } catch (e) {
      logger.error('Error in PUT /api_v1/games/:game_id route', {
        error: e.message,
      });
      return jsonRes(res, '', 'Server error', [], 500);
    }
  };
