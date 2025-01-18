import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const deleteGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    logger.info('DELETE /api_v1/games/:game_id called', {
      method: req.method,
      url: req.url,
      clientIp: req.ip,
    });
    try {
      const requestingUser = req.body.requestingUser;
      logger.debug('Decoded user role for deleting game', {
        role: requestingUser?.role,
      });
      if (!requestingUser || !requestingUser.id) {
        logger.warn('Unauthorized attempt to delete game');
        return jsonRes(res, '', 'Unauthorized', [], 401);
      }
      const gameId = req.params.game_id;
      const plainGameId = gameId;
      if (!plainGameId) {
        logger.warn('Unable to decrypt game_id for deletion');
        return jsonRes(res, '', 'Invalid game_id', [], 400);
      }
      const gameCheck = await database.game.findById(gameId);
      if (!gameCheck) {
        logger.warn('Game not found for deletion');
        return jsonRes(res, '', 'Not found', [], 404);
      }
      if (gameCheck.owner_id !== requestingUser.id) {
        logger.warn('Unauthorized attempt to delete game');
        return jsonRes(res, '', 'Unauthorized', [], 401);
      }
      await database.game.deleteGame(gameId);
      activeGames.delete(gameId);
      websockets.emit('games_list', Array.from(activeGames.values()));
      logger.info('Game deleted successfully');
      websockets.emit('game_deleted', { id: gameId });
      return jsonRes(res, 'Game deleted', '', {}, 200);
    } catch (e) {
      logger.error('Error in DELETE /api_v1/games/:game_id route', {
        error: e.message,
      });
      return jsonRes(res, '', 'Server error', [], 500);
    }
  };
