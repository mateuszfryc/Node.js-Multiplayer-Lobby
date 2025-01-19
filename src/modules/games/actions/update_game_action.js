import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const updateGameAction =
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
    await database.game.updateGame(gameId, newData);
    logger.debug('Game updated in database');
    const updatedGame = await database.game.findById(gameId);
    activeGames.set(gameId, updatedGame.toJSON());
    websockets.emit('game_updated', updatedGame);
    logger.info('Game updated successfully');
    return jsonRes(res, '', updatedGame, 200);
  };
