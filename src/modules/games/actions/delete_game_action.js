import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const deleteGameAction =
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
    await database.game.deleteGame(gameId);
    activeGames.delete(gameId);
    websockets.emit('game_deleted', { id: gameId });
    const ownerUser = await database.user.findUserById(game.owner_id);
    const updatedHostedGames = ownerUser.hosted_games.filter(
      (g) => g !== gameId
    );
    await database.user.updateUser(ownerUser.id, {
      hosted_games: updatedHostedGames,
    });
    logger.info('Game deleted successfully');
    return jsonRes(res, '', [], 200);
  };
