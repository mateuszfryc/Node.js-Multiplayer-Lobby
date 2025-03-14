import { logger } from '#config/logger.js';
import { gamesFeedEvents } from '#games/websockets/setup_games_feed.js';
import { jsonRes } from '#utils/response.js';

export const leaveGameAction = (database, websockets) => async (req, res) => {
  const { requestingUser } = req.body;
  if (!requestingUser || !requestingUser.id) {
    logger.warn('Unauthorized attempt to leave game');
    return jsonRes(res, 'Unauthorized', [], 401);
  }
  const gameId = req.params.game_id;
  const plainGameId = gameId;
  if (!plainGameId) {
    logger.warn('Unable to decrypt game_id for leave');
    return jsonRes(res, 'Invalid game_id', [], 400);
  }
  const gameData = database.game.findById(plainGameId);
  if (!gameData) {
    logger.warn('User tried to leave non-existent game');
    return jsonRes(res, 'Game not found', [], 404);
  }
  if (gameData.owner_id === requestingUser.id) {
    logger.warn('Player tried to leave the game hosted by himself.');
    return jsonRes(
      res,
      'Player cannot leave the game hosted by himself.',
      [],
      404
    );
  }

  const connectedPlayers = gameData.connected_players || [];
  const playerIndex = connectedPlayers.indexOf(requestingUser.id);
  if (playerIndex > -1) {
    connectedPlayers.splice(playerIndex, 1);
    gameData.connected_players = connectedPlayers;
    await database.game.update(gameId, {
      connected_players: connectedPlayers,
    });
    websockets.emit(gamesFeedEvents.gamesUpdate, gameData);
    logger.info('Player left the game', {
      connectedPlayersCount: connectedPlayers.length,
    });
    return jsonRes(res, '', { game_id: gameId }, 200);
  }

  logger.warn(
    `Player id: ${requestingUser.id} that is not part of the game: ${gameData.id} tried to leave that game.`
  );
  return jsonRes(res, 'Bad request', [], 404);
};
