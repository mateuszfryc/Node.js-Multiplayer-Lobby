import { logger } from '#config/logger.js';
import { gamesFeedEvents } from '#games/websockets/setup_games_feed.js';
import { jsonRes } from '#utils/response.js';

export const joinGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    const { requestingUser } = req.body;
    if (!requestingUser || !requestingUser.id) {
      logger.warn('Unauthorized attempt to join game');
      return jsonRes(res, 'Unauthorized', [], 401);
    }
    const gameId = req.params.game_id;
    const plainGameId = gameId;
    if (!plainGameId) {
      logger.warn('Unable to decrypt game_id for join');
      return jsonRes(res, 'Invalid game_id', [], 400);
    }
    const gameData = activeGames.get(gameId);
    if (!gameData) {
      logger.warn('Game not found in activeGames for join');
      return jsonRes(res, 'Game not found', [], 404);
    }
    if (gameData.owner_id === requestingUser.id) {
      logger.warn('Player tried to join game hosted by himself.');
      return jsonRes(
        res,
        'Player cannot join game hosted by himself.',
        [],
        404
      );
    }
    const connectedPlayers = gameData.connected_players || [];
    if (connectedPlayers.length > gameData.max_players) {
      logger.warn('Game is full');
      return jsonRes(res, 'Game is full', [], 403);
    }
    if (!connectedPlayers.includes(requestingUser.id)) {
      connectedPlayers.push(requestingUser.id);
      gameData.connected_players = connectedPlayers;
      await database.game.update(gameId, {
        connected_players: connectedPlayers,
      });
      activeGames.set(gameId, gameData);
      websockets.emit(gamesFeedEvents.userJoined, {
        game_id: gameId,
        user_id: requestingUser.id,
      });
      logger.info('Player joined the game', {
        connectedPlayersCount: connectedPlayers.length,
      });
    }
    return jsonRes(res, '', { game_id: gameId }, 200);
  };
