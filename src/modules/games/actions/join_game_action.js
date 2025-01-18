import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const joinGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    logger.info('POST /api_v1/games/:game_id/join called', {
      method: req.method,
      url: req.url,
      clientIp: req.ip,
    });
    try {
      const requestingUser = req.body.requestingUser;
      logger.debug('Decoded user role for joining game', {
        role: requestingUser?.role,
      });
      if (!requestingUser || !requestingUser.id) {
        logger.warn('Unauthorized attempt to join game');
        return jsonRes(res, '', 'Unauthorized', [], 401);
      }
      const gameId = req.params.game_id;
      const plainGameId = gameId;
      if (!plainGameId) {
        logger.warn('Unable to decrypt game_id for join');
        return jsonRes(res, '', 'Invalid game_id', [], 400);
      }
      const gameData = activeGames.get(gameId);
      if (!gameData) {
        logger.warn('Game not found in activeGames for join');
        return jsonRes(res, '', 'Game not found', [], 404);
      }
      if (gameData.owner_id === requestingUser.id) {
        logger.warn('Player tried to join game hosted by himself.');
        return jsonRes(
          res,
          '',
          'Player cannot join game hosted by himself.',
          [],
          404
        );
      }
      const connectedPlayers = gameData.connected_players || [];
      if (!connectedPlayers.includes(requestingUser.id)) {
        connectedPlayers.push(requestingUser.id);
        gameData.connected_players = connectedPlayers;
        await database.game.updateGame(gameId, {
          connected_players: connectedPlayers,
        });
        activeGames.set(gameId, gameData);
        logger.info('Player joined the game', {
          connectedPlayersCount: connectedPlayers.length,
        });
        websockets.emit('game_updated', gameData);
      }
      return jsonRes(res, 'Joined game', '', { game_id: gameId }, 200);
    } catch (e) {
      logger.error('Error in POST /api_v1/games/:game_id/join route', {
        error: e.message,
      });
      return jsonRes(res, '', 'Server error', [], 500);
    }
  };
