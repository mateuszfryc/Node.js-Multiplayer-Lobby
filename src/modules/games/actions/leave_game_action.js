import { logger } from '#config/logger.js';
import { jsonRes } from '#utils/response.js';

export const leaveGameAction =
  (database, activeGames, websockets) => async (req, res) => {
    logger.info('POST /api_v1/games/:game_id/leave called', {
      method: req.method,
      url: req.url,
      clientIp: req.ip,
    });
    try {
      const user = req.body.requestingUser;
      logger.debug('Decoded user role for leaving game', {
        role: user?.role,
      });
      if (!user || !user.id) {
        logger.warn('Unauthorized attempt to leave game');
        return jsonRes(res, '', 'Unauthorized', [], 401);
      }
      const gameId = req.params.game_id;
      const plainGameId = gameId;
      if (!plainGameId) {
        logger.warn('Unable to decrypt game_id for leave');
        return jsonRes(res, '', 'Invalid game_id', [], 400);
      }
      const gameData = activeGames.get(gameId);
      if (!gameData) {
        logger.warn('Game not found in activeGames for leave');
        return jsonRes(res, '', 'Game not found', [], 404);
      }
      if (gameData.owner_id === user.id) {
        logger.warn('Player tried to leave the game hosted by himself.');
        return jsonRes(
          res,
          '',
          'Player cannot leave the game hosted by himself.',
          [],
          404
        );
      }
      const connectedPlayers = gameData.connected_players || [];
      const playerIndex = connectedPlayers.indexOf(user.id);
      if (playerIndex > -1) {
        connectedPlayers.splice(playerIndex, 1);
        gameData.connected_players = connectedPlayers;
        await database.game.updateGame(gameId, {
          connected_players: connectedPlayers,
        });
        activeGames.set(gameId, gameData);
        logger.info('Player left the game', {
          connectedPlayersCount: connectedPlayers.length,
        });
        websockets.emit('game_updated', gameData);
        return jsonRes(res, 'Left game', '', { game_id: gameId }, 200);
      }
      logger.warn(
        `Player id: ${user.id} that is not part of the game: ${gameData.id} tried to leave that game.`
      );
      return jsonRes(res, 'Bad request', '', {}, 404);
    } catch (e) {
      logger.error('Error in POST /api_v1/games/:game_id/leave route', {
        error: e.message,
      });
      return jsonRes(res, '', 'Server error', [], 500);
    }
  };
